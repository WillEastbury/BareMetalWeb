using System.Collections.Concurrent;
using System.Diagnostics;
using BareMetalWeb.Core;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// Executes a <see cref="ReportQuery"/> or a stored <see cref="ReportDefinition"/> by
/// performing in-memory hash-joins across entity collections loaded from the data store.
/// </summary>
public sealed class ReportExecutor
{
    /// <summary>Maximum rows returned per report execution to guard against runaway results.</summary>
    public const int DefaultRowLimit = 10_000;

    /// <summary>Maximum records loaded per entity to prevent unbounded memory usage.</summary>
    public const int MaxEntityLoadSize = 50_000;

    /// <summary>Maximum combined rows during join processing before early termination.</summary>
    public const int MaxIntermediateRows = 100_000;

    private readonly IDataObjectStore _store;

    public ReportExecutor(IDataObjectStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /// <summary>Executes a stored <see cref="ReportDefinition"/>.</summary>
    public ValueTask<ReportResult> ExecuteAsync(
        ReportDefinition definition,
        IReadOnlyDictionary<string, string>? runtimeParameters = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(definition);

        var query = new ReportQuery().From(definition.RootEntity ?? string.Empty);

        if (definition.Joins != null)
        {
            foreach (var join in definition.Joins)
                query.Join(join.FromEntity, join.FromField, join.ToEntity, join.ToField);
        }

        if (definition.Columns != null)
        {
            foreach (var col in definition.Columns)
                query.SelectColumn(col.Entity, col.Field, col.Label, col.Format, col.Aggregate);
        }

        // Apply stored filters, substituting runtime parameters
        if (definition.Filters == null) { /* no filters */ }
        else foreach (var filter in definition.Filters)
        {
            var value = SubstituteParameter(filter.Value, runtimeParameters);
            query.Where($"{filter.Entity}.{filter.Field}", filter.Operator, value);
        }

        if (!string.IsNullOrWhiteSpace(definition.SortField))
            query.OrderBy(definition.SortField, definition.SortDescending);

        return ExecuteAsync(query, cancellationToken);
    }

    /// <summary>Executes a <see cref="ReportQuery"/> built with the fluent API.</summary>
    public async ValueTask<ReportResult> ExecuteAsync(
        ReportQuery query,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        var rootSlug = query.RootEntity;
        if (string.IsNullOrWhiteSpace(rootSlug))
            throw new InvalidOperationException("ReportQuery requires a root entity (call .From(...)).");

        if (!DataScaffold.TryGetEntity(rootSlug, out var rootMeta))
            throw new InvalidOperationException($"Entity '{rootSlug}' not found. Check the entity slug.");

        // Plan query — produce optimised execution plan
        var planner = new QueryPlanner();
        var plan = planner.Plan(query);
        var sw = Stopwatch.StartNew();

        // Load root entity rows with pushed-down filters
        plan.PushedFilters.TryGetValue(rootSlug, out var rootPushedFilter);
        var rootRowsRaw = await rootMeta.Handlers.QueryAsync(rootPushedFilter, cancellationToken);
        using var rootRows = new BmwValueList<BaseDataObject>(64);
        foreach (var r in rootRowsRaw)
        {
            if (rootRows.Count >= MaxEntityLoadSize) break;
            rootRows.Add(r);
        }

        // Start: each combined row is a dict of entitySlug -> BaseDataObject
        var combined = new List<Dictionary<string, BaseDataObject>>(rootRows.Count);
        foreach (var r in rootRows)
        {
            combined.Add(new Dictionary<string, BaseDataObject>(StringComparer.OrdinalIgnoreCase)
            {
                [rootSlug] = r
            });
        }

        // Process joins (INNER JOIN semantics)
        foreach (var join in query.Joins)
        {
            if (!DataScaffold.TryGetEntity(join.ToEntity, out var joinMeta))
                continue; // skip unknown entity

            if (!DataScaffold.TryGetEntity(join.FromEntity, out var fromMeta))
                continue;

            // Load join entity rows with pushed-down filters
            plan.PushedFilters.TryGetValue(join.ToEntity, out var joinPushedFilter);
            var joinRowsRaw = await joinMeta.Handlers.QueryAsync(joinPushedFilter, cancellationToken);
            using var joinRows = new BmwValueList<BaseDataObject>(64);
            foreach (var r in joinRowsRaw)
            {
                if (joinRows.Count >= MaxEntityLoadSize) break;
                joinRows.Add(r);
            }

            // Build hash map: toField value -> list of matching join rows
            var toAccessor = FindAccessor(joinMeta, join.ToField);
            if (toAccessor == null)
                continue;

            var hashMap = new Dictionary<string, List<BaseDataObject>>(joinRows.Count, StringComparer.OrdinalIgnoreCase);
            foreach (var jr in joinRows)
            {
                var key = GetStringValue(toAccessor, jr);
                if (!hashMap.TryGetValue(key, out var list))
                    hashMap[key] = list = new List<BaseDataObject>();
                list.Add(jr);
            }

            // Perform join based on join type
            var fromAccessor = FindAccessor(fromMeta, join.FromField);
            if (fromAccessor == null)
                continue;

            var newCombined = new List<Dictionary<string, BaseDataObject>>(combined.Count);
            var matchedRightKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool intermediateOverflow = false;

            foreach (var row in combined)
            {
                if (intermediateOverflow)
                    break;

                if (!row.TryGetValue(join.FromEntity, out var fromObj))
                {
                    // Left side missing (e.g. nulled out by prior outer join)
                    if (join.Type == JoinType.Left || join.Type == JoinType.FullOuter)
                        newCombined.Add(row); // preserve row without right side
                    continue;
                }

                var fromValue = GetStringValue(fromAccessor, fromObj);
                if (hashMap.TryGetValue(fromValue, out var matches))
                {
                    matchedRightKeys.Add(fromValue);
                    foreach (var match in matches)
                    {
                        var newRow = new Dictionary<string, BaseDataObject>(row, StringComparer.OrdinalIgnoreCase)
                        {
                            [join.ToEntity] = match
                        };
                        newCombined.Add(newRow);
                        if (newCombined.Count >= MaxIntermediateRows)
                        {
                            intermediateOverflow = true;
                            break;
                        }
                    }
                }
                else
                {
                    // No match on right side
                    switch (join.Type)
                    {
                        case JoinType.Left:
                        case JoinType.FullOuter:
                            newCombined.Add(row); // keep left row, right side absent
                            break;
                        case JoinType.Inner:
                        case JoinType.Right:
                            break; // drop unmatched left rows
                    }
                }
            }

            // For RIGHT and FULL OUTER: emit unmatched right-side records
            if (!intermediateOverflow && (join.Type == JoinType.Right || join.Type == JoinType.FullOuter))
            {
                foreach (var kvp in hashMap)
                {
                    if (matchedRightKeys.Contains(kvp.Key))
                        continue;
                    foreach (var rightObj in kvp.Value)
                    {
                        var newRow = new Dictionary<string, BaseDataObject>(StringComparer.OrdinalIgnoreCase)
                        {
                            [join.ToEntity] = rightObj
                        };
                        newCombined.Add(newRow);
                    }
                }
            }

            combined = newCombined;
        }

        // Apply filters
        var filters = query.Filters;
        if (filters.Count > 0)
        {
            var filtered = new List<Dictionary<string, BaseDataObject>>(combined.Count);
            foreach (var row in combined)
            {
                if (PassesFilters(row, filters))
                    filtered.Add(row);
            }
            combined = filtered;
        }

        // Resolve columns
        var columns = query.Columns;
        if (columns.Count == 0)
        {
            // Default: emit all root entity fields
            var defaultColumns = new List<ReportColumn>(rootMeta.Fields.Count);
            foreach (var f in rootMeta.Fields)
            {
                defaultColumns.Add(new ReportColumn
                {
                    Entity = rootSlug,
                    Field = f.Name,
                    Label = f.Label
                });
            }
            columns = defaultColumns;
        }

        var headers = new string[columns.Count];
        for (int i = 0; i < columns.Count; i++)
        {
            var c = columns[i];
            headers[i] = string.IsNullOrWhiteSpace(c.Label) ? $"{c.Entity}.{c.Field}" : c.Label;
        }

        // Project rows
        var projected = new List<string?[]>(combined.Count);
        foreach (var row in combined)
        {
            projected.Add(ProjectRow(row, columns));
        }

        // Aggregation
        bool hasAggregates = false;
        foreach (var c in columns)
        {
            if (c.Aggregate != AggregateFunction.None)
            {
                hasAggregates = true;
                break;
            }
        }
        if (hasAggregates)
            projected = AggregateRows(projected, columns);

        // Sort
        var sortField = query.SortField;
        if (!string.IsNullOrWhiteSpace(sortField))
        {
            var colIdx = FindColumnIndex(headers, sortField);
            if (colIdx >= 0)
            {
                int sortDir = query.SortDescending ? -1 : 1;
                projected.Sort((a, b) => sortDir * StringComparer.OrdinalIgnoreCase.Compare(a[colIdx], b[colIdx]));
            }
        }

        // Apply row limit
        var limit = query.QueryLimit ?? DefaultRowLimit;
        bool truncated = projected.Count > limit;
        var finalRows = truncated ? projected.GetRange(0, limit) : projected;

        sw.Stop();
        QueryPlanHistory.Record(new QueryPlanEntry
        {
            ExecutedAt    = DateTimeOffset.UtcNow,
            RootEntity    = rootSlug,
            JoinCount     = query.Joins.Count,
            ResultRowCount = finalRows.Count,
            ElapsedMs     = sw.Elapsed.TotalMilliseconds,
            Plan          = plan
        });

        return new ReportResult
        {
            ColumnLabels = headers,
            Rows = finalRows,
            TotalRows = finalRows.Count,
            IsTruncated = truncated,
            GeneratedAt = DateTime.UtcNow
        };
    }

    // ── Field access helpers ─────────────────────────────────────────────────

    private static Func<object, object?>? FindAccessor(DataEntityMetadata meta, string fieldName)
    {
        // Check DataField metadata first (compiled delegates, no reflection)
        foreach (var f in meta.Fields)
        {
            if (string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase))
                return f.GetValueFn;
        }

        // Fall back to EntityLayout which covers all properties including base class ones (Key, etc.)
        return EntityLayoutCompiler.GetOrCompile(meta).FieldByName(fieldName)?.Getter;
    }

    private static string GetStringValue(Func<object, object?> getter, object obj)
        => getter(obj)?.ToString() ?? string.Empty;

    // ── Row projection ───────────────────────────────────────────────────────

    // Sentinel used to cache "field not found" so we don't re-scan metadata on every row.
    private static readonly Func<object, object?> _missingFieldSentinel = static _ => null;

    // Cached compiled property accessors — avoids per-cell metadata lookup in report projection.
    private static readonly ConcurrentDictionary<(Type, string), Func<object, object?>> AccessorCache = new();

    /// <summary>
    /// Returns a compiled accessor for <paramref name="fieldName"/> on <paramref name="objType"/>,
    /// or <see langword="null"/> if the field is not found. Result is cached per (type, field) pair.
    /// </summary>
    private static Func<object, object?>? GetOrCreateAccessor(Type objType, string fieldName)
    {
        var cached = AccessorCache.GetOrAdd((objType, fieldName), static key =>
        {
            var meta = DataScaffold.GetEntityByType(key.Item1);
            if (meta != null)
            {
                var f = meta.FindField(key.Item2);
                if (f != null) return f.GetValueFn;
                var layout = EntityLayoutCompiler.GetOrCompile(meta).FieldByName(key.Item2);
                if (layout != null) return layout.Getter;
            }
            return _missingFieldSentinel;
        });
        return ReferenceEquals(cached, _missingFieldSentinel) ? null : cached;
    }

    private static string?[] ProjectRow(Dictionary<string, BaseDataObject> row, IReadOnlyList<ReportColumn> columns)
    {
        var cells = new string?[columns.Count];
        for (int i = 0; i < columns.Count; i++)
        {
            var col = columns[i];
            if (!row.TryGetValue(col.Entity, out var obj))
            {
                cells[i] = null;
                continue;
            }

            var getter = GetOrCreateAccessor(obj.GetType(), col.Field);
            cells[i] = getter != null ? FormatValue(getter(obj), col.Format) : null;
        }
        return cells;
    }

    private static string? FormatValue(object? value, string format)
    {
        if (value == null) return null;
        return format?.ToLowerInvariant() switch
        {
            "currency" => value is IConvertible c
                ? c.ToDecimal(System.Globalization.CultureInfo.InvariantCulture).ToString("C2")
                : value.ToString(),
            "date" => value is DateTime dt ? dt.ToString("yyyy-MM-dd")
                : value is DateOnly d ? d.ToString("yyyy-MM-dd")
                : value.ToString(),
            "datetime" => value is DateTime dtm ? dtm.ToString("yyyy-MM-dd HH:mm")
                : value.ToString(),
            "number" => value is IConvertible cn
                ? cn.ToDouble(System.Globalization.CultureInfo.InvariantCulture).ToString("N2")
                : value.ToString(),
            _ => value.ToString()
        };
    }

    // ── Filter evaluation ────────────────────────────────────────────────────

    private static bool PassesFilters(
        Dictionary<string, BaseDataObject> row,
        IReadOnlyList<ReportFilter> filters)
    {
        foreach (var filter in filters)
        {
            if (!row.TryGetValue(filter.Entity, out var obj))
                return false;

            var objType = obj.GetType();
            if (!AccessorCache.TryGetValue((objType, filter.Field), out var getter))
            {
                var meta = DataScaffold.GetEntityByType(objType);
                getter = meta?.FindField(filter.Field)?.GetValueFn;
                if (getter == null && meta != null)
                    getter = EntityLayoutCompiler.GetOrCompile(meta).FieldByName(filter.Field)?.Getter;
                if (getter != null)
                    AccessorCache.TryAdd((objType, filter.Field), getter);
            }

            var rawValue = getter?.Invoke(obj)?.ToString() ?? string.Empty;

            if (!EvaluateFilter(rawValue, filter.Operator, filter.Value))
                return false;
        }
        return true;
    }

    private static bool EvaluateFilter(string fieldValue, string op, string filterValue)
    {
        var cmp = StringComparison.OrdinalIgnoreCase;
        return op.Trim() switch
        {
            "=" or "==" or "eq" or "equals" =>
                string.Equals(fieldValue, filterValue, cmp),
            "!=" or "<>" or "ne" or "notequals" =>
                !string.Equals(fieldValue, filterValue, cmp),
            "contains" =>
                fieldValue.Contains(filterValue, cmp),
            "startswith" =>
                fieldValue.StartsWith(filterValue, cmp),
            "endswith" =>
                fieldValue.EndsWith(filterValue, cmp),
            ">" or "gt" =>
                CompareNumericOrString(fieldValue, filterValue) > 0,
            ">=" or "gte" =>
                CompareNumericOrString(fieldValue, filterValue) >= 0,
            "<" or "lt" =>
                CompareNumericOrString(fieldValue, filterValue) < 0,
            "<=" or "lte" =>
                CompareNumericOrString(fieldValue, filterValue) <= 0,
            _ => string.Equals(fieldValue, filterValue, cmp)
        };
    }

    private static int CompareNumericOrString(string a, string b)
    {
        if (decimal.TryParse(a, out var dA) && decimal.TryParse(b, out var dB))
            return dA.CompareTo(dB);
        return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
    }

    // ── Aggregation ──────────────────────────────────────────────────────────

    private static List<string?[]> AggregateRows(
        List<string?[]> rows,
        IReadOnlyList<ReportColumn> columns)
    {
        // Group-by columns are those without an aggregate function
        using var groupByList = new BmwValueList<int>(columns.Count);
        for (int i = 0; i < columns.Count; i++)
        {
            if (columns[i].Aggregate == AggregateFunction.None)
                groupByList.Add(i);
        }
        var groupByIndices = groupByList.ToArray();

        using var aggList = new BmwValueList<(ReportColumn c, int i)>(columns.Count);
        for (int i = 0; i < columns.Count; i++)
        {
            if (columns[i].Aggregate != AggregateFunction.None)
                aggList.Add((columns[i], i));
        }
        var aggIndices = aggList.ToArray();

        // Group rows by group-by column values
        var groups = new Dictionary<string, List<string?[]>>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            var keyParts = new string[groupByIndices.Length];
            for (int gi = 0; gi < groupByIndices.Length; gi++)
                keyParts[gi] = row[groupByIndices[gi]] ?? string.Empty;
            var key = string.Join("\x00", keyParts);
            if (!groups.TryGetValue(key, out var group))
                groups[key] = group = new List<string?[]>();
            group.Add(row);
        }

        var result = new List<string?[]>(groups.Count);
        foreach (var (_, group) in groups)
        {
            var output = new string?[columns.Count];

            // Copy group-by values from first row
            foreach (var idx in groupByIndices)
                output[idx] = group[0][idx];

            // Compute aggregates
            foreach (var (col, idx) in aggIndices)
            {
                output[idx] = col.Aggregate switch
                {
                    AggregateFunction.Count => group.Count.ToString(),
                    AggregateFunction.Sum => SumColumn(group, idx),
                    AggregateFunction.Min => MinColumn(group, idx),
                    AggregateFunction.Max => MaxColumn(group, idx),
                    AggregateFunction.Average => AvgColumn(group, idx),
                    AggregateFunction.StdDev => StdDevColumn(group, idx),
                    _ => null
                };
            }

            result.Add(output);
        }

        return result;
    }

    private static string SumColumn(List<string?[]> rows, int idx)
    {
        decimal sum = 0;
        foreach (var row in rows)
            if (decimal.TryParse(row[idx], out var v)) sum += v;
        return sum.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string MinColumn(List<string?[]> rows, int idx)
    {
        string? min = null;
        foreach (var row in rows)
        {
            var v = row[idx];
            if (v != null && (min == null || CompareNumericOrString(v, min) < 0))
                min = v;
        }
        return min ?? string.Empty;
    }

    private static string MaxColumn(List<string?[]> rows, int idx)
    {
        string? max = null;
        foreach (var row in rows)
        {
            var v = row[idx];
            if (v != null && (max == null || CompareNumericOrString(v, max) > 0))
                max = v;
        }
        return max ?? string.Empty;
    }

    private static string AvgColumn(List<string?[]> rows, int idx)
    {
        decimal sum = 0;
        int count = 0;
        foreach (var row in rows)
            if (decimal.TryParse(row[idx], out var v)) { sum += v; count++; }
        return count == 0 ? "0" : (sum / count).ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string StdDevColumn(List<string?[]> rows, int idx)
    {
        // Welford's online algorithm for population stddev
        int count = 0;
        double mean = 0, m2 = 0;
        foreach (var row in rows)
        {
            if (!double.TryParse(row[idx], out var v)) continue;
            count++;
            double delta = v - mean;
            mean += delta / count;
            double delta2 = v - mean;
            m2 += delta * delta2;
        }
        if (count < 2) return "0";
        return Math.Sqrt(m2 / count).ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    // ── Utility ──────────────────────────────────────────────────────────────

    private static int FindColumnIndex(string[] headers, string columnKey)
    {
        for (int i = 0; i < headers.Length; i++)
            if (string.Equals(headers[i], columnKey, StringComparison.OrdinalIgnoreCase))
                return i;
        return -1;
    }

    private static string SubstituteParameter(string value, IReadOnlyDictionary<string, string>? parameters)
    {
        if (parameters == null || !value.StartsWith('{') || !value.EndsWith('}'))
            return value;
        var name = value[1..^1];
        return parameters.TryGetValue(name, out var pv) ? pv : value;
    }
}
