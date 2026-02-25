using System.Diagnostics.CodeAnalysis;
using System.Reflection;
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

        foreach (var join in definition.Joins ?? Enumerable.Empty<ReportJoin>())
            query.Join(join.FromEntity, join.FromField, join.ToEntity, join.ToField);

        foreach (var col in definition.Columns ?? Enumerable.Empty<ReportColumn>())
            query.SelectColumn(col.Entity, col.Field, col.Label, col.Format, col.Aggregate);

        // Apply stored filters, substituting runtime parameters
        foreach (var filter in definition.Filters ?? Enumerable.Empty<ReportFilter>())
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

        // Load root entity rows (capped to prevent unbounded memory usage)
        var rootRows = (await rootMeta.Handlers.QueryAsync(null, cancellationToken))
            .Take(MaxEntityLoadSize).ToList();

        // Start: each combined row is a dict of entitySlug -> BaseDataObject
        var combined = rootRows
            .Select(r => new Dictionary<string, BaseDataObject>(StringComparer.OrdinalIgnoreCase)
            {
                [rootSlug] = r
            })
            .ToList();

        // Process joins (INNER JOIN semantics)
        foreach (var join in query.Joins)
        {
            if (!DataScaffold.TryGetEntity(join.ToEntity, out var joinMeta))
                continue; // skip unknown entity

            if (!DataScaffold.TryGetEntity(join.FromEntity, out var fromMeta))
                continue;

            var joinRows = (await joinMeta.Handlers.QueryAsync(null, cancellationToken))
                .Take(MaxEntityLoadSize).ToList();

            // Build hash map: toField value -> list of matching join rows
            var toAccessor = FindAccessor(joinMeta, join.ToField);
            if (toAccessor == null)
                continue;

            var hashMap = new Dictionary<string, List<BaseDataObject>>(StringComparer.OrdinalIgnoreCase);
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
            combined = combined.Where(row => PassesFilters(row, filters)).ToList();

        // Resolve columns
        var columns = query.Columns;
        if (columns.Count == 0)
        {
            // Default: emit all root entity fields
            columns = rootMeta.Fields
                .Select(f => new ReportColumn
                {
                    Entity = rootSlug,
                    Field = f.Name,
                    Label = f.Label
                })
                .ToList();
        }

        var headers = columns
            .Select(c => string.IsNullOrWhiteSpace(c.Label) ? $"{c.Entity}.{c.Field}" : c.Label)
            .ToArray();

        // Project rows
        var projected = combined
            .Select(row => ProjectRow(row, columns))
            .ToList();

        // Aggregation
        bool hasAggregates = columns.Any(c => c.Aggregate != AggregateFunction.None);
        if (hasAggregates)
            projected = AggregateRows(projected, columns);

        // Sort
        var sortField = query.SortField;
        if (!string.IsNullOrWhiteSpace(sortField))
        {
            var colIdx = FindColumnIndex(headers, sortField);
            if (colIdx >= 0)
            {
                projected = query.SortDescending
                    ? projected.OrderByDescending(r => r[colIdx], StringComparer.OrdinalIgnoreCase).ToList()
                    : projected.OrderBy(r => r[colIdx], StringComparer.OrdinalIgnoreCase).ToList();
            }
        }

        // Apply row limit
        var limit = query.QueryLimit ?? DefaultRowLimit;
        bool truncated = projected.Count > limit;
        var finalRows = truncated ? projected.Take(limit).ToList() : projected;

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

    private static PropertyInfo? FindAccessor(DataEntityMetadata meta, string fieldName)
    {
        // Check DataField metadata first
        var field = meta.Fields.FirstOrDefault(f =>
            string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase));
        if (field != null)
            return field.Property;

        // Fall back to BaseDataObject base properties (Id, CreatedOnUtc, etc.)
        return typeof(BaseDataObject).GetProperty(fieldName,
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
    }

    private static string GetStringValue(PropertyInfo prop, object obj)
        => prop.GetValue(obj)?.ToString() ?? string.Empty;

    private static string? GetNullableStringValue(PropertyInfo? prop, BaseDataObject obj)
        => prop?.GetValue(obj)?.ToString();

    // ── Row projection ───────────────────────────────────────────────────────

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

            var prop = FindAccessorOnObject(obj.GetType(), col.Field);
            if (prop == null)
            {
                cells[i] = null;
                continue;
            }

            var raw = prop.GetValue(obj);
            cells[i] = FormatValue(raw, col.Format);
        }
        return cells;
    }

    private static PropertyInfo? FindAccessorOnObject([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties)] Type type, string fieldName)
        => type.GetProperty(fieldName,
            BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);

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

            var prop = FindAccessorOnObject(obj.GetType(), filter.Field);
            var rawValue = prop?.GetValue(obj)?.ToString() ?? string.Empty;

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
        var groupByIndices = columns
            .Select((c, i) => (c, i))
            .Where(x => x.c.Aggregate == AggregateFunction.None)
            .Select(x => x.i)
            .ToArray();

        var aggIndices = columns
            .Select((c, i) => (c, i))
            .Where(x => x.c.Aggregate != AggregateFunction.None)
            .Select(x => (x.c, x.i))
            .ToArray();

        // Group rows by group-by column values
        var groups = new Dictionary<string, List<string?[]>>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            var key = string.Join("\x00", groupByIndices.Select(i => row[i] ?? string.Empty));
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
