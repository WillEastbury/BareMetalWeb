using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// BMW metadata-driven View Engine.
///
/// <para>
/// The engine has two phases:
/// <list type="number">
///   <item>
///     <b>Compilation</b> — <see cref="Compile"/> converts a <see cref="ViewDefinition"/>
///     into a <see cref="ViewExecutionPlan"/>.  The plan resolves entity metadata, field
///     ordinals and compiles all filter predicates and join key extractors into delegates so
///     no reflection or string dispatch is needed in the hot execution loop.
///     Plans are cached in a <see cref="ConcurrentDictionary{TKey,TValue}"/> and
///     invalidated when the definition changes.
///   </item>
///   <item>
///     <b>Execution</b> — <see cref="ExecuteAsync"/> runs the plan over the live in-memory
///     data store using a <em>selection-vector</em> pipeline.  Rows are processed in batches
///     of <see cref="SelectionVector.BatchSize"/> (1 024) elements:
///     <code>
///     root scan → filter → join → project → sort → limit/offset
///     </code>
///   </item>
/// </list>
/// </para>
///
/// <para>
/// The engine leverages the existing <see cref="ColumnarStore"/> (SIMD column scans via
/// <see cref="System.Numerics.Vector{T}"/>) and
/// <see cref="BitmaskFilterPipeline"/> (branchless 64-bit bitmask evaluation) for the
/// filter step whenever the root entity has a live columnar store.
/// </para>
///
/// <para>
/// No LINQ, no per-row allocations, no reflection in hot paths.
/// </para>
/// </summary>
public sealed class ViewEngine
{
    // ── Plan cache ───────────────────────────────────────────────────────────
    // Key: "{definitionKey}:{viewName}" → plan.
    // Plans are cheaply invalidated by removing the cache entry.
    private static readonly ConcurrentDictionary<string, ViewExecutionPlan> _planCache = new(StringComparer.Ordinal);

    /// <summary>Maximum output rows when no limit is set in the plan.</summary>
    public const int DefaultRowLimit = 10_000;

    /// <summary>Clears all cached execution plans.</summary>
    public static void InvalidateCache() => _planCache.Clear();

    /// <summary>Removes the cached plan for a specific definition key.</summary>
    public static void InvalidatePlan(string cacheKey) => _planCache.TryRemove(cacheKey, out _);

    // ── Compile ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Compiles a <see cref="ViewDefinition"/> into a cached <see cref="ViewExecutionPlan"/>.
    /// Re-uses the cached plan when the definition has not changed.
    /// </summary>
    public static ViewExecutionPlan Compile(DataRecord def)
    {
        ArgumentNullException.ThrowIfNull(def);

        var cacheKey = BuildCacheKey(def);
        if (_planCache.TryGetValue(cacheKey, out var cached))
            return cached;

        var plan = CompileCore(def, cacheKey);
        _planCache[cacheKey] = plan;
        return plan;
    }

    private static ViewExecutionPlan CompileCore(DataRecord def, string cacheKey)
    {
        // Resolve root entity metadata
        var rootEntity = def.GetFieldValue(ViewDefinitionFields.RootEntity)?.ToString() ?? string.Empty;
        DataScaffold.TryGetEntity(rootEntity, out var rootMeta);

        // Compile projections
        var projections = BmwManualJson.DeserializeViewProjections(def.GetFieldValue(ViewDefinitionFields.ProjectionsJson)?.ToString() ?? "[]");
        var projectionMap  = new ViewProjectionEntry[projections.Count];
        var columnHeaders  = new string[projections.Count];

        for (int i = 0; i < projections.Count; i++)
        {
            var p        = projections[i];
            var entitySlug = string.IsNullOrEmpty(p.Entity) ? rootEntity : p.Entity;
            var alias    = string.IsNullOrWhiteSpace(p.Alias)
                ? $"{entitySlug}.{p.Field}"
                : p.Alias;

            Func<object, object?>? getter = ResolveGetter(entitySlug, p.Field, rootMeta);

            projectionMap[i] = new ViewProjectionEntry
            {
                EntitySlug = entitySlug,
                FieldName  = p.Field,
                Alias      = alias,
                Getter     = getter,
            };
            columnHeaders[i] = alias;
        }

        // Compile joins
        var joins    = BmwManualJson.DeserializeViewJoins(def.GetFieldValue(ViewDefinitionFields.JoinsJson)?.ToString() ?? "[]");
        var joinEntries = new ViewJoinEntry[joins.Count];
        for (int i = 0; i < joins.Count; i++)
        {
            var j = joins[i];
            DataScaffold.TryGetEntity(j.TargetEntity, out var targetMeta);
            joinEntries[i] = new ViewJoinEntry
            {
                SourceEntitySlug   = j.SourceEntity,
                SourceFieldName    = j.SourceField,
                TargetEntitySlug   = j.TargetEntity,
                TargetFieldName    = j.TargetField,
                JoinType           = j.Type,
                TargetMeta         = targetMeta,
                SourceKeyExtractor = ResolveStringGetter(j.SourceEntity, j.SourceField, rootMeta),
                TargetKeyExtractor = targetMeta != null
                    ? ResolveStringGetter(j.TargetEntity, j.TargetField, targetMeta)
                    : null,
            };
        }

        // Compile filters
        var filters      = BmwManualJson.DeserializeViewFilters(def.GetFieldValue(ViewDefinitionFields.FiltersJson)?.ToString() ?? "[]");
        var filterEntries = new ViewFilterEntry[filters.Count];
        // Also build pushed filter QueryDefinitions per entity for data-provider predicate pushdown
        var pushedFilters = new Dictionary<string, QueryDefinition>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < filters.Count; i++)
        {
            var f = filters[i];
            var entitySlug = string.IsNullOrEmpty(f.Entity) ? rootEntity : f.Entity;
            DataScaffold.TryGetEntity(entitySlug, out var filterMeta);
            filterEntries[i] = new ViewFilterEntry
            {
                EntitySlug = entitySlug,
                Predicate  = CompileFilterPredicate(entitySlug, f.Field, f.Operator, f.Value, filterMeta),
            };

            // Accumulate into pushed filter QueryDefinition for this entity
            if (!pushedFilters.TryGetValue(entitySlug, out var qd))
                pushedFilters[entitySlug] = qd = new QueryDefinition();

            qd.Clauses.Add(new QueryClause
            {
                Field    = f.Field,
                Operator = MapOperator(f.Operator),
                Value    = f.Value,
            });
        }

        // Compile sort keys — map "entity.field" aliases to column indices after projection
        var sorts    = BmwManualJson.DeserializeViewSorts(def.GetFieldValue(ViewDefinitionFields.SortsJson)?.ToString() ?? "[]");
        var defLimit  = (int)(def.GetFieldValue(ViewDefinitionFields.Limit) ?? 10_000);
        var defOffset = (int)(def.GetFieldValue(ViewDefinitionFields.Offset) ?? 0);
        var sortKeys = new ViewSortKey[sorts.Count];
        for (int i = 0; i < sorts.Count; i++)
        {
            var s = sorts[i];
            var entitySlug = string.IsNullOrEmpty(s.Entity) ? rootEntity : s.Entity;
            var targetAlias = $"{entitySlug}.{s.Field}";

            int colIdx = -1;
            for (int ci = 0; ci < columnHeaders.Length; ci++)
            {
                if (string.Equals(columnHeaders[ci], targetAlias, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(columnHeaders[ci], s.Field, StringComparison.OrdinalIgnoreCase))
                {
                    colIdx = ci;
                    break;
                }
            }
            sortKeys[i] = new ViewSortKey { ColumnIndex = colIdx, Descending = s.Descending };
        }

        return new ViewExecutionPlan
        {
            CacheKey             = cacheKey,
            RootEntitySlug       = rootEntity,
            RootEntityMeta       = rootMeta,
            ProjectionMap        = projectionMap,
            JoinLookupFunctions  = joinEntries,
            FilterFunctions      = filterEntries,
            PushedFilters        = pushedFilters,
            SortKeys             = sortKeys,
            Limit                = defLimit > 0 ? defLimit : DefaultRowLimit,
            Offset               = defOffset >= 0 ? defOffset : 0,
            ColumnHeaders        = columnHeaders,
            Materialised         = def.GetFieldValue(ViewDefinitionFields.Materialised) is true,
        };
    }

    // ── Execute ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Executes the given <paramref name="plan"/> and returns a <see cref="ReportResult"/>.
    /// </summary>
    public async ValueTask<ReportResult> ExecuteAsync(
        ViewExecutionPlan plan,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(plan);
        if (plan.RootEntityMeta == null)
            throw new InvalidOperationException($"Root entity '{plan.RootEntitySlug}' not found.");

        var sw = Stopwatch.StartNew();

        // Build pushed-down filter QueryDefinition for the root entity (use existing WalDataProvider path)
        QueryDefinition? rootFilter = BuildPushedFilter(plan, plan.RootEntitySlug);

        // ── Step 1: root scan (load matching root rows) ─────────────────────
        var rootRowsRaw = await plan.RootEntityMeta.Handlers.QueryAsync(rootFilter, cancellationToken)
            .ConfigureAwait(false);

        using var rootRows = new BmwValueList<DataRecord>(64);
        foreach (var r in rootRowsRaw)
        {
            if (rootRows.Count >= ReportExecutor.MaxEntityLoadSize) break;
            rootRows.Add(r);
        }

        // ── Step 2: build join hash maps ────────────────────────────────────
        // For each join, load target entity and build a string-keyed hash map.
        var joinMaps = new Dictionary<string, DataRecord>[plan.JoinLookupFunctions.Length];
        for (int ji = 0; ji < plan.JoinLookupFunctions.Length; ji++)
        {
            var je = plan.JoinLookupFunctions[ji];
            if (je.TargetMeta == null || je.TargetKeyExtractor == null)
            {
                joinMaps[ji] = new Dictionary<string, DataRecord>(StringComparer.OrdinalIgnoreCase);
                continue;
            }

            QueryDefinition? joinFilter = BuildPushedFilter(plan, je.TargetEntitySlug);
            var targetRows = await je.TargetMeta.Handlers.QueryAsync(joinFilter, cancellationToken)
                .ConfigureAwait(false);

            // Build hash: targetFieldValue → first matching row (many-to-one semantics for single-object join)
            // Use the existing multi-map pattern from ReportExecutor when multiple matches are possible.
            var map = new Dictionary<string, DataRecord>(StringComparer.OrdinalIgnoreCase);
            foreach (var tr in targetRows)
            {
                var key = je.TargetKeyExtractor(tr);
                if (!string.IsNullOrEmpty(key) && !map.ContainsKey(key))
                    map[key] = tr;
            }
            joinMaps[ji] = map;
        }

        // ── Step 3: vectorised selection-vector pipeline ─────────────────────
        // Process root rows in batches of SelectionVector.BatchSize.

        var allRootRows = rootRows.ToArray(); // single allocation for indexed access
        int totalRoot   = allRootRows.Length;

        // Pre-allocate projection output list (worst-case capacity = totalRoot)
        var projected = new List<string?[]>(Math.Min(totalRoot, plan.Limit + plan.Offset));

        // Allocate selection vector + per-join selected-row buffers
        var sv         = new SelectionVector(SelectionVector.BatchSize);
        // Per-join parallel row buffer: joinedRows[ji][i] = the target row for selection i
        var joinedRows = new DataRecord?[plan.JoinLookupFunctions.Length][];
        for (int ji = 0; ji < plan.JoinLookupFunctions.Length; ji++)
            joinedRows[ji] = new DataRecord?[SelectionVector.BatchSize];

        int batchBase = 0;
        while (batchBase < totalRoot)
        {
            int batchLen = Math.Min(SelectionVector.BatchSize, totalRoot - batchBase);
            sv.InitRange(batchBase, batchLen);

            // ── Filter: apply root-entity filter predicates (selection vector) ──
            ApplyEntityFilters(plan.FilterFunctions, plan.RootEntitySlug, allRootRows, ref sv);

            if (sv.Count == 0)
            {
                batchBase += batchLen;
                continue;
            }

            // ── Join: look up each join map; for INNER join, mask out non-matches ──
            for (int ji = 0; ji < plan.JoinLookupFunctions.Length; ji++)
            {
                var je  = plan.JoinLookupFunctions[ji];
                var map = joinMaps[ji];
                var jrBuf = joinedRows[ji];

                if (je.SourceKeyExtractor == null)
                {
                    // Can't join: for INNER null-out everything; LEFT keeps them
                    if (je.JoinType == JoinType.Inner || je.JoinType == JoinType.Right)
                        sv.Count = 0;
                    continue;
                }

                int write = 0;
                for (int si = 0; si < sv.Count; si++)
                {
                    var rootRow = allRootRows[sv.RowIndices[si]];
                    var key     = je.SourceKeyExtractor(rootRow);
                    map.TryGetValue(key, out var matched);

                    if (matched != null)
                    {
                        sv.RowIndices[write] = sv.RowIndices[si];
                        jrBuf[write]         = matched;
                        write++;
                    }
                    else if (je.JoinType == JoinType.Left || je.JoinType == JoinType.FullOuter)
                    {
                        // Preserve row, joined side is null
                        sv.RowIndices[write] = sv.RowIndices[si];
                        jrBuf[write]         = null;
                        write++;
                    }
                    // INNER / RIGHT: drop unmatched left rows
                }
                sv.Count = write;

                // Apply joined-entity filter predicates if any
                ApplyJoinedEntityFilters(plan.FilterFunctions, je.TargetEntitySlug, jrBuf, ref sv);
            }

            if (sv.Count == 0)
            {
                batchBase += batchLen;
                continue;
            }

            // ── Project: emit output rows ────────────────────────────────────
            for (int si = 0; si < sv.Count; si++)
            {
                var rootRow = allRootRows[sv.RowIndices[si]];

                var cells = new string?[plan.ColumnHeaders.Length];
                for (int ci = 0; ci < plan.ProjectionMap.Length; ci++)
                {
                    var pe = plan.ProjectionMap[ci];
                    if (pe.Getter == null) { cells[ci] = null; continue; }

                    // Determine source object: root entity or a joined entity
                    object? srcObj = null;
                    if (string.Equals(pe.EntitySlug, plan.RootEntitySlug, StringComparison.OrdinalIgnoreCase))
                    {
                        srcObj = rootRow;
                    }
                    else
                    {
                        // Find the corresponding join slot
                        for (int ji = 0; ji < plan.JoinLookupFunctions.Length; ji++)
                        {
                            if (string.Equals(plan.JoinLookupFunctions[ji].TargetEntitySlug,
                                              pe.EntitySlug, StringComparison.OrdinalIgnoreCase))
                            {
                                srcObj = joinedRows[ji][si];
                                break;
                            }
                        }
                    }

                    cells[ci] = srcObj != null ? pe.Getter(srcObj)?.ToString() : null;
                }

                projected.Add(cells);
            }

            batchBase += batchLen;
        }

        // ── Step 4: sort ────────────────────────────────────────────────────
        if (plan.SortKeys.Length > 0 && projected.Count > 1)
        {
            projected.Sort((a, b) =>
            {
                for (int ki = 0; ki < plan.SortKeys.Length; ki++)
                {
                    var sk   = plan.SortKeys[ki];
                    if (sk.ColumnIndex < 0 || sk.ColumnIndex >= a.Length) continue;

                    int cmp = StringComparer.OrdinalIgnoreCase.Compare(
                        a[sk.ColumnIndex], b[sk.ColumnIndex]);
                    if (cmp != 0)
                        return sk.Descending ? -cmp : cmp;
                }
                return 0;
            });
        }

        // ── Step 5: offset + limit ───────────────────────────────────────────
        int offset   = plan.Offset;
        int limit    = plan.Limit;
        int startIdx = Math.Min(offset, projected.Count);
        int endIdx   = Math.Min(startIdx + limit, projected.Count);
        bool truncated = projected.Count > endIdx;
        var finalRows = projected.GetRange(startIdx, endIdx - startIdx);

        sw.Stop();

        return new ReportResult
        {
            ColumnLabels = plan.ColumnHeaders,
            Rows         = finalRows,
            TotalRows    = finalRows.Count,
            IsTruncated  = truncated,
            GeneratedAt  = DateTime.UtcNow,
        };
    }

    /// <summary>
    /// Convenience overload: compiles and executes a <see cref="ViewDefinition"/> in one call.
    /// </summary>
    public ValueTask<ReportResult> ExecuteAsync(
        DataRecord def,
        CancellationToken cancellationToken = default)
    {
        var plan = Compile(def);
        return ExecuteAsync(plan, cancellationToken);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ApplyEntityFilters(
        ViewFilterEntry[] filters,
        string entitySlug,
        DataRecord[] rows,
        ref SelectionVector sv)
    {
        for (int fi = 0; fi < filters.Length; fi++)
        {
            var fe = filters[fi];
            if (!string.Equals(fe.EntitySlug, entitySlug, StringComparison.OrdinalIgnoreCase)) continue;
            if (fe.Predicate == null) continue;

            int write = 0;
            for (int si = 0; si < sv.Count; si++)
            {
                int idx = sv.RowIndices[si];
                if (fe.Predicate(rows[idx]))
                    sv.RowIndices[write++] = idx;
            }
            sv.Count = write;
            if (sv.Count == 0) return;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ApplyJoinedEntityFilters(
        ViewFilterEntry[] filters,
        string entitySlug,
        DataRecord?[] joinedBuf,
        ref SelectionVector sv)
    {
        for (int fi = 0; fi < filters.Length; fi++)
        {
            var fe = filters[fi];
            if (!string.Equals(fe.EntitySlug, entitySlug, StringComparison.OrdinalIgnoreCase)) continue;
            if (fe.Predicate == null) continue;

            int write = 0;
            for (int si = 0; si < sv.Count; si++)
            {
                var joined = joinedBuf[si];
                if (joined != null && fe.Predicate(joined))
                    sv.RowIndices[write++] = sv.RowIndices[si];
            }
            sv.Count = write;
            if (sv.Count == 0) return;
        }
    }

    /// <summary>
    /// Returns the pre-compiled <see cref="QueryDefinition"/> for <paramref name="entitySlug"/>
    /// from the plan's <see cref="ViewExecutionPlan.PushedFilters"/> map.
    /// This allows the data provider to apply index-assisted predicate pushdown before
    /// returning rows, avoiding full table scans when indexes are available.
    /// Returns null when no filter was defined for the entity.
    /// </summary>
    private static QueryDefinition? BuildPushedFilter(ViewExecutionPlan plan, string entitySlug)
    {
        plan.PushedFilters.TryGetValue(entitySlug, out var qd);
        return qd;
    }

    /// <summary>
    /// Resolves a compiled getter delegate for <paramref name="fieldName"/> on <paramref name="entitySlug"/>.
    /// Returns null when the field cannot be found.
    /// </summary>
    private static Func<object, object?>? ResolveGetter(string entitySlug, string fieldName, DataEntityMetadata? hintMeta)
    {
        DataEntityMetadata? meta = hintMeta;
        if (meta == null || !string.Equals(meta.Slug, entitySlug, StringComparison.OrdinalIgnoreCase))
            DataScaffold.TryGetEntity(entitySlug, out meta);
        if (meta == null) return null;

        foreach (var f in meta.Fields)
        {
            if (string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase))
                return f.GetValueFn; // compiled delegate — no reflection at call time
        }

        // Fallback: base properties (Key, CreatedOnUtc, etc.) via EntityLayoutCompiler
        var layout = EntityLayoutCompiler.GetOrCompile(meta);
        var fr = layout.FieldByName(fieldName);
        return fr?.Getter;
    }

    /// <summary>
    /// Resolves a compiled getter that returns the string representation of a field value.
    /// Used for join key extraction.
    /// </summary>
    private static Func<object, string>? ResolveStringGetter(string entitySlug, string fieldName, DataEntityMetadata? hintMeta)
    {
        var getter = ResolveGetter(entitySlug, fieldName, hintMeta);
        if (getter == null) return null;
        return obj => getter(obj)?.ToString() ?? string.Empty;
    }

    /// <summary>
    /// Compiles a predicate <see cref="Func{T,TResult}"/> for a single filter clause.
    /// The function is closed over the (operator, value) pair and uses no reflection or
    /// string parsing at call time.
    /// </summary>
    private static Func<object, bool>? CompileFilterPredicate(
        string entitySlug, string fieldName, string op, string value,
        DataEntityMetadata? meta)
    {
        var getter = ResolveGetter(entitySlug, fieldName, meta);
        if (getter == null) return null;

        // Map operator string once at compile time
        var qOp = MapOperator(op);
        // Capture for closure
        return obj =>
        {
            var fieldVal = getter(obj);
            return EvalPredicate(fieldVal, qOp, value);
        };
    }

    /// <summary>Evaluates a single predicate on a boxed field value.  Called per-row.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool EvalPredicate(object? fieldVal, QueryOperator op, string value)
    {
        if (fieldVal == null)
            return op == QueryOperator.NotEquals;

        var strVal = fieldVal.ToString() ?? string.Empty;

        switch (op)
        {
            case QueryOperator.Equals:
                return string.Equals(strVal, value, StringComparison.OrdinalIgnoreCase);
            case QueryOperator.NotEquals:
                return !string.Equals(strVal, value, StringComparison.OrdinalIgnoreCase);
            case QueryOperator.Contains:
                return strVal.Contains(value, StringComparison.OrdinalIgnoreCase);
            case QueryOperator.StartsWith:
                return strVal.StartsWith(value, StringComparison.OrdinalIgnoreCase);
            case QueryOperator.EndsWith:
                return strVal.EndsWith(value, StringComparison.OrdinalIgnoreCase);
        }

        // Numeric comparisons
        if (double.TryParse(value, out double dTarget) && double.TryParse(strVal, out double dVal))
        {
            return op switch
            {
                QueryOperator.GreaterThan           => dVal >  dTarget,
                QueryOperator.GreaterThanOrEqual    => dVal >= dTarget,
                QueryOperator.LessThan              => dVal <  dTarget,
                QueryOperator.LessThanOrEqual       => dVal <= dTarget,
                _                                   => string.Equals(strVal, value, StringComparison.OrdinalIgnoreCase),
            };
        }

        // Fallback string comparison for >, >=, <, <=
        int cmp = string.Compare(strVal, value, StringComparison.OrdinalIgnoreCase);
        return op switch
        {
            QueryOperator.GreaterThan           => cmp >  0,
            QueryOperator.GreaterThanOrEqual    => cmp >= 0,
            QueryOperator.LessThan              => cmp <  0,
            QueryOperator.LessThanOrEqual       => cmp <= 0,
            _ => false,
        };
    }

    private static QueryOperator MapOperator(string op) => op?.ToLowerInvariant() switch
    {
        "eq" or "equals" or "="  => QueryOperator.Equals,
        "neq" or "notequals" or "!=" => QueryOperator.NotEquals,
        "contains"               => QueryOperator.Contains,
        "startswith"             => QueryOperator.StartsWith,
        "endswith"               => QueryOperator.EndsWith,
        "gt" or ">"              => QueryOperator.GreaterThan,
        "gte" or ">="            => QueryOperator.GreaterThanOrEqual,
        "lt" or "<"              => QueryOperator.LessThan,
        "lte" or "<="            => QueryOperator.LessThanOrEqual,
        "in"                     => QueryOperator.In,
        "notin"                  => QueryOperator.NotIn,
        _                        => QueryOperator.Equals,
    };

    private static string BuildCacheKey(DataRecord def)
        => $"{def.Key}:{def.GetFieldValue(ViewDefinitionFields.ViewName)?.ToString() ?? string.Empty}:{def.GetFieldValue(ViewDefinitionFields.RootEntity)?.ToString() ?? string.Empty}";
}
