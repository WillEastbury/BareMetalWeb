using System.Buffers;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// Per-column statistics collected during <see cref="ColumnarStore.Build{T}"/>.
/// Used by <see cref="QueryCostEstimator"/> to estimate clause selectivity,
/// reorder clauses, and choose between scan paths.
///
/// <para>Statistics are lightweight value types stored per field name.
/// They are rebuilt on every <c>Build()</c> call. After incremental
/// <c>UpsertRow</c> / <c>RemoveRow</c> operations the stats become
/// stale — <see cref="ColumnStatsRegistry.IsStale"/> can be checked
/// by callers that need accurate estimates.</para>
/// </summary>
internal readonly struct ColumnStats
{
    /// <summary>Total number of live (valid-bit-set) rows when stats were computed.</summary>
    public int RowCount { get; init; }

    /// <summary>Number of distinct values in the column (among valid rows).</summary>
    public int DistinctCount { get; init; }

    /// <summary>Number of rows whose validity bit was cleared (deleted/empty slots).</summary>
    public int NullCount { get; init; }

    /// <summary>Minimum value (as long for int/long, as bit-cast long for float/double).</summary>
    public long MinValue { get; init; }

    /// <summary>Maximum value (as long for int/long, as bit-cast long for float/double).</summary>
    public long MaxValue { get; init; }

    /// <summary>
    /// Equi-depth histogram bucket boundaries (stored as long).
    /// Each bucket covers approximately <c>RowCount / BucketCount</c> rows.
    /// A null/empty array means no histogram was built (too few rows).
    /// Bucket count adapts to min(<see cref="MaxBucketCount"/>, distinct, validRowCount).
    /// </summary>
    public long[]? HistogramBoundaries { get; init; }

    /// <summary>Whether the column stores floating-point data (min/max are bit-cast).</summary>
    public bool IsFloatingPoint { get; init; }

    /// <summary>Maximum bucket count for equi-depth histograms.</summary>
    internal const int MaxBucketCount = 64;

    /// <summary>Minimum number of valid rows required to build a histogram.</summary>
    internal const int MinRowsForHistogram = 8;
}

/// <summary>
/// Estimates query clause selectivity and overall query cost using
/// per-column statistics from <see cref="ColumnarStore"/>.
///
/// <para>Selectivity is a value in [0, 1] representing the estimated fraction
/// of rows that match a predicate. A selectivity of 0.01 means ~1% of rows
/// match. Lower selectivity = more selective = fewer rows = cheaper.</para>
///
/// <para><b>Cost model:</b></para>
/// <list type="bullet">
///   <item><c>EstimatedRows = RowCount × ∏(selectivity per clause)</c></item>
///   <item><c>ScanCost = EstimatedRows × CostPerRow(path)</c></item>
///   <item>Clause reordering: most selective clause first → early termination via AND bitmask</item>
/// </list>
/// </summary>
internal static class QueryCostEstimator
{
    // ── Cost multipliers per execution path ──────────────────────────────────

    /// <summary>Cost per row for full scalar evaluation (property access + comparison).</summary>
    internal const double CostScalarScan = 1.0;

    /// <summary>Cost per row for SIMD columnar scan (dense array + vector ops).</summary>
    internal const double CostColumnarScan = 0.3;

    /// <summary>Cost per row for index lookup (hash/tree probe + ID resolution).</summary>
    internal const double CostIndexLookup = 0.1;

    /// <summary>Fixed overhead for extracting columns from objects into the columnar store.</summary>
    internal const double CostColumnExtraction = 50.0;

    // ── Selectivity estimation ──────────────────────────────────────────────

    /// <summary>
    /// Estimates the selectivity of a single <see cref="QueryClause"/> given
    /// column statistics. Returns a value in [0, 1].
    /// </summary>
    /// <param name="clause">The query predicate.</param>
    /// <param name="stats">Column statistics (may be default if unavailable).</param>
    /// <returns>Estimated fraction of rows matching the clause.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static double EstimateSelectivity(QueryClause clause, ColumnStats stats)
    {
        if (stats.RowCount == 0)
            return 1.0; // no stats → assume all rows match (conservative)

        int distinct = stats.DistinctCount > 0 ? stats.DistinctCount : 1;

        return clause.Operator switch
        {
            // Equality: uniform assumption → 1/distinct
            QueryOperator.Equals => 1.0 / distinct,

            // Not-equals: complement of equality
            QueryOperator.NotEquals => 1.0 - (1.0 / distinct),

            // Range operators: use histogram if available, else uniform assumption
            QueryOperator.GreaterThan        => EstimateRangeSelectivity(stats, clause.Value, upper: true, inclusive: false),
            QueryOperator.GreaterThanOrEqual => EstimateRangeSelectivity(stats, clause.Value, upper: true, inclusive: true),
            QueryOperator.LessThan           => EstimateRangeSelectivity(stats, clause.Value, upper: false, inclusive: false),
            QueryOperator.LessThanOrEqual    => EstimateRangeSelectivity(stats, clause.Value, upper: false, inclusive: true),

            // Contains/StartsWith/EndsWith: heuristic — typically low selectivity
            QueryOperator.Contains   => 0.10,
            QueryOperator.StartsWith => 0.05,
            QueryOperator.EndsWith   => 0.10,

            // IN: each value ≈ 1/distinct, capped at 1.0
            QueryOperator.In    => EstimateInSelectivity(clause.Value, distinct),
            QueryOperator.NotIn => 1.0 - EstimateInSelectivity(clause.Value, distinct),

            _ => 0.5, // unknown operator — 50%
        };
    }

    /// <summary>
    /// Estimates the total number of matching rows for a multi-clause AND query.
    /// Assumes clause independence (multiply selectivities).
    /// </summary>
    internal static double EstimateResultRows(
        int rowCount,
        IReadOnlyList<QueryClause> clauses,
        IReadOnlyDictionary<string, ColumnStats> statsMap)
    {
        double selectivity = 1.0;
        for (int i = 0; i < clauses.Count; i++)
        {
            var clause = clauses[i];
            if (string.IsNullOrEmpty(clause.Field)) continue;

            statsMap.TryGetValue(clause.Field, out var stats);
            selectivity *= EstimateSelectivity(clause, stats);
        }
        return rowCount * selectivity;
    }

    /// <summary>
    /// Returns clause indexes sorted by estimated selectivity (most selective first).
    /// This enables the SIMD AND-chain to eliminate rows as early as possible.
    /// </summary>
    internal static int[] OrderClausesBySelectivity(
        IReadOnlyList<QueryClause> clauses,
        IReadOnlyDictionary<string, ColumnStats> statsMap)
    {
        int n = clauses.Count;
        var indexed = new (int Index, double Selectivity)[n];
        for (int i = 0; i < n; i++)
        {
            var clause = clauses[i];
            statsMap.TryGetValue(clause.Field ?? "", out var stats);
            indexed[i] = (i, EstimateSelectivity(clause, stats));
        }

        // Sort ascending by selectivity (most selective = smallest fraction first)
        Array.Sort(indexed, static (a, b) => a.Selectivity.CompareTo(b.Selectivity));

        var order = new int[n];
        for (int i = 0; i < n; i++)
            order[i] = indexed[i].Index;
        return order;
    }

    /// <summary>
    /// Compares estimated cost of SIMD columnar scan vs scalar scan.
    /// Returns <c>true</c> if the columnar path is cheaper.
    /// </summary>
    internal static bool ShouldUseColumnarPath(
        int rowCount,
        IReadOnlyList<QueryClause> clauses,
        IReadOnlyDictionary<string, ColumnStats> statsMap)
    {
        double estimatedRows = EstimateResultRows(rowCount, clauses, statsMap);

        // Columnar cost: extraction overhead + per-row SIMD scan
        double columnarCost = CostColumnExtraction + (rowCount * CostColumnarScan);

        // Scalar cost: per-row full evaluation (but only on matching rows after first clause)
        double scalarCost = rowCount * CostScalarScan;

        return columnarCost < scalarCost;
    }

    /// <summary>
    /// Builds a diagnostic cost breakdown for a query.
    /// </summary>
    internal static QueryCostBreakdown EstimateCost(
        int rowCount,
        IReadOnlyList<QueryClause> clauses,
        IReadOnlyDictionary<string, ColumnStats> statsMap)
    {
        double totalSelectivity = 1.0;
        var perClause = new ClauseCostDetail[clauses.Count];

        for (int i = 0; i < clauses.Count; i++)
        {
            var clause = clauses[i];
            statsMap.TryGetValue(clause.Field ?? "", out var stats);
            double sel = EstimateSelectivity(clause, stats);
            totalSelectivity *= sel;

            perClause[i] = new ClauseCostDetail
            {
                Field = clause.Field ?? "",
                Operator = clause.Operator,
                Selectivity = sel,
                EstimatedMatchingRows = (int)(rowCount * sel),
                HasStats = stats.RowCount > 0,
                DistinctValues = stats.DistinctCount,
            };
        }

        double estimatedRows = rowCount * totalSelectivity;
        bool useColumnar = ShouldUseColumnarPath(rowCount, clauses, statsMap);

        return new QueryCostBreakdown
        {
            TotalRows = rowCount,
            EstimatedResultRows = (int)estimatedRows,
            TotalSelectivity = totalSelectivity,
            RecommendedPath = useColumnar ? ScanPath.Columnar : ScanPath.Scalar,
            EstimatedCost = useColumnar
                ? CostColumnExtraction + (rowCount * CostColumnarScan)
                : rowCount * CostScalarScan,
            ClauseDetails = perClause,
            ClauseOrder = OrderClausesBySelectivity(clauses, statsMap),
        };
    }

    // ── Private helpers ─────────────────────────────────────────────────────

    private static double EstimateRangeSelectivity(
        ColumnStats stats, object? value, bool upper, bool inclusive)
    {
        if (stats.MinValue == stats.MaxValue)
            return 0.5; // degenerate range

        // Try to position the target within [min, max]
        long target;
        if (stats.IsFloatingPoint)
        {
            if (value is double d) target = BitConverter.DoubleToInt64Bits(d);
            else if (value is float f) target = (long)BitConverter.SingleToInt32Bits(f);
            else return 0.33; // can't position → default
        }
        else
        {
            if (!TryConvertToLong(value, out target))
                return 0.33;
        }

        // Linear interpolation within [min, max]
        double range = (double)(stats.MaxValue - stats.MinValue);
        if (range == 0) return 0.5;

        double position = (double)(target - stats.MinValue) / range;
        position = Math.Clamp(position, 0.0, 1.0);

        // For > / >=: fraction above target; for < / <=: fraction below
        double sel = upper ? (1.0 - position) : position;

        // Inclusive adds ~1/distinct more rows
        if (inclusive && stats.DistinctCount > 0)
            sel += 1.0 / stats.DistinctCount;

        return Math.Clamp(sel, 0.001, 1.0);
    }

    private static double EstimateInSelectivity(object? value, int distinct)
    {
        int count = 1;
        if (value is System.Collections.ICollection col)
            count = col.Count;
        else if (value is string s && s.Contains(','))
            count = CountCommas(s) + 1;

        return Math.Min(1.0, (double)count / distinct);
    }

    private static int CountCommas(string s)
    {
        int count = 0;
        for (int i = 0; i < s.Length; i++)
            if (s[i] == ',') count++;
        return count;
    }

    private static bool TryConvertToLong(object? value, out long result)
    {
        result = 0;
        if (value is null) return false;
        if (value is int i) { result = i; return true; }
        if (value is long l) { result = l; return true; }
        if (value is short sh) { result = sh; return true; }
        if (value is uint ui) { result = ui; return true; }
        if (value is byte b) { result = b; return true; }
        if (value is string s && long.TryParse(s, out result)) return true;
        return false;
    }
}

/// <summary>
/// Builds and caches <see cref="ColumnStats"/> per entity per field.
/// Thread-safe: <see cref="ConcurrentDictionary{TKey,TValue}"/> handles concurrent reads/writes.
/// Stats are rebuilt atomically during <see cref="ColumnarStore.Build{T}"/> and become
/// stale after incremental <c>UpsertRow</c> / <c>RemoveRow</c> operations.
/// </summary>
internal sealed class ColumnStatsRegistry
{
    // entityName → (fieldName → stats)
    private readonly ConcurrentDictionary<string, Dictionary<string, ColumnStats>> _registry = new(StringComparer.OrdinalIgnoreCase);

    // Tracks whether stats have been invalidated by incremental mutations.
    private readonly ConcurrentDictionary<string, bool> _stale = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Collects statistics for all numeric columns during a columnar store build.
    /// Called from <see cref="ColumnarStore.Build{T}"/> after columns are populated.
    /// </summary>
    internal void CollectStats(string entityName, Dictionary<string, int[]> intCols,
        Dictionary<string, long[]> longCols, Dictionary<string, double[]> doubleCols,
        Dictionary<string, float[]> floatCols, ulong[] validMask, int rowCount)
    {
        var stats = new Dictionary<string, ColumnStats>(StringComparer.OrdinalIgnoreCase);

        foreach (var (name, col) in intCols)
            stats[name] = BuildIntStats(col, validMask, rowCount);

        foreach (var (name, col) in longCols)
            stats[name] = BuildLongStats(col, validMask, rowCount);

        foreach (var (name, col) in doubleCols)
            stats[name] = BuildDoubleStats(col, validMask, rowCount);

        foreach (var (name, col) in floatCols)
            stats[name] = BuildFloatStats(col, validMask, rowCount);

        _registry[entityName] = stats;
        _stale[entityName] = false;
    }

    /// <summary>Returns stats for a specific entity, or an empty dictionary if none collected.</summary>
    internal IReadOnlyDictionary<string, ColumnStats> GetStats(string entityName)
    {
        if (_registry.TryGetValue(entityName, out var stats))
            return stats;
        return EmptyStats;
    }

    /// <summary>
    /// Returns the RowCount from any column's stats for the given entity,
    /// or -1 if no stats are available (used by QueryPlanner as a cardinality hint).
    /// </summary>
    internal int GetRowCount(string entityName)
    {
        if (!_registry.TryGetValue(entityName, out var stats))
            return -1;
        foreach (var s in stats.Values)
            return s.RowCount;
        return -1;
    }

    /// <summary>Marks stats as stale for the given entity (after UpsertRow/RemoveRow).</summary>
    internal void MarkStale(string entityName) => _stale[entityName] = true;

    /// <summary>Returns true if stats for the given entity have been invalidated by incremental mutations.</summary>
    internal bool IsStale(string entityName) =>
        !_stale.TryGetValue(entityName, out var stale) || stale;

    private static readonly Dictionary<string, ColumnStats> EmptyStats = new();

    // ── Per-type stat builders ──────────────────────────────────────────────

    private static ColumnStats BuildIntStats(int[] col, ulong[] validMask, int rowCount)
    {
        int min = int.MaxValue, max = int.MinValue;
        int validCount = 0, n = Math.Min(rowCount, col.Length);

        // First pass: min/max + count valid rows
        for (int i = 0; i < n; i++)
        {
            if (!IsValid(validMask, i)) continue;
            int v = col[i];
            if (v < min) min = v;
            if (v > max) max = v;
            validCount++;
        }

        int nullCount = n - validCount;

        // Distinct count via sort-based approach (avoids HashSet allocation)
        int distinct = CountDistinctInt(col, validMask, n, validCount);

        return new ColumnStats
        {
            RowCount = validCount,
            DistinctCount = distinct,
            NullCount = nullCount,
            MinValue = min == int.MaxValue ? 0 : min,
            MaxValue = max == int.MinValue ? 0 : max,
            IsFloatingPoint = false,
            HistogramBoundaries = BuildHistogramInt(col, validMask, n, validCount, distinct),
        };
    }

    private static ColumnStats BuildLongStats(long[] col, ulong[] validMask, int rowCount)
    {
        long min = long.MaxValue, max = long.MinValue;
        int validCount = 0, n = Math.Min(rowCount, col.Length);

        for (int i = 0; i < n; i++)
        {
            if (!IsValid(validMask, i)) continue;
            long v = col[i];
            if (v < min) min = v;
            if (v > max) max = v;
            validCount++;
        }

        int nullCount = n - validCount;
        int distinct = CountDistinctLong(col, validMask, n, validCount);

        return new ColumnStats
        {
            RowCount = validCount,
            DistinctCount = distinct,
            NullCount = nullCount,
            MinValue = min == long.MaxValue ? 0 : min,
            MaxValue = max == long.MinValue ? 0 : max,
            IsFloatingPoint = false,
            HistogramBoundaries = BuildHistogramLong(col, validMask, n, validCount, distinct),
        };
    }

    private static ColumnStats BuildDoubleStats(double[] col, ulong[] validMask, int rowCount)
    {
        double min = double.MaxValue, max = double.MinValue;
        int validCount = 0, n = Math.Min(rowCount, col.Length);

        for (int i = 0; i < n; i++)
        {
            if (!IsValid(validMask, i)) continue;
            double v = col[i];
            if (v < min) min = v;
            if (v > max) max = v;
            validCount++;
        }

        int nullCount = n - validCount;
        int distinct = CountDistinctDouble(col, validMask, n, validCount);

        return new ColumnStats
        {
            RowCount = validCount,
            DistinctCount = distinct,
            NullCount = nullCount,
            MinValue = min == double.MaxValue ? 0 : BitConverter.DoubleToInt64Bits(min),
            MaxValue = max == double.MinValue ? 0 : BitConverter.DoubleToInt64Bits(max),
            IsFloatingPoint = true,
            HistogramBoundaries = BuildHistogramDouble(col, validMask, n, validCount, distinct),
        };
    }

    private static ColumnStats BuildFloatStats(float[] col, ulong[] validMask, int rowCount)
    {
        float min = float.MaxValue, max = float.MinValue;
        int validCount = 0, n = Math.Min(rowCount, col.Length);

        for (int i = 0; i < n; i++)
        {
            if (!IsValid(validMask, i)) continue;
            float v = col[i];
            if (v < min) min = v;
            if (v > max) max = v;
            validCount++;
        }

        int nullCount = n - validCount;
        int distinct = CountDistinctFloat(col, validMask, n, validCount);

        return new ColumnStats
        {
            RowCount = validCount,
            DistinctCount = distinct,
            NullCount = nullCount,
            MinValue = min == float.MaxValue ? 0 : (long)BitConverter.SingleToInt32Bits(min),
            MaxValue = max == float.MinValue ? 0 : (long)BitConverter.SingleToInt32Bits(max),
            IsFloatingPoint = true,
            HistogramBoundaries = BuildHistogramFloat(col, validMask, n, validCount, distinct),
        };
    }

    // ── Sort-based distinct counting (avoids HashSet allocation) ────────────
    // Rents a temp array from ArrayPool, copies valid values, sorts, counts unique.

    private static int CountDistinctInt(int[] col, ulong[] validMask, int n, int validCount)
    {
        if (validCount == 0) return 0;
        var buf = ArrayPool<int>.Shared.Rent(validCount);
        int c = 0;
        for (int i = 0; i < n; i++)
        {
            if (!IsValid(validMask, i)) continue;
            buf[c++] = col[i];
        }
        Array.Sort(buf, 0, c);
        int distinct = 1;
        for (int i = 1; i < c; i++)
            if (buf[i] != buf[i - 1]) distinct++;
        ArrayPool<int>.Shared.Return(buf);
        return distinct;
    }

    private static int CountDistinctLong(long[] col, ulong[] validMask, int n, int validCount)
    {
        if (validCount == 0) return 0;
        var buf = ArrayPool<long>.Shared.Rent(validCount);
        int c = 0;
        for (int i = 0; i < n; i++)
        {
            if (!IsValid(validMask, i)) continue;
            buf[c++] = col[i];
        }
        Array.Sort(buf, 0, c);
        int distinct = 1;
        for (int i = 1; i < c; i++)
            if (buf[i] != buf[i - 1]) distinct++;
        ArrayPool<long>.Shared.Return(buf);
        return distinct;
    }

    private static int CountDistinctDouble(double[] col, ulong[] validMask, int n, int validCount)
    {
        if (validCount == 0) return 0;
        // Bit-cast to long for exact equality (avoids NaN != NaN issues)
        var buf = ArrayPool<long>.Shared.Rent(validCount);
        int c = 0;
        for (int i = 0; i < n; i++)
        {
            if (!IsValid(validMask, i)) continue;
            buf[c++] = BitConverter.DoubleToInt64Bits(col[i]);
        }
        Array.Sort(buf, 0, c);
        int distinct = 1;
        for (int i = 1; i < c; i++)
            if (buf[i] != buf[i - 1]) distinct++;
        ArrayPool<long>.Shared.Return(buf);
        return distinct;
    }

    private static int CountDistinctFloat(float[] col, ulong[] validMask, int n, int validCount)
    {
        if (validCount == 0) return 0;
        var buf = ArrayPool<int>.Shared.Rent(validCount);
        int c = 0;
        for (int i = 0; i < n; i++)
        {
            if (!IsValid(validMask, i)) continue;
            buf[c++] = BitConverter.SingleToInt32Bits(col[i]);
        }
        Array.Sort(buf, 0, c);
        int distinct = 1;
        for (int i = 1; i < c; i++)
            if (buf[i] != buf[i - 1]) distinct++;
        ArrayPool<int>.Shared.Return(buf);
        return distinct;
    }

    // ── Histogram builders ──────────────────────────────────────────────────
    // Adaptive bucket count: min(MaxBucketCount, distinct, validCount).
    // Requires at least MinRowsForHistogram valid rows and ≥ 2 distinct values.

    private static long[]? BuildHistogramInt(int[] col, ulong[] validMask, int n, int validCount, int distinct)
    {
        if (validCount < ColumnStats.MinRowsForHistogram || distinct < 2)
            return null;

        var buf = ArrayPool<int>.Shared.Rent(validCount);
        int c = 0;
        for (int i = 0; i < n; i++)
        {
            if (!IsValid(validMask, i)) continue;
            buf[c++] = col[i];
        }
        Array.Sort(buf, 0, c);

        int buckets = Math.Min(ColumnStats.MaxBucketCount, Math.Min(distinct, c));
        var boundaries = new long[buckets + 1];
        for (int b = 0; b <= buckets; b++)
        {
            int idx = (int)((long)b * (c - 1) / buckets);
            boundaries[b] = buf[idx];
        }
        ArrayPool<int>.Shared.Return(buf);
        return boundaries;
    }

    private static long[]? BuildHistogramLong(long[] col, ulong[] validMask, int n, int validCount, int distinct)
    {
        if (validCount < ColumnStats.MinRowsForHistogram || distinct < 2)
            return null;

        var buf = ArrayPool<long>.Shared.Rent(validCount);
        int c = 0;
        for (int i = 0; i < n; i++)
        {
            if (!IsValid(validMask, i)) continue;
            buf[c++] = col[i];
        }
        Array.Sort(buf, 0, c);

        int buckets = Math.Min(ColumnStats.MaxBucketCount, Math.Min(distinct, c));
        var boundaries = new long[buckets + 1];
        for (int b = 0; b <= buckets; b++)
        {
            int idx = (int)((long)b * (c - 1) / buckets);
            boundaries[b] = buf[idx];
        }
        ArrayPool<long>.Shared.Return(buf);
        return boundaries;
    }

    private static long[]? BuildHistogramDouble(double[] col, ulong[] validMask, int n, int validCount, int distinct)
    {
        if (validCount < ColumnStats.MinRowsForHistogram || distinct < 2)
            return null;

        // Sort by bit-cast representation for consistent ordering with stats min/max
        var buf = ArrayPool<long>.Shared.Rent(validCount);
        int c = 0;
        for (int i = 0; i < n; i++)
        {
            if (!IsValid(validMask, i)) continue;
            buf[c++] = BitConverter.DoubleToInt64Bits(col[i]);
        }
        Array.Sort(buf, 0, c);

        int buckets = Math.Min(ColumnStats.MaxBucketCount, Math.Min(distinct, c));
        var boundaries = new long[buckets + 1];
        for (int b = 0; b <= buckets; b++)
        {
            int idx = (int)((long)b * (c - 1) / buckets);
            boundaries[b] = buf[idx];
        }
        ArrayPool<long>.Shared.Return(buf);
        return boundaries;
    }

    private static long[]? BuildHistogramFloat(float[] col, ulong[] validMask, int n, int validCount, int distinct)
    {
        if (validCount < ColumnStats.MinRowsForHistogram || distinct < 2)
            return null;

        // Bit-cast to int for sort; store as long in boundaries for consistency
        var buf = ArrayPool<int>.Shared.Rent(validCount);
        int c = 0;
        for (int i = 0; i < n; i++)
        {
            if (!IsValid(validMask, i)) continue;
            buf[c++] = BitConverter.SingleToInt32Bits(col[i]);
        }
        Array.Sort(buf, 0, c);

        int buckets = Math.Min(ColumnStats.MaxBucketCount, Math.Min(distinct, c));
        var boundaries = new long[buckets + 1];
        for (int b = 0; b <= buckets; b++)
        {
            int idx = (int)((long)b * (c - 1) / buckets);
            boundaries[b] = (long)buf[idx];
        }
        ArrayPool<int>.Shared.Return(buf);
        return boundaries;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsValid(ulong[] validMask, int ordinal)
    {
        int word = ordinal >> 6;
        int bit = ordinal & 63;
        return word < validMask.Length && (validMask[word] & (1UL << bit)) != 0;
    }
}

/// <summary>Execution path recommendation.</summary>
internal enum ScanPath
{
    /// <summary>Per-row property-based evaluation.</summary>
    Scalar,
    /// <summary>SIMD vectorised columnar scan.</summary>
    Columnar,
    /// <summary>Index probe (hash or tree).</summary>
    Index,
}

/// <summary>
/// Full cost breakdown for a query — used for diagnostics, EXPLAIN output,
/// and plan selection. Struct to avoid allocation on the query hot path.
/// </summary>
internal readonly struct QueryCostBreakdown
{
    /// <summary>Total rows in the entity store.</summary>
    public int TotalRows { get; init; }

    /// <summary>Estimated rows after all filters applied.</summary>
    public int EstimatedResultRows { get; init; }

    /// <summary>Product of all clause selectivities.</summary>
    public double TotalSelectivity { get; init; }

    /// <summary>Recommended execution path.</summary>
    public ScanPath RecommendedPath { get; init; }

    /// <summary>Estimated total cost units.</summary>
    public double EstimatedCost { get; init; }

    /// <summary>Per-clause detail.</summary>
    public ClauseCostDetail[] ClauseDetails { get; init; }

    /// <summary>Optimal clause execution order (most selective first).</summary>
    public int[] ClauseOrder { get; init; }
}

/// <summary>Cost detail for a single query clause.</summary>
internal readonly struct ClauseCostDetail
{
    public string Field { get; init; }
    public QueryOperator Operator { get; init; }
    public double Selectivity { get; init; }
    public int EstimatedMatchingRows { get; init; }
    public bool HasStats { get; init; }
    public int DistinctValues { get; init; }
}
