using System.Numerics;
using System.Runtime.CompilerServices;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Batch-vectorised query executor for flat (non-nested) queries.
///
/// <para>When a full-table scan is required, loading every row and evaluating predicates
/// one at a time via reflection is slow for large datasets. This executor takes a
/// different approach: after all rows are loaded into memory, it extracts each
/// queried field into a typed column array (int[], long[], double[], float[]) and
/// then sweeps those arrays with <see cref="Vector{T}"/> portable SIMD instructions,
/// producing a per-row <c>ulong[]</c> bitmask. Multi-clause AND queries are composed
/// via bitmask intersection using SIMD <c>ulong</c> AND. The final result set is
/// materialised by iterating set bits.</para>
///
/// <para>Unsupported clause types (Contains, StartsWith, EndsWith, In, NotIn, and
/// all string fields) automatically fall back to a scalar per-row loop that still
/// writes into the shared bitmask, so correctness is maintained for any mix of
/// vectorisable and non-vectorisable predicates.</para>
///
/// <para>Activation threshold: <see cref="VectorizationThreshold"/> rows (default 256).
/// Below this threshold column-extraction overhead outweighs any SIMD benefit.
/// Eligibility also requires <c>query.Groups.Count == 0</c> (nested OR groups are
/// not handled by this path).</para>
/// </summary>
internal static class ColumnQueryExecutor
{
    /// <summary>
    /// Minimum number of rows needed before the column-extraction overhead is
    /// worth paying.  Below this threshold the caller should use the scalar path.
    /// </summary>
    internal const int VectorizationThreshold = 256;

    /// <summary>
    /// Returns <c>true</c> when the row count and query shape make the vectorised
    /// path worth activating.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static bool IsEligible<T>(IReadOnlyList<T> rows, QueryDefinition? query)
        where T : BaseDataObject
        => query != null
           && rows.Count >= VectorizationThreshold
           && query.Groups.Count == 0
           && query.Clauses.Count > 0;

    /// <summary>
    /// Filters <paramref name="rows"/> using vectorised column scans, honouring
    /// <paramref name="skip"/> and <paramref name="top"/> for pagination.
    /// </summary>
    internal static List<T> Filter<T>(
        IReadOnlyList<T> rows,
        QueryDefinition query,
        int skip = 0,
        int top = int.MaxValue)
        where T : BaseDataObject
    {
        var meta = DataScaffold.GetEntityByType(typeof(T));
        if (meta == null)
            return ScalarFallback(rows, query, skip, top);

        int n = rows.Count;
        int wordCount = (n + 63) >> 6;
        ulong[]? combined = null;

        foreach (var clause in query.Clauses)
        {
            if (string.IsNullOrEmpty(clause.Field)) continue;
            var field = meta.FindField(clause.Field);
            if (field == null) continue;

            var clauseMask = BuildClauseMask(rows, clause, field, n, wordCount);
            if (clauseMask == null) return new List<T>(0);

            if (combined == null)
                combined = clauseMask;
            else
                AndInPlace(combined, clauseMask);

            if (IsAllZeros(combined)) return new List<T>(0);
        }

        return combined == null
            ? Slice(rows, skip, top)
            : Materialize(rows, combined, n, skip, top);
    }

    // Static shared evaluator — DataQueryEvaluator is stateless (debug hook aside).
    private static readonly DataQueryEvaluator _sharedEvaluator = new();

    private static ulong[]? BuildClauseMask<T>(
        IReadOnlyList<T> rows,
        QueryClause clause,
        DataFieldMetadata field,
        int n,
        int wordCount)
        where T : BaseDataObject
    {
        var propType = Nullable.GetUnderlyingType(field.ClrType) ?? field.ClrType;

        // Int-range types: int, uint, short, ushort, byte, sbyte, bool, enum
        if (IsIntType(propType) && TryConvertToInt(clause.Value, propType, out int iTarget))
            return ScanIntColumn(rows, clause.Operator, field, iTarget, n, wordCount);

        // Long-range types: long, ulong, DateTime, DateOnly, DateTimeOffset, TimeOnly, TimeSpan
        if (IsLongType(propType) && TryConvertToLong(clause.Value, propType, out long lTarget))
            return ScanLongColumn(rows, clause.Operator, field, lTarget, n, wordCount);

        // Double types: double, decimal
        if (IsDoubleType(propType) && TryConvertToDouble(clause.Value, out double dTarget))
            return ScanDoubleColumn(rows, clause.Operator, field, dTarget, n, wordCount);

        // Float type
        if (IsFloatType(propType) && TryConvertToFloat(clause.Value, out float fTarget))
            return ScanFloatColumn(rows, clause.Operator, field, fTarget, n, wordCount);

        // Strings, GUIDs, unsupported operators (Contains, StartsWith …): scalar per-row
        return ScanScalarClause(rows, clause, n, wordCount);
    }

    // ── Typed column scans ─────────────────────────────────────────────────

    private static ulong[] ScanIntColumn<T>(
        IReadOnlyList<T> rows,
        QueryOperator op,
        DataFieldMetadata field,
        int target,
        int n,
        int wordCount)
        where T : BaseDataObject
    {
        var bitmask = new ulong[wordCount];
        var column  = new int[n];
        var getter  = field.GetValueFn;
        for (int i = 0; i < n; i++) column[i] = ToInt(getter(rows[i]));

        int vLen      = Vector<int>.Count;
        var targetVec = new Vector<int>(target);
        int idx       = 0;

        for (; idx <= n - vLen; idx += vLen)
        {
            var chunk = new Vector<int>(column, idx);
            var mask  = ApplyIntOp(op, chunk, targetVec);
            WriteToBitmask(bitmask, mask, idx, vLen);
        }
        for (; idx < n; idx++)
            if (EvalIntScalar(op, column[idx], target))
                bitmask[idx >> 6] |= 1UL << (idx & 63);

        return bitmask;
    }

    private static ulong[] ScanLongColumn<T>(
        IReadOnlyList<T> rows,
        QueryOperator op,
        DataFieldMetadata field,
        long target,
        int n,
        int wordCount)
        where T : BaseDataObject
    {
        var bitmask = new ulong[wordCount];
        var column  = new long[n];
        var getter  = field.GetValueFn;
        for (int i = 0; i < n; i++) column[i] = ToLong(getter(rows[i]));

        int vLen      = Vector<long>.Count;
        var targetVec = new Vector<long>(target);
        int idx       = 0;

        for (; idx <= n - vLen; idx += vLen)
        {
            var chunk = new Vector<long>(column, idx);
            var mask  = ApplyLongOp(op, chunk, targetVec);
            WriteToBitmask(bitmask, mask, idx, vLen);
        }
        for (; idx < n; idx++)
            if (EvalLongScalar(op, column[idx], target))
                bitmask[idx >> 6] |= 1UL << (idx & 63);

        return bitmask;
    }

    private static ulong[] ScanDoubleColumn<T>(
        IReadOnlyList<T> rows,
        QueryOperator op,
        DataFieldMetadata field,
        double target,
        int n,
        int wordCount)
        where T : BaseDataObject
    {
        var bitmask = new ulong[wordCount];
        var column  = new double[n];
        var getter  = field.GetValueFn;
        for (int i = 0; i < n; i++) column[i] = ToDouble(getter(rows[i]));

        int vLen      = Vector<double>.Count;
        var targetVec = new Vector<double>(target);
        int idx       = 0;

        for (; idx <= n - vLen; idx += vLen)
        {
            var chunk = new Vector<double>(column, idx);
            // Comparison ops on Vector<double> return Vector<long> (integer mask of same bitwidth).
            Vector<long> mask = ApplyDoubleOp(op, chunk, targetVec);
            WriteToBitmask(bitmask, mask, idx, vLen);
        }
        for (; idx < n; idx++)
            if (EvalDoubleScalar(op, column[idx], target))
                bitmask[idx >> 6] |= 1UL << (idx & 63);

        return bitmask;
    }

    private static ulong[] ScanFloatColumn<T>(
        IReadOnlyList<T> rows,
        QueryOperator op,
        DataFieldMetadata field,
        float target,
        int n,
        int wordCount)
        where T : BaseDataObject
    {
        var bitmask = new ulong[wordCount];
        var column  = new float[n];
        var getter  = field.GetValueFn;
        for (int i = 0; i < n; i++) column[i] = ToFloat(getter(rows[i]));

        int vLen      = Vector<float>.Count;
        var targetVec = new Vector<float>(target);
        int idx       = 0;

        for (; idx <= n - vLen; idx += vLen)
        {
            var chunk = new Vector<float>(column, idx);
            // Comparison ops on Vector<float> return Vector<int> (integer mask of same bitwidth).
            Vector<int> mask = ApplyFloatOp(op, chunk, targetVec);
            WriteToBitmask(bitmask, mask, idx, vLen);
        }
        for (; idx < n; idx++)
            if (EvalFloatScalar(op, column[idx], target))
                bitmask[idx >> 6] |= 1UL << (idx & 63);

        return bitmask;
    }

    // ── Scalar per-row fallback (strings, Contains, StartsWith, …) ─────────

    private static ulong[] ScanScalarClause<T>(
        IReadOnlyList<T> rows,
        QueryClause clause,
        int n,
        int wordCount)
        where T : BaseDataObject
    {
        var bitmask = new ulong[wordCount];
        // Wrap the single clause in a lightweight query for reuse across all rows.
        var singleQuery = new QueryDefinition { Clauses = { clause } };
        for (int i = 0; i < n; i++)
            if (_sharedEvaluator.Matches(rows[i], singleQuery))
                bitmask[i >> 6] |= 1UL << (i & 63);
        return bitmask;
    }

    // ── Vector operator helpers ────────────────────────────────────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector<int> ApplyIntOp(QueryOperator op, Vector<int> chunk, Vector<int> target) => op switch
    {
        QueryOperator.Equals             => Vector.Equals(chunk, target),
        QueryOperator.NotEquals          => Vector.OnesComplement(Vector.Equals(chunk, target)),
        QueryOperator.GreaterThan        => Vector.GreaterThan(chunk, target),
        QueryOperator.LessThan           => Vector.LessThan(chunk, target),
        QueryOperator.GreaterThanOrEqual => Vector.GreaterThanOrEqual(chunk, target),
        QueryOperator.LessThanOrEqual    => Vector.LessThanOrEqual(chunk, target),
        _                                => Vector<int>.Zero,
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector<long> ApplyLongOp(QueryOperator op, Vector<long> chunk, Vector<long> target) => op switch
    {
        QueryOperator.Equals             => Vector.Equals(chunk, target),
        QueryOperator.NotEquals          => Vector.OnesComplement(Vector.Equals(chunk, target)),
        QueryOperator.GreaterThan        => Vector.GreaterThan(chunk, target),
        QueryOperator.LessThan           => Vector.LessThan(chunk, target),
        QueryOperator.GreaterThanOrEqual => Vector.GreaterThanOrEqual(chunk, target),
        QueryOperator.LessThanOrEqual    => Vector.LessThanOrEqual(chunk, target),
        _                                => Vector<long>.Zero,
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector<long> ApplyDoubleOp(QueryOperator op, Vector<double> chunk, Vector<double> target) => op switch
    {
        QueryOperator.Equals             => Vector.Equals(chunk, target),
        QueryOperator.NotEquals          => Vector.OnesComplement(Vector.Equals(chunk, target)),
        QueryOperator.GreaterThan        => Vector.GreaterThan(chunk, target),
        QueryOperator.LessThan           => Vector.LessThan(chunk, target),
        QueryOperator.GreaterThanOrEqual => Vector.GreaterThanOrEqual(chunk, target),
        QueryOperator.LessThanOrEqual    => Vector.LessThanOrEqual(chunk, target),
        _                                => Vector<long>.Zero,
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector<int> ApplyFloatOp(QueryOperator op, Vector<float> chunk, Vector<float> target) => op switch
    {
        QueryOperator.Equals             => Vector.Equals(chunk, target),
        QueryOperator.NotEquals          => Vector.OnesComplement(Vector.Equals(chunk, target)),
        QueryOperator.GreaterThan        => Vector.GreaterThan(chunk, target),
        QueryOperator.LessThan           => Vector.LessThan(chunk, target),
        QueryOperator.GreaterThanOrEqual => Vector.GreaterThanOrEqual(chunk, target),
        QueryOperator.LessThanOrEqual    => Vector.LessThanOrEqual(chunk, target),
        _                                => Vector<int>.Zero,
    };

    // ── Scalar comparison helpers ──────────────────────────────────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool EvalIntScalar(QueryOperator op, int value, int target) => op switch
    {
        QueryOperator.Equals             => value == target,
        QueryOperator.NotEquals          => value != target,
        QueryOperator.GreaterThan        => value > target,
        QueryOperator.LessThan           => value < target,
        QueryOperator.GreaterThanOrEqual => value >= target,
        QueryOperator.LessThanOrEqual    => value <= target,
        _                                => false,
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool EvalLongScalar(QueryOperator op, long value, long target) => op switch
    {
        QueryOperator.Equals             => value == target,
        QueryOperator.NotEquals          => value != target,
        QueryOperator.GreaterThan        => value > target,
        QueryOperator.LessThan           => value < target,
        QueryOperator.GreaterThanOrEqual => value >= target,
        QueryOperator.LessThanOrEqual    => value <= target,
        _                                => false,
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool EvalDoubleScalar(QueryOperator op, double value, double target) => op switch
    {
        QueryOperator.Equals             => value == target,
        QueryOperator.NotEquals          => value != target,
        QueryOperator.GreaterThan        => value > target,
        QueryOperator.LessThan           => value < target,
        QueryOperator.GreaterThanOrEqual => value >= target,
        QueryOperator.LessThanOrEqual    => value <= target,
        _                                => false,
    };

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool EvalFloatScalar(QueryOperator op, float value, float target) => op switch
    {
        QueryOperator.Equals             => value == target,
        QueryOperator.NotEquals          => value != target,
        QueryOperator.GreaterThan        => value > target,
        QueryOperator.LessThan           => value < target,
        QueryOperator.GreaterThanOrEqual => value >= target,
        QueryOperator.LessThanOrEqual    => value <= target,
        _                                => false,
    };

    // ── Bitmask writers ────────────────────────────────────────────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteToBitmask(ulong[] bitmask, Vector<int> mask, int rowOffset, int vLen)
    {
        ulong contrib = 0;
        for (int j = 0; j < vLen; j++)
            if (mask[j] != 0) contrib |= 1UL << j;
        WriteMaskWord(bitmask, contrib, rowOffset, vLen);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteToBitmask(ulong[] bitmask, Vector<long> mask, int rowOffset, int vLen)
    {
        ulong contrib = 0;
        for (int j = 0; j < vLen; j++)
            if (mask[j] != 0L) contrib |= 1UL << j;
        WriteMaskWord(bitmask, contrib, rowOffset, vLen);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteMaskWord(ulong[] bitmask, ulong contrib, int rowOffset, int vLen)
    {
        if (contrib == 0) return;
        int wordIdx = rowOffset >> 6;
        int bitOff  = rowOffset & 63;
        bitmask[wordIdx] |= contrib << bitOff;
        // Handle cross-word spill (when the vector straddles a 64-bit word boundary).
        // The guard ensures we never write past the end of the bitmask array.
        if (bitOff + vLen > 64 && wordIdx + 1 < bitmask.Length)
            bitmask[wordIdx + 1] |= contrib >> (64 - bitOff);
    }

    // ── Bitmask AND (SIMD over ulong words) ───────────────────────────────

    private static void AndInPlace(ulong[] dest, ulong[] src)
    {
        int vLen = Vector<ulong>.Count;
        int i    = 0;
        for (; i <= dest.Length - vLen; i += vLen)
        {
            var d = new Vector<ulong>(dest, i);
            var s = new Vector<ulong>(src,  i);
            (d & s).CopyTo(dest, i);
        }
        for (; i < dest.Length; i++) dest[i] &= src[i];
    }

    private static bool IsAllZeros(ulong[] bitmask)
    {
        foreach (var w in bitmask)
            if (w != 0) return false;
        return true;
    }

    // ── Result materialisation ─────────────────────────────────────────────

    private static List<T> Materialize<T>(
        IReadOnlyList<T> rows,
        ulong[] bitmask,
        int n,
        int skip,
        int top)
        where T : BaseDataObject
    {
        var result  = new List<T>(Math.Min(top, n));
        int matched = 0;
        int added   = 0;

        for (int wordIdx = 0; wordIdx < bitmask.Length && added < top; wordIdx++)
        {
            ulong word = bitmask[wordIdx];
            while (word != 0)
            {
                int bit    = BitOperations.TrailingZeroCount(word);
                int rowIdx = (wordIdx << 6) | bit;
                word      &= word - 1;   // clear lowest set bit

                if (rowIdx >= n) break;
                if (matched++ < skip) continue;
                result.Add(rows[rowIdx]);
                added++;
                if (added >= top) break;
            }
        }
        return result;
    }

    // ── Type classification ────────────────────────────────────────────────

    private static bool IsIntType(Type t)
        => t == typeof(int)   || t == typeof(uint)  || t == typeof(short) || t == typeof(ushort)
        || t == typeof(byte)  || t == typeof(sbyte) || t == typeof(bool)  || t.IsEnum;

    private static bool IsLongType(Type t)
        => t == typeof(long)           || t == typeof(ulong)
        || t == typeof(DateTime)       || t == typeof(DateOnly)
        || t == typeof(DateTimeOffset) || t == typeof(TimeOnly)
        || t == typeof(TimeSpan);

    private static bool IsDoubleType(Type t) => t == typeof(double) || t == typeof(decimal);
    private static bool IsFloatType(Type t)  => t == typeof(float);

    // ── Clause-value conversion ────────────────────────────────────────────

    private static bool TryConvertToInt(object? value, Type targetType, out int result)
    {
        if (value == null) { result = 0; return false; }
        try
        {
            if (targetType.IsEnum)
            {
                object enumVal = value is string s
                    ? Enum.Parse(targetType, s, ignoreCase: true)
                    : value;
                result = (int)Convert.ChangeType(enumVal, typeof(int));
                return true;
            }
            if (value is bool b) { result = b ? 1 : 0; return true; }
            result = Convert.ToInt32(value);
            return true;
        }
        catch { result = 0; return false; }
    }

    private static bool TryConvertToLong(object? value, Type targetType, out long result)
    {
        if (value == null) { result = 0; return false; }
        try
        {
            if (targetType == typeof(DateTime) && value is string ds && DateTime.TryParse(ds, out var dt))
                { result = dt.Ticks; return true; }
            if (targetType == typeof(DateOnly) && value is string dos && DateOnly.TryParse(dos, out var d))
                { result = d.DayNumber; return true; }
            if (targetType == typeof(TimeOnly) && value is string tos && TimeOnly.TryParse(tos, out var to))
                { result = to.Ticks; return true; }
            if (targetType == typeof(TimeSpan) && value is string tss && TimeSpan.TryParse(tss, out var ts))
                { result = ts.Ticks; return true; }
            if (targetType == typeof(DateTimeOffset) && value is string dtos && DateTimeOffset.TryParse(dtos, out var dto))
                { result = dto.UtcTicks; return true; }
            result = Convert.ToInt64(value);
            return true;
        }
        catch { result = 0; return false; }
    }

    private static bool TryConvertToDouble(object? value, out double result)
    {
        if (value == null) { result = 0; return false; }
        try
        {
            if (value is decimal dec) { result = (double)dec; return true; }
            result = Convert.ToDouble(value);
            return true;
        }
        catch { result = 0; return false; }
    }

    private static bool TryConvertToFloat(object? value, out float result)
    {
        if (value == null) { result = 0; return false; }
        try { result = Convert.ToSingle(value); return true; }
        catch { result = 0; return false; }
    }

    // ── Row-value unboxing ─────────────────────────────────────────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int ToInt(object? v)
    {
        if (v is int i)    return i;
        if (v is bool b)   return b ? 1 : 0;
        if (v == null)     return 0;
        try { return Convert.ToInt32(v); } catch { return 0; }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static long ToLong(object? v)
    {
        if (v is long l)           return l;
        if (v is DateTime dt)      return dt.Ticks;
        if (v is DateOnly d)       return d.DayNumber;
        if (v is TimeOnly to)      return to.Ticks;
        if (v is TimeSpan ts)      return ts.Ticks;
        if (v is DateTimeOffset dto) return dto.UtcTicks;
        if (v == null)             return 0;
        try { return Convert.ToInt64(v); } catch { return 0; }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static double ToDouble(object? v)
    {
        if (v is double d)   return d;
        if (v is decimal dec) return (double)dec;
        if (v is float f)    return f;
        if (v == null)       return 0;
        try { return Convert.ToDouble(v); } catch { return 0; }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float ToFloat(object? v)
    {
        if (v is float f) return f;
        if (v == null)    return 0;
        try { return Convert.ToSingle(v); } catch { return 0; }
    }

    // ── Utility ────────────────────────────────────────────────────────────

    private static List<T> Slice<T>(IReadOnlyList<T> rows, int skip, int top)
    {
        int start = Math.Min(skip, rows.Count);
        int end   = Math.Min(start + top, rows.Count);
        var r     = new List<T>(end - start);
        for (int i = start; i < end; i++) r.Add(rows[i]);
        return r;
    }

    private static List<T> ScalarFallback<T>(
        IReadOnlyList<T> rows,
        QueryDefinition query,
        int skip,
        int top)
        where T : BaseDataObject
    {
        var result  = new List<T>(Math.Min(top, rows.Count));
        int matched = 0;
        foreach (var row in rows)
        {
            if (!_sharedEvaluator.Matches(row, query)) continue;
            if (matched++ < skip) continue;
            result.Add(row);
            if (result.Count >= top) break;
        }
        return result;
    }
}
