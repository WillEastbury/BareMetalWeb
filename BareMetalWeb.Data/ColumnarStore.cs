using System.Buffers;
using System.Numerics;
using System.Runtime.CompilerServices;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// In-memory columnar store for a single entity type.
/// Maintains dense typed arrays (one per numeric field) synced with row additions/removals.
/// Enables SIMD column scans without per-query object loading or property extraction.
///
/// <para>Lifecycle: created lazily on first vectorised query, invalidated on any write.
/// The columnar layout avoids the "load all objects, extract column, then scan" pattern
/// in <see cref="ColumnQueryExecutor"/> — arrays are pre-built and cache-friendly.</para>
/// </summary>
internal sealed class ColumnarStore
{
    private readonly Dictionary<string, int[]> _intColumns = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long[]> _longColumns = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, double[]> _doubleColumns = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, float[]> _floatColumns = new(StringComparer.OrdinalIgnoreCase);

    // Row index: maps object key → dense array position
    private readonly Dictionary<uint, int> _keyToRow = new();
    private uint[] _rowToKey;  // reverse map: dense position → object key
    private int _rowCount;

    // Stamp incremented on every mutation; callers compare to detect invalidation
    private long _version;

    public int RowCount => _rowCount;
    public long Version => _version;

    public ColumnarStore(int initialCapacity)
    {
        _rowToKey = new uint[Math.Max(initialCapacity, 64)];
    }

    /// <summary>
    /// Populates the store from a pre-loaded set of objects and their metadata.
    /// Called once during lazy initialisation.
    /// </summary>
    public void Build<T>(IReadOnlyList<T> objects, DataEntityMetadata meta) where T : BaseDataObject
    {
        _keyToRow.Clear();
        _intColumns.Clear();
        _longColumns.Clear();
        _doubleColumns.Clear();
        _floatColumns.Clear();

        int n = objects.Count;
        _rowCount = n;
        if (_rowToKey.Length < n)
            _rowToKey = new uint[n];

        // Identify numeric fields and allocate columns
        foreach (var field in meta.Fields)
        {
            var propType = Nullable.GetUnderlyingType(field.Property.PropertyType)
                           ?? field.Property.PropertyType;

            if (IsIntType(propType))
                _intColumns[field.Name] = new int[n];
            else if (IsLongType(propType))
                _longColumns[field.Name] = new long[n];
            else if (IsDoubleType(propType))
                _doubleColumns[field.Name] = new double[n];
            else if (IsFloatType(propType))
                _floatColumns[field.Name] = new float[n];
        }

        // Extract column values in a single pass over all objects
        for (int i = 0; i < n; i++)
        {
            var obj = objects[i];
            _keyToRow[obj.Key] = i;
            _rowToKey[i] = obj.Key;

            foreach (var field in meta.Fields)
            {
                var getter = field.GetValueFn;
                var val = getter(obj);

                if (_intColumns.TryGetValue(field.Name, out var intCol))
                    intCol[i] = ToInt(val);
                else if (_longColumns.TryGetValue(field.Name, out var longCol))
                    longCol[i] = ToLong(val);
                else if (_doubleColumns.TryGetValue(field.Name, out var dblCol))
                    dblCol[i] = ToDouble(val);
                else if (_floatColumns.TryGetValue(field.Name, out var fltCol))
                    fltCol[i] = ToFloat(val);
            }
        }

        _version++;
    }

    /// <summary>Marks the store as stale. Next query will trigger a rebuild.</summary>
    public void Invalidate() => Interlocked.Increment(ref _version);

    // ── Column access ─────────────────────────────────────────────────────────

    public bool TryGetIntColumn(string fieldName, out ReadOnlySpan<int> column)
    {
        if (_intColumns.TryGetValue(fieldName, out var arr))
        {
            column = arr.AsSpan(0, _rowCount);
            return true;
        }
        column = default;
        return false;
    }

    public bool TryGetLongColumn(string fieldName, out ReadOnlySpan<long> column)
    {
        if (_longColumns.TryGetValue(fieldName, out var arr))
        {
            column = arr.AsSpan(0, _rowCount);
            return true;
        }
        column = default;
        return false;
    }

    public bool TryGetDoubleColumn(string fieldName, out ReadOnlySpan<double> column)
    {
        if (_doubleColumns.TryGetValue(fieldName, out var arr))
        {
            column = arr.AsSpan(0, _rowCount);
            return true;
        }
        column = default;
        return false;
    }

    public bool TryGetFloatColumn(string fieldName, out ReadOnlySpan<float> column)
    {
        if (_floatColumns.TryGetValue(fieldName, out var arr))
        {
            column = arr.AsSpan(0, _rowCount);
            return true;
        }
        column = default;
        return false;
    }

    /// <summary>Returns the object key at the given dense row index.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint GetKeyAtRow(int rowIndex) => _rowToKey[rowIndex];

    /// <summary>
    /// Returns the set of field names that have columnar storage.
    /// Useful for checking which clause fields can use the fast path.
    /// </summary>
    public bool HasColumn(string fieldName)
        => _intColumns.ContainsKey(fieldName)
        || _longColumns.ContainsKey(fieldName)
        || _doubleColumns.ContainsKey(fieldName)
        || _floatColumns.ContainsKey(fieldName);

    // ── SIMD column scan ──────────────────────────────────────────────────────

    /// <summary>
    /// Scans a pre-built column using SIMD and returns a bitmask of matching rows.
    /// This is the hot path — no object loading, no property extraction, no boxing.
    /// </summary>
    public ulong[]? ScanClause(string fieldName, QueryOperator op, object? value, int wordCount)
    {
        if (_intColumns.TryGetValue(fieldName, out var intCol))
        {
            var propType = typeof(int); // simplified — all int-range are stored as int
            if (!TryConvertToInt(value, propType, out int iTarget)) return null;
            return ScanIntArray(intCol, op, iTarget, _rowCount, wordCount);
        }

        if (_longColumns.TryGetValue(fieldName, out var longCol))
        {
            if (!TryConvertToLong(value, typeof(long), out long lTarget)) return null;
            return ScanLongArray(longCol, op, lTarget, _rowCount, wordCount);
        }

        if (_doubleColumns.TryGetValue(fieldName, out var dblCol))
        {
            if (!TryConvertToDouble(value, out double dTarget)) return null;
            return ScanDoubleArray(dblCol, op, dTarget, _rowCount, wordCount);
        }

        if (_floatColumns.TryGetValue(fieldName, out var fltCol))
        {
            if (!TryConvertToFloat(value, out float fTarget)) return null;
            return ScanFloatArray(fltCol, op, fTarget, _rowCount, wordCount);
        }

        return null; // field not in columnar store
    }

    // ── Typed array scans (no object access, pure array SIMD) ─────────────────

    private static ulong[] ScanIntArray(int[] column, QueryOperator op, int target, int n, int wordCount)
    {
        var bitmask = new ulong[wordCount];
        int vLen = Vector<int>.Count;
        var targetVec = new Vector<int>(target);
        int idx = 0;

        for (; idx <= n - vLen; idx += vLen)
        {
            var chunk = new Vector<int>(column, idx);
            var mask = ApplyIntOp(op, chunk, targetVec);
            WriteToBitmask(bitmask, mask, idx, vLen);
        }
        for (; idx < n; idx++)
            if (EvalScalar(op, column[idx], target))
                bitmask[idx >> 6] |= 1UL << (idx & 63);

        return bitmask;
    }

    private static ulong[] ScanLongArray(long[] column, QueryOperator op, long target, int n, int wordCount)
    {
        var bitmask = new ulong[wordCount];
        int vLen = Vector<long>.Count;
        var targetVec = new Vector<long>(target);
        int idx = 0;

        for (; idx <= n - vLen; idx += vLen)
        {
            var chunk = new Vector<long>(column, idx);
            var mask = ApplyLongOp(op, chunk, targetVec);
            WriteToBitmask(bitmask, mask, idx, vLen);
        }
        for (; idx < n; idx++)
            if (EvalScalar(op, column[idx], target))
                bitmask[idx >> 6] |= 1UL << (idx & 63);

        return bitmask;
    }

    private static ulong[] ScanDoubleArray(double[] column, QueryOperator op, double target, int n, int wordCount)
    {
        var bitmask = new ulong[wordCount];
        int vLen = Vector<double>.Count;
        var targetVec = new Vector<double>(target);
        int idx = 0;

        for (; idx <= n - vLen; idx += vLen)
        {
            var chunk = new Vector<double>(column, idx);
            Vector<long> mask = ApplyDoubleOp(op, chunk, targetVec);
            WriteToBitmask(bitmask, mask, idx, vLen);
        }
        for (; idx < n; idx++)
            if (EvalScalar(op, column[idx], target))
                bitmask[idx >> 6] |= 1UL << (idx & 63);

        return bitmask;
    }

    private static ulong[] ScanFloatArray(float[] column, QueryOperator op, float target, int n, int wordCount)
    {
        var bitmask = new ulong[wordCount];
        int vLen = Vector<float>.Count;
        var targetVec = new Vector<float>(target);
        int idx = 0;

        for (; idx <= n - vLen; idx += vLen)
        {
            var chunk = new Vector<float>(column, idx);
            Vector<int> mask = ApplyFloatOp(op, chunk, targetVec);
            WriteToBitmask(bitmask, mask, idx, vLen);
        }
        for (; idx < n; idx++)
            if (EvalScalar(op, column[idx], target))
                bitmask[idx >> 6] |= 1UL << (idx & 63);

        return bitmask;
    }

    // ── Vector operator helpers (same as ColumnQueryExecutor) ──────────────────

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

    // ── Bitmask helpers ───────────────────────────────────────────────────────

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
        if (bitOff + vLen > 64 && wordIdx + 1 < bitmask.Length)
            bitmask[wordIdx + 1] |= contrib >> (64 - bitOff);
    }

    // ── Scalar helpers ────────────────────────────────────────────────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool EvalScalar<T>(QueryOperator op, T value, T target) where T : IComparable<T> => op switch
    {
        QueryOperator.Equals             => value.CompareTo(target) == 0,
        QueryOperator.NotEquals          => value.CompareTo(target) != 0,
        QueryOperator.GreaterThan        => value.CompareTo(target) > 0,
        QueryOperator.LessThan           => value.CompareTo(target) < 0,
        QueryOperator.GreaterThanOrEqual => value.CompareTo(target) >= 0,
        QueryOperator.LessThanOrEqual    => value.CompareTo(target) <= 0,
        _                                => false,
    };

    // ── Type utilities (same classification as ColumnQueryExecutor) ────────────

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

    // ── Value conversion (reuse ColumnQueryExecutor logic) ─────────────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int ToInt(object? v)
    {
        if (v is int i)    return i;
        if (v is bool b)   return b ? 1 : 0;
        if (v is Enum)     return (int)Convert.ChangeType(v, typeof(int));
        if (v == null)     return 0;
        try { return Convert.ToInt32(v); } catch { return 0; }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static long ToLong(object? v)
    {
        if (v is long l)             return l;
        if (v is DateTime dt)        return dt.Ticks;
        if (v is DateOnly d)         return d.DayNumber;
        if (v is TimeOnly to)        return to.Ticks;
        if (v is TimeSpan ts)        return ts.Ticks;
        if (v is DateTimeOffset dto) return dto.UtcTicks;
        if (v == null)               return 0;
        try { return Convert.ToInt64(v); } catch { return 0; }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static double ToDouble(object? v)
    {
        if (v is double d)    return d;
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
}
