using System.Buffers;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Threading;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// In-memory columnar store for a single entity type.
/// Maintains dense typed arrays (one per numeric field) synced with row additions/removals.
/// Enables SIMD column scans without per-query object loading or property extraction.
///
/// <para>
/// Rows are addressed via a stable <see cref="OrdinalMap"/> (id → ordinal) backed by a
/// <see cref="FreeOrdinalStack"/>.  Deleted rows push their ordinal back onto the free
/// stack so it can be reused by the next insert, keeping column arrays dense.
/// A validity bitmap masks freed (not-yet-reused) slots from SIMD scan results so
/// indexes — which always reference IDs — remain correct.
/// </para>
///
/// <para>
/// Lifecycle: created lazily on first vectorised query; from then on maintained
/// incrementally via <see cref="UpsertRow{T}"/> / <see cref="RemoveRow"/>.
/// A full <see cref="Build{T}"/> is still available for cold-start population.
/// </para>
/// </summary>
internal sealed class ColumnarStore
{
    private readonly Dictionary<string, int[]>    _intColumns    = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, long[]>   _longColumns   = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, double[]> _doubleColumns = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, float[]>  _floatColumns  = new(StringComparer.OrdinalIgnoreCase);

    // Stable id → ordinal mapping with pooled free-ordinal reuse
    private readonly OrdinalMap _ordinals;

    // Validity bitmap: bit at position <ordinal> is set iff that slot holds a live row.
    // Freed-but-not-yet-reused slots are cleared so SIMD scans do not produce stale hits.
    private ulong[] _validMask;

    // Read/write lock: multiple concurrent SIMD scans share the read lock;
    // Build / UpsertRow / RemoveRow take the write lock.
    private readonly ReaderWriterLockSlim _rwLock = new(LockRecursionPolicy.NoRecursion);

    // Stamp: incremented only by Build() and Invalidate().
    // UpsertRow/RemoveRow maintain the store in-place and do NOT change this value,
    // so GetOrBuildColumnarStore detects "needs rebuild" only when Invalidate() is called.
    private long _version;

    // Entity name for this store instance (set on first Build, used for stats staleness tracking).
    private string? _entityName;

    // Per-column statistics registry — shared across all ColumnarStore instances.
    // Stats are collected during Build() and used by QueryCostEstimator.
    internal static readonly ColumnStatsRegistry StatsRegistry = new();

    // ── Public properties ─────────────────────────────────────────────────────

    /// <summary>Number of live rows currently stored.</summary>
    public int RowCount
    {
        get
        {
            _rwLock.EnterReadLock();
            try   { return _ordinals.Count; }
            finally { _rwLock.ExitReadLock(); }
        }
    }

    /// <summary>
    /// Scan range — one past the highest assigned ordinal.
    /// Column arrays are sized to at least <c>Capacity</c> elements.
    /// Equal to <see cref="RowCount"/> when there are no freed slots (e.g. after a full build).
    /// </summary>
    public int Capacity
    {
        get
        {
            _rwLock.EnterReadLock();
            try   { return (int)_ordinals.HighWater; }
            finally { _rwLock.ExitReadLock(); }
        }
    }

    /// <summary>
    /// Number of <c>ulong</c> words required to cover one bitmask spanning
    /// <c>[0, Capacity)</c>.  Pass this to <see cref="ScanClause"/> and to the
    /// bitmask AND/OR helpers.
    /// </summary>
    public int ScanWordCount
    {
        get
        {
            _rwLock.EnterReadLock();
            try   { return ((int)_ordinals.HighWater + 63) >> 6; }
            finally { _rwLock.ExitReadLock(); }
        }
    }

    /// <summary>Stamp value; incremented on every mutation.</summary>
    public long Version => Interlocked.Read(ref _version);

    public ColumnarStore(int initialCapacity)
    {
        _ordinals  = new OrdinalMap(Math.Max(initialCapacity, 64));
        _validMask = new ulong[Math.Max((initialCapacity + 63) >> 6, 4)];
    }

    // ── Full rebuild ──────────────────────────────────────────────────────────

    /// <summary>
    /// Populates the store from a pre-loaded set of objects and their field metadata.
    /// Ordinals are assigned densely 0, 1, 2, … in input order, matching the
    /// previous row-index semantics so callers need no changes.
    /// </summary>
    public void Build<T>(IReadOnlyList<T> objects, DataEntityMetadata meta) where T : BaseDataObject
    {
        _rwLock.EnterWriteLock();
        try
        {
            _ordinals.Clear();
            _intColumns.Clear();
            _longColumns.Clear();
            _doubleColumns.Clear();
            _floatColumns.Clear();

            int n = objects.Count;

            // Ensure validity mask is large enough and fully cleared
            int words = Math.Max((n + 63) >> 6, 4);
            if (_validMask.Length < words)
                _validMask = new ulong[words];
            else
                Array.Clear(_validMask, 0, words);

            // Identify numeric fields and allocate dense column arrays
            foreach (var field in meta.Fields)
            {
                var propType = Nullable.GetUnderlyingType(field.ClrType)
                               ?? field.ClrType;

                if      (IsIntType(propType))    _intColumns[field.Name]    = new int[n];
                else if (IsLongType(propType))   _longColumns[field.Name]   = new long[n];
                else if (IsDoubleType(propType)) _doubleColumns[field.Name] = new double[n];
                else if (IsFloatType(propType))  _floatColumns[field.Name]  = new float[n];
            }

            // Single pass: assign ordinals, fill columns, mark valid bits
            for (int i = 0; i < n; i++)
            {
                var obj = objects[i];
                var (ordinal, _) = _ordinals.Upsert(obj.Key); // ordinal == (uint)i for fresh map

                SetValidBit(_validMask, ordinal);

                foreach (var field in meta.Fields)
                {
                    var val = field.GetValueFn(obj);

                    if      (_intColumns.TryGetValue(field.Name,    out var intCol))  intCol[ordinal]    = ToInt(val);
                    else if (_longColumns.TryGetValue(field.Name,   out var longCol)) longCol[ordinal]   = ToLong(val);
                    else if (_doubleColumns.TryGetValue(field.Name, out var dblCol))  dblCol[ordinal]    = ToDouble(val);
                    else if (_floatColumns.TryGetValue(field.Name,  out var fltCol))  fltCol[ordinal]    = ToFloat(val);
                }
            }

            Interlocked.Increment(ref _version);
            _entityName = meta.Name;

            // Collect per-column statistics for query cost estimation
            StatsRegistry.CollectStats(
                meta.Name, _intColumns, _longColumns, _doubleColumns, _floatColumns, _validMask, n);
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }
    }

    // ── Incremental single-row operations ─────────────────────────────────────

    /// <summary>
    /// Inserts or updates a single row in the columnar store without a full rebuild.
    /// <list type="bullet">
    ///   <item><description>
    ///     <b>Insert</b>: acquires a free ordinal (from the <see cref="FreeOrdinalStack"/> or
    ///     high-water increment), grows column arrays if needed, writes values, sets validity bit.
    ///   </description></item>
    ///   <item><description>
    ///     <b>Update</b>: reuses the existing ordinal and overwrites the column values in-place.
    ///   </description></item>
    /// </list>
    /// Returns <c>false</c> when the store has not yet been built (schema is unknown).
    /// </summary>
    public bool UpsertRow<T>(T obj, DataEntityMetadata meta) where T : BaseDataObject
    {
        if (obj is null) return false;

        _rwLock.EnterWriteLock();
        try
        {
            // Refuse to operate if no schema columns have been initialised yet
            if (_intColumns.Count == 0 && _longColumns.Count == 0
                && _doubleColumns.Count == 0 && _floatColumns.Count == 0)
                return false;

            var (ordinal, isNew) = _ordinals.Upsert(obj.Key);

            if (isNew)
            {
                // Grow column arrays and validity mask if the new ordinal exceeds their length
                EnsureColumnCapacity((int)ordinal + 1);
                EnsureValidMaskCapacity((int)ordinal + 1);
            }

            // Write column values at the ordinal position
            foreach (var field in meta.Fields)
            {
                var val = field.GetValueFn(obj);

                if      (_intColumns.TryGetValue(field.Name,    out var intCol))  intCol[ordinal]    = ToInt(val);
                else if (_longColumns.TryGetValue(field.Name,   out var longCol)) longCol[ordinal]   = ToLong(val);
                else if (_doubleColumns.TryGetValue(field.Name, out var dblCol))  dblCol[ordinal]    = ToDouble(val);
                else if (_floatColumns.TryGetValue(field.Name,  out var fltCol))  fltCol[ordinal]    = ToFloat(val);
            }

            SetValidBit(_validMask, ordinal);

            if (_entityName != null) StatsRegistry.MarkStale(_entityName);
            return true;
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }
    }

    /// <summary>
    /// Removes a single row by key.
    /// The freed ordinal is pushed onto the <see cref="FreeOrdinalStack"/> for immediate
    /// reuse by the next <see cref="UpsertRow{T}"/> call; the validity bit is cleared so
    /// SIMD scans skip the stale slot.
    /// Returns <c>false</c> when the key was not found.
    /// </summary>
    public bool RemoveRow(uint key)
    {
        _rwLock.EnterWriteLock();
        try
        {
            if (!_ordinals.Remove(key, out var ordinal))
                return false;

            ClearValidBit(_validMask, ordinal);

            if (_entityName != null) StatsRegistry.MarkStale(_entityName);
            return true;
        }
        finally
        {
            _rwLock.ExitWriteLock();
        }
    }

    /// <summary>
    /// Marks the store as stale so the next query triggers a full rebuild.
    /// Prefer <see cref="UpsertRow{T}"/> / <see cref="RemoveRow"/> for incremental updates.
    /// </summary>
    public void Invalidate() => Interlocked.Increment(ref _version);

    // ── Column access ─────────────────────────────────────────────────────────

    public bool TryGetIntColumn(string fieldName, out ReadOnlySpan<int> column)
    {
        if (_intColumns.TryGetValue(fieldName, out var arr))
        {
            column = arr.AsSpan(0, (int)_ordinals.HighWater);
            return true;
        }
        column = default;
        return false;
    }

    public bool TryGetLongColumn(string fieldName, out ReadOnlySpan<long> column)
    {
        if (_longColumns.TryGetValue(fieldName, out var arr))
        {
            column = arr.AsSpan(0, (int)_ordinals.HighWater);
            return true;
        }
        column = default;
        return false;
    }

    public bool TryGetDoubleColumn(string fieldName, out ReadOnlySpan<double> column)
    {
        if (_doubleColumns.TryGetValue(fieldName, out var arr))
        {
            column = arr.AsSpan(0, (int)_ordinals.HighWater);
            return true;
        }
        column = default;
        return false;
    }

    public bool TryGetFloatColumn(string fieldName, out ReadOnlySpan<float> column)
    {
        if (_floatColumns.TryGetValue(fieldName, out var arr))
        {
            column = arr.AsSpan(0, (int)_ordinals.HighWater);
            return true;
        }
        column = default;
        return false;
    }

    /// <summary>
    /// Returns the object key (ID) stored at dense column position <paramref name="rowIndex"/>.
    /// Returns <c>0</c> when the slot is freed (not yet reused); callers should skip key 0.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public uint GetKeyAtRow(int rowIndex) => _ordinals.GetId((uint)rowIndex);

    /// <summary>
    /// Returns the set of field names that have columnar storage.
    /// Useful for checking which clause fields can use the fast path.
    /// </summary>
    public bool HasColumn(string fieldName)
        => _intColumns.ContainsKey(fieldName)
        || _longColumns.ContainsKey(fieldName)
        || _doubleColumns.ContainsKey(fieldName)
        || _floatColumns.ContainsKey(fieldName);

    // ── Private helpers: grow arrays ──────────────────────────────────────────

    private void EnsureColumnCapacity(int needed)
    {
        foreach (var kv in _intColumns)
            if (kv.Value.Length < needed)
                _intColumns[kv.Key] = GrowArray(kv.Value, needed);
        foreach (var kv in _longColumns)
            if (kv.Value.Length < needed)
                _longColumns[kv.Key] = GrowArray(kv.Value, needed);
        foreach (var kv in _doubleColumns)
            if (kv.Value.Length < needed)
                _doubleColumns[kv.Key] = GrowArray(kv.Value, needed);
        foreach (var kv in _floatColumns)
            if (kv.Value.Length < needed)
                _floatColumns[kv.Key] = GrowArray(kv.Value, needed);
    }

    private static T[] GrowArray<T>(T[] src, int minLength)
    {
        var dst = new T[Math.Max(minLength, src.Length * 2)];
        src.CopyTo(dst, 0);
        return dst;
    }

    private void EnsureValidMaskCapacity(int neededOrdinals)
    {
        int words = (neededOrdinals + 63) >> 6;
        if (_validMask.Length < words)
            Array.Resize(ref _validMask, Math.Max(words, _validMask.Length * 2));
    }

    // ── Validity bitmap helpers ───────────────────────────────────────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void SetValidBit(ulong[] mask, uint ordinal)
        => mask[ordinal >> 6] |= 1UL << (int)(ordinal & 63);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ClearValidBit(ulong[] mask, uint ordinal)
        => mask[ordinal >> 6] &= ~(1UL << (int)(ordinal & 63));

    /// <summary>
    /// ANDs <paramref name="bitmask"/> in-place with <paramref name="validMask"/>,
    /// clearing any bits that correspond to freed (not-yet-reused) ordinals.
    /// </summary>
    private static void ApplyValidityMask(ulong[] bitmask, ulong[] validMask, int wordCount)
    {
        int limit = Math.Min(bitmask.Length, Math.Min(validMask.Length, wordCount));
        for (int i = 0; i < limit; i++)
            bitmask[i] &= validMask[i];
        // Words beyond the validity mask are outside HighWater — zero them out.
        for (int i = limit; i < bitmask.Length; i++)
            bitmask[i] = 0;
    }

    // ── SIMD column scan ──────────────────────────────────────────────────────

    /// <summary>
    /// Scans a pre-built column using SIMD and returns a bitmask of matching rows.
    /// This is the hot path — no object loading, no property extraction, no boxing.
    /// <para>
    /// The bitmask spans <c>[0, Capacity)</c> bits.  Freed (not-yet-reused) ordinals
    /// are masked out via the internal validity bitmap, so callers never see stale hits.
    /// </para>
    /// <para>
    /// Pass <see cref="ScanWordCount"/> as <paramref name="wordCount"/> to ensure the
    /// returned array is correctly sized when there are freed slots between live rows.
    /// </para>
    /// </summary>
    public ulong[]? ScanClause(string fieldName, QueryOperator op, object? value, int wordCount)
    {
        _rwLock.EnterReadLock();
        try
        {
            // Use the full scan range (HighWater), not just live-row count, so all valid
            // ordinals (including those that reused freed slots) are covered.
            int n         = (int)_ordinals.HighWater;
            int realWords = (n + 63) >> 6;

            // Ensure the caller's word count is at least as large as our scan range.
            int words = Math.Max(wordCount, realWords);

            ulong[]? bitmask = null;

            if (_intColumns.TryGetValue(fieldName, out var intCol))
            {
                if (!TryConvertToInt(value, typeof(int), out int iTarget)) return null;
                bitmask = ScanIntArray(intCol, op, iTarget, n, words);
            }
            else if (_longColumns.TryGetValue(fieldName, out var longCol))
            {
                if (!TryConvertToLong(value, typeof(long), out long lTarget)) return null;
                bitmask = ScanLongArray(longCol, op, lTarget, n, words);
            }
            else if (_doubleColumns.TryGetValue(fieldName, out var dblCol))
            {
                if (!TryConvertToDouble(value, out double dTarget)) return null;
                bitmask = ScanDoubleArray(dblCol, op, dTarget, n, words);
            }
            else if (_floatColumns.TryGetValue(fieldName, out var fltCol))
            {
                if (!TryConvertToFloat(value, out float fTarget)) return null;
                bitmask = ScanFloatArray(fltCol, op, fTarget, n, words);
            }

            if (bitmask == null)
                return null; // field not in columnar store

            // Apply validity mask: exclude freed-but-not-yet-reused ordinals.
            ApplyValidityMask(bitmask, _validMask, realWords);
            return bitmask;
        }
        finally
        {
            _rwLock.ExitReadLock();
        }
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
                    && DataScaffold.GetEnumLookup(targetType).TryGetValue(s, out var cached)
                    ? cached
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
