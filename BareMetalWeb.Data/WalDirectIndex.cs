using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// Direct ordinal-based index for WAL key → pointer lookups.
/// Replaces binary-search-based <see cref="WalHeadMap"/> with per-table
/// contiguous <c>ulong[]</c> arrays indexed by recordId for O(1) reads.
///
/// Architecture:
///   walKey = (tableId &lt;&lt; 32 | recordId)
///   → TableSlot lookup by tableId (small ConcurrentDictionary, ~10-50 tables)
///   → Direct array access: slot._ptrs[recordId] → walPtr
///
/// Thread safety:
///   Reads are lock-free via Volatile.Read on the array reference and elements.
///   Writes acquire a per-table lock only when the array must grow.
///   Deletions are tombstoned (value = 0 = NullPtr).
///
/// Memory: 8 bytes per record per table. 1M records ≈ 8 MB per table.
/// </summary>
public sealed class WalDirectIndex : IDisposable
{
    private readonly ConcurrentDictionary<uint, TableSlot> _tables = new();
    private volatile bool _disposed; // reserved for future guard checks

    // ── Single-key operations ───────────────────────────────────────────

    /// <summary>O(1) lock-free read: walKey → walPtr.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryGetHead(ulong key, out ulong ptr)
    {
        var (tableId, recordId) = UnpackKey(key);
        if (_tables.TryGetValue(tableId, out var slot))
            return slot.TryGet(recordId, out ptr);
        ptr = 0;
        return false;
    }

    /// <summary>O(1) write: set walKey → walPtr.</summary>
    public void SetHead(ulong key, ulong ptr)
    {
        var (tableId, recordId) = UnpackKey(key);
        var slot = _tables.GetOrAdd(tableId, static _ => new TableSlot());
        slot.Set(recordId, ptr);
    }

    /// <summary>Remove a key by tombstoning (set to NullPtr).</summary>
    public void Remove(ulong key) => SetHead(key, 0);

    // ── Batch operations ────────────────────────────────────────────────

    /// <summary>Set all keys to the same pointer (commit batch).</summary>
    public void BatchSetHeads(ReadOnlySpan<ulong> keys, ulong ptr)
    {
        for (int i = 0; i < keys.Length; i++)
            SetHead(keys[i], ptr);
    }

    /// <summary>Set keys to corresponding pointers.</summary>
    public void BatchSetHeads(ReadOnlySpan<ulong> keys, ulong[] ptrs)
    {
        int len = Math.Min(keys.Length, ptrs.Length);
        for (int i = 0; i < len; i++)
            SetHead(keys[i], ptrs[i]);
    }

    /// <summary>Set keys to corresponding pointers (span variant).</summary>
    public void BatchSetHeads(ReadOnlySpan<ulong> keys, ReadOnlySpan<ulong> ptrs)
    {
        int len = Math.Min(keys.Length, ptrs.Length);
        for (int i = 0; i < len; i++)
            SetHead(keys[i], ptrs[i]);
    }

    // ── Recovery / snapshot ─────────────────────────────────────────────

    /// <summary>Bulk-load from pre-sorted key/head arrays (recovery path).</summary>
    internal void BulkLoad(ulong[] sortedKeys, ulong[] sortedHeads)
    {
        int len = Math.Min(sortedKeys.Length, sortedHeads.Length);
        for (int i = 0; i < len; i++)
        {
            if (sortedHeads[i] != 0)
                SetHead(sortedKeys[i], sortedHeads[i]);
        }
    }

    /// <summary>
    /// Extract all live key→head pairs as sorted arrays for snapshot persistence.
    /// </summary>
    internal void CopyArrays(out ulong[] keys, out ulong[] heads)
    {
        // First pass: count live entries
        int totalLive = 0;
        foreach (var kvp in _tables)
            totalLive += kvp.Value.LiveCount;

        if (totalLive == 0)
        {
            keys = [];
            heads = [];
            return;
        }

        // Second pass: collect entries
        var keyList = new ulong[totalLive];
        var headList = new ulong[totalLive];
        int idx = 0;

        foreach (var kvp in _tables)
        {
            uint tableId = kvp.Key;
            var slot = kvp.Value;
            idx = slot.CopyEntries(tableId, keyList, headList, idx);
        }

        // Trim if we over/under-estimated due to concurrent modifications
        if (idx < totalLive)
        {
            Array.Resize(ref keyList, idx);
            Array.Resize(ref headList, idx);
        }

        // Sort by key for deterministic snapshot ordering
        Array.Sort(keyList, headList);

        keys = keyList;
        heads = headList;
    }

    /// <summary>Total number of live entries across all tables.</summary>
    public int Count
    {
        get
        {
            int total = 0;
            foreach (var kvp in _tables)
                total += kvp.Value.LiveCount;
            return total;
        }
    }

    public void Dispose()
    {
        _disposed = true;
        _tables.Clear();
    }

    // ── Key packing ─────────────────────────────────────────────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static (uint tableId, uint recordId) UnpackKey(ulong key)
        => ((uint)(key >> 32), (uint)(key & 0xFFFF_FFFFu));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong PackKey(uint tableId, uint recordId)
        => (ulong)tableId << 32 | recordId;

    // ── Per-table slot ──────────────────────────────────────────────────

    private sealed class TableSlot
    {
        private const int InitialCapacity = 1024;

        private ulong[] _ptrs = new ulong[InitialCapacity];
        private readonly object _growLock = new();
        private volatile int _liveCount;

        /// <summary>O(1) lock-free read.</summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public bool TryGet(uint recordId, out ulong ptr)
        {
            var array = Volatile.Read(ref _ptrs);
            if (recordId < (uint)array.Length)
            {
                ptr = Volatile.Read(ref array[recordId]);
                return ptr != 0;
            }
            ptr = 0;
            return false;
        }

        /// <summary>O(1) write with automatic growth.</summary>
        public void Set(uint recordId, ulong ptr)
        {
            EnsureCapacity(recordId + 1);
            var array = Volatile.Read(ref _ptrs);

            ulong old = Interlocked.Exchange(ref array[recordId], ptr);

            // Track live count
            if (old == 0 && ptr != 0)
                Interlocked.Increment(ref _liveCount);
            else if (old != 0 && ptr == 0)
                Interlocked.Decrement(ref _liveCount);
        }

        public int LiveCount => _liveCount;

        /// <summary>Copy all live entries into pre-allocated arrays.</summary>
        public int CopyEntries(uint tableId, ulong[] keys, ulong[] heads, int startIdx)
        {
            var array = Volatile.Read(ref _ptrs);
            int idx = startIdx;
            for (uint i = 0; i < (uint)array.Length && idx < keys.Length; i++)
            {
                ulong ptr = Volatile.Read(ref array[i]);
                if (ptr != 0)
                {
                    keys[idx] = PackKey(tableId, i);
                    heads[idx] = ptr;
                    idx++;
                }
            }
            return idx;
        }

        private void EnsureCapacity(uint minCapacity)
        {
            if (minCapacity <= (uint)Volatile.Read(ref _ptrs).Length)
                return;

            lock (_growLock)
            {
                var current = _ptrs;
                if (minCapacity <= (uint)current.Length)
                    return;

                // Grow to next power of 2 or at least minCapacity
                uint newCap = (uint)current.Length;
                while (newCap < minCapacity)
                    newCap = Math.Min(newCap * 2, newCap + 1_048_576); // cap growth to 1M entries at a time
                if (newCap < minCapacity)
                    newCap = minCapacity;

                var newArr = new ulong[newCap];
                Array.Copy(current, newArr, current.Length);
                Volatile.Write(ref _ptrs, newArr);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong PackKey(uint tableId, uint recordId)
            => (ulong)tableId << 32 | recordId;
    }
}
