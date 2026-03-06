using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;

namespace BareMetalWeb.Data;

/// <summary>
/// Striped in-memory head map.  The key space is divided across
/// <see cref="DefaultShardCount"/> independent shards, each backed by two
/// sorted parallel arrays and its own <see cref="ReaderWriterLockSlim"/>.
///
/// <para>
/// Shard selection is <c>(tableId) &amp; shardMask</c> where
/// <c>tableId = (key &gt;&gt; 32)</c>.  Records that belong to different tables
/// therefore land in independent shards, so concurrent commits touching
/// different tables never contend on the same lock stripe.
/// </para>
///
/// <para>
/// Binary search gives O(log n/S) reads per shard; writes rebuild one
/// shard's arrays under that shard's exclusive lock.
/// Keys are packed as (tableId &lt;&lt; 32 | recordId).
/// Head values are packed as (segmentId &lt;&lt; 32 | offset32).
/// Thread-safe.
/// </para>
/// </summary>
public sealed class WalHeadMap : IDisposable
{
    /// <summary>Default number of lock stripes (power-of-two for mask-based dispatch).</summary>
    public const int DefaultShardCount = 16;

    private readonly HeadMapShard[] _shards;
    private readonly int _shardMask;

    /// <param name="shardCount">
    /// Number of independent lock stripes.  Must be a positive power of two;
    /// defaults to <see cref="DefaultShardCount"/>.
    /// </param>
    public WalHeadMap(int shardCount = DefaultShardCount)
    {
        if (shardCount <= 0 || (shardCount & (shardCount - 1)) != 0)
            throw new ArgumentOutOfRangeException(nameof(shardCount),
                "shardCount must be a positive power of two.");

        _shardMask = shardCount - 1;
        _shards = new HeadMapShard[shardCount];
        for (int i = 0; i < shardCount; i++)
            _shards[i] = new HeadMapShard();
    }

    // ── Shard routing ──────────────────────────────────────────────────────────

    /// <summary>Maps a packed key to its shard index by the tableId (upper 32 bits).</summary>
    private int ShardFor(ulong key) => (int)((key >> 32) & (uint)_shardMask);

    // ── Public API ─────────────────────────────────────────────────────────────

    /// <summary>Total number of tracked keys across all shards.</summary>
    public int Count
    {
        get
        {
            int total = 0;
            foreach (var shard in _shards) total += shard.Count;
            return total;
        }
    }

    /// <summary>
    /// Gets the head pointer for <paramref name="key"/>.
    /// Returns <c>false</c> if the key is not tracked.
    /// </summary>
    public bool TryGetHead(ulong key, out ulong ptr)
        => _shards[ShardFor(key)].TryGetHead(key, out ptr);

    /// <summary>
    /// Inserts or updates the head pointer for <paramref name="key"/>.
    /// Keeps the sorted arrays for its shard consistent.
    /// </summary>
    public void SetHead(ulong key, ulong ptr)
        => _shards[ShardFor(key)].SetHead(key, ptr);

    /// <summary>
    /// Bulk-loads pre-sorted key/head arrays, replacing all existing content.
    /// Arrays must be the same length and sorted ascending by key.
    /// Used during startup recovery to avoid repeated per-key write-lock acquisitions.
    /// </summary>
    internal void BulkLoad(ulong[] sortedKeys, ulong[] sortedHeads)
    {
        ArgumentNullException.ThrowIfNull(sortedKeys);
        ArgumentNullException.ThrowIfNull(sortedHeads);
        if (sortedKeys.Length != sortedHeads.Length)
            throw new ArgumentException("Arrays must have equal length.");

        int shardCount = _shards.Length;
        int guess      = sortedKeys.Length / shardCount + 1;

        // Allocate per-shard arrays conservatively (Length/N + 1 each)
        ulong[][] shardKeys  = new ulong[shardCount][];
        ulong[][] shardHeads = new ulong[shardCount][];
        int[]     fill       = new int[shardCount];
        for (int s = 0; s < shardCount; s++)
        {
            shardKeys[s]  = new ulong[guess];
            shardHeads[s] = new ulong[guess];
        }

        // Single pass: distribute into per-shard buffers, growing if needed.
        // The input is globally sorted, so within each shard the subset is also sorted
        // (tableId occupies the high bits, so all records for tableId=X precede tableId=Y
        // whenever X < Y — even when both map to the same shard via modulo, the relative
        // order is preserved in the global sort).
        for (int i = 0; i < sortedKeys.Length; i++)
        {
            int s = ShardFor(sortedKeys[i]);
            int f = fill[s];
            if (f == shardKeys[s].Length)
            {
                int newLen = shardKeys[s].Length * 2;
                Array.Resize(ref shardKeys[s],  newLen);
                Array.Resize(ref shardHeads[s], newLen);
            }
            shardKeys[s][f]  = sortedKeys[i];
            shardHeads[s][f] = sortedHeads[i];
            fill[s]++;
        }

        // Trim to exact size and bulk-load each shard
        for (int s = 0; s < shardCount; s++)
        {
            if (fill[s] != shardKeys[s].Length)
            {
                Array.Resize(ref shardKeys[s],  fill[s]);
                Array.Resize(ref shardHeads[s], fill[s]);
            }
            _shards[s].BulkLoad(shardKeys[s], shardHeads[s]);
        }
    }

    /// <summary>
    /// Copies all key/head pairs across all shards into a single globally-sorted pair
    /// of arrays.  Used by <see cref="WalSnapshot"/> for checkpoint writes.
    /// </summary>
    internal void CopyArrays(out ulong[] keys, out ulong[] heads)
    {
        // Snapshot each shard under its own read lock
        ulong[][] shardKeyArrays  = new ulong[_shards.Length][];
        ulong[][] shardHeadArrays = new ulong[_shards.Length][];
        int total = 0;
        for (int s = 0; s < _shards.Length; s++)
        {
            _shards[s].CopyArrays(out shardKeyArrays[s], out shardHeadArrays[s]);
            total += shardKeyArrays[s].Length;
        }

        if (total == 0) { keys = []; heads = []; return; }

        // Flatten all shards and sort the combined result.
        // With K ≤ 16 shards a single Array.Sort is simpler than a K-way merge and is
        // only called on the snapshot path (not the per-record hot path).
        var outKeys  = new ulong[total];
        var outHeads = new ulong[total];
        int w = 0;
        for (int s = 0; s < _shards.Length; s++)
        {
            shardKeyArrays[s].CopyTo(outKeys,  w);
            shardHeadArrays[s].CopyTo(outHeads, w);
            w += shardKeyArrays[s].Length;
        }
        Array.Sort(outKeys, outHeads);

        keys  = outKeys;
        heads = outHeads;
    }

    /// <summary>
    /// Updates multiple heads in a single write-lock acquisition <em>per shard</em>.
    /// Keys that already exist are updated in-place; new keys trigger a single
    /// sorted merge at the end rather than N array rebuilds.
    /// Concurrent commits touching different tables do not contend on the same lock.
    /// </summary>
    internal void BatchSetHeads(ReadOnlySpan<ulong> keys, ulong ptr)
    {
        if (keys.Length == 0) return;

        // Fast path: single key — no grouping needed
        if (keys.Length == 1)
        {
            _shards[ShardFor(keys[0])].SetHead(keys[0], ptr);
            return;
        }

        // Common case: all keys belong to the same shard (same tableId)
        int firstShard = ShardFor(keys[0]);
        bool singleShard = true;
        for (int i = 1; i < keys.Length; i++)
        {
            if (ShardFor(keys[i]) != firstShard) { singleShard = false; break; }
        }

        if (singleShard)
        {
            _shards[firstShard].BatchSetHeads(keys, ptr);
            return;
        }

        // Multi-shard: group keys by shard then update each independently
        var groups = new Dictionary<int, List<ulong>>(_shards.Length);
        for (int i = 0; i < keys.Length; i++)
        {
            int s = ShardFor(keys[i]);
            if (!groups.TryGetValue(s, out var list))
                groups[s] = list = new List<ulong>();
            list.Add(keys[i]);
        }

        foreach (var (shard, shardKeys) in groups)
            _shards[shard].BatchSetHeads(CollectionsMarshal.AsSpan(shardKeys), ptr);
    }

    /// <summary>
    /// Updates multiple heads with per-key ptrs in a single write-lock acquisition
    /// per shard.  Used during recovery where different keys map to different
    /// segment pointers.  Keys and ptrs must be pre-sorted ascending by key.
    /// </summary>
    internal void BatchSetHeads(ReadOnlySpan<ulong> keys, ulong[] ptrs)
    {
        if (keys.Length == 0) return;

        // Common case: all keys belong to the same shard
        int firstShard = ShardFor(keys[0]);
        bool singleShard = true;
        for (int i = 1; i < keys.Length; i++)
        {
            if (ShardFor(keys[i]) != firstShard) { singleShard = false; break; }
        }

        if (singleShard)
        {
            _shards[firstShard].BatchSetHeads(keys, ptrs);
            return;
        }

        // Multi-shard: group (key, ptr) pairs by shard then update each independently
        var keyGroups = new Dictionary<int, List<ulong>>(_shards.Length);
        var ptrGroups = new Dictionary<int, List<ulong>>(_shards.Length);
        for (int i = 0; i < keys.Length; i++)
        {
            int s = ShardFor(keys[i]);
            if (!keyGroups.TryGetValue(s, out var kl))
                keyGroups[s] = kl = new List<ulong>();
            if (!ptrGroups.TryGetValue(s, out var pl))
                ptrGroups[s] = pl = new List<ulong>();
            kl.Add(keys[i]);
            pl.Add(ptrs[i]);
        }

        foreach (var (shard, shardKeys) in keyGroups)
            _shards[shard].BatchSetHeads(
                CollectionsMarshal.AsSpan(shardKeys),
                CollectionsMarshal.AsSpan(ptrGroups[shard]));
    }

    /// <summary>
    /// Updates multiple heads with per-key ptrs in a single write-lock acquisition
    /// per shard, accepting both key and ptr arrays as <see cref="ReadOnlySpan{T}"/>
    /// to avoid array allocation when the caller already has exact-size slices.
    /// Keys and ptrs must be pre-sorted ascending by key and have equal length.
    /// </summary>
    internal void BatchSetHeads(ReadOnlySpan<ulong> keys, ReadOnlySpan<ulong> ptrs)
    {
        if (keys.Length == 0) return;
        if (keys.Length != ptrs.Length)
            throw new ArgumentException("keys and ptrs must have equal length.");

        // Common case: all keys belong to the same shard
        int firstShard = ShardFor(keys[0]);
        bool singleShard = true;
        for (int i = 1; i < keys.Length; i++)
        {
            if (ShardFor(keys[i]) != firstShard) { singleShard = false; break; }
        }

        if (singleShard)
        {
            _shards[firstShard].BatchSetHeads(keys, ptrs);
            return;
        }

        // Multi-shard: group (key, ptr) pairs by shard then update each independently
        var keyGroups = new Dictionary<int, List<ulong>>(_shards.Length);
        var ptrGroups = new Dictionary<int, List<ulong>>(_shards.Length);
        for (int i = 0; i < keys.Length; i++)
        {
            int s = ShardFor(keys[i]);
            if (!keyGroups.TryGetValue(s, out var kl))
                keyGroups[s] = kl = new List<ulong>();
            if (!ptrGroups.TryGetValue(s, out var pl))
                ptrGroups[s] = pl = new List<ulong>();
            kl.Add(keys[i]);
            pl.Add(ptrs[i]);
        }

        foreach (var (shard, shardKeys) in keyGroups)
            _shards[shard].BatchSetHeads(
                CollectionsMarshal.AsSpan(shardKeys),
                CollectionsMarshal.AsSpan(ptrGroups[shard]));
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        foreach (var shard in _shards)
            shard.Dispose();
    }

    // ── Private shard ─────────────────────────────────────────────────────────

    /// <summary>
    /// One stripe of the striped head map.  Holds two parallel sorted arrays
    /// and an independent <see cref="ReaderWriterLockSlim"/>.
    /// </summary>
    private sealed class HeadMapShard : IDisposable
    {
        private readonly ReaderWriterLockSlim _lock = new(LockRecursionPolicy.NoRecursion);

        // Parallel sorted arrays; always the same length and sorted ascending by key.
        private ulong[] _keysSorted  = [];
        private ulong[] _headsSorted = [];

        public int Count
        {
            get
            {
                _lock.EnterReadLock();
                try   { return _keysSorted.Length; }
                finally { _lock.ExitReadLock(); }
            }
        }

        public bool TryGetHead(ulong key, out ulong ptr)
        {
            _lock.EnterReadLock();
            try
            {
                int idx = Array.BinarySearch(_keysSorted, key);
                if (idx >= 0) { ptr = _headsSorted[idx]; return true; }
                ptr = WalConstants.NullPtr;
                return false;
            }
            finally { _lock.ExitReadLock(); }
        }

        public void SetHead(ulong key, ulong ptr)
        {
            _lock.EnterWriteLock();
            try
            {
                int idx = Array.BinarySearch(_keysSorted, key);
                if (idx >= 0)
                {
                    _headsSorted[idx] = ptr;
                    return;
                }

                int ins = ~idx;
                var newKeys  = new ulong[_keysSorted.Length + 1];
                var newHeads = new ulong[_headsSorted.Length + 1];

                _keysSorted .AsSpan(0, ins).CopyTo(newKeys);
                _headsSorted.AsSpan(0, ins).CopyTo(newHeads);
                newKeys [ins] = key;
                newHeads[ins] = ptr;
                _keysSorted .AsSpan(ins).CopyTo(newKeys .AsSpan(ins + 1));
                _headsSorted.AsSpan(ins).CopyTo(newHeads.AsSpan(ins + 1));

                _keysSorted  = newKeys;
                _headsSorted = newHeads;
            }
            finally { _lock.ExitWriteLock(); }
        }

        internal void BulkLoad(ulong[] sortedKeys, ulong[] sortedHeads)
        {
            _lock.EnterWriteLock();
            try   { _keysSorted = sortedKeys; _headsSorted = sortedHeads; }
            finally { _lock.ExitWriteLock(); }
        }

        internal void CopyArrays(out ulong[] keys, out ulong[] heads)
        {
            _lock.EnterReadLock();
            try
            {
                keys  = (ulong[])_keysSorted.Clone();
                heads = (ulong[])_headsSorted.Clone();
            }
            finally { _lock.ExitReadLock(); }
        }

        internal void BatchSetHeads(ReadOnlySpan<ulong> keys, ulong ptr)
        {
            if (keys.Length == 0) return;

            _lock.EnterWriteLock();
            try
            {
                // Fast path: all keys already exist — update in-place
                bool allExist = true;
                for (int i = 0; i < keys.Length; i++)
                {
                    int idx = Array.BinarySearch(_keysSorted, keys[i]);
                    if (idx >= 0)
                        _headsSorted[idx] = ptr;
                    else
                        { allExist = false; break; }
                }
                if (allExist) return;

                // Slow path: some new keys — collect inserts and do a single merge
                var insertKeys = new List<ulong>();
                for (int i = 0; i < keys.Length; i++)
                {
                    int idx = Array.BinarySearch(_keysSorted, keys[i]);
                    if (idx >= 0)
                        _headsSorted[idx] = ptr;
                    else
                        insertKeys.Add(keys[i]);
                }

                if (insertKeys.Count == 0) return;

                insertKeys.Sort();
                int oldLen = _keysSorted.Length;
                int newLen = oldLen + insertKeys.Count;
                var newKeys  = new ulong[newLen];
                var newHeads = new ulong[newLen];

                int a = 0, b = 0, w = 0;
                while (a < oldLen && b < insertKeys.Count)
                {
                    if (_keysSorted[a] <= insertKeys[b])
                    {
                        newKeys[w] = _keysSorted[a];
                        newHeads[w] = _headsSorted[a];
                        a++;
                    }
                    else
                    {
                        newKeys[w] = insertKeys[b];
                        newHeads[w] = ptr;
                        b++;
                    }
                    w++;
                }
                while (a < oldLen) { newKeys[w] = _keysSorted[a]; newHeads[w] = _headsSorted[a]; a++; w++; }
                while (b < insertKeys.Count) { newKeys[w] = insertKeys[b]; newHeads[w] = ptr; b++; w++; }

                _keysSorted  = newKeys;
                _headsSorted = newHeads;
            }
            finally { _lock.ExitWriteLock(); }
        }

        internal void BatchSetHeads(ReadOnlySpan<ulong> keys, ReadOnlySpan<ulong> ptrs)
        {
            if (keys.Length == 0) return;

            _lock.EnterWriteLock();
            try
            {
                var insertKeys = new List<ulong>();
                var insertPtrs = new List<ulong>();

                for (int i = 0; i < keys.Length; i++)
                {
                    int idx = Array.BinarySearch(_keysSorted, keys[i]);
                    if (idx >= 0)
                        _headsSorted[idx] = ptrs[i];
                    else
                    {
                        insertKeys.Add(keys[i]);
                        insertPtrs.Add(ptrs[i]);
                    }
                }

                if (insertKeys.Count == 0) return;

                int oldLen = _keysSorted.Length;
                int newLen = oldLen + insertKeys.Count;
                var newKeys  = new ulong[newLen];
                var newHeads = new ulong[newLen];

                // insertKeys are already in insertion order from the (sorted) input span
                int a = 0, b = 0, w = 0;
                while (a < oldLen && b < insertKeys.Count)
                {
                    if (_keysSorted[a] <= insertKeys[b])
                    {
                        newKeys[w] = _keysSorted[a];
                        newHeads[w] = _headsSorted[a];
                        a++;
                    }
                    else
                    {
                        newKeys[w] = insertKeys[b];
                        newHeads[w] = insertPtrs[b];
                        b++;
                    }
                    w++;
                }
                while (a < oldLen) { newKeys[w] = _keysSorted[a]; newHeads[w] = _headsSorted[a]; a++; w++; }
                while (b < insertKeys.Count) { newKeys[w] = insertKeys[b]; newHeads[w] = insertPtrs[b]; b++; w++; }

                _keysSorted  = newKeys;
                _headsSorted = newHeads;
            }
            finally { _lock.ExitWriteLock(); }
        }

        public void Dispose() => _lock.Dispose();
    }
}
