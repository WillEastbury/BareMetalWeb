using System.Threading;

namespace BareMetalWeb.Data;

/// <summary>
/// Cache-friendly in-memory head map backed by two sorted parallel arrays.
/// Binary search gives O(log n) reads; writes rebuild the arrays under a write lock.
/// Keys are packed as (tableId &lt;&lt; 32 | recordId).
/// Head values are packed as (segmentId &lt;&lt; 32 | offset32).
/// Thread-safe.
/// </summary>
public sealed class WalHeadMap : IDisposable
{
    private readonly ReaderWriterLockSlim _lock = new(LockRecursionPolicy.NoRecursion);

    // Parallel sorted arrays; always the same length and sorted ascending by key.
    private ulong[] _keysSorted  = [];
    private ulong[] _headsSorted = [];

    /// <summary>Number of tracked keys.</summary>
    public int Count
    {
        get
        {
            _lock.EnterReadLock();
            try   { return _keysSorted.Length; }
            finally { _lock.ExitReadLock(); }
        }
    }

    /// <summary>
    /// Gets the head pointer for <paramref name="key"/>.
    /// Returns <c>false</c> if the key is not tracked.
    /// </summary>
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

    /// <summary>
    /// Inserts or updates the head pointer for <paramref name="key"/>.
    /// Keeps the sorted arrays consistent.
    /// </summary>
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

        _lock.EnterWriteLock();
        try   { _keysSorted = sortedKeys; _headsSorted = sortedHeads; }
        finally { _lock.ExitWriteLock(); }
    }

    /// <summary>
    /// Copies the current sorted key/head arrays for snapshot use.
    /// </summary>
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

    /// <summary>
    /// Updates multiple heads in a single write-lock acquisition.
    /// Keys that already exist are updated in-place; new keys trigger a single
    /// sorted merge at the end rather than N array rebuilds.
    /// </summary>
    internal void BatchSetHeads(ReadOnlySpan<ulong> keys, ulong ptr)
    {
        if (keys.Length == 0) return;

        _lock.EnterWriteLock();
        try
        {
            // Fast path: all keys already exist — just update in-place
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

            // Merge sorted _keysSorted and sorted insertKeys
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

            _keysSorted = newKeys;
            _headsSorted = newHeads;
        }
        finally { _lock.ExitWriteLock(); }
    }

    /// <summary>
    /// Updates multiple heads with per-key ptrs in a single write-lock acquisition.
    /// Used during recovery where different keys map to different segment pointers.
    /// Keys and ptrs must be pre-sorted ascending by key.
    /// </summary>
    internal void BatchSetHeads(ReadOnlySpan<ulong> keys, ulong[] ptrs)
    {
        if (keys.Length == 0) return;

        _lock.EnterWriteLock();
        try
        {
            // Collect new keys (not already present) and update existing ones
            var insertKeys  = new List<ulong>();
            var insertPtrs  = new List<ulong>();

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

            // Merge sorted arrays (insertKeys are already sorted since input is sorted)
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

            _keysSorted = newKeys;
            _headsSorted = newHeads;
        }
        finally { _lock.ExitWriteLock(); }
    }

    /// <inheritdoc/>
    public void Dispose() => _lock.Dispose();
}
