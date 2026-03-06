using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;

namespace BareMetalWeb.Data;

/// <summary>
/// Lightweight in-memory index: segmentId → contiguous pooled array of WAL keys
/// whose latest version resides in that segment.
/// Enables O(rows-in-segment) compaction lookups instead of scanning the entire head map.
/// Thread-safe via a ReaderWriterLockSlim.
///
/// Backing storage uses <see cref="ArrayPool{T}"/>-rented arrays with swap-remove
/// semantics — zero per-key heap allocations during steady-state operation.
/// </summary>
public sealed class WalSegmentIndex : IDisposable
{
    private const int InitialCapacity = 64;

    private readonly ReaderWriterLockSlim _lock = new(LockRecursionPolicy.NoRecursion);
    private readonly Dictionary<uint, KeyBucket> _map = new();

    /// <summary>Register that <paramref name="walKey"/>'s head is in <paramref name="segmentId"/>.</summary>
    public void Add(ulong walKey, uint segmentId)
    {
        _lock.EnterWriteLock();
        try
        {
            if (!_map.TryGetValue(segmentId, out var bucket))
            {
                bucket = new KeyBucket(InitialCapacity);
                _map[segmentId] = bucket;
            }
            bucket.Add(walKey);
        }
        finally { _lock.ExitWriteLock(); }
    }

    /// <summary>Atomically remove <paramref name="walKey"/> from <paramref name="oldSegmentId"/> and add to <paramref name="newSegmentId"/>.</summary>
    public void Move(ulong walKey, uint oldSegmentId, uint newSegmentId)
    {
        _lock.EnterWriteLock();
        try
        {
            if (_map.TryGetValue(oldSegmentId, out var oldBucket))
            {
                oldBucket.Remove(walKey);
                if (oldBucket.Count == 0)
                {
                    oldBucket.Return();
                    _map.Remove(oldSegmentId);
                }
            }

            if (!_map.TryGetValue(newSegmentId, out var newBucket))
            {
                newBucket = new KeyBucket(InitialCapacity);
                _map[newSegmentId] = newBucket;
            }
            newBucket.Add(walKey);
        }
        finally { _lock.ExitWriteLock(); }
    }

    /// <summary>Remove <paramref name="walKey"/> from <paramref name="segmentId"/>'s set.</summary>
    public void Remove(ulong walKey, uint segmentId)
    {
        _lock.EnterWriteLock();
        try
        {
            if (_map.TryGetValue(segmentId, out var bucket))
            {
                bucket.Remove(walKey);
                if (bucket.Count == 0)
                {
                    bucket.Return();
                    _map.Remove(segmentId);
                }
            }
        }
        finally { _lock.ExitWriteLock(); }
    }

    /// <summary>Returns a snapshot of all keys in <paramref name="segmentId"/>.</summary>
    public void GetKeys(uint segmentId, out ulong[] keys)
    {
        _lock.EnterReadLock();
        try
        {
            if (_map.TryGetValue(segmentId, out var bucket) && bucket.Count > 0)
            {
                keys = new ulong[bucket.Count];
                bucket.CopyTo(keys);
            }
            else
            {
                keys = Array.Empty<ulong>();
            }
        }
        finally { _lock.ExitReadLock(); }
    }

    /// <summary>Returns count of keys in <paramref name="segmentId"/> (O(1)).</summary>
    public int GetCount(uint segmentId)
    {
        _lock.EnterReadLock();
        try
        {
            if (_map.TryGetValue(segmentId, out var bucket))
                return bucket.Count;
            return 0;
        }
        finally { _lock.ExitReadLock(); }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        foreach (var bucket in _map.Values)
            bucket.Return();
        _map.Clear();
        _lock.Dispose();
    }

    /// <summary>
    /// Contiguous pooled array of WAL keys for a single segment.
    /// Uses swap-remove for O(1) deletion, ArrayPool for zero-alloc growth.
    /// </summary>
    private sealed class KeyBucket
    {
        private ulong[] _keys;
        private int _count;

        public int Count => _count;

        public KeyBucket(int capacity)
        {
            _keys = ArrayPool<ulong>.Shared.Rent(capacity);
            _count = 0;
        }

        public void Add(ulong key)
        {
            if (_count == _keys.Length)
                Grow();
            _keys[_count++] = key;
        }

        /// <summary>Swap-remove: O(n) scan + O(1) removal. Order is not preserved.</summary>
        public void Remove(ulong key)
        {
            for (int i = 0; i < _count; i++)
            {
                if (_keys[i] == key)
                {
                    _keys[i] = _keys[--_count];
                    return;
                }
            }
        }

        public void CopyTo(ulong[] dest)
        {
            Array.Copy(_keys, dest, _count);
        }

        public void Return()
        {
            if (_keys.Length > 0)
            {
                ArrayPool<ulong>.Shared.Return(_keys);
                _keys = Array.Empty<ulong>();
                _count = 0;
            }
        }

        private void Grow()
        {
            int newCap = _keys.Length * 2;
            var newArr = ArrayPool<ulong>.Shared.Rent(newCap);
            Array.Copy(_keys, newArr, _count);
            ArrayPool<ulong>.Shared.Return(_keys);
            _keys = newArr;
        }
    }
}
