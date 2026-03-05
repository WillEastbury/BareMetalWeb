using System;
using System.Collections.Generic;
using System.Threading;

namespace BareMetalWeb.Data;

/// <summary>
/// Lightweight in-memory index: segmentId → set of WAL keys whose latest
/// version resides in that segment. Enables O(rows-in-segment) compaction
/// lookups instead of scanning the entire head map.
/// Thread-safe via a ReaderWriterLockSlim.
/// </summary>
public sealed class WalSegmentIndex : IDisposable
{
    private readonly ReaderWriterLockSlim _lock = new(LockRecursionPolicy.NoRecursion);
    private readonly Dictionary<uint, HashSet<ulong>> _map = new();

    /// <summary>Register that <paramref name="walKey"/>'s head is in <paramref name="segmentId"/>.</summary>
    public void Add(ulong walKey, uint segmentId)
    {
        _lock.EnterWriteLock();
        try
        {
            if (!_map.TryGetValue(segmentId, out var set))
            {
                set = new HashSet<ulong>();
                _map[segmentId] = set;
            }
            set.Add(walKey);
        }
        finally { _lock.ExitWriteLock(); }
    }

    /// <summary>Atomically remove <paramref name="walKey"/> from <paramref name="oldSegmentId"/> and add to <paramref name="newSegmentId"/>.</summary>
    public void Move(ulong walKey, uint oldSegmentId, uint newSegmentId)
    {
        _lock.EnterWriteLock();
        try
        {
            if (_map.TryGetValue(oldSegmentId, out var oldSet))
            {
                oldSet.Remove(walKey);
                if (oldSet.Count == 0)
                    _map.Remove(oldSegmentId);
            }

            if (!_map.TryGetValue(newSegmentId, out var newSet))
            {
                newSet = new HashSet<ulong>();
                _map[newSegmentId] = newSet;
            }
            newSet.Add(walKey);
        }
        finally { _lock.ExitWriteLock(); }
    }

    /// <summary>Remove <paramref name="walKey"/> from <paramref name="segmentId"/>'s set.</summary>
    public void Remove(ulong walKey, uint segmentId)
    {
        _lock.EnterWriteLock();
        try
        {
            if (_map.TryGetValue(segmentId, out var set))
            {
                set.Remove(walKey);
                if (set.Count == 0)
                    _map.Remove(segmentId);
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
            if (_map.TryGetValue(segmentId, out var set))
            {
                keys = new ulong[set.Count];
                int i = 0;
                foreach (ulong k in set)
                    keys[i++] = k;
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
            if (_map.TryGetValue(segmentId, out var set))
                return set.Count;
            return 0;
        }
        finally { _lock.ExitReadLock(); }
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        _lock.Dispose();
    }
}
