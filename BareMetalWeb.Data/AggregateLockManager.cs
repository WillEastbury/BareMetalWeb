using System.Collections.Concurrent;
using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// In-memory pessimistic aggregate lock manager.
/// Locks are ephemeral, not persisted, short-lived with safety expiry.
/// Deadlock-free by sorted acquisition order.
/// No async inside lock scope. No nested locking.
/// </summary>
public sealed class AggregateLockManager
{
    private readonly ConcurrentDictionary<string, LockEntry> _locks = new(StringComparer.Ordinal);
    private static readonly TimeSpan DefaultExpiry = TimeSpan.FromSeconds(30);
    private const int MaxRetries = 5;
    private const int BaseBackoffMs = 10;

    /// <summary>
    /// Acquire locks for all aggregate keys in deterministic sorted order.
    /// Returns a disposable handle that releases all locks on dispose.
    /// Throws TimeoutException if locks cannot be acquired after retries.
    /// </summary>
    public LockHandle AcquireAll(IReadOnlyList<string> aggregateKeys, string transactionId)
    {
        var startTicks = EngineMetrics.StartTiming();
        bool contended = false;

        // Sort deterministically to prevent deadlocks
        var sortedList = new List<string>(aggregateKeys.Count);
        foreach (var k in aggregateKeys)
        {
            bool exists = false;
            foreach (var s in sortedList)
            {
                if (StringComparer.Ordinal.Equals(s, k))
                {
                    exists = true;
                    break;
                }
            }
            if (!exists)
                sortedList.Add(k);
        }
        sortedList.Sort(StringComparer.Ordinal);
        var sorted = sortedList.ToArray();

        for (int attempt = 0; attempt <= MaxRetries; attempt++)
        {
            if (attempt > 0)
            {
                contended = true;
                EngineMetrics.RecordCommitRetry();
            }

            var acquired = new List<string>(sorted.Length);
            bool success = true;

            foreach (var key in sorted)
            {
                if (TryAcquire(key, transactionId))
                {
                    acquired.Add(key);
                }
                else
                {
                    // Release what we acquired and retry
                    foreach (var acq in acquired)
                        Release(acq, transactionId);
                    success = false;
                    break;
                }
            }

            if (success)
            {
                EngineMetrics.RecordLockAcquire(EngineMetrics.ElapsedUs(startTicks), contended);
                return new LockHandle(this, acquired, transactionId);
            }

            // Exponential backoff
            if (attempt < MaxRetries)
                Thread.Sleep(BaseBackoffMs * (1 << attempt));
        }

        EngineMetrics.RecordLockAcquire(EngineMetrics.ElapsedUs(startTicks), true);
        throw new TimeoutException(
            $"Failed to acquire locks for transaction {transactionId} after {MaxRetries} retries. " +
            $"Keys: {string.Join(", ", sorted)}");
    }

    /// <summary>Try to acquire a single lock. Returns true if acquired.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryAcquire(string aggregateKey, string transactionId)
    {
        var now = DateTime.UtcNow;
        var entry = new LockEntry(aggregateKey, transactionId, now + DefaultExpiry);

        return _locks.AddOrUpdate(aggregateKey,
            _ => entry,
            (_, existing) =>
            {
                // If existing lock is expired or owned by same transaction, replace
                if (existing.ExpiryUtc < now || existing.OwnerTransactionId == transactionId)
                    return entry;
                return existing; // keep existing
            }).OwnerTransactionId == transactionId;
    }

    /// <summary>Release a lock owned by the given transaction.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Release(string aggregateKey, string transactionId)
    {
        _locks.TryRemove(new KeyValuePair<string, LockEntry>(
            aggregateKey,
            new LockEntry(aggregateKey, transactionId, default)));

        // Fallback: remove if owner matches
        if (_locks.TryGetValue(aggregateKey, out var entry) &&
            entry.OwnerTransactionId == transactionId)
        {
            _locks.TryRemove(aggregateKey, out _);
        }
    }

    /// <summary>Release all locks for a transaction.</summary>
    public void ReleaseAll(IEnumerable<string> keys, string transactionId)
    {
        foreach (var key in keys)
            Release(key, transactionId);
    }

    /// <summary>Purge expired locks (call periodically if needed).</summary>
    public int PurgeExpired()
    {
        var now = DateTime.UtcNow;
        int purged = 0;
        foreach (var (key, entry) in _locks)
        {
            if (entry.ExpiryUtc < now)
            {
                _locks.TryRemove(key, out _);
                purged++;
            }
        }
        return purged;
    }

    public int ActiveLockCount => _locks.Count;
}

/// <summary>Ephemeral lock entry. Not persisted.</summary>
public readonly record struct LockEntry(
    string AggregateKey,
    string OwnerTransactionId,
    DateTime ExpiryUtc
);

/// <summary>Disposable handle that releases all acquired locks.</summary>
public sealed class LockHandle : IDisposable
{
    private readonly AggregateLockManager _manager;
    private readonly List<string> _keys;
    private readonly string _transactionId;
    private bool _disposed;

    internal LockHandle(AggregateLockManager manager, List<string> keys, string transactionId)
    {
        _manager = manager;
        _keys = keys;
        _transactionId = transactionId;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _manager.ReleaseAll(_keys, _transactionId);
    }
}
