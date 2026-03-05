namespace BareMetalWeb.Runtime;

/// <summary>
/// An in-memory, ephemeral lock entry for a single aggregate.
/// Locks are never persisted and are destroyed when the process exits.
/// </summary>
public readonly record struct LockEntry(
    string AggregateId,
    string OwnerTransactionId,
    DateTime ExpiryUtc);

/// <summary>
/// Process-scoped in-memory pessimistic lock manager for aggregate instances.
///
/// Guarantees:
/// <list type="bullet">
///   <item>Deadlock-free: callers must acquire locks in ascending <c>aggregateId</c> order
///   (see <see cref="TryAcquireAll"/>).</item>
///   <item>Locks are ephemeral and never persisted.</item>
///   <item>Short-lived: locks carry a safety expiry; expired locks are released automatically.</item>
///   <item>No blocking waits: all operations return immediately with a success/failure result.</item>
///   <item>No async inside lock scope: the sync lock is held only for the duration of the
///   in-memory map operations.</item>
/// </list>
/// </summary>
public sealed class AggregateLockManager
{
    private static readonly AggregateLockManager _instance = new();

    /// <summary>Global singleton. Tests may construct their own instances for isolation.</summary>
    public static AggregateLockManager Instance => _instance;

    private readonly Dictionary<string, LockEntry> _locks =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly object _syncRoot = new();

    // ── Single-lock operations ─────────────────────────────────────────────────

    /// <summary>
    /// Attempts to acquire an exclusive lock on <paramref name="aggregateId"/> for
    /// <paramref name="transactionId"/>.  Fails immediately if the aggregate is already
    /// locked by a different (non-expired) transaction.
    /// </summary>
    public bool TryAcquire(string aggregateId, string transactionId, TimeSpan expiry)
    {
        var expiryUtc = DateTime.UtcNow.Add(expiry);
        lock (_syncRoot)
        {
            if (_locks.TryGetValue(aggregateId, out var existing))
            {
                // Reentrant (same owner) is allowed; stale locks are swept
                if (existing.ExpiryUtc > DateTime.UtcNow &&
                    !string.Equals(existing.OwnerTransactionId, transactionId, StringComparison.Ordinal))
                    return false;
            }

            _locks[aggregateId] = new LockEntry(aggregateId, transactionId, expiryUtc);
            return true;
        }
    }

    /// <summary>
    /// Releases the lock on <paramref name="aggregateId"/> if it is owned by
    /// <paramref name="transactionId"/>.  No-op otherwise.
    /// </summary>
    public void Release(string aggregateId, string transactionId)
    {
        lock (_syncRoot)
        {
            if (_locks.TryGetValue(aggregateId, out var entry) &&
                string.Equals(entry.OwnerTransactionId, transactionId, StringComparison.Ordinal))
                _locks.Remove(aggregateId);
        }
    }

    // ── Batch operations ───────────────────────────────────────────────────────

    /// <summary>
    /// Attempts to acquire locks on all supplied aggregate IDs in a single atomic
    /// (deadlock-free) operation.
    ///
    /// The IDs are sorted deterministically before acquisition.  If any individual
    /// acquisition fails, all already-acquired locks are released before returning
    /// <c>false</c>.
    /// </summary>
    public bool TryAcquireAll(
        IEnumerable<string> aggregateIds,
        string transactionId,
        TimeSpan expiry)
    {
        // §6.2 — sort deterministically to prevent deadlocks
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var sorted = new List<string>();
        foreach (var id in aggregateIds)
            if (seen.Add(id)) sorted.Add(id);
        sorted.Sort(StringComparer.Ordinal);

        var acquired = new List<string>(sorted.Count);
        foreach (var id in sorted)
        {
            if (TryAcquire(id, transactionId, expiry))
            {
                acquired.Add(id);
            }
            else
            {
                ReleaseAll(acquired, transactionId);
                return false;
            }
        }

        return true;
    }

    /// <summary>Releases all locks in <paramref name="aggregateIds"/> owned by <paramref name="transactionId"/>.</summary>
    public void ReleaseAll(IEnumerable<string> aggregateIds, string transactionId)
    {
        foreach (var id in aggregateIds)
            Release(id, transactionId);
    }

    // ── Diagnostic ─────────────────────────────────────────────────────────────

    /// <summary>Returns the number of currently active (non-expired) locks. For diagnostics only.</summary>
    public int ActiveLockCount
    {
        get
        {
            var now = DateTime.UtcNow;
            lock (_syncRoot)
            {
                int count = 0;
                foreach (var e in _locks.Values)
                    if (e.ExpiryUtc > now) count++;
                return count;
            }
        }
    }
}
