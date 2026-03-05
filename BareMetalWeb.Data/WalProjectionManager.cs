using System.Collections.Generic;
using System.Threading;

namespace BareMetalWeb.Data;

/// <summary>
/// Coordinates in-memory secondary indexes (projections) on top of the WAL commit stream.
///
/// <para>
/// After each successful <see cref="WalStore.CommitAsync"/> the store calls
/// <see cref="ApplyCommit"/> to forward committed op payloads to every registered index
/// whose <see cref="ISecondaryIndex.TableId"/> matches the op's tableId.
/// </para>
///
/// Thread-safety: registration is protected by its own write lock; commit
/// dispatch is called from inside the store's write lock so no additional
/// synchronisation is needed for the dispatch path.
/// </summary>
public sealed class WalProjectionManager : IDisposable
{
    private readonly ReaderWriterLockSlim _regLock = new(LockRecursionPolicy.NoRecursion);
    private readonly List<ISecondaryIndex> _indexes = new();
    private volatile ISecondaryIndex[] _cachedSnapshot = [];
    private bool _disposed;

    // ── Registration ─────────────────────────────────────────────────────────

    /// <summary>Registers a secondary index. Idempotent by (TableId, Name).</summary>
    public void Register(ISecondaryIndex index)
    {
        ArgumentNullException.ThrowIfNull(index);
        _regLock.EnterWriteLock();
        try
        {
            for (int i = 0; i < _indexes.Count; i++)
                if (_indexes[i].TableId == index.TableId && _indexes[i].Name == index.Name)
                    return; // already registered
            _indexes.Add(index);
            _cachedSnapshot = _indexes.ToArray();
        }
        finally { _regLock.ExitWriteLock(); }
    }

    /// <summary>Unregisters the index identified by (<paramref name="tableId"/>, <paramref name="name"/>).</summary>
    public void Unregister(uint tableId, string name)
    {
        _regLock.EnterWriteLock();
        try
        {
            _indexes.RemoveAll(idx => idx.TableId == tableId && idx.Name == name);
            _cachedSnapshot = _indexes.ToArray();
        }
        finally { _regLock.ExitWriteLock(); }
    }

    /// <summary>Returns a snapshot of all currently registered indexes (safe for iteration).</summary>
    public IReadOnlyList<ISecondaryIndex> Indexes
    {
        get
        {
            _regLock.EnterReadLock();
            try { return _indexes.ToArray(); }
            finally { _regLock.ExitReadLock(); }
        }
    }

    // ── Commit dispatch ───────────────────────────────────────────────────────

    /// <summary>
    /// Dispatches a committed batch to all matching secondary indexes.
    /// Called by <see cref="WalStore"/> after fsync + head map update.
    ///
    /// <paramref name="payloadResolver"/> provides the raw row bytes for a given key
    /// (for upsert ops); it may return <see cref="ReadOnlyMemory{T}.Empty"/> when
    /// the data is unavailable (e.g. tombstone or resolver not wired up).
    /// </summary>
    public void ApplyCommit(IReadOnlyList<WalOp> ops,
        Func<ulong, ReadOnlyMemory<byte>>? payloadResolver = null)
    {
        if (ops.Count == 0) return;

        // Use cached snapshot — no lock, no allocation on the commit hot path
        var snapshot = _cachedSnapshot;
        if (snapshot.Length == 0) return;

        foreach (var op in ops)
        {
            var (tableId, _) = WalConstants.UnpackKey(op.Key);

            foreach (var idx in snapshot)
            {
                if (idx.TableId != tableId) continue;

                if (op.OpType == WalConstants.OpTypeDeleteTombstone)
                {
                    idx.Remove(op.Key, ReadOnlySpan<byte>.Empty);
                }
                else
                {
                    var newRow = payloadResolver?.Invoke(op.Key) ?? op.Payload;
                    idx.ApplyChange(op.Key, ReadOnlySpan<byte>.Empty, newRow.Span, ChangeType.Upsert);
                }
            }
        }
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose()
    {
        if (!_disposed) { _disposed = true; _regLock.Dispose(); }
    }
}
