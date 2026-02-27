using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace BareMetalWeb.Data;

/// <summary>
/// A lightweight staging buffer for uncommitted WAL operations.
///
/// <para>
/// Uncommitted changes stay in this buffer until <see cref="CommitAsync"/> is called.
/// The underlying <see cref="WalStore"/> is only written to on commit — satisfying the
/// spec requirement that "uncommitted changes stay in memory until commit".
/// </para>
///
/// Usage:
/// <code>
/// using var tx = store.BeginTransaction();
/// tx.Stage(WalOp.Upsert(key1, bytes1));
/// tx.Stage(WalOp.Upsert(key2, bytes2));
/// await tx.CommitAsync();
/// </code>
/// </summary>
public sealed class WalTransaction : IDisposable
{
    private readonly WalStore _store;
    private readonly List<WalOp> _staged = new();
    private bool _committed;
    private bool _disposed;

    internal WalTransaction(WalStore store)
    {
        _store = store ?? throw new ArgumentNullException(nameof(store));
    }

    /// <summary>Number of staged (not yet committed) operations.</summary>
    public int StagedCount => _staged.Count;

    /// <summary>
    /// Stages an operation into the in-memory buffer.
    /// The operation is not written to disk until <see cref="CommitAsync"/> is called.
    /// </summary>
    public void Stage(WalOp op)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_committed) throw new InvalidOperationException("Transaction has already been committed.");
        _staged.Add(op);
    }

    /// <summary>
    /// Atomically commits all staged operations to the WAL store.
    /// Returns the Ptr of the commit record.
    /// Throws if the transaction has already been committed or rolled back.
    /// </summary>
    public async Task<ulong> CommitAsync(CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_committed) throw new InvalidOperationException("Transaction has already been committed.");
        if (_staged.Count == 0) throw new InvalidOperationException("Cannot commit an empty transaction.");

        ulong ptr = await _store.CommitAsync(_staged, cancellationToken).ConfigureAwait(false);
        _committed = true;
        return ptr;
    }

    /// <summary>Discards all staged operations without writing anything to disk.</summary>
    public void Rollback()
    {
        if (_committed) throw new InvalidOperationException("Cannot roll back a committed transaction.");
        _staged.Clear();
        _disposed = true;
    }

    /// <summary>
    /// If the transaction has not been committed, rolls it back automatically.
    /// </summary>
    public void Dispose()
    {
        if (!_disposed && !_committed)
            _staged.Clear();
        _disposed = true;
    }
}
