using System.Diagnostics;

namespace BareMetalWeb.Data;

/// <summary>
/// Manages cluster state: leader election, epoch tracking, role transitions,
/// and write fencing. Runs a background renewal loop when in leader role.
///
/// Invariants:
/// - No two leaders share the same Epoch
/// - No WAL entry is written without valid lease
/// - LSN strictly increases
/// - Old leader cannot append after losing lease
/// </summary>
public sealed class ClusterState : IDisposable
{
    private readonly ILeaseAuthority _lease;
    private readonly TimeSpan _renewInterval;
    private CancellationTokenSource? _renewCts;
    private Task? _renewTask;
    private volatile ClusterRole _role = ClusterRole.Follower;
    private long _lastLsn;

    /// <summary>Event raised when role changes (leader ↔ follower).</summary>
    public event Action<ClusterRole>? RoleChanged;

    public ClusterState(ILeaseAuthority lease, TimeSpan? renewInterval = null)
    {
        _lease = lease ?? throw new ArgumentNullException(nameof(lease));
        _renewInterval = renewInterval ?? TimeSpan.FromSeconds(5);
    }

    public ClusterRole Role => _role;
    public bool IsLeader => _role == ClusterRole.Leader;
    public long CurrentEpoch => _lease.CurrentEpoch;
    public long LastLsn => Volatile.Read(ref _lastLsn);
    public string InstanceId => _lease.InstanceId;

    /// <summary>
    /// Attempt to become leader. Acquires lease, increments epoch,
    /// starts renewal loop. Returns true if leadership acquired.
    /// </summary>
    public async ValueTask<bool> TryBecomeLeaderAsync(CancellationToken ct)
    {
        if (IsLeader) return true;

        var acquired = await _lease.TryAcquireAsync(ct);
        if (!acquired) return false;

        _role = ClusterRole.Leader;
        RoleChanged?.Invoke(ClusterRole.Leader);

        // Start renewal loop
        _renewCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _renewTask = RunRenewalLoopAsync(_renewCts.Token);

        return true;
    }

    /// <summary>
    /// Validate that this instance is allowed to write.
    /// Must be called before every WAL append.
    /// Throws if not leader or lease expired.
    /// Returns the current epoch for the fence token.
    /// </summary>
    public long ValidateWritePermission()
    {
        if (!IsLeader)
            throw new InvalidOperationException(
                "Write rejected: this instance is not the cluster leader.");

        if (!_lease.IsLeader)
        {
            // Lease lost between checks — immediate demotion
            Demote();
            throw new InvalidOperationException(
                "Write rejected: leader lease lost. Instance demoted to follower.");
        }

        // Capture epoch atomically with validation — prevents stale epoch in WAL entries
        return _lease.CurrentEpoch;
    }

    /// <summary>
    /// Assign the next LSN for a WAL entry. Must be called under write lock.
    /// Returns (epoch, lsn) for the WAL header.
    /// </summary>
    public (long Epoch, long Lsn) AssignLsn()
    {
        var epoch = ValidateWritePermission();
        var lsn = Interlocked.Increment(ref _lastLsn);
        return (epoch, lsn);
    }

    /// <summary>Set the LSN watermark during recovery/replay.</summary>
    public void SetLastLsn(long lsn) => Volatile.Write(ref _lastLsn, lsn);

    /// <summary>Voluntarily step down from leadership.</summary>
    public async ValueTask StepDownAsync(CancellationToken ct)
    {
        if (!IsLeader) return;

        _renewCts?.Cancel();
        if (_renewTask != null)
        {
            try { await _renewTask; } catch (OperationCanceledException) { }
        }

        await _lease.ReleaseAsync(ct);
        Demote();
    }

    /// <summary>Get a snapshot of the current cluster state for diagnostics.</summary>
    public ClusterStateSnapshot GetSnapshot() => new(
        Role: _role,
        Epoch: _lease.CurrentEpoch,
        LastLsn: LastLsn,
        InstanceId: _lease.InstanceId,
        IsLeaseValid: _lease.IsLeader);

    private async Task RunRenewalLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_renewInterval, ct);

                var renewed = await _lease.TryRenewAsync(ct);
                if (!renewed)
                {
                    Demote();
                    return;
                }
            }
            catch (OperationCanceledException) { return; }
            catch
            {
                // Renewal error — immediate demotion
                Demote();
                return;
            }
        }
    }

    private void Demote()
    {
        if (_role == ClusterRole.Follower) return;
        _role = ClusterRole.Follower;
        RoleChanged?.Invoke(ClusterRole.Follower);
    }

    public void Dispose()
    {
        _renewCts?.Cancel();
        _renewCts?.Dispose();
    }
}

public enum ClusterRole
{
    Follower,
    Leader
}

/// <summary>Point-in-time cluster state snapshot for diagnostics.</summary>
public sealed record ClusterStateSnapshot(
    ClusterRole Role, long Epoch, long LastLsn,
    string InstanceId, bool IsLeaseValid);

/// <summary>
/// Manages an independent compactor lease. On a single-node deployment, both
/// the writer and compactor leases are held by the same instance. On multi-node
/// deployments, the compactor can run on a separate node.
/// </summary>
public sealed class CompactorState : IDisposable
{
    private readonly ILeaseAuthority _lease;
    private readonly TimeSpan _renewInterval;
    private CancellationTokenSource? _renewCts;
    private Task? _renewTask;
    private volatile bool _isCompactor;

    public event Action<bool>? CompactorRoleChanged;

    public CompactorState(ILeaseAuthority lease, TimeSpan? renewInterval = null)
    {
        _lease = lease ?? throw new ArgumentNullException(nameof(lease));
        _renewInterval = renewInterval ?? TimeSpan.FromSeconds(5);
    }

    public bool IsCompactor => _isCompactor;
    public string InstanceId => _lease.InstanceId;

    /// <summary>Attempt to acquire the compactor lease.</summary>
    public async ValueTask<bool> TryBecomeCompactorAsync(CancellationToken ct)
    {
        if (_isCompactor) return true;
        var acquired = await _lease.TryAcquireAsync(ct);
        if (!acquired) return false;
        _isCompactor = true;
        CompactorRoleChanged?.Invoke(true);
        _renewCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _renewTask = RunRenewalLoopAsync(_renewCts.Token);
        return true;
    }

    /// <summary>Validate that this instance may run compaction.</summary>
    public void ValidateCompactionPermission()
    {
        if (!_isCompactor)
            throw new InvalidOperationException("Compaction rejected: this instance does not hold the compactor lease.");
        if (!_lease.IsLeader)
        {
            Demote();
            throw new InvalidOperationException("Compaction rejected: compactor lease lost.");
        }
    }

    public async ValueTask StepDownAsync(CancellationToken ct)
    {
        if (!_isCompactor) return;
        _renewCts?.Cancel();
        if (_renewTask != null)
        {
            try { await _renewTask; } catch (OperationCanceledException) { }
        }
        await _lease.ReleaseAsync(ct);
        Demote();
    }

    private async Task RunRenewalLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_renewInterval, ct);
                if (!await _lease.TryRenewAsync(ct)) { Demote(); return; }
            }
            catch (OperationCanceledException) { return; }
            catch (Exception) { Demote(); return; }
        }
    }

    private void Demote()
    {
        if (!_isCompactor) return;
        _isCompactor = false;
        CompactorRoleChanged?.Invoke(false);
    }

    public void Dispose()
    {
        _renewCts?.Cancel();
        _renewCts?.Dispose();
    }
}
