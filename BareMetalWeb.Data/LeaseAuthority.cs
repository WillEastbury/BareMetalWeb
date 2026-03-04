namespace BareMetalWeb.Data;

/// <summary>
/// Pluggable leader election strategy. Implementations control how a single
/// writer is elected in a multi-instance deployment.
///
/// Invariants:
/// - No two instances may hold the lease simultaneously
/// - Lease has a bounded duration with renewal
/// - On renewal failure, holder must immediately demote
/// - Each acquisition increments a monotonic Epoch
/// </summary>
public interface ILeaseAuthority
{
    /// <summary>Attempt to acquire the leader lease. Returns true if this instance is now leader.</summary>
    ValueTask<bool> TryAcquireAsync(CancellationToken ct);

    /// <summary>Renew the leader lease. Returns false if renewal failed (immediate demotion required).</summary>
    ValueTask<bool> TryRenewAsync(CancellationToken ct);

    /// <summary>Release the leader lease voluntarily.</summary>
    ValueTask ReleaseAsync(CancellationToken ct);

    /// <summary>Whether this instance currently holds the leader lease.</summary>
    bool IsLeader { get; }

    /// <summary>Current monotonic epoch (incremented on each leadership acquisition).</summary>
    long CurrentEpoch { get; }

    /// <summary>Unique identifier for this instance.</summary>
    string InstanceId { get; }
}

/// <summary>
/// Single-instance lease authority — always leader, epoch always 1.
/// Used when running a single server instance (no clustering).
/// </summary>
public sealed class LocalLeaseAuthority : ILeaseAuthority
{
    public LocalLeaseAuthority(string? instanceId = null)
    {
        InstanceId = instanceId ?? Environment.MachineName;
    }

    public ValueTask<bool> TryAcquireAsync(CancellationToken ct) => ValueTask.FromResult(true);
    public ValueTask<bool> TryRenewAsync(CancellationToken ct) => ValueTask.FromResult(true);
    public ValueTask ReleaseAsync(CancellationToken ct) => ValueTask.CompletedTask;
    public bool IsLeader => true;
    public long CurrentEpoch => 1;
    public string InstanceId { get; }
}

/// <summary>
/// File-based lease authority for multi-instance deployments on shared storage.
/// Uses a lock file with atomic create/delete semantics for leader election.
/// Epoch is stored in a separate file and incremented on each acquisition.
/// </summary>
public sealed class FileLeaseAuthority : ILeaseAuthority, IDisposable
{
    private readonly string _leaseFilePath;
    private readonly string _epochFilePath;
    private readonly TimeSpan _leaseDuration;
    private FileStream? _leaseFile;
    private long _epoch;
    private DateTime _leaseExpiryUtc;

    public FileLeaseAuthority(string directory, TimeSpan? leaseDuration = null, string? instanceId = null, string? leaseName = null)
    {
        Directory.CreateDirectory(directory);
        var suffix = string.IsNullOrEmpty(leaseName) ? "" : $"-{leaseName}";
        _leaseFilePath = Path.Combine(directory, $".cluster-lease{suffix}");
        _epochFilePath = Path.Combine(directory, $".cluster-epoch{suffix}");
        _leaseDuration = leaseDuration ?? TimeSpan.FromSeconds(15);
        InstanceId = instanceId ?? Environment.MachineName;
    }

    public bool IsLeader => _leaseFile != null && DateTime.UtcNow < _leaseExpiryUtc;
    public long CurrentEpoch => _epoch;
    public string InstanceId { get; }

    public ValueTask<bool> TryAcquireAsync(CancellationToken ct)
    {
        if (IsLeader) return ValueTask.FromResult(true);

        try
        {
            // Try to exclusively create the lease file
            _leaseFile = new FileStream(_leaseFilePath, FileMode.CreateNew, FileAccess.ReadWrite,
                FileShare.None, 4096, FileOptions.DeleteOnClose);

            // Write instance ID
            using var writer = new StreamWriter(_leaseFile, leaveOpen: true);
            writer.Write(InstanceId);
            writer.Flush();

            // Increment epoch atomically (write to temp, then rename)
            _epoch = IncrementEpoch();
            _leaseExpiryUtc = DateTime.UtcNow + _leaseDuration;

            return ValueTask.FromResult(true);
        }
        catch (IOException)
        {
            // Lease file already exists — check if stale via last-write time.
            // If stale, attempt a single CreateNew retry (if another instance beats us
            // to the delete+create, the retry will harmlessly fail with IOException).
            try
            {
                var info = new FileInfo(_leaseFilePath);
                if (info.Exists && DateTime.UtcNow - info.LastWriteTimeUtc > _leaseDuration * 2)
                {
                    try { File.Delete(_leaseFilePath); } catch { /* lost race — OK */ }

                    // Single retry (no recursion) — if another instance already re-created, we lose cleanly.
                    try
                    {
                        _leaseFile = new FileStream(_leaseFilePath, FileMode.CreateNew, FileAccess.ReadWrite,
                            FileShare.None, 4096, FileOptions.DeleteOnClose);
                        using var w = new StreamWriter(_leaseFile, leaveOpen: true);
                        w.Write(InstanceId);
                        w.Flush();
                        _epoch = IncrementEpoch();
                        _leaseExpiryUtc = DateTime.UtcNow + _leaseDuration;
                        return ValueTask.FromResult(true);
                    }
                    catch (IOException) { /* another instance won the race */ }
                }
            }
            catch { /* ignore stat errors */ }

            return ValueTask.FromResult(false);
        }
    }

    public ValueTask<bool> TryRenewAsync(CancellationToken ct)
    {
        if (_leaseFile == null) return ValueTask.FromResult(false);

        try
        {
            // Verify the lease file on disk is still ours (same path, still locked by us)
            if (!File.Exists(_leaseFilePath))
            {
                Demote();
                return ValueTask.FromResult(false);
            }

            // Touch the file to update LastWriteTime
            _leaseFile.Seek(0, SeekOrigin.Begin);
            _leaseFile.SetLength(0);
            using var writer = new StreamWriter(_leaseFile, leaveOpen: true);
            writer.Write($"{InstanceId}|{DateTime.UtcNow:O}");
            writer.Flush();
            _leaseFile.Flush(true);

            _leaseExpiryUtc = DateTime.UtcNow + _leaseDuration;
            return ValueTask.FromResult(true);
        }
        catch
        {
            // Renewal failed — demote immediately
            Demote();
            return ValueTask.FromResult(false);
        }
    }

    public ValueTask ReleaseAsync(CancellationToken ct)
    {
        Demote();
        return ValueTask.CompletedTask;
    }

    private void Demote()
    {
        _leaseFile?.Dispose();
        _leaseFile = null;
        _leaseExpiryUtc = DateTime.MinValue;
    }

    private long IncrementEpoch()
    {
        long epoch = 1;
        try
        {
            if (File.Exists(_epochFilePath))
                epoch = long.Parse(File.ReadAllText(_epochFilePath).Trim()) + 1;
        }
        catch { /* start at 1 */ }

        // Atomic write: temp file then rename (atomic on POSIX, near-atomic on Windows)
        var tempPath = _epochFilePath + ".tmp";
        File.WriteAllText(tempPath, epoch.ToString());
        File.Move(tempPath, _epochFilePath, overwrite: true);
        return epoch;
    }

    public void Dispose() => Demote();
}
