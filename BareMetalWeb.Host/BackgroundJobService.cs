using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Data;

namespace BareMetalWeb.Host;

/// <summary>
/// Status values for a background job, following the Azure async-request-reply pattern.
/// </summary>
public enum BackgroundJobStatus
{
    Queued,
    Running,
    Succeeded,
    Failed
}

/// <summary>
/// Allows a background job callback to report its progress.
/// </summary>
public interface IJobProgressReporter
{
    /// <summary>Report progress (0-100) and a human-readable description.</summary>
    void Report(int percentComplete, string description);

    /// <summary>Token that is cancelled if the job is cancelled or the server is shutting down.</summary>
    CancellationToken CancellationToken { get; }
}

/// <summary>
/// Immutable snapshot of a job's current state, safe to return from the status endpoint.
/// </summary>
public sealed record JobStatusSnapshot(
    string JobId,
    string OperationName,
    BackgroundJobStatus Status,
    int PercentComplete,
    string Description,
    DateTime StartedAt,
    DateTime? CompletedAt,
    string? Error,
    string? ResultUrl,
    string InstanceId = "");

/// <summary>
/// In-process registry that starts and tracks background jobs.
/// Follows the Azure async-request-reply cloud pattern:
///   POST → 202 Accepted + Location: /api/jobs/{jobId}
///   GET /api/jobs/{jobId} → 202 while running, 200 on completion.
/// Jobs are retained in memory for <see cref="RetentionPeriod"/> after completion.
/// Job status is also persisted to the WAL store so all instances can see them.
/// </summary>
public sealed class BackgroundJobService
{
    /// <summary>Singleton instance; no DI needed in the bare-metal model.</summary>
    public static readonly BackgroundJobService Instance = new();

    internal static readonly TimeSpan RetentionPeriod = TimeSpan.FromHours(1);

    /// <summary>
    /// Identifies this server instance in job records.
    /// Format: <c>MachineName/ProcessId</c>.
    /// </summary>
    public static readonly string InstanceId =
        $"{Environment.MachineName}/{Environment.ProcessId}";

    private readonly ConcurrentDictionary<string, JobEntry> _jobs =
        new(StringComparer.OrdinalIgnoreCase);

    // ──────────────────────────────────────────────────────────────
    // Public API
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Enqueue <paramref name="work"/> as a fire-and-forget background task and
    /// return the new job ID immediately.
    /// </summary>
    /// <param name="operationName">Human-readable name shown in the status response.</param>
    /// <param name="resultUrl">
    ///   Optional URL included in the <c>Location</c> header when the job succeeds
    ///   (e.g. the admin page that triggered the job).
    /// </param>
    /// <param name="work">
    ///   The long-running work to execute. Receives an <see cref="IJobProgressReporter"/>
    ///   and a <see cref="CancellationToken"/>; should call
    ///   <see cref="IJobProgressReporter.Report"/> periodically.
    /// </param>
    public string StartJob(
        string operationName,
        string? resultUrl,
        Func<IJobProgressReporter, CancellationToken, Task> work)
    {
        if (work == null) throw new ArgumentNullException(nameof(work));

        var jobId = Guid.NewGuid().ToString("N");
        var entry = new JobEntry
        {
            JobId = jobId,
            OperationName = operationName ?? string.Empty,
            ResultUrl = resultUrl
        };
        _jobs[jobId] = entry;

        // Persist initial state to WAL so other instances can see it immediately.
        _ = PersistToWalAsync(entry);

        _ = Task.Run(async () =>
        {
            entry.Status = BackgroundJobStatus.Running;
            // Persist running state.
            _ = PersistToWalAsync(entry);
            var reporter = new ProgressReporter(entry);
            try
            {
                await work(reporter, entry.Cts.Token).ConfigureAwait(false);
                entry.PercentComplete = 100;
                entry.Status = BackgroundJobStatus.Succeeded;
            }
            catch (OperationCanceledException)
            {
                entry.Status = BackgroundJobStatus.Failed;
                entry.Error = "Job was cancelled.";
            }
            catch (Exception ex)
            {
                entry.Status = BackgroundJobStatus.Failed;
                entry.Error = ex.Message;
            }
            finally
            {
                entry.CompletedAt = DateTime.UtcNow;
                // Persist final state.
                _ = PersistToWalAsync(entry);
            }
        });

        PruneOldJobs();
        return jobId;
    }

    /// <summary>
    /// Requests cancellation of the job with the given ID.
    /// Returns <c>true</c> if the job was found and cancellation was requested;
    /// <c>false</c> if the job ID is unknown or the job has already completed.
    /// <para>
    /// Note: there is an inherent benign race between the status check and the Cancel()
    /// call. If the job completes between those two operations, Cancel() is called on a
    /// completed <see cref="CancellationTokenSource"/>, which is safe and idempotent.
    /// </para>
    /// </summary>
    public bool CancelJob(string jobId)
    {
        if (!_jobs.TryGetValue(jobId, out var entry))
            return false;

        if (entry.Status is BackgroundJobStatus.Succeeded or BackgroundJobStatus.Failed)
            return false;

        entry.Cts.Cancel();
        return true;
    }

    /// <summary>
    /// Returns point-in-time snapshots of all currently tracked jobs
    /// (both active and recently completed, up to <see cref="RetentionPeriod"/>).
    /// </summary>
    public IReadOnlyList<JobStatusSnapshot> GetAllJobs()
    {
        var result = new List<JobStatusSnapshot>();
        foreach (var kv in _jobs)
        {
            var entry = kv.Value;
            result.Add(new JobStatusSnapshot(
                entry.JobId,
                entry.OperationName,
                entry.Status,
                entry.PercentComplete,
                entry.Description,
                entry.StartedAt,
                entry.CompletedAt,
                entry.Error,
                entry.ResultUrl,
                InstanceId));
        }
        return result;
    }

    /// <summary>
    /// Returns a point-in-time snapshot of the job, or <c>false</c> if the job
    /// ID is unknown (e.g. pruned after <see cref="RetentionPeriod"/>).
    /// </summary>
    public bool TryGetJob(string jobId, out JobStatusSnapshot? snapshot)
    {
        if (!_jobs.TryGetValue(jobId, out var entry))
        {
            snapshot = null;
            return false;
        }

        snapshot = new JobStatusSnapshot(
            entry.JobId,
            entry.OperationName,
            entry.Status,
            entry.PercentComplete,
            entry.Description,
            entry.StartedAt,
            entry.CompletedAt,
            entry.Error,
            entry.ResultUrl,
            InstanceId);
        return true;
    }

    // ──────────────────────────────────────────────────────────────
    // Internals
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Upserts a <see cref="WalPersistedJob"/> record to the data store so that
    /// all instances can see current job status. Failures are silently swallowed
    /// to prevent WAL errors from affecting job execution.
    /// </summary>
    private static async Task PersistToWalAsync(JobEntry entry)
    {
        try
        {
            var store = DataStoreProvider.Current;
            var walJob = new WalPersistedJob
            {
                Key          = WalPersistedJob.DeriveKey(entry.JobId),
                JobId        = entry.JobId,
                OperationName = entry.OperationName,
                Status       = entry.Status switch
                {
                    BackgroundJobStatus.Queued    => "queued",
                    BackgroundJobStatus.Running   => "running",
                    BackgroundJobStatus.Succeeded => "succeeded",
                    BackgroundJobStatus.Failed    => "failed",
                    _                             => "unknown"
                },
                PercentComplete = entry.PercentComplete,
                Description  = entry.Description,
                StartedAtUtc = entry.StartedAt,
                CompletedAtUtc = entry.CompletedAt,
                Error        = entry.Error,
                ResultUrl    = entry.ResultUrl,
                InstanceId   = InstanceId
            };
            await store.SaveAsync(walJob).ConfigureAwait(false);
        }
        catch
        {
            // WAL persistence is best-effort; never let it affect job execution.
        }
    }

    private void PruneOldJobs()
    {
        var cutoff = DateTime.UtcNow - RetentionPeriod;
        foreach (var kv in _jobs)
        {
            if (kv.Value.Status is BackgroundJobStatus.Succeeded or BackgroundJobStatus.Failed
                && kv.Value.CompletedAt.HasValue
                && kv.Value.CompletedAt.Value < cutoff)
            {
                if (_jobs.TryRemove(kv.Key, out var removed))
                    removed.Cts.Dispose();
            }
        }
    }

    // Mutable per-job state (all fields written only from the single Task.Run worker
    // except Status/PercentComplete/Description which are written atomically enough
    // for a progress-polling use case).
    internal sealed class JobEntry
    {
        public string JobId { get; init; } = string.Empty;
        public string OperationName { get; init; } = string.Empty;
        public volatile BackgroundJobStatus Status = BackgroundJobStatus.Queued;
        public volatile int PercentComplete;
        public volatile string Description = string.Empty;
        public DateTime StartedAt { get; } = DateTime.UtcNow;
        public DateTime? CompletedAt { get; set; }
        public string? Error { get; set; }
        public string? ResultUrl { get; init; }
        public CancellationTokenSource Cts { get; } = new();
    }

    private sealed class ProgressReporter(JobEntry entry) : IJobProgressReporter
    {
        private int _lastPersistedPct = -1;

        public CancellationToken CancellationToken => entry.Cts.Token;

        public void Report(int percentComplete, string description)
        {
            entry.PercentComplete = Math.Clamp(percentComplete, 0, 100);
            entry.Description = description ?? string.Empty;

            // Persist to WAL on every 10% milestone to keep cross-instance view fresh
            // without excessive writes. Use Interlocked to safely advance the milestone
            // across concurrent calls.
            var pct = entry.PercentComplete;
            var milestone = (pct / 10) * 10;
            var prev = Volatile.Read(ref _lastPersistedPct);
            if (milestone > prev &&
                Interlocked.CompareExchange(ref _lastPersistedPct, milestone, prev) == prev)
            {
                _ = PersistToWalAsync(entry);
            }
        }
    }
}
