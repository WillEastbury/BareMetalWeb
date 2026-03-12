using System.Collections.Concurrent;
using System.Reflection;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;

namespace BareMetalWeb.ControlPlane;

/// <summary>
/// Background service that periodically streams heartbeats, telemetry snapshots,
/// and error events to a central BMW control-plane instance.
///
/// Offline behaviour: when the endpoint is unreachable, outbound records are
/// written to a local disk buffer (<see cref="TelemetryBuffer"/>) and retried
/// with exponential back-off + jitter.  The buffer is bounded; when it is full
/// the oldest record is evicted (oldest-first drop policy).  All operations are
/// non-blocking and never impact the request-handling path.
///
/// Configuration (Metal.config):
///   ControlPlane.Url                    — base URL of the control plane
///   ControlPlane.ApiKey                 — API key for authentication
///   ControlPlane.HeartbeatIntervalSeconds — heartbeat frequency (default 60)
///   ControlPlane.InstanceId             — identifier for this instance (default: machine name)
///   ControlPlane.BufferDir              — directory for the pending-record buffer (default: {dataRoot}/cpbuffer)
///   ControlPlane.BufferMaxRecords       — max buffered records before oldest is dropped (default: 10000)
/// </summary>
public sealed class ControlPlaneService
{
    private readonly ControlPlaneClient _client;
    private readonly IMetricsTracker _metrics;
    private readonly IBufferedLogger? _logger;
    private readonly string _instanceId;
    private readonly string _version;
    private readonly int _heartbeatIntervalSeconds;
    private readonly TelemetryBuffer _buffer;

    // Snapshot baselines for computing deltas in telemetry windows
    private long _prevTotalRequests;
    private long _prev2xx;
    private long _prev4xx;
    private long _prev5xx;
    private long _prevThrottled;
    private long _prevWalReads;
    private long _prevWalCommits;
    private long _prevWalCompactions;

    // Error buffer: accumulates errors between telemetry flushes
    private readonly ConcurrentQueue<ErrorEvent> _errorBuffer = new();
    private const int MaxBufferedErrors = 100;

    // Health tracking
    private long _retryCount;
    private long _drainSuccessCount;
    private volatile bool _isOnline;
    private DateTime? _lastSuccessfulSendUtc;

    // Retry back-off state
    private int _consecutiveFailures;
    private static readonly TimeSpan MinBackoff = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromMinutes(5);

    // Optional delegates for data the service can't access directly
    private Func<long>? _getRecordCount;
    private Func<int>? _getWalSegmentCount;
    private Func<string?>? _getLastBackupAt;
    private Func<bool>? _getIsLeader;
    private Func<long>? _getEpoch;
    private Func<string?>? _getInstanceUrl;

    public ControlPlaneService(
        ControlPlaneClient client,
        IMetricsTracker metrics,
        BmwConfig config,
        IBufferedLogger? logger = null,
        string? bufferDir = null)
    {
        _client = client;
        _metrics = metrics;
        _logger = logger;
        _instanceId = config.GetValue("ControlPlane.InstanceId", Environment.MachineName);
        _heartbeatIntervalSeconds = config.GetValue("ControlPlane.HeartbeatIntervalSeconds", 60);

        var resolvedBufferDir = bufferDir
            ?? config.GetValue("ControlPlane.BufferDir", "")
            .Let(d => string.IsNullOrEmpty(d)
                ? Path.Combine(AppContext.BaseDirectory, "cpbuffer")
                : d);

        var maxRecords = config.GetValue("ControlPlane.BufferMaxRecords", TelemetryBuffer.DefaultMaxRecords);
        _buffer = new TelemetryBuffer(resolvedBufferDir, maxRecords);

        _version = Assembly.GetEntryAssembly()
            ?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? Assembly.GetEntryAssembly()?.GetName().Version?.ToString(3)
            ?? "unknown";
    }

    /// <summary>Wire up optional data sources that live outside this library.</summary>
    public ControlPlaneService WithDataSources(
        Func<long>? recordCount = null,
        Func<int>? walSegmentCount = null,
        Func<string?>? lastBackupAt = null,
        Func<bool>? isLeader = null,
        Func<long>? epoch = null,
        Func<string?>? instanceUrl = null)
    {
        _getRecordCount = recordCount;
        _getWalSegmentCount = walSegmentCount;
        _getLastBackupAt = lastBackupAt;
        _getIsLeader = isLeader;
        _getEpoch = epoch;
        _getInstanceUrl = instanceUrl;
        return this;
    }

    /// <summary>
    /// Buffer an error event for streaming to the control plane.
    /// Safe to call from any thread (including the logging hot path).
    /// When the control plane is online the event will be delivered on the next tick;
    /// when offline it is held in the offline disk buffer.
    /// </summary>
    public void BufferError(string level, string message, string? exceptionType = null,
        string? stackTrace = null, string? path = null, string? method = null,
        int statusCode = 0, string? correlationId = null)
    {
        if (_errorBuffer.Count >= MaxBufferedErrors) return;
        _errorBuffer.Enqueue(new ErrorEvent
        {
            InstanceId = _instanceId,
            Level = level,
            Message = message,
            ExceptionType = exceptionType,
            StackTrace = stackTrace?.Length > 2000 ? stackTrace[..2000] : stackTrace,
            Path = path,
            Method = method,
            StatusCode = statusCode,
            CorrelationId = correlationId,
            Timestamp = DateTime.UtcNow.ToString("O"),
        });
    }

    /// <summary>
    /// Notify the control plane that a backup completed.
    /// Call this after WalBackupService.CreateBackup() succeeds.
    /// </summary>
    public void NotifyBackupCompleted(string backupId, long recordCount, int segmentCount,
        long sizeBytes, bool validated)
    {
        _client.SendBackupRecord(new BackupRecord
        {
            InstanceId = _instanceId,
            BackupId = backupId,
            Timestamp = DateTime.UtcNow.ToString("O"),
            RecordCount = recordCount,
            SegmentCount = segmentCount,
            SizeBytes = sizeBytes,
            Validated = validated,
        });
    }

    /// <summary>
    /// Returns a point-in-time health snapshot of the telemetry pipeline:
    /// queue depth, last successful send, dropped and retry counters, online status.
    /// </summary>
    public ObservabilityHealth GetHealth() => new()
    {
        PendingQueueDepth = _buffer.QueueDepth,
        DroppedCount = _buffer.DroppedCount,
        RetryCount = Interlocked.Read(ref _retryCount),
        LastSuccessfulSendUtc = _lastSuccessfulSendUtc,
        IsOnline = _isOnline,
    };

    /// <summary>Main loop — runs until cancellation.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        if (!_client.IsConfigured)
        {
            _logger?.Log(BmwLogLevel.Info,
                "[BMW ControlPlane] Not configured (ControlPlane.Url/ApiKey missing) — disabled.");
            return;
        }

        _logger?.Log(BmwLogLevel.Info,
            $"[BMW ControlPlane] Streaming to control plane every {_heartbeatIntervalSeconds}s as '{_instanceId}'.");

        if (_buffer.QueueDepth > 0)
            _logger?.Log(BmwLogLevel.Info,
                $"[BMW ControlPlane] Loaded {_buffer.QueueDepth} pending record(s) from offline buffer.");

        // Seed baselines
        SeedBaselines();

        while (!ct.IsCancellationRequested)
        {
            // Wait for the next heartbeat interval, or the current back-off delay
            var delay = _consecutiveFailures == 0
                ? TimeSpan.FromSeconds(_heartbeatIntervalSeconds)
                : ComputeBackoff(_consecutiveFailures);

            try
            {
                await Task.Delay(delay, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }

            try
            {
                bool anyFailed = false;

                anyFailed |= !await SendHeartbeatAsync(ct).ConfigureAwait(false);
                anyFailed |= !await SendTelemetryWindowAsync(ct).ConfigureAwait(false);
                anyFailed |= !await FlushErrorsAsync(ct).ConfigureAwait(false);

                if (anyFailed)
                {
                    _consecutiveFailures++;
                    _isOnline = false;
                    _logger?.Log(BmwLogLevel.Debug,
                        $"[BMW ControlPlane] Endpoint unreachable — back-off #{_consecutiveFailures}, " +
                        $"buffer depth={_buffer.QueueDepth}, dropped={_buffer.DroppedCount}");
                }
                else
                {
                    if (_consecutiveFailures > 0)
                        _logger?.Log(BmwLogLevel.Info,
                            $"[BMW ControlPlane] Connectivity restored after {_consecutiveFailures} failure(s). " +
                            $"Draining {_buffer.QueueDepth} buffered record(s).");

                    _consecutiveFailures = 0;
                    _isOnline = true;
                    _lastSuccessfulSendUtc = DateTime.UtcNow;

                    // Drain any offline-buffered records now that we are online
                    await DrainBufferAsync(ct).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                _logger?.Log(BmwLogLevel.Debug,
                    $"[BMW ControlPlane] Tick failed: {ex.Message}");
            }
        }
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    private void SeedBaselines()
    {
        var snap = _metrics.GetSnapshot();
        _prevTotalRequests = snap.TotalRequests;
        _prev2xx = snap.Requests2xx;
        _prev4xx = snap.Requests4xx;
        _prev5xx = snap.Requests5xx;
        _prevThrottled = snap.ThrottledRequests;

        var engine = BareMetalWeb.Data.EngineMetrics.GetSnapshot();
        _prevWalReads = engine.WalAppendCount;
        _prevWalCommits = engine.CommitCount;
        _prevWalCompactions = engine.CompactionCount;
    }

    private async Task<bool> SendHeartbeatAsync(CancellationToken ct)
    {
        var snap = _metrics.GetSnapshot();
        double errorRate = snap.TotalRequests > 0
            ? (double)snap.Requests5xx / snap.TotalRequests
            : 0;

        var heartbeat = new InstanceHeartbeat
        {
            InstanceId = _instanceId,
            Url = _getInstanceUrl?.Invoke(),
            Version = _version,
            UptimeSeconds = (long)snap.ProcessUptime.TotalSeconds,
            Status = "healthy",
            Ready = true,
            RecordCount = _getRecordCount?.Invoke() ?? 0,
            WalSegmentCount = _getWalSegmentCount?.Invoke() ?? 0,
            LastBackupAt = _getLastBackupAt?.Invoke(),
            MemoryMb = snap.WorkingSet64 / (1024 * 1024),
            RequestsTotal = snap.TotalRequests,
            ErrorRate5xx = Math.Round(errorRate, 6),
            IsLeader = _getIsLeader?.Invoke() ?? true,
            Epoch = _getEpoch?.Invoke() ?? 0,
            Timestamp = DateTime.UtcNow.ToString("O"),
        };

        var ok = await _client.TrySendAsync("InstanceHeartbeat", heartbeat).ConfigureAwait(false);
        if (!ok)
            _buffer.TryEnqueue(_client.Serialize(heartbeat).PrependEntityType("InstanceHeartbeat"));
        return ok;
    }

    private async Task<bool> SendTelemetryWindowAsync(CancellationToken ct)
    {
        var snap = _metrics.GetSnapshot();
        var engine = BareMetalWeb.Data.EngineMetrics.GetSnapshot();
        var now = DateTime.UtcNow;

        var telemetry = new TelemetrySnapshot
        {
            InstanceId = _instanceId,
            PeriodStart = now.AddSeconds(-_heartbeatIntervalSeconds).ToString("O"),
            PeriodEnd = now.ToString("O"),
            RequestsTotal = snap.TotalRequests - _prevTotalRequests,
            Requests2xx = snap.Requests2xx - _prev2xx,
            Requests4xx = snap.Requests4xx - _prev4xx,
            Requests5xx = snap.Requests5xx - _prev5xx,
            ThrottledRequests = snap.ThrottledRequests - _prevThrottled,
            P50Ms = snap.RecentAverageResponseTime.TotalMilliseconds,
            P95Ms = snap.RecentP95ResponseTime.TotalMilliseconds,
            P99Ms = snap.RecentP99ResponseTime.TotalMilliseconds,
            WalReads = engine.WalAppendCount - _prevWalReads,
            WalCommits = engine.CommitCount - _prevWalCommits,
            WalCompactions = engine.CompactionCount - _prevWalCompactions,
            GcGen0 = snap.GcGen0Collections,
            GcGen1 = snap.GcGen1Collections,
            GcGen2 = snap.GcGen2Collections,
            GcAllocatedBytes = snap.GcTotalAllocatedBytes,
            Timestamp = now.ToString("O"),
        };

        // Update baselines regardless of send success so deltas stay accurate
        _prevTotalRequests = snap.TotalRequests;
        _prev2xx = snap.Requests2xx;
        _prev4xx = snap.Requests4xx;
        _prev5xx = snap.Requests5xx;
        _prevThrottled = snap.ThrottledRequests;
        _prevWalReads = engine.WalAppendCount;
        _prevWalCommits = engine.CommitCount;
        _prevWalCompactions = engine.CompactionCount;

        var ok = await _client.TrySendAsync("TelemetrySnapshot", telemetry).ConfigureAwait(false);
        if (!ok)
            _buffer.TryEnqueue(_client.Serialize(telemetry).PrependEntityType("TelemetrySnapshot"));
        return ok;
    }

    private async Task<bool> FlushErrorsAsync(CancellationToken ct)
    {
        bool allOk = true;
        while (_errorBuffer.TryDequeue(out var error))
        {
            var ok = await _client.TrySendAsync("ErrorEvent", error).ConfigureAwait(false);
            if (!ok)
            {
                _buffer.TryEnqueue(_client.Serialize(error).PrependEntityType("ErrorEvent"));
                allOk = false;
            }
        }
        return allOk;
    }

    /// <summary>
    /// Drain the offline buffer by replaying each pending record.
    /// Stops on first transient failure to preserve ordering; re-persists remaining records.
    /// Records that have exceeded <see cref="MaxDrainRetries"/> attempts are dropped
    /// (dead-letter policy) and counted in <see cref="_retryCount"/>.
    /// </summary>
    private async Task DrainBufferAsync(CancellationToken ct)
    {
        int sent = 0;
        while (!ct.IsCancellationRequested && _buffer.TryDequeue(out var raw))
        {
            if (!raw.TryParseEntityRecord(out var entityType, out var json, out var attempt))
                continue; // malformed — skip

            Interlocked.Increment(ref _retryCount);
            var ok = await _client.TrySendRawAsync(entityType, json).ConfigureAwait(false);
            if (!ok)
            {
                if (attempt < MaxDrainRetries)
                {
                    // Re-queue at the back with incremented retry count; stop this cycle
                    _buffer.TryEnqueue(raw.IncrementAttempt(attempt));
                }
                else
                {
                    // Exceeded retry limit — dead-letter drop
                    _logger?.Log(BmwLogLevel.Debug,
                        $"[BMW ControlPlane] Dropping buffered {entityType} record after {attempt} retries.");
                }
                break;
            }
            sent++;
            Interlocked.Increment(ref _drainSuccessCount);
        }

        if (sent > 0)
        {
            _lastSuccessfulSendUtc = DateTime.UtcNow;
            _buffer.PersistCurrentState();
            _logger?.Log(BmwLogLevel.Debug,
                $"[BMW ControlPlane] Drained {sent} buffered record(s), " +
                $"{_buffer.QueueDepth} remaining.");
        }
    }

    private const int MaxDrainRetries = 10;

    /// <summary>
    /// Compute back-off delay for the given number of consecutive failures.
    /// Uses exponential back-off with ±20 % jitter, capped at <see cref="MaxBackoff"/>.
    /// </summary>
    internal static TimeSpan ComputeBackoff(int consecutiveFailures)
    {
        // 2^n * MinBackoff: exponent is capped at 10 (multiplier 2^10 = 1024), then MaxBackoff clamps the result
        var exp = Math.Min(consecutiveFailures - 1, 10);
        var baseTicks = (long)(MinBackoff.Ticks * Math.Pow(2, exp));
        var capped = Math.Min(baseTicks, MaxBackoff.Ticks);

        // ±20 % jitter to spread retries across instances
        var jitter = (long)(capped * 0.2 * (Random.Shared.NextDouble() * 2.0 - 1.0));
        var final = Math.Max(MinBackoff.Ticks, capped + jitter);
        return TimeSpan.FromTicks(final);
    }
}

// ── String helpers (internal, allocation-minimal) ────────────────────────────

internal static class RecordEnvelopeExtensions
{
    private const char Sep = '\x1F'; // ASCII unit-separator — not valid in JSON

    /// <summary>
    /// Encode a JSON payload into a stored envelope: <c>{entityType}\x1F{attempt}\x1F{json}</c>.
    /// The attempt counter starts at 0 and is incremented each time the record is re-queued.
    /// </summary>
    internal static string PrependEntityType(this string json, string entityType)
        => string.Concat(entityType, Sep, "0", Sep, json);

    /// <summary>Return a copy of the envelope with the attempt counter incremented by one.</summary>
    internal static string IncrementAttempt(this string envelope, int currentAttempt)
    {
        if (!envelope.TryParseEntityRecord(out var entityType, out var json, out _))
            return envelope;
        return string.Concat(entityType, Sep, (currentAttempt + 1).ToString(), Sep, json);
    }

    /// <summary>Split a stored envelope back into entity type, attempt count, and JSON payload.</summary>
    internal static bool TryParseEntityRecord(this string raw,
        out string entityType, out string json, out int attempt)
    {
        attempt = 0;
        var first = raw.IndexOf(Sep);
        if (first <= 0)
        {
            entityType = string.Empty;
            json = string.Empty;
            return false;
        }
        entityType = raw[..first];
        var rest = raw[(first + 1)..];

        // Support legacy format (no attempt field) for backward compat with existing buffer files
        var second = rest.IndexOf(Sep);
        if (second < 0)
        {
            // Legacy: entityType\x1Fjson
            json = rest;
            return true;
        }

        if (!int.TryParse(rest[..second], out attempt))
            attempt = 0;
        json = rest[(second + 1)..];
        return true;
    }
}

// ── Tiny helper to avoid 'Let' extension call on strings inline ───────────────
file static class StringLetExtension
{
    internal static TResult Let<T, TResult>(this T value, Func<T, TResult> selector)
        => selector(value);
}
