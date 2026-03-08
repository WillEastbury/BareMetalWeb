using System.Collections.Concurrent;
using System.Reflection;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;

namespace BareMetalWeb.ControlPlane;

/// <summary>
/// Background service that periodically streams heartbeats, telemetry snapshots,
/// and error events to a central BMW control-plane instance.
///
/// Configuration (Metal.config):
///   ControlPlane.Url                    — base URL of the control plane
///   ControlPlane.ApiKey                 — API key for authentication
///   ControlPlane.HeartbeatIntervalSeconds — heartbeat frequency (default 60)
///   ControlPlane.InstanceId             — identifier for this instance (default: machine name)
/// </summary>
public sealed class ControlPlaneService
{
    private readonly ControlPlaneClient _client;
    private readonly IMetricsTracker _metrics;
    private readonly IBufferedLogger? _logger;
    private readonly string _instanceId;
    private readonly string _version;
    private readonly int _heartbeatIntervalSeconds;

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
        IBufferedLogger? logger = null)
    {
        _client = client;
        _metrics = metrics;
        _logger = logger;
        _instanceId = config.GetValue("ControlPlane.InstanceId", Environment.MachineName);
        _heartbeatIntervalSeconds = config.GetValue("ControlPlane.HeartbeatIntervalSeconds", 60);

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
    /// Call this from the logger or error handler to buffer errors for streaming.
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

        // Seed baselines
        SeedBaselines();

        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(_heartbeatIntervalSeconds), ct)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) { break; }

            try
            {
                SendHeartbeat();
                SendTelemetryWindow();
                FlushErrors();
            }
            catch (Exception ex)
            {
                _logger?.Log(BmwLogLevel.Debug,
                    $"[BMW ControlPlane] Tick failed: {ex.Message}");
            }
        }
    }

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

    private void SendHeartbeat()
    {
        var snap = _metrics.GetSnapshot();
        double errorRate = snap.TotalRequests > 0
            ? (double)snap.Requests5xx / snap.TotalRequests
            : 0;

        _client.SendHeartbeat(new InstanceHeartbeat
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
        });
    }

    private void SendTelemetryWindow()
    {
        var snap = _metrics.GetSnapshot();
        var engine = BareMetalWeb.Data.EngineMetrics.GetSnapshot();
        var now = DateTime.UtcNow;

        _client.SendTelemetry(new TelemetrySnapshot
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
        });

        // Update baselines
        _prevTotalRequests = snap.TotalRequests;
        _prev2xx = snap.Requests2xx;
        _prev4xx = snap.Requests4xx;
        _prev5xx = snap.Requests5xx;
        _prevThrottled = snap.ThrottledRequests;
        _prevWalReads = engine.WalAppendCount;
        _prevWalCommits = engine.CommitCount;
        _prevWalCompactions = engine.CompactionCount;
    }

    private void FlushErrors()
    {
        while (_errorBuffer.TryDequeue(out var error))
            _client.SendError(error);
    }
}
