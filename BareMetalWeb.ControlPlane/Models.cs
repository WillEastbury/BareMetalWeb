namespace BareMetalWeb.ControlPlane;

// ── Webstore / gallery template models ──────────────────────────────────────

/// <summary>Summary of a template package available on the control plane webstore.</summary>
public sealed class GalleryListing
{
    public string? Name { get; set; }
    public string? Slug { get; set; }
    public string? Description { get; set; }
    public string? Icon { get; set; }
    public string? Version { get; set; }
    public string? Author { get; set; }
    public int EntityCount { get; set; }
    public int FieldCount { get; set; }
    public string? Category { get; set; }
    public string? PublishedAt { get; set; }
    public long Downloads { get; set; }
}

/// <summary>Response wrapper for the webstore listing endpoint.</summary>
public sealed class GalleryListingResponse
{
    public List<GalleryListing>? Packages { get; set; }
}

// ── Telemetry models ────────────────────────────────────────────────────────

/// <summary>Periodic health/version/uptime report from an instance.</summary>
public sealed class InstanceHeartbeat
{
    public string? InstanceId { get; set; }
    public string? Url { get; set; }
    public string? Version { get; set; }
    public string? CommitSha { get; set; }
    public long UptimeSeconds { get; set; }
    public string? Status { get; set; }
    public bool Ready { get; set; }
    public long RecordCount { get; set; }
    public int WalSegmentCount { get; set; }
    public string? LastBackupAt { get; set; }
    public string? LastCompactionAt { get; set; }
    public long MemoryMb { get; set; }
    public long RequestsTotal { get; set; }
    public double ErrorRate5xx { get; set; }
    public bool IsLeader { get; set; }
    public long Epoch { get; set; }
    public string? Timestamp { get; set; }
}

/// <summary>Aggregated metrics for a time window.</summary>
public sealed class TelemetrySnapshot
{
    public string? InstanceId { get; set; }
    public string? PeriodStart { get; set; }
    public string? PeriodEnd { get; set; }
    public long RequestsTotal { get; set; }
    public long Requests2xx { get; set; }
    public long Requests4xx { get; set; }
    public long Requests5xx { get; set; }
    public long ThrottledRequests { get; set; }
    public double P50Ms { get; set; }
    public double P95Ms { get; set; }
    public double P99Ms { get; set; }
    public long WalReads { get; set; }
    public long WalCommits { get; set; }
    public long WalCompactions { get; set; }
    public long GcGen0 { get; set; }
    public long GcGen1 { get; set; }
    public long GcGen2 { get; set; }
    public long GcAllocatedBytes { get; set; }
    public string? TopError { get; set; }
    public string? Timestamp { get; set; }
}

/// <summary>Individual error/fatal event streamed to the control plane.</summary>
public sealed class ErrorEvent
{
    public string? InstanceId { get; set; }
    public string? Level { get; set; }
    public string? Message { get; set; }
    public string? ExceptionType { get; set; }
    public string? StackTrace { get; set; }
    public string? Path { get; set; }
    public string? Method { get; set; }
    public int StatusCode { get; set; }
    public string? CorrelationId { get; set; }
    public string? Timestamp { get; set; }
}

/// <summary>Record of a completed backup, streamed to the control plane.</summary>
public sealed class BackupRecord
{
    public string? InstanceId { get; set; }
    public string? BackupId { get; set; }
    public string? Timestamp { get; set; }
    public long RecordCount { get; set; }
    public int SegmentCount { get; set; }
    public long SizeBytes { get; set; }
    public bool Validated { get; set; }
}

// ── Upgrade verification models ─────────────────────────────────────────────

/// <summary>
/// Response from GET /api/_cluster/upgrade-status.
/// Indicates whether a pod has self-reported the target version with healthy status.
/// </summary>
public sealed class UpgradeStatus
{
    public string? InstanceId { get; set; }
    public string? TargetVersion { get; set; }
    public string? CurrentVersion { get; set; }
    public bool Verified { get; set; }
    public bool Ready { get; set; }
    public double ErrorRate5xx { get; set; }
    public string? Timestamp { get; set; }
    public string? Reason { get; set; }
}

/// <summary>
/// Audit record of an upgrade verification decision, streamed to the control plane.
/// </summary>
public sealed class UpgradeVerificationRecord
{
    public string? InstanceId { get; set; }
    public string? TargetVersion { get; set; }
    public bool Success { get; set; }
    public string? Reason { get; set; }
    public string? Timestamp { get; set; }
}