namespace BareMetalWeb.ControlPlane;

using System.Text.Json.Serialization;

// ── Deployment ring ──────────────────────────────────────────────────────────

/// <summary>
/// Staged deployment ring that determines which runtime version an agent receives.
/// Rings are ordered from fastest-moving (Testing) to most stable (Main).
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<DeploymentRing>))]
public enum DeploymentRing
{
    Testing = 0,
    Canary  = 1,
    Early   = 2,
    Main    = 3,
}

// ── Agent / node identity ────────────────────────────────────────────────────

/// <summary>
/// First-boot registration request.  Sent by the agent to <c>POST /api/bootstrap/register</c>
/// with a Bearer token derived from the hardware key.
/// </summary>
public sealed class NodeRegistrationRequest
{
    /// <summary>Hardware-derived node ID (UUID shaped, deterministic per device).</summary>
    public string NodeId             { get; set; } = "";
    /// <summary>SHA-256 hex of the bearer secret — never transmitted in plain text.</summary>
    public string SecretHash         { get; set; } = "";
    /// <summary>Bootstrap principal used to authorise the registration (e.g. the operator identity).</summary>
    public string BootstrapPrincipal { get; set; } = "";
    /// <summary>CPU architecture string (e.g. "X64", "Arm64").</summary>
    public string Architecture       { get; set; } = "";
    /// <summary>Human-readable OS description from /etc/os-release PRETTY_NAME.</summary>
    public string OsDescription      { get; set; } = "";
    /// <summary>Glibc version string (e.g. "2.38"), or "n/a" on non-Linux.</summary>
    public string GlibcVersion       { get; set; } = "";
    /// <summary>SHA-256 hex of the first NIC MAC address (hardware binding).</summary>
    public string MacHash            { get; set; } = "";
}

/// <summary>
/// Per-boot attestation record.  Sent by the agent to <c>POST /api/bootstrap/attest</c>
/// on each startup so the control plane can verify the node's platform has not changed.
/// </summary>
public sealed class NodeAttestationRequest
{
    /// <summary>Registered node ID.</summary>
    public string NodeId        { get; set; } = "";
    /// <summary>CPU architecture string.</summary>
    public string Architecture  { get; set; } = "";
    /// <summary>Human-readable OS description.</summary>
    public string OsDescription { get; set; } = "";
    /// <summary>Glibc version string.</summary>
    public string GlibcVersion  { get; set; } = "";
    /// <summary>SHA-256 hex of the first NIC MAC (hardware binding check).</summary>
    public string MacHash       { get; set; } = "";
    /// <summary>ISO-8601 UTC timestamp of this attestation.</summary>
    public string Timestamp     { get; set; } = "";
}

/// <summary>
/// Per-node identity provisioned by the control plane and stored locally as
/// <c>/var/lib/bmw/node.json</c> (or an equivalent path on the target OS).
/// The agent reads this file at startup to authenticate itself.
/// </summary>
public sealed class NodeIdentity
{
    /// <summary>Unique identifier for this node (e.g. a UUID assigned at provisioning).</summary>
    public string NodeId          { get; set; } = "";
    /// <summary>Service-principal name used for audit and RBAC on the control plane.</summary>
    public string ServicePrincipal { get; set; } = "";
    /// <summary>Bearer secret used in <c>Authorization: Bearer {Secret}</c> requests.</summary>
    public string Secret          { get; set; } = "";
    /// <summary>Control-plane cluster endpoint base URL.</summary>
    public string ClusterEndpoint { get; set; } = "";
    /// <summary>TLS certificate fingerprint (SHA-256 hex) expected from the control plane.</summary>
    public string CertFingerprint { get; set; } = "";
    /// <summary>Deployment ring this node belongs to (serialised as a string, e.g. "Canary").</summary>
    public DeploymentRing Ring    { get; set; } = DeploymentRing.Main;
}

// ── Agent polling models ─────────────────────────────────────────────────────

/// <summary>
/// Response from <c>GET /api/runtime/desired/{nodeId}</c>.
/// Tells the agent which runtime version it should be running and where to get it.
/// </summary>
public sealed class RuntimeResponse
{
    /// <summary>The version the agent should be running for its ring.</summary>
    public string? DesiredVersion { get; set; }
    /// <summary>SHA-256 hex checksum of the binary at <see cref="DownloadUrl"/>.</summary>
    public string? Sha256 { get; set; }
    /// <summary>
    /// URL path (relative to the cluster endpoint) from which the runtime binary
    /// can be downloaded.  Append to <see cref="NodeIdentity.ClusterEndpoint"/>.
    /// </summary>
    public string? DownloadUrl { get; set; }
    /// <summary>Seconds the agent should wait before the next poll.</summary>
    public int PollSeconds { get; set; }
}

/// <summary>
/// Describes a runtime binary artefact that has been pushed to the control plane by CI.
/// </summary>
public sealed class RuntimeArtifact
{
    /// <summary>Semantic version string (e.g. "1.4.2").</summary>
    public string? Version { get; set; }
    /// <summary>Commit SHA that produced this build.</summary>
    public string? CommitSha { get; set; }
    /// <summary>Target platform (e.g. "linux-x64", "linux-arm64").</summary>
    public string? Platform { get; set; }
    /// <summary>SHA-256 hex checksum of the binary.</summary>
    public string? Sha256 { get; set; }
    /// <summary>Size of the binary in bytes.</summary>
    public long SizeBytes { get; set; }
    /// <summary>UTC timestamp when this artefact was registered.</summary>
    public string? PublishedAt { get; set; }
    /// <summary>Minimum ring that may receive this version (e.g. Testing gets it first).</summary>
    public DeploymentRing MinRing { get; set; }
}

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