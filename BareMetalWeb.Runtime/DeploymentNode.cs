using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// A registered deployment node that runs the BMW bootstrap agent.
/// Tracks node identity, ring assignment, current runtime version,
/// and policy-evaluation state (fingerprint, network location, telemetry).
/// </summary>
[DataEntity("Deployment Nodes", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1021)]
public class DeploymentNode : BaseDataObject
{
    /// <summary>Unique node identifier (set during provisioning).</summary>
    [DataField(Label = "Node ID", Order = 1, Required = true, List = true, View = true, Edit = true)]
    [DataIndex]
    public string NodeId { get; set; } = string.Empty;

    /// <summary>SHA256 hash of the node's authentication secret.</summary>
    [DataField(Label = "Secret Hash", Order = 2, Required = true, View = true)]
    public string SecretHash { get; set; } = string.Empty;

    /// <summary>Deployment ring this node belongs to (canary, early-access, production).</summary>
    [DataField(Label = "Ring", Order = 3, Required = true, List = true, View = true, Edit = true)]
    [DataIndex]
    public string Ring { get; set; } = "production";

    /// <summary>CPU architecture of the node (Arm64, X64).</summary>
    [DataField(Label = "Architecture", Order = 4, List = true, View = true, Edit = true)]
    public string Architecture { get; set; } = "Arm64";

    /// <summary>Version currently running on this node (reported by agent).</summary>
    [DataField(Label = "Current Version", Order = 5, List = true, View = true, ReadOnly = true)]
    public string CurrentVersion { get; set; } = string.Empty;

    /// <summary>UTC timestamp of the last heartbeat from this node's agent.</summary>
    [DataField(Label = "Last Seen", Order = 6, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime LastHeartbeatUtc { get; set; }

    /// <summary>Desired polling interval in seconds for this node.</summary>
    [DataField(Label = "Poll Interval (s)", Order = 7, List = true, View = true, Edit = true, FieldType = FormFieldType.Integer)]
    public int PollIntervalSeconds { get; set; } = 60;

    /// <summary>Whether this node is enabled (disabled nodes won't receive updates).</summary>
    [DataField(Label = "Enabled", Order = 8, List = true, View = true, Edit = true, FieldType = FormFieldType.YesNo)]
    public bool IsEnabled { get; set; } = true;

    /// <summary>Optional display name for the node.</summary>
    [DataField(Label = "Name", Order = 9, List = true, View = true, Edit = true)]
    public string DisplayName { get; set; } = string.Empty;

    /// <summary>Service principal or cluster endpoint for this node.</summary>
    [DataField(Label = "Cluster Endpoint", Order = 10, View = true, Edit = true)]
    public string ClusterEndpoint { get; set; } = string.Empty;

    // ── Policy fields (capsule issuance) ─────────────────────────────────────

    /// <summary>Device hardware fingerprint (SHA256 of MAC + machine-id + CPU serial).</summary>
    [DataField(Label = "Fingerprint", Order = 11, View = true)]
    public string Fingerprint { get; set; } = string.Empty;

    /// <summary>Node lifecycle status.</summary>
    [DataField(Label = "Status", Order = 12, List = true, View = true, Edit = true)]
    [DataIndex]
    public NodeStatus Status { get; set; } = NodeStatus.Active;

    /// <summary>UTC timestamp of last telemetry received from this node.</summary>
    [DataField(Label = "Last Telemetry", Order = 13, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime LastTelemetryUtc { get; set; }

    /// <summary>Whether the node's last shutdown was clean (graceful).</summary>
    [DataField(Label = "Clean Shutdown", Order = 14, View = true, ReadOnly = true, FieldType = FormFieldType.YesNo)]
    public bool LastShutdownClean { get; set; } = true;

    /// <summary>IP address from the most recent capsule or heartbeat request.</summary>
    [DataField(Label = "Last IP", Order = 15, View = true, ReadOnly = true)]
    public string LastKnownIp { get; set; } = string.Empty;

    /// <summary>ASN (Autonomous System Number) from the most recent request.</summary>
    [DataField(Label = "Last ASN", Order = 16, View = true, ReadOnly = true)]
    public string LastKnownAsn { get; set; } = string.Empty;

    /// <summary>Geographic region from the most recent request.</summary>
    [DataField(Label = "Last Region", Order = 17, View = true, ReadOnly = true)]
    public string LastKnownRegion { get; set; } = string.Empty;

    /// <summary>UTC timestamp of last capsule issuance.</summary>
    [DataField(Label = "Last Capsule Issued", Order = 18, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime LastCapsuleIssuedUtc { get; set; }

    public override string ToString() => string.IsNullOrEmpty(DisplayName) ? NodeId : DisplayName;
}

/// <summary>Node lifecycle status for policy evaluation.</summary>
public enum NodeStatus
{
    Active = 0,
    Revoked = 1,
    Quarantined = 2,
}
