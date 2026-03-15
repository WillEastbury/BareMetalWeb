using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// A registered deployment node that runs the BMW bootstrap agent.
/// Tracks node identity, ring assignment, and current runtime version.
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

    /// <summary>Human-readable OS description reported during registration/attestation.</summary>
    [DataField(Label = "OS", Order = 11, List = true, View = true, ReadOnly = true)]
    public string OsDescription { get; set; } = string.Empty;

    /// <summary>Glibc version string reported during registration/attestation.</summary>
    [DataField(Label = "Glibc", Order = 12, View = true, ReadOnly = true)]
    public string GlibcVersion { get; set; } = string.Empty;

    /// <summary>SHA-256 hex of the first NIC MAC address (hardware binding).</summary>
    [DataField(Label = "MAC Hash", Order = 13, View = true, ReadOnly = true)]
    public string MacHash { get; set; } = string.Empty;

    /// <summary>UTC timestamp of the last successful attestation.</summary>
    [DataField(Label = "Last Attestation", Order = 14, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime LastAttestationUtc { get; set; }

    /// <summary>Bootstrap principal that registered this node.</summary>
    [DataField(Label = "Principal", Order = 15, View = true, ReadOnly = true)]
    public string BootstrapPrincipal { get; set; } = string.Empty;

    public override string ToString() => string.IsNullOrEmpty(DisplayName) ? NodeId : DisplayName;
}
