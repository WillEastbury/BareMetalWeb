using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// A registered deployment node that runs the BMW bootstrap agent.
/// Tracks node identity, ring assignment, current runtime version,
/// and policy-evaluation state (fingerprint, network location, telemetry).
/// </summary>
[DataEntity("Deployment Nodes", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1021)]
public class DeploymentNode : DataRecord
{
    public override string EntityTypeName => "DeploymentNode";
    private const int Ord_NodeId = BaseFieldCount + 0;
    private const int Ord_SecretHash = BaseFieldCount + 1;
    private const int Ord_Ring = BaseFieldCount + 2;
    private const int Ord_Architecture = BaseFieldCount + 3;
    private const int Ord_CurrentVersion = BaseFieldCount + 4;
    private const int Ord_LastHeartbeatUtc = BaseFieldCount + 5;
    private const int Ord_PollIntervalSeconds = BaseFieldCount + 6;
    private const int Ord_IsEnabled = BaseFieldCount + 7;
    private const int Ord_DisplayName = BaseFieldCount + 8;
    private const int Ord_ClusterEndpoint = BaseFieldCount + 9;
    private const int Ord_Fingerprint = BaseFieldCount + 10;
    private const int Ord_Status = BaseFieldCount + 11;
    private const int Ord_LastTelemetryUtc = BaseFieldCount + 12;
    private const int Ord_LastShutdownClean = BaseFieldCount + 13;
    private const int Ord_LastKnownIp = BaseFieldCount + 14;
    private const int Ord_LastKnownAsn = BaseFieldCount + 15;
    private const int Ord_LastKnownRegion = BaseFieldCount + 16;
    private const int Ord_LastCapsuleIssuedUtc = BaseFieldCount + 17;
    internal const int TotalFieldCount = BaseFieldCount + 18;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("Architecture", Ord_Architecture),
        new FieldSlot("ClusterEndpoint", Ord_ClusterEndpoint),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("CurrentVersion", Ord_CurrentVersion),
        new FieldSlot("DisplayName", Ord_DisplayName),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Fingerprint", Ord_Fingerprint),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("IsEnabled", Ord_IsEnabled),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("LastCapsuleIssuedUtc", Ord_LastCapsuleIssuedUtc),
        new FieldSlot("LastHeartbeatUtc", Ord_LastHeartbeatUtc),
        new FieldSlot("LastKnownAsn", Ord_LastKnownAsn),
        new FieldSlot("LastKnownIp", Ord_LastKnownIp),
        new FieldSlot("LastKnownRegion", Ord_LastKnownRegion),
        new FieldSlot("LastShutdownClean", Ord_LastShutdownClean),
        new FieldSlot("LastTelemetryUtc", Ord_LastTelemetryUtc),
        new FieldSlot("NodeId", Ord_NodeId),
        new FieldSlot("PollIntervalSeconds", Ord_PollIntervalSeconds),
        new FieldSlot("Ring", Ord_Ring),
        new FieldSlot("SecretHash", Ord_SecretHash),
        new FieldSlot("Status", Ord_Status),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public DeploymentNode() : base(TotalFieldCount) { }
    public DeploymentNode(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>Unique node identifier (set during provisioning).</summary>
    [DataField(Label = "Node ID", Order = 1, Required = true, List = true, View = true, Edit = true)]
    [DataIndex]
    public string NodeId
    {
        get => (string?)_values[Ord_NodeId] ?? string.Empty;
        set => _values[Ord_NodeId] = value;
    }

    /// <summary>SHA256 hash of the node's authentication secret.</summary>
    [DataField(Label = "Secret Hash", Order = 2, Required = true, View = true)]
    public string SecretHash
    {
        get => (string?)_values[Ord_SecretHash] ?? string.Empty;
        set => _values[Ord_SecretHash] = value;
    }

    /// <summary>Deployment ring this node belongs to (canary, early-access, production).</summary>
    [DataField(Label = "Ring", Order = 3, Required = true, List = true, View = true, Edit = true)]
    [DataIndex]
    public string Ring
    {
        get => (string?)_values[Ord_Ring] ?? "production";
        set => _values[Ord_Ring] = value;
    }

    /// <summary>CPU architecture of the node (Arm64, X64).</summary>
    [DataField(Label = "Architecture", Order = 4, List = true, View = true, Edit = true)]
    public string Architecture
    {
        get => (string?)_values[Ord_Architecture] ?? "Arm64";
        set => _values[Ord_Architecture] = value;
    }

    /// <summary>Version currently running on this node (reported by agent).</summary>
    [DataField(Label = "Current Version", Order = 5, List = true, View = true, ReadOnly = true)]
    public string CurrentVersion
    {
        get => (string?)_values[Ord_CurrentVersion] ?? string.Empty;
        set => _values[Ord_CurrentVersion] = value;
    }

    /// <summary>UTC timestamp of the last heartbeat from this node's agent.</summary>
    [DataField(Label = "Last Seen", Order = 6, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime LastHeartbeatUtc
    {
        get => _values[Ord_LastHeartbeatUtc] is DateTime dt ? dt : default;
        set => _values[Ord_LastHeartbeatUtc] = value;
    }

    /// <summary>Desired polling interval in seconds for this node.</summary>
    [DataField(Label = "Poll Interval (s)", Order = 7, List = true, View = true, Edit = true, FieldType = FormFieldType.Integer)]
    public int PollIntervalSeconds
    {
        get => (int)(_values[Ord_PollIntervalSeconds] ?? 60);
        set => _values[Ord_PollIntervalSeconds] = value;
    }

    /// <summary>Whether this node is enabled (disabled nodes won't receive updates).</summary>
    [DataField(Label = "Enabled", Order = 8, List = true, View = true, Edit = true, FieldType = FormFieldType.YesNo)]
    public bool IsEnabled
    {
        get => _values[Ord_IsEnabled] is true;
        set => _values[Ord_IsEnabled] = value;
    }

    /// <summary>Optional display name for the node.</summary>
    [DataField(Label = "Name", Order = 9, List = true, View = true, Edit = true)]
    public string DisplayName
    {
        get => (string?)_values[Ord_DisplayName] ?? string.Empty;
        set => _values[Ord_DisplayName] = value;
    }

    /// <summary>Service principal or cluster endpoint for this node.</summary>
    [DataField(Label = "Cluster Endpoint", Order = 10, View = true, Edit = true)]
    public string ClusterEndpoint
    {
        get => (string?)_values[Ord_ClusterEndpoint] ?? string.Empty;
        set => _values[Ord_ClusterEndpoint] = value;
    }

    // ── Policy fields (capsule issuance) ─────────────────────────────────────

    /// <summary>Device hardware fingerprint (SHA256 of MAC + machine-id + CPU serial).</summary>
    [DataField(Label = "Fingerprint", Order = 11, View = true)]
    public string Fingerprint
    {
        get => (string?)_values[Ord_Fingerprint] ?? string.Empty;
        set => _values[Ord_Fingerprint] = value;
    }

    /// <summary>Node lifecycle status.</summary>
    [DataField(Label = "Status", Order = 12, List = true, View = true, Edit = true)]
    [DataIndex]
    public NodeStatus Status
    {
        get => _values[Ord_Status] is NodeStatus v ? v : default;
        set => _values[Ord_Status] = value;
    }

    /// <summary>UTC timestamp of last telemetry received from this node.</summary>
    [DataField(Label = "Last Telemetry", Order = 13, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime LastTelemetryUtc
    {
        get => _values[Ord_LastTelemetryUtc] is DateTime dt ? dt : default;
        set => _values[Ord_LastTelemetryUtc] = value;
    }

    /// <summary>Whether the node's last shutdown was clean (graceful).</summary>
    [DataField(Label = "Clean Shutdown", Order = 14, View = true, ReadOnly = true, FieldType = FormFieldType.YesNo)]
    public bool LastShutdownClean
    {
        get => _values[Ord_LastShutdownClean] is true;
        set => _values[Ord_LastShutdownClean] = value;
    }

    /// <summary>IP address from the most recent capsule or heartbeat request.</summary>
    [DataField(Label = "Last IP", Order = 15, View = true, ReadOnly = true)]
    public string LastKnownIp
    {
        get => (string?)_values[Ord_LastKnownIp] ?? string.Empty;
        set => _values[Ord_LastKnownIp] = value;
    }

    /// <summary>ASN (Autonomous System Number) from the most recent request.</summary>
    [DataField(Label = "Last ASN", Order = 16, View = true, ReadOnly = true)]
    public string LastKnownAsn
    {
        get => (string?)_values[Ord_LastKnownAsn] ?? string.Empty;
        set => _values[Ord_LastKnownAsn] = value;
    }

    /// <summary>Geographic region from the most recent request.</summary>
    [DataField(Label = "Last Region", Order = 17, View = true, ReadOnly = true)]
    public string LastKnownRegion
    {
        get => (string?)_values[Ord_LastKnownRegion] ?? string.Empty;
        set => _values[Ord_LastKnownRegion] = value;
    }

    /// <summary>UTC timestamp of last capsule issuance.</summary>
    [DataField(Label = "Last Capsule Issued", Order = 18, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime LastCapsuleIssuedUtc
    {
        get => _values[Ord_LastCapsuleIssuedUtc] is DateTime dt ? dt : default;
        set => _values[Ord_LastCapsuleIssuedUtc] = value;
    }

    public override string ToString() => string.IsNullOrEmpty(DisplayName) ? NodeId : DisplayName;
}

/// <summary>Node lifecycle status for policy evaluation.</summary>
public enum NodeStatus
{
    Active = 0,
    Revoked = 1,
    Quarantined = 2,
}
