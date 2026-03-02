using System;
using System.Collections.Generic;

namespace BareMetalWeb.Data;

/// <summary>
/// Audit trail record for entity changes and remote command executions
/// </summary>
[DataEntity(
    "Audit Entry",
    Slug = "auditentry",
    Permissions = "admin",
    ShowOnNav = true,
    NavGroup = "Admin",
    NavOrder = 30,
    IdGeneration = AutoIdStrategy.Sequential
)]
public sealed class AuditEntry : BaseDataObject
{
    public AuditEntry() : base()
    {
    }

    public AuditEntry(string createdBy) : base(createdBy)
    {
    }

    /// <summary>
    /// Type of entity being audited (e.g., "User", "Order")
    /// </summary>
    [DataField(Label = "Entity Type", Required = true, Order = 1)]
    [DataIndex(IndexKind.Inverted)]
    public string EntityType { get; set; } = string.Empty;

    /// <summary>
    /// Key of the entity being audited
    /// </summary>
    [DataField(Label = "Entity Key", Required = true, Order = 2)]
    [DataIndex(IndexKind.Inverted)]
    public uint EntityKey { get; set; }

    /// <summary>
    /// Operation performed (Create, Update, Delete, RemoteCommand)
    /// </summary>
    [DataField(Label = "Operation", Required = true, Order = 3)]
    [DataIndex(IndexKind.Inverted)]
    public AuditOperation Operation { get; set; }

    /// <summary>
    /// When the operation occurred
    /// </summary>
    [DataField(Label = "Timestamp", Required = true, Order = 4)]
    [DataIndex(IndexKind.BTree)]
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Username of the user who performed the operation
    /// </summary>
    [DataField(Label = "User", Required = true, Order = 5)]
    [DataIndex(IndexKind.Inverted)]
    public string UserName { get; set; } = string.Empty;

    /// <summary>
    /// JSON-serialized list of field changes (for Update operations)
    /// </summary>
    [DataField(Label = "Field Changes", Order = 6)]
    public string FieldChangesJson { get; set; } = "[]";

    /// <summary>
    /// Gets or sets field changes, serialized as JSON for binary storage compatibility
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public List<FieldChange> FieldChanges
    {
        get
        {
            try { return string.IsNullOrEmpty(FieldChangesJson) ? new() : System.Text.Json.JsonSerializer.Deserialize<List<FieldChange>>(FieldChangesJson) ?? new(); }
            catch { return new(); }
        }
        set { FieldChangesJson = System.Text.Json.JsonSerializer.Serialize(value ?? new List<FieldChange>()); }
    }

    /// <summary>
    /// For RemoteCommand operations: the command name
    /// </summary>
    [DataField(Label = "Command Name", Order = 7)]
    public string? CommandName { get; set; }

    /// <summary>
    /// For RemoteCommand operations: command parameters (JSON)
    /// </summary>
    [DataField(Label = "Command Parameters", Order = 8)]
    public string? CommandParameters { get; set; }

    /// <summary>
    /// For RemoteCommand operations: command result
    /// </summary>
    [DataField(Label = "Command Result", Order = 9)]
    public string? CommandResult { get; set; }

    /// <summary>
    /// Additional context or notes
    /// </summary>
    [DataField(Label = "Notes", Order = 10)]
    public string? Notes { get; set; }
}
