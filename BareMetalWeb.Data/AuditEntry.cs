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
public sealed class AuditEntry : DataRecord
{
    public override string EntityTypeName => "AuditEntry";
    private const int Ord_EntityType = BaseFieldCount + 0;
    private const int Ord_EntityKey = BaseFieldCount + 1;
    private const int Ord_Operation = BaseFieldCount + 2;
    private const int Ord_TimestampUtc = BaseFieldCount + 3;
    private const int Ord_UserName = BaseFieldCount + 4;
    private const int Ord_FieldChangesJson = BaseFieldCount + 5;
    private const int Ord_CommandName = BaseFieldCount + 6;
    private const int Ord_CommandParameters = BaseFieldCount + 7;
    private const int Ord_CommandResult = BaseFieldCount + 8;
    private const int Ord_Notes = BaseFieldCount + 9;
    internal new const int TotalFieldCount = BaseFieldCount + 10;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CommandName", Ord_CommandName),
        new FieldSlot("CommandParameters", Ord_CommandParameters),
        new FieldSlot("CommandResult", Ord_CommandResult),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("EntityKey", Ord_EntityKey),
        new FieldSlot("EntityType", Ord_EntityType),
        new FieldSlot("FieldChangesJson", Ord_FieldChangesJson),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Notes", Ord_Notes),
        new FieldSlot("Operation", Ord_Operation),
        new FieldSlot("TimestampUtc", Ord_TimestampUtc),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("UserName", Ord_UserName),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public AuditEntry() : base(TotalFieldCount)
    {
    }

    public AuditEntry(string createdBy) : base(TotalFieldCount, createdBy)
    {
    }

    /// <summary>
    /// Type of entity being audited (e.g., "User", "Order")
    /// </summary>
    [DataField(Label = "Entity Type", Required = true, Order = 1)]
    [DataIndex(IndexKind.Inverted)]
    public string EntityType
    {
        get => (string?)_values[Ord_EntityType] ?? string.Empty;
        set => _values[Ord_EntityType] = value;
    }

    /// <summary>
    /// Key of the entity being audited
    /// </summary>
    [DataField(Label = "Entity Key", Required = true, Order = 2)]
    [DataIndex(IndexKind.Inverted)]
    public uint EntityKey
    {
        get => (uint)(_values[Ord_EntityKey] ?? 0u);
        set => _values[Ord_EntityKey] = value;
    }

    /// <summary>
    /// Operation performed (Create, Update, Delete, RemoteCommand)
    /// </summary>
    [DataField(Label = "Operation", Required = true, Order = 3)]
    [DataIndex(IndexKind.Inverted)]
    public AuditOperation Operation
    {
        get => _values[Ord_Operation] is AuditOperation v ? v : default;
        set => _values[Ord_Operation] = value;
    }

    /// <summary>
    /// When the operation occurred
    /// </summary>
    [DataField(Label = "Timestamp", Required = true, Order = 4)]
    [DataIndex(IndexKind.BTree)]
    public DateTime TimestampUtc
    {
        get => _values[Ord_TimestampUtc] is DateTime dt ? dt : default;
        set => _values[Ord_TimestampUtc] = value;
    }

    /// <summary>
    /// Username of the user who performed the operation
    /// </summary>
    [DataField(Label = "User", Required = true, Order = 5)]
    [DataIndex(IndexKind.Inverted)]
    public string UserName
    {
        get => (string?)_values[Ord_UserName] ?? string.Empty;
        set => _values[Ord_UserName] = value;
    }

    /// <summary>
    /// JSON-serialized list of field changes (for Update operations)
    /// </summary>
    [DataField(Label = "Field Changes", Order = 6)]
    public string FieldChangesJson
    {
        get => (string?)_values[Ord_FieldChangesJson] ?? "[]";
        set => _values[Ord_FieldChangesJson] = value;
    }

    /// <summary>
    /// Gets or sets field changes, serialized as JSON for binary storage compatibility
    /// </summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public List<FieldChange> FieldChanges
    {
        get
        {
            try { return BmwManualJson.DeserializeFieldChanges(FieldChangesJson); }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"AuditEntry.FieldChanges deserialization failed: {ex.Message}"); return new(); }
        }
        set { FieldChangesJson = BmwManualJson.SerializeFieldChanges(value ?? new List<FieldChange>()); }
    }

    /// <summary>
    /// For RemoteCommand operations: the command name
    /// </summary>
    [DataField(Label = "Command Name", Order = 7)]
    public string? CommandName
    {
        get => (string?)_values[Ord_CommandName];
        set => _values[Ord_CommandName] = value;
    }

    /// <summary>
    /// For RemoteCommand operations: command parameters (JSON)
    /// </summary>
    [DataField(Label = "Command Parameters", Order = 8)]
    public string? CommandParameters
    {
        get => (string?)_values[Ord_CommandParameters];
        set => _values[Ord_CommandParameters] = value;
    }

    /// <summary>
    /// For RemoteCommand operations: command result
    /// </summary>
    [DataField(Label = "Command Result", Order = 9)]
    public string? CommandResult
    {
        get => (string?)_values[Ord_CommandResult];
        set => _values[Ord_CommandResult] = value;
    }

    /// <summary>
    /// Additional context or notes
    /// </summary>
    [DataField(Label = "Notes", Order = 10)]
    public string? Notes
    {
        get => (string?)_values[Ord_Notes];
        set => _values[Ord_Notes] = value;
    }
}
