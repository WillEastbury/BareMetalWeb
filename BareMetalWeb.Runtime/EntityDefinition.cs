using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted schema definition for a runtime-managed entity type.
/// Stored via the standard storage subsystem; loaded at startup and compiled
/// into an immutable <see cref="RuntimeEntityModel"/>.
/// </summary>
[DataEntity("Entity Definitions", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1000)]
public class EntityDefinition : DataRecord
{
    public override string EntityTypeName => "EntityDefinition";
    private const int Ord_EntityId = BaseFieldCount + 0;
    private const int Ord_Name = BaseFieldCount + 1;
    private const int Ord_Slug = BaseFieldCount + 2;
    private new const int Ord_Version = BaseFieldCount + 3;
    private const int Ord_IdStrategy = BaseFieldCount + 4;
    private const int Ord_ShowOnNav = BaseFieldCount + 5;
    private const int Ord_Permissions = BaseFieldCount + 6;
    private const int Ord_NavGroup = BaseFieldCount + 7;
    private const int Ord_NavOrder = BaseFieldCount + 8;
    private const int Ord_SchemaHash = BaseFieldCount + 9;
    private const int Ord_FormLayout = BaseFieldCount + 10;
    internal const int TotalFieldCount = BaseFieldCount + 11;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("EntityId", Ord_EntityId),
        new FieldSlot("FormLayout", Ord_FormLayout),
        new FieldSlot("IdStrategy", Ord_IdStrategy),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Name", Ord_Name),
        new FieldSlot("NavGroup", Ord_NavGroup),
        new FieldSlot("NavOrder", Ord_NavOrder),
        new FieldSlot("Permissions", Ord_Permissions),
        new FieldSlot("SchemaHash", Ord_SchemaHash),
        new FieldSlot("ShowOnNav", Ord_ShowOnNav),
        new FieldSlot("Slug", Ord_Slug),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public EntityDefinition() : base(TotalFieldCount) { }
    public EntityDefinition(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>Stable GUID identity that survives renames. Defaults to Id.</summary>
    [DataField(Label = "Entity ID", Order = 1, ReadOnly = true)]
    public string EntityId
    {
        get => (string?)_values[Ord_EntityId] ?? string.Empty;
        set => _values[Ord_EntityId] = value;
    }

    [DataField(Label = "Name", Order = 2, Required = true)]
    public string Name
    {
        get => (string?)_values[Ord_Name] ?? string.Empty;
        set => _values[Ord_Name] = value;
    }

    /// <summary>URL slug override. Derived from Name if empty.</summary>
    [DataField(Label = "Slug", Order = 3)]
    public string? Slug
    {
        get => (string?)_values[Ord_Slug];
        set => _values[Ord_Slug] = value;
    }

    /// <summary>Schema version, incremented on every field-set change.</summary>
    [DataField(Label = "Version", Order = 4, ReadOnly = true)]
    public new int Version
    {
        get => (int)(_values[Ord_Version] ?? 1);
        set => _values[Ord_Version] = value;
    }

    /// <summary>ID auto-generation strategy: "guid", "sequential", or "none".</summary>
    [DataField(Label = "ID Strategy", Order = 5, Placeholder = "guid | sequential | none")]
    public string IdStrategy
    {
        get => (string?)_values[Ord_IdStrategy] ?? "guid";
        set => _values[Ord_IdStrategy] = value;
    }

    [DataField(Label = "Show on Nav", Order = 6)]
    public bool ShowOnNav
    {
        get => _values[Ord_ShowOnNav] is true;
        set => _values[Ord_ShowOnNav] = value;
    }

    /// <summary>Comma-separated permission tokens required to access this entity.</summary>
    [DataField(Label = "Permissions", Order = 7)]
    public string Permissions
    {
        get => (string?)_values[Ord_Permissions] ?? string.Empty;
        set => _values[Ord_Permissions] = value;
    }

    [DataField(Label = "Nav Group", Order = 8)]
    public string NavGroup
    {
        get => (string?)_values[Ord_NavGroup] ?? "Admin";
        set => _values[Ord_NavGroup] = value;
    }

    [DataField(Label = "Nav Order", Order = 9)]
    public int NavOrder
    {
        get => (int)(_values[Ord_NavOrder] ?? 0);
        set => _values[Ord_NavOrder] = value;
    }

    /// <summary>
    /// FNV-1a hash of the compiled field ordinals and types.
    /// Used for migration-change detection at startup.
    /// </summary>
    [DataField(Label = "Schema Hash", Order = 10, ReadOnly = true)]
    public string SchemaHash
    {
        get => (string?)_values[Ord_SchemaHash] ?? string.Empty;
        set => _values[Ord_SchemaHash] = value;
    }

    /// <summary>
    /// Form layout style: "Standard" (default) or "Wizard" (multi-step guided form).
    /// When "Wizard", fields are grouped by FieldGroup into sequential steps.
    /// </summary>
    [DataField(Label = "Form Layout", Order = 11, Placeholder = "Standard | Wizard")]
    public string FormLayout
    {
        get => (string?)_values[Ord_FormLayout] ?? "Standard";
        set => _values[Ord_FormLayout] = value;
    }

    /// <summary>
    /// When true, registers a GET-based ingress route (<c>/api/{slug}/_ingest?text=…</c>
    /// and <c>/queryinput/{slug}?text=…</c>) that creates a record by populating
    /// the field marked <see cref="FieldDefinition.IsIngressTarget"/>.
    /// </summary>
    [DataField(Label = "Enable GET Ingress", Order = 12)]
    public bool EnableGetIngress { get; set; } = false;

    public override string ToString() => Name;
}
