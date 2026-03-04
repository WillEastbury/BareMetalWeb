using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted schema definition for a runtime-managed entity type.
/// Stored via the standard storage subsystem; loaded at startup and compiled
/// into an immutable <see cref="RuntimeEntityModel"/>.
/// </summary>
[DataEntity("Entity Definitions", ShowOnNav = true, NavGroup = "Admin", NavOrder = 1000)]
public class EntityDefinition : RenderableDataObject
{
    /// <summary>Stable GUID identity that survives renames. Defaults to Id.</summary>
    [DataField(Label = "Entity ID", Order = 1, ReadOnly = true)]
    public string EntityId { get; set; } = string.Empty;

    [DataField(Label = "Name", Order = 2, Required = true)]
    public string Name { get; set; } = string.Empty;

    /// <summary>URL slug override. Derived from Name if empty.</summary>
    [DataField(Label = "Slug", Order = 3)]
    public string? Slug { get; set; }

    /// <summary>Schema version, incremented on every field-set change.</summary>
    [DataField(Label = "Version", Order = 4, ReadOnly = true)]
    public int Version { get; set; } = 1;

    /// <summary>ID auto-generation strategy: "guid", "sequential", or "none".</summary>
    [DataField(Label = "ID Strategy", Order = 5, Placeholder = "guid | sequential | none")]
    public string IdStrategy { get; set; } = "guid";

    [DataField(Label = "Show on Nav", Order = 6)]
    public bool ShowOnNav { get; set; } = false;

    /// <summary>Comma-separated permission tokens required to access this entity.</summary>
    [DataField(Label = "Permissions", Order = 7)]
    public string Permissions { get; set; } = string.Empty;

    [DataField(Label = "Nav Group", Order = 8)]
    public string NavGroup { get; set; } = "Admin";

    [DataField(Label = "Nav Order", Order = 9)]
    public int NavOrder { get; set; } = 0;

    /// <summary>
    /// FNV-1a hash of the compiled field ordinals and types.
    /// Used for migration-change detection at startup.
    /// </summary>
    [DataField(Label = "Schema Hash", Order = 10, ReadOnly = true)]
    public string SchemaHash { get; set; } = string.Empty;

    /// <summary>
    /// Form layout style: "Standard" (default) or "Wizard" (multi-step guided form).
    /// When "Wizard", fields are grouped by FieldGroup into sequential steps.
    /// </summary>
    [DataField(Label = "Form Layout", Order = 11, Placeholder = "Standard | Wizard")]
    public string FormLayout { get; set; } = "Standard";

    public override string ToString() => Name;
}
