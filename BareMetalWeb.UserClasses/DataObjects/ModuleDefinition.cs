using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

/// <summary>
/// Defines a logical module boundary within BareMetalWeb.
/// A module groups related entities, actions, UI layouts, and permissions
/// into a cohesive, portable unit that can be enabled/disabled and exported/imported.
/// </summary>
[DataEntity("Modules", ShowOnNav = true, NavGroup = "Admin", NavOrder = 5, Permissions = "admin")]
public class ModuleDefinition : RenderableDataObject
{
    [DataField(Label = "Module ID", Order = 1, Required = true)]
    [DataIndex]
    public string ModuleId { get; set; } = string.Empty;

    [DataField(Label = "Name", Order = 2, Required = true)]
    public string Name { get; set; } = string.Empty;

    [DataField(Label = "Description", Order = 3)]
    public string Description { get; set; } = string.Empty;

    [DataField(Label = "Version", Order = 4, Required = true)]
    public string Version { get; set; } = "1.0.0";

    /// <summary>Comma-separated entity slugs owned by this module.</summary>
    [DataField(Label = "Entity Slugs", Order = 5)]
    public string EntitySlugs { get; set; } = string.Empty;

    /// <summary>Comma-separated action composite keys (type:actionId) owned by this module.</summary>
    [DataField(Label = "Action Keys", Order = 6)]
    public string ActionKeys { get; set; } = string.Empty;

    /// <summary>Comma-separated report slugs owned by this module.</summary>
    [DataField(Label = "Report Slugs", Order = 7)]
    public string ReportSlugs { get; set; } = string.Empty;

    /// <summary>Comma-separated permission codes required by this module.</summary>
    [DataField(Label = "Required Permissions", Order = 8)]
    public string RequiredPermissions { get; set; } = string.Empty;

    /// <summary>Navigation group name for UI binding (entities in this module appear under this nav group).</summary>
    [DataField(Label = "Nav Group", Order = 9)]
    public string NavGroup { get; set; } = string.Empty;

    /// <summary>UI icon class (e.g. "bi-box-seam").</summary>
    [DataField(Label = "Icon", Order = 10)]
    public string Icon { get; set; } = string.Empty;

    /// <summary>Whether this module is currently enabled.</summary>
    [DataField(Label = "Enabled", Order = 11)]
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Comma-separated module IDs this module depends on.
    /// Dependent modules must be enabled before this module can be enabled.
    /// </summary>
    [DataField(Label = "Dependencies", Order = 12)]
    public string Dependencies { get; set; } = string.Empty;

    /// <summary>
    /// Isolation level: "shared" (default) or "isolated".
    /// Isolated modules cannot reference entities in other modules.
    /// </summary>
    [DataField(Label = "Isolation", Order = 13)]
    public string Isolation { get; set; } = "shared";

    public override string ToString() => $"{ModuleId} v{Version}";
}
