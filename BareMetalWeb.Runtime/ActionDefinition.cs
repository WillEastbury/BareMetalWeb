using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted descriptor for a server-side action that can be invoked against
/// an entity instance. The metadata layer describes actions; execution is
/// handled by <see cref="ICommandService"/>.
/// </summary>
[DataEntity("Action Definitions", ShowOnNav = true, NavGroup = "Admin", NavOrder = 1003)]
public class ActionDefinition : RenderableDataObject
{
    /// <summary>Foreign key to <see cref="EntityDefinition.Id"/>.</summary>
    [DataField(Label = "Entity ID", Order = 1, Required = true)]
    [DataLookup(typeof(EntityDefinition), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc)]
    public string EntityId { get; set; } = string.Empty;

    [DataField(Label = "Name", Order = 2, Required = true)]
    public string Name { get; set; } = string.Empty;

    [DataField(Label = "Label", Order = 3)]
    public string? Label { get; set; }

    [DataField(Label = "Icon", Order = 4)]
    public string? Icon { get; set; }

    /// <summary>Permission token required to execute this action.</summary>
    [DataField(Label = "Permission", Order = 5)]
    public string? Permission { get; set; }

    /// <summary>
    /// Boolean expression evaluated at runtime to determine whether the action
    /// button is enabled. Example: "IsResolved == false".
    /// </summary>
    [DataField(Label = "Enabled When", Order = 6)]
    public string? EnabledWhen { get; set; }

    /// <summary>
    /// Pipe-separated list of "SetField:FieldName=Value" operations executed
    /// when this action is invoked. Example: "SetField:IsResolved=true|SetField:ResolvedBy=CurrentUser".
    /// This is intentionally declarative and limited; complex logic belongs in compiled code.
    /// </summary>
    [DataField(Label = "Operations", Order = 7)]
    public string? Operations { get; set; }

    /// <summary>
    /// Schema version of this action definition.
    /// Increment when the command set changes to invalidate any cached expansions.
    /// Once published, the <see cref="Name"/> (ActionId) is immutable per spec §2.
    /// </summary>
    [DataField(Label = "Version", Order = 8, ReadOnly = true)]
    public new int Version { get; set; } = 1;

    public override string ToString() => Label ?? Name;
}
