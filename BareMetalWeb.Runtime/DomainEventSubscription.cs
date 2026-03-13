using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted workflow / automation rule that fires an action when a watched entity
/// field transitions to (or from) a specific value.
///
/// Business-user readable form:
/// <code>
///   IF [SourceEntity].[WatchField] changes [FROM &lt;FromValue&gt;] TO &lt;TriggerValue&gt;
///   THEN run [TargetAction] on [TargetResolution]
/// </code>
///
/// Leaving <see cref="WatchField"/> empty fires the rule on any save of the entity.
/// Leaving <see cref="TriggerValue"/> empty fires on any value change.
/// Leaving <see cref="FromValue"/> empty fires regardless of the previous value.
///
/// Rules are evaluated by <see cref="BareMetalWeb.Data.DomainEventDispatcher"/> after
/// every successful commit, inside the lock scope.
/// </summary>
[DataEntity(
    "Workflow Rules",
    Slug = "domain-event-subscriptions",
    ShowOnNav = false,
    NavGroup = "Admin",
    NavOrder = 1005,
    IdGeneration = AutoIdStrategy.Sequential)]
public class DomainEventSubscription : BaseDataObject
{
    /// <summary>Human-readable rule name, e.g. "Require approval for large orders".</summary>
    [DataField(Label = "Name", Order = 1, Required = true)]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Slug of the entity type to watch, e.g. "order".
    /// Must match a registered entity slug.
    /// </summary>
    [DataField(Label = "Source Entity", Order = 2, Required = true, Placeholder = "e.g. order")]
    [DataLookup(typeof(EntityDefinition), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc)]
    public string SourceEntity { get; set; } = string.Empty;

    /// <summary>
    /// Name of the field on <see cref="SourceEntity"/> to watch for changes.
    /// Leave blank to trigger on any save of the entity.
    /// </summary>
    [DataField(Label = "Watch Field", Order = 3, Placeholder = "e.g. Status (blank = any save)")]
    public string? WatchField { get; set; }

    /// <summary>
    /// Optional previous value constraint. The rule only fires if the field was
    /// this value before the change. Leave blank for any previous value.
    /// </summary>
    [DataField(Label = "From Value", Order = 4, Placeholder = "e.g. Draft (blank = any)")]
    public string? FromValue { get; set; }

    /// <summary>
    /// Optional new value constraint. The rule only fires if the field changes to
    /// this value. Leave blank for any new value.
    /// </summary>
    [DataField(Label = "Trigger Value", Order = 5, Placeholder = "e.g. Approved (blank = any change)")]
    public string? TriggerValue { get; set; }

    /// <summary>
    /// Name of the <see cref="ActionDefinition"/> to execute when the rule fires.
    /// Must match an action that is registered on the target entity type.
    /// </summary>
    [DataField(Label = "Target Action", Order = 6, Required = true, Placeholder = "e.g. SendApprovalNotification")]
    public string TargetAction { get; set; } = string.Empty;

    /// <summary>
    /// Determines which aggregate instance the action runs against.
    /// <list type="bullet">
    ///   <item><c>self</c> — the entity that changed (default).</item>
    ///   <item><c>field:FieldName</c> — the entity whose key is stored in the named field on the changed entity.</item>
    /// </list>
    /// </summary>
    [DataField(Label = "Target Resolution", Order = 7, Placeholder = "self  OR  field:ManagerId")]
    public string TargetResolution { get; set; } = "self";

    /// <summary>
    /// Lower numbers run first when multiple rules match the same event.
    /// Default is 100.
    /// </summary>
    [DataField(Label = "Priority", Order = 8)]
    public int Priority { get; set; } = 100;

    /// <summary>Whether this rule is active.</summary>
    [DataField(Label = "Enabled", Order = 9)]
    public bool Enabled { get; set; } = true;

    public override string ToString() => Name;
}
