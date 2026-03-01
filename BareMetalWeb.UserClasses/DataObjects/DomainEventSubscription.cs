using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

/// <summary>
/// Declarative domain event subscription: when a field on an entity
/// transitions to a specific value, fire a registered action on a target aggregate.
/// No scripting — deterministic, replay-safe, runs inside commit pipeline.
/// </summary>
[DataEntity("Domain Event Subscriptions", ShowOnNav = true, NavGroup = "Automation", NavOrder = 10, Permissions = "admin")]
public class DomainEventSubscription : RenderableDataObject
{
    /// <summary>Human-readable label for this subscription.</summary>
    [DataField(Label = "Name", Order = 1, Required = true)]
    [DataIndex]
    public string Name { get; set; } = string.Empty;

    [DataField(Label = "Description", Order = 2)]
    public string Description { get; set; } = string.Empty;

    /// <summary>Entity slug that triggers this event (e.g. "orders").</summary>
    [DataField(Label = "Source Entity", Order = 3, Required = true)]
    [DataIndex]
    public string SourceEntity { get; set; } = string.Empty;

    /// <summary>
    /// Field name to watch for state transitions.
    /// Empty = fire on any save of the source entity.
    /// </summary>
    [DataField(Label = "Watch Field", Order = 4)]
    public string WatchField { get; set; } = string.Empty;

    /// <summary>
    /// Value the watch field must transition TO for the event to fire.
    /// Empty = fire on any change to the watch field.
    /// </summary>
    [DataField(Label = "Trigger Value", Order = 5)]
    public string TriggerValue { get; set; } = string.Empty;

    /// <summary>
    /// Optional: value the watch field must transition FROM.
    /// Empty = fire regardless of previous value.
    /// </summary>
    [DataField(Label = "From Value", Order = 6)]
    public string FromValue { get; set; } = string.Empty;

    /// <summary>Entity slug + action ID to fire (format: "entity-slug:actionId").</summary>
    [DataField(Label = "Target Action", Order = 7, Required = true)]
    public string TargetAction { get; set; } = string.Empty;

    /// <summary>
    /// How to resolve the target aggregate for the action.
    /// "self" = same aggregate that triggered the event.
    /// "field:FieldName" = use the value of FieldName on the source entity as the target aggregate key.
    /// </summary>
    [DataField(Label = "Target Resolution", Order = 8)]
    public string TargetResolution { get; set; } = "self";

    /// <summary>Whether this subscription is active.</summary>
    [DataField(Label = "Enabled", Order = 9)]
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Execution priority (lower = runs first). Subscriptions for the same
    /// source entity are evaluated in priority order.
    /// </summary>
    [DataField(Label = "Priority", Order = 10)]
    public int Priority { get; set; } = 100;

    public override string ToString() => Name;
}
