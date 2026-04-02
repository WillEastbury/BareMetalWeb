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
public class DomainEventSubscription : DataRecord
{
    public override string EntityTypeName => "DomainEventSubscription";
    private const int Ord_Name = BaseFieldCount + 0;
    private const int Ord_SourceEntity = BaseFieldCount + 1;
    private const int Ord_WatchField = BaseFieldCount + 2;
    private const int Ord_FromValue = BaseFieldCount + 3;
    private const int Ord_TriggerValue = BaseFieldCount + 4;
    private const int Ord_TargetAction = BaseFieldCount + 5;
    private const int Ord_TargetResolution = BaseFieldCount + 6;
    private const int Ord_Priority = BaseFieldCount + 7;
    private const int Ord_Enabled = BaseFieldCount + 8;
    internal const int TotalFieldCount = BaseFieldCount + 9;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Enabled", Ord_Enabled),
        new FieldSlot("FromValue", Ord_FromValue),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Name", Ord_Name),
        new FieldSlot("Priority", Ord_Priority),
        new FieldSlot("SourceEntity", Ord_SourceEntity),
        new FieldSlot("TargetAction", Ord_TargetAction),
        new FieldSlot("TargetResolution", Ord_TargetResolution),
        new FieldSlot("TriggerValue", Ord_TriggerValue),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
        new FieldSlot("WatchField", Ord_WatchField),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public DomainEventSubscription() : base(TotalFieldCount) { _values[Ord_Enabled] = true; }
    public DomainEventSubscription(string createdBy) : base(TotalFieldCount, createdBy) { _values[Ord_Enabled] = true; }

    /// <summary>Human-readable rule name, e.g. "Require approval for large orders".</summary>
    [DataField(Label = "Name", Order = 1, Required = true)]
    public string Name
    {
        get => (string?)_values[Ord_Name] ?? string.Empty;
        set => _values[Ord_Name] = value;
    }

    /// <summary>
    /// Slug of the entity type to watch, e.g. "order".
    /// Must match a registered entity slug.
    /// </summary>
    [DataField(Label = "Source Entity", Order = 2, Required = true, Placeholder = "e.g. order")]
    [DataLookup(typeof(EntityDefinition), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc)]
    public string SourceEntity
    {
        get => (string?)_values[Ord_SourceEntity] ?? string.Empty;
        set => _values[Ord_SourceEntity] = value;
    }

    /// <summary>
    /// Name of the field on <see cref="SourceEntity"/> to watch for changes.
    /// Leave blank to trigger on any save of the entity.
    /// </summary>
    [DataField(Label = "Watch Field", Order = 3, Placeholder = "e.g. Status (blank = any save)")]
    public string? WatchField
    {
        get => (string?)_values[Ord_WatchField];
        set => _values[Ord_WatchField] = value;
    }

    /// <summary>
    /// Optional previous value constraint. The rule only fires if the field was
    /// this value before the change. Leave blank for any previous value.
    /// </summary>
    [DataField(Label = "From Value", Order = 4, Placeholder = "e.g. Draft (blank = any)")]
    public string? FromValue
    {
        get => (string?)_values[Ord_FromValue];
        set => _values[Ord_FromValue] = value;
    }

    /// <summary>
    /// Optional new value constraint. The rule only fires if the field changes to
    /// this value. Leave blank for any new value.
    /// </summary>
    [DataField(Label = "Trigger Value", Order = 5, Placeholder = "e.g. Approved (blank = any change)")]
    public string? TriggerValue
    {
        get => (string?)_values[Ord_TriggerValue];
        set => _values[Ord_TriggerValue] = value;
    }

    /// <summary>
    /// Name of the <see cref="ActionDefinition"/> to execute when the rule fires.
    /// Must match an action that is registered on the target entity type.
    /// </summary>
    [DataField(Label = "Target Action", Order = 6, Required = true, Placeholder = "e.g. SendApprovalNotification")]
    public string TargetAction
    {
        get => (string?)_values[Ord_TargetAction] ?? string.Empty;
        set => _values[Ord_TargetAction] = value;
    }

    /// <summary>
    /// Determines which aggregate instance the action runs against.
    /// <list type="bullet">
    ///   <item><c>self</c> — the entity that changed (default).</item>
    ///   <item><c>field:FieldName</c> — the entity whose key is stored in the named field on the changed entity.</item>
    /// </list>
    /// </summary>
    [DataField(Label = "Target Resolution", Order = 7, Placeholder = "self  OR  field:ManagerId")]
    public string TargetResolution
    {
        get => (string?)_values[Ord_TargetResolution] ?? "self";
        set => _values[Ord_TargetResolution] = value;
    }

    /// <summary>
    /// Lower numbers run first when multiple rules match the same event.
    /// Default is 100.
    /// </summary>
    [DataField(Label = "Priority", Order = 8)]
    public int Priority
    {
        get => (int)(_values[Ord_Priority] ?? 100);
        set => _values[Ord_Priority] = value;
    }

    /// <summary>Whether this rule is active.</summary>
    [DataField(Label = "Enabled", Order = 9)]
    public bool Enabled
    {
        get => _values[Ord_Enabled] is true;
        set => _values[Ord_Enabled] = value;
    }

    public override string ToString() => Name;
}
