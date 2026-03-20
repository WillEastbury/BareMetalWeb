using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted schedule for running an action automatically at specified intervals.
/// The <see cref="ScheduledActionService"/> evaluates active schedules each tick
/// and executes matching actions against qualifying records.
/// </summary>
[DataEntity("Scheduled Actions", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1006)]
public class ScheduledActionDefinition : BaseDataObject
{
    private const int Ord_EntityId = BaseFieldCount + 0;
    private const int Ord_Name = BaseFieldCount + 1;
    private const int Ord_ActionName = BaseFieldCount + 2;
    private const int Ord_Schedule = BaseFieldCount + 3;
    private const int Ord_FilterExpression = BaseFieldCount + 4;
    private const int Ord_Enabled = BaseFieldCount + 5;
    private const int Ord_LastRunUtc = BaseFieldCount + 6;
    private const int Ord_LastRunCount = BaseFieldCount + 7;
    internal const int TotalFieldCount = BaseFieldCount + 8;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("ActionName", Ord_ActionName),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Enabled", Ord_Enabled),
        new FieldSlot("EntityId", Ord_EntityId),
        new FieldSlot("FilterExpression", Ord_FilterExpression),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("LastRunCount", Ord_LastRunCount),
        new FieldSlot("LastRunUtc", Ord_LastRunUtc),
        new FieldSlot("Name", Ord_Name),
        new FieldSlot("Schedule", Ord_Schedule),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public ScheduledActionDefinition() : base(TotalFieldCount) { }
    public ScheduledActionDefinition(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>Foreign key to <see cref="EntityDefinition.EntityId"/>.</summary>
    [DataField(Label = "Entity ID", Order = 1, Required = true)]
    [DataLookup(typeof(EntityDefinition), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc)]
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

    /// <summary>Name of the action to execute (must match an ActionDefinition.Name on the entity).</summary>
    [DataField(Label = "Action Name", Order = 3, Required = true)]
    public string ActionName
    {
        get => (string?)_values[Ord_ActionName] ?? string.Empty;
        set => _values[Ord_ActionName] = value;
    }

    /// <summary>
    /// Cron-like schedule: "hourly", "daily", "weekly", "monthly",
    /// or a custom interval in minutes (e.g. "15" = every 15 minutes).
    /// </summary>
    [DataField(Label = "Schedule", Order = 4, Required = true, Placeholder = "hourly | daily | weekly | monthly | 15")]
    public string Schedule
    {
        get => (string?)_values[Ord_Schedule] ?? "daily";
        set => _values[Ord_Schedule] = value;
    }

    /// <summary>
    /// Optional filter expression evaluated per record to decide whether
    /// the action should run. Empty = run on all records.
    /// </summary>
    [DataField(Label = "Filter Expression", Order = 5)]
    public string? FilterExpression
    {
        get => (string?)_values[Ord_FilterExpression];
        set => _values[Ord_FilterExpression] = value;
    }

    /// <summary>Whether this schedule is active.</summary>
    [DataField(Label = "Enabled", Order = 6)]
    public bool Enabled
    {
        get => _values[Ord_Enabled] is true;
        set => _values[Ord_Enabled] = value;
    }

    /// <summary>UTC timestamp of the last successful run.</summary>
    [DataField(Label = "Last Run (UTC)", Order = 7, ReadOnly = true)]
    public DateTime? LastRunUtc
    {
        get => _values[Ord_LastRunUtc] as DateTime?;
        set => _values[Ord_LastRunUtc] = value;
    }

    /// <summary>Count of records affected in the last run.</summary>
    [DataField(Label = "Last Run Count", Order = 8, ReadOnly = true)]
    public int LastRunCount
    {
        get => (int)(_values[Ord_LastRunCount] ?? 0);
        set => _values[Ord_LastRunCount] = value;
    }

    public override string ToString() => Name;
}
