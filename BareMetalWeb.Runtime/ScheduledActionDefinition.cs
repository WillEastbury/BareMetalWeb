using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted schedule for running an action automatically at specified intervals.
/// The <see cref="ScheduledActionService"/> evaluates active schedules each tick
/// and executes matching actions against qualifying records.
/// </summary>
[DataEntity("Scheduled Actions", ShowOnNav = true, NavGroup = "Admin", NavOrder = 1006)]
public class ScheduledActionDefinition : RenderableDataObject
{
    /// <summary>Foreign key to <see cref="EntityDefinition.EntityId"/>.</summary>
    [DataField(Label = "Entity ID", Order = 1, Required = true)]
    [DataLookup(typeof(EntityDefinition), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc)]
    public string EntityId { get; set; } = string.Empty;

    [DataField(Label = "Name", Order = 2, Required = true)]
    public string Name { get; set; } = string.Empty;

    /// <summary>Name of the action to execute (must match an ActionDefinition.Name on the entity).</summary>
    [DataField(Label = "Action Name", Order = 3, Required = true)]
    public string ActionName { get; set; } = string.Empty;

    /// <summary>
    /// Cron-like schedule: "hourly", "daily", "weekly", "monthly",
    /// or a custom interval in minutes (e.g. "15" = every 15 minutes).
    /// </summary>
    [DataField(Label = "Schedule", Order = 4, Required = true, Placeholder = "hourly | daily | weekly | monthly | 15")]
    public string Schedule { get; set; } = "daily";

    /// <summary>
    /// Optional filter expression evaluated per record to decide whether
    /// the action should run. Empty = run on all records.
    /// </summary>
    [DataField(Label = "Filter Expression", Order = 5)]
    public string? FilterExpression { get; set; }

    /// <summary>Whether this schedule is active.</summary>
    [DataField(Label = "Enabled", Order = 6)]
    public bool Enabled { get; set; } = true;

    /// <summary>UTC timestamp of the last successful run.</summary>
    [DataField(Label = "Last Run (UTC)", Order = 7, ReadOnly = true)]
    public DateTime? LastRunUtc { get; set; }

    /// <summary>Count of records affected in the last run.</summary>
    [DataField(Label = "Last Run Count", Order = 8, ReadOnly = true)]
    public int LastRunCount { get; set; }

    public override string ToString() => Name;
}
