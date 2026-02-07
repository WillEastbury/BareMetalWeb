namespace BareMetalWeb.Data.DataObjects;

[DataEntity("Time Table Plans", ShowOnNav = true, NavGroup = "School", NavOrder = 20)]
public class TimeTablePlan : RenderableDataObject
{
    [DataLookup(typeof(Subject), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc, CacheSeconds = 120)]
    [DataField(Label = "Subject Id", Order = 1, Required = true)]
    public string SubjectId { get; set; } = string.Empty;

    [DataField(Label = "Notes", Order = 2)]
    public string Notes { get; set; } = string.Empty;

    [DataField(Label = "Day", Order = 3, Required = true)]
    public DayOfWeek Day { get; set; }

    [DataField(Label = "Start Time", Order = 4, Required = true)]
    public TimeOnly StartTime { get; set; }

    [DataField(Label = "Minutes", Order = 5)]
    public int Minutes { get; set; } = 30;
}
