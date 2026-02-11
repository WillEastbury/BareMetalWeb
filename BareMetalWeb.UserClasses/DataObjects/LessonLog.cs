namespace BareMetalWeb.Data.DataObjects;

[DataEntity("Lesson Logs", ShowOnNav = true, NavGroup = "School", NavOrder = 30)]
public class LessonLog : RenderableDataObject
{
    [DataField(Label = "Subject Id", Order = 1, Required = true)]
    [DataLookup(typeof(Subject), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc, CacheSeconds = 120)]
    public string SubjectId { get; set; } = string.Empty;

    [DataField(Label = "Date", Order = 2, Required = true)]
    public DateOnly Date { get; set; }

    [DataField(Label = "Start Time", Order = 3, Required = true)]
    public TimeOnly StartTime { get; set; }

    [DataField(Label = "Minutes", Order = 4)]
    public int Minutes { get; set; } = 30;

    [DataField(Label = "Notes", Order = 5)]
    public string Notes { get; set; } = string.Empty;

    [DataField(Label = "Link", Order = 6)]
    public string Link { get; set; } = string.Empty;
}
