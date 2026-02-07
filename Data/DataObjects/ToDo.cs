namespace BareMetalWeb.Data.DataObjects;

[DataEntity("To Do", ShowOnNav = true, NavGroup = "Tasks", NavOrder = 30)]
public class ToDo : RenderableDataObject
{

    [DataField(Label = "Title", Order = 1, Required = true)]
    public string Title { get; set; } = string.Empty;

    [DataField(Label = "Deadline", Order = 2, Required = true)]
    public DateOnly Deadline { get; set; }

    [DataField(Label = "Start Time", Order = 3, Required = true)]
    public TimeOnly StartTime { get; set; }

    [DataField(Label = "Notes", Order = 5)]
    public string Notes { get; set; } = string.Empty;

    [DataField(Label = "Link", Order = 6)]
    public string Link { get; set; } = string.Empty;

    [DataField(Label = "Is Completed", Order = 7)]
    public bool IsCompleted { get; set; }

    [DataField(Label = "Sub items", Order = 8)]
    public List<string> SubItems { get; set; } = new List<string>();
}
