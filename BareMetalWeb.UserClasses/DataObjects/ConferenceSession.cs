namespace BareMetalWeb.Data.DataObjects;

[DataEntity("Conference Sessions", ShowOnNav = true, NavGroup = "Events", NavOrder = 30)]
public class ConferenceSession : RenderableDataObject
{
    [DataField(Label = "Title", Order = 1, Required = true)]
    public string Title { get; set; } = string.Empty;

    [DataField(Label = "Speaker", Order = 2, Required = true)]
    public string Speaker { get; set; } = string.Empty;

    [DataField(Label = "Track", Order = 3)]
    public string Track { get; set; } = string.Empty;

    [DataField(Label = "Room", Order = 4)]
    public string Room { get; set; } = string.Empty;

    [DataField(Label = "Start Time", Order = 5, Required = true, FieldType = Rendering.Models.FormFieldType.DateTime)]
    public DateTime StartTime { get; set; } = DateTime.UtcNow;

    [DataField(Label = "End Time", Order = 6, Required = true, FieldType = Rendering.Models.FormFieldType.DateTime)]
    public DateTime EndTime { get; set; } = DateTime.UtcNow.AddHours(1);

    [DataField(Label = "Capacity", Order = 7)]
    public int Capacity { get; set; }

    [DataField(Label = "Description", Order = 8)]
    public string Description { get; set; } = string.Empty;

    [DataField(Label = "Tags", Order = 9)]
    public List<string> Tags { get; set; } = new();

    [DataField(Label = "Active", Order = 10)]
    public bool IsActive { get; set; } = true;
}
