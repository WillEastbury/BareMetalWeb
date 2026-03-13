using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// A simple todo / action item that can be created and tracked by the admin agent.
/// </summary>
[DataEntity("Todo Items", ShowOnNav = true, NavGroup = "Productivity", NavOrder = 100)]
public class TodoItem : BaseDataObject
{
    [DataField(Label = "Title", Order = 1)]
    public string Title { get; set; } = string.Empty;

    [DataField(Label = "Description", Order = 2, FieldType = FormFieldType.TextArea)]
    public string Description { get; set; } = string.Empty;

    [DataField(Label = "Status", Order = 3)]
    public TodoStatus Status { get; set; } = TodoStatus.Open;

    [DataField(Label = "Due Date", Order = 4, FieldType = FormFieldType.DateOnly)]
    public DateTime? DueDate { get; set; }

    [DataField(Label = "Created At", Order = 5, ReadOnly = true)]
    public DateTime CreatedAtUtc { get; set; }

    public override string ToString() => Title;
}

public enum TodoStatus
{
    Open = 0,
    InProgress = 1,
    Done = 2,
    Cancelled = 3
}
