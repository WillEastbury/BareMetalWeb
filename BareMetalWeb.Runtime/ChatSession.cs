using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted chat session. Groups a conversation between a user and the
/// BitNet inference engine, maintaining context across multiple turns.
/// </summary>
[DataEntity("Chat Sessions", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1010)]
public class ChatSession : BaseDataObject
{
    /// <summary>Username of the session owner.</summary>
    [DataField(Label = "User", Order = 1, Required = true, List = true, View = true)]
    [DataIndex]
    public string UserName { get; set; } = string.Empty;

    /// <summary>Short title summarising the conversation.</summary>
    [DataField(Label = "Title", Order = 2, Required = true, List = true, View = true, Edit = true)]
    public string Title { get; set; } = string.Empty;

    /// <summary>UTC timestamp when the session was created.</summary>
    [DataField(Label = "Created", Order = 3, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>UTC timestamp of the last message in the session.</summary>
    [DataField(Label = "Last Message", Order = 4, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime UpdatedAtUtc { get; set; }

    /// <summary>Number of messages in the session (user + assistant).</summary>
    [DataField(Label = "Messages", Order = 5, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.Integer)]
    public int MessageCount { get; set; }

    /// <summary>Session status: active, archived.</summary>
    [DataField(Label = "Status", Order = 6, List = true, View = true, FieldType = FormFieldType.Enum)]
    public string Status { get; set; } = "active";

    public override string ToString() => Title;
}
