using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted chat session. Groups a conversation between a user and the
/// BitNet inference engine, maintaining context across multiple turns.
/// </summary>
[DataEntity("Chat Sessions", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1010)]
public class ChatSession : DataRecord
{
    public override string EntityTypeName => "ChatSession";
    private const int Ord_UserName = BaseFieldCount + 0;
    private const int Ord_Title = BaseFieldCount + 1;
    private const int Ord_CreatedAtUtc = BaseFieldCount + 2;
    private const int Ord_UpdatedAtUtc = BaseFieldCount + 3;
    private const int Ord_MessageCount = BaseFieldCount + 4;
    private const int Ord_Status = BaseFieldCount + 5;
    internal const int TotalFieldCount = BaseFieldCount + 6;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedAtUtc", Ord_CreatedAtUtc),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("MessageCount", Ord_MessageCount),
        new FieldSlot("Status", Ord_Status),
        new FieldSlot("Title", Ord_Title),
        new FieldSlot("UpdatedAtUtc", Ord_UpdatedAtUtc),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("UserName", Ord_UserName),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public ChatSession() : base(TotalFieldCount) { }
    public ChatSession(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>Username of the session owner.</summary>
    [DataField(Label = "User", Order = 1, Required = true, List = true, View = true)]
    [DataIndex]
    public string UserName
    {
        get => (string?)_values[Ord_UserName] ?? string.Empty;
        set => _values[Ord_UserName] = value;
    }

    /// <summary>Short title summarising the conversation.</summary>
    [DataField(Label = "Title", Order = 2, Required = true, List = true, View = true, Edit = true)]
    public string Title
    {
        get => (string?)_values[Ord_Title] ?? string.Empty;
        set => _values[Ord_Title] = value;
    }

    /// <summary>UTC timestamp when the session was created.</summary>
    [DataField(Label = "Created", Order = 3, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime CreatedAtUtc
    {
        get => _values[Ord_CreatedAtUtc] is DateTime dt ? dt : default;
        set => _values[Ord_CreatedAtUtc] = value;
    }

    /// <summary>UTC timestamp of the last message in the session.</summary>
    [DataField(Label = "Last Message", Order = 4, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime UpdatedAtUtc
    {
        get => _values[Ord_UpdatedAtUtc] is DateTime dt ? dt : default;
        set => _values[Ord_UpdatedAtUtc] = value;
    }

    /// <summary>Number of messages in the session (user + assistant).</summary>
    [DataField(Label = "Messages", Order = 5, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.Integer)]
    public int MessageCount
    {
        get => (int)(_values[Ord_MessageCount] ?? 0);
        set => _values[Ord_MessageCount] = value;
    }

    /// <summary>Session status: active, archived.</summary>
    [DataField(Label = "Status", Order = 6, List = true, View = true, FieldType = FormFieldType.Enum)]
    public string Status
    {
        get => (string?)_values[Ord_Status] ?? "active";
        set => _values[Ord_Status] = value;
    }

    public override string ToString() => Title;
}
