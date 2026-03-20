using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted in-app inbox message. Each record represents a notification
/// delivered to a specific user's in-app inbox.
/// </summary>
[DataEntity("Inbox Messages", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1008)]
public class InboxMessage : BaseDataObject
{
    public override string EntityTypeName => "Inbox Messages";
    private const int Ord_RecipientUserName = BaseFieldCount + 0;
    private const int Ord_Subject = BaseFieldCount + 1;
    private const int Ord_Body = BaseFieldCount + 2;
    private const int Ord_Category = BaseFieldCount + 3;
    private const int Ord_IsRead = BaseFieldCount + 4;
    private const int Ord_CreatedAtUtc = BaseFieldCount + 5;
    private const int Ord_EntitySlug = BaseFieldCount + 6;
    private const int Ord_EntityId = BaseFieldCount + 7;
    internal const int TotalFieldCount = BaseFieldCount + 8;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("Body", Ord_Body),
        new FieldSlot("Category", Ord_Category),
        new FieldSlot("CreatedAtUtc", Ord_CreatedAtUtc),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("EntityId", Ord_EntityId),
        new FieldSlot("EntitySlug", Ord_EntitySlug),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("IsRead", Ord_IsRead),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("RecipientUserName", Ord_RecipientUserName),
        new FieldSlot("Subject", Ord_Subject),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public InboxMessage() : base(TotalFieldCount) { }
    public InboxMessage(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>Username of the recipient user.</summary>
    [DataField(Label = "Recipient", Order = 1, Required = true, List = true, View = true)]
    [DataIndex]
    public string RecipientUserName
    {
        get => (string?)_values[Ord_RecipientUserName] ?? string.Empty;
        set => _values[Ord_RecipientUserName] = value;
    }

    /// <summary>Short subject line for the notification.</summary>
    [DataField(Label = "Subject", Order = 2, Required = true, List = true, View = true)]
    public string Subject
    {
        get => (string?)_values[Ord_Subject] ?? string.Empty;
        set => _values[Ord_Subject] = value;
    }

    /// <summary>Notification body text (plain text only; HTML characters are escaped on display).</summary>
    [DataField(Label = "Body", Order = 3, FieldType = FormFieldType.TextArea, View = true)]
    public string Body
    {
        get => (string?)_values[Ord_Body] ?? string.Empty;
        set => _values[Ord_Body] = value;
    }

    /// <summary>Category tag (e.g. Lead, Payment, Ticket).</summary>
    [DataField(Label = "Category", Order = 4, List = true, View = true)]
    [DataIndex]
    public string Category
    {
        get => (string?)_values[Ord_Category] ?? string.Empty;
        set => _values[Ord_Category] = value;
    }

    /// <summary>Whether the user has read this message.</summary>
    [DataField(Label = "Read", Order = 5, List = true, View = true, FieldType = FormFieldType.YesNo)]
    [DataIndex]
    public bool IsRead
    {
        get => _values[Ord_IsRead] is true;
        set => _values[Ord_IsRead] = value;
    }

    /// <summary>UTC timestamp when the notification was created.</summary>
    [DataField(Label = "Created", Order = 6, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime CreatedAtUtc
    {
        get => _values[Ord_CreatedAtUtc] is DateTime dt ? dt : default;
        set => _values[Ord_CreatedAtUtc] = value;
    }

    /// <summary>
    /// Optional deep-link: the entity slug the notification relates to (e.g. "orders").
    /// </summary>
    [DataField(Label = "Entity Slug", Order = 7, View = true)]
    public string EntitySlug
    {
        get => (string?)_values[Ord_EntitySlug] ?? string.Empty;
        set => _values[Ord_EntitySlug] = value;
    }

    /// <summary>
    /// Optional deep-link: the entity record ID the notification relates to.
    /// </summary>
    [DataField(Label = "Entity Id", Order = 8, View = true)]
    public string EntityId
    {
        get => (string?)_values[Ord_EntityId] ?? string.Empty;
        set => _values[Ord_EntityId] = value;
    }

    public override string ToString() => Subject;
}
