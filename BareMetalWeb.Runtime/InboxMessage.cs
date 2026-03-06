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
    /// <summary>Username of the recipient user.</summary>
    [DataField(Label = "Recipient", Order = 1, Required = true, List = true, View = true)]
    [DataIndex]
    public string RecipientUserName { get; set; } = string.Empty;

    /// <summary>Short subject line for the notification.</summary>
    [DataField(Label = "Subject", Order = 2, Required = true, List = true, View = true)]
    public string Subject { get; set; } = string.Empty;

    /// <summary>Notification body text (plain text only; HTML characters are escaped on display).</summary>
    [DataField(Label = "Body", Order = 3, FieldType = FormFieldType.TextArea, View = true)]
    public string Body { get; set; } = string.Empty;

    /// <summary>Category tag (e.g. Lead, Payment, Ticket).</summary>
    [DataField(Label = "Category", Order = 4, List = true, View = true)]
    [DataIndex]
    public string Category { get; set; } = string.Empty;

    /// <summary>Whether the user has read this message.</summary>
    [DataField(Label = "Read", Order = 5, List = true, View = true, FieldType = FormFieldType.YesNo)]
    [DataIndex]
    public bool IsRead { get; set; } = false;

    /// <summary>UTC timestamp when the notification was created.</summary>
    [DataField(Label = "Created", Order = 6, List = true, View = true, ReadOnly = true, FieldType = FormFieldType.DateTime)]
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>
    /// Optional deep-link: the entity slug the notification relates to (e.g. "orders").
    /// </summary>
    [DataField(Label = "Entity Slug", Order = 7, View = true)]
    public string EntitySlug { get; set; } = string.Empty;

    /// <summary>
    /// Optional deep-link: the entity record ID the notification relates to.
    /// </summary>
    [DataField(Label = "Entity Id", Order = 8, View = true)]
    public string EntityId { get; set; } = string.Empty;

    public override string ToString() => Subject;
}
