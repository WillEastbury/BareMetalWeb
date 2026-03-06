using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted notification channel configuration. Each record defines a delivery
/// channel (Email or SMS) with connection details and template settings.
/// Notifications can be triggered by scheduled actions or long-running processes.
/// </summary>
[DataEntity("Notification Channels", ShowOnNav = true, NavGroup = "Admin", NavOrder = 1007)]
public class NotificationDefinition : BaseDataObject
{
    [DataField(Label = "Name", Order = 1, Required = true)]
    public string Name { get; set; } = string.Empty;

    /// <summary>Channel type: Email or SMS.</summary>
    [DataField(Label = "Channel Type", Order = 2, Required = true)]
    public NotificationChannelType ChannelType { get; set; } = NotificationChannelType.Email;

    /// <summary>SMTP host (for Email) or API endpoint (for SMS).</summary>
    [DataField(Label = "Host / Endpoint", Order = 3)]
    public string Host { get; set; } = string.Empty;

    /// <summary>Port number (for SMTP).</summary>
    [DataField(Label = "Port", Order = 4)]
    public int Port { get; set; } = 587;

    /// <summary>Whether to use TLS/SSL.</summary>
    [DataField(Label = "Use TLS", Order = 5)]
    public bool UseTls { get; set; } = true;

    /// <summary>Username or API key for authentication.</summary>
    [DataField(Label = "Username / API Key", Order = 6)]
    public string Username { get; set; } = string.Empty;

    /// <summary>Password or API secret. Stored encrypted.</summary>
    [DataField(Label = "Password / Secret", Order = 7, FieldType = FormFieldType.Password)]
    public string Password { get; set; } = string.Empty;

    /// <summary>Default sender address (email) or phone number (SMS).</summary>
    [DataField(Label = "From Address / Number", Order = 8, Required = true)]
    public string FromAddress { get; set; } = string.Empty;

    /// <summary>Comma-separated default recipient addresses or phone numbers.</summary>
    [DataField(Label = "Default Recipients", Order = 9)]
    public string DefaultRecipients { get; set; } = string.Empty;

    /// <summary>Subject template (for Email). Supports {{fieldName}} placeholders.</summary>
    [DataField(Label = "Subject Template", Order = 10)]
    public string SubjectTemplate { get; set; } = string.Empty;

    /// <summary>Body template. Supports {{fieldName}} placeholders and basic HTML (for Email).</summary>
    [DataField(Label = "Body Template", Order = 11, FieldType = FormFieldType.TextArea)]
    public string BodyTemplate { get; set; } = string.Empty;

    /// <summary>Whether this channel is active.</summary>
    [DataField(Label = "Enabled", Order = 12)]
    public bool Enabled { get; set; } = true;

    public override string ToString() => Name;
}

public enum NotificationChannelType
{
    Email = 0,
    Sms = 1,
    Webhook = 2,
    InApp = 3
}
