using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted notification channel configuration. Each record defines a delivery
/// channel (Email or SMS) with connection details and template settings.
/// Notifications can be triggered by scheduled actions or long-running processes.
/// </summary>
[DataEntity("Notification Channels", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1007)]
public class NotificationDefinition : BaseDataObject
{
    public override string EntityTypeName => "Notification Channels";
    private const int Ord_Name = BaseFieldCount + 0;
    private const int Ord_ChannelType = BaseFieldCount + 1;
    private const int Ord_Host = BaseFieldCount + 2;
    private const int Ord_Port = BaseFieldCount + 3;
    private const int Ord_UseTls = BaseFieldCount + 4;
    private const int Ord_Username = BaseFieldCount + 5;
    private const int Ord_Password = BaseFieldCount + 6;
    private const int Ord_FromAddress = BaseFieldCount + 7;
    private const int Ord_DefaultRecipients = BaseFieldCount + 8;
    private const int Ord_SubjectTemplate = BaseFieldCount + 9;
    private const int Ord_BodyTemplate = BaseFieldCount + 10;
    private const int Ord_Enabled = BaseFieldCount + 11;
    internal const int TotalFieldCount = BaseFieldCount + 12;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("BodyTemplate", Ord_BodyTemplate),
        new FieldSlot("ChannelType", Ord_ChannelType),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("DefaultRecipients", Ord_DefaultRecipients),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Enabled", Ord_Enabled),
        new FieldSlot("FromAddress", Ord_FromAddress),
        new FieldSlot("Host", Ord_Host),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Name", Ord_Name),
        new FieldSlot("Password", Ord_Password),
        new FieldSlot("Port", Ord_Port),
        new FieldSlot("SubjectTemplate", Ord_SubjectTemplate),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("UseTls", Ord_UseTls),
        new FieldSlot("Username", Ord_Username),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public NotificationDefinition() : base(TotalFieldCount) { }
    public NotificationDefinition(string createdBy) : base(TotalFieldCount, createdBy) { }

    [DataField(Label = "Name", Order = 1, Required = true)]
    public string Name
    {
        get => (string?)_values[Ord_Name] ?? string.Empty;
        set => _values[Ord_Name] = value;
    }

    /// <summary>Channel type: Email or SMS.</summary>
    [DataField(Label = "Channel Type", Order = 2, Required = true)]
    public NotificationChannelType ChannelType
    {
        get => _values[Ord_ChannelType] is NotificationChannelType v ? v : default;
        set => _values[Ord_ChannelType] = value;
    }

    /// <summary>SMTP host (for Email) or API endpoint (for SMS).</summary>
    [DataField(Label = "Host / Endpoint", Order = 3)]
    public string Host
    {
        get => (string?)_values[Ord_Host] ?? string.Empty;
        set => _values[Ord_Host] = value;
    }

    /// <summary>Port number (for SMTP).</summary>
    [DataField(Label = "Port", Order = 4)]
    public int Port
    {
        get => (int)(_values[Ord_Port] ?? 587);
        set => _values[Ord_Port] = value;
    }

    /// <summary>Whether to use TLS/SSL.</summary>
    [DataField(Label = "Use TLS", Order = 5)]
    public bool UseTls
    {
        get => _values[Ord_UseTls] is true;
        set => _values[Ord_UseTls] = value;
    }

    /// <summary>Username or API key for authentication.</summary>
    [DataField(Label = "Username / API Key", Order = 6)]
    public string Username
    {
        get => (string?)_values[Ord_Username] ?? string.Empty;
        set => _values[Ord_Username] = value;
    }

    /// <summary>Password or API secret. Stored encrypted.</summary>
    [DataField(Label = "Password / Secret", Order = 7, FieldType = FormFieldType.Password)]
    public string Password
    {
        get => (string?)_values[Ord_Password] ?? string.Empty;
        set => _values[Ord_Password] = value;
    }

    /// <summary>Default sender address (email) or phone number (SMS).</summary>
    [DataField(Label = "From Address / Number", Order = 8, Required = true)]
    public string FromAddress
    {
        get => (string?)_values[Ord_FromAddress] ?? string.Empty;
        set => _values[Ord_FromAddress] = value;
    }

    /// <summary>Comma-separated default recipient addresses or phone numbers.</summary>
    [DataField(Label = "Default Recipients", Order = 9)]
    public string DefaultRecipients
    {
        get => (string?)_values[Ord_DefaultRecipients] ?? string.Empty;
        set => _values[Ord_DefaultRecipients] = value;
    }

    /// <summary>Subject template (for Email). Supports {{fieldName}} placeholders.</summary>
    [DataField(Label = "Subject Template", Order = 10)]
    public string SubjectTemplate
    {
        get => (string?)_values[Ord_SubjectTemplate] ?? string.Empty;
        set => _values[Ord_SubjectTemplate] = value;
    }

    /// <summary>Body template. Supports {{fieldName}} placeholders and basic HTML (for Email).</summary>
    [DataField(Label = "Body Template", Order = 11, FieldType = FormFieldType.TextArea)]
    public string BodyTemplate
    {
        get => (string?)_values[Ord_BodyTemplate] ?? string.Empty;
        set => _values[Ord_BodyTemplate] = value;
    }

    /// <summary>Whether this channel is active.</summary>
    [DataField(Label = "Enabled", Order = 12)]
    public bool Enabled
    {
        get => _values[Ord_Enabled] is true;
        set => _values[Ord_Enabled] = value;
    }

    public override string ToString() => Name;
}

public enum NotificationChannelType
{
    Email = 0,
    Sms = 1,
    Webhook = 2,
    InApp = 3
}
