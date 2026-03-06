using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Runtime;

namespace BareMetalWeb.Host;

/// <summary>
/// Pluggable notification channel interface. Implementations deliver
/// messages via Email, SMS, or other transports.
/// </summary>
public interface INotificationChannel
{
    ValueTask SendAsync(string recipient, string subject, string body, CancellationToken ct);
}

/// <summary>SMTP email notification channel.</summary>
public sealed class SmtpNotificationChannel : INotificationChannel, IDisposable
{
    private readonly SmtpClient _client;
    private readonly string _from;

    public SmtpNotificationChannel(string host, int port, bool useTls, string username, string password, string from)
    {
        _from = from;
        _client = new SmtpClient(host, port)
        {
            EnableSsl = useTls,
            Credentials = new NetworkCredential(username, password),
            DeliveryMethod = SmtpDeliveryMethod.Network,
            Timeout = 30_000
        };
    }

    public async ValueTask SendAsync(string recipient, string subject, string body, CancellationToken ct)
    {
        using var msg = new MailMessage(_from, recipient, subject, body) { IsBodyHtml = true };
        await _client.SendMailAsync(msg, ct);
    }

    public void Dispose() => _client.Dispose();
}

/// <summary>
/// Webhook-based SMS channel. Posts JSON to an HTTP endpoint.
/// Compatible with services like Twilio, Vonage, or custom gateways.
/// </summary>
public sealed class WebhookSmsChannel : INotificationChannel
{
    private readonly string _endpoint;
    private readonly string _apiKey;
    private readonly string _from;
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };

    public WebhookSmsChannel(string endpoint, string apiKey, string from)
    {
        _endpoint = endpoint;
        _apiKey = apiKey;
        _from = from;
    }

    public async ValueTask SendAsync(string recipient, string subject, string body, CancellationToken ct)
    {
        var payload = JsonWriterHelper.ToJsonString(new Dictionary<string, object?>
        {
            ["from"] = _from,
            ["to"] = recipient,
            ["message"] = $"{subject}\n{body}"
        });
        using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint)
        {
            Content = new StringContent(payload, Encoding.UTF8, "application/json")
        };
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {_apiKey}");
        await _http.SendAsync(request, ct);
    }
}

/// <summary>
/// Outbound webhook notification channel. Posts a JSON payload to a configured HTTP endpoint.
/// Compatible with any HTTP webhook receiver (Slack, Teams, custom integrations, etc.).
/// </summary>
public sealed class WebhookNotificationChannel : INotificationChannel
{
    private readonly string _endpoint;
    private readonly string _secret;
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };

    public WebhookNotificationChannel(string endpoint, string secret)
    {
        _endpoint = endpoint;
        _secret   = secret;
    }

    public async ValueTask SendAsync(string recipient, string subject, string body, CancellationToken ct)
    {
        var payload = JsonWriterHelper.ToJsonString(new Dictionary<string, object?>
        {
            ["recipient"] = recipient,
            ["subject"] = subject,
            ["body"] = body,
            ["timestamp"] = DateTime.UtcNow
        });
        using var request = new HttpRequestMessage(HttpMethod.Post, _endpoint)
        {
            Content = new StringContent(payload, Encoding.UTF8, "application/json")
        };
        if (!string.IsNullOrEmpty(_secret))
            request.Headers.TryAddWithoutValidation("X-Webhook-Secret", _secret);
        await _http.SendAsync(request, ct);
    }
}

/// <summary>
/// In-app notification channel. Persists an <see cref="InboxMessage"/> record
/// for the recipient user so it appears in their inbox.
/// </summary>
public sealed class InAppNotificationChannel : INotificationChannel
{
    private readonly string _category;

    public InAppNotificationChannel(string category = "") => _category = category;

    public async ValueTask SendAsync(string recipient, string subject, string body, CancellationToken ct)
    {
        var msg = new InboxMessage
        {
            RecipientUserName = recipient,
            Subject           = subject,
            Body              = body,
            Category          = _category,
            IsRead            = false,
            CreatedAtUtc      = DateTime.UtcNow
        };
        await DataStoreProvider.Current.SaveAsync(msg, ct).ConfigureAwait(false);
    }
}

/// <summary>
/// Notification service that resolves channels from NotificationDefinition records
/// and sends templated messages. Integrates with scheduled actions.
/// </summary>
public static class NotificationService
{
    private static IBufferedLogger? _logger;

    public static void Initialize(IBufferedLogger? logger = null) => _logger = logger;

    /// <summary>
    /// Send a notification using the specified channel definition, substituting
    /// field placeholders in subject/body templates.
    /// </summary>
    public static async ValueTask SendAsync(
        NotificationDefinition channel,
        string recipient,
        Dictionary<string, string>? fields,
        CancellationToken ct)
    {
        if (!channel.Enabled) return;

        var subject = ApplyTemplate(channel.SubjectTemplate, fields);
        var body = ApplyTemplate(channel.BodyTemplate, fields);

        INotificationChannel transport = channel.ChannelType switch
        {
            NotificationChannelType.Email => new SmtpNotificationChannel(
                channel.Host, channel.Port, channel.UseTls,
                channel.Username, channel.Password, channel.FromAddress),
            NotificationChannelType.Sms => new WebhookSmsChannel(
                channel.Host, channel.Username, channel.FromAddress),
            NotificationChannelType.Webhook => new WebhookNotificationChannel(
                channel.Host, channel.Password),
            NotificationChannelType.InApp => new InAppNotificationChannel(channel.Name),
            _ => throw new InvalidOperationException($"Unknown channel type: {channel.ChannelType}")
        };

        try
        {
            await transport.SendAsync(recipient, subject, body, ct);
            _logger?.LogInfo($"Notification sent via {channel.ChannelType}: {channel.Name} → {recipient}");
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Notification failed: {channel.Name} → {recipient}", ex);
        }
        finally
        {
            (transport as IDisposable)?.Dispose();
        }
    }

    /// <summary>Send to all default recipients configured on the channel.</summary>
    public static async ValueTask SendToDefaultRecipientsAsync(
        NotificationDefinition channel,
        Dictionary<string, string>? fields,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(channel.DefaultRecipients)) return;
        var recipients = channel.DefaultRecipients.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var r in recipients)
            await SendAsync(channel, r, fields, ct);
    }

    /// <summary>Replace {{fieldName}} placeholders in a template string.</summary>
    private static string ApplyTemplate(string template, Dictionary<string, string>? fields)
    {
        if (string.IsNullOrEmpty(template) || fields == null) return template ?? string.Empty;
        return Regex.Replace(template, @"\{\{(\w+)\}\}", m =>
        {
            var key = m.Groups[1].Value;
            return fields.TryGetValue(key, out var val) ? val : m.Value;
        });
    }
}
