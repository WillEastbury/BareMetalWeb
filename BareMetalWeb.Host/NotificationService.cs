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

/// <summary>Shared HttpClient for webhook-based notification channels.</summary>
internal static class SharedWebhookHttpClient
{
    internal static readonly HttpClient Instance = new() { Timeout = TimeSpan.FromSeconds(30) };

    /// <summary>
    /// Validates that a webhook endpoint does not target private, loopback, or cloud metadata IPs.
    /// Mirrors the SSRF protection in ProxyRouteHandler.IsPrivateOrMetadataHost (see #1209).
    /// </summary>
    internal static bool ValidateWebhookEndpoint(string endpoint)
    {
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri))
            return false;

        var host = uri.Host;
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
            return false;

        if (IPAddress.TryParse(host, out var ip))
        {
            if (IPAddress.IsLoopback(ip)) return false;
            var bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
            {
                if (bytes[0] == 10) return false;                                        // 10.0.0.0/8
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return false;   // 172.16.0.0/12
                if (bytes[0] == 192 && bytes[1] == 168) return false;                    // 192.168.0.0/16
                if (bytes[0] == 169 && bytes[1] == 254) return false;                    // 169.254.0.0/16
            }
        }

        return true;
    }
}

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
    public WebhookSmsChannel(string endpoint, string apiKey, string from)
    {
        _endpoint = endpoint;
        _apiKey = apiKey;
        _from = from;
    }

    public async ValueTask SendAsync(string recipient, string subject, string body, CancellationToken ct)
    {
        // SECURITY: Block private/metadata IPs to prevent SSRF (see #1209)
        if (!SharedWebhookHttpClient.ValidateWebhookEndpoint(_endpoint))
            throw new InvalidOperationException("Webhook endpoint targets a private or metadata IP address.");

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
        await SharedWebhookHttpClient.Instance.SendAsync(request, ct);
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
    public WebhookNotificationChannel(string endpoint, string secret)
    {
        _endpoint = endpoint;
        _secret   = secret;
    }

    public async ValueTask SendAsync(string recipient, string subject, string body, CancellationToken ct)
    {
        // SECURITY: Block private/metadata IPs to prevent SSRF (see #1209)
        if (!SharedWebhookHttpClient.ValidateWebhookEndpoint(_endpoint))
            throw new InvalidOperationException("Webhook endpoint targets a private or metadata IP address.");
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
        await SharedWebhookHttpClient.Instance.SendAsync(request, ct);
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
        if (!DataScaffold.TryGetEntity("inbox-messages", out var meta))
            return;

        var msg = meta.Handlers.Create();
        meta.FindField("RecipientUserName")?.SetValueFn(msg, recipient);
        meta.FindField("Subject")?.SetValueFn(msg, subject);
        meta.FindField("Body")?.SetValueFn(msg, body);
        meta.FindField("Category")?.SetValueFn(msg, _category);
        meta.FindField("IsRead")?.SetValueFn(msg, false);
        meta.FindField("CreatedAtUtc")?.SetValueFn(msg, DateTime.UtcNow);
        await meta.Handlers.SaveAsync(msg, ct).ConfigureAwait(false);
    }
}

/// <summary>
/// Notification service that resolves channels from metadata-defined notification records
/// and sends templated messages. Integrates with scheduled actions.
/// Works with any BaseDataObject (typed NotificationDefinition or DataRecord).
/// </summary>
public static class NotificationService
{
    private static IBufferedLogger? _logger;
    private static DataEntityMetadata? _channelMeta;

    public static void Initialize(IBufferedLogger? logger = null) => _logger = logger;

    private static DataEntityMetadata? GetChannelMeta()
    {
        if (_channelMeta != null) return _channelMeta;
        if (DataScaffold.TryGetEntity("notification-channels", out var meta))
            _channelMeta = meta;
        return _channelMeta;
    }

    private static string F(BaseDataObject obj, DataEntityMetadata meta, string fieldName)
    {
        var field = meta.FindField(fieldName);
        return field?.GetValueFn?.Invoke(obj)?.ToString() ?? string.Empty;
    }

    /// <summary>
    /// Send a notification using the specified channel record, substituting
    /// field placeholders in subject/body templates.
    /// </summary>
    public static async ValueTask SendAsync(
        BaseDataObject channel,
        string recipient,
        Dictionary<string, string>? fields,
        CancellationToken ct)
    {
        var meta = GetChannelMeta();
        if (meta == null) return;

        if (string.Equals(F(channel, meta, "Enabled"), "False", StringComparison.OrdinalIgnoreCase)) return;

        var subject = ApplyTemplate(F(channel, meta, "SubjectTemplate"), fields);
        var body = ApplyTemplate(F(channel, meta, "BodyTemplate"), fields);
        var channelType = F(channel, meta, "ChannelType");
        var name = F(channel, meta, "Name");
        var host = F(channel, meta, "Host");
        var portStr = F(channel, meta, "Port");
        var port = int.TryParse(portStr, out var p) ? p : 587;
        var useTls = string.Equals(F(channel, meta, "UseTls"), "True", StringComparison.OrdinalIgnoreCase);
        var username = F(channel, meta, "Username");
        var password = F(channel, meta, "Password");
        var fromAddress = F(channel, meta, "FromAddress");

        INotificationChannel transport = channelType.ToLowerInvariant() switch
        {
            "email" => new SmtpNotificationChannel(host, port, useTls, username, password, fromAddress),
            "sms" => new WebhookSmsChannel(host, username, fromAddress),
            "webhook" => new WebhookNotificationChannel(host, password),
            "inapp" => new InAppNotificationChannel(name),
            _ => throw new InvalidOperationException($"Unknown channel type: {channelType}")
        };

        // #1247: Retry with exponential backoff (3 attempts)
        const int maxRetries = 3;
        int[] delaysMs = [0, 2_000, 8_000];
        Exception? lastEx = null;

        try
        {
            for (int attempt = 0; attempt < maxRetries; attempt++)
            {
                if (attempt > 0)
                {
                    try { await Task.Delay(delaysMs[attempt], ct); }
                    catch (OperationCanceledException) { break; }
                }

                try
                {
                    await transport.SendAsync(recipient, subject, body, ct);
                    _logger?.LogInfo($"Notification sent via {channelType}: {name} → {recipient}");
                    return;
                }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex)
                {
                    lastEx = ex;
                    _logger?.LogError($"Notification attempt {attempt + 1}/{maxRetries} failed: {name} → {recipient}", ex);
                }
            }

            if (lastEx != null)
            {
                _logger?.LogError($"Notification permanently failed after {maxRetries} attempts: {name} → {recipient}", lastEx);
            }
        }
        finally
        {
            (transport as IDisposable)?.Dispose();
        }
    }

    /// <summary>Send to all default recipients configured on the channel.</summary>
    public static async ValueTask SendToDefaultRecipientsAsync(
        BaseDataObject channel,
        Dictionary<string, string>? fields,
        CancellationToken ct)
    {
        var meta = GetChannelMeta();
        if (meta == null) return;

        var defaultRecipients = F(channel, meta, "DefaultRecipients");
        if (string.IsNullOrWhiteSpace(defaultRecipients)) return;
        var recipients = defaultRecipients.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
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
