using System.Net.Http;
using System.Text;
using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;

namespace BareMetalWeb.ControlPlane;

/// <summary>
/// Fire-and-forget HTTP client for streaming heartbeats, telemetry, errors,
/// and backup records to a central BareMetalWeb control-plane instance.
/// All operations are non-blocking and fail silently — the control plane
/// being unavailable must never affect the running instance.
/// </summary>
public sealed class ControlPlaneClient
{
    private readonly string _baseUrl;
    private readonly string _apiKey;
    private readonly IBufferedLogger? _logger;

    private static readonly HttpClient Http = new(new SocketsHttpHandler
    {
        MaxConnectionsPerServer = 4,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
        ConnectTimeout = TimeSpan.FromSeconds(5),
    })
    {
        Timeout = TimeSpan.FromSeconds(10),
    };

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    public ControlPlaneClient(string baseUrl, string apiKey, IBufferedLogger? logger = null)
    {
        _baseUrl = baseUrl.TrimEnd('/');
        _apiKey = apiKey;
        _logger = logger;
    }

    /// <summary>True when both URL and API key are configured.</summary>
    public bool IsConfigured => !string.IsNullOrEmpty(_baseUrl) && !string.IsNullOrEmpty(_apiKey);

    public void SendHeartbeat(InstanceHeartbeat heartbeat)
        => PostFireAndForget("InstanceHeartbeat", heartbeat);

    public void SendTelemetry(TelemetrySnapshot snapshot)
        => PostFireAndForget("TelemetrySnapshot", snapshot);

    public void SendError(ErrorEvent error)
        => PostFireAndForget("ErrorEvent", error);

    public void SendBackupRecord(BackupRecord record)
        => PostFireAndForget("BackupRecord", record);
    public void SendUpgradeVerification(UpgradeVerificationRecord record)
        => PostFireAndForget("UpgradeVerificationRecord", record);

    /// <summary>
    /// Query the control plane for the upgrade status of a specific instance.
    /// Returns null if the control plane is unreachable or not configured.
    /// </summary>
    public Task<UpgradeStatus?> GetUpgradeStatusAsync(string instanceId, string targetVersion)
        => GetAsync<UpgradeStatus>(
            $"/api/_cluster/upgrade-status?instanceId={Uri.EscapeDataString(instanceId)}&targetVersion={Uri.EscapeDataString(targetVersion)}");

    private void PostFireAndForget<T>(string entityType, T payload)
    {
        if (!IsConfigured) return;
        _ = Task.Run(async () =>
        {
            try
            {
                var json = JsonSerializer.Serialize(payload, JsonOpts);
                using var content = new StringContent(json, Encoding.UTF8, "application/json");
                using var request = new HttpRequestMessage(HttpMethod.Post,
                    $"{_baseUrl}/api/data/{entityType}");
                request.Headers.TryAddWithoutValidation("ApiKey", _apiKey);
                request.Content = content;
                using var response = await Http.SendAsync(request,
                    HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
                if (!response.IsSuccessStatusCode)
                    _logger?.Log(BmwLogLevel.Debug,
                        $"[BMW ControlPlane] POST {entityType} returned {(int)response.StatusCode}");
            }
            catch (Exception ex)
            {
                _logger?.Log(BmwLogLevel.Debug,
                    $"[BMW ControlPlane] POST {entityType} failed: {ex.Message}");
            }
        });
    }

    // ── GET operations (synchronous, awaitable) ─────────────────────────────

    /// <summary>GET a typed response from the control plane. Returns null on any failure.</summary>
    public async Task<T?> GetAsync<T>(string path) where T : class
    {
        if (!IsConfigured) return null;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{_baseUrl}{path}");
            request.Headers.TryAddWithoutValidation("ApiKey", _apiKey);
            using var response = await Http.SendAsync(request).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                _logger?.Log(BmwLogLevel.Debug,
                    $"[BMW ControlPlane] GET {path} returned {(int)response.StatusCode}");
                return null;
            }
            var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            return JsonSerializer.Deserialize<T>(json, JsonOpts);
        }
        catch (Exception ex)
        {
            _logger?.Log(BmwLogLevel.Debug,
                $"[BMW ControlPlane] GET {path} failed: {ex.Message}");
            return null;
        }
    }

    /// <summary>GET raw JSON string from the control plane. Returns null on any failure.</summary>
    public async Task<string?> GetRawAsync(string path)
    {
        if (!IsConfigured) return null;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{_baseUrl}{path}");
            request.Headers.TryAddWithoutValidation("ApiKey", _apiKey);
            using var response = await Http.SendAsync(request).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                _logger?.Log(BmwLogLevel.Debug,
                    $"[BMW ControlPlane] GET {path} returned {(int)response.StatusCode}");
                return null;
            }
            return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger?.Log(BmwLogLevel.Debug,
                $"[BMW ControlPlane] GET {path} failed: {ex.Message}");
            return null;
        }
    }
}
