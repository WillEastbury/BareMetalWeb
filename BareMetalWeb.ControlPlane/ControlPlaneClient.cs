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

    // ── Retry-capable async sends ─────────────────────────────────────────────

    /// <summary>
    /// Attempt to POST a pre-serialised JSON record to the control plane.
    /// Returns <c>true</c> on HTTP 2xx; <c>false</c> on network error or non-success status.
    /// Never throws — the caller (ControlPlaneService) decides how to buffer/retry.
    /// </summary>
    public async Task<bool> TrySendRawAsync(string entityType, string json)
    {
        if (!IsConfigured) return false;
        try
        {
            using var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var request = new HttpRequestMessage(HttpMethod.Post,
                $"{_baseUrl}/api/data/{entityType}");
            request.Headers.TryAddWithoutValidation("ApiKey", _apiKey);
            request.Content = content;
            using var response = await Http.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                _logger?.Log(BmwLogLevel.Debug,
                    $"[BMW ControlPlane] POST {entityType} returned {(int)response.StatusCode}");
                return false;
            }
            return true;
        }
        catch (Exception ex)
        {
            _logger?.Log(BmwLogLevel.Debug,
                $"[BMW ControlPlane] POST {entityType} failed: {ex.Message}");
            return false;
        }
    }

    /// <summary>Serialise <paramref name="payload"/> and attempt to POST it; returns success.</summary>
    public Task<bool> TrySendAsync<T>(string entityType, T payload)
    {
        if (!IsConfigured) return Task.FromResult(false);
        var json = ControlPlaneJsonHelper.SerializeObject(payload);
        return TrySendRawAsync(entityType, json);
    }

    /// <summary>Serialise <paramref name="payload"/> to a JSON string without sending it.</summary>
    public string Serialize<T>(T payload) => ControlPlaneJsonHelper.SerializeObject(payload);

    /// <summary>
    /// Query the control plane for the upgrade status of a specific instance.
    /// Returns null if the control plane is unreachable or not configured.
    /// </summary>
    public Task<UpgradeStatus?> GetUpgradeStatusAsync(string instanceId, string targetVersion)
        => GetAsync<UpgradeStatus>(
            $"/api/_cluster/upgrade-status?instanceId={Uri.EscapeDataString(instanceId)}&targetVersion={Uri.EscapeDataString(targetVersion)}");

    // ── Agent polling ────────────────────────────────────────────────────────

    /// <summary>
    /// Poll the control plane for the desired runtime version for a node.
    /// Uses <c>GET /api/runtime/desired/{nodeId}</c> with
    /// <c>Authorization: Bearer {secret}</c> and <c>X-BMW-Architecture</c> headers.
    /// Returns null if the control plane is unreachable.
    /// </summary>
    public static async Task<RuntimeResponse?> GetDesiredVersionAsync(
        string clusterEndpoint, string nodeId, string secret, string architecture)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get,
                $"{clusterEndpoint.TrimEnd('/')}/api/runtime/desired/{Uri.EscapeDataString(nodeId)}");
            request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {secret}");
            request.Headers.TryAddWithoutValidation("X-BMW-Architecture", architecture);
            using var response = await Http.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                Console.Error.WriteLine(
                    $"[BMW Agent] Poll returned {(int)response.StatusCode}");
                return null;
            }
            var json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            return ControlPlaneJsonHelper.DeserializeRuntimeResponse(json);
        }
        catch (HttpRequestException ex)
        {
            Console.Error.WriteLine($"[BMW Agent] Poll network error: {ex.Message}");
            return null;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[BMW Agent] Poll error: {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Download a runtime binary from <paramref name="downloadUrl"/> (Bearer-authenticated)
    /// and write it to <paramref name="destPath"/>.
    /// Returns <c>true</c> on success.
    /// </summary>
    public static async Task<bool> DownloadRuntimeAsync(
        string downloadUrl, string secret, string destPath, CancellationToken ct = default)
    {
        var tmpPath = destPath + ".tmp";
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, downloadUrl);
            request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {secret}");
            using var response = await Http.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                Console.Error.WriteLine(
                    $"[BMW Agent] Download returned {(int)response.StatusCode}");
                return false;
            }
            await using (var fs = new FileStream(tmpPath, FileMode.Create, FileAccess.Write,
                FileShare.None, bufferSize: 65536, useAsync: true))
            {
                await response.Content.CopyToAsync(fs, ct).ConfigureAwait(false);
            }
            File.Move(tmpPath, destPath, overwrite: true);
            return true;
        }
        catch (HttpRequestException ex)
        {
            Console.Error.WriteLine($"[BMW Agent] Download network error: {ex.Message}");
            TryDeleteTmp(tmpPath);
            return false;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[BMW Agent] Download error: {ex.GetType().Name}: {ex.Message}");
            TryDeleteTmp(tmpPath);
            return false;
        }
    }

    private static void TryDeleteTmp(string path)
    { try { if (File.Exists(path)) File.Delete(path); } catch { /* best-effort */ } }

    // ── Bootstrap: registration + attestation ────────────────────────────────

    /// <summary>
    /// Register a new node with the control plane bootstrap endpoint.
    /// POSTs a <see cref="NodeRegistrationRequest"/> to
    /// <c>POST {bootstrapEndpoint}/api/bootstrap/register</c> with
    /// <c>Authorization: Bearer {secret}</c> and returns the provisioned
    /// <see cref="NodeIdentity"/>, or <c>null</c> on failure.
    /// </summary>
    public static async Task<NodeIdentity?> RegisterNodeAsync(
        string bootstrapEndpoint,
        string secret,
        NodeRegistrationRequest request,
        CancellationToken ct = default)
    {
        try
        {
            var json    = ControlPlaneJsonHelper.Serialize(request);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var req = new HttpRequestMessage(
                HttpMethod.Post,
                $"{bootstrapEndpoint.TrimEnd('/')}/api/bootstrap/register")
            {
                Content = content,
            };
            req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {secret}");

            using var response = await Http.SendAsync(req,
                HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                Console.Error.WriteLine(
                    $"[BMW Agent] Register returned {(int)response.StatusCode}");
                return null;
            }

            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            return ControlPlaneJsonHelper.DeserializeNodeIdentity(body);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[BMW Agent] Register error: {ex.GetType().Name}: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Attest a node's platform with the control plane.
    /// POSTs a <see cref="NodeAttestationRequest"/> to
    /// <c>POST {clusterEndpoint}/api/bootstrap/attest</c>.
    /// Returns <c>true</c> if the control plane accepted the attestation.
    /// </summary>
    public static async Task<bool> AttestNodeAsync(
        string clusterEndpoint,
        string secret,
        NodeAttestationRequest request,
        CancellationToken ct = default)
    {
        try
        {
            var json    = ControlPlaneJsonHelper.Serialize(request);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            using var req = new HttpRequestMessage(
                HttpMethod.Post,
                $"{clusterEndpoint.TrimEnd('/')}/api/bootstrap/attest")
            {
                Content = content,
            };
            req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {secret}");

            using var response = await Http.SendAsync(req,
                HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"[BMW Agent] Attest error: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    private void PostFireAndForget<T>(string entityType, T payload)
    {
        if (!IsConfigured) return;
        _ = Task.Run(async () =>
        {
            try
            {
                var json = ControlPlaneJsonHelper.SerializeObject(payload);
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
            return ControlPlaneJsonHelper.DeserializeObject<T>(json);
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
