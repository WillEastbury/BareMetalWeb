using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Interfaces;
using Microsoft.Extensions.Primitives;

namespace BareMetalWeb.Host;

public sealed class ProxyRouteHandler
{
    private static readonly HttpClient Client = new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        MaxConnectionsPerServer = 1024,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        PooledConnectionIdleTimeout = TimeSpan.FromMinutes(2),
        AutomaticDecompression = DecompressionMethods.None
    });

    private static readonly HashSet<string> HopByHopHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Connection",
        "Keep-Alive",
        "Proxy-Authenticate",
        "Proxy-Authorization",
        "TE",
        "Trailers",
        "Transfer-Encoding",
        "Upgrade"
    };

    private static readonly HashSet<string> RetryableMethods = new(StringComparer.OrdinalIgnoreCase)
    {
        "GET",
        "HEAD",
        "OPTIONS",
        "TRACE"
    };

    private static readonly HashSet<HttpStatusCode> RetryableStatusCodes = new()
    {
        HttpStatusCode.BadGateway,
        HttpStatusCode.ServiceUnavailable,
        HttpStatusCode.GatewayTimeout
    };

    private static ClusterState? _clusterState;

    /// <summary>Set the cluster state reference so proxy handlers can inject lease-owner affinity cookies.</summary>
    public static void Initialize(ClusterState clusterState) => _clusterState = clusterState;

    private readonly ProxyRouteConfig _route;
    private readonly IBufferedLogger _logger;
    private readonly List<ProxyTargetState> _targets;
    private int _roundRobinIndex;

    public ProxyRouteHandler(ProxyRouteConfig route, IBufferedLogger logger)
    {
        _route = route ?? throw new ArgumentNullException(nameof(route));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _targets = BuildTargetStates(route);
    }

    public async ValueTask HandleAsync(HttpContext context)
    {
        if (context == null) throw new ArgumentNullException(nameof(context));

        var hasBody = ShouldHaveBody(context.Request);
        var retryAllRequested = !string.IsNullOrWhiteSpace(_route.RetryAllMethodsHeader)
            && context.Request.Headers.ContainsKey(_route.RetryAllMethodsHeader);
        byte[]? bufferedBody = null;

        if (retryAllRequested && hasBody)
        {
            bufferedBody = await TryBufferRequestBodyAsync(context, _route.MaxRetryBodyBytes);
            if (bufferedBody == null)
            {
                retryAllRequested = false;
            }
        }

        var canRetry = retryAllRequested
            ? (!hasBody || bufferedBody != null)
            : _route.RetryIdempotentRequests && RetryableMethods.Contains(context.Request.Method) && !hasBody;

        var maxAttempts = canRetry ? Math.Max(1, _route.MaxRetries + 1) : 1;
        var attempted = new HashSet<ProxyTargetState>();
        var stickyKey = GetStickyKey(context, out var setStickyCookie);

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            var targetState = SelectTargetState(attempted, stickyKey);
            if (targetState == null)
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                await context.Response.WriteAsync("No proxy targets available.");
                return;
            }

            attempted.Add(targetState);
            if (setStickyCookie && _route.StickySessionsEnabled && string.Equals(_route.StickySessionMode, "Cookie", StringComparison.OrdinalIgnoreCase))
            {
                SetStickyCookie(context, stickyKey!);
            }
            if (_route.EnableVerboseLog)
            {
                _logger.LogInfo($"Proxy attempt {attempt}/{maxAttempts} -> {targetState.BaseUri}");
            }
            Uri targetUri;
            try
            {
                targetUri = BuildTargetUri(context, targetState.BaseUri);
            }
            catch (InvalidOperationException)
            {
                context.Response.StatusCode = StatusCodes.Status502BadGateway;
                await context.Response.WriteAsync("Proxy target blocked.");
                return;
            }
            using var requestMessage = new HttpRequestMessage(new HttpMethod(context.Request.Method), targetUri)
            {
                VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
            };

            if (hasBody)
            {
                if (bufferedBody != null)
                {
                    requestMessage.Content = new ByteArrayContent(bufferedBody);
                }
                else
                {
                    requestMessage.Content = new StreamContent(context.Request.Body);
                }
                if (!string.IsNullOrWhiteSpace(context.Request.ContentType))
                {
                    requestMessage.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(context.Request.ContentType);
                }
                if (context.Request.ContentLength.HasValue)
                {
                    requestMessage.Content.Headers.ContentLength = context.Request.ContentLength.Value;
                }
            }

            CopyRequestHeaders(context, requestMessage);
            ApplyTraceId(context, requestMessage);
            ApplyLeaseAffinityCookie(requestMessage);

            try
            {
                using var responseMessage = await Client.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);
                var isRetryableFailure = RetryableStatusCodes.Contains(responseMessage.StatusCode);
                if (canRetry && isRetryableFailure && attempt < maxAttempts && HasAvailableTargets(attempted))
                {
                    TrackResult(targetState, responseMessage.StatusCode);
                    if (_route.EnableVerboseLog)
                    {
                        _logger.LogInfo($"Proxy retryable status {(int)responseMessage.StatusCode} from {targetState.BaseUri}");
                    }
                    await ApplyRetryDelayAsync(attempt, context.RequestAborted);
                    continue;
                }

                context.Response.StatusCode = (int)responseMessage.StatusCode;
                if (responseMessage.Content.Headers.ContentLength.HasValue)
                {
                    context.Response.ContentLength = responseMessage.Content.Headers.ContentLength.Value;
                }
                CopyResponseHeaders(context, responseMessage);
                await using var responseStream = await responseMessage.Content.ReadAsStreamAsync(context.RequestAborted);
                await responseStream.CopyToAsync(context.Response.Body, 81920, context.RequestAborted);

                TrackResult(targetState, responseMessage.IsSuccessStatusCode ? null : responseMessage.StatusCode);
                if (_route.EnableVerboseLog)
                {
                    _logger.LogInfo($"Proxy completed with {(int)responseMessage.StatusCode} from {targetState.BaseUri}");
                }
                return;
            }
            catch (OperationCanceledException)
            {
                if (_route.UseStatus499ForClientAbort)
                {
                    context.Response.StatusCode = 499;
                }
                else
                {
                    context.Response.StatusCode = StatusCodes.Status400BadRequest;
                }
                return;
            }
            catch (Exception ex)
            {
                _logger.LogError("Proxy request failed.", ex);
                TrackResult(targetState, HttpStatusCode.BadGateway, ex);
                if (canRetry && attempt < maxAttempts && HasAvailableTargets(attempted))
                {
                    await ApplyRetryDelayAsync(attempt, context.RequestAborted);
                    continue;
                }

                context.Response.StatusCode = StatusCodes.Status502BadGateway;
                context.Response.ContentType = "text/plain";
                await context.Response.WriteAsync("Proxy request failed.");
                return;
            }
        }
    }

    private Uri BuildTargetUri(HttpContext context, Uri targetBaseUri)
    {
        var builder = new UriBuilder(targetBaseUri);
        var query = context.Request.QueryString.HasValue ? context.Request.QueryString.Value : string.Empty;

        var requestPath = context.Request.Path.HasValue ? context.Request.Path.Value! : string.Empty;
        var stripPrefix = _route.PathPrefixToStrip ?? string.Empty;
        if (!string.IsNullOrWhiteSpace(stripPrefix) && requestPath.StartsWith(stripPrefix, StringComparison.OrdinalIgnoreCase))
        {
            requestPath = requestPath[stripPrefix.Length..];
            if (!requestPath.StartsWith('/'))
                requestPath = "/" + requestPath;
        }

        // Block path traversal sequences
        if (requestPath.Contains(".."))
            requestPath = requestPath.Replace("..", string.Empty);

        if (!string.IsNullOrWhiteSpace(_route.RewritePath))
        {
            builder.Path = _route.RewritePath!;
        }
        else
        {
            var basePath = builder.Path?.TrimEnd('/') ?? string.Empty;
            var addPrefix = _route.PathPrefixToAdd ?? string.Empty;
            var combinedPath = string.Concat(basePath, addPrefix, requestPath).Replace("//", "/");
            builder.Path = string.IsNullOrWhiteSpace(combinedPath) ? "/" : combinedPath;
        }

        if (_route.IncludeQuery && !string.IsNullOrWhiteSpace(query))
        {
            var extraQuery = query.TrimStart('?');
            if (string.IsNullOrWhiteSpace(builder.Query))
            {
                builder.Query = extraQuery;
            }
            else
            {
                builder.Query = builder.Query.TrimStart('?') + "&" + extraQuery;
            }
        }

        var result = builder.Uri;

        // Block requests to private/metadata IPs
        if (IsPrivateOrMetadataHost(result.Host))
            throw new InvalidOperationException("Proxy target resolves to a blocked address.");

        return result;
    }

    /// <summary>Reject private, loopback, and cloud metadata IPs/hostnames.</summary>
    private static bool IsPrivateOrMetadataHost(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)) return true;
        if (!IPAddress.TryParse(host, out var ip)) return false;
        if (IPAddress.IsLoopback(ip)) return true;
        var bytes = ip.GetAddressBytes();
        if (bytes.Length == 4)
        {
            if (bytes[0] == 10) return true;                                    // 10.0.0.0/8
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true; // 172.16.0.0/12
            if (bytes[0] == 192 && bytes[1] == 168) return true;                // 192.168.0.0/16
            if (bytes[0] == 169 && bytes[1] == 254) return true;                // 169.254.0.0/16 (link-local + cloud metadata)
        }
        return false;
    }

    private static bool ShouldHaveBody(HttpRequest request)
    {
        if (request.ContentLength.HasValue && request.ContentLength.Value > 0)
            return true;

        return request.Headers.ContainsKey("Transfer-Encoding");
    }

    private void CopyRequestHeaders(HttpContext context, HttpRequestMessage requestMessage)
    {
        foreach (var header in context.Request.Headers)
        {
            if (string.Equals(header.Key, "Host", StringComparison.OrdinalIgnoreCase))
                continue;
            if (string.Equals(header.Key, "Cookie", StringComparison.OrdinalIgnoreCase))
                continue;
            if (HopByHopHeaders.Contains(header.Key))
                continue;
            if (!string.IsNullOrWhiteSpace(_route.RetryAllMethodsHeader)
                && string.Equals(header.Key, _route.RetryAllMethodsHeader, StringComparison.OrdinalIgnoreCase))
                continue;
            if (_route.StickySessionsEnabled
                && string.Equals(_route.StickySessionMode, "Cookie", StringComparison.OrdinalIgnoreCase)
                && string.Equals(header.Key, _route.StickySessionKeyName, StringComparison.OrdinalIgnoreCase))
                continue;
            if (ListContainsIgnoreCase(_route.RemoveHeaders, header.Key))
                continue;

            if (ContainsCrlf(header.Key))
                continue;

            var rawValues = header.Value.ToArray();
            bool hasCrlf = false;
            for (int i = 0; i < rawValues.Length; i++)
            {
                if (ContainsCrlf(rawValues[i]))
                {
                    hasCrlf = true;
                    break;
                }
            }

            string?[] safeValues;
            if (hasCrlf)
            {
                using var filtered = new BmwValueList<string?>(rawValues.Length);
                for (int i = 0; i < rawValues.Length; i++)
                {
                    if (!ContainsCrlf(rawValues[i]))
                        filtered.Add(rawValues[i]);
                }
                safeValues = filtered.ToArray();
            }
            else
            {
                safeValues = rawValues;
            }
            if (safeValues.Length == 0)
                continue;

            if (!requestMessage.Headers.TryAddWithoutValidation(header.Key, safeValues))
            {
                requestMessage.Content?.Headers.TryAddWithoutValidation(header.Key, safeValues);
            }
        }

        foreach (var header in _route.AddHeaders)
        {
            if (ContainsCrlf(header.Key) || ContainsCrlf(header.Value))
                continue;

            if (!requestMessage.Headers.TryAddWithoutValidation(header.Key, header.Value))
            {
                requestMessage.Content?.Headers.TryAddWithoutValidation(header.Key, header.Value);
            }
        }

        var filteredCookieHeader = BuildFilteredCookieHeader(context);
        if (!string.IsNullOrWhiteSpace(filteredCookieHeader))
        {
            requestMessage.Headers.TryAddWithoutValidation("Cookie", filteredCookieHeader);
        }

        var remoteIp = context.Connection.RemoteIpAddress?.ToString();
        if (!string.IsNullOrWhiteSpace(remoteIp))
        {
            requestMessage.Headers.TryAddWithoutValidation("X-Forwarded-For", remoteIp);
        }

        if (!string.IsNullOrWhiteSpace(context.Request.Scheme))
        {
            requestMessage.Headers.TryAddWithoutValidation("X-Forwarded-Proto", context.Request.Scheme);
        }

        if (context.Request.Host.HasValue)
        {
            requestMessage.Headers.TryAddWithoutValidation("X-Forwarded-Host", context.Request.Host.Value);
        }
    }

    private string? BuildFilteredCookieHeader(HttpContext context)
    {
        if (context.Request.Cookies == null || context.Request.Cookies.Count == 0)
            return null;

        var builder = new StringBuilder(256);
        foreach (var cookie in context.Request.Cookies)
        {
            if (string.Equals(cookie.Key, UserAuth.SessionCookieName, StringComparison.OrdinalIgnoreCase))
                continue;
            if (_route.StickySessionsEnabled
                && string.Equals(_route.StickySessionMode, "Cookie", StringComparison.OrdinalIgnoreCase)
                && string.Equals(cookie.Key, _route.StickySessionKeyName, StringComparison.OrdinalIgnoreCase))
                continue;

            if (builder.Length > 0)
                builder.Append("; ");

            builder.Append(cookie.Key);
            builder.Append('=');
            builder.Append(cookie.Value);
        }

        return builder.Length == 0 ? null : builder.ToString();
    }

    private static void CopyResponseHeaders(HttpContext context, HttpResponseMessage responseMessage)
    {
        foreach (var header in responseMessage.Headers)
        {
            if (HopByHopHeaders.Contains(header.Key))
                continue;

            if (!context.Response.Headers.TryAdd(header.Key, new StringValues(EnumerableToArray(header.Value))))
            {
                context.Response.Headers[header.Key] = new StringValues(EnumerableToArray(header.Value));
            }
        }

        foreach (var header in responseMessage.Content.Headers)
        {
            if (HopByHopHeaders.Contains(header.Key))
                continue;

            if (!context.Response.Headers.TryAdd(header.Key, new StringValues(EnumerableToArray(header.Value))))
            {
                context.Response.Headers[header.Key] = new StringValues(EnumerableToArray(header.Value));
            }
        }

        context.Response.Headers.Remove("transfer-encoding");
    }

    private void ApplyTraceId(HttpContext context, HttpRequestMessage requestMessage)
    {
        if (string.IsNullOrWhiteSpace(_route.TraceIdHeader))
            return;

        var traceId = context.TraceIdentifier;
        if (string.IsNullOrWhiteSpace(traceId))
        {
            traceId = Guid.NewGuid().ToString("N");
        }

        if (!requestMessage.Headers.Contains(_route.TraceIdHeader))
        {
            requestMessage.Headers.TryAddWithoutValidation(_route.TraceIdHeader, traceId);
        }

        if (!context.Response.Headers.ContainsKey(_route.TraceIdHeader))
        {
            context.Response.Headers.TryAdd(_route.TraceIdHeader, traceId);
        }
    }

    private void ApplyLeaseAffinityCookie(HttpRequestMessage requestMessage)
    {
        if (!_route.LeaseAffinityCookieEnabled || _clusterState == null)
            return;

        var instanceId = _clusterState.InstanceId;
        if (string.IsNullOrEmpty(instanceId))
            return;

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(instanceId));
        var affinityValue = Convert.ToHexStringLower(hash);
        var cookieName = string.IsNullOrWhiteSpace(_route.LeaseAffinityCookieName)
            ? "ARRAffinity"
            : _route.LeaseAffinityCookieName;

        // Append (or create) the Cookie header with the affinity cookie
        var existing = requestMessage.Headers.TryGetValues("Cookie", out var vals)
            ? string.Join("; ", vals)
            : null;
        var affinityCookie = $"{cookieName}={affinityValue}";
        var sameSiteCookie = $"{cookieName}SameSite={affinityValue}";
        var combined = string.IsNullOrWhiteSpace(existing)
            ? $"{affinityCookie}; {sameSiteCookie}"
            : $"{existing}; {affinityCookie}; {sameSiteCookie}";

        requestMessage.Headers.Remove("Cookie");
        requestMessage.Headers.TryAddWithoutValidation("Cookie", combined);
    }

    private static async Task<byte[]?> TryBufferRequestBodyAsync(HttpContext context, int maxBytes)
    {
        if (maxBytes <= 0)
            return null;

        if (context.Request.ContentLength.HasValue && context.Request.ContentLength.Value > maxBytes)
            return null;

        using var buffer = new MemoryStream(context.Request.ContentLength.HasValue
            ? (int)Math.Min(context.Request.ContentLength.Value, maxBytes)
            : 0);

        var temp = new byte[81920];
        int read;
        int total = 0;
        while ((read = await context.Request.Body.ReadAsync(temp, 0, temp.Length, context.RequestAborted)) > 0)
        {
            total += read;
            if (total > maxBytes)
            {
                return null;
            }

            buffer.Write(temp, 0, read);
        }

        return buffer.ToArray();
    }

    private static List<ProxyTargetState> BuildTargetStates(ProxyRouteConfig route)
    {
        var targets = new List<ProxyTargetState>();
        if (route.TargetConfigs.Count > 0)
        {
            foreach (var target in route.TargetConfigs)
            {
                if (Uri.TryCreate(target.Uri, UriKind.Absolute, out var uri))
                {
                    targets.Add(new ProxyTargetState(uri, target.Weight));
                }
            }
        }
        else
        {
            foreach (var target in route.Targets)
            {
                if (Uri.TryCreate(target, UriKind.Absolute, out var uri))
                {
                    targets.Add(new ProxyTargetState(uri, 1));
                }
            }
        }

        if (targets.Count == 0 && !string.IsNullOrWhiteSpace(route.TargetBaseUrl))
        {
            if (Uri.TryCreate(route.TargetBaseUrl, UriKind.Absolute, out var uri))
            {
                targets.Add(new ProxyTargetState(uri, 1));
            }
        }

        return targets;
    }

    private ProxyTargetState? SelectTargetState(HashSet<ProxyTargetState>? exclude, string? stickyKey)
    {
        if (_targets.Count == 0)
            return null;

        var now = DateTimeOffset.UtcNow;
        var available = new List<ProxyTargetState>();
        for (int i = 0; i < _targets.Count; i++)
        {
            if (!_targets[i].IsOffline(now))
                available.Add(_targets[i]);
        }
        if (exclude != null && exclude.Count > 0)
        {
            var filtered = new List<ProxyTargetState>();
            for (int i = 0; i < available.Count; i++)
            {
                if (!exclude.Contains(available[i]))
                    filtered.Add(available[i]);
            }
            available = filtered;
        }
        if (available.Count == 0)
            return null;

        if (_route.StickySessionsEnabled && !string.IsNullOrWhiteSpace(stickyKey))
        {
            var stickyTarget = SelectTargetByHash(available, stickyKey);
            if (stickyTarget != null)
                return stickyTarget;
        }

        if (string.Equals(_route.LoadBalance, "Failover", StringComparison.OrdinalIgnoreCase))
        {
            return available[0];
        }

        return SelectTargetByWeight(available);
    }

    private bool HasAvailableTargets(HashSet<ProxyTargetState> attempted)
    {
        var now = DateTimeOffset.UtcNow;
        for (int i = 0; i < _targets.Count; i++)
        {
            if (!_targets[i].IsOffline(now) && !attempted.Contains(_targets[i]))
                return true;
        }
        return false;
    }

    private ProxyTargetState? SelectTargetByWeight(List<ProxyTargetState> available)
    {
        int totalWeight = 0;
        for (int i = 0; i < available.Count; i++)
            totalWeight += available[i].Weight;
        if (totalWeight <= 0)
            return available[0];

        var index = Interlocked.Increment(ref _roundRobinIndex);
        var position = Math.Abs(index % totalWeight);
        foreach (var target in available)
        {
            position -= target.Weight;
            if (position < 0)
                return target;
        }

        return available[0];
    }

    private ProxyTargetState? SelectTargetByHash(List<ProxyTargetState> available, string key)
    {
        int totalWeight = 0;
        for (int i = 0; i < available.Count; i++)
            totalWeight += available[i].Weight;
        if (totalWeight <= 0)
            return available[0];

        var hash = Fnv1aHash(key);
        var position = (int)(hash % (uint)totalWeight);
        foreach (var target in available)
        {
            position -= target.Weight;
            if (position < 0)
                return target;
        }

        return available[0];
    }

    private string? GetStickyKey(HttpContext context, out bool setCookie)
    {
        setCookie = false;
        if (!_route.StickySessionsEnabled)
            return null;

        if (string.Equals(_route.StickySessionMode, "IpHash", StringComparison.OrdinalIgnoreCase))
        {
            return context.Connection.RemoteIpAddress?.ToString();
        }

        var keyName = _route.StickySessionKeyName;
        if (!string.IsNullOrWhiteSpace(keyName))
        {
            if (context.Request.Headers.TryGetValue(keyName, out var headerValue) && !StringValues.IsNullOrEmpty(headerValue))
                return headerValue.ToString();

            if (context.Request.Cookies.TryGetValue(keyName, out var cookieValue) && !string.IsNullOrWhiteSpace(cookieValue))
                return cookieValue;
        }

        var generated = Guid.NewGuid().ToString("N");
        setCookie = true;
        return generated;
    }

    private void SetStickyCookie(HttpContext context, string key)
    {
        var options = new CookieOptions
        {
            HttpOnly = true,
            Secure = context.Request.IsHttps,
            SameSite = SameSiteMode.Lax,
            Expires = DateTimeOffset.UtcNow.AddSeconds(Math.Max(1, _route.StickySessionTtlSeconds))
        };

        context.Response.Cookies.Append(_route.StickySessionKeyName, key, options);
    }

    private static uint Fnv1aHash(string input)
    {
        unchecked
        {
            const uint offset = 2166136261;
            const uint prime = 16777619;
            uint hash = offset;
            foreach (var c in input)
            {
                hash ^= c;
                hash *= prime;
            }
            return hash;
        }
    }

    public ProxyRouteStatus GetStatus()
    {
        var now = DateTimeOffset.UtcNow;
        var snapshots = new ProxyTargetStatus[_targets.Count];
        for (int i = 0; i < _targets.Count; i++)
            snapshots[i] = _targets[i].Snapshot(now);
        return new ProxyRouteStatus
        {
            Route = _route.Route,
            MatchMode = _route.MatchMode,
            LoadBalance = _route.LoadBalance,
            Targets = snapshots
        };
    }

    private async Task ApplyRetryDelayAsync(int attempt, CancellationToken cancellationToken)
    {
        var baseDelay = Math.Max(0, _route.RetryBaseDelayMs);
        var maxDelay = Math.Max(baseDelay, _route.RetryMaxDelayMs);

        var delay = Math.Min(maxDelay, baseDelay * (int)Math.Pow(2, Math.Max(0, attempt - 1)));
        if (_route.RetryUseJitter && delay > 0)
        {
            var jitter = Random.Shared.Next(0, delay + 1);
            delay = jitter;
        }

        if (delay > 0)
        {
            await Task.Delay(delay, cancellationToken);
        }
    }

    private static readonly char[] CrLfChars = ['\r', '\n'];

    private static bool ContainsCrlf(string? value) =>
        value != null && value.IndexOfAny(CrLfChars) >= 0;

    private void TrackResult(ProxyTargetState target, HttpStatusCode? statusCode, Exception? exception = null)
    {
        var isFailure = exception != null || (statusCode.HasValue && (int)statusCode.Value >= 500);
        if (!isFailure)
        {
            target.RecordSuccess(DateTimeOffset.UtcNow, _route.FailureWindowSeconds);
            return;
        }

        target.RecordFailure(DateTimeOffset.UtcNow, _route.FailureWindowSeconds);
        if (target.ShouldTrip(_route.FailurePercentageThreshold, _route.MinimumRequestsInWindow))
        {
            target.TakeOffline(DateTimeOffset.UtcNow, TimeSpan.FromSeconds(_route.OfflineSeconds));
            _logger.LogError($"Proxy target {target.BaseUri} taken offline due to failure rate.", exception ?? new Exception("Proxy failure rate exceeded."));
        }
    }

    private static bool ListContainsIgnoreCase(List<string> list, string value)
    {
        for (int i = 0; i < list.Count; i++)
        {
            if (string.Equals(list[i], value, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    private static string[] EnumerableToArray(IEnumerable<string> values)
    {
        // Use the collection count when available; fall back to 4 as a small-list default
        using var list = new BmwValueList<string>(values is ICollection<string> col ? col.Count : 4);
        foreach (var v in values)
            list.Add(v);
        return list.ToArray();
    }
}
