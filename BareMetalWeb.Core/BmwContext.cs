using System.Diagnostics;
using System.IO.Pipelines;
using System.Text;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Rendering;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;

namespace BareMetalWeb.Core;

/// <summary>
/// Lightweight request context built directly from Kestrel features.
/// No <see cref="HttpContext"/> allocation in the hot path — features are
/// resolved once in <see cref="CreateFromFeatures"/> and stored. Handlers
/// that still need the full ASP.NET API surface get a lazily-allocated
/// <see cref="DefaultHttpContext"/> via the <see cref="HttpContext"/> property.
/// </summary>
/// <remarks>
/// Pipeline path: socket → Kestrel → IHttpApplication → BmwContext → BMW router → PipeWriter
/// </remarks>
public sealed class BmwContext
{
    // ── Request data (populated once) ──────────────────────────────────
    public BmwRequest Request;

    // ── Pipelines ───────────────────────────────────────────────────────
    public PipeReader RequestBody { get; }
    public PipeWriter ResponseBody { get; }

    // ── Features (resolved once, never looked up again) ─────────────────
    private readonly IHttpRequestFeature _requestFeature;
    private readonly IHttpResponseFeature _responseFeature;
    private readonly IHttpResponseBodyFeature? _responseBodyFeature;
    private readonly IHttpConnectionFeature? _connectionFeature;
    private readonly IFeatureCollection _features;

    // ── Direct response accessors (hot-path, zero HttpContext) ──────────
    /// <summary>HTTP response status code.</summary>
    public int StatusCode { get => _responseFeature.StatusCode; set => _responseFeature.StatusCode = value; }

    /// <summary>Response headers — same IHeaderDictionary Kestrel uses internally.</summary>
    public IHeaderDictionary ResponseHeaders => _responseFeature.Headers;

    /// <summary>True once the first byte of the response body has been sent.</summary>
    public bool HasResponseStarted => _responseFeature.HasStarted;

    /// <summary>Response Content-Type header.</summary>
    public string? ContentType
    {
        get => ResponseHeaders.ContentType;
        set => ResponseHeaders.ContentType = value;
    }

    /// <summary>Response Content-Length header.</summary>
    public long? ContentLength
    {
        get => ResponseHeaders.ContentLength;
        set => ResponseHeaders.ContentLength = value;
    }

    // ── Direct request accessors (hot-path, zero HttpContext) ───────────
    /// <summary>Request headers — same IHeaderDictionary from the Kestrel request feature.</summary>
    public IHeaderDictionary RequestHeaders => _requestFeature.Headers;

    /// <summary>Request scheme (http or https).</summary>
    public string RequestScheme => _requestFeature.Scheme;

    /// <summary>HTTP protocol version string (e.g. "HTTP/1.1", "HTTP/2").</summary>
    public string RequestProtocol => _requestFeature.Protocol;

    /// <summary>True when the request arrived over HTTPS (or was forwarded as such).</summary>
    public bool IsHttps => string.Equals(RequestScheme, "https", StringComparison.OrdinalIgnoreCase);

    // ── Exposed features (for callers that need the raw interface) ──────
    public IFeatureCollection Features => _features;
    public IHttpResponseFeature ResponseFeature => _responseFeature;
    public IHttpConnectionFeature? ConnectionFeature => _connectionFeature;

    // ── BMW runtime state ───────────────────────────────────────────────
    public IBareWebHost App { get; }

    /// <summary>Page metadata for the current route (set by router dispatch).</summary>
    public PageMetaData? PageMetaData { get; set; }

    /// <summary>Page context for the current route (template values, loops, tables).</summary>
    public PageContext? PageContext { get; set; }

    /// <summary>Combined page info (computed from PageMetaData + PageContext).</summary>
    public PageInfo? PageInfo
    {
        get => PageMetaData != null && PageContext != null
            ? new PageInfo(PageMetaData, PageContext) : null;
        set
        {
            if (value != null) { PageMetaData = value.PageMetaData; PageContext = value.PageContext; }
            else { PageMetaData = null; PageContext = null; }
        }
    }

    /// <summary>Pre-compiled render plans for this route (set by jump table dispatch). Null = use parsing path.</summary>
    public RouteRenderPlans? CompiledPlans { get; set; }

    /// <summary>Unique correlation ID for this request (X-Trace-ID header or Kestrel trace identifier).</summary>
    public string CorrelationId { get; }
    private readonly long _requestParsedTimestamp;
    private long _firstByteWriteTimestamp;
    private long _firstFlushStartTimestamp;
    private int _firstWriteObserved;
    private int _firstFlushStartObserved;
    private int _firstFlushLogged;

    /// <summary>Route parameters extracted by the jump-table or pattern router.</summary>
    public Dictionary<string, string>? RouteParameters { get; set; }

    // ── Prefix-router fast-path fields (zero-allocation param passing) ──
    /// <summary>Entity type slug set by the prefix router for /api/{type} routes.</summary>
    public string? EntitySlug;
    /// <summary>Entity ID string set by the prefix router for /api/{type}/{id} routes.</summary>
    public string? EntityId;
    /// <summary>Extra route segment value (field name, command name, etc.).</summary>
    public string? RouteExtra;
    /// <summary>Key name for <see cref="RouteExtra"/> (e.g. "field", "command").</summary>
    public string? RouteExtraKey;
    /// <summary>Compiled entity ordinal from RuntimeSnapshot (-1 = unresolved).</summary>
    public int EntityOrdinal = -1;

    // ── Per-request storage (replaces HttpContext.Items for pipeline data) ──
    /// <summary>CSP nonce for the current request (generated on first access).</summary>
    public string? CspNonce { get; set; }

    /// <summary>Source IP extracted once from the connection feature.</summary>
    public string SourceIp { get; }

    /// <summary>Cancellation token signalled when the client disconnects.</summary>
    public CancellationToken RequestAborted { get; }

    // ── Lazy HttpContext bridge ─────────────────────────────────────────
    // Only allocated when handler code accesses the full ASP.NET API surface
    // (cookies, form reading, DI, etc.). Pipeline code uses direct accessors.
    private HttpContext? _httpContext;

    /// <summary>
    /// Lazily-allocated HttpContext for handlers that need the full ASP.NET API.
    /// Pipeline code should use direct accessors (StatusCode, ResponseHeaders, etc.) instead.
    /// </summary>
    public HttpContext HttpContext => _httpContext ??= new DefaultHttpContext(_features);

    /// <summary>Bridge: HTTP response via lazy HttpContext (prefer direct accessors).</summary>
    public HttpResponse Response => HttpContext.Response;

    /// <summary>Bridge: HTTP request via lazy HttpContext (prefer RequestHeaders).</summary>
    public HttpRequest HttpRequest => HttpContext.Request;

    /// <summary>Bridge: connection info via lazy HttpContext.</summary>
    public ConnectionInfo Connection => HttpContext.Connection;

    /// <summary>Bridge: DI container via lazy HttpContext.</summary>
    public IServiceProvider? RequestServices => HttpContext.RequestServices;

    // ── Constructor ─────────────────────────────────────────────────────

    private BmwContext(
        IFeatureCollection features,
        IHttpRequestFeature requestFeature,
        IHttpResponseFeature responseFeature,
        IHttpResponseBodyFeature? responseBodyFeature,
        IHttpConnectionFeature? connectionFeature,
        BmwRequest request,
        PipeReader requestBody,
        PipeWriter responseBody,
        IBareWebHost app,
        string sourceIp,
        string correlationId,
        long requestParsedTimestamp,
        CancellationToken requestAborted)
    {
        _features = features;
        _requestFeature = requestFeature;
        _responseFeature = responseFeature;
        _responseBodyFeature = responseBodyFeature;
        _connectionFeature = connectionFeature;
        Request = request;
        RequestBody = requestBody;
        ResponseBody = responseBody;
        App = app;
        SourceIp = sourceIp;
        CorrelationId = correlationId;
        _requestParsedTimestamp = requestParsedTimestamp;
        RequestAborted = requestAborted;
    }

    // ── Clone helpers ───────────────────────────────────────────────────

    /// <summary>
    /// Returns a shallow clone of this context with a different <see cref="ResponseBody"/> writer.
    /// Used by the binary WebSocket transport to redirect each handler's output into a
    /// per-frame capture buffer so it can be sent back via <c>webSocket.SendAsync</c>.
    /// All other state (request, session, features) is shared with the original.
    /// </summary>
    public BmwContext CloneWithResponseBody(PipeWriter responseBody)
        => new(_features, _requestFeature, _responseFeature, _responseBodyFeature,
               _connectionFeature, Request, RequestBody, responseBody, App,
               SourceIp, CorrelationId, _requestParsedTimestamp, RequestAborted);

    // ── Factory methods ─────────────────────────────────────────────────

    /// <summary>
    /// Creates a <see cref="BmwContext"/> directly from Kestrel's feature collection.
    /// Zero HttpContext allocation — features are resolved once and stored.
    /// </summary>
    public static BmwContext CreateFromFeatures(IFeatureCollection features, IBareWebHost app)
    {
        var requestFeature = features.Get<IHttpRequestFeature>()!;
        var responseFeature = features.Get<IHttpResponseFeature>()!;
        var responseBodyFeature = features.Get<IHttpResponseBodyFeature>();
        var connectionFeature = features.Get<IHttpConnectionFeature>();

        var request = new BmwRequest(
            requestFeature.Method,
            requestFeature.Path,
            requestFeature.QueryString ?? string.Empty);

        var sourceIp = connectionFeature?.RemoteIpAddress?.ToString() ?? "unknown";

        var correlationId = (requestFeature.Headers.TryGetValue("X-Trace-ID", out var traceHeader) && traceHeader.Count > 0)
            ? traceHeader[0]!
            : features.Get<IHttpRequestIdentifierFeature>()?.TraceIdentifier
              ?? Guid.NewGuid().ToString("N")[..16];

        var requestBody = features.Get<IRequestBodyPipeFeature>()?.Reader
            ?? PipeReader.Create(requestFeature.Body);

        var responseBody = responseBodyFeature?.Writer
            ?? PipeWriter.Create(Stream.Null);

        var requestAborted = features.Get<IHttpRequestLifetimeFeature>()?.RequestAborted
            ?? CancellationToken.None;
        var requestParsedTimestamp = Stopwatch.GetTimestamp();

        return new BmwContext(
            features,
            requestFeature,
            responseFeature,
            responseBodyFeature,
            connectionFeature,
            request,
            requestBody,
            responseBody,
            app,
            sourceIp,
            correlationId,
            requestParsedTimestamp,
            requestAborted);
    }

    /// <summary>
    /// Migration bridge: creates from an existing <see cref="HttpContext"/>.
    /// Pre-sets the lazy HttpContext so no additional allocation occurs.
    /// </summary>
    public static BmwContext CreateFrom(HttpContext httpContext, IBareWebHost app)
    {
        var ctx = CreateFromFeatures(httpContext.Features, app);
        ctx._httpContext = httpContext;
        return ctx;
    }

    // ── Response helpers (zero-allocation hot-path writes) ──────────────

    /// <summary>
    /// Writes a UTF-8 string directly to the PipeWriter response body.
    /// Zero intermediate allocation — encodes directly into PipeWriter's buffer.
    /// </summary>
    public async ValueTask WriteResponseAsync(string text, CancellationToken ct = default)
    {
        var maxByteCount = Encoding.UTF8.GetMaxByteCount(text.Length);
        var memory = ResponseBody.GetMemory(maxByteCount);
        int written = Encoding.UTF8.GetBytes(text, memory.Span);
        MarkFirstByteWrite();
        ResponseBody.Advance(written);
        MarkFirstFlushStart();
        await ResponseBody.FlushAsync(ct).ConfigureAwait(false);
        TryLogFirstWriteLatency();
    }

    /// <summary>Writes raw bytes directly to the response body PipeWriter.</summary>
    public async ValueTask<FlushResult> WriteResponseAsync(ReadOnlyMemory<byte> data, CancellationToken ct = default)
    {
        MarkFirstByteWrite();
        MarkFirstFlushStart();
        var result = await ResponseBody.WriteAsync(data, ct).ConfigureAwait(false);
        TryLogFirstWriteLatency();
        return result;
    }

    private void MarkFirstByteWrite()
    {
        if (Interlocked.CompareExchange(ref _firstWriteObserved, 1, 0) == 0)
            _firstByteWriteTimestamp = Stopwatch.GetTimestamp();
    }

    private void MarkFirstFlushStart()
    {
        if (Volatile.Read(ref _firstWriteObserved) == 0)
            return;

        if (Interlocked.CompareExchange(ref _firstFlushStartObserved, 1, 0) == 0)
            _firstFlushStartTimestamp = Stopwatch.GetTimestamp();
    }

    private void TryLogFirstWriteLatency()
    {
        if (Volatile.Read(ref _firstWriteObserved) == 0)
            return;

        if (Interlocked.CompareExchange(ref _firstFlushLogged, 1, 0) != 0)
            return;

        var now = Stopwatch.GetTimestamp();
        var parseToFirstMs = (_firstByteWriteTimestamp - _requestParsedTimestamp) * 1000d / Stopwatch.Frequency;
        var flushStartTimestamp = _firstFlushStartTimestamp != 0 ? _firstFlushStartTimestamp : _firstByteWriteTimestamp;
        var firstToFlushStartMs = (flushStartTimestamp - _firstByteWriteTimestamp) * 1000d / Stopwatch.Frequency;
        var flushAwaitMs = (now - flushStartTimestamp) * 1000d / Stopwatch.Frequency;
        var firstToFlushMs = (now - _firstByteWriteTimestamp) * 1000d / Stopwatch.Frequency;
        ResponseTimingMetrics.Record(parseToFirstMs, firstToFlushStartMs, flushAwaitMs, firstToFlushMs);

        if (!App.BufferedLogger.IsEnabled(BmwLogLevel.Debug))
            return;

        App.BufferedLogger.Log(
            BmwLogLevel.Debug,
            $"response_timing|parse_to_first_ms={parseToFirstMs:F3}|first_to_flush_start_ms={firstToFlushStartMs:F3}|flush_await_ms={flushAwaitMs:F3}|first_to_flush_ms={firstToFlushMs:F3}",
            CorrelationId,
            new LogFields
            {
                Method = Request.Method,
                Path = Request.Path,
                SourceIp = SourceIp,
                Detail = $"parseToFirstMs={parseToFirstMs:F3};firstToFlushStartMs={firstToFlushStartMs:F3};flushAwaitMs={flushAwaitMs:F3};firstToFlushMs={firstToFlushMs:F3}"
            });
    }

    /// <summary>Sets a redirect response.</summary>
    public void Redirect(string url, int statusCode = StatusCodes.Status302Found)
    {
        StatusCode = statusCode;
        ResponseHeaders.Location = url;
    }

    /// <summary>Resets response state (status code + headers). Only valid before headers are sent.</summary>
    public void ClearResponse()
    {
        if (!HasResponseStarted)
        {
            _responseFeature.StatusCode = 200;
            _responseFeature.ReasonPhrase = null;
            _responseFeature.Headers.Clear();
        }
    }

    /// <summary>Aborts the underlying connection.</summary>
    public void Abort()
    {
        _features.Get<IHttpRequestLifetimeFeature>()?.Abort();
    }
}
