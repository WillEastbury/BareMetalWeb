using System.IO.Pipelines;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Rendering;

namespace BareMetalWeb.Core;

/// <summary>
/// Lightweight request context that wraps only the Kestrel features BMW needs.
/// Created once per request in the pipeline entry point; avoids repeated
/// IFeatureCollection lookups and HttpContext.Items dictionary access in handlers.
/// </summary>
/// <remarks>
/// During migration, <see cref="HttpContext"/> remains available so existing
/// handlers continue to work unchanged. New handlers should prefer the
/// strongly-typed fields on this struct.
/// </remarks>
public sealed class BmwContext
{
    // ── Request data (populated once in CreateFrom) ─────────────────────
    public BmwRequest Request;

    // ── Pipelines ───────────────────────────────────────────────────────
    public PipeReader RequestBody { get; }
    public PipeWriter ResponseBody { get; }

    // ── Features resolved once ──────────────────────────────────────────
    public IHttpResponseFeature ResponseFeature { get; }
    public IHttpConnectionFeature? ConnectionFeature { get; }

    // ── BMW runtime state ───────────────────────────────────────────────
    public IBareWebHost App { get; }
    public PageInfo? PageInfo { get; set; }

    /// <summary>Route parameters extracted by the jump-table or pattern router.</summary>
    public Dictionary<string, string>? RouteParameters { get; set; }

    // ── Migration bridge ────────────────────────────────────────────────
    /// <summary>
    /// The underlying ASP.NET HttpContext. Available during migration so
    /// existing handlers can still access the full API surface. New code
    /// should use the strongly-typed fields instead.
    /// </summary>
    public HttpContext HttpContext { get; }

    /// <summary>Source IP extracted once from the connection feature.</summary>
    public string SourceIp { get; }

    /// <summary>Cancellation token from the underlying connection.</summary>
    public CancellationToken RequestAborted => HttpContext.RequestAborted;

    private BmwContext(
        HttpContext httpContext,
        BmwRequest request,
        PipeReader requestBody,
        PipeWriter responseBody,
        IHttpResponseFeature responseFeature,
        IHttpConnectionFeature? connectionFeature,
        IBareWebHost app,
        string sourceIp)
    {
        HttpContext = httpContext;
        Request = request;
        RequestBody = requestBody;
        ResponseBody = responseBody;
        ResponseFeature = responseFeature;
        ConnectionFeature = connectionFeature;
        App = app;
        SourceIp = sourceIp;
    }

    /// <summary>
    /// Creates a <see cref="BmwContext"/> from an <see cref="HttpContext"/>,
    /// resolving all required features exactly once.
    /// </summary>
    public static BmwContext CreateFrom(HttpContext httpContext, IBareWebHost app)
    {
        var features = httpContext.Features;
        var responseFeature = features.Get<IHttpResponseFeature>()!;
        var connectionFeature = features.Get<IHttpConnectionFeature>();
        var responseBodyFeature = features.Get<IHttpResponseBodyFeature>();

        var request = new BmwRequest(
            httpContext.Request.Method,
            httpContext.Request.Path.Value ?? "/",
            httpContext.Request.QueryString.Value ?? string.Empty);

        var sourceIp = connectionFeature?.RemoteIpAddress?.ToString() ?? "unknown";

        return new BmwContext(
            httpContext,
            request,
            httpContext.Request.BodyReader,
            responseBodyFeature?.Writer ?? httpContext.Response.BodyWriter,
            responseFeature,
            connectionFeature,
            app,
            sourceIp);
    }

    /// <summary>
    /// Creates a <see cref="BmwContext"/> directly from Kestrel's
    /// <see cref="IFeatureCollection"/> — used by <c>BmwApplication</c>
    /// when running without the ASP.NET middleware pipeline.
    /// A <see cref="DefaultHttpContext"/> is created as a migration bridge.
    /// </summary>
    public static BmwContext CreateFromFeatures(IFeatureCollection features, IBareWebHost app)
    {
        var httpContext = new DefaultHttpContext(features);

        var responseFeature = features.Get<IHttpResponseFeature>()!;
        var connectionFeature = features.Get<IHttpConnectionFeature>();
        var responseBodyFeature = features.Get<IHttpResponseBodyFeature>();
        var requestFeature = features.Get<IHttpRequestFeature>()!;

        var request = new BmwRequest(
            requestFeature.Method,
            requestFeature.Path,
            requestFeature.QueryString ?? string.Empty);

        var sourceIp = connectionFeature?.RemoteIpAddress?.ToString() ?? "unknown";

        return new BmwContext(
            httpContext,
            request,
            httpContext.Request.BodyReader,
            responseBodyFeature?.Writer ?? httpContext.Response.BodyWriter,
            responseFeature,
            connectionFeature,
            app,
            sourceIp);
    }
}
