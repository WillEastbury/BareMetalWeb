using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Extension to wrap a test <see cref="HttpContext"/> into a <see cref="BmwContext"/>
/// for handlers that now accept <see cref="BmwContext"/>.
/// </summary>
internal static class BmwContextTestExtensions
{
    private static readonly NullBareWebHost _host = new();

    internal static BmwContext ToBmw(this HttpContext context)
        => BmwContext.CreateFrom(context, _host);

    internal static BmwContext ToBmw(this HttpContext context, IBareWebHost host)
        => BmwContext.CreateFrom(context, host);
}

/// <summary>
/// Minimal no-op <see cref="IBareWebHost"/> used only to satisfy
/// <see cref="BmwContext.CreateFrom"/> in unit tests.
/// </summary>
internal sealed class NullBareWebHost : IBareWebHost
{
    public static string[] appMetaDataKeys { get; set; } = Array.Empty<string>();

    public WebApplication app { get; set; } = null!;
    public IBufferedLogger BufferedLogger => null!;
    public IMetricsTracker Metrics { get; set; } = null!;
    public IClientRequestTracker ClientRequests => null!;
    public IHtmlRenderer HtmlRenderer => null!;
    public Dictionary<string, RouteHandlerData> routes { get; set; } = new();
    public string AppName { get; set; } = "Test";
    public string CompanyDescription { get; set; } = "";
    public string CopyrightYear { get; set; } = "2024";
    public string PrivacyPolicyUrl { get; set; } = "";
    public string[] AppMetaDataKeys { get; } = Array.Empty<string>();
    public string[] AppMetaDataValues { get; set; } = Array.Empty<string>();
    public List<IMenuOption> MenuOptionsList { get; set; } = new();
    public PageInfo NotFoundPageInfo => null!;
    public PageInfo ErrorPageInfo => null!;
    public CancellationTokenSource cts { get; } = new();
    public string[] CorsAllowedOrigins { get; set; } = Array.Empty<string>();
    public string[] CorsAllowedMethods { get; set; } = Array.Empty<string>();
    public string[] CorsAllowedHeaders { get; set; } = Array.Empty<string>();
    public StaticFileConfigOptions StaticFiles { get; set; } = new();
    public HttpsRedirectMode HttpsRedirectMode { get; set; }
    public bool TrustForwardedHeaders { get; set; }
    public bool HttpsEndpointAvailable { get; set; }
    public string? HttpsRedirectHost { get; set; }
    public int? HttpsRedirectPort { get; set; }
    public BmwConfig Configuration { get; set; } = BmwConfig.Load("/tmp");
    public string ContentRootPath { get; set; } = "/tmp";
    public bool ShowHostDiagnostics { get; set; }

    public ValueTask BuildAppInfoMenuOptionsAsync(BmwContext? context = null, CancellationToken cancellationToken = default)
        => ValueTask.CompletedTask;

    public void RegisterRoute(string path, RouteHandlerData routeHandler) { }
    public Task RenderForbidden(BmwContext context) => Task.CompletedTask;
    public Task RequestHandler(HttpContext context) => Task.CompletedTask;
    public Task WireUpRequestHandlingAndLoggerAsyncLifetime() => Task.CompletedTask;
}
