using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Core.Interfaces;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using BareMetalWeb.Host;

namespace BareMetalWeb.Core.Host;

public interface IBareWebHost
{
    static abstract string[] appMetaDataKeys { get; set; }
    WebApplication app { get; set; }
    IBufferedLogger BufferedLogger { get; }
    IMetricsTracker Metrics { get; }
    IClientRequestTracker ClientRequests { get; }
    IHtmlRenderer HtmlRenderer { get; }
    Dictionary<string, RouteHandlerData> routes { get; set; }
    string AppName { get; set; }
    string CompanyDescription { get; set; }
    string CopyrightYear { get; set; }
    string[] AppMetaDataKeys { get; }
    string[] AppMetaDataValues { get; set; }
    List<IMenuOption> MenuOptionsList { get; set; }
    PageInfo NotFoundPageInfo { get; }
    PageInfo ErrorPageInfo { get; }
    CancellationTokenSource cts { get; }
    string[] CorsAllowedOrigins { get; set; }
    string[] CorsAllowedMethods { get; set; }
    string[] CorsAllowedHeaders { get; set; }
    StaticFileConfigOptions StaticFiles { get; set; }
    HttpsRedirectMode HttpsRedirectMode { get; set; }
    bool TrustForwardedHeaders { get; set; }
    bool HttpsEndpointAvailable { get; set; }
    string? HttpsRedirectHost { get; set; }
    int? HttpsRedirectPort { get; set; }

    ValueTask BuildAppInfoMenuOptionsAsync(HttpContext? context = null, CancellationToken cancellationToken = default);
    void RegisterRoute(string path, RouteHandlerData routeHandler);
    Task RenderForbidden(HttpContext context);
    Task RequestHandler(HttpContext context);
    Task WireUpRequestHandlingAndLoggerAsyncLifetime();
}
