using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Host;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Core.Host;

public interface IBareWebHost
{
    static abstract string[] appMetaDataKeys { get; set; }
    BmwConfig Configuration { get; }
    string ContentRootPath { get; }
    IBufferedLogger BufferedLogger { get; }
    IMetricsTracker Metrics { get; }
    IClientRequestTracker ClientRequests { get; }
    IHtmlRenderer HtmlRenderer { get; }
    Dictionary<string, RouteHandlerData> routes { get; set; }
    string AppName { get; set; }
    string CompanyDescription { get; set; }
    string CopyrightYear { get; set; }
    string PrivacyPolicyUrl { get; set; }
    string[] AppMetaDataKeys { get; }
    string[] AppMetaDataValues { get; set; }
    List<IMenuOption> MenuOptionsList { get; set; }
    PageInfo NotFoundPageInfo { get; }
    PageInfo ErrorPageInfo { get; }
    CancellationTokenSource cts { get; }
    bool ShowHostDiagnostics { get; }
    string[] CorsAllowedOrigins { get; set; }
    string[] CorsAllowedMethods { get; set; }
    string[] CorsAllowedHeaders { get; set; }
    StaticFileConfigOptions StaticFiles { get; set; }
    HttpsRedirectMode HttpsRedirectMode { get; set; }
    bool TrustForwardedHeaders { get; set; }
    bool HttpsEndpointAvailable { get; set; }
    string? HttpsRedirectHost { get; set; }
    int? HttpsRedirectPort { get; set; }

    ValueTask BuildAppInfoMenuOptionsAsync(BmwContext? context = null, CancellationToken cancellationToken = default);
    void RegisterRoute(string path, RouteHandlerData routeHandler);
    Task RenderForbidden(BmwContext context);
    Task RequestHandler(BmwContext context);
    Task WireUpRequestHandlingAndLoggerAsyncLifetime();
}
