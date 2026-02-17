using System.Reflection;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Interfaces;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace BareMetalWeb.Host;

/// <summary>
/// Single entry point for wiring up the full BareMetalWeb stack.
/// Usage:
///   var app = WebApplication.Create(args);
///   await app.UseBareMetalWeb();
///   app.Run();
/// </summary>
public static class BareMetalWebExtensions
{
    /// <summary>
    /// Configures and starts the full BareMetalWeb stack: data store, rendering,
    /// authentication, routing, static files, CORS, HTTPS, and proxy support.
    /// Optionally pass <paramref name="configureRoutes"/> to register additional routes.
    /// </summary>
    public static async Task UseBareMetalWeb(
        this WebApplication app,
        Action<BareMetalWebServer, IRouteHandlers, IPageInfoFactory, IHtmlTemplate>? configureRoutes = null)
    {
        // Logger & data root
        IBufferedLogger logger = ProgramSetup.CreateLogger(app);
        logger.LogInfo("Starting BareMetalWeb server...");

        var contentRoot = app.Environment.ContentRootPath;
        var dataRoot = app.Configuration.GetValue("Data:Root", Path.Combine(contentRoot, "Data"));
        ProgramSetup.ResetDataIfRequested(app, dataRoot, logger);
        CookieProtection.ConfigureKeyRoot(dataRoot);

        // Data store
        ISchemaAwareObjectSerializer serializer = BinaryObjectSerializer.CreateDefault(dataRoot);
        IDataQueryEvaluator queryEvaluator = new DataQueryEvaluator();
        try { _ = Assembly.Load("BareMetalWeb.UserClasses"); } catch { }
        DataEntityRegistry.RegisterAllEntities();
        IDataObjectStore dataStore = ProgramSetup.CreateDataStore(app, serializer, queryEvaluator, logger);

        // Permissions
        var entityPermissions = DataScaffold.Entities
            .SelectMany(e => (e.Permissions ?? string.Empty)
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var rootPermissionSet = new HashSet<string>(entityPermissions, StringComparer.OrdinalIgnoreCase)
        {
            "admin",
            "monitoring"
        };
        await ProgramSetup.EnsureRootPermissionsAsync(logger, rootPermissionSet.ToArray());

        // Rendering
        IHtmlFragmentStore fragmentStore = new HtmlFragmentStore();
        IHtmlFragmentRenderer fragmentRenderer = new HtmlFragmentRenderer(fragmentStore);
        IHtmlRenderer htmlRenderer = new HtmlRenderer(fragmentRenderer);
        ITemplateStore templateStore = new TemplateStore();
        IPageInfoFactory pageInfoFactory = new PageInfoFactory();
        IMetricsTracker metricsTracker = new MetricsTracker();
        IClientRequestTracker throttling = ProgramSetup.CreateClientRequestTracker(app, logger);

        // Route handlers
        bool allowAccountCreation = app.Configuration.GetValue("Auth:AllowAccountCreation", false);
        IRouteHandlers routeHandlers = new RouteHandlers(htmlRenderer, templateStore, allowAccountCreation, dataRoot);
        IHtmlTemplate mainTemplate = templateStore.Get("Index");
        CancellationTokenSource cts = new CancellationTokenSource();

        // App info
        BareMetalWebServer appInfo = ProgramSetup.CreateAppInfo(
            app, logger, htmlRenderer, pageInfoFactory, mainTemplate, metricsTracker, throttling, cts);

        // Infrastructure configuration
        ProgramSetup.ConfigureStaticFiles(app, appInfo);
        ProgramSetup.ConfigureCors(app, appInfo);
        ProgramSetup.ConfigureHttps(app, appInfo);
        ProgramSetup.ConfigureProxyRoutes(app, appInfo, logger, pageInfoFactory);

        // Built-in routes
        appInfo.RegisterStaticRoutes(routeHandlers, pageInfoFactory, mainTemplate);
        appInfo.RegisterAuthRoutes(routeHandlers, pageInfoFactory, mainTemplate, allowAccountCreation);
        appInfo.RegisterMonitoringRoutes(routeHandlers, pageInfoFactory, mainTemplate);
        appInfo.RegisterAdminRoutes(routeHandlers, pageInfoFactory, mainTemplate);
        appInfo.RegisterDataRoutes(routeHandlers, pageInfoFactory, mainTemplate);
        appInfo.RegisterApiRoutes(routeHandlers, pageInfoFactory);

        // Custom routes from caller
        configureRoutes?.Invoke(appInfo, routeHandlers, pageInfoFactory, mainTemplate);

        // Finalise
        await appInfo.BuildAppInfoMenuOptionsAsync();
        await appInfo.WireUpRequestHandlingAndLoggerAsyncLifetime();

        app.Lifetime.ApplicationStarted.Register(() =>
        {
            var addresses = app.Services.GetService(typeof(IServer)) is IServer server
                ? server.Features.Get<IServerAddressesFeature>()?.Addresses
                : null;
            var list = addresses is null || addresses.Count == 0
                ? (app.Urls ?? Array.Empty<string>())
                : addresses;
            var display = list.Any() ? string.Join(", ", list) : "unknown";
            logger.LogInfo($"BareMetalWeb server is ready - listening for requests on {display}");
            Console.WriteLine($"BareMetalWeb server is ready - listening for requests on {display}");

            var httpsConfig = $"HTTPS redirect settings: mode={appInfo.HttpsRedirectMode}, trustForwardedHeaders={appInfo.TrustForwardedHeaders}, redirectHost={(string.IsNullOrWhiteSpace(appInfo.HttpsRedirectHost) ? "(auto)" : appInfo.HttpsRedirectHost)}, redirectPort={(appInfo.HttpsRedirectPort.HasValue ? appInfo.HttpsRedirectPort.Value.ToString() : "(auto)")}";
            logger.LogInfo(httpsConfig);
            Console.WriteLine(httpsConfig);

            var httpsAddress = list.FirstOrDefault(a => a.StartsWith("https://", StringComparison.OrdinalIgnoreCase));
            appInfo.HttpsEndpointAvailable = !string.IsNullOrWhiteSpace(httpsAddress);
            if (appInfo.HttpsEndpointAvailable && Uri.TryCreate(httpsAddress, UriKind.Absolute, out var httpsUri))
            {
                if (string.IsNullOrWhiteSpace(appInfo.HttpsRedirectHost))
                    appInfo.HttpsRedirectHost = httpsUri.Host;
                if (!appInfo.HttpsRedirectPort.HasValue || appInfo.HttpsRedirectPort.Value <= 0)
                    appInfo.HttpsRedirectPort = httpsUri.IsDefaultPort ? 443 : httpsUri.Port;
            }

            if (!appInfo.HttpsEndpointAvailable)
            {
                var warn = "HTTPS endpoint not configured. Configure HTTPS (ASPNETCORE_URLS / Kestrel) to expose an https:// address.";
                logger.LogInfo(warn);
                Console.WriteLine(warn);
            }
        });
    }
}
