using System.Reflection;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Interfaces;
using BareMetalWeb.Runtime;
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
        DataEntityRegistry.RegisterVirtualEntitiesFromFile(
            Path.Combine(contentRoot, "virtualEntities.json"),
            dataRoot);
        IDataObjectStore dataStore = ProgramSetup.CreateDataStore(app, serializer, queryEvaluator, logger);

        // Configure high-cardinality lookup threshold
        DataScaffold.LargeListThreshold = app.Configuration.GetValue("LookupSearch:LargeListThreshold", 20);

        // Runtime entity registry — load persisted EntityDefinitions from storage and compile
        await RuntimeEntityRegistry.BuildAsync(
            dataStore,
            new RuntimeEntityCompiler(),
            dataRoot,
            msg => logger.LogInfo($"[RuntimeEntityRegistry] {msg}")).ConfigureAwait(false);

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
        AuditService auditService = new AuditService(DataStoreProvider.Current, logger);
        var settingDefaults = new (string SettingId, string Value, string Description)[]
        {
            (WellKnownSettings.AppName,      app.Configuration.GetValue("AppInfo:Name",      "BareMetalWeb"),       "Application display name"),
            (WellKnownSettings.AppCompany,   app.Configuration.GetValue("AppInfo:Company",   "BareMetalWeb Inc."),  "Company name shown in the header and footer"),
            (WellKnownSettings.AppCopyright, app.Configuration.GetValue("AppInfo:Copyright", "2026"),              "Copyright year or statement shown in the footer"),

            // Kestrel / transport
            (WellKnownSettings.KestrelHttp2Enabled,                 app.Configuration.GetValue("Kestrel:Http2Enabled", true).ToString(),        "Enable HTTP/2 protocol support"),
            (WellKnownSettings.KestrelHttp3Enabled,                 app.Configuration.GetValue("Kestrel:Http3Enabled", false).ToString(),       "Enable HTTP/3 (QUIC) protocol support"),
            (WellKnownSettings.KestrelMaxStreamsPerConnection,      app.Configuration.GetValue("Kestrel:MaxStreamsPerConnection", 100).ToString(), "Max concurrent HTTP/2 streams per connection"),
            (WellKnownSettings.KestrelInitialConnectionWindowSize,  app.Configuration.GetValue("Kestrel:InitialConnectionWindowSize", 131072).ToString(), "HTTP/2 initial connection-level flow-control window (bytes)"),
            (WellKnownSettings.KestrelInitialStreamWindowSize,      app.Configuration.GetValue("Kestrel:InitialStreamWindowSize", 98304).ToString(), "HTTP/2 initial per-stream flow-control window (bytes)"),

            // Thread pool
            (WellKnownSettings.ThreadPoolMinWorkerThreads, app.Configuration.GetValue("ThreadPool:MinWorkerThreads", 0).ToString(), "Minimum worker threads (0 = runtime default)"),
            (WellKnownSettings.ThreadPoolMinIOThreads,     app.Configuration.GetValue("ThreadPool:MinIOThreads", 0).ToString(),     "Minimum I/O completion threads (0 = runtime default)"),

            // GC
            (WellKnownSettings.GCServerMode, app.Configuration.GetValue("GC:ServerMode", true).ToString(), "Enable server GC mode (true/false)"),

            // Admin
            (WellKnownSettings.AllowWipeData, app.Configuration.GetValue("Admin:AllowWipeData", string.Empty), "Secret token required to trigger wipe-all-data. Leave empty to disable the endpoint."),
        };
        // Seed any missing settings and promote empty values when the config provides a non-empty default.
        // This runs at every startup so that changes to appsettings.json are picked up without
        // requiring a manual edit in the admin UI.
        await SettingsService.EnsureDefaultsAsync(DataStoreProvider.Current, settingDefaults, "system").ConfigureAwait(false);

        IRouteHandlers routeHandlers = new RouteHandlers(htmlRenderer, templateStore, allowAccountCreation, dataRoot, auditService, settingDefaults);
        IHtmlTemplate mainTemplate = templateStore.Get("Index");
        CancellationTokenSource cts = new CancellationTokenSource();

        // App info
        BareMetalWebServer appInfo = ProgramSetup.CreateAppInfo(
            app, logger, htmlRenderer, pageInfoFactory, mainTemplate, metricsTracker, throttling, cts);

        // Infrastructure configuration
        ProgramSetup.ConfigureStaticFiles(app, appInfo);

        // Build JS bundle from static JS files (runtime bundler - no build-time changes needed)
        JsBundleService.BuildBundle(Path.Combine(appInfo.StaticFiles.RootPathFull, "js"));

        ProgramSetup.ConfigureCors(app, appInfo);
        ProgramSetup.ConfigureHttps(app, appInfo);
        ProgramSetup.ConfigureProxyRoutes(app, appInfo, logger, pageInfoFactory);

        // Built-in routes
        appInfo.RegisterStaticRoutes(routeHandlers, pageInfoFactory, mainTemplate);
        appInfo.RegisterAuthRoutes(routeHandlers, pageInfoFactory, mainTemplate, allowAccountCreation);
        appInfo.RegisterMonitoringRoutes(routeHandlers, pageInfoFactory, mainTemplate);
        appInfo.RegisterAdminRoutes(routeHandlers, pageInfoFactory, mainTemplate);
        appInfo.RegisterDataRoutes(routeHandlers, pageInfoFactory, mainTemplate);
        appInfo.RegisterEntityMetadataRoute(pageInfoFactory);  // must be before RegisterApiRoutes
        appInfo.RegisterRuntimeApiRoutes(pageInfoFactory);       // /meta/entity/{name}, POST /query, POST /intent
        appInfo.RegisterLookupApiRoutes(pageInfoFactory);       // must be before RegisterApiRoutes
        appInfo.RegisterApiRoutes(routeHandlers, pageInfoFactory);
        appInfo.RegisterVNextRoutes(pageInfoFactory, templateStore);
        appInfo.RegisterReportRoutes(pageInfoFactory);
        appInfo.RegisterMcpRoutes(pageInfoFactory);

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
            logger.LogInfo($"BareMetalWeb server is ready — PID {Environment.ProcessId} — listening for requests on {display}");
            Console.WriteLine($"BareMetalWeb server is ready — PID {Environment.ProcessId} — listening for requests on {display}");

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
