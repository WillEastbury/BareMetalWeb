using System.Reflection;
using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Host;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Interfaces;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

// Setup 
WebApplication app = WebApplication.Create();
IBufferedLogger logger = ProgramSetup.CreateLogger(app);
logger.LogInfo("Starting BareMetalWeb server...");

var contentRoot = app.Environment.ContentRootPath;
var dataRoot = app.Configuration.GetValue("Data:Root", Path.Combine(contentRoot, "Data"));
ProgramSetup.ResetDataIfRequested(app, dataRoot, logger);
CookieProtection.ConfigureKeyRoot(dataRoot);

ISchemaAwareObjectSerializer serializer = BinaryObjectSerializer.CreateDefault(dataRoot);
IDataQueryEvaluator queryEvaluator = new DataQueryEvaluator();
try
{
    _ = Assembly.Load("BareMetalWeb.UserClasses");
}
catch
{
    // Optional library; ignore if not present.
}
DataEntityRegistry.RegisterAllEntities();
IDataObjectStore dataStore = ProgramSetup.CreateDataStore(app, serializer, queryEvaluator, logger);
var entityPermissions = DataScaffold.Entities
    .SelectMany(entity => (entity.Permissions ?? string.Empty)
        .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
    .Distinct(StringComparer.OrdinalIgnoreCase)
    .ToArray();
    
var rootPermissionSet = new HashSet<string>(entityPermissions, StringComparer.OrdinalIgnoreCase)
{
    "admin",
    "monitoring"
};

ProgramSetup.EnsureRootPermissions(logger, rootPermissionSet.ToArray());

IHtmlFragmentStore fragmentStore = new HtmlFragmentStore();
IHtmlFragmentRenderer fragmentRenderer = new HtmlFragmentRenderer(fragmentStore);
IHtmlRenderer htmlRenderer = new HtmlRenderer(fragmentRenderer);
ITemplateStore templateStore = new TemplateStore();
IPageInfoFactory pageInfoFactory = new PageInfoFactory();
IMetricsTracker metricsTracker = new MetricsTracker();
IClientRequestTracker throttling = ProgramSetup.CreateClientRequestTracker(app, logger);

bool allowAccountCreation = app.Configuration.GetValue("Auth:AllowAccountCreation", false);
IRouteHandlers routeHandlers = new RouteHandlers(htmlRenderer, templateStore, allowAccountCreation, dataRoot);
IHtmlTemplate mainTemplate = templateStore.Get("Index");
IHtmlTemplate blankTemplate = templateStore.Get("Blank");
CancellationTokenSource cts = new CancellationTokenSource();

BareMetalWebServer appInfo = ProgramSetup.CreateAppInfo(app, logger, htmlRenderer, pageInfoFactory, mainTemplate, metricsTracker, throttling, cts);
ProgramSetup.ConfigureStaticFiles(app, appInfo);
ProgramSetup.ConfigureCors(app, appInfo);
ProgramSetup.ConfigureHttps(app, appInfo);
ProgramSetup.ConfigureProxyRoutes(app, appInfo, logger, pageInfoFactory);

// Register routes using plugin-like extension methods
appInfo.RegisterStaticRoutes(routeHandlers, pageInfoFactory, mainTemplate);
appInfo.RegisterAuthRoutes(routeHandlers, pageInfoFactory, mainTemplate, allowAccountCreation);
appInfo.RegisterMonitoringRoutes(routeHandlers, pageInfoFactory, mainTemplate);
appInfo.RegisterAdminRoutes(routeHandlers, pageInfoFactory, mainTemplate);
appInfo.RegisterDataRoutes(routeHandlers, pageInfoFactory, mainTemplate);
appInfo.RegisterApiRoutes(routeHandlers, pageInfoFactory);

appInfo.BuildAppInfoMenuOptions();
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
    var message = $"BareMetalWeb server is ready - listening for requests on {display}";
    logger.LogInfo(message);
    Console.WriteLine(message);

    var httpsConfig = $"HTTPS redirect settings: mode={appInfo.HttpsRedirectMode}, trustForwardedHeaders={appInfo.TrustForwardedHeaders}, redirectHost={(string.IsNullOrWhiteSpace(appInfo.HttpsRedirectHost) ? "(auto)" : appInfo.HttpsRedirectHost)}, redirectPort={(appInfo.HttpsRedirectPort.HasValue ? appInfo.HttpsRedirectPort.Value.ToString() : "(auto)")}";
    logger.LogInfo(httpsConfig);
    Console.WriteLine(httpsConfig);

    var httpsAddress = list.FirstOrDefault(address => address.StartsWith("https://", StringComparison.OrdinalIgnoreCase));
    appInfo.HttpsEndpointAvailable = !string.IsNullOrWhiteSpace(httpsAddress);
    if (appInfo.HttpsEndpointAvailable && Uri.TryCreate(httpsAddress, UriKind.Absolute, out var httpsUri))
    {
        if (string.IsNullOrWhiteSpace(appInfo.HttpsRedirectHost))
        {
            appInfo.HttpsRedirectHost = httpsUri.Host;
        }

        if (!appInfo.HttpsRedirectPort.HasValue || appInfo.HttpsRedirectPort.Value <= 0)
        {
            appInfo.HttpsRedirectPort = httpsUri.IsDefaultPort ? 443 : httpsUri.Port;
        }
    }

    if (!appInfo.HttpsEndpointAvailable)
    {
        var warn = "HTTPS endpoint not configured. Configure HTTPS (ASPNETCORE_URLS / Kestrel) to expose an https:// address.";
        logger.LogInfo(warn);
        Console.WriteLine(warn);
    }
});

app.Run();

static class ProgramSetup
{
    public static IBufferedLogger CreateLogger(WebApplication app)
        => new DiskBufferedLogger(app.Configuration.GetValue("Logging:LogFolder", "Logs"));

    public static IDataObjectStore CreateDataStore(WebApplication app, ISchemaAwareObjectSerializer serializer, IDataQueryEvaluator queryEvaluator, IBufferedLogger logger)
    {
        var dataStore = new DataObjectStore();
        DataStoreProvider.Current = dataStore;
        var provider = new LocalFolderBinaryDataProvider(
            app.Configuration.GetValue("Data:Root", Path.Combine(app.Environment.ContentRootPath, "Data")),
            serializer,
            queryEvaluator,
            logger);
        DataStoreProvider.PrimaryProvider = provider;
        dataStore.RegisterProvider(provider);

        return dataStore;
    }

    public static void ResetDataIfRequested(WebApplication app, string dataRoot, IBufferedLogger logger)
    {
        var resetFlagPath = Path.Combine(app.Environment.ContentRootPath, "reset-data.flag");
        var shouldReset = app.Configuration.GetValue("Data:ResetOnStartup", false) || File.Exists(resetFlagPath);
        if (!shouldReset)
            return;

        var fullRoot = Path.GetFullPath(dataRoot);
        if (IsUnsafeDataRoot(fullRoot))
        {
            logger.LogError($"Refusing to reset data root '{fullRoot}'. Path is not safe.", new InvalidOperationException("Unsafe data root path."));
            return;
        }

        try
        {
            if (Directory.Exists(fullRoot))
            {
                Directory.Delete(fullRoot, recursive: true);
            }
            Directory.CreateDirectory(fullRoot);

            if (File.Exists(resetFlagPath))
            {
                File.Delete(resetFlagPath);
            }

            logger.LogInfo($"Data reset complete. Root: {fullRoot}");
        }
        catch (Exception ex)
        {
            logger.LogError($"Failed to reset data root '{fullRoot}'.", ex);
            throw;
        }
    }

    private static bool IsUnsafeDataRoot(string fullRoot)
    {
        if (string.IsNullOrWhiteSpace(fullRoot))
            return true;

        var root = Path.GetPathRoot(fullRoot);
        if (string.IsNullOrWhiteSpace(root))
            return true;

        return string.Equals(fullRoot.TrimEnd(Path.DirectorySeparatorChar), root.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
    }


    public static IClientRequestTracker CreateClientRequestTracker(WebApplication app, IBufferedLogger logger)
        => new ClientRequestTracker(
            logger,
            normalRpsThreshold: app.Configuration.GetValue("ClientRequests:NormalRpsThreshold", 20),
            suspiciousRpsThreshold: app.Configuration.GetValue("ClientRequests:SuspiciousRpsThreshold", 10),
            blockDuration: TimeSpan.FromMinutes(app.Configuration.GetValue("ClientRequests:BlockDurationMinutes", 1)),
            allowList: app.Configuration.GetSection("ClientRequests:AllowList").Get<string[]>() ?? Array.Empty<string>(),
            denyList: app.Configuration.GetSection("ClientRequests:DenyList").Get<string[]>() ?? Array.Empty<string>(),
            staleThreshold: TimeSpan.FromSeconds(app.Configuration.GetValue("ClientRequests:StaleThresholdSeconds", 120)),
            pruneInterval: TimeSpan.FromSeconds(app.Configuration.GetValue("ClientRequests:PruneIntervalSeconds", 30)),
            maxEntries: app.Configuration.GetValue("ClientRequests:MaxEntries", 100000));

    public static void EnsureRootPermissions(IBufferedLogger logger, params string[] requiredPermissions)
    {
        if (requiredPermissions is null || requiredPermissions.Length == 0)
            return;

        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = nameof(User.Permissions), Operator = QueryOperator.Contains, Value = "admin" },
                new QueryClause { Field = nameof(User.Permissions), Operator = QueryOperator.Contains, Value = "monitoring" }
            }
        };

        var users = DataStoreProvider.Current.Query<User>(query).ToList();
        foreach (var user in users)
        {
            if (user is null || !user.IsActive)
                continue;

            var perms = user.Permissions?.ToList() ?? new List<string>();
            var changed = false;
            foreach (var required in requiredPermissions)
            {
                if (string.IsNullOrWhiteSpace(required))
                    continue;
                if (perms.Any(p => string.Equals(p, required, StringComparison.OrdinalIgnoreCase)))
                    continue;
                perms.Add(required);
                changed = true;
            }

            if (!changed)
                continue;

            user.Permissions = perms.ToArray();
            DataStoreProvider.Current.Save(user);
            logger.LogInfo($"Updated root permissions for {user.UserName}.");
        }
    }

    public static BareMetalWebServer CreateAppInfo(
        WebApplication app,
        IBufferedLogger logger,
        IHtmlRenderer htmlRenderer,
        IPageInfoFactory pageInfoFactory,
        IHtmlTemplate mainTemplate,
        IMetricsTracker metrics,
        IClientRequestTracker clientRequests,
        CancellationTokenSource cts)
        => new BareMetalWebServer(
            app.Configuration.GetValue("AppInfo:Name", "BareMetalWeb"),
            app.Configuration.GetValue("AppInfo:Company", "BareMetalWeb Inc."),
            app.Configuration.GetValue("AppInfo:Copyright", "2026"),
            app,
            logger,
            htmlRenderer,
            pageInfoFactory.TemplatedPage(mainTemplate, 404, new[] { "title", "message" }, new[] { "404 - Not Found", "<p>The requested page was not found.</p>" }, "", true, 6000),
            pageInfoFactory.TemplatedPage(mainTemplate, 500, new[] { "title", "message" }, new[] { "500 - Internal Server Error", "<p>An unexpected error occurred.</p>" }, "", true, 6000),
            cts,
            metrics: metrics,
            clientRequests: clientRequests);

    public static void ConfigureStaticFiles(WebApplication app, BareMetalWebServer appInfo)
    {
        var staticFileConfig = app.Configuration.GetSection("StaticFiles").Get<StaticFileOptionsConfig>()
            ?? new StaticFileOptionsConfig();
        var staticFileOptions = StaticFileConfigOptions.FromConfig(staticFileConfig);
        staticFileOptions.Normalize();
        appInfo.StaticFiles = staticFileOptions;
    }

    public static void ConfigureCors(WebApplication app, BareMetalWebServer appInfo)
    {
        appInfo.CorsAllowedOrigins = app.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
    }

    public static void ConfigureHttps(WebApplication app, BareMetalWebServer appInfo)
    {
        appInfo.HttpsRedirectMode = app.Configuration.GetValue("Https:RedirectMode", HttpsRedirectMode.IfAvailable);
        appInfo.TrustForwardedHeaders = app.Configuration.GetValue("Https:TrustForwardedHeaders", false);
        var httpsRedirectHost = app.Configuration.GetValue<string>("Https:RedirectHost");
        var httpsRedirectPort = app.Configuration.GetValue<int>("Https:RedirectPort", 0);

        if (!string.IsNullOrWhiteSpace(httpsRedirectHost))
        {
            appInfo.HttpsRedirectHost = httpsRedirectHost.Trim();
        }
        if (httpsRedirectPort > 0)
        {
            appInfo.HttpsRedirectPort = httpsRedirectPort;
        }
    }

    public static void ConfigureProxyRoutes(WebApplication app, IBareWebHost appInfo, IBufferedLogger logger, IPageInfoFactory pageInfoFactory)
    {
        ProxyRoutingOptions proxyOptions = app.Configuration.GetSection("Proxy").Get<ProxyRoutingOptions>() ?? new ProxyRoutingOptions();
        List<ProxyRouteHandler> proxyHandlers = new();

        if (proxyOptions.Routes.Count > 0)
        {
            foreach (var route in proxyOptions.Routes)
            {
                var proxyHandler = new ProxyRouteHandler(route, logger);
                proxyHandlers.Add(proxyHandler);
                var verb = string.IsNullOrWhiteSpace(route.Verb) ? "ALL" : route.Verb.Trim();
                var matchMode = route.MatchMode?.Trim() ?? "Equals";
                var routeTemplate = route.Route;
                if (string.Equals(matchMode, "StartsWith", StringComparison.OrdinalIgnoreCase))
                {
                    var basePath = route.Route.TrimEnd('/');
                    if (string.IsNullOrWhiteSpace(basePath))
                        basePath = "/";
                    routeTemplate = basePath == "/" ? "/{*proxyPath}" : $"{basePath}/{{*proxyPath}}";
                }
                else if (string.Equals(matchMode, "Regex", StringComparison.OrdinalIgnoreCase))
                {
                    routeTemplate = $"regex:{route.Route}";
                }

                appInfo.RegisterRoute($"{verb} {routeTemplate}", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), proxyHandler.HandleAsync));
            }

            appInfo.RegisterRoute("GET /proxy/status", new RouteHandlerData(pageInfoFactory.RawPage("admin", false), async context =>
            {
                context.Response.ContentType = "application/json";
                var status = proxyHandlers.Select(handler => handler.GetStatus()).ToArray();

                await using var stream = context.Response.Body;
                using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true });
                writer.WriteStartArray();
                foreach (var routeStatus in status)
                {
                    writer.WriteStartObject();
                    writer.WriteString("route", routeStatus.Route);
                    writer.WriteString("matchMode", routeStatus.MatchMode);
                    writer.WriteString("loadBalance", routeStatus.LoadBalance);
                    writer.WriteStartArray("targets");
                    foreach (var target in routeStatus.Targets)
                    {
                        writer.WriteStartObject();
                        writer.WriteString("uri", target.Uri);
                        writer.WriteNumber("weight", target.Weight);
                        writer.WriteBoolean("online", target.Online);
                        if (target.OfflineUntil.HasValue)
                            writer.WriteString("offlineUntil", target.OfflineUntil.Value.ToString("O"));
                        else
                            writer.WriteNull("offlineUntil");
                        writer.WriteNumber("successes", target.Successes);
                        writer.WriteNumber("failures", target.Failures);
                        writer.WriteNumber("windowTotal", target.WindowTotal);
                        writer.WriteNumber("windowFailures", target.WindowFailures);
                        writer.WriteNumber("windowSuccesses", target.WindowSuccesses);
                        writer.WriteEndObject();
                    }
                    writer.WriteEndArray();
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();
                await writer.FlushAsync();
            }));
        }
        else
        {
            var proxyRoute = app.Configuration.GetValue<string>("Proxy:Route");
            var proxyTarget = app.Configuration.GetValue<string>("Proxy:TargetBaseUrl");
            if (!string.IsNullOrWhiteSpace(proxyRoute) && !string.IsNullOrWhiteSpace(proxyTarget))
            {
                var legacyRoute = new ProxyRouteConfig
                {
                    Route = proxyRoute,
                    TargetBaseUrl = proxyTarget
                };
                var proxyHandler = new ProxyRouteHandler(legacyRoute, logger);
                appInfo.RegisterRoute($"ALL {proxyRoute}", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), proxyHandler.HandleAsync));
            }
        }
    }
}