using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Interfaces;
using BareMetalWeb.Runtime;

namespace BareMetalWeb.Host;

/// <summary>
/// Single entry point for wiring up the full BareMetalWeb stack.
/// Usage (direct Kestrel hosting — no Web SDK):
/// <code>
///   var config = BmwConfig.Load(contentRoot);
///   var server = await BareMetalWebExtensions.InitializeAsync(config, contentRoot);
///   await using var host = BmwHost.Create(server, ProgramSetup.ConfigureKestrel(config));
///   await host.RunAsync();
/// </code>
/// </summary>
public static class BareMetalWebExtensions
{
    /// <summary>
    /// Configures and starts the full BareMetalWeb stack: data store, rendering,
    /// authentication, routing, static files, CORS, HTTPS, and proxy support.
    /// Optionally pass <paramref name="configureRoutes"/> to register additional routes.
    /// </summary>
    public static async Task<BareMetalWebServer> InitializeAsync(
        BmwConfig config,
        string contentRoot,
        Action<BareMetalWebServer, IRouteHandlers, IPageInfoFactory, IHtmlTemplate>? configureRoutes = null)
    {
        // Logger & data root
        IBufferedLogger logger = ProgramSetup.CreateLogger(config);
        logger.LogInfo("Starting BareMetalWeb server...");

        var dataRoot = config.GetValue("Data.Root", Path.Combine(contentRoot, "Data"));
        ProgramSetup.ResetDataIfRequested(config, contentRoot, dataRoot, logger);
        CookieProtection.ConfigureKeyRoot(dataRoot);

        // Data store
        ISchemaAwareObjectSerializer serializer = BinaryObjectSerializer.CreateDefault(dataRoot);
        IDataQueryEvaluator queryEvaluator = new DataQueryEvaluator();

        // Initialize binary wire API with the same signing key
        if (serializer is BinaryObjectSerializer bos)
            BinaryApiHandlers.Initialize(bos.GetSigningKeyCopy(), logger);
            LookupApiHandlers.Init(logger);

        // Register system entities explicitly (AOT-safe, no assembly scanning).
        DataScaffold.RegisterEntity<AppSetting>();
        DataScaffold.RegisterEntity<User>();
        DataScaffold.RegisterEntity<SystemPrincipal>();
        DataScaffold.RegisterEntity<AuditEntry>();
        DataScaffold.RegisterEntity<ReportDefinition>();
        DataScaffold.RegisterEntity<EntityDefinition>();
        DataScaffold.RegisterEntity<FieldDefinition>();
        DataScaffold.RegisterEntity<IndexDefinition>();
        DataScaffold.RegisterEntity<ActionDefinition>();
        DataScaffold.RegisterEntity<ActionCommandDefinition>();

        IDataObjectStore dataStore = ProgramSetup.CreateDataStore(config, contentRoot, serializer, queryEvaluator, logger);

        // ── Multitenancy ──────────────────────────────────────────────────────
        // Build the TenantRegistry and wire up additional per-tenant stores.
        // When multitenancy is disabled this is a no-op and the single system store
        // created above is used for every request, exactly as before.
        var multitenancyOptions = new MultitenancyOptions
        {
            Enabled = config.GetValue("Multitenancy.Enabled", false),
            DefaultTenantId = config.GetValue("Multitenancy.DefaultTenantId", "_system"),
        };
        var tenantRegistry = new TenantRegistry(multitenancyOptions, contentRoot);

        // Register the system tenant so that it can be used as a fallback.
        var systemProvider = DataStoreProvider.PrimaryProvider
            ?? throw new InvalidOperationException("PrimaryProvider was not set after CreateDataStore.");
        var systemTenant = new TenantContext(
            multitenancyOptions.DefaultTenantId,
            dataRoot,
            config.GetValue("Logging.LogFolder", "Logs"),
            dataStore,
            systemProvider);
        tenantRegistry.RegisterSystemTenant(systemTenant);

        if (multitenancyOptions.Enabled)
        {
            // Factory creates an isolated WalDataProvider + DataObjectStore for each tenant.
            // Returns both as an explicit tuple to avoid relying on side-effects.
            tenantRegistry.Initialize(
                storeFactory: (tenantId, tenantDataRoot) =>
                {
                    LegacyDataWipeGuard.WipeIfLegacyDetected(tenantDataRoot, logger);
                    var tenantSerializer = BinaryObjectSerializer.CreateDefault(tenantDataRoot);
                    var tenantProvider   = new WalDataProvider(tenantDataRoot, tenantSerializer, queryEvaluator, logger);
                    var tenantStore      = new DataObjectStore();
                    tenantStore.RegisterProvider(tenantProvider);
                    return (tenantStore, tenantProvider);
                },
                systemLogger: logger);
        }

        // Configure high-cardinality lookup threshold
        DataScaffold.LargeListThreshold = config.GetValue("LookupSearch.LargeListThreshold", 20);

        // Runtime entity registry — load persisted EntityDefinitions from storage and compile
        await RuntimeEntityRegistry.BuildAsync(
            dataStore,
            new RuntimeEntityCompiler(),
            systemProvider as WalDataProvider,
            dataRoot,
            msg => logger.LogInfo($"[RuntimeEntityRegistry] {msg}")).ConfigureAwait(false);

        // Permissions
        var permSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in DataScaffold.Entities)
        {
            foreach (var perm in (e.Permissions ?? string.Empty)
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                permSet.Add(perm);
            }
        }
        var entityPermissions = new string[permSet.Count];
        permSet.CopyTo(entityPermissions);
        var rootPermissionSet = new HashSet<string>(entityPermissions, StringComparer.OrdinalIgnoreCase)
        {
            "admin",
            "monitoring"
        };
        var rootPermsArray = new string[rootPermissionSet.Count];
        rootPermissionSet.CopyTo(rootPermsArray);
        await ProgramSetup.EnsureRootPermissionsAsync(logger, rootPermsArray);

        // Rendering
        IHtmlFragmentStore fragmentStore = new HtmlFragmentStore();
        IHtmlFragmentRenderer fragmentRenderer = new HtmlFragmentRenderer(fragmentStore);
        IHtmlRenderer htmlRenderer = new HtmlRenderer(fragmentRenderer);
        ITemplateStore templateStore = new TemplateStore();
        IPageInfoFactory pageInfoFactory = new PageInfoFactory();
        IMetricsTracker metricsTracker = new MetricsTracker();
        IClientRequestTracker throttling = ProgramSetup.CreateClientRequestTracker(config, logger);

        // Route handlers
        bool allowAccountCreation = config.GetValue("Auth.AllowAccountCreation", false);
        AuditService auditService = new AuditService(DataStoreProvider.Current, logger);
        var settingDefaults = new (string SettingId, string Value, string Description)[]
        {
            (WellKnownSettings.AppName,      config.GetValue("AppInfo.Name",      "BareMetalWeb"),       "Application display name"),
            (WellKnownSettings.AppCompany,   config.GetValue("AppInfo.Company",   "BareMetalWeb Inc."),  "Company name shown in the header and footer"),
            (WellKnownSettings.AppCopyright, config.GetValue("AppInfo.Copyright", "2026"),              "Copyright year or statement shown in the footer"),
            (WellKnownSettings.AppPrivacyPolicyUrl, config.GetValue("AppInfo.PrivacyPolicyUrl", ""),    "Privacy policy URL shown as a link in the footer. Leave empty to hide the link."),

            // Kestrel / transport
            (WellKnownSettings.KestrelHttp2Enabled,                 config.GetValue("Kestrel.Http2Enabled", true).ToString(),        "Enable HTTP/2 protocol support"),
            (WellKnownSettings.KestrelHttp3Enabled,                 config.GetValue("Kestrel.Http3Enabled", false).ToString(),       "Enable HTTP/3 (QUIC) protocol support"),
            (WellKnownSettings.KestrelMaxStreamsPerConnection,      config.GetValue("Kestrel.MaxStreamsPerConnection", 100).ToString(), "Max concurrent HTTP/2 streams per connection"),
            (WellKnownSettings.KestrelInitialConnectionWindowSize,  config.GetValue("Kestrel.InitialConnectionWindowSize", 131072).ToString(), "HTTP/2 initial connection-level flow-control window (bytes)"),
            (WellKnownSettings.KestrelInitialStreamWindowSize,      config.GetValue("Kestrel.InitialStreamWindowSize", 98304).ToString(), "HTTP/2 initial per-stream flow-control window (bytes)"),

            // Thread pool
            (WellKnownSettings.ThreadPoolMinWorkerThreads, config.GetValue("ThreadPool.MinWorkerThreads", 0).ToString(), "Minimum worker threads (0 = runtime default)"),
            (WellKnownSettings.ThreadPoolMinIOThreads,     config.GetValue("ThreadPool.MinIOThreads", 0).ToString(),     "Minimum I/O completion threads (0 = runtime default)"),

            // GC — informational only; actual values are baked in at publish time via the
            // project's RuntimeHostConfigurationOption entries. Override at process-start time
            // by setting DOTNET_GCServer=1 (server GC) env variable before launching the process
            // — these cannot be changed while running.
            (WellKnownSettings.GCServerMode, config.GetValue("GC.ServerMode", true).ToString(), "Server GC mode (true = one heap per CPU, false = workstation GC). Fixed at process start; set DOTNET_GCServer env var before launch to override."),

            // Admin
            (WellKnownSettings.AllowWipeData, config.GetValue("Admin.AllowWipeData", string.Empty), "Secret token required to trigger wipe-all-data. Leave empty to disable the endpoint."),

            // Diagnostics
            (WellKnownSettings.ShowHostInfo, "False", "When True, append a diagnostic banner (host, server, RTT, payload) to each page when ?showhst=true is on the request. Default: False."),
        };
        // Seed any missing settings and promote empty values when the config provides a non-empty default.
        // This runs at every startup so that changes to appsettings.json are picked up without
        // requiring a manual edit in the admin UI.
        await SettingsService.EnsureDefaultsAsync(DataStoreProvider.Current, settingDefaults, "system").ConfigureAwait(false);

        IRouteHandlers routeHandlers = new RouteHandlers(htmlRenderer, templateStore, allowAccountCreation, dataRoot, auditService, settingDefaults, logger, config);
        EntraIdService.Init(logger);
        IHtmlTemplate mainTemplate = templateStore.Get("Index");
        CancellationTokenSource cts = new CancellationTokenSource();

        // App info — create from config then override with any admin-edited store values
        BareMetalWebServer appInfo = ProgramSetup.CreateAppInfo(
            config, contentRoot, logger, htmlRenderer, pageInfoFactory, mainTemplate, metricsTracker, throttling, cts);
        appInfo.AppName            = SettingsService.GetValue(WellKnownSettings.AppName,           appInfo.AppName);
        appInfo.CompanyDescription = SettingsService.GetValue(WellKnownSettings.AppCompany,        appInfo.CompanyDescription);
        appInfo.CopyrightYear      = SettingsService.GetValue(WellKnownSettings.AppCopyright,      appInfo.CopyrightYear);
        appInfo.PrivacyPolicyUrl   = SettingsService.GetValue(WellKnownSettings.AppPrivacyPolicyUrl, "");
        appInfo.ShowHostDiagnostics = string.Equals(SettingsService.GetValue(WellKnownSettings.ShowHostInfo, "False"), "True", StringComparison.OrdinalIgnoreCase);

        // Wire up the tenant registry so RequestHandler can resolve tenants per-request.
        if (multitenancyOptions.Enabled)
            appInfo.TenantRegistry = tenantRegistry;

        // Keep in-memory server state in sync whenever a setting is edited via the admin UI.
        // Assign (not append) so that if UseBareMetalWeb is ever called more than once only the
        // current appInfo is subscribed.
        SettingsService.OnSettingInvalidated = settingId =>
        {
            if (string.Equals(settingId, WellKnownSettings.AppName, StringComparison.OrdinalIgnoreCase))
                appInfo.AppName = SettingsService.GetValue(WellKnownSettings.AppName, appInfo.AppName);
            else if (string.Equals(settingId, WellKnownSettings.AppCompany, StringComparison.OrdinalIgnoreCase))
                appInfo.CompanyDescription = SettingsService.GetValue(WellKnownSettings.AppCompany, appInfo.CompanyDescription);
            else if (string.Equals(settingId, WellKnownSettings.AppCopyright, StringComparison.OrdinalIgnoreCase))
                appInfo.CopyrightYear = SettingsService.GetValue(WellKnownSettings.AppCopyright, appInfo.CopyrightYear);
            else if (string.Equals(settingId, WellKnownSettings.AppPrivacyPolicyUrl, StringComparison.OrdinalIgnoreCase))
                appInfo.PrivacyPolicyUrl = SettingsService.GetValue(WellKnownSettings.AppPrivacyPolicyUrl, "");
            else if (string.Equals(settingId, WellKnownSettings.ShowHostInfo, StringComparison.OrdinalIgnoreCase))
                appInfo.ShowHostDiagnostics = string.Equals(SettingsService.GetValue(WellKnownSettings.ShowHostInfo, "False"), "True", StringComparison.OrdinalIgnoreCase);
        };

        // Infrastructure configuration
        ProgramSetup.ConfigureStaticFiles(config, appInfo);

        // Load pre-built per-theme CSS bundles from disk into memory.
        // Theme files are committed to the repository (generated by tools/download-assets.js).
        CssBundleService.LoadAssets(appInfo.StaticFiles.RootPathFull);
        if (!CssBundleService.HasBundles)
            logger.LogInfo("CssBundleService: no theme bundles found on disk — run 'node tools/download-assets.js' to generate them.");

        // Build JS bundle from static JS files.
        // bootstrap.bundle.min.js must be present (committed to repository or generated by tools/download-assets.js).
        JsBundleService.BuildBundle(Path.Combine(appInfo.StaticFiles.RootPathFull, "js"));

        // Build the pre-compressed in-memory static asset cache.
        // All compressible files up to InMemoryCacheMaxFileSizeBytes are Brotli- and
        // Gzip-compressed and packed into a single contiguous buffer.  Requests are
        // then served via an O(1) lookup + zero-copy PipeWriter write, bypassing
        // disk I/O and per-request compression entirely.
        if (appInfo.StaticFiles.EnableInMemoryCache)
        {
            StaticAssetCache.Build(
                appInfo.StaticFiles.RootPathFull,
                appInfo.StaticFiles,
                msg => logger.LogInfo(msg));
        }

        ProgramSetup.ConfigureCors(config, appInfo);
        ProgramSetup.ConfigureHttps(config, appInfo);
        ProgramSetup.ConfigureProxyRoutes(config, appInfo, logger, pageInfoFactory);

        // Built-in routes
        appInfo.RegisterStaticRoutes(routeHandlers, pageInfoFactory, mainTemplate);
        appInfo.RegisterAuthRoutes(routeHandlers, pageInfoFactory, mainTemplate, allowAccountCreation);
        appInfo.RegisterMonitoringRoutes(routeHandlers, pageInfoFactory, mainTemplate);
        appInfo.RegisterAdminRoutes(routeHandlers, pageInfoFactory, mainTemplate);
        appInfo.RegisterEntityMetadataRoute(pageInfoFactory);  // must be before RegisterApiRoutes
        appInfo.RegisterRuntimeApiRoutes(pageInfoFactory);       // /meta/entity/{name}, POST /query, POST /intent
        appInfo.RegisterLookupApiRoutes(pageInfoFactory);       // must be before RegisterApiRoutes
        ActionApiHandlers.Initialize();                           // action engine lock manager

        // Initialize cluster state with local lease (single-instance default)
        var clusterState = new BareMetalWeb.Data.ClusterState(new BareMetalWeb.Data.LocalLeaseAuthority());
        _ = clusterState.TryBecomeLeaderAsync(CancellationToken.None);

        // Initialize compactor with its own independent lease
        var compactorState = new BareMetalWeb.Data.CompactorState(new BareMetalWeb.Data.LocalLeaseAuthority());
        _ = compactorState.TryBecomeCompactorAsync(CancellationToken.None);

        ClusterApiHandlers.Initialize(clusterState, compactorState);
        ProxyRouteHandler.Initialize(clusterState);
        TenantApiHandlers.Initialize(tenantRegistry);

        // Vector ANN index manager
        var vectorIndexManager = new BareMetalWeb.Data.VectorIndexManager(dataRoot, logger);
        VectorApiHandlers.Initialize(vectorIndexManager);

        // Attach write fencing to the primary WAL provider
        if (DataStoreProvider.PrimaryProvider is BareMetalWeb.Data.WalDataProvider walProvider)
            walProvider.SetClusterState(clusterState);

        appInfo.RegisterBinaryApiRoutes(routeHandlers, pageInfoFactory, mainTemplate);       // binary wire-format API
        appInfo.RegisterApiRoutes(routeHandlers, pageInfoFactory);
        appInfo.RegisterVNextRoutes(pageInfoFactory, templateStore);
        appInfo.RegisterReportRoutes(pageInfoFactory);
        appInfo.RegisterMcpRoutes(pageInfoFactory);
        appInfo.RegisterOpenApiRoute(pageInfoFactory);

        // Custom routes from caller
        configureRoutes?.Invoke(appInfo, routeHandlers, pageInfoFactory, mainTemplate);

        // Finalise
        await appInfo.BuildAppInfoMenuOptionsAsync();
        await appInfo.WireUpRequestHandlingAndLoggerAsyncLifetime();

        return appInfo;
    }
}
