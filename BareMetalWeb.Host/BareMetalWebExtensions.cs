using System.Diagnostics;
using BareMetalWeb.ControlPlane;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Interfaces;
using BareMetalWeb.Runtime;
using Microsoft.AspNetCore.Http;

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
        var startupSw = Stopwatch.StartNew();
        Console.WriteLine();
        Console.WriteLine("╔══════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║              BareMetalWeb — Startup Diagnostics             ║");
        Console.WriteLine("╚══════════════════════════════════════════════════════════════╝");
        Console.WriteLine();

        // Validate configuration — fail fast on invalid values (#1271)
        config.LogConfiguration();
        var configErrors = config.Validate();
        if (configErrors.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("[BMW Startup] ✗ Configuration validation FAILED:");
            foreach (var err in configErrors)
                Console.WriteLine($"[BMW Startup]   ERROR: {err}");
            throw new InvalidOperationException(
                $"Configuration validation failed with {configErrors.Count} error(s). " +
                $"Fix Metal.config and restart. First error: {configErrors[0]}");
        }
        Console.WriteLine($"[BMW Startup] Configuration validated ({config.Keys.Count()} keys, 0 errors)");
        Console.WriteLine();

        // Logger & data root
        IBufferedLogger logger = ProgramSetup.CreateLogger(config);
        logger.LogInfo("Starting BareMetalWeb server...");
        Console.WriteLine($"[BMW Startup] Logger created (minLevel={logger.MinimumLevel}, format=JSON structured)");

        var dataRoot = config.GetValue("Data.Root", Path.Combine(contentRoot, "Data"));
        ProgramSetup.ResetDataIfRequested(config, contentRoot, dataRoot, logger);
        CookieProtection.ConfigureKeyRoot(dataRoot);
        Console.WriteLine($"[BMW Startup] Data root: {dataRoot}");

        // Data store
        var phaseSw = Stopwatch.StartNew();
        ISchemaAwareObjectSerializer serializer = BinaryObjectSerializer.CreateDefault(dataRoot);
        IDataQueryEvaluator queryEvaluator = new DataQueryEvaluator();
        Console.WriteLine($"[BMW Startup] Serializer + query evaluator created ({phaseSw.ElapsedMilliseconds}ms)");

        // Initialize binary wire API with the same signing key
        if (serializer is BinaryObjectSerializer bos)
        {
            BinaryApiHandlers.Initialize(bos.GetSigningKeyCopy(), logger);
        }
        LookupApiHandlers.Init(logger);
        Console.WriteLine($"[BMW Startup] Binary API + Lookup handlers initialized");

        // Register metadata-core entities explicitly (AOT-safe, no assembly scanning).
        // Only EntityDefinition, FieldDefinition, IndexDefinition need compiled C# types
        // because they define the metadata system itself.
        DataScaffold.RegisterEntity("EntityDefinition", SystemEntitySchemas.EntityDefinition,
            DataScaffold.BuildStoreHandlers("EntityDefinition", () => new EntityDefinition()));
        DataScaffold.RegisterEntity("FieldDefinition", SystemEntitySchemas.FieldDefinition,
            DataScaffold.BuildStoreHandlers("FieldDefinition", () => new FieldDefinition()));
        DataScaffold.RegisterEntity("IndexDefinition", SystemEntitySchemas.IndexDefinition,
            DataScaffold.BuildStoreHandlers("IndexDefinition", () => new IndexDefinition()));

        BinaryObjectSerializer.RegisterKnownType(typeof(EntityDefinition), () => new EntityDefinition());
        BinaryObjectSerializer.RegisterKnownType(typeof(FieldDefinition), () => new FieldDefinition());
        BinaryObjectSerializer.RegisterKnownType(typeof(IndexDefinition), () => new IndexDefinition());

        // All other system entities (reports, dashboards, views, actions, etc.) are
        // metadata-driven virtual entities registered via SystemCatalog → RuntimeEntityRegistry.
        Console.WriteLine($"[BMW Startup] Registered {DataScaffold.Entities.Count} code-first entities + system catalog provides the rest");

        phaseSw.Restart();
        IDataObjectStore dataStore = ProgramSetup.CreateDataStore(config, contentRoot, serializer, queryEvaluator, logger);
        Console.WriteLine($"[BMW Startup] Data store created with WAL provider ({phaseSw.ElapsedMilliseconds}ms)");

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
        Console.WriteLine($"[BMW Startup] Multitenancy: {(multitenancyOptions.Enabled ? "ENABLED" : "disabled (single-tenant)")}, default tenant: {multitenancyOptions.DefaultTenantId}");

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

        // System metadata catalog — seed built-in entity definitions on first startup
        phaseSw.Restart();
        var catalogSeeded = await SystemCatalog.SeedIfNeededAsync(
            dataStore,
            msg => logger.LogInfo($"[SystemCatalog] {msg}"),
            CancellationToken.None).ConfigureAwait(false);
        if (catalogSeeded > 0)
            Console.WriteLine($"[BMW Startup] System catalog: seeded {catalogSeeded} entities ({phaseSw.ElapsedMilliseconds}ms)");
        else
            Console.WriteLine($"[BMW Startup] System catalog: already present ({phaseSw.ElapsedMilliseconds}ms)");

        // Runtime entity registry — load persisted EntityDefinitions from storage and compile
        phaseSw.Restart();
        await RuntimeEntityRegistry.BuildAsync(
            dataStore,
            new RuntimeEntityCompiler(),
            systemProvider as WalDataProvider,
            dataRoot,
            msg => logger.LogInfo($"[RuntimeEntityRegistry] {msg}")).ConfigureAwait(false);
        Console.WriteLine($"[BMW Startup] RuntimeEntityRegistry built ({phaseSw.ElapsedMilliseconds}ms)");

        // Build capability graph from metadata (#1259)
        phaseSw.Restart();
        var capGraphBuilder = new BareMetalWeb.Runtime.CapabilityGraph.CapabilityGraphBuilder(RuntimeEntityRegistry.Current);
        var capGraph = await capGraphBuilder.BuildAsync(dataStore).ConfigureAwait(false);
        BareMetalWeb.Runtime.CapabilityGraph.CapabilityGraphRegistry.Current = capGraph;
        var (nodeCount, edgeCount, entityCount) = capGraph.Stats;
        Console.WriteLine($"[BMW Startup] CapabilityGraph: {nodeCount} nodes, {edgeCount} edges, {entityCount} entities ({phaseSw.ElapsedMilliseconds}ms)");

        // Compile metadata into dense runtime tables (struct-of-arrays)
        phaseSw.Restart();
        MetadataCompiler.CompileAndSwap(DataScaffold.Entities);
        logger.LogInfo($"[MetadataCompiler] Compiled {RuntimeSnapshot.Current!.Entities.Count} entities, " +
                       $"{RuntimeSnapshot.Current.Fields.Count} fields");
        Console.WriteLine($"[BMW Startup] MetadataCompiler: {RuntimeSnapshot.Current.Entities.Count} entities, {RuntimeSnapshot.Current.Fields.Count} fields ({phaseSw.ElapsedMilliseconds}ms)");

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
        Console.WriteLine($"[BMW Startup] Rendering stack initialized (HtmlRenderer, TemplateStore, PageInfoFactory)");

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
        Console.WriteLine($"[BMW Startup] Route handlers + EntraID initialized");
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

        // Wire up metrics callbacks for subsystem timers
        BmwJsonWriter.OnSerializationComplete = elapsed => metricsTracker.RecordSerialization(elapsed);
        WalDataProvider.OnWalReadComplete = elapsed => metricsTracker.RecordWalRead(elapsed);
        BareMetalWeb.Rendering.HtmlRenderer.OnRenderComplete = elapsed => metricsTracker.RecordUiRender(elapsed);

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
        Console.WriteLine($"[BMW Startup] Static files configured (root: {appInfo.StaticFiles.RootPathFull}, in-memory cache: {appInfo.StaticFiles.EnableInMemoryCache})");

        // Load pre-built per-theme CSS bundles from disk into memory.
        // Theme files are committed to the repository (generated by tools/download-assets.js).
        CssBundleService.LoadAssets(appInfo.StaticFiles.RootPathFull);
        if (!CssBundleService.HasBundles)
            logger.LogInfo("CssBundleService: no theme bundles found on disk — run 'node tools/download-assets.js' to generate them.");
        Console.WriteLine($"[BMW Startup] CSS bundles: {(CssBundleService.HasBundles ? "loaded" : "none found")}");

        // Build JS bundle from static JS files.
        // bootstrap.bundle.min.js must be present (committed to repository or generated by tools/download-assets.js).
        JsBundleService.BuildBundle(Path.Combine(appInfo.StaticFiles.RootPathFull, "js"));
        Console.WriteLine($"[BMW Startup] JS bundle built");

        // Build the pre-compressed in-memory static asset cache.
        // All compressible files up to InMemoryCacheMaxFileSizeBytes are Brotli- and
        // Gzip-compressed and packed into a single contiguous buffer.  Requests are
        // then served via an O(1) lookup + zero-copy PipeWriter write, bypassing
        // disk I/O and per-request compression entirely.
        if (appInfo.StaticFiles.EnableInMemoryCache)
        {
            _ = Task.Run(() => StaticAssetCache.Build(
                appInfo.StaticFiles.RootPathFull,
                appInfo.StaticFiles,
                msg => logger.LogInfo(msg)));
        }

        ProgramSetup.ConfigureCors(config, appInfo);
        ProgramSetup.ConfigureHttps(config, appInfo);
        ProgramSetup.ConfigureProxyRoutes(config, appInfo, logger, pageInfoFactory);
        Console.WriteLine($"[BMW Startup] CORS, HTTPS, proxy routes configured");

        // Built-in routes
        Console.WriteLine($"[BMW Startup] Registering routes...");
        var routeCountBefore = appInfo.routes.Count;
        appInfo.RegisterStaticRoutes(routeHandlers, pageInfoFactory, mainTemplate);
        Console.WriteLine($"[BMW Startup]   Static routes: +{appInfo.routes.Count - routeCountBefore} ({appInfo.routes.Count} total)");

        routeCountBefore = appInfo.routes.Count;
        appInfo.RegisterAuthRoutes(routeHandlers, pageInfoFactory, mainTemplate, allowAccountCreation);
        Console.WriteLine($"[BMW Startup]   Auth routes:   +{appInfo.routes.Count - routeCountBefore} ({appInfo.routes.Count} total)");

        routeCountBefore = appInfo.routes.Count;
        appInfo.RegisterMonitoringRoutes(routeHandlers, pageInfoFactory, mainTemplate);
        Console.WriteLine($"[BMW Startup]   Monitoring:    +{appInfo.routes.Count - routeCountBefore} ({appInfo.routes.Count} total)");

        routeCountBefore = appInfo.routes.Count;
        appInfo.RegisterAdminRoutes(routeHandlers, pageInfoFactory, mainTemplate);
        Console.WriteLine($"[BMW Startup]   Admin routes:  +{appInfo.routes.Count - routeCountBefore} ({appInfo.routes.Count} total)");

        routeCountBefore = appInfo.routes.Count;
        appInfo.RegisterEntityMetadataRoute(pageInfoFactory);  // must be before RegisterApiRoutes
        appInfo.RegisterRuntimeApiRoutes(pageInfoFactory);       // /meta/entity/{name}, POST /query, POST /intent
        appInfo.RegisterLookupApiRoutes(pageInfoFactory);       // must be before RegisterApiRoutes
        Console.WriteLine($"[BMW Startup]   Meta/Runtime:  +{appInfo.routes.Count - routeCountBefore} ({appInfo.routes.Count} total)");

        ActionApiHandlers.Initialize();                           // action engine lock manager
        NotificationService.Initialize(logger);                   // notification channels
        Console.WriteLine($"[BMW Startup]   ActionAPI + NotificationService initialized");

        // Initialize cluster state with local lease (single-instance default)
        var clusterState = new BareMetalWeb.Data.ClusterState(new BareMetalWeb.Data.LocalLeaseAuthority());
        _ = clusterState.TryBecomeLeaderAsync(CancellationToken.None);

        // Initialize compactor with its own independent lease
        var compactorState = new BareMetalWeb.Data.CompactorState(new BareMetalWeb.Data.LocalLeaseAuthority());
        _ = compactorState.TryBecomeCompactorAsync(CancellationToken.None);

        ClusterApiHandlers.Initialize(clusterState, compactorState);
        ProxyRouteHandler.Initialize(clusterState);
        MetricsTracker.ClusterState = clusterState;
        TenantApiHandlers.Initialize(tenantRegistry);
        Console.WriteLine($"[BMW Startup]   Cluster + Compactor state initialized (local lease)");

        // Vector ANN index manager
        var vectorIndexManager = new BareMetalWeb.Data.VectorIndexManager(dataRoot, logger);
        VectorApiHandlers.Initialize(vectorIndexManager);
        Console.WriteLine($"[BMW Startup]   Vector index manager initialized");

        // Attach write fencing to the primary WAL provider
        if (DataStoreProvider.PrimaryProvider is BareMetalWeb.Data.WalDataProvider walProvider)
            walProvider.SetClusterState(clusterState);

        routeCountBefore = appInfo.routes.Count;
        appInfo.RegisterBinaryApiRoutes(routeHandlers, pageInfoFactory, mainTemplate);       // binary wire-format API
        appInfo.RegisterApiRoutes(routeHandlers, pageInfoFactory);
        appInfo.RegisterInboxRoutes(pageInfoFactory);
        appInfo.RegisterVNextRoutes(pageInfoFactory, templateStore);
        appInfo.RegisterReportRoutes(pageInfoFactory);
        appInfo.RegisterDashboardRoutes(pageInfoFactory);
        appInfo.RegisterModuleRoutes(pageInfoFactory);
        appInfo.RegisterChatRoutes(pageInfoFactory);
        appInfo.RegisterRuntimeRoutes(pageInfoFactory, dataRoot);
        appInfo.RegisterViewRoutes(pageInfoFactory);
        appInfo.RegisterMcpRoutes(pageInfoFactory);
        appInfo.RegisterOpenApiRoute(pageInfoFactory);
        Console.WriteLine($"[BMW Startup]   API/UI routes: +{appInfo.routes.Count - routeCountBefore} ({appInfo.routes.Count} total)");

        // Custom routes from caller
        routeCountBefore = appInfo.routes.Count;
        configureRoutes?.Invoke(appInfo, routeHandlers, pageInfoFactory, mainTemplate);
        if (appInfo.routes.Count > routeCountBefore)
            Console.WriteLine($"[BMW Startup]   Custom routes: +{appInfo.routes.Count - routeCountBefore} ({appInfo.routes.Count} total)");

        Console.WriteLine($"[BMW Startup] Route registration complete — {appInfo.routes.Count} routes total");

        // ── Automated backup service (#1270) ──────────────────────────────────
        WalBackupService? backupService = null;
        if (config.GetValue("Backup.Enabled", false)
            && DataStoreProvider.PrimaryProvider is WalDataProvider backupWalProvider)
        {
            var walDir = Path.Combine(dataRoot, "wal");
            var backupDir = config.GetValue("Backup.Directory", Path.Combine(dataRoot, "backups"));
            var intervalMin = config.GetValue("Backup.IntervalMinutes", 360);
            var retentionDays = config.GetValue("Backup.RetentionDays", 30);

            backupService = new WalBackupService(
                backupWalProvider.WalStore,
                walDir,
                backupDir,
                intervalMin,
                retentionDays,
                logger);
            backupService.Start();
            Console.WriteLine($"[BMW Startup] Backup service started (interval: {intervalMin}min, retention: {retentionDays}d, dir: {backupDir})");

            appInfo.RegisterBackupRoutes(pageInfoFactory, backupService);
            Console.WriteLine($"[BMW Startup]   Backup routes: +2 ({appInfo.routes.Count} total)");
        }
        else if (!config.GetValue("Backup.Enabled", false))
        {
            Console.WriteLine($"[BMW Startup] Backup service: disabled (set Backup.Enabled|true in Metal.config)");
        }

        // Admin API routes for capability graph and workflow planner
        appInfo.RegisterCapabilityRoutes(pageInfoFactory);
        Console.WriteLine($"[BMW Startup]   Capability + workflow planner routes: +2");

        // Finalise
        await appInfo.BuildAppInfoMenuOptionsAsync();
        await appInfo.WireUpRequestHandlingAndLoggerAsyncLifetime();
        Console.WriteLine($"[BMW Startup] Menu options built, request handler wired");

        // Fire-and-forget: warm up search index metadata in the background so the
        // first real query does not pay the reflection/compilation cost.
        if (DataStoreProvider.PrimaryProvider is WalDataProvider warmupProvider)
        {
            _ = Task.Run(async () =>
            {
                await Task.Delay(2000);
                warmupProvider.WarmSearchIndexMetadata();
                Console.WriteLine($"[BMW Startup] Search index metadata warm-up complete (background)");
            });
            Console.WriteLine($"[BMW Startup] Search index warm-up scheduled (2s delay)");
        }

        // ── Control plane telemetry streaming (#1305) ──────────────────────────
        var cpUrl = config.GetValue("ControlPlane.Url", "");
        var cpApiKey = config.GetValue("ControlPlane.ApiKey", "");
        if (!string.IsNullOrEmpty(cpUrl) && !string.IsNullOrEmpty(cpApiKey))
        {
            var cpClient = new ControlPlaneClient(cpUrl, cpApiKey, logger);
            var cpBufferDir = Path.Combine(dataRoot, "cpbuffer");
            var cpService = new ControlPlaneService(cpClient, metricsTracker, config, logger, cpBufferDir);

            // Wire optional data sources from WAL layer
            if (DataStoreProvider.PrimaryProvider is WalDataProvider cpWalProvider)
            {
                var walStore = cpWalProvider.WalStore;
                var cpWalDir = Path.Combine(dataRoot, "wal");
                cpService.WithDataSources(
                    recordCount: () => walStore.HeadMap.Count,
                    walSegmentCount: () =>
                    {
                        try { return Directory.GetFiles(cpWalDir, "wal_seg_*.log").Length; }
                        catch { return 0; }
                    },
                    lastBackupAt: () => backupService?.ListBackups().FirstOrDefault()?.Timestamp.ToString("O"),
                    isLeader: () => clusterState?.IsLeader ?? true,
                    epoch: () => clusterState?.CurrentEpoch ?? 0
                );
            }

            // Forward error/fatal log events to the control-plane error stream
            if (logger is DiskBufferedLogger diskLogger)
                diskLogger.ErrorHook = cpService.BufferError;

            appInfo.ControlPlane = cpService;
            RouteHandlers.WebStoreClient = cpClient;
            Console.WriteLine($"[BMW Startup] Control plane telemetry: streaming to {cpUrl} (offline buffer: {cpBufferDir})");
            Console.WriteLine($"[BMW Startup] Template webstore: enabled at /admin/webstore");
        }
        else
        {
            Console.WriteLine("[BMW Startup] Control plane: disabled (set ControlPlane.Url and ControlPlane.ApiKey in Metal.config)");
        }

        startupSw.Stop();
        Console.WriteLine();
        Console.WriteLine($"[BMW Startup] ✓ Initialization complete in {startupSw.ElapsedMilliseconds}ms");
        Console.WriteLine();

        // Signal readiness for /readyz and /health probes (#1263)
        BareMetalWebServer.IsReady = true;

        return appInfo;
    }
}
