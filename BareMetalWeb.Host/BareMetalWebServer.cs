using System.Collections.Concurrent;
using System.Diagnostics;
using BareMetalWeb.ControlPlane;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

public class BareMetalWebServer : IBareWebHost
{
    // Content Security Policy: Uses nonces for inline scripts/styles to provide strong XSS protection.
    // The {0} placeholder is replaced with the request-specific nonce at runtime.
    private const string ContentSecurityPolicyTemplate = "default-src 'self'; script-src 'self' 'nonce-{0}'; style-src 'self' 'nonce-{0}'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'";
    private static readonly TimeSpan MenuCacheTtl = TimeSpan.FromSeconds(30);
    private static readonly QueryDefinition RootUserQuery = new()
    {
        Clauses = new List<QueryClause>
        {
            new QueryClause { Field = "Permissions", Operator = QueryOperator.Contains, Value = "admin" },
            new QueryClause { Field = "Permissions", Operator = QueryOperator.Contains, Value = "monitoring" }
        }
    };
    public BmwConfig Configuration { get; }
    public string ContentRootPath { get; }
    public IBufferedLogger BufferedLogger { get; }
    public IMetricsTracker Metrics { get; }
    public IClientRequestTracker ClientRequests { get; }
    internal ApiRateLimiter ApiLimiter { get; } = new();
    public IHtmlRenderer HtmlRenderer { get; }
    public Dictionary<string, RouteHandlerData> routes { get; set; } = new();
    private string _appName = "";
    public string AppName
    {
        get => _appName;
        set { _appName = value; if (AppMetaDataValues != null) AppMetaDataValues[0] = value; }
    }
    private string _companyDescription = "";
    public string CompanyDescription
    {
        get => _companyDescription;
        set { _companyDescription = value; if (AppMetaDataValues != null) AppMetaDataValues[1] = value; }
    }
    private string _copyrightYear = "";
    public string CopyrightYear
    {
        get => _copyrightYear;
        set { _copyrightYear = value; if (AppMetaDataValues != null) AppMetaDataValues[2] = value; }
    }
    private string _privacyPolicyUrl = "";
    public string PrivacyPolicyUrl
    {
        get => _privacyPolicyUrl;
        set
        {
            _privacyPolicyUrl = value;
            AppMetaDataValues[4] = ComputePrivacyPolicyLink(value);
        }
    }
    public static string[] appMetaDataKeys { get; set; } = new[] { "AppName", "CompanyDescription", "CopyrightYear", "AppVersion", "html_PrivacyPolicyUrl" };
    public string[] AppMetaDataKeys => appMetaDataKeys;
    public string[] AppMetaDataValues { get; set; }
    public List<IMenuOption> MenuOptionsList { get; set; } = new List<IMenuOption>();
    public PageInfo NotFoundPageInfo { get; }
    public PageInfo ErrorPageInfo { get; }
    public CancellationTokenSource cts { get; }
    public string[] CorsAllowedOrigins { get; set; } = Array.Empty<string>();
    public string[] CorsAllowedMethods { get; set; } = new[] { "GET", "POST", "PUT", "DELETE", "OPTIONS" };
    public string[] CorsAllowedHeaders { get; set; } = new[] { "Content-Type", "Authorization" };
    public StaticFileConfigOptions StaticFiles { get; set; } = new();
    public HttpsRedirectMode HttpsRedirectMode { get; set; } = HttpsRedirectMode.IfAvailable;
    public bool TrustForwardedHeaders { get; set; } = false;
    public bool HttpsEndpointAvailable { get; set; } = false;
    public string? HttpsRedirectHost { get; set; }
    public int? HttpsRedirectPort { get; set; }
    public bool ShowHostDiagnostics { get; set; } = false;

    /// <summary>
    /// Set to <c>true</c> when startup is complete and the server is ready to serve traffic.
    /// Used by <c>GET /readyz</c> to signal readiness to orchestrators.
    /// Static because route handlers don't have access to the server instance.
    /// </summary>
    public static volatile bool IsReady;

    /// <summary>
    /// When multitenancy is enabled, this registry resolves the correct per-tenant
    /// data store at the start of each request based on the HTTP Host header.
    /// Null (default) means multitenancy is disabled and the system store is used for all requests.
    /// </summary>
    public TenantRegistry? TenantRegistry { get; set; }
    internal ControlPlaneService? ControlPlane { get; set; }
    private readonly ConcurrentDictionary<string, MenuCacheEntry> _menuCache = new(StringComparer.Ordinal);
    private DateTime _lastMenuCacheScavenge = DateTime.UtcNow;
    private const int MaxMenuCacheEntries = 2048;
    private int _routesVersion = 0;
    private ushort _nextRouteId = 1; // 0 = unassigned
    private readonly Dictionary<string, CompiledRoute> _compiledRoutes = new(StringComparer.Ordinal);
    private List<(string Key, RouteHandlerData Data, CompiledRoute Compiled)>? _sortedRoutes;
    private int _sortedRoutesVersion = -1;
    private readonly RouteJumpTable _jumpTable = new();
    private int _jumpTableVersion = -1;
    private readonly PrefixRouter _prefixRouter = new();
    private int _prefixRouterVersion = -1;
    /// <summary>Dense array of handlers indexed by RouteId for O(1) numeric dispatch.</summary>
    private RouteHandlerData[] _routeById = Array.Empty<RouteHandlerData>();
    private int _routeByIdVersion = -1;
    /// <summary>Max RouteId currently assigned (for bounds checking).</summary>
    private ushort _maxRouteId;
    /// <summary>Binary WebSocket transport with branch-free jump table dispatch.</summary>
    private BmwBinaryTransport? _binaryTransport;
    /// <summary>Protocol descriptor — single shared contract between server and all clients.</summary>
    private BmwProtocolDescriptor? _protocolDescriptor;
    private readonly NumericRouteTable _numericRoutes = new();
    private int _numericRouteVersion = -1;
    public BareMetalWebServer(
        string appName,
        string companyDescription,
        string copyrightYear,
        BmwConfig configuration,
        string contentRootPath,
        IBufferedLogger logger,
        IHtmlRenderer htmlRenderer,
        PageInfo NotFoundPage,
        PageInfo ErrorPage,
        CancellationTokenSource _cts,
        IMetricsTracker metrics,
        IClientRequestTracker clientRequests)

    {
        AppName = appName;
        CompanyDescription = companyDescription;
        CopyrightYear = copyrightYear;
        var rawVersion = BareMetalWeb.Host.BuildVersion.Value;
        // Strip leading 'v'/'V' (template already adds 'v') and shorten full commit SHA after '+' to 7 chars
        var trimmed = rawVersion.TrimStart('v').TrimStart('V');
        var plusIdx = trimmed.IndexOf('+');
        var version = plusIdx >= 0 && trimmed.Length - plusIdx - 1 > 7
            ? trimmed[..plusIdx] + "+" + trimmed[(plusIdx + 1)..(plusIdx + 8)]
            : trimmed;
        AppMetaDataValues = new[] { AppName, CompanyDescription, CopyrightYear, version, ComputePrivacyPolicyLink(_privacyPolicyUrl) };
        Configuration = configuration;
        ContentRootPath = contentRootPath;
        BufferedLogger = logger;
        HtmlRenderer = htmlRenderer;
        Metrics = metrics;
        ClientRequests = clientRequests;
        NotFoundPageInfo = NotFoundPage;
        ErrorPageInfo = ErrorPage;
        cts = _cts;
    }
    public async ValueTask BuildAppInfoMenuOptionsAsync(BmwContext? context = null, CancellationToken cancellationToken = default)
    {
        var user = context != null ? await UserAuth.GetUserAsync(context, cancellationToken).ConfigureAwait(false) : null;
        bool isAnonymous = user == null;
        var userPermissions = new HashSet<string>(UserAuth.GetPermissions(user), StringComparer.OrdinalIgnoreCase);

        if (context != null)
        {
            var cacheKey = BuildMenuCacheKey(user, _routesVersion);
            if (_menuCache.TryGetValue(cacheKey, out var cached) && cached.ExpiresUtc > DateTime.UtcNow)
            {
                MenuOptionsList = new List<IMenuOption>(cached.Options);
                return;
            }

            _menuCache.TryRemove(cacheKey, out _);
        }

        // Build into a local list so concurrent readers never see a partially-built menu (#1303)
        var menuOptions = new List<IMenuOption>();
        foreach (var rte in routes)
        {
            var pageInfo = rte.Value.PageInfo;
            if (pageInfo == null || !pageInfo.PageMetaData.ShowOnNavBar)
                continue;

            if (!TryParseRoute(rte.Key, out var verb, out var path))
                continue;

            if (!verb.Equals("GET", StringComparison.OrdinalIgnoreCase) &&
                !verb.Equals("ALL", StringComparison.OrdinalIgnoreCase))
                continue;

            if (UserAuth.IsMfaEnabled(user) && path.Equals("/account/mfa", StringComparison.OrdinalIgnoreCase))
                continue;

            // Build menu options here
            string href = path;
            string label = (pageInfo.PageContext.PageMetaDataValues.Length > 0 ? pageInfo.PageContext.PageMetaDataValues[0] : null) ?? path.Trim('/');
            bool rightAligned = pageInfo.PageContext.NavAlignment == NavAlignment.Right;
            bool highlightAsButton = pageInfo.PageContext.NavRenderStyle == NavRenderStyle.Button;
            var permissionsNeeded = pageInfo.PageMetaData.PermissionsNeeded ?? string.Empty;
            bool requiresAnonymous = string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase);
            bool requiresAuthenticated = string.Equals(permissionsNeeded, "Authenticated", StringComparison.OrdinalIgnoreCase);
            bool isPublic = string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase);

            var requiredPermissions = (string.IsNullOrWhiteSpace(permissionsNeeded) || requiresAnonymous || requiresAuthenticated || isPublic)
                ? Array.Empty<string>()
                : permissionsNeeded.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            if (requiresAnonymous && !isAnonymous)
                continue;

            if (requiresAuthenticated && isAnonymous)
                continue;

            if (!requiresAnonymous && !requiresAuthenticated && requiredPermissions.Length > 0)
            {
                if (isAnonymous)
                    continue;

                bool hasPermission = true;
                for (int i = 0; i < requiredPermissions.Length; i++)
                {
                    if (!userPermissions.Contains(requiredPermissions[i]))
                    {
                        hasPermission = false;
                        break;
                    }
                }
                if (!hasPermission)
                    continue;
            }

            string? group = pageInfo.PageContext.NavGroup;

            bool requiresLoggedIn = requiresAuthenticated || (!requiresAnonymous && requiredPermissions.Length > 0);

            menuOptions.Add(new MenuOption(
                href,
                label,
                pageInfo.PageMetaData.ShowOnNavBar,
                pageInfo.PageMetaData.PermissionsNeeded ?? string.Empty,
                rightAligned,
                highlightAsButton,
                requiresAnonymous,
                requiresLoggedIn: requiresLoggedIn,
                requiredPermissions: requiredPermissions,
                colorClass: pageInfo.PageContext.NavColorClass,
                group: group,
                subGroup: pageInfo.PageContext.NavSubGroup));
        }

        foreach (var entity in DataScaffold.Entities)
        {
            if (!entity.ShowOnNav)
                continue;

            var permissionsNeeded = entity.Permissions?.Trim() ?? string.Empty;
            bool requiresAnonymous = string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase);
            bool requiresAuthenticated = string.Equals(permissionsNeeded, "Authenticated", StringComparison.OrdinalIgnoreCase);
            bool isPublic = string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase);

            var requiredPermissions = (string.IsNullOrWhiteSpace(permissionsNeeded) || requiresAnonymous || requiresAuthenticated || isPublic)
                ? Array.Empty<string>()
                : permissionsNeeded.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            if (requiresAnonymous && !isAnonymous)
                continue;

            if (requiresAuthenticated && isAnonymous)
                continue;

            if (!requiresAnonymous && !requiresAuthenticated && requiredPermissions.Length > 0)
            {
                if (isAnonymous)
                    continue;

                bool allPermissionsMatch = true;
                for (int i = 0; i < requiredPermissions.Length; i++)
                {
                    if (!userPermissions.Contains(requiredPermissions[i]))
                    {
                        allPermissionsMatch = false;
                        break;
                    }
                }
                if (!allPermissionsMatch)
                    continue;
            }

            bool requiresLoggedIn = requiresAuthenticated || (!requiresAnonymous && requiredPermissions.Length > 0);

            bool entityRightAligned = string.Equals(entity.NavGroup, "Admin", StringComparison.OrdinalIgnoreCase);

            menuOptions.Add(new MenuOption(
                href: $"/{entity.Slug}",
                label: entity.Name,
                showOnNavBar: true,
                permissionsNeeded: permissionsNeeded,
                rightAligned: entityRightAligned,
                highlightAsButton: false,
                requiresAnonymous: requiresAnonymous,
                requiresLoggedIn: requiresLoggedIn,
                requiredPermissions: requiredPermissions,
                group: entity.NavGroup));
        }

        if (!isAnonymous)
        {
            menuOptions.Add(new MenuOption(
                href: "/logout",
                label: "Logout",
                showOnNavBar: true,
                rightAligned: true,
                highlightAsButton: true,
                colorClass: "btn-warning"));
        }

        var loginIndex = menuOptions.FindIndex(option => string.Equals(option.Href, "/login", StringComparison.OrdinalIgnoreCase));
        if (loginIndex >= 0)
        {
            var loginOption = menuOptions[loginIndex];
            menuOptions.RemoveAt(loginIndex);
            menuOptions.Add(loginOption);
        }

        // Atomic swap — readers always see a complete, consistent list
        MenuOptionsList = menuOptions;

        if (context != null)
        {
            var cacheKey = BuildMenuCacheKey(user, _routesVersion);
            _menuCache[cacheKey] = new MenuCacheEntry(menuOptions.ToArray(), DateTime.UtcNow.Add(MenuCacheTtl));
            ScavengeMenuCache();
        }
    }
    public delegate Task BareMetalRequestDelegate(HttpContext ctx, IHtmlRenderer renderer, PageInfo page, BareMetalWebServer app, IOutputCache cache);
    public void RegisterRoute(string path, RouteHandlerData routeHandler)
    {
        routeHandler.RouteId = _nextRouteId++;
        routeHandler.RouteKey = path;
        routes[path] = routeHandler;
        _compiledRoutes[path] = new CompiledRoute(path);
        _routesVersion++;
        _sortedRoutes = null; // invalidate sorted cache
        BufferedLogger.LogInfo($"Route registered: {path} [id={routeHandler.RouteId}] with handler {routeHandler.Handler.Method.Name}");
    }

    // Returns routes sorted by specificity (most literal segments first), rebuilding only when routes change.
    private List<(string Key, RouteHandlerData Data, CompiledRoute Compiled)> GetSortedRoutes()
    {
        if (_sortedRoutes == null || _sortedRoutesVersion != _routesVersion)
        {
            var tempList = new List<(string Key, RouteHandlerData Data, CompiledRoute Compiled)>();
            foreach (var r in routes)
            {
                if (_compiledRoutes.ContainsKey(r.Key))
                {
                    tempList.Add((r.Key, r.Value, _compiledRoutes[r.Key]));
                }
            }
            tempList.Sort((a, b) => b.Compiled.LiteralSegmentCount.CompareTo(a.Compiled.LiteralSegmentCount));
            _sortedRoutes = tempList;
            _sortedRoutesVersion = _routesVersion;
        }
        return _sortedRoutes;
    }

    /// <summary>Ensures the jump table is rebuilt when routes change.</summary>
    private void EnsureJumpTable()
    {
        if (_jumpTableVersion != _routesVersion)
        {
            _jumpTable.Build(routes, _compiledRoutes, BufferedLogger);
            _jumpTableVersion = _routesVersion;
        }
    }

    /// <summary>Ensures the prefix router is rebuilt when routes change.</summary>
    private void EnsurePrefixRouter()
    {
        if (_prefixRouterVersion != _routesVersion)
        {
            _prefixRouter.Build(routes, BufferedLogger);
            _prefixRouterVersion = _routesVersion;
        }
    }

    /// <summary>Builds the dense RouteId → handler array when routes change.</summary>
    private void EnsureRouteIdTable()
    {
        if (_routeByIdVersion != _routesVersion)
        {
            ushort maxId = 0;
            foreach (var kvp in routes)
            {
                if (kvp.Value.RouteId > maxId)
                    maxId = kvp.Value.RouteId;
            }

            var table = new RouteHandlerData[maxId + 1];
            foreach (var kvp in routes)
            {
                var data = kvp.Value;
                if (data.RouteId > 0)
                    table[data.RouteId] = data;
            }

            _routeById = table;
            _maxRouteId = maxId;
            _routeByIdVersion = _routesVersion;
            BufferedLogger.LogInfo($"Route ID table built: {routes.Count} routes, max ID={maxId}");
        }
    }

    /// <summary>Ensures the binary WebSocket transport is initialized and populated from current routes.</summary>
    private void EnsureBinaryTransport()
    {
        if (_binaryTransport == null)
        {
            _binaryTransport = new BmwBinaryTransport();
            _binaryTransport.PopulateFromRoutes(routes, this);

            // Build the protocol descriptor — the single shared contract
            _protocolDescriptor = BmwProtocolDescriptor.Build(routes, _compiledRoutes);

            // Register the WebSocket upgrade endpoint
            RegisterRoute("GET /bmw/ws", new RouteHandlerData(null, BmwWebSocketHandler.CreateHandler(_binaryTransport)));

            // Register protocol descriptor endpoint
            RegisterRoute("GET /bmw/protocol", new RouteHandlerData(null, async (BmwContext ctx) =>
            {
                ctx.StatusCode = 200;
                ctx.ContentType = "application/json";
                await ctx.WriteResponseAsync(_protocolDescriptor!.ToJson());
            }));

            // Register JS SDK generator endpoint
            RegisterRoute("GET /bmw/sdk.js", new RouteHandlerData(null, async (BmwContext ctx) =>
            {
                ctx.StatusCode = 200;
                ctx.ContentType = "application/javascript";
                await ctx.WriteResponseAsync(_protocolDescriptor!.GenerateJsSdk());
            }));

            // Register CLI reference endpoint
            RegisterRoute("GET /bmw/cli", new RouteHandlerData(null, async (BmwContext ctx) =>
            {
                ctx.StatusCode = 200;
                ctx.ContentType = "application/javascript";                await ctx.WriteResponseAsync(_protocolDescriptor!.GenerateCliReference());
            }));

            BufferedLogger.LogInfo($"Binary transport initialized: {_binaryTransport.RegisteredHandlerCount} handlers in jump table, {_protocolDescriptor.Routes.Count} protocol routes");

            // Register WAL binary stream endpoint
            RegisterRoute("GET /bmw/wal/stream", new RouteHandlerData(null, async (BmwContext ctx) =>
            {
                if (DataStoreProvider.PrimaryProvider is not WalDataProvider walProv)
                {
                    ctx.StatusCode = 503;
                    await ctx.WriteResponseAsync("WAL provider not available");
                    return;
                }

                ctx.StatusCode = 200;
                ctx.ContentType = "application/octet-stream";

                var entity = ReadQueryParam(ctx.HttpRequest.QueryString.Value.AsSpan(), "entity".AsSpan());
                if (entity.Length > 0)
                {
                    await WalStreamWriter.StreamEntityAsync(
                        ctx.ResponseBody, walProv, entity.ToString(), ctx.RequestAborted);
                }
                else
                {
                    await WalStreamWriter.StreamAllAsync(
                        ctx.ResponseBody, walProv, ctx.RequestAborted);
                }
            }));
        }
    }

    /// <summary>Ensures the numeric route table is rebuilt when routes change.</summary>
    private void EnsureNumericRouteTable()
    {
        if (_numericRouteVersion != _routesVersion)
        {
            _numericRoutes.Build(routes);
            _numericRouteVersion = _routesVersion;
        }
    }

    /// <summary>Returns the numeric route table for metadata export.</summary>
    internal NumericRouteTable NumericRoutes => _numericRoutes;
    public Task WireUpRequestHandlingAndLoggerAsyncLifetime()
    {
        EnsureNumericRouteTable();
        EnsureJumpTable();
        EnsureRouteIdTable();
        EnsureBinaryTransport();
        StartBackgroundServices();
        BufferedLogger.LogInfo($"WireUpRequestHandlingAndLoggerAsyncLifetime completed and request handling is live.");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Prepares the server for direct Kestrel hosting via <see cref="BmwHost"/>.
    /// Identical to <see cref="WireUpRequestHandlingAndLoggerAsyncLifetime"/> —
    /// kept as a separate entry point for clarity.
    /// </summary>
    public Task WireUpDirectHosting()
    {
        EnsureNumericRouteTable();
        EnsureJumpTable();
        EnsureRouteIdTable();
        StartBackgroundServices();
        BufferedLogger.LogInfo("WireUpDirectHosting completed — ready for BmwHost.RunAsync().");
        return Task.CompletedTask;
    }

    private Task? _loggerTask;
    private readonly List<(string Name, Task Task)> _backgroundTasks = new();

    private void StartBackgroundServices()
    {
        _loggerTask = BufferedLogger.RunAsync(cts.Token);

        var clientPruneTask = ClientRequests.RunPruningAsync(cts.Token);
        _backgroundTasks.Add(("ClientRequestPruning", clientPruneTask));

        var todoPeriodicityTask = new TodoPeriodicityService(BufferedLogger).RunAsync(cts.Token);
        _backgroundTasks.Add(("TodoPeriodicity", todoPeriodicityTask));

        var scheduledActionTask = new ScheduledActionService(BufferedLogger).RunAsync(cts.Token);
        _backgroundTasks.Add(("ScheduledActions", scheduledActionTask));

        // WAL segment compaction background service
        if (DataStoreProvider.PrimaryProvider is WalDataProvider walProvider)
        {
            var compactionTask = new WalCompactor(walProvider.WalStore).RunAsync(cts.Token);
            _backgroundTasks.Add(("WalCompactor", compactionTask));
        }

        // Deployment target upgrade watcher
        var deployWatcherTask = new DeploymentWatcherService(BufferedLogger).RunAsync(cts.Token);
        _backgroundTasks.Add(("DeploymentWatcher", deployWatcherTask));

        // Control plane telemetry streaming
        if (ControlPlane is not null)
        {
            var cpTask = ControlPlane.RunAsync(cts.Token);
            _backgroundTasks.Add(("ControlPlane", cpTask));
        }
    }

    /// <summary>
    /// Waits for all background services to complete after cancellation has been
    /// requested, with a configurable timeout. Logs drain progress.
    /// </summary>
    public async Task DrainBackgroundServicesAsync(TimeSpan timeout)
    {
        var pending = _backgroundTasks.Where(t => !t.Task.IsCompleted).ToList();
        if (pending.Count == 0)
        {
            BufferedLogger.LogInfo("[Shutdown] No background services to drain.");
            Console.WriteLine("[BMW Shutdown] No background services to drain.");
            return;
        }

        Console.WriteLine($"[BMW Shutdown] Waiting for {pending.Count} background service(s) to drain: {string.Join(", ", pending.Select(t => t.Name))}");
        BufferedLogger.LogInfo($"[Shutdown] Draining {pending.Count} background services (timeout: {timeout.TotalSeconds}s)...");

        var allTasks = Task.WhenAll(pending.Select(t => t.Task));
        var completed = await Task.WhenAny(allTasks, Task.Delay(timeout)).ConfigureAwait(false);

        if (completed == allTasks)
        {
            Console.WriteLine($"[BMW Shutdown] All background services drained successfully.");
            BufferedLogger.LogInfo("[Shutdown] All background services drained.");
        }
        else
        {
            var stillRunning = _backgroundTasks.Where(t => !t.Task.IsCompleted).Select(t => t.Name).ToList();
            Console.WriteLine($"[BMW Shutdown] Drain timeout ({timeout.TotalSeconds}s) — {stillRunning.Count} service(s) still running: {string.Join(", ", stillRunning)}");
            BufferedLogger.LogInfo($"[Shutdown] Drain timeout — forcing shutdown with {stillRunning.Count} service(s) still running: {string.Join(", ", stillRunning)}");
        }

        // WAL checkpoint — ensure all pending writes are flushed
        if (DataStoreProvider.PrimaryProvider is WalDataProvider walProv)
        {
            try
            {
                walProv.WalStore.TakeSnapshot();
                Console.WriteLine("[BMW Shutdown] WAL snapshot checkpoint written.");
                BufferedLogger.LogInfo("[Shutdown] WAL snapshot checkpoint written.");
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                Console.WriteLine($"[BMW Shutdown] WAL checkpoint failed: {ex.Message}");
                BufferedLogger.LogError("[Shutdown] WAL checkpoint failed.", ex);
            }
        }
    }
    public async Task RequestHandler(BmwContext bmwCtx)
    {
        // ── Bench fast-paths: bypass entire pipeline for perf diagnostics ──
        // Static readonly bool lets JIT eliminate this branch in production.
        if (BenchmarkEndpoints.Enabled && BenchmarkEndpoints.TryHandle(bmwCtx))
            return;

        var stopwatch = Stopwatch.StartNew();
        Metrics.EnterRequest();

        // BmwContext already created by BmwApplication.CreateContext — zero double-creation
        string method = bmwCtx.Request.Method;
        string requestPath = bmwCtx.Request.Path;
        string routeKey = bmwCtx.Request.RouteKey;
        string sourceIp = bmwCtx.SourceIp;
        string rid = bmwCtx.CorrelationId;

        // Return correlation ID on every response for distributed tracing
        bmwCtx.ResponseHeaders["X-Trace-ID"] = rid;

        // ── Multitenancy: resolve tenant from Host header ─────────────────────
        // When enabled, sets DataStoreProvider.CurrentTenant for the duration of
        // this async call chain. Disposed at the end of the request.
        using var tenantScope = TenantRegistry?.ResolveForRequest(bmwCtx);

        bool isHttps = IsHttpsRequest(bmwCtx, TrustForwardedHeaders);
        // SECURITY: X-BareMetal-* diagnostic headers removed to avoid exposing internal
        // TLS termination architecture, redirect configuration, and HTTPS availability
        // to external clients. Re-enable gated behind a debug/development flag if needed.
        if (!isHttps && ShouldRedirectToHttps())
        {
            var httpsUrl = BuildHttpsRedirectUrl(bmwCtx, TrustForwardedHeaders, HttpsRedirectHost, HttpsRedirectPort);
            bmwCtx.StatusCode = StatusCodes.Status301MovedPermanently;
            bmwCtx.ResponseHeaders.Location = httpsUrl;
            BufferedLogger.Log(BmwLogLevel.Info, $"{routeKey}|301|redirect={httpsUrl}", rid, new LogFields { Method = method, Path = requestPath, StatusCode = 301, SourceIp = sourceIp, Detail = $"mode={HttpsRedirectMode}" });
            return;
        }
        ApplySecurityHeaders(bmwCtx, isHttps);

        if (ApplyCors(bmwCtx))
        {
            if (string.Equals(method, "OPTIONS", StringComparison.OrdinalIgnoreCase))
            {
                bmwCtx.StatusCode = StatusCodes.Status204NoContent;
                return;
            }
        }

        if (ClientRequests.ShouldThrottle(sourceIp, out var throttleReason, out var retryAfterSeconds))
        {
            if (retryAfterSeconds.HasValue)
            {
                bmwCtx.ResponseHeaders.RetryAfter = retryAfterSeconds.Value.ToString();
            }
            if (IsAjaxRequest(bmwCtx))
            {
                await ApiErrorWriter.WriteAsync(bmwCtx,
                    ApiErrorWriter.RateLimited(retryAfterSeconds: retryAfterSeconds),
                    bmwCtx.RequestAborted);
            }
            else
            {
                bmwCtx.StatusCode = StatusCodes.Status429TooManyRequests;
                bmwCtx.ContentType = "text/plain";
                await bmwCtx.WriteResponseAsync(retryAfterSeconds.HasValue
                    ? $"Too many Requests. Retry after {retryAfterSeconds.Value}s."
                    : "Too many Requests.");
            }
            BufferedLogger.Log(BmwLogLevel.Warn, $"{routeKey}|429|{throttleReason}", rid, new LogFields { Method = method, Path = requestPath, StatusCode = 429, SourceIp = sourceIp, Detail = throttleReason });
            stopwatch.Stop();
            Metrics.RecordThrottled(stopwatch.Elapsed);
            return;
        }
        try
        {
            if (await ShouldForceSetupAsync(requestPath, bmwCtx.RequestAborted).ConfigureAwait(false))
            {
                bmwCtx.StatusCode = StatusCodes.Status302Found;
                bmwCtx.ResponseHeaders.Location = "/setup";
                BufferedLogger.Log(BmwLogLevel.Info, $"{routeKey}|302|setup=required", rid, new LogFields { Method = method, Path = requestPath, StatusCode = 302, SourceIp = sourceIp });
                return;
            }

            if (await JsBundleService.TryServeAsync(bmwCtx))
            {
                BufferedLogger.Log(BmwLogLevel.Debug, $"{routeKey}|{bmwCtx.StatusCode}|bundle", rid, new LogFields { Method = method, Path = requestPath, StatusCode = bmwCtx.StatusCode, SourceIp = sourceIp, Detail = "bundle" });
                return;
            }

            if (await CssBundleService.TryServeAsync(bmwCtx))
            {
                BufferedLogger.Log(BmwLogLevel.Debug, $"{routeKey}|{bmwCtx.StatusCode}|css-bundle", rid, new LogFields { Method = method, Path = requestPath, StatusCode = bmwCtx.StatusCode, SourceIp = sourceIp, Detail = "css-bundle" });
                return;
            }

            if (await StaticFileService.TryServeAsync(bmwCtx, StaticFiles))
            {
                BufferedLogger.Log(BmwLogLevel.Debug, $"{routeKey}|{bmwCtx.StatusCode}|static", rid, new LogFields { Method = method, Path = requestPath, StatusCode = bmwCtx.StatusCode, SourceIp = sourceIp, Detail = "static" });
                return;
            }

            // Build the menu/session context now — only for actual page/API requests,
            // not for static assets (bundles, files) served above.
            await BuildAppInfoMenuOptionsAsync(bmwCtx, bmwCtx.RequestAborted).ConfigureAwait(false);

            // ── Per-identity API rate limiting (#1264) ──────────────────────
            if (requestPath.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
            {
                bool isWrite = !string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase);
                if (!ApiLimiter.TryAcquire(sourceIp, isWrite, out int apiRetryAfter))
                {
                    bmwCtx.ResponseHeaders.RetryAfter = apiRetryAfter.ToString();
                    if (IsAjaxRequest(bmwCtx))
                    {
                        await ApiErrorWriter.WriteAsync(bmwCtx,
                            ApiErrorWriter.RateLimited(retryAfterSeconds: apiRetryAfter),
                            bmwCtx.RequestAborted);
                    }
                    else
                    {
                        bmwCtx.StatusCode = StatusCodes.Status429TooManyRequests;
                        bmwCtx.ContentType = "text/plain";
                        await bmwCtx.WriteResponseAsync(
                            $"API rate limit exceeded. Retry after {apiRetryAfter}s.");
                    }
                    BufferedLogger.Log(BmwLogLevel.Warn,
                        $"{routeKey}|429|api-rate-limit|{(isWrite ? "write" : "read")}", rid,
                        new LogFields { Method = method, Path = requestPath, StatusCode = 429,
                            SourceIp = sourceIp, Detail = $"api-rate-limit:{(isWrite ? "write" : "read")}" });
                    stopwatch.Stop();
                    Metrics.RecordThrottled(stopwatch.Elapsed);
                    return;
                }
            }

            long dispatchStart = Stopwatch.GetTimestamp();
            // ── Numeric route ID dispatch: O(1) array lookup ────────────────
            // Paths like "/123" are parsed as route IDs for client-optimized dispatch.
            // Single branchless integer parse, single array index — no hashing, no strings.
            if (requestPath.Length > 1 && requestPath[1] >= '0' && requestPath[1] <= '9')
            {
                EnsureRouteIdTable();
                uint numericId = ParseRouteId(requestPath);
                if (numericId > 0 && numericId <= _maxRouteId)
                {
                    var idPage = _routeById[numericId];
                    if (idPage.Handler != null)
                    {
                        Metrics.RecordRouteDispatch(Stopwatch.GetElapsedTime(dispatchStart));
                        if (idPage.PageInfo != null)
                            bmwCtx.SetPageInfo(idPage.PageInfo);
                        bmwCtx.CompiledPlans = idPage.CompiledPlans;

                        // Hydrate route parameters from query string so handlers
                        // (GetRouteValue / GetRouteParam) work identically to path-based dispatch.
                        HydrateRouteParamsFromQuery(bmwCtx, idPage.RouteKey);

                        if (!await IsAuthorizedAsync(idPage.PageInfo, bmwCtx, bmwCtx.RequestAborted).ConfigureAwait(false))
                        {
                            await LogAccessDeniedAsync(routeKey, sourceIp, bmwCtx, idPage.PageInfo, bmwCtx.RequestAborted).ConfigureAwait(false);
                            await RenderForbidden(bmwCtx);
                            return;
                        }
                        await idPage.Handler(bmwCtx);
                        BufferedLogger.Log(BmwLogLevel.Info, $"/{numericId}|200|numeric", rid, new LogFields { Method = method, Path = requestPath, StatusCode = 200, SourceIp = sourceIp, Detail = "numeric-route" });
                        return;
                    }
                }
                // Numeric path but no matching route ID — return 404 immediately
                bmwCtx.StatusCode = StatusCodes.Status404NotFound;
                bmwCtx.ContentType = "text/plain";
                await bmwCtx.WriteResponseAsync($"Route ID {numericId} not found");
                BufferedLogger.Log(BmwLogLevel.Info, $"/{numericId}|404|numeric", rid, new LogFields { Method = method, Path = requestPath, StatusCode = 404, SourceIp = sourceIp, Detail = "numeric-route-not-found" });
                return;
            }

            // ── Jump table: O(1) exact-match dispatch ───────────────────────
            EnsureJumpTable();
            EnsurePrefixRouter();
            if (_jumpTable.TryLookup(routeKey, out RouteHandlerData page))
            {
                Metrics.RecordRouteDispatch(Stopwatch.GetElapsedTime(dispatchStart));
                if (page.PageInfo != null)
                {
                    bmwCtx.SetPageInfo(page.PageInfo);
                }
                bmwCtx.CompiledPlans = page.CompiledPlans;
                if (!await IsAuthorizedAsync(page.PageInfo, bmwCtx, bmwCtx.RequestAborted).ConfigureAwait(false))
                {
                    await LogAccessDeniedAsync(routeKey, sourceIp, bmwCtx, page.PageInfo, bmwCtx.RequestAborted).ConfigureAwait(false);
                    await RenderForbidden(bmwCtx);
                    return;
                }
                await page.Handler(bmwCtx);
                BufferedLogger.Log(BmwLogLevel.Info, $"{routeKey}|200", rid, new LogFields { Method = method, Path = requestPath, StatusCode = 200, SourceIp = sourceIp });
                return;
            }
            // Jump table also handles "ALL" verb routes (allocation-free concat lookup)
            if (_jumpTable.TryLookupConcat("ALL ", requestPath, out RouteHandlerData allPage))
            {
                Metrics.RecordRouteDispatch(Stopwatch.GetElapsedTime(dispatchStart));
                if (allPage.PageInfo != null)
                {
                    bmwCtx.SetPageInfo(allPage.PageInfo);
                }
                if (!await IsAuthorizedAsync(allPage.PageInfo, bmwCtx, bmwCtx.RequestAborted).ConfigureAwait(false))
                {
                    await LogAccessDeniedAsync(routeKey, sourceIp, bmwCtx, allPage.PageInfo, bmwCtx.RequestAborted).ConfigureAwait(false);
                    await RenderForbidden(bmwCtx);
                    return;
                }
                await allPage.Handler(bmwCtx);
                BufferedLogger.Log(BmwLogLevel.Info, $"{routeKey}|ALL {requestPath}|200", rid, new LogFields { Method = method, Path = requestPath, StatusCode = 200, SourceIp = sourceIp });
                return;
            }
            // ── Prefix router: O(1) entity dispatch for /api/{type} routes ──
            if (_prefixRouter.TryMatch(bmwCtx, out RouteHandlerData prefixPage))
            {
                Metrics.RecordRouteDispatch(Stopwatch.GetElapsedTime(dispatchStart));
                if (!await IsAuthorizedAsync(prefixPage.PageInfo, bmwCtx, bmwCtx.RequestAborted).ConfigureAwait(false))
                {
                    await LogAccessDeniedAsync(routeKey, sourceIp, bmwCtx, prefixPage.PageInfo, bmwCtx.RequestAborted).ConfigureAwait(false);
                    await RenderForbidden(bmwCtx);
                    return;
                }
                await prefixPage.Handler(bmwCtx);
                BufferedLogger.Log(BmwLogLevel.Info, $"{routeKey}|200|prefix", rid, new LogFields { Method = method, Path = requestPath, StatusCode = 200, SourceIp = sourceIp, Detail = "prefix" });
                return;
            }
            // Pattern match fallback— iterate most-specific routes first so that literal
            // segments (e.g. /api/_lookup/{type}) beat generic routes (e.g. /api/{type}/{id}).
            // Skip routes with no parameters (already covered by jump table).
            bool methodNotAllowed = false;
            var matchParams = new Dictionary<string, string>(8, StringComparer.Ordinal);
            // Pattern-match fallback: single pass handles both verb-specific and ALL routes.
            // Skip parameterless non-regex routes — those are already in the jump table.
            // Reuse one dictionary across all TryMatch calls to avoid per-call allocations.
            foreach (var (_, routeData, compiled) in GetSortedRoutes())
            {
                if (!compiled.IsRegex && compiled.ParameterCount == 0) continue;

                if (RouteMatching.TryMatch(requestPath, compiled, matchParams))
                {
                    if (!compiled.Verb.Equals(method, StringComparison.OrdinalIgnoreCase) &&
                        !compiled.Verb.Equals("ALL", StringComparison.OrdinalIgnoreCase))
                    {
                        methodNotAllowed = true;
                        continue;
                    }
                    Metrics.RecordRouteDispatch(Stopwatch.GetElapsedTime(dispatchStart));
                    var injectedPage = RouteInfoHelpers.InjectRouteParametersIntoPageInfo(routeData, matchParams);
                    if (injectedPage.PageInfo != null)
                    {
                        bmwCtx.SetPageInfo(injectedPage.PageInfo);
                    }
                    if (!await IsAuthorizedAsync(injectedPage.PageInfo, bmwCtx, bmwCtx.RequestAborted).ConfigureAwait(false))
                    {
                        await LogAccessDeniedAsync(routeKey, sourceIp, bmwCtx, injectedPage.PageInfo, bmwCtx.RequestAborted).ConfigureAwait(false);
                        await RenderForbidden(bmwCtx);
                        return;
                    }
                    await injectedPage.Handler(bmwCtx);
                    var paramParts = new string[matchParams.Count];
                    int paramIdx = 0;
                    foreach (var p in matchParams)
                        paramParts[paramIdx++] = $"{p.Key}={p.Value}";
                    BufferedLogger.Log(BmwLogLevel.Info, $"{routeKey}|{method}|{compiled.Verb}|{string.Join(", ", paramParts)}|200", rid, new LogFields { Method = method, Path = requestPath, StatusCode = 200, SourceIp = sourceIp });
                    return;
                }
            }
            if (methodNotAllowed)
            {
                Metrics.RecordRouteDispatch(Stopwatch.GetElapsedTime(dispatchStart));
                bmwCtx.StatusCode = StatusCodes.Status405MethodNotAllowed;
                bmwCtx.SetPageInfo(ErrorPageInfo);
                await HtmlRenderer.RenderPage(bmwCtx);
                BufferedLogger.Log(BmwLogLevel.Warn, $"{routeKey}|405", rid, new LogFields { Method = method, Path = requestPath, StatusCode = 405, SourceIp = sourceIp });
                return;
            }
            Metrics.RecordRouteDispatch(Stopwatch.GetElapsedTime(dispatchStart));
            bmwCtx.SetPageInfo(NotFoundPageInfo);
            await HtmlRenderer.RenderPage(bmwCtx);
            BufferedLogger.Log(BmwLogLevel.Info, $"{routeKey}|404", rid, new LogFields { Method = method, Path = requestPath, StatusCode = 404, SourceIp = sourceIp });
        }
        catch (OperationCanceledException oce)
        {
            BufferedLogger.Log(BmwLogLevel.Debug, $"Client disconnected:{routeKey}|{oce.Message}", rid);
        }
        catch (Exception ex)
        {
            var errorId = Guid.NewGuid().ToString("N");
            BufferedLogger.LogError($"Exception: {routeKey} | ErrorId={errorId}", ex, rid);
            if (bmwCtx.HasResponseStarted)
            {
                bmwCtx.Abort();
                return;
            }
            bmwCtx.ClearResponse();
            if (IsAjaxRequest(bmwCtx))
            {
                await ApiErrorWriter.WriteAsync(bmwCtx,
                    ApiErrorWriter.InternalError(errorId),
                    bmwCtx.RequestAborted);
            }
            else
            {
                bmwCtx.StatusCode = StatusCodes.Status500InternalServerError;
                bmwCtx.ResponseHeaders["X-Error-Id"] = errorId;
                bmwCtx.SetPageInfo(ErrorPageInfo);
                bmwCtx.SetStringValue("html_message", $"<p>An unexpected error occurred.</p><p>Error ID: <code>{errorId}</code></p>");
                await HtmlRenderer.RenderPage(bmwCtx);
            }
            BufferedLogger.Log(BmwLogLevel.Error, $"{routeKey}|500|ErrorId={errorId}", rid, new LogFields { Method = method, Path = requestPath, StatusCode = 500, SourceIp = sourceIp, Detail = errorId });
        }
        finally
        {
            Metrics.LeaveRequest();
            stopwatch.Stop();
            var statusCode = bmwCtx.StatusCode;
            Metrics.RecordRequest(statusCode, stopwatch.Elapsed);
        }
    }

    private static bool IsAjaxRequest(BmwContext context) =>
        context.RequestHeaders.ContainsKey("X-Requested-With") ||
        context.Request.Path.StartsWith("/api", StringComparison.OrdinalIgnoreCase);

    private static bool TryParseRoute(string route, out string verb, out string path)
    {
        verb = string.Empty;
        path = string.Empty;

        if (string.IsNullOrWhiteSpace(route))
            return false;

        int spaceIndex = route.IndexOf(' ');
        if (spaceIndex <= 0 || spaceIndex >= route.Length - 1)
            return false;

        verb = route[..spaceIndex].Trim();
        path = route[(spaceIndex + 1)..].Trim();

        if (string.IsNullOrWhiteSpace(verb) || string.IsNullOrWhiteSpace(path))
            return false;

        return true;
    }

    /// <summary>
    /// Branchless ASCII integer parse from a path like "/123" or "/42?query".
    /// Stops at the first non-digit after the leading '/'. Returns 0 on failure.
    /// </summary>
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    private static uint ParseRouteId(string path)
    {
        uint id = 0;
        for (int i = 1; i < path.Length; i++)
        {
            uint d = (uint)(path[i] - '0');
            if (d > 9) break; // stop at '?', '/', ' ', or any non-digit
            id = id * 10 + d;
            if (id > ushort.MaxValue) return 0; // overflow guard
        }
        return id;
    }

    /// <summary>
    /// Allocation-free query string parameter reader (Span overload).
    /// Scans the raw query string for <paramref name="key"/> and returns its value.
    /// </summary>
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    internal static ReadOnlySpan<char> ReadQueryParam(ReadOnlySpan<char> query, ReadOnlySpan<char> key)
    {
        if (query.IsEmpty) return ReadOnlySpan<char>.Empty;
        // Skip leading '?'
        if (query[0] == '?') query = query.Slice(1);

        while (!query.IsEmpty)
        {
            int ampIdx = query.IndexOf('&');
            ReadOnlySpan<char> pair = ampIdx >= 0 ? query.Slice(0, ampIdx) : query;

            int eqIdx = pair.IndexOf('=');
            if (eqIdx >= 0)
            {
                var pairKey = pair.Slice(0, eqIdx);
                if (pairKey.SequenceEqual(key))
                    return pair.Slice(eqIdx + 1);
            }

            if (ampIdx < 0) break;
            query = query.Slice(ampIdx + 1);
        }
        return ReadOnlySpan<char>.Empty;
    }

    /// <summary>
    /// Populates BmwContext route parameter fields from the query string
    /// when dispatching via numeric route ID. Uses the CompiledRoute segments
    /// to map query keys → EntitySlug, EntityId, RouteExtra, or RouteParameters.
    /// </summary>
    internal void HydrateRouteParamsFromQuery(BmwContext ctx, string? routeKey)
    {
        if (routeKey == null || !_compiledRoutes.TryGetValue(routeKey, out var compiled))
            return;
        if (compiled.ParameterCount == 0)
            return;

        var qs = ctx.Request.QueryString;
        if (qs.Length <= 1) // empty or just "?"
            return;

        foreach (var seg in compiled.Segments)
        {
            if (seg.Kind != RouteSegmentKind.Parameter && seg.Kind != RouteSegmentKind.CatchAll)
                continue;

            var val = ReadQueryParam(qs, seg.Value);
            if (val == null)
                continue;

            if (seg.Value == "type")
                ctx.EntitySlug = val;
            else if (seg.Value == "id")
                ctx.EntityId = val;
            else
            {
                ctx.RouteParameters ??= new Dictionary<string, string>(compiled.ParameterCount);
                ctx.RouteParameters[seg.Value] = val;
            }
        }
    }

    /// <summary>
    /// Reads a single query parameter value from a raw query string without allocating
    /// an IQueryCollection. Returns null if not found.
    /// </summary>
    internal static string? ReadQueryParam(string qs, string key)
    {
        // qs starts with '?', scan for key=value pairs separated by '&'
        int pos = 1; // skip '?'
        while (pos < qs.Length)
        {
            int ampIdx = qs.IndexOf('&', pos);
            int end = ampIdx < 0 ? qs.Length : ampIdx;

            int eqIdx = qs.IndexOf('=', pos);
            if (eqIdx >= pos && eqIdx < end)
            {
                var k = qs.AsSpan(pos, eqIdx - pos);
                if (k.Equals(key.AsSpan(), StringComparison.OrdinalIgnoreCase))
                    return Uri.UnescapeDataString(qs.Substring(eqIdx + 1, end - eqIdx - 1));
            }

            pos = end + 1;
        }
        return null;
    }

    private static async ValueTask<bool> IsAuthorizedAsync(PageInfo? pageInfo, BmwContext context, CancellationToken cancellationToken = default)
    {
        if (pageInfo == null)
            return true;

        var permissionsNeeded = pageInfo.PageMetaData.PermissionsNeeded ?? string.Empty;
        // Empty permissions means public/anonymous access is allowed
        if (string.IsNullOrWhiteSpace(permissionsNeeded))
            return true;

        if (string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase))
            return true;

        var user = await UserAuth.GetRequestUserAsync(context, cancellationToken).ConfigureAwait(false);
        bool isAnonymous = user == null;

        if (string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase))
            return isAnonymous;

        if (string.Equals(permissionsNeeded, "Authenticated", StringComparison.OrdinalIgnoreCase))
            return !isAnonymous;

        // Parse required permissions with span-based iteration to avoid string[] allocation
        if (isAnonymous)
        {
            // Quick check: if there are any non-empty segments, anonymous users can't pass
            var check = permissionsNeeded.AsSpan();
            bool hasAnyPerm = false;
            while (check.Length > 0)
            {
                int ci = check.IndexOf(',');
                ReadOnlySpan<char> seg;
                if (ci < 0) { seg = check; check = default; }
                else { seg = check[..ci]; check = check[(ci + 1)..]; }
                if (!seg.Trim().IsEmpty) { hasAnyPerm = true; break; }
            }
            return !hasAnyPerm;
        }

        var userPermissions = new HashSet<string>(UserAuth.GetPermissions(user), StringComparer.OrdinalIgnoreCase);
        var altLookup = userPermissions.GetAlternateLookup<ReadOnlySpan<char>>();

        var remaining = permissionsNeeded.AsSpan();
        bool foundAny = false;
        while (remaining.Length > 0)
        {
            int idx = remaining.IndexOf(',');
            ReadOnlySpan<char> segment;
            if (idx < 0) { segment = remaining; remaining = default; }
            else { segment = remaining[..idx]; remaining = remaining[(idx + 1)..]; }
            var trimmed = segment.Trim();
            if (trimmed.IsEmpty) continue;
            foundAny = true;
            if (!altLookup.Contains(trimmed))
                return false;
        }
        if (!foundAny)
            return true; // No actual permissions after parsing, treat as public
        return true;
    }

    private static async ValueTask<bool> RootUserExistsAsync(CancellationToken cancellationToken = default)
    {
        var users = await UserAuth.QueryUsersAsync(RootUserQuery, cancellationToken).ConfigureAwait(false);
        foreach (var _ in users)
            return true;
        return false;
    }

    private async ValueTask<bool> ShouldForceSetupAsync(string requestPath, CancellationToken cancellationToken = default)
    {
        if (await RootUserExistsAsync(cancellationToken).ConfigureAwait(false))
            return false;

        if (requestPath.StartsWith("/setup", StringComparison.OrdinalIgnoreCase))
            return false;

        // Allow API calls through so background-job polling (and other API requests)
        // continue to work even when all users have been wiped (e.g. wipe-all-data job).
        if (requestPath.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
            return false;

        // Health/readiness probes and Prometheus scrape must always be reachable
        if (requestPath.Equals("/health", StringComparison.OrdinalIgnoreCase)
            || requestPath.Equals("/healthz", StringComparison.OrdinalIgnoreCase)
            || requestPath.Equals("/readyz", StringComparison.OrdinalIgnoreCase)
            || requestPath.Equals("/metrics/prometheus", StringComparison.OrdinalIgnoreCase)
            || requestPath.StartsWith("/bmw/", StringComparison.OrdinalIgnoreCase))
            return false;

        // Numeric route IDs (e.g. /42) must always be reachable
        if (requestPath.Length > 1 && requestPath[1] >= '0' && requestPath[1] <= '9')
            return false;

        var staticPrefix = StaticFiles?.NormalizedRequestPathPrefix;
        if (string.IsNullOrWhiteSpace(staticPrefix))
            staticPrefix = StaticFiles?.RequestPathPrefix;

        if (!string.IsNullOrWhiteSpace(staticPrefix)
            && requestPath.StartsWith(staticPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }

    private async ValueTask LogAccessDeniedAsync(string path, string sourceIp, BmwContext context, PageInfo? pageInfo, CancellationToken cancellationToken = default)
    {
        var user = await UserAuth.GetRequestUserAsync(context, cancellationToken).ConfigureAwait(false);
        var userName = UserAuth.GetUserName(user) ?? "anonymous";
        var required = pageInfo?.PageMetaData.PermissionsNeeded ?? string.Empty;
        BufferedLogger.LogInfo($"{path}|403|{sourceIp}|user={userName}|required={required}");
    }

    private static void ApplySecurityHeaders(BmwContext context, bool isHttps)
    {
        var nonce = context.GetCspNonce();
        context.ResponseHeaders["Content-Security-Policy"] = string.Format(ContentSecurityPolicyTemplate, nonce);
        context.ResponseHeaders["X-Content-Type-Options"] = "nosniff";
        context.ResponseHeaders["X-Frame-Options"] = "DENY";
        context.ResponseHeaders["Referrer-Policy"] = "strict-origin-when-cross-origin";
        context.ResponseHeaders["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
        if (isHttps)
            context.ResponseHeaders["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload";
        // HTTP/1.x keep-alive hint — skip for HTTP/2+ (connection multiplexing makes it unnecessary)
        if (!context.RequestProtocol.StartsWith("HTTP/2", StringComparison.OrdinalIgnoreCase)
            && !context.RequestProtocol.StartsWith("HTTP/3", StringComparison.OrdinalIgnoreCase))
            context.ResponseHeaders["Keep-Alive"] = "timeout=60, max=1000";
    }

    public async Task RenderForbidden(BmwContext context)
    {
        if (IsAjaxRequest(context))
        {
            await ApiErrorWriter.WriteAsync(context,
                ApiErrorWriter.Forbidden(),
                context.RequestAborted);
            return;
        }

        context.StatusCode = StatusCodes.Status403Forbidden;

        PageInfo forbiddenPage = ErrorPageInfo with
        {
            PageMetaData = ErrorPageInfo.PageMetaData with
            {
                StatusCode = StatusCodes.Status403Forbidden
            },
            PageContext = ErrorPageInfo.PageContext with
            {
                PageMetaDataValues = new[] { "403 - Forbidden", "<p>Access denied.</p>" }
            }
        };
        context.SetPageInfo(forbiddenPage);
        await HtmlRenderer.RenderPage(context);
    }

    private bool ApplyCors(BmwContext context)
    {
        var origin = context.RequestHeaders.Origin.ToString();
        if (string.IsNullOrWhiteSpace(origin))
            return false;

        if (CorsAllowedOrigins.Length == 0)
            return false;

        bool allowAny = false;
        for (int i = 0; i < CorsAllowedOrigins.Length; i++)
        {
            if (CorsAllowedOrigins[i] == "*")
            {
                allowAny = true;
                break;
            }
        }
        bool allowOrigin = allowAny;
        if (!allowOrigin)
        {
            for (int i = 0; i < CorsAllowedOrigins.Length; i++)
            {
                if (string.Equals(CorsAllowedOrigins[i], origin, StringComparison.OrdinalIgnoreCase))
                {
                    allowOrigin = true;
                    break;
                }
            }
        }
        if (!allowOrigin)
            return false;

        context.ResponseHeaders.AccessControlAllowOrigin = allowAny ? "*" : origin;
        context.ResponseHeaders.Append("Vary", "Origin");
        context.ResponseHeaders.AccessControlAllowMethods = string.Join(", ", CorsAllowedMethods);
        context.ResponseHeaders.AccessControlAllowHeaders = string.Join(", ", CorsAllowedHeaders);
        context.ResponseHeaders.AccessControlMaxAge = "600";
        return true;
    }

    private bool ShouldRedirectToHttps()
    {
        return HttpsRedirectMode switch
        {
            HttpsRedirectMode.Off => false,
            HttpsRedirectMode.Always => true,
            HttpsRedirectMode.IfAvailable => HttpsEndpointAvailable || TrustForwardedHeaders,
            _ => true
        };
    }

    private static bool IsHttpsRequest(BmwContext context, bool trustForwardedHeaders)
    {
        if (context.IsHttps)
            return true;

        if (!trustForwardedHeaders)
            return false;

        if (TryGetForwardedHeaderValue(context, "X-Forwarded-Proto", out var proto))
        {
            var value = GetFirstForwardedValue(proto);
            return string.Equals(value, "https", StringComparison.OrdinalIgnoreCase);
        }

        if (TryGetForwardedProtoFromForwardedHeader(context, out var forwardedProto))
        {
            return string.Equals(forwardedProto, "https", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    private static string BuildHttpsRedirectUrl(BmwContext context, bool trustForwardedHeaders, string? redirectHost, int? redirectPort)
    {
        var hostHeader = context.RequestHeaders.Host.ToString();
        var host = string.IsNullOrEmpty(hostHeader) ? new HostString("localhost") : HostString.FromUriComponent(hostHeader);

        if (trustForwardedHeaders)
        {
            if (TryGetForwardedHost(context, out var forwardedHost))
            {
                host = forwardedHost;
            }
        }

        if (!string.IsNullOrWhiteSpace(redirectHost))
        {
            host = redirectPort.HasValue
                ? new HostString(redirectHost, redirectPort.Value)
                : new HostString(redirectHost);
        }
        else if (redirectPort.HasValue)
        {
            host = new HostString(host.Host, redirectPort.Value);
        }

        var builder = new UriBuilder
        {
            Scheme = "https",
            Host = host.Host,
            Path = context.Request.Path,
            Query = context.Request.QueryString
        };

        int? port = host.Port;
        if (!port.HasValue && trustForwardedHeaders && TryGetForwardedPort(context, out var forwardedPort))
        {
            port = forwardedPort;
        }

        if (port.HasValue)
        {
            var normalized = port.Value == 80 ? 443 : port.Value;
            builder.Port = normalized;
        }

        return builder.Uri.ToString();
    }

    private static string BuildMenuCacheKey(BaseDataObject? user, int routesVersion)
    {
        if (user == null)
            return $"anon|routes:{routesVersion}";

        var perms = UserAuth.GetPermissions(user);
        var permString = perms.Length == 0
            ? string.Empty
            : string.Join(',', perms);
        return $"user:{user.Key}|mfa:{UserAuth.IsMfaEnabled(user)}|perms:{permString}|routes:{routesVersion}";
    }

    private static string ComputePrivacyPolicyLink(string url) =>
        string.IsNullOrWhiteSpace(url) ? string.Empty
        : $"<a href=\"{System.Net.WebUtility.HtmlEncode(url)}\" class=\"text-white-50 ms-2\">Privacy Policy</a>";

    private readonly record struct MenuCacheEntry(IMenuOption[] Options, DateTime ExpiresUtc);

    private void ScavengeMenuCache()
    {
        var now = DateTime.UtcNow;
        if ((now - _lastMenuCacheScavenge).TotalSeconds < 15) return;
        _lastMenuCacheScavenge = now;

        // Evict all expired entries
        foreach (var kvp in _menuCache)
        {
            if (kvp.Value.ExpiresUtc < now)
                _menuCache.TryRemove(kvp.Key, out _);
        }

        // Hard cap: if still over limit, evict oldest entries
        if (_menuCache.Count > MaxMenuCacheEntries)
        {
            foreach (var kvp in _menuCache.OrderBy(x => x.Value.ExpiresUtc))
            {
                _menuCache.TryRemove(kvp.Key, out _);
                if (_menuCache.Count <= MaxMenuCacheEntries) break;
            }
        }
    }

    private static bool TryGetForwardedHost(BmwContext context, out HostString host)
    {
        host = default;
        if (!TryGetForwardedHeaderValue(context, "X-Forwarded-Host", out var value))
            return false;

        var first = GetFirstForwardedValue(value);
        if (string.IsNullOrWhiteSpace(first))
            return false;

        host = HostString.FromUriComponent(first);
        return true;
    }

    private static bool TryGetForwardedPort(BmwContext context, out int port)
    {
        port = 0;
        if (!TryGetForwardedHeaderValue(context, "X-Forwarded-Port", out var value))
            return false;

        var first = GetFirstForwardedValue(value);
        return int.TryParse(first, out port);
    }

    private static bool TryGetForwardedHeaderValue(BmwContext context, string headerName, out string value)
    {
        value = string.Empty;
        if (!context.RequestHeaders.TryGetValue(headerName, out var values))
            return false;

        value = values.ToString();
        return !string.IsNullOrWhiteSpace(value);
    }

    private static string GetFirstForwardedValue(string headerValue)
    {
        var commaIndex = headerValue.IndexOf(',');
        return commaIndex >= 0 ? headerValue.Substring(0, commaIndex).Trim() : headerValue.Trim();
    }

    private static bool TryGetForwardedProtoFromForwardedHeader(BmwContext context, out string proto)
    {
        proto = string.Empty;
        if (!TryGetForwardedHeaderValue(context, "Forwarded", out var forwarded))
            return false;

        var first = GetFirstForwardedValue(forwarded);
        var remaining = first.AsSpan();
        while (remaining.Length > 0)
        {
            int semiIdx = remaining.IndexOf(';');
            ReadOnlySpan<char> part;
            if (semiIdx < 0) { part = remaining; remaining = default; }
            else { part = remaining[..semiIdx]; remaining = remaining[(semiIdx + 1)..]; }
            var trimmedPart = part.Trim();
            if (trimmedPart.IsEmpty) continue;

            var idx = trimmedPart.IndexOf('=');
            if (idx <= 0)
                continue;

            var key = trimmedPart[..idx].Trim();
            if (!key.Equals("proto".AsSpan(), StringComparison.OrdinalIgnoreCase))
                continue;

            proto = trimmedPart[(idx + 1)..].Trim().Trim('"').ToString();
            return !string.IsNullOrWhiteSpace(proto);
        }

        return false;
    }
}
