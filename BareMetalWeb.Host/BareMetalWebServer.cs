using System.Diagnostics;
using System.Reflection;
using Microsoft.AspNetCore.Http;
using BareMetalWeb.Data;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core;

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
            new QueryClause { Field = nameof(User.Permissions), Operator = QueryOperator.Contains, Value = "admin" },
            new QueryClause { Field = nameof(User.Permissions), Operator = QueryOperator.Contains, Value = "monitoring" }
        }
    };
    public BmwConfig Configuration { get; }
    public string ContentRootPath { get; }
    public IBufferedLogger BufferedLogger { get; }
    public IMetricsTracker Metrics { get; }
    public IClientRequestTracker ClientRequests { get; }
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
    /// When multitenancy is enabled, this registry resolves the correct per-tenant
    /// data store at the start of each request based on the HTTP Host header.
    /// Null (default) means multitenancy is disabled and the system store is used for all requests.
    /// </summary>
    public TenantRegistry? TenantRegistry { get; set; }
    private readonly Dictionary<string, MenuCacheEntry> _menuCache = new(StringComparer.Ordinal);
    private int _routesVersion = 0;
    private readonly Dictionary<string, CompiledRoute> _compiledRoutes = new(StringComparer.Ordinal);
    private List<(string Key, RouteHandlerData Data, CompiledRoute Compiled)>? _sortedRoutes;
    private int _sortedRoutesVersion = -1;
    private readonly RouteJumpTable _jumpTable = new();
    private int _jumpTableVersion = -1;
    private readonly PrefixRouter _prefixRouter = new();
    private int _prefixRouterVersion = -1;
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
        var rawVersion = typeof(BareMetalWebServer).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
            ?? typeof(BareMetalWebServer).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
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
        MenuOptionsList.Clear();
        var user = context != null ? await UserAuth.GetUserAsync(context, cancellationToken).ConfigureAwait(false) : null;
        bool isAnonymous = user == null;
        var userPermissions = new HashSet<string>(user?.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);

        if (context != null)
        {
            var cacheKey = BuildMenuCacheKey(user, _routesVersion);
            if (_menuCache.TryGetValue(cacheKey, out var cached) && cached.ExpiresUtc > DateTime.UtcNow)
            {
                MenuOptionsList = new List<IMenuOption>(cached.Options);
                return;
            }

            _menuCache.Remove(cacheKey);
        }
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

            if (user != null && user.MfaEnabled && path.Equals("/account/mfa", StringComparison.OrdinalIgnoreCase))
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

            MenuOptionsList.Add(new MenuOption(
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

            MenuOptionsList.Add(new MenuOption(
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
            MenuOptionsList.Add(new MenuOption(
                href: "/logout",
                label: "Logout",
                showOnNavBar: true,
                rightAligned: true,
                highlightAsButton: true,
                colorClass: "btn-warning"));
        }

        var loginIndex = MenuOptionsList.FindIndex(option => string.Equals(option.Href, "/login", StringComparison.OrdinalIgnoreCase));
        if (loginIndex >= 0)
        {
            var loginOption = MenuOptionsList[loginIndex];
            MenuOptionsList.RemoveAt(loginIndex);
            MenuOptionsList.Add(loginOption);
        }

        if (context != null)
        {
            var cacheKey = BuildMenuCacheKey(user, _routesVersion);
            _menuCache[cacheKey] = new MenuCacheEntry(MenuOptionsList.ToArray(), DateTime.UtcNow.Add(MenuCacheTtl));
        }
    }
    public delegate Task BareMetalRequestDelegate(HttpContext ctx, IHtmlRenderer renderer, PageInfo page, BareMetalWebServer app, IOutputCache cache);
    public void RegisterRoute(string path, RouteHandlerData routeHandler)
    {
        routes[path] = routeHandler;
        _compiledRoutes[path] = new CompiledRoute(path);
        _routesVersion++;
        _sortedRoutes = null; // invalidate sorted cache
        BufferedLogger.LogInfo($"Route registered: {path} with handler {routeHandler.Handler.Method.Name}");
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
    public Task WireUpRequestHandlingAndLoggerAsyncLifetime()
    {
        EnsureJumpTable();
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
        EnsureJumpTable();
        StartBackgroundServices();
        BufferedLogger.LogInfo("WireUpDirectHosting completed — ready for BmwHost.RunAsync().");
        return Task.CompletedTask;
    }

    private Task? _loggerTask;
    private void StartBackgroundServices()
    {
        _loggerTask = BufferedLogger.RunAsync(cts.Token);
        Task clientPruneTask = ClientRequests.RunPruningAsync(cts.Token);
        Task todoPeriodicityTask = new TodoPeriodicityService(BufferedLogger).RunAsync(cts.Token);
        Task scheduledActionTask = new ScheduledActionService(BufferedLogger).RunAsync(cts.Token);
        _ = clientPruneTask;
        _ = todoPeriodicityTask;
        _ = scheduledActionTask;

        // WAL segment compaction background service
        if (DataStoreProvider.PrimaryProvider is WalDataProvider walProvider)
        {
            Task compactionTask = new WalCompactor(walProvider.WalStore).RunAsync(cts.Token);
            _ = compactionTask;
        }
    }
    public async Task RequestHandler(HttpContext context)
    {
        // ── Bench fast-paths: bypass entire pipeline for perf diagnostics ──
        // Static readonly bool lets JIT eliminate this branch in production.
        if (BenchmarkEndpoints.Enabled && BenchmarkEndpoints.TryHandle(context))
            return;

        var stopwatch = Stopwatch.StartNew();

        // ── Create BmwContext: resolve features once per request ─────────
        var bmwCtx = BmwContext.CreateFrom(context, this);
        string method = bmwCtx.Request.Method;
        string requestPath = bmwCtx.Request.Path;
        string routeKey = bmwCtx.Request.RouteKey;
        string sourceIp = bmwCtx.SourceIp;
        bmwCtx.SetApp(this);

        // ── Multitenancy: resolve tenant from Host header ─────────────────────
        // When enabled, sets DataStoreProvider.CurrentTenant for the duration of
        // this async call chain. Disposed at the end of the request.
        using var tenantScope = TenantRegistry?.ResolveForRequest(context);

        bool isHttps = IsHttpsRequest(context, TrustForwardedHeaders);
        // SECURITY: X-BareMetal-* diagnostic headers removed to avoid exposing internal
        // TLS termination architecture, redirect configuration, and HTTPS availability
        // to external clients. Re-enable gated behind a debug/development flag if needed.
        if (!isHttps && ShouldRedirectToHttps())
        {
            var httpsUrl = BuildHttpsRedirectUrl(context, TrustForwardedHeaders, HttpsRedirectHost, HttpsRedirectPort);
            context.Response.StatusCode = StatusCodes.Status301MovedPermanently;
            context.Response.Headers.Location = httpsUrl;
            BufferedLogger.LogInfo($"{routeKey}|301|{sourceIp}|redirect={httpsUrl}|mode={HttpsRedirectMode}|httpsAvailable={HttpsEndpointAvailable}|trustForwarded={TrustForwardedHeaders}|host={context.Request.Host}");
            return;
        }
        ApplySecurityHeaders(context, isHttps);

        if (ApplyCors(context))
        {
            if (string.Equals(method, "OPTIONS", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                return;
            }
        }

        if (ClientRequests.ShouldThrottle(sourceIp, out var throttleReason, out var retryAfterSeconds))
        {
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            if (retryAfterSeconds.HasValue)
            {
                context.Response.Headers.RetryAfter = retryAfterSeconds.Value.ToString();
            }
            context.Response.ContentType = "text/plain";
            var retryText = retryAfterSeconds.HasValue
                ? $"Too many Requests. Retry after {retryAfterSeconds.Value}s."
                : "Too many Requests.";
            await context.Response.WriteAsync(retryText);
            BufferedLogger.LogInfo($"{routeKey}|429|{sourceIp}|{throttleReason}");
            stopwatch.Stop();
            Metrics.RecordThrottled(stopwatch.Elapsed);
            return;
        }
        try
        {
            if (await ShouldForceSetupAsync(requestPath, context.RequestAborted).ConfigureAwait(false))
            {
                context.Response.StatusCode = StatusCodes.Status302Found;
                context.Response.Headers.Location = "/setup";
                BufferedLogger.LogInfo($"{routeKey}|302|{sourceIp}|setup=required");
                return;
            }

            if (await JsBundleService.TryServeAsync(bmwCtx))
            {
                BufferedLogger.LogInfo($"{routeKey}|{context.Response.StatusCode}|{sourceIp}|bundle");
                return;
            }

            if (await CssBundleService.TryServeAsync(bmwCtx))
            {
                BufferedLogger.LogInfo($"{routeKey}|{context.Response.StatusCode}|{sourceIp}|css-bundle");
                return;
            }

            if (await StaticFileService.TryServeAsync(bmwCtx, StaticFiles))
            {
                BufferedLogger.LogInfo($"{routeKey}|{context.Response.StatusCode}|{sourceIp}|static");
                return;
            }

            // Build the menu/session context now — only for actual page/API requests,
            // not for static assets (bundles, files) served above.
            await BuildAppInfoMenuOptionsAsync(bmwCtx, context.RequestAborted).ConfigureAwait(false);

            var dispatchSw = Stopwatch.StartNew();
            // ── Jump table: O(1) exact-match dispatch ───────────────────────
            EnsureJumpTable();
            EnsurePrefixRouter();
            if (_jumpTable.TryLookup(routeKey, out RouteHandlerData page))
            {
                if (page.PageInfo != null)
                {
                    bmwCtx.SetPageInfo(page.PageInfo);
                }
                if (!await IsAuthorizedAsync(page.PageInfo, bmwCtx, context.RequestAborted).ConfigureAwait(false))
                {
                    await LogAccessDeniedAsync(routeKey, sourceIp, bmwCtx, page.PageInfo, context.RequestAborted).ConfigureAwait(false);
                    await RenderForbidden(bmwCtx);
                    dispatchSw.Stop();
                    Metrics.RecordRouteDispatch(dispatchSw.Elapsed);
                    return;
                }
                await page.Handler(bmwCtx);
                BufferedLogger.LogInfo($"{routeKey}|200|{sourceIp}");
                dispatchSw.Stop();
                Metrics.RecordRouteDispatch(dispatchSw.Elapsed);
                return;
            }
            // Jump table also handles "ALL" verb routes
            if (_jumpTable.TryLookup(string.Concat("ALL ", requestPath), out RouteHandlerData allPage))
            {
                if (allPage.PageInfo != null)
                {
                    bmwCtx.SetPageInfo(allPage.PageInfo);
                }
                if (!await IsAuthorizedAsync(allPage.PageInfo, bmwCtx, context.RequestAborted).ConfigureAwait(false))
                {
                    await LogAccessDeniedAsync(routeKey, sourceIp, bmwCtx, allPage.PageInfo, context.RequestAborted).ConfigureAwait(false);
                    await RenderForbidden(bmwCtx);
                    dispatchSw.Stop();
                    Metrics.RecordRouteDispatch(dispatchSw.Elapsed);
                    return;
                }
                await allPage.Handler(bmwCtx);
                BufferedLogger.LogInfo($"{routeKey}|ALL {requestPath}|200|{sourceIp}");
                dispatchSw.Stop();
                Metrics.RecordRouteDispatch(dispatchSw.Elapsed);
                return;
            }
            // ── Prefix router: O(1) entity dispatch for /api/{type} routes ──
            if (_prefixRouter.TryMatch(bmwCtx, out RouteHandlerData prefixPage))
            {
                if (!await IsAuthorizedAsync(prefixPage.PageInfo, bmwCtx, context.RequestAborted).ConfigureAwait(false))
                {
                    await LogAccessDeniedAsync(routeKey, sourceIp, bmwCtx, prefixPage.PageInfo, context.RequestAborted).ConfigureAwait(false);
                    await RenderForbidden(bmwCtx);
                    dispatchSw.Stop();
                    Metrics.RecordRouteDispatch(dispatchSw.Elapsed);
                    return;
                }
                await prefixPage.Handler(bmwCtx);
                BufferedLogger.LogInfo($"{routeKey}|200|{sourceIp}|prefix");
                dispatchSw.Stop();
                Metrics.RecordRouteDispatch(dispatchSw.Elapsed);
                return;
            }
            // Pattern match fallback— iterate most-specific routes first so that literal
            // segments (e.g. /api/_lookup/{type}) beat generic routes (e.g. /api/{type}/{id}).
            bool methodNotAllowed = false;
            foreach (var (_, routeData, compiled) in GetSortedRoutes())
            {
                if (RouteMatching.TryMatch(requestPath, compiled, out var parameters))
                {
                    if (!compiled.Verb.Equals(method, StringComparison.OrdinalIgnoreCase))
                    {
                        if (!compiled.Verb.Equals("ALL", StringComparison.OrdinalIgnoreCase))
                            methodNotAllowed = true;
                        continue;
                    }
                    // a routed parameter match ! --> grab it and inject it into the rendering parameters
                    var injectedPage = RouteInfoHelpers.InjectRouteParametersIntoPageInfo(routeData, parameters);
                    if (injectedPage.PageInfo != null)
                    {
                        bmwCtx.SetPageInfo(injectedPage.PageInfo);
                    }
                    if (!await IsAuthorizedAsync(injectedPage.PageInfo, bmwCtx, context.RequestAborted).ConfigureAwait(false))
                    {
                        await LogAccessDeniedAsync(routeKey, sourceIp, bmwCtx, injectedPage.PageInfo, context.RequestAborted).ConfigureAwait(false);
                        await RenderForbidden(bmwCtx);
                        dispatchSw.Stop();
                        Metrics.RecordRouteDispatch(dispatchSw.Elapsed);
                        return;
                    }
                    await injectedPage.Handler(bmwCtx);
                    var paramParts = new string[parameters.Count];
                    int paramIdx = 0;
                    foreach (var p in parameters)
                        paramParts[paramIdx++] = $"{p.Key}={p.Value}";
                    BufferedLogger.LogInfo($"{routeKey}|{method}|{compiled.Verb}|{string.Join(", ", paramParts)}|200|{sourceIp}");
                    dispatchSw.Stop();
                    Metrics.RecordRouteDispatch(dispatchSw.Elapsed);
                    return;
                }
            }
            foreach (var kvp in _compiledRoutes)
            {
                var compiled = kvp.Value;
                if (!compiled.Verb.Equals("ALL", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (RouteMatching.TryMatch(requestPath, compiled, out var parameters))
                {
                    // _compiledRoutes and routes are always kept in sync by RegisterRoute;
                    // this TryGetValue is a defensive guard against future concurrent modifications.
                    if (!routes.TryGetValue(kvp.Key, out var routeData))
                        continue;
                    var injectedPage = RouteInfoHelpers.InjectRouteParametersIntoPageInfo(routeData, parameters);
                    if (injectedPage.PageInfo != null)
                    {
                        bmwCtx.SetPageInfo(injectedPage.PageInfo);
                    }
                    if (!await IsAuthorizedAsync(injectedPage.PageInfo, bmwCtx, context.RequestAborted).ConfigureAwait(false))
                    {
                        await LogAccessDeniedAsync(routeKey, sourceIp, bmwCtx, injectedPage.PageInfo, context.RequestAborted).ConfigureAwait(false);
                        await RenderForbidden(bmwCtx);
                        dispatchSw.Stop();
                        Metrics.RecordRouteDispatch(dispatchSw.Elapsed);
                        return;
                    }
                    await injectedPage.Handler(bmwCtx);
                    var paramParts2 = new string[parameters.Count];
                    int paramIdx2 = 0;
                    foreach (var p in parameters)
                        paramParts2[paramIdx2++] = $"{p.Key}={p.Value}";
                    BufferedLogger.LogInfo($"{routeKey}|{method}|{compiled.Verb}|{string.Join(", ", paramParts2)}|200|{sourceIp}");
                    dispatchSw.Stop();
                    Metrics.RecordRouteDispatch(dispatchSw.Elapsed);
                    return;
                }
            }
            if (methodNotAllowed)
            {
                context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                bmwCtx.SetPageInfo(ErrorPageInfo);
                await HtmlRenderer.RenderPage(bmwCtx.HttpContext);
                BufferedLogger.LogInfo($"{routeKey}|405|{sourceIp}");
                dispatchSw.Stop();
                Metrics.RecordRouteDispatch(dispatchSw.Elapsed);
                return;
            }
            bmwCtx.SetPageInfo(NotFoundPageInfo);
            await HtmlRenderer.RenderPage(bmwCtx.HttpContext); // Still nothing? 404
            BufferedLogger.LogInfo($"{routeKey}|404|{sourceIp}");
            dispatchSw.Stop();
            Metrics.RecordRouteDispatch(dispatchSw.Elapsed);
        }
        catch (OperationCanceledException oce)
        {
            BufferedLogger.LogInfo($"Client disconnected:{routeKey}|{oce.Message}|{sourceIp}");
        }
        catch (Exception ex)
        {
            var errorId = Guid.NewGuid().ToString("N");
            BufferedLogger.LogError($"Exception: {routeKey} | {sourceIp} | ErrorId={errorId}", ex);
            if (context.Response.HasStarted)
            {
                context.Abort();
                return;
            }
            context.Response.Clear();
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            context.Response.Headers["X-Error-Id"] = errorId;
            if (IsAjaxRequest(context))
            {
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync($"{{\"error\":\"An unexpected error occurred.\",\"errorId\":\"{errorId}\"}}");
            }
            else
            {
                bmwCtx.SetPageInfo(ErrorPageInfo);
                bmwCtx.SetStringValue("html_message", $"<p>An unexpected error occurred.</p><p>Error ID: <code>{errorId}</code></p>");
                await HtmlRenderer.RenderPage(bmwCtx.HttpContext); // Render error page
            }
            BufferedLogger.LogInfo($"{routeKey}|500|{sourceIp}");
        }
        finally
        {
            stopwatch.Stop();
            var statusCode = context.Response?.StatusCode ?? 0;
            Metrics.RecordRequest(statusCode, stopwatch.Elapsed);
        }
    }

    private static bool IsAjaxRequest(HttpContext context) =>
        context.Request.Headers.ContainsKey("X-Requested-With") ||
        context.Request.Path.StartsWithSegments("/api");

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

        var userPermissions = new HashSet<string>(user!.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
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
        var users = await DataStoreProvider.Current.QueryAsync<User>(RootUserQuery, cancellationToken).ConfigureAwait(false);
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

        // Health endpoint must always be reachable for load balancers / monitoring
        if (requestPath.Equals("/health", StringComparison.OrdinalIgnoreCase))
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
        var userName = user?.UserName ?? "anonymous";
        var required = pageInfo?.PageMetaData.PermissionsNeeded ?? string.Empty;
        BufferedLogger.LogInfo($"{path}|403|{sourceIp}|user={userName}|required={required}");
    }

    private static void ApplySecurityHeaders(HttpContext context, bool isHttps)
    {
        var nonce = context.GenerateCspNonce();
        context.Response.Headers["Content-Security-Policy"] = string.Format(ContentSecurityPolicyTemplate, nonce);
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["X-Frame-Options"] = "DENY";
        context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
        context.Response.Headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
        if (isHttps)
            context.Response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload";
        // HTTP/1.x keep-alive hint so clients reuse TCP connections across requests
        if (context.Request.Protocol is "HTTP/1.0" or "HTTP/1.1")
            context.Response.Headers["Keep-Alive"] = "timeout=60, max=1000";
    }

    public async Task RenderForbidden(BmwContext context)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;

        // Refactor this to use the helpers on the context

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
        await HtmlRenderer.RenderPage(context.HttpContext);
    }

    private bool ApplyCors(HttpContext context)
    {
        var origin = context.Request.Headers.Origin.ToString();
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

        context.Response.Headers.AccessControlAllowOrigin = allowAny ? "*" : origin;
        context.Response.Headers.Append("Vary", "Origin");
        context.Response.Headers.AccessControlAllowMethods = string.Join(", ", CorsAllowedMethods);
        context.Response.Headers.AccessControlAllowHeaders = string.Join(", ", CorsAllowedHeaders);
        context.Response.Headers.AccessControlMaxAge = "600";
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

    private static bool IsHttpsRequest(HttpContext context, bool trustForwardedHeaders)
    {
        if (context.Request.IsHttps)
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

    private static string BuildHttpsRedirectUrl(HttpContext context, bool trustForwardedHeaders, string? redirectHost, int? redirectPort)
    {
        var request = context.Request;
        var host = request.Host;

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
            Path = request.PathBase.Add(request.Path).ToString(),
            Query = request.QueryString.HasValue ? request.QueryString.Value : string.Empty
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

    private static string BuildMenuCacheKey(BareMetalWeb.Data.User? user, int routesVersion)
    {
        if (user == null)
            return $"anon|routes:{routesVersion}";

        var perms = user.Permissions is null || user.Permissions.Length == 0
            ? string.Empty
            : string.Join(',', user.Permissions);
        return $"user:{user.Key}|mfa:{user.MfaEnabled}|perms:{perms}|routes:{routesVersion}";
    }

    private static string ComputePrivacyPolicyLink(string url) =>
        string.IsNullOrWhiteSpace(url) ? string.Empty
        : $"<a href=\"{System.Net.WebUtility.HtmlEncode(url)}\" class=\"text-white-50 ms-2\">Privacy Policy</a>";

    private readonly record struct MenuCacheEntry(IMenuOption[] Options, DateTime ExpiresUtc);

    private static bool TryGetForwardedHost(HttpContext context, out HostString host)
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

    private static bool TryGetForwardedPort(HttpContext context, out int port)
    {
        port = 0;
        if (!TryGetForwardedHeaderValue(context, "X-Forwarded-Port", out var value))
            return false;

        var first = GetFirstForwardedValue(value);
        return int.TryParse(first, out port);
    }

    private static bool TryGetForwardedHeaderValue(HttpContext context, string headerName, out string value)
    {
        value = string.Empty;
        if (!context.Request.Headers.TryGetValue(headerName, out var values))
            return false;

        value = values.ToString();
        return !string.IsNullOrWhiteSpace(value);
    }

    private static string GetFirstForwardedValue(string headerValue)
    {
        var commaIndex = headerValue.IndexOf(',');
        return commaIndex >= 0 ? headerValue.Substring(0, commaIndex).Trim() : headerValue.Trim();
    }

    private static bool TryGetForwardedProtoFromForwardedHeader(HttpContext context, out string proto)
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
