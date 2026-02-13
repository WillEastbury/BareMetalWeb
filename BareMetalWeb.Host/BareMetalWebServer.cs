using System.Diagnostics;
using BareMetalWeb.Data;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core;

namespace BareMetalWeb.Host;

public class BareMetalWebServer : IBareWebHost
{
    // Content Security Policy: Includes 'unsafe-inline' for script-src and style-src to support inline scripts/styles.
    // This is intentional for simplicity and compatibility with templates using inline styles/scripts.
    // For stronger XSS protection, consider using nonces/hashes or removing inline allowances.
    private const string ContentSecurityPolicy = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' https://cdn.jsdelivr.net; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'";
    private static readonly TimeSpan MenuCacheTtl = TimeSpan.FromSeconds(30);
    private static readonly QueryDefinition RootUserQuery = new()
    {
        Clauses = new List<QueryClause>
        {
            new QueryClause { Field = nameof(User.Permissions), Operator = QueryOperator.Contains, Value = "admin" },
            new QueryClause { Field = nameof(User.Permissions), Operator = QueryOperator.Contains, Value = "monitoring" }
        }
    };
    public WebApplication app { get; set; }
    public IBufferedLogger BufferedLogger { get; }
    public IMetricsTracker Metrics { get; }
    public IClientRequestTracker ClientRequests { get; }
    public IHtmlRenderer HtmlRenderer { get; }
    public Dictionary<string, RouteHandlerData> routes { get; set; } = new();
    public string AppName { get; set; }
    public string CompanyDescription { get; set; }
    public string CopyrightYear { get; set; }
    public static string[] appMetaDataKeys { get; set; } = new[] { "AppName", "CompanyDescription", "CopyrightYear" };
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
    private readonly Dictionary<string, MenuCacheEntry> _menuCache = new(StringComparer.Ordinal);
    private int _routesVersion = 0;
    public BareMetalWebServer(
        string appName,
        string companyDescription,
        string copyrightYear,
        WebApplication application,
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
        AppMetaDataValues = new[] { AppName, CompanyDescription, CopyrightYear };
        app = application;
        BufferedLogger = logger;
        HtmlRenderer = htmlRenderer;
        Metrics = metrics;
        ClientRequests = clientRequests;
        NotFoundPageInfo = NotFoundPage;
        ErrorPageInfo = ErrorPage;
        cts = _cts;
    }
    public void BuildAppInfoMenuOptions(HttpContext? context = null)
    {
        MenuOptionsList.Clear();
        var user = context != null ? UserAuth.GetUser(context) : null;
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
        foreach (var rte in routes.Where(kvp => kvp.Value.PageInfo is not null && kvp.Value.PageInfo.PageMetaData.ShowOnNavBar))
        {
            var pageInfo = rte.Value.PageInfo;
            if (pageInfo == null)
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
            string label = pageInfo.PageContext.PageMetaDataValues.FirstOrDefault() ?? path.Trim('/');
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

                bool hasPermission = requiredPermissions.All(userPermissions.Contains);
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
                group: group));
        }

        foreach (var entity in DataScaffold.Entities.Where(e => e.ShowOnNav))
        {
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

                if (!requiredPermissions.All(userPermissions.Contains))
                    continue;
            }

            bool requiresLoggedIn = requiresAuthenticated || (!requiresAnonymous && requiredPermissions.Length > 0);

            MenuOptionsList.Add(new MenuOption(
                href: $"/admin/data/{entity.Slug}",
                label: entity.Name,
                showOnNavBar: true,
                permissionsNeeded: permissionsNeeded,
                rightAligned: false,
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
        _routesVersion++;
        BufferedLogger.LogInfo($"Route registered: {path} with handler {routeHandler.Handler.Method.Name}");
    }
    public Task WireUpRequestHandlingAndLoggerAsyncLifetime()
    {
        // Single terminal request handler. We deliberately do not use routing, MVC, or minimal APIs. All requests are handled explicitly by RequestHandler.
        app.Use(async (HttpContext context, RequestDelegate _) => await RequestHandler(context));
        // Start everything (logging, request handling etc)
        Task loggerTask = BufferedLogger.RunAsync(cts.Token); // Run the logging flusher loop
        Task clientPruneTask = ClientRequests.RunPruningAsync(cts.Token); // Run client pruning loop
        app.Lifetime.ApplicationStopping.Register(() => BufferedLogger.OnApplicationStopping(cts, loggerTask)); // Setup shutdown to stop the logging flusher loop
        // log it
        BufferedLogger.LogInfo($"WireUpRequestHandlingAndLoggerAsyncLifetime completed and request handling is live.");
        _ = clientPruneTask;
        return Task.CompletedTask;
    }
    public async Task RequestHandler(HttpContext context)
    {
        var stopwatch = Stopwatch.StartNew();
        string method = context.Request.Method.ToUpperInvariant();
        string requestPath = context.Request.Path.Value ?? "/";
        string path = method + " " + requestPath;
        string sourceIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        context.SetApp(this);
        BuildAppInfoMenuOptions(context);

        bool isHttps = IsHttpsRequest(context, TrustForwardedHeaders);
        context.Response.Headers["X-BareMetal-IsHttps"] = isHttps ? "true" : "false";
        context.Response.Headers["X-BareMetal-RedirectMode"] = HttpsRedirectMode.ToString();
        context.Response.Headers["X-BareMetal-HttpsAvailable"] = HttpsEndpointAvailable ? "true" : "false";
        if (!isHttps && ShouldRedirectToHttps())
        {
            var httpsUrl = BuildHttpsRedirectUrl(context, TrustForwardedHeaders, HttpsRedirectHost, HttpsRedirectPort);
            context.Response.StatusCode = StatusCodes.Status301MovedPermanently;
            context.Response.Headers.Location = httpsUrl;
            BufferedLogger.LogInfo($"{path}|301|{sourceIp}|redirect={httpsUrl}|mode={HttpsRedirectMode}|httpsAvailable={HttpsEndpointAvailable}|trustForwarded={TrustForwardedHeaders}|host={context.Request.Host}");
            return;
        }
        ApplySecurityHeaders(context);

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
            BufferedLogger.LogInfo($"{path}|429|{sourceIp}|{throttleReason}");
            stopwatch.Stop();
            Metrics.RecordThrottled(stopwatch.Elapsed);
            return;
        }
        try
        {
            if (ShouldForceSetup(requestPath))
            {
                context.Response.StatusCode = StatusCodes.Status302Found;
                context.Response.Headers.Location = "/setup";
                BufferedLogger.LogInfo($"{path}|302|{sourceIp}|setup=required");
                return;
            }

            if (await StaticFileService.TryServeAsync(context, StaticFiles))
            {
                BufferedLogger.LogInfo($"{path}|{context.Response.StatusCode}|{sourceIp}|static");
                return;
            }

            // (simplistic routing and parameter service) - Exact match first
            if (routes.TryGetValue(path, out RouteHandlerData page))
            {
                // exact match found - no params needed.
                if (page.PageInfo != null)
                {
                    context.SetPageInfo(page.PageInfo);
                }
                if (!IsAuthorized(page.PageInfo, context))
                {
                    await RenderForbidden(context);
                    LogAccessDenied(path, sourceIp, context, page.PageInfo);
                    return;
                }
                await page.Handler(context);
                BufferedLogger.LogInfo($"{path}|200|{sourceIp}");
                return;
            }
            if (routes.TryGetValue($"ALL {requestPath}", out RouteHandlerData allPage))
            {
                if (allPage.PageInfo != null)
                {
                    context.SetPageInfo(allPage.PageInfo);
                }
                if (!IsAuthorized(allPage.PageInfo, context))
                {
                    await RenderForbidden(context);
                    LogAccessDenied(path, sourceIp, context, allPage.PageInfo);
                    return;
                }
                await allPage.Handler(context);
                BufferedLogger.LogInfo($"{path}|ALL {requestPath}|200|{sourceIp}");
                return;
            }
            // Pattern match fallback
            bool methodNotAllowed = false;
            foreach (var kvp in routes)
            {
                if (!TryParseRoute(kvp.Key, out var verb, out var templatePath))
                    continue;

                if (RouteMatching.TryMatch(requestPath, templatePath, out var parameters))
                {
                    if (!verb.Equals(method, StringComparison.OrdinalIgnoreCase))
                    {
                        if (!verb.Equals("ALL", StringComparison.OrdinalIgnoreCase))
                            methodNotAllowed = true;
                        continue;
                    }
                    // a routed parameter match ! --> grab it and inject it into the rendering parameters
                    var injectedPage = RouteInfoHelpers.InjectRouteParametersIntoPageInfo(kvp.Value, parameters);
                    if (injectedPage.PageInfo != null)
                    {
                        context.SetPageInfo(injectedPage.PageInfo);
                    }
                    if (!IsAuthorized(injectedPage.PageInfo, context))
                    {
                        await RenderForbidden(context);
                        LogAccessDenied(path, sourceIp, context, injectedPage.PageInfo);
                        return;
                    }
                    await injectedPage.Handler(context);
                    BufferedLogger.LogInfo($"{path}|{method}|{templatePath}|{string.Join(", ", parameters.Select(p => $"{p.Key}={p.Value}"))}|200|{sourceIp}");
                    return;
                }
            }
            foreach (var kvp in routes)
            {
                if (!TryParseRoute(kvp.Key, out var verb, out var templatePath))
                    continue;

                if (!verb.Equals("ALL", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (RouteMatching.TryMatch(requestPath, templatePath, out var parameters))
                {
                    var injectedPage = RouteInfoHelpers.InjectRouteParametersIntoPageInfo(kvp.Value, parameters);
                    if (injectedPage.PageInfo != null)
                    {
                        context.SetPageInfo(injectedPage.PageInfo);
                    }
                    if (!IsAuthorized(injectedPage.PageInfo, context))
                    {
                        await RenderForbidden(context);
                        LogAccessDenied(path, sourceIp, context, injectedPage.PageInfo);
                        return;
                    }
                    await injectedPage.Handler(context);
                    BufferedLogger.LogInfo($"{path}|{method}|{templatePath}|{string.Join(", ", parameters.Select(p => $"{p.Key}={p.Value}"))}|200|{sourceIp}");
                    return;
                }
            }
            if (methodNotAllowed)
            {
                context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                context.SetPageInfo(ErrorPageInfo);
                await HtmlRenderer.RenderPage(context);
                BufferedLogger.LogInfo($"{path}|405|{sourceIp}");
                return;
            }
            context.SetPageInfo(NotFoundPageInfo);
            await HtmlRenderer.RenderPage(context); // Still nothing? 404
            BufferedLogger.LogInfo($"{path}|404|{sourceIp}");
        }
        catch (OperationCanceledException oce)
        {
            BufferedLogger.LogInfo($"Client disconnected:{path}|{oce.Message}|{sourceIp}");
        }
        catch (Exception ex)
        {
            var errorId = Guid.NewGuid().ToString("N");
            BufferedLogger.LogError($"Exception: {path} | {sourceIp} | ErrorId={errorId}", ex);
            if (context.Response.HasStarted)
            {
                context.Abort();
                return;
            }
            context.Response.Clear();
            context.Response.Headers["X-Error-Id"] = errorId;
            context.SetPageInfo(ErrorPageInfo);
            context.SetStringValue("message", $"<p>An unexpected error occurred.</p><p>Error ID: <code>{errorId}</code></p>");
            await HtmlRenderer.RenderPage(context); // Render error page
            BufferedLogger.LogInfo($"{path}|500|{sourceIp}");
        }
        finally
        {
            stopwatch.Stop();
            var statusCode = context.Response?.StatusCode ?? 0;
            Metrics.RecordRequest(statusCode, stopwatch.Elapsed);
        }
    }

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

    private static bool IsAuthorized(PageInfo? pageInfo, HttpContext context)
    {
        if (pageInfo == null)
            return true;

        var permissionsNeeded = pageInfo.PageMetaData.PermissionsNeeded ?? string.Empty;
        // Empty permissions means public/anonymous access is allowed
        if (string.IsNullOrWhiteSpace(permissionsNeeded))
            return true;

        if (string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase))
            return true;

        var user = UserAuth.GetRequestUser(context);
        bool isAnonymous = user == null;

        if (string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase))
            return isAnonymous;

        if (string.Equals(permissionsNeeded, "Authenticated", StringComparison.OrdinalIgnoreCase))
            return !isAnonymous;

        // Parse required permissions and check if empty after splitting
        var requiredPermissions = permissionsNeeded.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (requiredPermissions.Length == 0)
            return true; // No actual permissions after parsing, treat as public

        // If we reach here, specific permissions are required
        if (isAnonymous)
            return false;

        var userPermissions = new HashSet<string>(user!.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);

        return requiredPermissions.All(userPermissions.Contains);
    }

    private static bool RootUserExists()
        => DataStoreProvider.Current.Query<User>(RootUserQuery).Any();

    private bool ShouldForceSetup(string requestPath)
    {
        if (RootUserExists())
            return false;

        if (requestPath.StartsWith("/setup", StringComparison.OrdinalIgnoreCase))
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

    private void LogAccessDenied(string path, string sourceIp, HttpContext context, PageInfo? pageInfo)
    {
        var user = UserAuth.GetRequestUser(context);
        var userName = user?.UserName ?? "anonymous";
        var required = pageInfo?.PageMetaData.PermissionsNeeded ?? string.Empty;
        BufferedLogger.LogInfo($"{path}|403|{sourceIp}|user={userName}|required={required}");
    }

    private static void ApplySecurityHeaders(HttpContext context)
    {
        context.Response.Headers["Content-Security-Policy"] = ContentSecurityPolicy;
    }

    public async Task RenderForbidden(HttpContext context)
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
        await HtmlRenderer.RenderPage(context);
    }

    private bool ApplyCors(HttpContext context)
    {
        var origin = context.Request.Headers.Origin.ToString();
        if (string.IsNullOrWhiteSpace(origin))
            return false;

        if (CorsAllowedOrigins.Length == 0)
            return false;

        bool allowAny = CorsAllowedOrigins.Any(o => o == "*");
        bool allowOrigin = allowAny || CorsAllowedOrigins.Any(o => string.Equals(o, origin, StringComparison.OrdinalIgnoreCase));
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
        return $"user:{user.Id}|mfa:{user.MfaEnabled}|perms:{perms}|routes:{routesVersion}";
    }

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
        var parts = first.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            var idx = part.IndexOf('=');
            if (idx <= 0)
                continue;

            var key = part.Substring(0, idx).Trim();
            if (!key.Equals("proto", StringComparison.OrdinalIgnoreCase))
                continue;

            proto = part.Substring(idx + 1).Trim().Trim('"');
            return !string.IsNullOrWhiteSpace(proto);
        }

        return false;
    }
}
