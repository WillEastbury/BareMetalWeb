using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Host;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Interfaces;
using BareMetalWeb.Rendering.Models;

WebApplication app = WebApplication.Create();

await app.UseBareMetalWeb(configureRoutes: (appInfo, routeHandlers, pageInfoFactory, mainTemplate) =>
{
    // Device code auth flow
    appInfo.RegisterRoute("POST /api/device/code", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), async context =>
    {
        var dc = new DeviceCodeAuth
        {
            UserCode = DeviceCodeAuth.GenerateUserCode(),
            DeviceCode = DeviceCodeAuth.GenerateDeviceCode(),
            ExpiresUtc = DateTime.UtcNow.AddMinutes(15),
            Status = "pending"
        };
        DataStoreProvider.Current.Save(dc);
        var baseUrl = $"{context.Request.Scheme}://{context.Request.Host}";
        var json = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["device_code"] = dc.DeviceCode,
            ["user_code"] = dc.UserCode,
            ["verification_url"] = $"{baseUrl}/device",
            ["expires_in"] = 900,
            ["interval"] = 5
        });
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(json);
    }));
    appInfo.RegisterRoute("POST /api/device/token", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), async context =>
    {
        string body;
        using (var reader = new System.IO.StreamReader(context.Request.Body))
            body = await reader.ReadToEndAsync();
        var deviceCode = "";
        try { var doc = JsonDocument.Parse(body); deviceCode = doc.RootElement.GetProperty("device_code").GetString() ?? ""; } catch { }
        if (string.IsNullOrEmpty(deviceCode))
        {
            context.Response.StatusCode = 400;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"missing device_code\"}");
            return;
        }
        var all = DataStoreProvider.Current.Query<DeviceCodeAuth>(null).ToList();
        var dc = all.FirstOrDefault(d => d.DeviceCode == deviceCode);
        if (dc == null || dc.IsExpired(DateTime.UtcNow))
        {
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"status\":\"expired\"}");
            return;
        }
        if (dc.Status == "approved" && !string.IsNullOrEmpty(dc.UserId))
        {
            var user = await DataStoreProvider.Current.LoadAsync<User>(dc.UserId);
            if (user != null)
            {
                await UserAuth.SignInAsync(context, user, false);
                dc.Status = "consumed";
                DataStoreProvider.Current.Save(dc);
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(new Dictionary<string, object>
                {
                    ["status"] = "approved",
                    ["user"] = user.DisplayName ?? user.UserName
                }));
                return;
            }
        }
        if (dc.Status == "denied")
        {
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"status\":\"denied\"}");
            return;
        }
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync("{\"status\":\"authorization_pending\"}");
    }));
    appInfo.RegisterRoute("GET /device", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), async context =>
    {
        var code = context.Request.Query.ContainsKey("code") ? context.Request.Query["code"].ToString() : "";
        var msg = context.Request.Query.ContainsKey("msg") ? context.Request.Query["msg"].ToString() : "";
        var sb = new System.Text.StringBuilder();
        sb.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        sb.Append("<title>Device Login - BareMetalWeb</title><style>");
        sb.Append("*{margin:0;padding:0;box-sizing:border-box}");
        sb.Append("body{font-family:system-ui,-apple-system,sans-serif;background:#1a1a2e;color:#e0e0e0;display:flex;justify-content:center;align-items:center;min-height:100vh}");
        sb.Append(".card{background:#16213e;border-radius:12px;padding:40px;max-width:420px;width:100%;box-shadow:0 8px 32px rgba(0,0,0,.4);text-align:center}");
        sb.Append("h1{font-size:1.6em;margin-bottom:8px;color:#fff}");
        sb.Append("p{color:#a0a0b0;margin-bottom:24px;font-size:.95em}");
        sb.Append("input[type=text]{width:100%;padding:14px;font-size:1.4em;text-align:center;letter-spacing:4px;border:2px solid #4361ee;border-radius:8px;background:#0f3460;color:#fff;outline:none;text-transform:uppercase}");
        sb.Append("input:focus{border-color:#7c8cf8;box-shadow:0 0 12px rgba(67,97,238,.4)}");
        sb.Append("button{width:100%;margin-top:16px;padding:14px;font-size:1.1em;background:#4361ee;color:#fff;border:none;border-radius:8px;cursor:pointer;font-weight:600}");
        sb.Append("button:hover{background:#3a56d4}");
        sb.Append(".msg{margin-top:16px;padding:12px;border-radius:6px;font-size:.9em}");
        sb.Append(".msg-ok{background:#1b5e20;color:#a5d6a7}.msg-err{background:#b71c1c;color:#ef9a9a}");
        sb.Append(".logo{font-size:2.5em;margin-bottom:16px}");
        sb.Append("</style></head><body>");
        sb.Append("<div class=\"card\">");
        sb.Append("<div class=\"logo\">&#128272;</div>");
        sb.Append("<h1>Device Login</h1>");
        sb.Append("<p>Enter the code shown in your CLI to authorize this device.</p>");
        sb.Append("<form method=\"post\" action=\"/device\">");
        sb.Append($"<input type=\"text\" name=\"code\" maxlength=\"9\" placeholder=\"XXXX-XXXX\" value=\"{System.Net.WebUtility.HtmlEncode(code)}\" autocomplete=\"off\" autofocus>");
        sb.Append("<button type=\"submit\">Authorize Device</button>");
        sb.Append("</form>");
        if (!string.IsNullOrEmpty(msg))
        {
            var isErr = msg.StartsWith("Error", StringComparison.OrdinalIgnoreCase);
            sb.Append($"<div class=\"msg {(isErr ? "msg-err" : "msg-ok")}\">{System.Net.WebUtility.HtmlEncode(msg)}</div>");
        }
        sb.Append("</div></body></html>");
        context.Response.ContentType = "text/html";
        await context.Response.WriteAsync(sb.ToString());
    }));
    appInfo.RegisterRoute("POST /device", new RouteHandlerData(pageInfoFactory.RawPage("Authenticated", false), async context =>
    {
        var user = await UserAuth.GetRequestUserAsync(context);
        string code = "";
        if (context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync();
            code = form["code"].ToString().Trim().ToUpperInvariant();
        }
        if (string.IsNullOrEmpty(code) || user == null)
        {
            context.Response.Redirect("/device?msg=Error:+Invalid+request");
            return;
        }
        var all = DataStoreProvider.Current.Query<DeviceCodeAuth>(null).ToList();
        var dc = all.FirstOrDefault(d => d.UserCode == code && d.Status == "pending" && !d.IsExpired(DateTime.UtcNow));
        if (dc == null)
        {
            context.Response.Redirect($"/device?msg=Error:+Invalid+or+expired+code&code={System.Net.WebUtility.UrlEncode(code)}");
            return;
        }
        dc.Status = "approved";
        dc.UserId = user.Id;
        DataStoreProvider.Current.Save(dc);
        context.Response.Redirect("/device?msg=Device+authorized+successfully!+You+can+close+this+tab.");
    }));
    // API metadata endpoint
    appInfo.RegisterRoute("GET /api/_meta", new RouteHandlerData(pageInfoFactory.RawPage("Authenticated", false), async context =>
    {
        var entities = DataScaffold.Entities;
        var result = entities.Select(e => new Dictionary<string, object?>
        {
            ["name"] = e.Name,
            ["slug"] = e.Slug,
            ["permissions"] = e.Permissions,
            ["showOnNav"] = e.ShowOnNav,
            ["navGroup"] = e.NavGroup,
            ["navOrder"] = e.NavOrder,
            ["viewType"] = e.ViewType.ToString(),
            ["parentField"] = e.ParentField?.Name,
            ["commands"] = e.Commands.Select(c => new Dictionary<string, object?>
            {
                ["name"] = c.Name,
                ["label"] = c.Label,
                ["icon"] = c.Icon,
                ["confirmMessage"] = c.ConfirmMessage,
                ["destructive"] = c.Destructive,
                ["order"] = c.Order
            }).ToArray(),
            ["fields"] = e.Fields.Select(f => new Dictionary<string, object?>
            {
                ["name"] = f.Name,
                ["label"] = f.Label,
                ["type"] = f.FieldType.ToString(),
                ["order"] = f.Order,
                ["required"] = f.Required,
                ["list"] = f.List,
                ["view"] = f.View,
                ["edit"] = f.Edit,
                ["create"] = f.Create,
                ["readOnly"] = f.ReadOnly,
                ["placeholder"] = f.Placeholder,
                ["isComputed"] = f.Computed != null,
                ["isCalculated"] = f.Calculated != null,
                ["lookupTargetSlug"] = f.Lookup != null ? DataScaffold.GetEntityByType(f.Lookup.TargetType)?.Slug : null,
                ["lookupValueField"] = f.Lookup?.ValueField,
                ["lookupDisplayField"] = f.Lookup?.DisplayField,
                ["lookupFilterField"] = f.Lookup?.QueryField,
                ["lookupFilterValue"] = f.Lookup?.QueryValue,
                ["enumValues"] = f.FieldType == FormFieldType.Enum
                    ? DataScaffold.BuildEnumOptions(f.Property.PropertyType)
                        .Select(kv => new { value = kv.Key, label = kv.Value })
                        .ToArray()
                    : null,
                ["upload"] = f.Upload == null ? null : new Dictionary<string, object?>
                {
                    ["maxFileSizeBytes"] = f.Upload.MaxFileSizeBytes,
                    ["allowedMimeTypes"] = f.Upload.AllowedMimeTypes,
                    ["maxImageWidth"] = f.Upload.MaxImageWidth,
                    ["maxImageHeight"] = f.Upload.MaxImageHeight,
                    ["generateThumbnail"] = f.Upload.GenerateThumbnail
                }
            }).ToArray()
        }).ToArray();
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
    }));
    
<<<<<<< fix/vnext-lookup-metadata
    // Lookup API routes are now registered in RegisterApiRoutes (RouteRegistrationExtensions.cs)
    // before the parameterised /api/{type} routes to prevent route shadowing.

=======
>>>>>>> main
    // Ideas/search page
    appInfo.RegisterRoute("GET /ideas/search", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), async context =>
    {
        var q = context.Request.Query.ContainsKey("q") ? context.Request.Query["q"].ToString() : null;
        var caller = context.Request.Query.ContainsKey("caller") ? context.Request.Query["caller"].ToString() : null;
        var source = context.Request.Query.ContainsKey("source") ? context.Request.Query["source"].ToString() : null;

        if (!string.IsNullOrWhiteSpace(q))
        {
            var todo = new ToDo
            {
                Id = Guid.NewGuid().ToString("N"),
                Title = q,
                Notes = $"caller={caller ?? ""}, source={source ?? ""}",
                Deadline = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(7)),
                StartTime = TimeOnly.FromDateTime(DateTime.UtcNow),
                IsCompleted = false
            };
            DataStoreProvider.Current.Save(todo);
        }

        var todos = DataStoreProvider.Current.Query<ToDo>(null);
        var sb = new System.Text.StringBuilder();
        sb.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        sb.Append("<title>Ideas</title><style>");
        sb.Append("*{margin:0;padding:0;box-sizing:border-box}");
        sb.Append("body{font-family:system-ui,-apple-system,sans-serif;background:#f4f6f9;color:#333}");
        sb.Append("header{background:#1a1a2e;color:#fff;padding:16px 24px;font-size:1.4em;font-weight:600}");
        sb.Append(".container{max-width:900px;margin:24px auto;padding:0 16px}");
        sb.Append("form{display:flex;gap:8px;margin-bottom:24px}");
        sb.Append("input[type=text]{flex:1;padding:10px 14px;border:1px solid #ccc;border-radius:6px;font-size:1em}");
        sb.Append("button{padding:10px 20px;background:#4361ee;color:#fff;border:none;border-radius:6px;font-size:1em;cursor:pointer}");
        sb.Append("button:hover{background:#3a56d4}");
        sb.Append("table{width:100%;border-collapse:collapse;background:#fff;border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.1)}");
        sb.Append("th{background:#e8eaf6;text-align:left;padding:12px 14px;font-weight:600;font-size:.9em;color:#555}");
        sb.Append("td{padding:10px 14px;border-top:1px solid #eee;font-size:.95em}");
        sb.Append("tr:hover{background:#f0f4ff}");
        sb.Append(".done{text-decoration:line-through;color:#999}");
        sb.Append(".badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:.8em;font-weight:600}");
        sb.Append(".badge-open{background:#e3f2fd;color:#1565c0}.badge-done{background:#e8f5e9;color:#2e7d32}");
        sb.Append(".empty{text-align:center;padding:40px;color:#999;font-size:1.1em}");
        sb.Append("footer{text-align:center;padding:24px;color:#999;font-size:.85em}");
        sb.Append("</style></head><body>");
        sb.Append("<header>&#128161; Ideas</header>");
        sb.Append("<div class=\"container\">");
        sb.Append("<form method=\"get\" action=\"/ideas/search\">");
        sb.Append("<input type=\"text\" name=\"q\" placeholder=\"Enter a new idea...\" value=\"\">");
        sb.Append("<button type=\"submit\">Add &amp; Search</button>");
        sb.Append("</form>");

        var list = todos.ToList();
        if (list.Count == 0)
        {
            sb.Append("<div class=\"empty\">No ideas yet. Add one above!</div>");
        }
        else
        {
            sb.Append("<table><thead><tr><th>Title</th><th>Notes</th><th>Deadline</th><th>Status</th></tr></thead><tbody>");
            foreach (var t in list)
            {
                var css = t.IsCompleted ? " class=\"done\"" : "";
                var badge = t.IsCompleted ? "<span class=\"badge badge-done\">Done</span>" : "<span class=\"badge badge-open\">Open</span>";
                sb.Append($"<tr><td{css}>{System.Net.WebUtility.HtmlEncode(t.Title)}</td>");
                sb.Append($"<td>{System.Net.WebUtility.HtmlEncode(t.Notes)}</td>");
                sb.Append($"<td>{t.Deadline:yyyy-MM-dd}</td>");
                sb.Append($"<td>{badge}</td></tr>");
            }
            sb.Append("</tbody></table>");
        }

        sb.Append("</div><footer>BareMetalWeb &middot; Ideas</footer></body></html>");

        context.Response.ContentType = "text/html";
        await context.Response.WriteAsync(sb.ToString());
    }));
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

    public static async ValueTask EnsureRootPermissionsAsync(IBufferedLogger logger, string[] requiredPermissions, CancellationToken cancellationToken = default)
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

        var users = (await DataStoreProvider.Current.QueryAsync<User>(query, cancellationToken).ConfigureAwait(false)).ToList();
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
            await DataStoreProvider.Current.SaveAsync(user, cancellationToken).ConfigureAwait(false);
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
