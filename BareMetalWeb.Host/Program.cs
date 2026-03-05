using System.Collections.Concurrent;
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
using BareMetalWeb.Rendering.Models;

var builder = WebApplication.CreateBuilder();
ProgramSetup.ConfigureKestrel(builder);
WebApplication app = builder.Build();

// Simple per-IP rate limiter for device code endpoints
var _deviceRateLimiter = new ConcurrentDictionary<string, (int Count, DateTime Window)>();
bool DeviceRateCheck(HttpContext ctx, int maxPerMinute = 10)
{
    var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var now = DateTime.UtcNow;
    var entry = _deviceRateLimiter.AddOrUpdate(ip,
        _ => (1, now.AddMinutes(1)),
        (_, old) => old.Window < now ? (1, now.AddMinutes(1)) : (old.Count + 1, old.Window));
    return entry.Count <= maxPerMinute;
}

await app.UseBareMetalWeb(configureRoutes: (appInfo, routeHandlers, pageInfoFactory, mainTemplate) =>
{
    // Device code auth flow
    appInfo.RegisterRoute("POST /api/device/code", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), async context =>
    {
        if (!DeviceRateCheck(context))
        {
            context.Response.StatusCode = 429;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"rate_limited\"}");
            return;
        }
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
        if (!DeviceRateCheck(context, 30))
        {
            context.Response.StatusCode = 429;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"rate_limited\"}");
            return;
        }
        // Validate Content-Type (CSRF mitigation)
        if (!(context.Request.ContentType ?? "").Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = 415;
            await context.Response.WriteAsync("{\"error\":\"Unsupported Content-Type\"}");
            return;
        }
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
        var queryDef = new BareMetalWeb.Data.QueryDefinition { Clauses = new() { new BareMetalWeb.Data.QueryClause { Field = "DeviceCode", Operator = BareMetalWeb.Data.QueryOperator.Equals, Value = deviceCode } }, Top = 1 };
        DeviceCodeAuth? dc = null;
        foreach (var item in await DataStoreProvider.Current.QueryAsync<DeviceCodeAuth>(queryDef))
        {
            dc = item;
            break;
        }
        if (dc == null || dc.IsExpired(DateTime.UtcNow))
        {
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"status\":\"expired\"}");
            return;
        }
        if (dc.Status == "approved" && !string.IsNullOrEmpty(dc.UserId))
        {
            var user = await DataStoreProvider.Current.LoadAsync<User>(uint.Parse(dc.UserId));
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
            // CSRF validation for form-based POST
            if (!BareMetalWeb.Host.CsrfProtection.ValidateFormToken(context, form))
            {
                context.Response.Redirect("/device?msg=Error:+Invalid+security+token.+Please+try+again.");
                return;
            }
            code = form["code"].ToString().Trim().ToUpperInvariant();
        }
        if (string.IsNullOrEmpty(code) || user == null)
        {
            context.Response.Redirect("/device?msg=Error:+Invalid+request");
            return;
        }
        var queryDef = new BareMetalWeb.Data.QueryDefinition { Clauses = new() { new BareMetalWeb.Data.QueryClause { Field = "UserCode", Operator = BareMetalWeb.Data.QueryOperator.Equals, Value = code } }, Top = 10 };
        var candidates = await DataStoreProvider.Current.QueryAsync<DeviceCodeAuth>(queryDef);
        DeviceCodeAuth? dc = null;
        foreach (var d in candidates)
        {
            if (d.Status == "pending" && !d.IsExpired(DateTime.UtcNow))
            {
                dc = d;
                break;
            }
        }
        if (dc == null)
        {
            context.Response.Redirect($"/device?msg=Error:+Invalid+or+expired+code&code={System.Net.WebUtility.UrlEncode(code)}");
            return;
        }
        dc.Status = "approved";
        dc.UserId = user.Key.ToString();
        DataStoreProvider.Current.Save(dc);
        context.Response.Redirect("/device?msg=Device+authorized+successfully!+You+can+close+this+tab.");
    }));
    // API metadata endpoint
    appInfo.RegisterRoute("GET /api/_meta", new RouteHandlerData(pageInfoFactory.RawPage("Authenticated", false), async context =>
    {
        var entities = DataScaffold.Entities;
        var resultList = new List<Dictionary<string, object?>>();
        foreach (var e in entities)
        {
            var commandsList = new List<Dictionary<string, object?>>();
            foreach (var c in e.Commands)
            {
                commandsList.Add(new Dictionary<string, object?>
                {
                    ["name"] = c.Name,
                    ["label"] = c.Label,
                    ["icon"] = c.Icon,
                    ["confirmMessage"] = c.ConfirmMessage,
                    ["destructive"] = c.Destructive,
                    ["order"] = c.Order
                });
            }

            var fieldsList = new List<Dictionary<string, object?>>();
            foreach (var f in e.Fields)
            {
                object? enumValues = null;
                if (f.FieldType == FormFieldType.Enum)
                {
                    var enumOptionsList = new List<object>();
                    foreach (var kv in DataScaffold.BuildEnumOptions(f.Property.PropertyType))
                    {
                        enumOptionsList.Add(new { value = kv.Key, label = kv.Value });
                    }
                    enumValues = enumOptionsList.ToArray();
                }

                fieldsList.Add(new Dictionary<string, object?>
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
                    ["enumValues"] = enumValues,
                    ["upload"] = f.Upload == null ? null : new Dictionary<string, object?>
                    {
                        ["maxFileSizeBytes"] = f.Upload.MaxFileSizeBytes,
                        ["allowedMimeTypes"] = f.Upload.AllowedMimeTypes,
                        ["maxImageWidth"] = f.Upload.MaxImageWidth,
                        ["maxImageHeight"] = f.Upload.MaxImageHeight,
                        ["generateThumbnail"] = f.Upload.GenerateThumbnail
                    }
                });
            }

            resultList.Add(new Dictionary<string, object?>
            {
                ["name"] = e.Name,
                ["slug"] = e.Slug,
                ["permissions"] = e.Permissions,
                ["showOnNav"] = e.ShowOnNav,
                ["navGroup"] = e.NavGroup,
                ["navOrder"] = e.NavOrder,
                ["viewType"] = e.ViewType.ToString(),
                ["parentField"] = e.ParentField?.Name,
                ["commands"] = commandsList.ToArray(),
                ["fields"] = fieldsList.ToArray()
            });
        }
        var result = resultList.ToArray();
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
    }));
    
    // Ideas/search page (metadata-driven — works with any entity that has Title, Notes, Deadline, IsCompleted fields)
    appInfo.RegisterRoute("GET /ideas/search", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), async context =>
    {
        var walProvider = DataStoreProvider.PrimaryProvider as BareMetalWeb.Data.WalDataProvider;
        var registry = BareMetalWeb.Runtime.RuntimeEntityRegistry.Current;
        if (walProvider == null || !registry.TryGet("todos", out var model))
        {
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync("<!DOCTYPE html><html><body><p>ToDo entity not deployed. <a href=\"/admin/gallery\">Deploy from Gallery</a>.</p></body></html>");
            return;
        }

        var schema = BareMetalWeb.Runtime.EntitySchemaFactory.FromModel(model);
        int titleOrd = -1, notesOrd = -1, deadlineOrd = -1, completedOrd = -1, startTimeOrd = -1;
        foreach (var f in model.Fields)
        {
            if (string.Equals(f.Name, "Title", StringComparison.OrdinalIgnoreCase)) titleOrd = f.Ordinal;
            else if (string.Equals(f.Name, "Notes", StringComparison.OrdinalIgnoreCase)) notesOrd = f.Ordinal;
            else if (string.Equals(f.Name, "Deadline", StringComparison.OrdinalIgnoreCase)) deadlineOrd = f.Ordinal;
            else if (string.Equals(f.Name, "IsCompleted", StringComparison.OrdinalIgnoreCase)) completedOrd = f.Ordinal;
            else if (string.Equals(f.Name, "StartTime", StringComparison.OrdinalIgnoreCase)) startTimeOrd = f.Ordinal;
        }

        var q = context.Request.Query.ContainsKey("q") ? context.Request.Query["q"].ToString() : null;
        var caller = context.Request.Query.ContainsKey("caller") ? context.Request.Query["caller"].ToString() : null;
        var source = context.Request.Query.ContainsKey("source") ? context.Request.Query["source"].ToString() : null;

        if (!string.IsNullOrWhiteSpace(q))
        {
            var record = schema.CreateRecord();
            record.EntityTypeName = model.Name;
            if (titleOrd >= 0) record.SetValue(titleOrd, q);
            if (notesOrd >= 0) record.SetValue(notesOrd, $"caller={caller ?? ""}, source={source ?? ""}");
            if (deadlineOrd >= 0) record.SetValue(deadlineOrd, DateOnly.FromDateTime(DateTime.UtcNow.AddDays(7)));
            if (startTimeOrd >= 0) record.SetValue(startTimeOrd, TimeOnly.FromDateTime(DateTime.UtcNow));
            if (completedOrd >= 0) record.SetValue(completedOrd, false);
            walProvider.SaveRecord(record, schema);
        }

        var todosEnumerable = walProvider.QueryRecords(schema);
        var todos = new List<BareMetalWeb.Data.DataRecord>();
        foreach (var todo in todosEnumerable)
        {
            todos.Add(todo);
        }
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

        if (todos.Count == 0)
        {
            sb.Append("<div class=\"empty\">No ideas yet. Add one above!</div>");
        }
        else
        {
            sb.Append("<table><thead><tr><th>Title</th><th>Notes</th><th>Deadline</th><th>Status</th></tr></thead><tbody>");
            foreach (var t in todos)
            {
                var title = titleOrd >= 0 ? t.GetValue(titleOrd)?.ToString() ?? "" : "";
                var notes = notesOrd >= 0 ? t.GetValue(notesOrd)?.ToString() ?? "" : "";
                var deadline = deadlineOrd >= 0 && t.GetValue(deadlineOrd) is DateOnly d ? d.ToString("yyyy-MM-dd") : "";
                var done = completedOrd >= 0 && t.GetValue(completedOrd) is true;
                var css = done ? " class=\"done\"" : "";
                var badge = done ? "<span class=\"badge badge-done\">Done</span>" : "<span class=\"badge badge-open\">Open</span>";
                sb.Append($"<tr><td{css}>{System.Net.WebUtility.HtmlEncode(title)}</td>");
                sb.Append($"<td>{System.Net.WebUtility.HtmlEncode(notes)}</td>");
                sb.Append($"<td>{deadline}</td>");
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
    public static void ConfigureKestrel(WebApplicationBuilder builder)
    {
        var config = builder.Configuration;

        builder.WebHost.ConfigureKestrel(serverOptions =>
        {
            var http2Enabled = config.GetValue("Kestrel:Http2Enabled", true);
            var http3Enabled = config.GetValue("Kestrel:Http3Enabled", false);

            serverOptions.ConfigureEndpointDefaults(listenOptions =>
            {
                if (http2Enabled && http3Enabled)
                    listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1AndHttp2AndHttp3;
                else if (http2Enabled)
                    listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1AndHttp2;
                else
                    listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1;
            });

            var maxStreams = config.GetValue("Kestrel:MaxStreamsPerConnection", 100);
            if (maxStreams > 0)
                serverOptions.Limits.Http2.MaxStreamsPerConnection = maxStreams;

            var connWindowSize = config.GetValue("Kestrel:InitialConnectionWindowSize", 131072);
            if (connWindowSize > 0)
                serverOptions.Limits.Http2.InitialConnectionWindowSize = connWindowSize;

            var streamWindowSize = config.GetValue("Kestrel:InitialStreamWindowSize", 98304);
            if (streamWindowSize > 0)
                serverOptions.Limits.Http2.InitialStreamWindowSize = streamWindowSize;
        });

        // Thread pool tuning
        var minWorker = config.GetValue("ThreadPool:MinWorkerThreads", 0);
        var minIO = config.GetValue("ThreadPool:MinIOThreads", 0);
        if (minWorker > 0 || minIO > 0)
        {
            ThreadPool.GetMinThreads(out int currentWorker, out int currentIO);
            ThreadPool.SetMinThreads(
                minWorker > 0 ? minWorker : currentWorker,
                minIO > 0 ? minIO : currentIO);
        }
    }

    public static IBufferedLogger CreateLogger(WebApplication app)
        => new DiskBufferedLogger(app.Configuration.GetValue("Logging:LogFolder", "Logs"));

    public static IDataObjectStore CreateDataStore(WebApplication app, ISchemaAwareObjectSerializer serializer, IDataQueryEvaluator queryEvaluator, IBufferedLogger logger)
    {
        var dataRoot = app.Configuration.GetValue("Data:Root", Path.Combine(app.Environment.ContentRootPath, "Data"));

        // Detect and wipe legacy GUID-based data before opening the store
        LegacyDataWipeGuard.WipeIfLegacyDetected(dataRoot, logger);

        var dataStore = new DataObjectStore();
        DataStoreProvider.Current = dataStore;
        var provider = new WalDataProvider(
            dataRoot,
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

        var usersEnumerable = await DataStoreProvider.Current.QueryAsync<User>(query, cancellationToken).ConfigureAwait(false);
        var users = new List<User>();
        foreach (var u in usersEnumerable)
        {
            users.Add(u);
        }
        foreach (var user in users)
        {
            if (user is null || !user.IsActive)
                continue;

            var perms = user.Permissions != null ? new List<string>(user.Permissions) : new List<string>();
            var changed = false;
            foreach (var required in requiredPermissions)
            {
                if (string.IsNullOrWhiteSpace(required))
                    continue;
                bool alreadyHasPerm = false;
                foreach (var p in perms)
                {
                    if (string.Equals(p, required, StringComparison.OrdinalIgnoreCase))
                    {
                        alreadyHasPerm = true;
                        break;
                    }
                }
                if (alreadyHasPerm)
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
                var statusList = new List<ProxyRouteStatus>();
                foreach (var handler in proxyHandlers)
                {
                    statusList.Add(handler.GetStatus());
                }
                var status = statusList.ToArray();

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
