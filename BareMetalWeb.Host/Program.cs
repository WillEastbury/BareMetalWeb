using System.Collections.Concurrent;
using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Host;
using BareMetalWeb.Rendering.Models;
using Microsoft.AspNetCore.Http;

var contentRoot = ProgramSetup.WriteConfigBanner();
var config = BmwConfig.Load(contentRoot);

var configureKestrel = ProgramSetup.ConfigureKestrel(config);
var configureSocketTransport = ProgramSetup.ConfigureSocketTransport(config);

var _deviceRateLimiter = new ConcurrentDictionary<string, (int Count, DateTime Window)>();
bool DeviceRateCheck(BmwContext ctx, int maxPerMinute = 10)
{
    var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    var now = DateTime.UtcNow;
    var entry = _deviceRateLimiter.AddOrUpdate(ip,
        _ => (1, now.AddMinutes(1)),
        (_, old) => old.Window < now ? (1, now.AddMinutes(1)) : (old.Count + 1, old.Window));
    return entry.Count <= maxPerMinute;
}

var server = await BareMetalWebExtensions.InitializeAsync(config, contentRoot, configureRoutes: (appInfo, routeHandlers, pageInfoFactory, mainTemplate) =>
{
    appInfo.RegisterRoute("POST /api/device/code", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), async context =>
    {
        if (!DeviceRateCheck(context))
        {
            await ApiErrorWriter.WriteAsync(context.Response,
                ApiErrorWriter.RateLimited(), context.RequestAborted);
            return;
        }
        var dc = new DeviceCodeAuth
        {
            UserCode = DeviceCodeAuth.GenerateUserCode(),
            DeviceCode = DeviceCodeAuth.GenerateDeviceCode(),
            ExpiresUtc = DateTime.UtcNow.AddMinutes(15),
            Status = "pending"
        };
        DataStoreProvider.Current.Save(dc.EntityTypeName, dc);
        var baseUrl = $"{context.HttpRequest.Scheme}://{context.HttpRequest.Host}";
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonWriterHelper.ToJsonString(new Dictionary<string, object?>
        {
            ["device_code"] = dc.DeviceCode,
            ["user_code"] = dc.UserCode,
            ["verification_url"] = $"{baseUrl}/device",
            ["expires_in"] = 900,
            ["interval"] = 5
        }));
    }));
    appInfo.RegisterRoute("POST /api/device/token", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), async context =>
    {
        if (!DeviceRateCheck(context, 30))
        {
            await ApiErrorWriter.WriteAsync(context.Response,
                ApiErrorWriter.RateLimited(), context.RequestAborted);
            return;
        }
        // Validate Content-Type (CSRF mitigation)
        if (!(context.HttpRequest.ContentType ?? "").Contains("application/json", StringComparison.OrdinalIgnoreCase))
        {
            await ApiErrorWriter.WriteAsync(context.Response,
                ApiErrorWriter.UnsupportedMediaType(), context.RequestAborted);
            return;
        }
        string body;
        using (var reader = new System.IO.StreamReader(context.HttpRequest.Body))
            body = await reader.ReadToEndAsync();
        var deviceCode = "";
        try
        {
            var doc = JsonDocument.Parse(body);
            deviceCode = doc.RootElement.GetProperty("device_code").GetString() ?? "";
        }
        catch (Exception)
        {
            // Malformed JSON or missing property — deviceCode stays empty, handled below
        }
        if (string.IsNullOrEmpty(deviceCode))
        {
            await ApiErrorWriter.WriteAsync(context.Response,
                ApiErrorWriter.BadRequest("Field 'device_code' is required.",
                    new[] { new FieldError { Field = "device_code", Message = "Required" } }),
                context.RequestAborted);
            return;
        }
        var queryDef = new BareMetalWeb.Data.QueryDefinition { Clauses = new() { new BareMetalWeb.Data.QueryClause { Field = "DeviceCode", Operator = BareMetalWeb.Data.QueryOperator.Equals, Value = deviceCode } }, Top = 1 };
        DeviceCodeAuth? dc = null;
        foreach (var item in (await DataStoreProvider.Current.QueryAsync("DeviceCodeAuth", queryDef)).Cast<DeviceCodeAuth>())
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
            if (!uint.TryParse(dc.UserId, out var parsedUserId))
            {
                await ApiErrorWriter.WriteAsync(context.Response,
                    ApiErrorWriter.BadRequest("Invalid user id."),
                    context.RequestAborted);
                return;
            }
            var user = await UserAuth.LoadUserAsync(parsedUserId);
            if (user != null)
            {
                await UserAuth.SignInAsync(context, user, false);
                dc.Status = "consumed";
                DataStoreProvider.Current.Save(dc.EntityTypeName, dc);
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonWriterHelper.ToJsonString(new Dictionary<string, object?>
                {
                    ["status"] = "approved",
                    ["user"] = UserAuth.GetDisplayName(user) ?? UserAuth.GetUserName(user)
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
        var code = context.HttpRequest.Query.ContainsKey("code") ? context.HttpRequest.Query["code"].ToString() : "";
        var msg = context.HttpRequest.Query.ContainsKey("msg") ? context.HttpRequest.Query["msg"].ToString() : "";
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
        if (context.HttpRequest.HasFormContentType)
        {
            var form = await context.HttpRequest.ReadFormAsync();
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
        var candidates = (await DataStoreProvider.Current.QueryAsync("DeviceCodeAuth", queryDef)).Cast<DeviceCodeAuth>();
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
        DataStoreProvider.Current.Save(dc.EntityTypeName, dc);
        context.Response.Redirect("/device?msg=Device+authorized+successfully!+You+can+close+this+tab.");
    }));
    appInfo.RegisterRoute("GET /api/_meta", new RouteHandlerData(pageInfoFactory.RawPage("Authenticated", false), async context =>
    {
        var entities = DataScaffold.Entities;
        var resultList = new List<Dictionary<string, object?>>();
        foreach (var e in entities)
        {
            var commandsList = new Dictionary<string, object?>[e.Commands.Count];
            for (int ci = 0; ci < e.Commands.Count; ci++)
            {
                var c = e.Commands[ci];
                commandsList[ci] = new Dictionary<string, object?>
                {
                    ["name"] = c.Name,
                    ["label"] = c.Label,
                    ["icon"] = c.Icon,
                    ["confirmMessage"] = c.ConfirmMessage,
                    ["destructive"] = c.Destructive,
                    ["order"] = c.Order
                };
            }

            var fieldsList = new Dictionary<string, object?>[e.Fields.Count];
            for (int fi = 0; fi < e.Fields.Count; fi++)
            {
                var f = e.Fields[fi];
                object? enumValues = null;
                if (f.FieldType == FormFieldType.Enum)
                {
                    var enumOpts = DataScaffold.BuildEnumOptions(f);
                    var enumOptionsList = new object[enumOpts.Count];
                    for (int ei = 0; ei < enumOpts.Count; ei++)
                        enumOptionsList[ei] = new { value = enumOpts[ei].Key, label = enumOpts[ei].Value };
                    enumValues = enumOptionsList;
                }

                fieldsList[fi] = new Dictionary<string, object?>
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
                    ["lookupTargetSlug"] = f.Lookup != null
                        ? ((f.Lookup.TargetSlug != null && DataScaffold.TryGetEntity(f.Lookup.TargetSlug, out var lkpMeta))
                            ? lkpMeta.Slug
                            : DataScaffold.GetEntityByType(f.Lookup.TargetType)?.Slug)
                        : null,
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
                };
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
                ["commands"] = commandsList,
                ["fields"] = fieldsList
            });
        }
        var result = resultList.ToArray();
        context.Response.ContentType = "application/json";
        await JsonWriterHelper.WriteResponseAsync(context.Response, result, indented: true);
    }));
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

        var q = context.HttpRequest.Query.ContainsKey("q") ? context.HttpRequest.Query["q"].ToString() : null;
        var caller = context.HttpRequest.Query.ContainsKey("caller") ? context.HttpRequest.Query["caller"].ToString() : null;
        var source = context.HttpRequest.Query.ContainsKey("source") ? context.HttpRequest.Query["source"].ToString() : null;

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

// ── Direct Kestrel hosting ────────────────────────────────────────────
await using var host = BmwHost.Create(server, configureKestrel, configureSocketTransport);
await host.RunAsync();
