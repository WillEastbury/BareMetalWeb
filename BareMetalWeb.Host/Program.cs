using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
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

// ── Configuration ──────────────────────────────────────────────────────
Console.WriteLine("BMW Platform INIT");
var asmVersion = typeof(BareMetalWebServer).Assembly
    .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
    ?? typeof(BareMetalWebServer).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
Console.WriteLine($"  Version:  {asmVersion}");
Console.WriteLine($"  Arch:     {RuntimeInformation.ProcessArchitecture}");
Console.WriteLine($"  CPU:      {GetCpuModel()}");
Console.WriteLine($"  Cores:    {Environment.ProcessorCount}");
Console.WriteLine($"  RAM:      {GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024 * 1024)} MB");
Console.WriteLine($"  Storage:  {GetStorageInfo()}");
Console.WriteLine($"  OS:       {RuntimeInformation.OSDescription}");
Console.WriteLine($"  Runtime:  {RuntimeInformation.FrameworkDescription}");
Console.WriteLine($"  {SimdCapabilities.Current.ToLogLine()}");
foreach (var warning in SimdCapabilities.Current.GetMismatchWarnings())
    Console.WriteLine($"  {warning}");
var contentRoot = Directory.GetCurrentDirectory();
var config = BmwConfig.Load(contentRoot);

// Apply Kestrel + thread-pool tuning from config
var configureKestrel = ProgramSetup.ConfigureKestrel(config);

// Simple per-IP rate limiter for device code endpoints
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
    // Device code auth flow
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
        DataStoreProvider.Current.Save(dc);
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
            if (!uint.TryParse(dc.UserId, out var parsedUserId))
            {
                await ApiErrorWriter.WriteAsync(context.Response,
                    ApiErrorWriter.BadRequest("Invalid user id."),
                    context.RequestAborted);
                return;
            }
            var user = await DataStoreProvider.Current.LoadAsync<User>(parsedUserId);
            if (user != null)
            {
                await UserAuth.SignInAsync(context, user, false);
                dc.Status = "consumed";
                DataStoreProvider.Current.Save(dc);
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonWriterHelper.ToJsonString(new Dictionary<string, object?>
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
                    var enumOpts = DataScaffold.BuildEnumOptions(f.ClrType);
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
await using var host = BmwHost.Create(server, configureKestrel);
await host.RunAsync();

static string GetCpuModel()
{
    try
    {
        if (OperatingSystem.IsLinux() && File.Exists("/proc/cpuinfo"))
        {
            // Prefer "model name" (x86 full brand string) over "Model" (ARM board name)
            string? modelName = null;
            string? model = null;
            foreach (var line in File.ReadLines("/proc/cpuinfo"))
            {
                if (line.StartsWith("model name", StringComparison.OrdinalIgnoreCase))
                {
                    var idx = line.IndexOf(':');
                    if (idx >= 0) { modelName = line[(idx + 1)..].Trim(); break; }
                }
                else if (model == null && line.StartsWith("Model", StringComparison.OrdinalIgnoreCase)
                         && !line.StartsWith("model name", StringComparison.OrdinalIgnoreCase))
                {
                    var idx = line.IndexOf(':');
                    if (idx >= 0) model = line[(idx + 1)..].Trim();
                }
            }
            if (!string.IsNullOrEmpty(modelName)) return modelName;
            if (!string.IsNullOrEmpty(model)) return model;
        }
        else if (OperatingSystem.IsWindows())
        {
            // PROCESSOR_IDENTIFIER gives "Intel64 Family 6 Model 154" — try registry first
            var psi = new System.Diagnostics.ProcessStartInfo("powershell", "-NoProfile -Command \"(Get-CimInstance Win32_Processor).Name\"")
            { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc != null)
            {
                var result = proc.StandardOutput.ReadToEnd().Trim();
                proc.WaitForExit(2000);
                if (!string.IsNullOrEmpty(result)) return result;
            }
            var cpu = Environment.GetEnvironmentVariable("PROCESSOR_IDENTIFIER");
            if (!string.IsNullOrEmpty(cpu)) return cpu;
        }
        else if (OperatingSystem.IsMacOS())
        {
            var psi = new System.Diagnostics.ProcessStartInfo("sysctl", "-n machdep.cpu.brand_string")
            { RedirectStandardOutput = true, UseShellExecute = false };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc != null)
            {
                var result = proc.StandardOutput.ReadToEnd().Trim();
                proc.WaitForExit(1000);
                if (!string.IsNullOrEmpty(result)) return result;
            }
        }
    }
    catch { }
    return RuntimeInformation.ProcessArchitecture.ToString();
}

static string GetStorageInfo()
{
    try
    {
        var drive = new DriveInfo(Path.GetPathRoot(Environment.CurrentDirectory) ?? "/");
        var totalGb = drive.TotalSize / (1024 * 1024 * 1024);
        var freeGb = drive.AvailableFreeSpace / (1024 * 1024 * 1024);
        return $"{freeGb} GB free / {totalGb} GB total";
    }
    catch { return "unknown"; }
}

static class ProgramSetup
{
    public static Action<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions> ConfigureKestrel(BmwConfig config)
    {
        // Thread pool tuning (applied immediately — not Kestrel-specific)
        var minWorker = config.GetValue("ThreadPool.MinWorkerThreads", 0);
        var minIO = config.GetValue("ThreadPool.MinIOThreads", 0);
        if (minWorker > 0 || minIO > 0)
        {
            ThreadPool.GetMinThreads(out int currentWorker, out int currentIO);
            ThreadPool.SetMinThreads(
                minWorker > 0 ? minWorker : currentWorker,
                minIO > 0 ? minIO : currentIO);
        }

        return serverOptions =>
        {
            // Respect PORT / WEBSITES_PORT env vars (Azure App Service, containers)
            var envPort = Environment.GetEnvironmentVariable("PORT")
                       ?? Environment.GetEnvironmentVariable("WEBSITES_PORT");
            var listenPort = !string.IsNullOrEmpty(envPort) && int.TryParse(envPort, out var ep)
                ? ep
                : config.GetValue("Kestrel.Port", 5000);
            serverOptions.ListenAnyIP(listenPort);

            // HTTPS: listen on a second port when a certificate is configured
            var httpsPort = config.GetValue("Kestrel.HttpsPort", 0);
            var certPath = config.GetValue("Kestrel.CertPath", "");
            var certPassword = Environment.GetEnvironmentVariable("KESTREL_CERT_PASSWORD") ?? config.GetValue("Kestrel.CertPassword", "");
            if (httpsPort > 0 && !string.IsNullOrEmpty(certPath) && File.Exists(certPath))
            {
                var cert = string.IsNullOrEmpty(certPassword)
                    ? System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPemFile(certPath, Path.ChangeExtension(certPath, ".key"))
                    : new System.Security.Cryptography.X509Certificates.X509Certificate2(certPath, certPassword);
                var sslOptions = new System.Net.Security.SslServerAuthenticationOptions
                {
                    ServerCertificate = cert,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                    ApplicationProtocols = [System.Net.Security.SslApplicationProtocol.Http11],
                };
                serverOptions.ListenAnyIP(httpsPort, listenOptions =>
                {
                    listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1;
                    listenOptions.Use(next => new TlsConnectionMiddleware(next, sslOptions).OnConnectionAsync);
                });
                Console.WriteLine($"[BMW TLS] HTTPS configured on port {httpsPort} (direct SslStream, TLS 1.2+1.3, HTTP/1.1)");
            }

            var http2Enabled = config.GetValue("Kestrel.Http2Enabled", true);
            var http3Enabled = config.GetValue("Kestrel.Http3Enabled", false);

            serverOptions.ConfigureEndpointDefaults(listenOptions =>
            {
                if (http2Enabled && http3Enabled)
                    listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1AndHttp2AndHttp3;
                else if (http2Enabled)
                    listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1AndHttp2;
                else
                    listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1;
            });

            var maxStreams = config.GetValue("Kestrel.MaxStreamsPerConnection", 100);
            if (maxStreams > 0)
                serverOptions.Limits.Http2.MaxStreamsPerConnection = maxStreams;

            var connWindowSize = config.GetValue("Kestrel.InitialConnectionWindowSize", 131072);
            if (connWindowSize > 0)
                serverOptions.Limits.Http2.InitialConnectionWindowSize = connWindowSize;

            var streamWindowSize = config.GetValue("Kestrel.InitialStreamWindowSize", 98304);
            if (streamWindowSize > 0)
                serverOptions.Limits.Http2.InitialStreamWindowSize = streamWindowSize;

            // ── Connection limits ────────────────────────────────────────────
            // MaxConcurrentConnections: 2048 supports high-concurrency benchmarks
            // (wrk -c400) and production traffic without artificial throttling.
            // Set lower on memory-constrained deployments.
            var maxConnections = config.GetValue("Kestrel.MaxConcurrentConnections", 2048);
            if (maxConnections > 0)
                serverOptions.Limits.MaxConcurrentConnections = maxConnections;

            // Upgraded connections (WebSocket): cap below total to reserve
            // capacity for normal HTTP requests under pressure.
            var maxUpgraded = config.GetValue("Kestrel.MaxConcurrentUpgradedConnections", 512);
            if (maxUpgraded > 0)
                serverOptions.Limits.MaxConcurrentUpgradedConnections = maxUpgraded;

            // ── Timeouts ────────────────────────────────────────────────────
            // Keep-alive: 2 minutes aligns with the HTTP/2 RFC default and lets
            // multiplexed connections amortize the TLS handshake cost.
            var keepAliveSeconds = config.GetValue("Kestrel.KeepAliveTimeoutSeconds", 120);
            serverOptions.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(keepAliveSeconds);

            // Request headers: 5s is tight enough to drop slowloris-style
            // attacks while still accepting legitimate slow mobile clients.
            var headerTimeoutSeconds = config.GetValue("Kestrel.RequestHeadersTimeoutSeconds", 5);
            serverOptions.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(headerTimeoutSeconds);

            var maxBodyBytes = config.GetValue("Kestrel.MaxRequestBodySizeMB", 10);
            serverOptions.Limits.MaxRequestBodySize = (long)maxBodyBytes * 1024 * 1024;

            // Disable minimum data-rate enforcement for response bodies.
            // Prevents Kestrel from killing slow consumers (SSE, long-poll,
            // large CSV exports over mobile connections).
            serverOptions.Limits.MinResponseDataRate = null;

            // Strip the "Server: Kestrel" header — avoid leaking server identity.
            serverOptions.AddServerHeader = false;
        };
    }

    public static IBufferedLogger CreateLogger(BmwConfig config)
    {
        var folder = config.GetValue("Logging.LogFolder", "Logs");
        var levelStr = config.GetValue("Logging.MinLevel", "Info");
        var level = Enum.TryParse<BmwLogLevel>(levelStr, ignoreCase: true, out var parsed)
            ? parsed
            : BmwLogLevel.Info;
        var redactPII = config.GetValue("Logging.RedactPII", true);
        return new DiskBufferedLogger(folder, level, redactPII);
    }

    public static IDataObjectStore CreateDataStore(BmwConfig config, string contentRoot, ISchemaAwareObjectSerializer serializer, IDataQueryEvaluator queryEvaluator, IBufferedLogger logger)
    {
        var dataRoot = config.GetValue("Data.Root", Path.Combine(contentRoot, "Data"));
        MetricsTracker.DataRoot = dataRoot;

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

    public static void ResetDataIfRequested(BmwConfig config, string contentRoot, string dataRoot, IBufferedLogger logger)
    {
        var resetFlagPath = Path.Combine(contentRoot, "reset-data.flag");
        var shouldReset = config.GetValue("Data.ResetOnStartup", false) || File.Exists(resetFlagPath);
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


    public static IClientRequestTracker CreateClientRequestTracker(BmwConfig config, IBufferedLogger logger)
        => new ClientRequestTracker(
            logger,
            normalRpsThreshold: config.GetValue("ClientRequests.NormalRpsThreshold", 20),
            suspiciousRpsThreshold: config.GetValue("ClientRequests.SuspiciousRpsThreshold", 10),
            blockDuration: TimeSpan.FromMinutes(config.GetValue("ClientRequests.BlockDurationMinutes", 1)),
            allowList: config.GetArray("ClientRequests.AllowList"),
            denyList: config.GetArray("ClientRequests.DenyList"),
            staleThreshold: TimeSpan.FromSeconds(config.GetValue("ClientRequests.StaleThresholdSeconds", 120)),
            pruneInterval: TimeSpan.FromSeconds(config.GetValue("ClientRequests.PruneIntervalSeconds", 30)),
            maxEntries: config.GetValue("ClientRequests.MaxEntries", 100000));

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
        BmwConfig config,
        string contentRoot,
        IBufferedLogger logger,
        IHtmlRenderer htmlRenderer,
        IPageInfoFactory pageInfoFactory,
        IHtmlTemplate mainTemplate,
        IMetricsTracker metrics,
        IClientRequestTracker clientRequests,
        CancellationTokenSource cts)
        => new BareMetalWebServer(
            config.GetValue("AppInfo.Name", "BareMetalWeb"),
            config.GetValue("AppInfo.Company", "BareMetalWeb Inc."),
            config.GetValue("AppInfo.Copyright", "2026"),
            config,
            contentRoot,
            logger,
            htmlRenderer,
            pageInfoFactory.TemplatedPage(mainTemplate, 404, new[] { "title", "message" }, new[] { "404 - Not Found", "<p>The requested page was not found.</p>" }, "", true, 6000),
            pageInfoFactory.TemplatedPage(mainTemplate, 500, new[] { "title", "message" }, new[] { "500 - Internal Server Error", "<p>An unexpected error occurred.</p>" }, "", true, 6000),
            cts,
            metrics: metrics,
            clientRequests: clientRequests);

    public static void ConfigureStaticFiles(BmwConfig config, BareMetalWebServer appInfo)
    {
        var staticFileConfig = new StaticFileOptionsConfig
        {
            Enabled = config.GetValue("StaticFiles.Enabled", true),
            RequestPathPrefix = config.GetValue("StaticFiles.RequestPathPrefix", "/static"),
            RootDirectory = config.GetValue("StaticFiles.RootDirectory", "wwwroot/static"),
            EnableCaching = config.GetValue("StaticFiles.EnableCaching", true),
            CacheSeconds = config.GetValue("StaticFiles.CacheSeconds", 86400),
            AddETag = config.GetValue("StaticFiles.AddETag", true),
            AddLastModified = config.GetValue("StaticFiles.AddLastModified", true),
            AllowUnknownMime = config.GetValue("StaticFiles.AllowUnknownMime", false),
            DefaultMimeType = config.GetValue("StaticFiles.DefaultMimeType", "application/octet-stream"),
        };
        var staticFileOptions = StaticFileConfigOptions.FromConfig(staticFileConfig);
        staticFileOptions.Normalize();
        appInfo.StaticFiles = staticFileOptions;
    }

    public static void ConfigureCors(BmwConfig config, BareMetalWebServer appInfo)
    {
        appInfo.CorsAllowedOrigins = config.GetArray("Cors.AllowedOrigins");
    }

    public static void ConfigureHttps(BmwConfig config, BareMetalWebServer appInfo)
    {
        var redirectModeStr = config.GetValue("Https.RedirectMode", "IfAvailable");
        appInfo.HttpsRedirectMode = Enum.TryParse<HttpsRedirectMode>(redirectModeStr, true, out var mode)
            ? mode : HttpsRedirectMode.IfAvailable;
        appInfo.TrustForwardedHeaders = config.GetValue("Https.TrustForwardedHeaders", false);
        var httpsRedirectHost = config.GetValue("Https.RedirectHost", "");
        var httpsRedirectPort = config.GetValue("Https.RedirectPort", 0);

        if (!string.IsNullOrWhiteSpace(httpsRedirectHost))
        {
            appInfo.HttpsRedirectHost = httpsRedirectHost.Trim();
        }
        if (httpsRedirectPort > 0)
        {
            appInfo.HttpsRedirectPort = httpsRedirectPort;
        }
    }

    public static void ConfigureProxyRoutes(BmwConfig config, IBareWebHost appInfo, IBufferedLogger logger, IPageInfoFactory pageInfoFactory)
    {
        // BmwConfig doesn't support complex nested object binding, so we handle
        // the legacy single-route config (Proxy.Route + Proxy.TargetBaseUrl) directly.
        var proxyRoute = config.GetValue("Proxy.Route", "");
        var proxyTarget = config.GetValue("Proxy.TargetBaseUrl", "");
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
