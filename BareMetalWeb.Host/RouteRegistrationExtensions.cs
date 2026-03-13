using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Models;
using BareMetalWeb.Runtime;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Extension methods for registering routes on IBareWebHost in a plugin-like fashion.
/// Each method handles registration of a logical group of related routes.
/// </summary>
public static class RouteRegistrationExtensions
{
    private static readonly JsonWriterOptions s_compactWriterOptions = new();
    private static readonly JsonWriterOptions s_indentedWriterOptions = new() { Indented = true };

    /// <summary>
    /// Register static/public page routes (home, status).
    /// </summary>
    public static void RegisterStaticRoutes(
        this IBareWebHost host,
        IRouteHandlers routeHandlers,
        IPageInfoFactory pageInfoFactory,
        IHtmlTemplate mainTemplate)
    {
        host.RegisterRoute("GET /", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Home", "<p></p>" }, "Public", false, 60),
            routeHandlers.DefaultPageHandler));

        // Browsers always request /favicon.ico at the root — redirect to the
        // actual static path and cache the redirect for one year so subsequent
        // page loads never hit this route again.
        host.RegisterRoute("GET /favicon.ico", new RouteHandlerData(
            pageInfoFactory.RawPage("Public", false),
            context =>
            {
                context.Response.StatusCode = 301;
                context.Response.Headers["Location"] = "/static/favicon.ico";
                context.Response.Headers["Cache-Control"] = "public, max-age=31536000, immutable";
                return ValueTask.CompletedTask;
            }));

        host.RegisterRoute("GET /status", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "", "" }, "Public", false, 1),
            routeHandlers.BuildPageHandler(context =>
            {
                context.Response.ContentType = "text/html";
                context.SetStringValue("title", "Server Time");
                context.SetStringValue("html_message", $"Current server time is: {DateTime.UtcNow:O}");
            })));

        host.RegisterRoute("GET /statusRaw", new RouteHandlerData(
            pageInfoFactory.RawPage("Public", false),
            routeHandlers.TimeRawHandler));

        // #1244: Health check endpoint for load balancers / monitoring
        // #1263: Separate liveness and readiness probes
        host.RegisterRoute("GET /health", new RouteHandlerData(
            pageInfoFactory.RawPage("Public", false),
            async context =>
            {
                bool ready = BareMetalWebServer.IsReady;
                context.Response.StatusCode = ready ? 200 : 503;
                context.Response.ContentType = "application/json";
                var uptime = DateTime.UtcNow - System.Diagnostics.Process.GetCurrentProcess().StartTime.ToUniversalTime();
                var status = ready ? "healthy" : "initializing";
                var json = $"{{\"status\":\"{status}\",\"ready\":{(ready ? "true" : "false")},\"uptime_seconds\":{uptime.TotalSeconds:F0}}}";
                await context.Response.WriteAsync(json);
            }));

        // GET /healthz — liveness probe: 200 if process is running (always succeeds)
        host.RegisterRoute("GET /healthz", new RouteHandlerData(
            pageInfoFactory.RawPage("Public", false),
            async context =>
            {
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"status\":\"alive\"}");
            }));

        // GET /readyz — readiness probe: 200 only when fully initialized, 503 during startup
        host.RegisterRoute("GET /readyz", new RouteHandlerData(
            pageInfoFactory.RawPage("Public", false),
            async context =>
            {
                bool ready = BareMetalWebServer.IsReady;
                context.Response.StatusCode = ready ? 200 : 503;
                context.Response.ContentType = "application/json";

                if (ready)
                {
                    await context.Response.WriteAsync("{\"status\":\"ready\"}");
                }
                else
                {
                    await context.Response.WriteAsync("{\"status\":\"not_ready\",\"reason\":\"Server is still initializing\"}");
                }
            }));
    }

    /// <summary>
    /// Register authentication and account management routes (login, logout, register, MFA, setup).
    /// </summary>
    public static void RegisterAuthRoutes(
        this IBareWebHost host,
        IRouteHandlers routeHandlers,
        IPageInfoFactory pageInfoFactory,
        IHtmlTemplate mainTemplate,
        bool allowAccountCreation)
    {
        // Login
        host.RegisterRoute("GET /login", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Login", "" }, "AnonymousOnly", true, 1, navAlignment: NavAlignment.Right, navRenderStyle: NavRenderStyle.Button, navColorClass: "btn-success"),
            routeHandlers.LoginHandler));
        host.RegisterRoute("POST /login", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Login", "" }, "AnonymousOnly", false, 1),
            routeHandlers.LoginPostHandler));

        // MFA
        host.RegisterRoute("GET /mfa", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Verify MFA", "" }, "AnonymousOnly", false, 1),
            routeHandlers.MfaChallengeHandler));
        host.RegisterRoute("POST /mfa", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Verify MFA", "" }, "AnonymousOnly", false, 1),
            routeHandlers.MfaChallengePostHandler));

        // Registration (conditional)
        if (allowAccountCreation)
        {
            host.RegisterRoute("GET /register", new RouteHandlerData(
                pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Create Account", "" }, "AnonymousOnly", false, 1, navAlignment: NavAlignment.Right),
                routeHandlers.RegisterHandler));
            host.RegisterRoute("POST /register", new RouteHandlerData(
                pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Create Account", "" }, "AnonymousOnly", false, 1),
                routeHandlers.RegisterPostHandler));
        }

        // Logout
        host.RegisterRoute("GET /logout", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Logout", "" }, "Authenticated", false, 1),
            routeHandlers.LogoutHandler));
        host.RegisterRoute("POST /logout", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Logout", "" }, "Authenticated", false, 1),
            routeHandlers.LogoutPostHandler));

        // SSO (Entra ID)
        host.RegisterRoute("GET /auth/sso/login", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 302, Array.Empty<string>(), Array.Empty<string>(), "AnonymousOnly", false, 0),
            routeHandlers.SsoLoginHandler));
        host.RegisterRoute("GET /auth/sso/callback", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "SSO Login", "" }, "AnonymousOnly", false, 0),
            routeHandlers.SsoCallbackHandler));
        host.RegisterRoute("GET /auth/sso/logout", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 302, Array.Empty<string>(), Array.Empty<string>(), "Authenticated", false, 0),
            routeHandlers.SsoLogoutHandler));

        // Account management
        host.RegisterRoute("GET /account", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 302, Array.Empty<string>(), Array.Empty<string>(), "Authenticated", false, 1, navAlignment: NavAlignment.Right),
            routeHandlers.AccountRedirectHandler));

        host.RegisterRoute("GET /system/me", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Account", "" }, "Authenticated", true, 1, navGroup: "Account", navAlignment: NavAlignment.Right),
            routeHandlers.AccountHandler));

        host.RegisterRoute("GET /account/mfa", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Multi-Factor Authentication", "" }, "Authenticated", true, 1, navGroup: "Account", navAlignment: NavAlignment.Right),
            routeHandlers.MfaStatusHandler));
        host.RegisterRoute("GET /account/mfa/setup", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Enable MFA", "" }, "Authenticated", false, 1),
            routeHandlers.MfaSetupHandler));
        host.RegisterRoute("POST /account/mfa/setup", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Enable MFA", "" }, "Authenticated", false, 1),
            routeHandlers.MfaSetupPostHandler));
        host.RegisterRoute("GET /account/mfa/reset", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Reset MFA", "" }, "Authenticated", false, 1),
            routeHandlers.MfaResetHandler));
        host.RegisterRoute("POST /account/mfa/reset", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Reset MFA", "" }, "Authenticated", false, 1),
            routeHandlers.MfaResetPostHandler));

        // Initial setup
        host.RegisterRoute("GET /setup", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Setup", "" }, "AnonymousOnly", false, 1),
            routeHandlers.SetupHandler));
        host.RegisterRoute("POST /setup", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Setup", "" }, "AnonymousOnly", false, 1),
            routeHandlers.SetupPostHandler));
    }

    /// <summary>
    /// Register monitoring routes (metrics, top IPs, suspicious IPs).
    /// </summary>
    public static void RegisterMonitoringRoutes(
        this IBareWebHost host,
        IRouteHandlers routeHandlers,
        IPageInfoFactory pageInfoFactory,
        IHtmlTemplate mainTemplate)
    {
        // Prometheus scrape endpoint — public, no auth, text/plain exposition format
        host.RegisterRoute("GET /metrics/prometheus", new RouteHandlerData(
            pageInfoFactory.RawPage("Public", false),
            PrometheusFormatter.WriteMetricsAsync));

        // Metrics
        host.RegisterRoute("GET /metrics", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Metric Viewer", "" }, "monitoring", true, 1, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "📊 Monitoring"),
            routeHandlers.BuildPageHandler(context =>
            {
                var app = context.GetApp()!;
                context.SetStringValue("title", "Metric Viewer");
                context.SetStringValue("html_message", app.Metrics.GetMetricGroupsHtml());
            })));

        host.RegisterRoute("GET /metrics/json", new RouteHandlerData(
            pageInfoFactory.RawPage("monitoring", false),
            routeHandlers.MetricsJsonHandler));

        // IP tracking
        host.RegisterRoute("GET /topips", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Top IPs", "" }, "monitoring", true, 1, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "📊 Monitoring"),
            routeHandlers.BuildPageHandler(context =>
            {
                var app = context.GetApp()!;
                app.ClientRequests.GetTopClientsTable(20, out var tableColumns, out var tableRows);
                context.SetStringValue("title", "Top IPs");
                context.AddTable(tableColumns, tableRows);
            })));

        host.RegisterRoute("GET /suspiciousips", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Suspicious IPs", "" }, "monitoring", true, 1, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "📊 Monitoring"),
            routeHandlers.BuildPageHandler(context =>
            {
                var app = context.GetApp()!;
                app.ClientRequests.GetSuspiciousClientsTable(20, out var tableColumns, out var tableRows);
                context.SetStringValue("title", "Suspicious IPs");
                context.AddTable(tableColumns, tableRows);
            })));

        // Numeric route table metadata — returns RouteId → Verb → Path mapping as JSON
        host.RegisterRoute("GET /bmw/routes", new RouteHandlerData(
            pageInfoFactory.RawPage("Public", false),
            NumericRouteTableHandler.WriteRoutesAsync));
    }

    /// <summary>
    /// Register admin/system routes (logs, sample data, template reload).
    /// </summary>
    public static void RegisterAdminRoutes(
        this IBareWebHost host,
        IRouteHandlers routeHandlers,
        IPageInfoFactory pageInfoFactory,
        IHtmlTemplate mainTemplate)
    {
        // Log management
        host.RegisterRoute("GET /admin/logs", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Logs", "" }, "monitoring", true, 1, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "📊 Monitoring"),
            routeHandlers.LogsViewerHandler));
        host.RegisterRoute("GET /admin/logs/prune", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Prune Logs", "" }, "monitoring", false, 1),
            routeHandlers.LogsPruneHandler));
        host.RegisterRoute("POST /admin/logs/prune", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Prune Logs", "" }, "monitoring", false, 1),
            routeHandlers.LogsPrunePostHandler));
        host.RegisterRoute("GET /admin/logs/download", new RouteHandlerData(
            pageInfoFactory.RawPage("monitoring", false),
            routeHandlers.LogsDownloadHandler));

        // Sample data generation
        // Template management
        host.RegisterRoute("GET /admin/reload-templates", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Reload Templates", "" }, "admin", true, 1, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "🔧 Tools"),
            routeHandlers.ReloadTemplatesHandler));

        // Wipe all data — always registered; returns 419 if admin.allowWipeData setting is not configured
        // Entity designer — visual editor for creating virtual entity JSON definitions
        host.RegisterRoute("GET /admin/entity-designer", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Entity Designer", "" }, "admin", true, 2, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "🔧 Tools"),
            routeHandlers.EntityDesignerHandler));

        // Gallery — browse and deploy pre-built sample entity schema packages
        host.RegisterRoute("GET /admin/gallery", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Sample Gallery", "" }, "admin", true, 3, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "🔧 Tools"),
            routeHandlers.GalleryHandler));
        host.RegisterRoute("POST /admin/gallery/deploy/{package}", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Sample Gallery", "" }, "admin", false, 0),
            routeHandlers.GalleryDeployPostHandler));

        // Webstore — browse and install shared templates from the control plane
        host.RegisterRoute("GET /admin/webstore", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Template Webstore", "" }, "admin", true, 3, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "🔧 Tools"),
            routeHandlers.WebStoreHandler));
        host.RegisterRoute("POST /admin/webstore/install/{package}", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Template Webstore", "" }, "admin", false, 0),
            routeHandlers.WebStoreInstallHandler));

        // Data & Index Sizing — disk and in-memory index footprint per table
        host.RegisterRoute("GET /admin/data-sizes", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Data & Index Sizing", "" }, "admin", true, 4, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "🔧 Tools"),
            routeHandlers.DataSizingHandler));

        // Loaded Metadata — view all registered entities, fields, and record counts
        host.RegisterRoute("GET /admin/metadata", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Loaded Metadata", "" }, "admin", true, 5, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "🔧 Tools"),
            routeHandlers.BuildPageHandler(async context =>
            {
                context.SetStringValue("title", "Loaded Metadata");
                var entities = DataScaffold.Entities;
                var columns = new[] { "Name", "Slug", "Fields", "Records", "Nav", "Nav Group", "Permissions", "ID Strategy", "Runtime" };
                var rows = new List<string[]>();
                foreach (var meta in entities.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase))
                {
                    int recordCount = 0;
                    try { recordCount = await meta.Handlers.CountAsync(null, context.RequestAborted).ConfigureAwait(false); }
                    catch { /* entity may not support count */ }

                    bool isRuntime = RuntimeEntityRegistry.Current?.TryGet(meta.Slug, out _) == true;
                    rows.Add(new[]
                    {
                        meta.Name,
                        meta.Slug,
                        meta.Fields.Count.ToString(),
                        recordCount.ToString(),
                        meta.ShowOnNav ? "✓" : "",
                        meta.NavGroup ?? "",
                        meta.Permissions,
                        meta.IdGeneration.ToString(),
                        isRuntime ? "✓" : ""
                    });
                }
                context.SetStringValue("html_message",
                    $"<p>{entities.Count} entities registered. <strong>{rows.Count(r => r[8] == "✓")}</strong> runtime-defined.</p>"
                    + "<form method=\"post\" action=\"/admin/metadata/refresh\" style=\"display:inline\">"
                    + $"<input type=\"hidden\" name=\"csrf_token\" value=\"{CsrfProtection.EnsureToken(context)}\">"
                    + "<button type=\"submit\" class=\"btn btn-warning btn-sm\">⟳ Refresh All Metadata Caches</button></form>");
                context.AddTable(columns, rows.ToArray());
            })));

        // Refresh metadata caches — rebuild runtime entities, snapshot, menus, capability graph
        host.RegisterRoute("POST /admin/metadata/refresh", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "Refresh Metadata", "" }, "admin", false, 0),
            routeHandlers.BuildPageHandler(async context =>
            {
                var form = await context.HttpRequest.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
                if (!CsrfProtection.ValidateFormToken(context, form)) { context.Response.StatusCode = 403; return; }

                var sw = System.Diagnostics.Stopwatch.StartNew();
                var steps = new List<string>();

                // 1. Rebuild runtime entity registry (re-reads persisted EntityDefinition/FieldDefinition from WAL)
                await RuntimeEntityRegistry.RebuildAsync().ConfigureAwait(false);
                steps.Add("Runtime entity registry rebuilt");

                // 2. Recompile metadata snapshot
                MetadataCompiler.CompileAndSwap(DataScaffold.Entities);
                steps.Add($"Metadata snapshot compiled ({DataScaffold.Entities.Count} entities)");

                // 3. Invalidate permission resolver caches
                PermissionResolver.Invalidate();
                steps.Add("Permission resolver invalidated");

                // 4. Invalidate lookup caches
                DataScaffold.InvalidateLookupCache();
                steps.Add("Lookup cache invalidated");

                // 5. Rebuild capability graph
                try
                {
                    var graphBuilder = new BareMetalWeb.Runtime.CapabilityGraph.CapabilityGraphBuilder(RuntimeEntityRegistry.Current);
                    var graph = await graphBuilder.BuildAsync(context.GetApp() as BareMetalWeb.Data.Interfaces.IDataObjectStore).ConfigureAwait(false);
                    BareMetalWeb.Runtime.CapabilityGraph.CapabilityGraphRegistry.Current = graph;
                    steps.Add("Capability graph rebuilt");
                }
                catch { steps.Add("Capability graph rebuild skipped (no data store)"); }

                // 6. Rebuild menus
                var app = context.GetApp();
                if (app != null)
                {
                    await app.BuildAppInfoMenuOptionsAsync(context, context.RequestAborted).ConfigureAwait(false);
                    steps.Add("Menu options rebuilt");
                }

                sw.Stop();
                context.SetStringValue("title", "Metadata Refreshed");
                context.SetStringValue("html_message",
                    $"<div class=\"alert alert-success\">All metadata caches refreshed in {sw.ElapsedMilliseconds}ms.</div>"
                    + "<ul>" + string.Join("", steps.Select(s => $"<li>{System.Net.WebUtility.HtmlEncode(s)}</li>")) + "</ul>"
                    + "<p><a href=\"/admin/metadata\" class=\"btn btn-primary\">← Back to Metadata</a></p>");
            })));
    }

    /// <summary>
    /// Register GET /api/metadata/{entity} — returns schema, layout and initial data
    /// for use by the BareMetalRendering client library.
    /// Must be registered BEFORE RegisterApiRoutes to ensure it matches before
    /// the parameterised GET /api/{type}/{id} route.
    /// </summary>
    public static void RegisterEntityMetadataRoute(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        host.RegisterRoute("GET /api/metadata/{entity}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            async context =>
            {
                var entitySlug = GetRouteParam(context, "entity");
                if (string.IsNullOrWhiteSpace(entitySlug) || !DataScaffold.TryGetEntity(entitySlug, out var meta))
                {
                    context.Response.StatusCode = 404;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Entity not found\"}");
                    return;
                }

                var schemaFields = new Dictionary<string, object?>();
                var initialData  = new Dictionary<string, object?>();
                var layoutFields = new List<string>();

                var sortedFieldsForSchema = new List<DataFieldMetadata>(meta.Fields);
                sortedFieldsForSchema.Sort((a, b) => a.Order.CompareTo(b.Order));
                foreach (var f in sortedFieldsForSchema)
                {
                    var isId = f.Name.Equals("Id", StringComparison.OrdinalIgnoreCase);
                    // Override type to "select" for fields with lookup config so the
                    // client renders a dropdown and hydrates options via lookupUrl.
                    var clientType = f.Lookup != null ? "select" : MapFieldType(f.FieldType);
                    var fieldDef = new Dictionary<string, object?>
                    {
                        ["type"]  = clientType,
                        ["label"] = f.Label
                    };
                    if (f.ReadOnly || isId)
                        fieldDef["readonly"] = true;
                    if (f.Required)
                        fieldDef["required"] = true;
                    if (!string.IsNullOrEmpty(f.Placeholder))
                        fieldDef["placeholder"] = f.Placeholder;
                    if (f.Lookup != null)
                    {
                        // Prefer slug-based resolution: all virtual entities share typeof(DataRecord)
                        // so GetEntityByType alone cannot distinguish them.
                        var target = (f.Lookup.TargetSlug != null
                            && DataScaffold.TryGetEntity(f.Lookup.TargetSlug, out var bySlugTarget))
                            ? bySlugTarget
                            : DataScaffold.GetEntityByType(f.Lookup.TargetType);
                        if (target != null)
                            fieldDef["lookupUrl"] = $"/api/_lookup/{target.Slug}";
                        fieldDef["lookupValueField"]   = f.Lookup.ValueField;
                        fieldDef["lookupDisplayField"] = f.Lookup.DisplayField;
                    }

                    schemaFields[f.Name] = fieldDef;
                    initialData[f.Name]  = GetFieldDefault(f.FieldType);

                    if (f.Edit)
                        layoutFields.Add(f.Name);
                }

                var result = new Dictionary<string, object?>
                {
                    ["name"]        = meta.Name,
                    ["endpoint"]    = $"/api/{meta.Slug}",
                    ["schema"]      = new Dictionary<string, object?> { ["fields"] = schemaFields },
                    ["layout"]      = new Dictionary<string, object?>
                    {
                        ["type"]    = "form",
                        ["columns"] = 1,
                        ["fields"]  = layoutFields
                    },
                    ["initialData"] = initialData
                };

                context.Response.ContentType = "application/json";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                {
                    JsonWriterHelper.WriteValue(w, result);
                }
            }));
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private static string? GetRouteParam(BmwContext context, string key)
    {
        // Fast path: prefix router sets these directly (zero allocation)
        if (string.Equals(key, "type", StringComparison.OrdinalIgnoreCase) && context.EntitySlug != null)
            return context.EntitySlug;
        if (string.Equals(key, "id", StringComparison.OrdinalIgnoreCase) && context.EntityId != null)
            return context.EntityId;
        if (context.RouteExtraKey != null && string.Equals(key, context.RouteExtraKey, StringComparison.OrdinalIgnoreCase))
            return context.RouteExtra;

        var pageContext = context.GetPageContext();
        if (pageContext == null) return null;
        for (int i = 0; i < pageContext.PageMetaDataKeys.Length; i++)
        {
            if (string.Equals(pageContext.PageMetaDataKeys[i], key, StringComparison.OrdinalIgnoreCase))
                return pageContext.PageMetaDataValues[i];
        }
        return null;
    }

    private static string MapFieldType(FormFieldType ft) => ft switch
    {
        FormFieldType.TextArea   => "textarea",
        FormFieldType.Integer
        or FormFieldType.Decimal
        or FormFieldType.Money   => "number",
        FormFieldType.Email      => "email",
        FormFieldType.Password   => "password",
        FormFieldType.DateOnly   => "date",
        FormFieldType.DateTime   => "datetime-local",
        FormFieldType.TimeOnly   => "time",
        FormFieldType.YesNo      => "boolean",
        FormFieldType.LookupList
        or FormFieldType.Enum
        or FormFieldType.Country => "select",
        FormFieldType.Hidden     => "hidden",
        FormFieldType.ReadOnly
        or FormFieldType.CustomHtml => "readonly",
        _                        => "string"
    };

    private static object? GetFieldDefault(FormFieldType ft) => ft switch
    {
        FormFieldType.Integer                    => 0,
        FormFieldType.Decimal or FormFieldType.Money => 0.0,
        FormFieldType.YesNo                      => false,
        _                                        => null
    };

    /// <summary>
    /// Register lookup API routes before generic /api/{type} routes to avoid pattern conflicts.
    /// Must be called before <see cref="RegisterApiRoutes"/>.
    /// </summary>
    public static void RegisterLookupApiRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        // More specific routes must be registered first to avoid {id} matching literal segments
        // Require authentication at route level; entity-level permissions are enforced in each handler via HasEntityPermissionAsync.
        var lookupAuth = pageInfoFactory.RawPage("Authenticated", false);
        host.RegisterRoute("GET /api/_lookup/{type}/_field/{id}/{fieldName}", new RouteHandlerData(lookupAuth, LookupApiHandlers.GetEntityFieldHandler));
        host.RegisterRoute("GET /api/_lookup/{type}/_aggregate", new RouteHandlerData(lookupAuth, LookupApiHandlers.AggregateEntitiesHandler));
        host.RegisterRoute("POST /api/_lookup/{type}/_batch", new RouteHandlerData(lookupAuth, LookupApiHandlers.BatchGetEntitiesHandler));
        host.RegisterRoute("GET /api/_lookup/{type}/{id}", new RouteHandlerData(lookupAuth, LookupApiHandlers.GetEntityByIdHandler));
        host.RegisterRoute("GET /api/_lookup/{type}", new RouteHandlerData(lookupAuth, LookupApiHandlers.QueryEntitiesHandler));
    }

    /// <summary>
    /// Register binary wire-format API routes.
    /// These serve BSO1-encoded payloads for the JS client and CLI — no JSON.
    /// </summary>
    public static void RegisterBinaryApiRoutes(
        this IBareWebHost host,
        IRouteHandlers routeHandlers,
        IPageInfoFactory pageInfoFactory,
        IHtmlTemplate mainTemplate)
    {
        var raw = pageInfoFactory.RawPage("Public", false);
        var adminOnly = pageInfoFactory.RawPage("admin", false);
        host.RegisterRoute("GET /api/_binary/_key", new RouteHandlerData(raw, BinaryApiHandlers.KeyHandler));
        host.RegisterRoute("GET /api/_binary/{type}/_schema", new RouteHandlerData(raw, BinaryApiHandlers.SchemaHandler));
        host.RegisterRoute("GET /api/_binary/{type}/_aggregate", new RouteHandlerData(raw, BinaryApiHandlers.AggregateHandler));
        host.RegisterRoute("GET /api/_binary/{type}/_raw", new RouteHandlerData(raw, BinaryApiHandlers.RawListHandler));
        host.RegisterRoute("GET /api/_binary/{type}/_aggregations", new RouteHandlerData(raw, BinaryApiHandlers.AggregationDefsHandler));
        host.RegisterRoute("GET /api/_binary/{type}/_layout", new RouteHandlerData(raw, DeltaApiHandlers.LayoutHandler));
        host.RegisterRoute("GET /api/_binary/{type}/_actions", new RouteHandlerData(raw, ActionApiHandlers.ListActionsHandler));
        host.RegisterRoute("POST /api/_binary/{type}/_action/{actionId}", new RouteHandlerData(raw, ActionApiHandlers.ExecuteActionHandler));
        host.RegisterRoute("GET /api/_metrics", new RouteHandlerData(adminOnly, EngineMetricsHandler));
        host.RegisterRoute("POST /api/graphql", new RouteHandlerData(pageInfoFactory.RawPage("Authenticated", false), GraphQLHandler.HandleAsync));
        host.RegisterRoute("GET /api/_cluster", new RouteHandlerData(adminOnly, ClusterApiHandlers.ClusterStatusHandler));
        host.RegisterRoute("GET /api/_cluster/replicate", new RouteHandlerData(adminOnly, ClusterApiHandlers.ReplicationHandler));
        host.RegisterRoute("POST /api/_cluster/stepdown", new RouteHandlerData(adminOnly, ClusterApiHandlers.StepDownHandler));
        host.RegisterRoute("GET /api/_cluster/upgrade-status", new RouteHandlerData(adminOnly, ClusterApiHandlers.UpgradeStatusHandler));
        host.RegisterRoute("GET /api/tenants", new RouteHandlerData(adminOnly, TenantApiHandlers.ListTenantsHandler));
        host.RegisterRoute("GET /api/tenants/{id}", new RouteHandlerData(adminOnly, TenantApiHandlers.GetTenantHandler));
        host.RegisterRoute("POST /api/tenants", new RouteHandlerData(adminOnly, TenantApiHandlers.ProvisionTenantHandler));
        host.RegisterRoute("PUT /api/tenants/{id}/branding", new RouteHandlerData(adminOnly, TenantApiHandlers.UpdateBrandingHandler));
        host.RegisterRoute("PUT /api/tenants/{id}/quotas", new RouteHandlerData(adminOnly, TenantApiHandlers.UpdateQuotasHandler));
        host.RegisterRoute("GET /api/tenant/branding", new RouteHandlerData(raw, TenantApiHandlers.GetCurrentBrandingHandler));
        host.RegisterRoute("POST /api/vector/search", new RouteHandlerData(raw, VectorApiHandlers.SearchHandler));
        host.RegisterRoute("POST /api/vector/upsert", new RouteHandlerData(raw, VectorApiHandlers.UpsertHandler));
        host.RegisterRoute("POST /api/vector/delete", new RouteHandlerData(raw, VectorApiHandlers.DeleteHandler));
        host.RegisterRoute("GET /api/vector/indexes", new RouteHandlerData(raw, VectorApiHandlers.ListIndexesHandler));
        host.RegisterRoute("POST /api/vector/register", new RouteHandlerData(adminOnly, VectorApiHandlers.RegisterHandler));
        host.RegisterRoute("POST /api/agent/chat", new RouteHandlerData(raw, AgentApiHandlers.ChatHandler));
        host.RegisterRoute("GET /api/agent/metrics", new RouteHandlerData(raw, AgentApiHandlers.MetricsHandler));
        var templated = pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "html_message" }, new[] { "", "" }, "Public", false, 1);
        host.RegisterRoute("GET /page/{slug}", new RouteHandlerData(templated, routeHandlers.BuildPageHandler(PageRenderer.ConfigurePageAsync)));
        host.RegisterRoute("GET /api/pages", new RouteHandlerData(raw, PageRenderer.ListPagesHandler));
        host.RegisterRoute("GET /products", new RouteHandlerData(templated, routeHandlers.BuildPageHandler(ProductRenderer.ConfigureCategoryBrowseAsync)));
        host.RegisterRoute("GET /products/{category}", new RouteHandlerData(templated, routeHandlers.BuildPageHandler(ProductRenderer.ConfigureProductGridAsync)));
        host.RegisterRoute("GET /api/basket", new RouteHandlerData(raw, BasketApiHandlers.GetBasketHandler));
        host.RegisterRoute("POST /api/basket/add", new RouteHandlerData(raw, BasketApiHandlers.AddItemHandler));
        host.RegisterRoute("POST /api/basket/remove", new RouteHandlerData(raw, BasketApiHandlers.RemoveItemHandler));
        host.RegisterRoute("POST /api/basket/clear", new RouteHandlerData(raw, BasketApiHandlers.ClearBasketHandler));
        host.RegisterRoute("POST /api/checkout", new RouteHandlerData(raw, CheckoutApiHandlers.CheckoutHandler));
        host.RegisterRoute("POST /api/checkout/confirm", new RouteHandlerData(raw, CheckoutApiHandlers.ConfirmPaymentHandler));
        host.RegisterRoute("GET /api/_binary/{type}/{id}", new RouteHandlerData(raw, BinaryApiHandlers.GetHandler));
        host.RegisterRoute("GET /api/_binary/{type}", new RouteHandlerData(raw, BinaryApiHandlers.ListHandler));
        host.RegisterRoute("POST /api/_binary/{type}", new RouteHandlerData(raw, BinaryApiHandlers.CreateHandler));
        host.RegisterRoute("PUT /api/_binary/{type}/{id}", new RouteHandlerData(raw, BinaryApiHandlers.UpdateHandler));
        host.RegisterRoute("DELETE /api/_binary/{type}/{id}", new RouteHandlerData(raw, BinaryApiHandlers.DeleteHandler));
        host.RegisterRoute("PATCH /api/_binary/{type}/{id}", new RouteHandlerData(raw, DeltaApiHandlers.DeltaHandler));
    }

    /// <summary>
    /// Register RESTful API routes for entity operations.
    /// </summary>
    public static void RegisterApiRoutes(
        this IBareWebHost host,
        IRouteHandlers routeHandlers,
        IPageInfoFactory pageInfoFactory)
    {
        // Lookup API routes are registered separately via RegisterLookupApiRoutes()
        // which must be called before this method (see BareMetalWebExtensions.cs).

        // Global search — must precede /api/{type} routes to avoid '_global-search' matching {type}
        host.RegisterRoute("GET /api/_global-search", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.GlobalSearchHandler));

        // Background job status — must precede /api/{type}/{id} to avoid 'jobs' matching {type}
        host.RegisterRoute("GET /api/jobs", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.JobsListHandler));

        host.RegisterRoute("GET /api/jobs/{jobId}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.JobStatusHandler));

        host.RegisterRoute("DELETE /api/jobs/{jobId}", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            routeHandlers.CancelJobHandler));

        // Admin JSON endpoints for VNext SPA (no CSRF form token required — validated via X-CSRF-Token header)
        host.RegisterRoute("POST /api/admin/sample-data", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            routeHandlers.AdminSampleDataJsonHandler));

        host.RegisterRoute("POST /api/admin/wipe-data", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            routeHandlers.AdminWipeDataJsonHandler));

        host.RegisterRoute("GET /api/admin/query-plans", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            routeHandlers.QueryPlanHistoryHandler));

        // Attachment API routes — must be registered before the generic /api/{type}/{id} route
        host.RegisterRoute("GET /api/{type}/{id}/_attachments", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.AttachmentsListHandler));
        host.RegisterRoute("POST /api/{type}/{id}/_attachments", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.AttachmentsUploadHandler));
        host.RegisterRoute("GET /api/_attachments/{id}/download", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.AttachmentsDownloadHandler));
        host.RegisterRoute("DELETE /api/_attachments/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.AttachmentsDeleteHandler));
        host.RegisterRoute("GET /api/_attachments/{id}/versions", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.AttachmentsVersionsHandler));

        // Comments API routes
        host.RegisterRoute("GET /api/{type}/{id}/_comments", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.CommentsListHandler));
        host.RegisterRoute("POST /api/{type}/{id}/_comments", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.CommentsAddHandler));
        host.RegisterRoute("PATCH /api/_comments/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.CommentsEditHandler));
        host.RegisterRoute("DELETE /api/_comments/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.CommentsDeleteHandler));

        // Document chain — must be before the generic GET /api/{type}/{id} route
        host.RegisterRoute("GET /api/{type}/{id}/_related-chain", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            async context =>
            {
                var slug = GetRouteParam(context, "type") ?? string.Empty;
                var id   = GetRouteParam(context, "id")   ?? string.Empty;

                if (!DataScaffold.TryGetEntity(slug, out var meta))
                {
                    context.Response.StatusCode = 404;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Entity not found\"}");
                    return;
                }

                // ── Upstream: walk RelatedDocument fields to find parent documents ──────────
                var upstream = new List<object>();
                if (meta.DocumentRelationFields is { Count: > 0 })
                {
                    // Load the current record to get its FK values
                    if (uint.TryParse(id, out var uKey))
                    {
                        var current = await meta.Handlers.LoadAsync(uKey, context.RequestAborted).ConfigureAwait(false);
                        if (current != null)
                        {
                            foreach (var rf in meta.DocumentRelationFields)
                            {
                                if (rf.RelatedDocument == null) continue;
                                var fkVal = rf.GetValueFn(current)?.ToString();
                                if (string.IsNullOrEmpty(fkVal)) continue;

                                var targetMeta = !string.IsNullOrEmpty(rf.RelatedDocument.TargetSlug)
                                    && DataScaffold.TryGetEntity(rf.RelatedDocument.TargetSlug, out var slugMeta)
                                    ? slugMeta
                                    : DataScaffold.GetEntityByType(rf.RelatedDocument.TargetType);
                                if (targetMeta == null) continue;

                                // Try to load the upstream document
                                object? parentDoc = null;
                                string? parentLabel = null;
                                if (uint.TryParse(fkVal, out var parentKey))
                                {
                                    parentDoc = await targetMeta.Handlers.LoadAsync(parentKey, context.RequestAborted).ConfigureAwait(false);
                                    if (parentDoc != null)
                                    {
                                        DataFieldMetadata? displayField = null;
                                        foreach (var fCandidate in targetMeta.Fields)
                                        {
                                            if (string.Equals(fCandidate.Name, rf.RelatedDocument.DisplayField, StringComparison.OrdinalIgnoreCase))
                                            {
                                                displayField = fCandidate;
                                                break;
                                            }
                                        }
                                        parentLabel = displayField?.GetValueFn(parentDoc)?.ToString();
                                    }
                                }

                                upstream.Add(new Dictionary<string, object?>
                                {
                                    ["fieldName"]   = rf.Name,
                                    ["fieldLabel"]  = rf.Label,
                                    ["targetSlug"]  = targetMeta.Slug,
                                    ["targetName"]  = targetMeta.Name,
                                    ["id"]          = fkVal,
                                    ["label"]       = parentLabel ?? fkVal
                                });
                            }
                        }
                    }
                }

                // ── Downstream: find entities whose RelatedDocument field points to this type ─
                var downstream = new List<object>();
                foreach (var childMeta in DataScaffold.Entities)
                {
                    if (childMeta.DocumentRelationFields == null) continue;
                    foreach (var rf in childMeta.DocumentRelationFields)
                    {
                        if (rf.RelatedDocument == null) continue;
                        // Match by slug (metadata-driven) or CLR type (compiled entities)
                        bool matches = !string.IsNullOrEmpty(rf.RelatedDocument.TargetSlug)
                            ? string.Equals(rf.RelatedDocument.TargetSlug, meta.Slug, StringComparison.OrdinalIgnoreCase)
                            : rf.RelatedDocument.TargetType == meta.Type;
                        if (!matches) continue;

                        // Query child records that reference this record's ID
                        var query = new QueryDefinition
                        {
                            Clauses = new List<QueryClause> { new QueryClause { Field = rf.Name, Operator = QueryOperator.Equals, Value = id } },
                            Top = 50
                        };

                        var children = await childMeta.Handlers.QueryAsync(query, context.RequestAborted).ConfigureAwait(false);
                        DataFieldMetadata? labelField = null;
                        {
                            int bestOrder = int.MaxValue;
                            foreach (var fCandidate in childMeta.Fields)
                            {
                                if (fCandidate.List && fCandidate.Order < bestOrder)
                                {
                                    bestOrder = fCandidate.Order;
                                    labelField = fCandidate;
                                }
                            }
                        }

                        foreach (var child in children)
                        {
                            var childId = (child as BaseDataObject)?.Key.ToString() ?? string.Empty;
                            var childLabel = labelField?.GetValueFn(child)?.ToString() ?? childId;
                            downstream.Add(new Dictionary<string, object?>
                            {
                                ["fieldName"]  = rf.Name,
                                ["fieldLabel"] = rf.Label,
                                ["targetSlug"] = childMeta.Slug,
                                ["targetName"] = childMeta.Name,
                                ["id"]         = childId,
                                ["label"]      = childLabel
                            });
                        }
                    }
                }

                var result = new Dictionary<string, object?>
                {
                    ["sourceSlug"] = slug,
                    ["sourceId"]   = id,
                    ["upstream"]   = upstream,
                    ["downstream"] = downstream
                };

                context.Response.ContentType = "application/json";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                {
                    JsonWriterHelper.WriteValue(w, result);
                }
            }));

        // Sankey graph: aggregate document chain counts across all entities with RelatedDocument fields
        host.RegisterRoute("GET /api/_document-chain-graph", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            async context =>
            {
                var nodes = new List<object>();
                var links = new List<object>();
                var seenSlugs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var entityMeta in DataScaffold.Entities)
                {
                    if (entityMeta.DocumentRelationFields == null || entityMeta.DocumentRelationFields.Count == 0)
                        continue;

                    var count = await entityMeta.Handlers.CountAsync(null, context.RequestAborted).ConfigureAwait(false);

                    if (seenSlugs.Add(entityMeta.Slug))
                        nodes.Add(new Dictionary<string, object?> { ["slug"] = entityMeta.Slug, ["name"] = entityMeta.Name, ["count"] = count });

                    foreach (var rf in entityMeta.DocumentRelationFields)
                    {
                        if (rf.RelatedDocument == null) continue;
                        var targetMeta = !string.IsNullOrEmpty(rf.RelatedDocument.TargetSlug)
                            && DataScaffold.TryGetEntity(rf.RelatedDocument.TargetSlug, out var slugMeta)
                            ? slugMeta
                            : DataScaffold.GetEntityByType(rf.RelatedDocument.TargetType);
                        if (targetMeta == null) continue;

                        if (seenSlugs.Add(targetMeta.Slug))
                        {
                            var tCount = await targetMeta.Handlers.CountAsync(null, context.RequestAborted).ConfigureAwait(false);
                            nodes.Add(new Dictionary<string, object?> { ["slug"] = targetMeta.Slug, ["name"] = targetMeta.Name, ["count"] = tCount });
                        }

                        // Count how many child records have the FK populated (non-empty)
                        var linkedQuery = new QueryDefinition
                        {
                            Clauses = new List<QueryClause> { new QueryClause { Field = rf.Name, Operator = QueryOperator.NotEquals, Value = "" } }
                        };
                        var linkedCount = await entityMeta.Handlers.CountAsync(linkedQuery, context.RequestAborted).ConfigureAwait(false);

                        links.Add(new Dictionary<string, object?>
                        {
                            ["from"]   = targetMeta.Slug,
                            ["to"]     = entityMeta.Slug,
                            ["field"]  = rf.Name,
                            ["count"]  = linkedCount
                        });
                    }
                }

                context.Response.ContentType = "application/json";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                {
                    JsonWriterHelper.WriteValue(w, new Dictionary<string, object?> { ["nodes"] = nodes, ["links"] = links });
                }
            }));

        // List and create
        host.RegisterRoute("GET /api/{type}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataApiListHandler));
        host.RegisterRoute("POST /api/{type}/import", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataApiImportHandler));
        host.RegisterRoute("POST /api/{type}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataApiPostHandler));

        // Get, update, and delete
        host.RegisterRoute("GET /api/{type}/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataApiGetHandler));
        host.RegisterRoute("PUT /api/{type}/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataApiPutHandler));
        host.RegisterRoute("PATCH /api/{type}/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataApiPatchHandler));
        host.RegisterRoute("DELETE /api/{type}/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataApiDeleteHandler));
        host.RegisterRoute("GET /api/{type}/{id}/files/{field}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataApiFileGetHandler));

        // Remote commands
        host.RegisterRoute("POST /api/{type}/{id}/_command/{command}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataCommandHandler));
    }

    /// <summary>
    /// Register the VNext JS SPA shell and metadata API endpoints.
    /// Metadata routes at /meta/objects and /meta/{object} provide schema info to the client.
    /// The SPA shell at /{*path} serves the client-side application as a catch-all fallback.
    /// </summary>
    public static void RegisterVNextRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory,
        ITemplateStore templateStore)
    {
        // List accessible entities for the current user
        host.RegisterRoute("GET /meta/objects", new RouteHandlerData(
            pageInfoFactory.RawPage("Public", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                var userPermissions = UserAuth.GetPermissions(user);

                var entitiesList = new List<object>();
                foreach (var e in DataScaffold.Entities)
                {
                    if (!await IsEntityAccessibleAsync(e, user, userPermissions).ConfigureAwait(false)) continue;
                    entitiesList.Add(new Dictionary<string, object?>
                    {
                        ["slug"]         = e.Slug,
                        ["name"]         = e.Name,
                        ["navGroup"]     = e.NavGroup,
                        ["showOnNav"]    = e.ShowOnNav,
                        ["navOrder"]     = e.NavOrder,
                        ["viewType"]     = e.ViewType.ToString(),
                        ["rightAligned"] = string.Equals(e.NavGroup, "Admin", StringComparison.OrdinalIgnoreCase)
                    });
                }
                var entities = entitiesList.ToArray();

                context.Response.ContentType = "application/json";
                context.Response.Headers["Cache-Control"] = "private, max-age=300";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                {
                    JsonWriterHelper.WriteValue(w, entities);
                }
            }));

        // Full schema for a single entity, including fields, lookups, computed, and commands
        host.RegisterRoute("GET /meta/{object}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            async context =>
            {
                var slug = GetMetaRouteParam(context, "object") ?? string.Empty;
                if (!DataScaffold.TryGetEntity(slug, out var metadata))
                {
                    context.Response.StatusCode = 404;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Entity not found\"}");
                    return;
                }

                var result = BuildEntitySchema(metadata);
                context.Response.ContentType = "application/json";
                context.Response.Headers["Cache-Control"] = "private, max-age=300";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                {
                    JsonWriterHelper.WriteValue(w, result);
                }
            }));

        // VNext SPA shell — nav entry visible in the Admin dropdown.
        host.RegisterRoute("GET /d", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", true, navGroup: "Admin", navAlignment: NavAlignment.Right, navLabel: "Data", navSubGroup: "🔧 Tools"),
            context => ServeVNextShell(context, host, templateStore)));

        // Catch-all fallback: serves the VNext SPA shell for any unmatched path
        // (e.g. /{slug}, /{slug}/{id}, /{slug}/{id}/edit).
        // Registered last and has 0 literal segments so the route sorter tries
        // all specific routes first.
        host.RegisterRoute("GET /{*path}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            context => ServeVNextShell(context, host, templateStore)));
    }

    /// <summary>
    /// Registers the metadata-driven Runtime API endpoints:
    /// <list type="bullet">
    ///   <item><description>GET /meta/entity/{name} — returns a <see cref="RuntimeEntityModel"/> as JSON, including EntityId, schemaHash, indexes, and actions.</description></item>
    ///   <item><description>POST /query — accepts { entity, clauses, sorts, skip, top } and returns matching records.</description></item>
    ///   <item><description>POST /intent — accepts a <see cref="BareMetalWeb.Runtime.CommandIntent"/> and executes create/update/delete/action.</description></item>
    ///   <item><description>GET /api/meta/registered-types — lists C# entity types available for metadata import.</description></item>
    ///   <item><description>POST /api/meta/seed-from-types — seeds EntityDefinition records from registered C# entity types (admin only). Pass ?overwrite=true to replace existing records.</description></item>
    /// </list>
    /// Must be registered BEFORE <see cref="RegisterApiRoutes"/> to avoid slug conflicts.
    /// </summary>
    public static void RegisterRuntimeApiRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        var queryService = new BareMetalWeb.Runtime.QueryService();
        var commandService = new BareMetalWeb.Runtime.CommandService();

        // GET /meta/entity/{name} — RuntimeEntityModel schema + DataEntityMetadata fields
        host.RegisterRoute("GET /meta/entity/{name}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            async context =>
            {
                var slug = GetRouteParam(context, "name") ?? string.Empty;

                if (!BareMetalWeb.Runtime.RuntimeEntityRegistry.Current.TryGet(slug, out var runtimeModel))
                {
                    context.Response.StatusCode = 404;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Runtime entity not found\"}");
                    return;
                }

                var runtimeFieldsList = new object[runtimeModel.Fields.Count];
                for (int fi = 0; fi < runtimeModel.Fields.Count; fi++)
                {
                    var f = runtimeModel.Fields[fi];
                    runtimeFieldsList[fi] = new Dictionary<string, object?>
                    {
                        ["fieldId"] = f.FieldId,
                        ["ordinal"] = f.Ordinal,
                        ["name"] = f.Name,
                        ["label"] = f.Label,
                        ["type"] = f.FieldType.ToString(),
                        ["isNullable"] = f.IsNullable,
                        ["required"] = f.Required,
                        ["list"] = f.List,
                        ["view"] = f.View,
                        ["edit"] = f.Edit,
                        ["create"] = f.Create,
                        ["readOnly"] = f.ReadOnly,
                        ["defaultValue"] = f.DefaultValue,
                        ["placeholder"] = f.Placeholder,
                        ["enumValues"] = f.EnumValues,
                        ["lookupEntitySlug"] = f.LookupEntitySlug,
                        ["lookupValueField"] = f.LookupValueField,
                        ["lookupDisplayField"] = f.LookupDisplayField,
                        ["validation"] = (f.MinLength.HasValue || f.MaxLength.HasValue ||
                                          f.RangeMin.HasValue || f.RangeMax.HasValue ||
                                          !string.IsNullOrEmpty(f.Pattern))
                            ? (object)new Dictionary<string, object?>
                              {
                                  ["minLength"] = f.MinLength,
                                  ["maxLength"] = f.MaxLength,
                                  ["rangeMin"] = f.RangeMin,
                                  ["rangeMax"] = f.RangeMax,
                                  ["pattern"] = f.Pattern
                              }
                            : null
                    };
                }
                var runtimeIndexesList = new object[runtimeModel.Indexes.Count];
                for (int ii = 0; ii < runtimeModel.Indexes.Count; ii++)
                {
                    var idx = runtimeModel.Indexes[ii];
                    runtimeIndexesList[ii] = new Dictionary<string, object?>
                    {
                        ["indexId"] = idx.IndexId,
                        ["fields"] = idx.FieldNames,
                        ["type"] = idx.Type
                    };
                }
                var runtimeActionsList = new object[runtimeModel.Actions.Count];
                for (int ai = 0; ai < runtimeModel.Actions.Count; ai++)
                {
                    var a = runtimeModel.Actions[ai];
                    runtimeActionsList[ai] = new Dictionary<string, object?>
                    {
                        ["actionId"] = a.ActionId,
                        ["name"] = a.Name,
                        ["label"] = a.Label,
                        ["icon"] = a.Icon,
                        ["permission"] = a.Permission,
                        ["enabledWhen"] = a.EnabledWhen
                    };
                }

                var result = new Dictionary<string, object?>
                {
                    ["entityId"] = runtimeModel.EntityId,
                    ["name"] = runtimeModel.Name,
                    ["slug"] = runtimeModel.Slug,
                    ["permissions"] = runtimeModel.Permissions,
                    ["showOnNav"] = runtimeModel.ShowOnNav,
                    ["navGroup"] = runtimeModel.NavGroup,
                    ["navOrder"] = runtimeModel.NavOrder,
                    ["idStrategy"] = runtimeModel.IdStrategy.ToString(),
                    ["version"] = runtimeModel.Version,
                    ["schemaHash"] = runtimeModel.SchemaHash,
                    ["formLayout"] = runtimeModel.FormLayout,
                    ["fields"] = runtimeFieldsList,
                    ["indexes"] = runtimeIndexesList,
                    ["actions"] = runtimeActionsList
                };

                context.Response.ContentType = "application/json";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                {
                    JsonWriterHelper.WriteValue(w, result);
                }
            }));

        // POST /query — { "entity": "slug", "clauses": [...], "sorts": [...], "skip": 0, "top": 50 }
        host.RegisterRoute("POST /query", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            async context =>
            {
                using var reader = new System.IO.StreamReader(context.HttpRequest.Body);
                var body = await reader.ReadToEndAsync(context.RequestAborted).ConfigureAwait(false);

                string entitySlug;
                QueryDefinition? query;
                try
                {
                    using var doc = JsonDocument.Parse(body);
                    var root = doc.RootElement;
                    entitySlug = root.TryGetProperty("entity", out var ep) ? ep.GetString() ?? string.Empty : string.Empty;
                    query = BuildQueryFromJson(root);
                }
                catch (Exception)
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                    {
                        w.WriteStartObject();
                        w.WriteString("error", "Invalid request.");
                        w.WriteEndObject();
                    }
                    return;
                }

                if (string.IsNullOrWhiteSpace(entitySlug))
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"'entity' field is required\"}");
                    return;
                }

                var results = await queryService.QueryAsync(entitySlug, query, context.RequestAborted).ConfigureAwait(false);
                context.Response.ContentType = "application/json";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                {
                    JsonWriterHelper.WriteValue(w, results);
                }
            }));

        // POST /intent — CommandIntent body
        host.RegisterRoute("POST /intent", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            async context =>
            {
                using var reader = new System.IO.StreamReader(context.HttpRequest.Body);
                var body = await reader.ReadToEndAsync(context.RequestAborted).ConfigureAwait(false);

                BareMetalWeb.Runtime.CommandIntent intent;
                try
                {
                    using var jdoc = JsonDocument.Parse(body);
                    var root = jdoc.RootElement;
                    intent = new BareMetalWeb.Runtime.CommandIntent
                    {
                        EntitySlug = root.TryGetProperty("entitySlug", out var es) ? es.GetString() ?? string.Empty : string.Empty,
                        EntityId = root.TryGetProperty("entityId", out var ei) ? ei.GetString() : null,
                        Operation = root.TryGetProperty("operation", out var op) ? op.GetString() ?? string.Empty : string.Empty,
                        Fields = root.TryGetProperty("fields", out var fp) && fp.ValueKind == JsonValueKind.Object
                            ? new Dictionary<string, string?>(fp.EnumerateObject().Count(), StringComparer.OrdinalIgnoreCase)
                            : new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase)
                    };
                    if (fp.ValueKind == JsonValueKind.Object)
                    {
                        foreach (var prop in fp.EnumerateObject())
                            intent.Fields[prop.Name] = prop.Value.ValueKind == JsonValueKind.Null ? null : prop.Value.ToString();
                    }
                }
                catch (Exception)
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                    {
                        w.WriteStartObject();
                        w.WriteString("error", "Invalid request.");
                        w.WriteEndObject();
                    }
                    return;
                }

                var result = await commandService.ExecuteAsync(intent, context.RequestAborted).ConfigureAwait(false);
                context.Response.StatusCode = result.Success ? 200 : 400;
                context.Response.ContentType = "application/json";
                await using (var w2 = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                {
                    w2.WriteStartObject();
                    w2.WriteBoolean("success", result.Success);
                    if (result.Error != null) w2.WriteString("error", result.Error);
                    if (result.EntityId != null) w2.WriteString("entityId", result.EntityId);
                    if (result.Data != null)
                    {
                        w2.WritePropertyName("data");
                        JsonWriterHelper.WriteValue(w2, result.Data);
                    }
                    w2.WriteEndObject();
                }
            }));

        // GET /api/meta/registered-types — lists C# entity types available for metadata import
        host.RegisterRoute("GET /api/meta/registered-types", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var filteredTypes = new List<DataEntityMetadata>();
                foreach (var m in DataScaffold.Entities)
                {
                    if (m.Type != typeof(DataRecord))
                        filteredTypes.Add(m);
                }
                filteredTypes.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.Ordinal));
                var types = new object[filteredTypes.Count];
                for (int ti = 0; ti < filteredTypes.Count; ti++)
                {
                    var m = filteredTypes[ti];
                    types[ti] = new Dictionary<string, object?>
                    {
                        ["name"] = m.Name,
                        ["slug"] = m.Slug,
                        ["typeName"] = m.Type.Name,
                        ["assembly"] = m.Type.Assembly.GetName().Name,
                        ["showOnNav"] = m.ShowOnNav,
                        ["navGroup"] = m.NavGroup,
                        ["fieldCount"] = m.Fields.Count
                    };
                }

                context.Response.ContentType = "application/json";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                {
                    JsonWriterHelper.WriteValue(w, types);
                }
            }));

        // POST /api/meta/seed-from-types — seeds EntityDefinition records for registered C# entity types
        host.RegisterRoute("POST /api/meta/seed-from-types", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var overwrite = context.HttpRequest.Query.TryGetValue("overwrite", out var ovVal)
                    && string.Equals(ovVal, "true", StringComparison.OrdinalIgnoreCase);

                var messages = new List<string>();
                var seeded = await BareMetalWeb.Runtime.MetadataSeeder
                    .SeedFromRegisteredEntitiesAsync(
                        DataStoreProvider.Current,
                        overwrite,
                        msg => messages.Add(msg),
                        context.RequestAborted)
                    .ConfigureAwait(false);

                context.Response.ContentType = "application/json";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                {
                    w.WriteStartObject();
                    w.WritePropertyName("seeded");
                    JsonWriterHelper.WriteValue(w, seeded);
                    w.WriteNumber("count", seeded.Count);
                    w.WritePropertyName("messages");
                    JsonWriterHelper.WriteValue(w, messages);
                    w.WriteEndObject();
                }
            }));
    }

    // ─── MCP routes ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Registers the MCP (Model Context Protocol) server endpoint at POST /mcp.
    /// Exposes all registered BareMetalWeb entities as MCP tools (query, get, create,
    /// update, delete, and named commands), enabling AI assistants to interact with
    /// application data using the standard JSON-RPC 2.0 MCP protocol.
    /// </summary>
    public static void RegisterMcpRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        host.RegisterRoute("POST /mcp", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            McpRouteHandler.HandleAsync));
    }

    // ─── OpenAPI routes ──────────────────────────────────────────────────────────

    /// <summary>
    /// Registers GET /openapi.json — a rudimentary OpenAPI 3.0.3 specification built
    /// by recursing the entity types registered with <see cref="DataScaffold"/>.
    /// Only entities accessible to the authenticated caller are included.
    /// No Swagger/NSwag library is used; the JSON is constructed manually.
    /// </summary>
    public static void RegisterOpenApiRoute(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        host.RegisterRoute("GET /openapi.json", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            OpenApiHandler.HandleAsync));
    }

    // ─── Private helpers ────────────────────────────────────────────────────────

    private static async ValueTask<bool> IsEntityAccessibleAsync(DataEntityMetadata entity, BaseDataObject? user, string[] userPermissions)
    {
        var perms = entity.Permissions ?? string.Empty;
        if (string.IsNullOrWhiteSpace(perms) || string.Equals(perms, "Public", StringComparison.OrdinalIgnoreCase))
            return true;
        if (string.Equals(perms, "Authenticated", StringComparison.OrdinalIgnoreCase))
            return user != null;

        // Legacy flat check — span-based iteration to avoid string[] allocation
        var remaining = perms.AsSpan();
        bool hasMatchingPermission = false;
        while (remaining.Length > 0)
        {
            int idx = remaining.IndexOf(',');
            ReadOnlySpan<char> segment;
            if (idx < 0) { segment = remaining; remaining = default; }
            else { segment = remaining[..idx]; remaining = remaining[(idx + 1)..]; }
            var trimmed = segment.Trim();
            if (trimmed.IsEmpty) continue;
            foreach (var p in userPermissions)
            {
                if (trimmed.Equals(p.AsSpan(), StringComparison.OrdinalIgnoreCase))
                {
                    hasMatchingPermission = true;
                    break;
                }
            }
            if (hasMatchingPermission) break;
        }
        if (hasMatchingPermission)
            return true;

        // RBAC check via resolved permission set
        if (user != null)
        {
            var resolved = await PermissionResolver.ResolveAsync(user, CancellationToken.None)
                .ConfigureAwait(false);
            if (resolved.CanAccess(entity.Slug))
                return true;
        }

        return false;
    }

    private static string? GetMetaRouteParam(BmwContext context, string key)
    {
        var pageContext = context.GetPageContext();
        if (pageContext == null)
            return null;
        for (int i = 0; i < pageContext.PageMetaDataKeys.Length; i++)
        {
            if (string.Equals(pageContext.PageMetaDataKeys[i], key, StringComparison.OrdinalIgnoreCase))
                return pageContext.PageMetaDataValues[i];
        }
        return null;
    }

    private static Dictionary<string, object?> BuildEntitySchema(DataEntityMetadata meta)
    {
        var sortedFieldsForBuild = new List<DataFieldMetadata>(meta.Fields);
        sortedFieldsForBuild.Sort((a, b) => a.Order.CompareTo(b.Order));
        var fieldsList = new object[sortedFieldsForBuild.Count];
        for (int fi = 0; fi < sortedFieldsForBuild.Count; fi++)
        {
            var f = sortedFieldsForBuild[fi];
            var fd = new Dictionary<string, object?>
            {
                ["name"] = f.Name,
                ["label"] = f.Label,
                ["type"] = f.Lookup != null ? FormFieldType.LookupList.ToString() :
                           f.FieldType == FormFieldType.ChildList ? FormFieldType.CustomHtml.ToString() :
                           f.FieldType.ToString(),
                ["order"] = f.Order,
                ["required"] = f.Required,
                ["list"] = f.List,
                ["view"] = f.View,
                ["edit"] = f.Edit,
                ["create"] = f.Create,
                ["readOnly"] = f.ReadOnly,
                ["isIdField"] = f.IdGeneration != IdGenerationStrategy.None,
                ["idGeneration"] = f.IdGeneration.ToString(),
                ["placeholder"] = f.Placeholder,
                ["indexed"] = f.IsIndexed,
                ["fieldGroup"] = f.FieldGroup,
                ["columnSpan"] = f.ColumnSpan
            };

            if (f.Lookup != null)
            {
                // Prefer slug-based resolution: all virtual entities share typeof(DataRecord)
                // so GetEntityByType alone cannot distinguish them.
                var targetMeta = (f.Lookup.TargetSlug != null
                    && DataScaffold.TryGetEntity(f.Lookup.TargetSlug, out var bySlugMeta))
                    ? bySlugMeta
                    : DataScaffold.GetEntityByType(f.Lookup.TargetType);
                // The generic /api/{slug} endpoint serialises the entity key as "id".
                // When the lookup's ValueField is the C# key property ("Key"), map it to
                // "id" so the VNext SPA's loadLookupSelect correctly matches options.
                var clientValueField = string.Equals(f.Lookup.ValueField,
                    nameof(BaseDataObject.Key),
                    StringComparison.OrdinalIgnoreCase) ? "id" : f.Lookup.ValueField;
                fd["lookup"] = new Dictionary<string, object?>
                {
                    ["targetSlug"] = targetMeta?.Slug,
                    ["targetName"] = targetMeta?.Name,
                    ["valueField"] = clientValueField,
                    ["displayField"] = f.Lookup.DisplayField,
                    ["queryField"] = f.Lookup.QueryField,
                    ["queryOperator"] = f.Lookup.QueryOperator.ToString(),
                    ["queryValue"] = f.Lookup.QueryValue,
                    ["sortField"] = f.Lookup.SortField,
                    ["sortDirection"] = f.Lookup.SortDirection.ToString(),
                    ["sourceSlug"] = meta.Slug,
                    ["sourceFieldName"] = f.Name,
                    ["cascadeFromField"] = f.CascadeFromField,
                    ["cascadeFilterField"] = f.CascadeFilterField
                };
            }
            else
            {
                fd["lookup"] = null;
            }

            if (f.Computed != null)
            {
                fd["computed"] = new Dictionary<string, object?>
                {
                    ["strategy"] = f.Computed.Strategy.ToString(),
                    ["trigger"] = f.Computed.Trigger.ToString(),
                    ["aggregate"] = f.Computed.Aggregate.ToString(),
                    ["sourceField"] = f.Computed.SourceField,
                    ["foreignKeyField"] = f.Computed.ForeignKeyField,
                    ["childCollectionProperty"] = f.Computed.ChildCollectionProperty
                };
            }
            else
            {
                fd["computed"] = null;
            }

            if (f.Calculated != null)
            {
                string jsExpr;
                try
                {
                    var parser = new BareMetalWeb.Data.ExpressionEngine.ExpressionParser();
                    var ast = parser.Parse(f.Calculated.Expression);
                    jsExpr = ast.ToJavaScript();
                }
                catch
                {
                    jsExpr = "0";
                }
                fd["calculated"] = new Dictionary<string, object?>
                {
                    ["expression"] = jsExpr,
                    ["displayFormat"] = f.Calculated.DisplayFormat
                };
            }
            else
            {
                fd["calculated"] = null;
            }

            if (f.Validation != null)
            {
                fd["validation"] = new Dictionary<string, object?>
                {
                    ["minLength"] = f.Validation.MinLength,
                    ["maxLength"] = f.Validation.MaxLength,
                    ["rangeMin"] = f.Validation.RangeMin,
                    ["rangeMax"] = f.Validation.RangeMax,
                    ["pattern"] = f.Validation.RegexPattern,
                    ["isEmail"] = f.Validation.IsEmail,
                    ["isUrl"] = f.Validation.IsUrl
                };
            }
            else
            {
                fd["validation"] = null;
            }

            if (f.Upload != null)
            {
                fd["upload"] = new Dictionary<string, object?>
                {
                    ["maxFileSizeBytes"] = f.Upload.MaxFileSizeBytes,
                    ["allowedMimeTypes"] = f.Upload.AllowedMimeTypes,
                    ["generateThumbnail"] = f.Upload.GenerateThumbnail
                };
            }
            else
            {
                fd["upload"] = null;
            }

            // Sub-field schema for List<T> child collections (CustomHtml type)
            fd["subFields"] = DataScaffold.BuildSubFieldSchemas(f);
            if (f.FieldType == FormFieldType.Enum)
            {
                var enumOptions = DataScaffold.BuildEnumOptions(f);
                var enumArr = new object[enumOptions.Count];
                for (int ei = 0; ei < enumOptions.Count; ei++)
                    enumArr[ei] = new { value = enumOptions[ei].Key, label = enumOptions[ei].Value };
                fd["enumValues"] = enumArr;
            }
            else
            {
                fd["enumValues"] = null;
            }

            if (f.RelatedDocument != null)
            {
                var targetMeta = !string.IsNullOrEmpty(f.RelatedDocument.TargetSlug)
                    && DataScaffold.TryGetEntity(f.RelatedDocument.TargetSlug, out var rdSlugMeta)
                    ? rdSlugMeta
                    : DataScaffold.GetEntityByType(f.RelatedDocument.TargetType);
                fd["relatedDocument"] = new Dictionary<string, object?>
                {
                    ["targetSlug"] = targetMeta?.Slug,
                    ["targetName"] = targetMeta?.Name,
                    ["displayField"] = f.RelatedDocument.DisplayField
                };
            }
            else
            {
                fd["relatedDocument"] = null;
            }

            fieldsList[fi] = fd;
        }
        var fields = fieldsList;

        var sortedCommands = new List<RemoteCommandMetadata>(meta.Commands);
        sortedCommands.Sort((a, b) => a.Order.CompareTo(b.Order));
        var commands = new object[sortedCommands.Count];
        for (int ci = 0; ci < sortedCommands.Count; ci++)
        {
            var c = sortedCommands[ci];
            commands[ci] = new Dictionary<string, object?>
            {
                ["name"] = c.Name,
                ["label"] = c.Label,
                ["icon"] = c.Icon,
                ["confirmMessage"] = c.ConfirmMessage,
                ["destructive"] = c.Destructive,
                ["permission"] = c.Permission,
                ["order"] = c.Order
            };
        }

        bool canShowWorkflow = false;
        foreach (var f in meta.Fields)
        {
            if (f.FieldType == BareMetalWeb.Rendering.Models.FormFieldType.Enum)
            {
                canShowWorkflow = true;
                break;
            }
        }

        object[]? documentRelationFieldsArray = null;
        if (meta.DocumentRelationFields != null && meta.DocumentRelationFields.Count > 0)
        {
            var drfList = new object[meta.DocumentRelationFields.Count];
            for (int di = 0; di < meta.DocumentRelationFields.Count; di++)
            {
                var f = meta.DocumentRelationFields[di];
                var targetMeta = DataScaffold.GetEntityByType(f.RelatedDocument!.TargetType);
                drfList[di] = new Dictionary<string, object?>
                {
                    ["name"] = f.Name,
                    ["label"] = f.Label,
                    ["targetSlug"] = targetMeta?.Slug,
                    ["targetName"] = targetMeta?.Name,
                    ["displayField"] = f.RelatedDocument.DisplayField
                };
            }
            documentRelationFieldsArray = drfList;
        }

        return new Dictionary<string, object?>
        {
            ["slug"] = meta.Slug,
            ["name"] = meta.Name,
            ["permissions"] = meta.Permissions,
            ["showOnNav"] = meta.ShowOnNav,
            ["navGroup"] = meta.NavGroup,
            ["navOrder"] = meta.NavOrder,
            ["viewType"] = meta.ViewType.ToString(),
            ["canShowTimetable"] = DataScaffold.CanShowTimetableView(meta),
            ["canShowTimeline"] = DataScaffold.CanShowTimelineView(meta),
            ["canShowSankey"] = DataScaffold.CanShowSankeyView(meta),
            ["canShowCalendar"] = DataScaffold.CanShowCalendarView(meta),
            ["canShowWorkflow"] = canShowWorkflow,
            ["idGeneration"] = meta.IdGeneration.ToString(),
            ["defaultSortField"] = meta.DefaultSortField,
            ["defaultSortDirection"] = meta.DefaultSortDirection.ToString(),
            ["parentField"] = meta.ParentField != null ? (object)new Dictionary<string, object?>
            {
                ["name"] = meta.ParentField.Name,
                ["label"] = meta.ParentField.Label
            } : null,
            ["documentRelationFields"] = documentRelationFieldsArray,
            ["fields"] = fields,
            ["commands"] = commands
        };
    }

    /// <summary>
    /// Register report listing, execution, and API export routes.
    /// GET  /reports             → list all report definitions
    /// GET  /reports/{id}        → run report, render HTML
    /// GET  /api/reports/{id}    → JSON results
    /// GET  /api/reports/{id}?format=csv  → CSV export
    /// </summary>
    public static void RegisterReportRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        // List all reports
        // Run a report → HTML
        // ── GET /api/reports — JSON list of all report definitions ────────
        host.RegisterRoute("GET /api/reports", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                if (!new HashSet<string>(UserAuth.GetPermissions(user), StringComparer.OrdinalIgnoreCase).Contains("admin"))
                { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Access denied\"}"); return; }

                var reports = new List<ReportDefinition>(DataStoreProvider.Current.Query<ReportDefinition>(null));
                reports.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.Ordinal));

                context.Response.ContentType = "application/json";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                {
                    w.WriteStartArray();
                    foreach (var r in reports)
                    {
                        w.WriteStartObject();
                        w.WriteNumber("id", r.Key);
                        w.WriteString("name", r.Name);
                        w.WriteString("description", r.Description);
                        w.WriteString("rootEntity", r.RootEntity);
                        w.WriteNumber("parameterCount", r.Parameters.Count);

                        w.WritePropertyName("parameters");
                        w.WriteStartArray();
                        foreach (var p in r.Parameters)
                        {
                            w.WriteStartObject();
                            w.WriteString("name", p.Name);
                            w.WriteString("label", p.Label);
                            w.WriteString("type", p.Type);
                            w.WriteString("defaultValue", p.DefaultValue);
                            if (p.Options != null && p.Options.Count > 0)
                            {
                                w.WritePropertyName("options");
                                w.WriteStartArray();
                                foreach (var o in p.Options) w.WriteStringValue(o);
                                w.WriteEndArray();
                            }
                            if (!string.IsNullOrEmpty(p.FieldSource))
                                w.WriteString("fieldSource", p.FieldSource);
                            w.WriteEndObject();
                        }
                        w.WriteEndArray();

                        w.WriteEndObject();
                    }
                    w.WriteEndArray();
                }
            }));

        // JSON results via API
        host.RegisterRoute("GET /api/reports/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                var userPermissions = new HashSet<string>(UserAuth.GetPermissions(user), StringComparer.OrdinalIgnoreCase);
                if (!userPermissions.Contains("admin")) { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Access denied\"}"); return; }

                var id = GetRouteParam(context, "id");
                if (string.IsNullOrWhiteSpace(id))
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Missing report id\"}");
                    return;
                }

                if (!uint.TryParse(id, out var parsedId))
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Invalid report id\"}");
                    return;
                }

                var def = await DataStoreProvider.Current.LoadAsync<ReportDefinition>(parsedId, context.RequestAborted).ConfigureAwait(false);
                if (def == null)
                {
                    context.Response.StatusCode = 404;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Report not found\"}");
                    return;
                }

                var parameters = def.Parameters;
                Dictionary<string, string>? runtimeParams = null;
                if (parameters.Count > 0)
                {
                    runtimeParams = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var p in parameters)
                    {
                        var val = context.HttpRequest.Query.TryGetValue(p.Name, out var qv) ? qv.ToString() : p.DefaultValue;
                        runtimeParams[p.Name] = val;
                    }
                }

                var executor = new ReportExecutor(DataStoreProvider.Current);
                ReportResult result;
                try
                {
                    result = await executor.ExecuteAsync(def, runtimeParams, context.RequestAborted).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    context.Response.StatusCode = 500;
                    context.Response.ContentType = "application/json";
                    await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                    {
                        w.WriteStartObject();
                        w.WriteString("error", "An internal error occurred.");
                        w.WriteEndObject();
                    }
                    return;
                }

                var format = context.HttpRequest.Query.TryGetValue("format", out var fmt) ? fmt.ToString() : "json";

                if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
                {
                    context.Response.ContentType = "text/csv";
                    context.Response.Headers.ContentDisposition = $"attachment; filename=\"{Uri.EscapeDataString(def.Name)}.csv\"";
                    var csvSb = new StringBuilder(1024);
                    {
                        var headerCells = new string[result.ColumnLabels.Length];
                        for (int ci = 0; ci < result.ColumnLabels.Length; ci++)
                            headerCells[ci] = CsvCell(result.ColumnLabels[ci]);
                        csvSb.AppendLine(string.Join(",", headerCells));
                    }
                    foreach (var row in result.Rows)
                    {
                        var rowCells = new string[row.Length];
                        for (int ci = 0; ci < row.Length; ci++)
                            rowCells[ci] = CsvCell(row[ci] ?? string.Empty);
                        csvSb.AppendLine(string.Join(",", rowCells));
                    }
                    await context.Response.WriteAsync(csvSb.ToString());
                    return;
                }

                var rowsList = new List<Dictionary<string, string?>>();
                foreach (var r in result.Rows)
                {
                    var dict = new Dictionary<string, string?>();
                    for (int i = 0; i < r.Length; i++)
                    {
                        var key = i < result.ColumnLabels.Length ? result.ColumnLabels[i] : $"col{i}";
                        dict[key] = r[i];
                    }
                    rowsList.Add(dict);
                }

                // Default: JSON
                context.Response.ContentType = "application/json";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                {
                    w.WriteStartObject();
                    w.WriteString("name", def.Name);
                    w.WriteString("generatedAt", result.GeneratedAt);
                    w.WriteNumber("totalRows", result.TotalRows);
                    w.WriteBoolean("isTruncated", result.IsTruncated);
                    w.WritePropertyName("columns");
                    JsonWriterHelper.WriteValue(w, result.ColumnLabels);
                    w.WritePropertyName("rows");
                    JsonWriterHelper.WriteValue(w, rowsList.ToArray());
                    w.WriteEndObject();
                }
            }));

        // GET /api/reports/_distinct/{entity}/{field} — distinct field values for dropdown population
        host.RegisterRoute("GET /api/reports/_distinct/{entity}/{field}", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var entitySlug = GetRouteParam(context, "entity") ?? string.Empty;
                var fieldName = GetRouteParam(context, "field") ?? string.Empty;

                var values = ReportHtmlRenderer.ResolveDistinctValues($"{entitySlug}.{fieldName}");

                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                {
                    JsonWriterHelper.WriteValue(w, values);
                }
            }));
    }

    private static string CsvCell(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        return value;
    }

    private static async ValueTask ServeVNextShell(BmwContext context, IBareWebHost host, ITemplateStore templateStore)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        var safeToken = WebUtility.HtmlEncode(csrfToken);
        var nonce = context.GetCspNonce();
        var safeNonce = WebUtility.HtmlEncode(nonce);

        var template = templateStore.Get("index");

        // Build right-nav items string
        var rightNavSb = new StringBuilder(512);
        AppendVNextRightNavItems(rightNavSb, host.MenuOptionsList);

        // Token map: covers all {{tokens}} in the head, navbar, and footer sections
        var tokens = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["title"]       = "BareMetalWeb — VNext",
            ["csp_nonce"]   = safeNonce,
            ["links_left"]  = string.Empty,   // populated dynamically by JS via buildNav()
            ["links_right"] = rightNavSb.ToString(),
            ["footer_user"] = string.Empty,
        };
        // Add app-level metadata tokens (AppName, CompanyDescription, CopyrightYear, AppVersion)
        // Keys prefixed with "html_" carry pre-rendered HTML and must NOT be encoded again.
        for (int i = 0; i < host.AppMetaDataKeys.Length && i < host.AppMetaDataValues.Length; i++)
        {
            var key = host.AppMetaDataKeys[i];
            tokens[key] = key.StartsWith("html_", StringComparison.Ordinal)
                ? host.AppMetaDataValues[i]
                : WebUtility.HtmlEncode(host.AppMetaDataValues[i]);
        }

        // Extract only the <nav>…</nav> block from the body template
        var navEndIdx = template.Body.IndexOf("</nav>", StringComparison.OrdinalIgnoreCase);
        var navbarSection = navEndIdx >= 0
            ? template.Body.Substring(0, navEndIdx + 6)
            : template.Body;
        // Brand link stays at the VNext root (/)
        // (navbarSection already has href="/", no override needed)

        // Extract only the <footer>…</footer> block from the footer template
        var footerEndIdx = template.Footer.IndexOf("</footer>", StringComparison.OrdinalIgnoreCase);
        var footerElement = footerEndIdx >= 0
            ? template.Footer.Substring(0, footerEndIdx + 9)
            : string.Empty;

        // Fetch user once — used by both meta-objects and initial-data inline scripts
        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
        var userPermissions = UserAuth.GetPermissions(user);

        // Inline /meta/objects (and optionally /meta/{slug}) to eliminate client-side round-trips
        var metaObjectsScript = await TryBuildMetaObjectsScriptAsync(user, userPermissions, safeNonce).ConfigureAwait(false);
        // For any /{slug}[/...] path, inline /meta/{slug} to eliminate the schema round-trip
        string? metaSlugScript = null;
        string? initialDataScript = null;
        // Extract the entity slug for /{slug} pages
        var reqPath = context.HttpRequest.Path.Value ?? string.Empty;
        string? dataSlug = null;
        {
            var trimmed = reqPath.TrimStart('/');
            // Extract slug — first path segment (before any '/')
            var slashIdx = trimmed.IndexOf('/');
            var entitySlug = slashIdx >= 0 ? trimmed.Substring(0, slashIdx) : trimmed;
            if (!string.IsNullOrEmpty(entitySlug))
                metaSlugScript = TryBuildMetaSlugScript(entitySlug, safeNonce);

            // For simple list-view paths (no sub-path), also inline the first page of data
            if (slashIdx < 0)
            {
                // Only when there are no data-affecting query params in the URL
                var q = context.HttpRequest.Query;
                var hasCustomParams = q.ContainsKey("skip") || q.ContainsKey("top") || q.ContainsKey("q") ||
                                      q.ContainsKey("sort") || q.ContainsKey("dir");
                if (!hasCustomParams)
                {
                    foreach (var k in q.Keys)
                    {
                        if (k.StartsWith("f_", StringComparison.OrdinalIgnoreCase))
                        {
                            hasCustomParams = true;
                            break;
                        }
                    }
                }
                if (!hasCustomParams)
                    initialDataScript = await TryBuildInitialDataScriptAsync(
                        context, entitySlug, safeNonce, user, context.RequestAborted).ConfigureAwait(false);
            }
            var slugCandidate = trimmed;
            // Only for simple slug paths (not /create, /123, /123/edit etc.)
            if (!string.IsNullOrEmpty(slugCandidate) && !slugCandidate.Contains('/'))
                dataSlug = slugCandidate;
        }

        var sb = new StringBuilder(4096);
        sb.Append("<!DOCTYPE html><html lang=\"en\">");
        sb.Append("<head>");
        sb.Append(ReplaceTemplateTokens(template.Head, tokens));
        sb.Append($"<meta name=\"csrf-token\" content=\"{safeToken}\">");
        sb.Append("<meta name=\"vnext-base\" content=\"\">");
        sb.Append("</head>");
        sb.Append("<body>");
        sb.Append(ReplaceTemplateTokens(navbarSection, tokens));
        sb.Append("<div class=\"container-fluid py-4 px-4 bm-content\" id=\"vnext-content\"><div class=\"text-center py-5\"><div class=\"spinner-border\" role=\"status\"><span class=\"visually-hidden\">Loading...</span></div></div></div>");
        sb.Append("<div id=\"vnext-modal-container\"></div>");
        sb.Append("<div id=\"vnext-toast-container\" class=\"position-fixed top-0 end-0 p-3\"></div>");
        sb.Append(ReplaceTemplateTokens(footerElement, tokens));
        if (metaObjectsScript != null)
            sb.Append(metaObjectsScript);
        if (metaSlugScript != null)
            sb.Append(metaSlugScript);
        if (initialDataScript != null)
            sb.Append(initialDataScript);
        sb.Append("<script src=\"/static/js/vnext-bundle.js\"></script>");
        if (BareMetalWeb.Rendering.HtmlRenderer.ShouldShowDiagnosticBanner(context, host))
            sb.Append(BareMetalWeb.Rendering.HtmlRenderer.BuildDiagnosticBannerHtml(context, host, sb.Length));
        sb.Append("</body></html>");

        context.Response.ContentType = "text/html; charset=utf-8";
        context.Response.Headers.CacheControl = "no-store";
        await context.Response.WriteAsync(sb.ToString());
    }

    /// <summary>
    /// Builds an inline &lt;script&gt; tag that pre-seeds <c>window.__BMW_META_OBJECTS__</c> with the
    /// list of entities accessible to the current user.
    /// Returns <c>null</c> on any error so the client falls back to normal API calls.
    /// </summary>
    private static async Task<string?> TryBuildMetaObjectsScriptAsync(BaseDataObject? user, string[] userPermissions, string safeNonce)
    {
        try
        {
            var entitiesMetaList = new List<object>();
            foreach (var e in DataScaffold.Entities)
            {
                if (!await IsEntityAccessibleAsync(e, user, userPermissions).ConfigureAwait(false)) continue;
                entitiesMetaList.Add(new Dictionary<string, object?>
                {
                    ["slug"]         = e.Slug,
                    ["name"]         = e.Name,
                    ["navGroup"]     = e.NavGroup,
                    ["showOnNav"]    = e.ShowOnNav,
                    ["navOrder"]     = e.NavOrder,
                    ["viewType"]     = e.ViewType.ToString(),
                    ["rightAligned"] = string.Equals(e.NavGroup, "Admin", StringComparison.OrdinalIgnoreCase)
                });
            }
            var entities = entitiesMetaList.ToArray();

            // Check if user has any elevated permissions
            bool hasElevated = false;
            if (user != null)
            {
                var resolved = await PermissionResolver.ResolveAsync(user, CancellationToken.None)
                    .ConfigureAwait(false);
                hasElevated = resolved.HasElevatedPermissions;
            }

            var json = EscapeJsonForInlineScript(JsonWriterHelper.ToJsonString(entities));
            var sb = new StringBuilder(256);
            sb.Append($"<script nonce=\"{safeNonce}\">window.__BMW_META_OBJECTS__={json};");
            if (hasElevated)
                sb.Append("window.__BMW_HAS_ELEVATED__=true;");
            sb.Append("</script>");
            return sb.ToString();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Builds an inline &lt;script&gt; tag that seeds <c>window.__BMW_META_SLUG__[slug]</c> with the
    /// entity schema, matching the /meta/{slug} response.
    /// Eliminates the /meta/{slug} round-trip when first opening a data entity page.
    /// Returns <c>null</c> if the entity is not found or any error occurs.
    /// </summary>
    private static string? TryBuildMetaSlugScript(string slug, string safeNonce)
    {
        try
        {
            if (!DataScaffold.TryGetEntity(slug, out var meta))
                return null;

            var schema = BuildEntitySchema(meta);
            var schemaJson = EscapeJsonForInlineScript(JsonWriterHelper.ToJsonString(schema));

            var safeSlug = JsonWriterHelper.ToJsonString(slug);
            return $"<script nonce=\"{safeNonce}\">window.__BMW_META_SLUG__=window.__BMW_META_SLUG__||{{}};window.__BMW_META_SLUG__[{safeSlug}]={schemaJson};</script>";
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Fetches the initial list data for a VNext data entity and returns an inline &lt;script&gt; tag
    /// that stores the result in <c>window.__BMW_INITIAL_DATA__</c>.
    /// Also pre-resolves FK lookup values and stores them in <c>window.__BMW_LOOKUP_PREFETCH__</c>
    /// to eliminate batch lookup round-trips when the list first renders.
    /// Eliminates the redundant API round-trip when the user first opens a data list view with no filters.
    /// Returns <c>null</c> if the entity is not found, the user lacks permission, or any error occurs
    /// (the client will fall back to the normal API call).
    /// </summary>
    private static async ValueTask<string?> TryBuildInitialDataScriptAsync(
        BmwContext context, string slug, string safeNonce, BaseDataObject? user, CancellationToken cancellationToken)
    {
        try
        {
            if (!DataScaffold.TryGetEntity(slug, out var meta))
                return null;

            // Permission check (mirrors HasEntityPermissionAsync in RouteHandlers)
            var permissionsNeeded = meta.Permissions?.Trim();
            if (!string.IsNullOrWhiteSpace(permissionsNeeded) &&
                !string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase))
            {
                if (user == null)
                    return null;
                if (!string.Equals(permissionsNeeded, "Authenticated", StringComparison.OrdinalIgnoreCase))
                {
                    var userPerms = new HashSet<string>(UserAuth.GetPermissions(user), StringComparer.OrdinalIgnoreCase);
                    var altLookup = userPerms.GetAlternateLookup<ReadOnlySpan<char>>();
                    var remaining = permissionsNeeded.AsSpan();
                    bool hasRequired = false;
                    bool allMatch = true;
                    while (remaining.Length > 0)
                    {
                        int idx = remaining.IndexOf(',');
                        ReadOnlySpan<char> segment;
                        if (idx < 0) { segment = remaining; remaining = default; }
                        else { segment = remaining[..idx]; remaining = remaining[(idx + 1)..]; }
                        var trimmed = segment.Trim();
                        if (trimmed.IsEmpty) continue;
                        hasRequired = true;
                        if (!altLookup.Contains(trimmed))
                        {
                            allMatch = false;
                            break;
                        }
                    }
                    if (hasRequired && !allMatch)
                            return null;
                }
            }

            // Always embed just the first page (25 rows) with the full row count.
            // Hierarchy views (TreeView, OrgChart, Timeline, Timetable) need top=10000 and will
            // fall back to the normal API call because their effectiveTop won't match this value.
            const int top = 25;

            // Build query — lets BuildQueryDefinition apply default sort from metadata
            var queryDict = new Dictionary<string, string?> { ["skip"] = "0", ["top"] = "25" };
            var query = DataScaffold.BuildQueryDefinition(queryDict, meta);

            var countQuery = DataScaffold.BuildQueryDefinition(queryDict, meta);
            countQuery.Skip = null;
            countQuery.Top  = null;

            var dataTask  = DataScaffold.QueryAsync(meta, query, cancellationToken).AsTask();
            var countTask = DataScaffold.CountAsync(meta, countQuery, cancellationToken).AsTask();
            await Task.WhenAll(dataTask, countTask).ConfigureAwait(false);

            var results = await dataTask;
            var total   = await countTask;
            var payloadList = new List<Dictionary<string, object?>>();
            foreach (object item in results)
                payloadList.Add(RouteHandlers.BuildApiModel(meta, item));
            var payload = payloadList.ToArray();
            // Clamp total (same as DataApiListHandler)
            if (payload.Length < top)
                total = Math.Min(total, payload.Length);

            var initialData = new Dictionary<string, object?>
            {
                ["slug"]  = slug,
                ["top"]   = top,
                ["items"] = payload,
                ["total"] = total
            };

            var initialJson = EscapeJsonForInlineScript(JsonWriterHelper.ToJsonString(initialData));

            // Pre-resolve FK lookup values for all lookup fields visible in the list view.
            // This allows the client to skip the /api/_lookup/{slug}/_batch round-trips.
            var lookupPrefetch = await BuildLookupPrefetchAsync(meta, payload, cancellationToken).ConfigureAwait(false);
            string? prefetchJson = null;
            if (lookupPrefetch != null)
                prefetchJson = EscapeJsonForInlineScript(JsonWriterHelper.ToJsonString(lookupPrefetch));

            var scriptContent = $"window.__BMW_INITIAL_DATA__={initialJson};";
            if (prefetchJson != null)
                scriptContent += $"window.__BMW_LOOKUP_PREFETCH__={prefetchJson};";

            return $"<script nonce=\"{safeNonce}\">{scriptContent}</script>";
        }
        catch
        {
            return null; // Silently fall back to client-side API call
        }
    }

    /// <summary>
    /// Pre-resolves FK lookup values for all lookup fields shown in the list view.
    /// Returns a dictionary keyed by target entity slug, each value being a dictionary of id → entity model.
    /// Returns <c>null</c> when there are no lookup fields or no items to resolve.
    /// </summary>
    private static async ValueTask<Dictionary<string, Dictionary<string, object?>>?> BuildLookupPrefetchAsync(
        DataEntityMetadata meta,
        Dictionary<string, object?>[] payload,
        CancellationToken cancellationToken)
    {
        if (payload.Length == 0) return null;

        // Only consider lookup fields that are shown in the list view
        var lookupFields = new List<DataFieldMetadata>();
        foreach (var f in meta.Fields)
        {
            if (f.Lookup != null && f.List)
                lookupFields.Add(f);
        }
        if (lookupFields.Count == 0) return null;

        var prefetch = new Dictionary<string, Dictionary<string, object?>>(StringComparer.OrdinalIgnoreCase);

        foreach (var field in lookupFields)
        {
            var targetMeta = field.Lookup!.TargetSlug != null
                ? (DataScaffold.TryGetEntity(field.Lookup.TargetSlug, out var bySlug) ? bySlug : null)
                : DataScaffold.GetEntityByType(field.Lookup!.TargetType);
            if (targetMeta == null) continue;

            // Collect unique non-null IDs for this field across all payload rows
            var seenIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var uniqueIds = new List<string>();
            foreach (var item in payload)
            {
                var idVal = item.TryGetValue(field.Name, out var val) ? val as string : null;
                if (!string.IsNullOrWhiteSpace(idVal) && seenIds.Add(idVal))
                    uniqueIds.Add(idVal);
            }

            if (uniqueIds.Count == 0) continue;

            if (!prefetch.TryGetValue(targetMeta.Slug, out var slugResults))
            {
                slugResults = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                prefetch[targetMeta.Slug] = slugResults;
            }

            foreach (var id in uniqueIds)
            {
                if (slugResults.ContainsKey(id!)) continue; // already loaded by a previous field
                if (!uint.TryParse(id, out var parsedEntityId)) continue;
                var entity = await targetMeta.Handlers.LoadAsync(parsedEntityId, cancellationToken).ConfigureAwait(false);
                if (entity != null)
                    slugResults[id!] = RouteHandlers.BuildApiModel(targetMeta, entity);
            }
        }

        return prefetch.Count > 0 ? prefetch : null;
    }

    /// <summary>
    /// Escapes a JSON string for safe embedding inside a &lt;script&gt; tag.
    /// Replaces <c>&lt;/</c> with <c>&lt;\/</c> to prevent the browser from
    /// treating <c>&lt;/script&gt;</c> inside the JSON as a closing tag.
    /// </summary>
    private static string EscapeJsonForInlineScript(string json)
        => json.Replace("</", "<\\/", StringComparison.Ordinal);

    /// <summary>Replaces all <c>{{key}}</c> tokens in <paramref name="template"/> using <paramref name="tokens"/>.
    /// Unknown tokens are silently removed (replaced with empty string).</summary>
    private static string ReplaceTemplateTokens(string template, Dictionary<string, string> tokens)
    {
        var sb = new StringBuilder(template.Length);
        int i = 0;
        while (i < template.Length)
        {
            if (template[i] == '{' && i + 1 < template.Length && template[i + 1] == '{')
            {
                var end = template.IndexOf("}}", i + 2, StringComparison.Ordinal);
                if (end >= 0)
                {
                    var key = template.Substring(i + 2, end - (i + 2));
                    if (tokens.TryGetValue(key, out var value))
                        sb.Append(value);
                    // else: unknown token silently removed
                    i = end + 2;
                    continue;
                }
            }
            sb.Append(template[i]);
            i++;
        }
        return sb.ToString();
    }

    internal static void AppendVNextRightNavItems(StringBuilder sb, List<IMenuOption> options)
    {
        var rightAligned = new List<IMenuOption>();
        foreach (var o in options)
        {
            if (o.RightAligned && o.ShowOnNavBar)
                rightAligned.Add(o);
        }
        var renderedGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var option in rightAligned)
        {
            if (string.IsNullOrWhiteSpace(option.Group))
            {
                var cssClass = option.HighlightAsButton
                    ? $"btn {(string.IsNullOrWhiteSpace(option.ColorClass) ? "btn-outline-light" : option.ColorClass)} btn-sm ms-2"
                    : string.IsNullOrWhiteSpace(option.ColorClass) ? "nav-link" : $"nav-link {option.ColorClass}";
                sb.Append($"<li class=\"nav-item\"><a class=\"{WebUtility.HtmlEncode(cssClass)}\" href=\"{WebUtility.HtmlEncode(option.Href)}\">{WebUtility.HtmlEncode(option.Label)}</a></li>");
                continue;
            }

            if (renderedGroups.Contains(option.Group))
                continue;

            renderedGroups.Add(option.Group);
            var groupItems = new List<IMenuOption>();
            foreach (var o in rightAligned)
            {
                if (string.Equals(o.Group, option.Group, StringComparison.OrdinalIgnoreCase))
                    groupItems.Add(o);
            }

            sb.Append($"<li class=\"nav-item dropdown\"><a class=\"nav-link dropdown-toggle\" href=\"#\" role=\"button\" data-bs-toggle=\"dropdown\" aria-expanded=\"false\">{WebUtility.HtmlEncode(option.Group)}</a>");
            sb.Append("<ul class=\"dropdown-menu dropdown-menu-end\">");
            foreach (var item in groupItems)
            {
                sb.Append($"<li><a class=\"dropdown-item\" href=\"{WebUtility.HtmlEncode(item.Href)}\">{WebUtility.HtmlEncode(item.Label)}</a></li>");
            }
            sb.Append("</ul></li>");
        }
    }
    /// <summary>Parses a POST /query JSON body into a <see cref="QueryDefinition"/>.</summary>
    private static QueryDefinition? BuildQueryFromJson(JsonElement root)
    {
        if (!root.TryGetProperty("clauses", out var clausesEl) &&
            !root.TryGetProperty("sorts", out _) &&
            !root.TryGetProperty("skip", out _) &&
            !root.TryGetProperty("top", out _))
            return null;

        var query = new QueryDefinition();

        if (root.TryGetProperty("skip", out var skipEl) && skipEl.TryGetInt32(out var skip))
            query.Skip = skip;

        if (root.TryGetProperty("top", out var topEl) && topEl.TryGetInt32(out var top))
            query.Top = top;

        if (root.TryGetProperty("clauses", out clausesEl) && clausesEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var c in clausesEl.EnumerateArray())
            {
                var clause = new QueryClause
                {
                    Field = c.TryGetProperty("field", out var fp) ? fp.GetString() ?? string.Empty : string.Empty,
                    Operator = c.TryGetProperty("operator", out var op)
                        ? Enum.TryParse<QueryOperator>(op.GetString(), ignoreCase: true, out var parsed) ? parsed : QueryOperator.Equals
                        : QueryOperator.Equals,
                    Value = c.TryGetProperty("value", out var vp) ? (object?)(vp.ValueKind == JsonValueKind.Null ? null : vp.GetString()) : null
                };
                query.Clauses.Add(clause);
            }
        }

        if (root.TryGetProperty("sorts", out var sortsEl) && sortsEl.ValueKind == JsonValueKind.Array)
        {
            foreach (var s in sortsEl.EnumerateArray())
            {
                var sortField = s.TryGetProperty("field", out var sf) ? sf.GetString() ?? string.Empty : string.Empty;
                var dirStr = s.TryGetProperty("direction", out var df) ? df.GetString() ?? "asc" : "asc";
                var dir = string.Equals(dirStr, "desc", StringComparison.OrdinalIgnoreCase)
                    ? SortDirection.Desc : SortDirection.Asc;
                query.Sorts.Add(new SortClause { Field = sortField, Direction = dir });
            }
        }

        return query;
    }

    /// <summary>GET /api/_metrics — returns engine telemetry snapshot as JSON.</summary>
    private static async ValueTask EngineMetricsHandler(BmwContext context)
    {
        var snapshot = BareMetalWeb.Data.EngineMetrics.GetSnapshot();

        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/json";
        await using var w = new System.Text.Json.Utf8JsonWriter(context.Response.Body);
        w.WriteStartObject();

        w.WriteStartObject("wal");
        w.WriteNumber("appendCount", snapshot.WalAppendCount);
        w.WriteNumber("appendAvgUs", Math.Round(snapshot.WalAppendAvgUs, 1));
        w.WriteNumber("appendMaxUs", snapshot.WalAppendMaxUs);
        w.WriteNumber("appendBytesTotal", snapshot.WalAppendBytesTotal);
        w.WriteEndObject();

        w.WriteStartObject("locks");
        w.WriteNumber("acquireCount", snapshot.LockAcquireCount);
        w.WriteNumber("acquireAvgUs", Math.Round(snapshot.LockAcquireAvgUs, 1));
        w.WriteNumber("acquireMaxUs", snapshot.LockAcquireMaxUs);
        w.WriteNumber("contentions", snapshot.LockContentions);
        w.WriteNumber("contentionRate", Math.Round(snapshot.LockContentionRate, 4));
        w.WriteEndObject();

        w.WriteStartObject("commits");
        w.WriteNumber("count", snapshot.CommitCount);
        w.WriteNumber("successCount", snapshot.CommitSuccessCount);
        w.WriteNumber("failCount", snapshot.CommitFailCount);
        w.WriteNumber("avgUs", Math.Round(snapshot.CommitAvgUs, 1));
        w.WriteNumber("maxUs", snapshot.CommitMaxUs);
        w.WriteNumber("retries", snapshot.CommitRetryCount);
        w.WriteNumber("successRate", Math.Round(snapshot.CommitSuccessRate, 4));
        w.WriteEndObject();

        w.WriteStartObject("deltas");
        w.WriteNumber("count", snapshot.DeltaSizeCount);
        w.WriteNumber("avgBytes", Math.Round(snapshot.DeltaSizeAvg, 1));
        w.WriteNumber("maxBytes", snapshot.DeltaSizeMax);
        w.WriteNumber("minBytes", snapshot.DeltaSizeMin);
        w.WriteNumber("totalBytes", snapshot.DeltaSizeTotal);
        w.WriteEndObject();

        w.WriteStartObject("compaction");
        w.WriteNumber("count", snapshot.CompactionCount);
        w.WriteNumber("totalUs", snapshot.CompactionTotalUs);
        w.WriteNumber("bytesReclaimed", snapshot.CompactionBytesReclaimed);
        w.WriteEndObject();

        w.WriteStartObject("replay");
        w.WriteNumber("count", snapshot.ReplayCount);
        w.WriteNumber("totalUs", snapshot.ReplayTotalUs);
        w.WriteNumber("opsTotal", snapshot.ReplayOpsTotal);
        w.WriteEndObject();

        w.WriteEndObject();
        await w.FlushAsync(context.RequestAborted);
    }

    // ── Dashboard routes ─────────────────────────────────────────────────────

    /// <summary>
    /// Register dashboard listing and rendering routes.
    /// GET  /dashboards           → list all dashboard definitions
    /// GET  /dashboards/{id}      → render a dashboard with live KPI tiles (HTML)
    /// GET  /api/dashboards       → JSON list of all dashboard definitions
    /// GET  /api/dashboards/{id}  → JSON with resolved KPI values for one dashboard
    /// </summary>
    public static void RegisterDashboardRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        // ── GET /dashboards — HTML listing ───────────────────────────────────
        // ── GET /dashboards/{id} — HTML dashboard render ─────────────────────
        // ── GET /api/dashboards — JSON list ──────────────────────────────────
        host.RegisterRoute("GET /api/dashboards", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                if (!new HashSet<string>(UserAuth.GetPermissions(user), StringComparer.OrdinalIgnoreCase).Contains("admin"))
                { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Access denied\"}"); return; }

                var dashboards = new List<DashboardDefinition>(DataStoreProvider.Current.Query<DashboardDefinition>(null));
                dashboards.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.Ordinal));
                var list = dashboards.Select(d => new Dictionary<string, object?>
                {
                    ["id"] = d.Key,
                    ["name"] = d.Name,
                    ["description"] = d.Description,
                    ["tileCount"] = d.Tiles.Count
                });
                context.Response.ContentType = "application/json";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                {
                    JsonWriterHelper.WriteValue(w, list);
                }
            }));

        // ── GET /api/dashboards/{id} — JSON with resolved KPI values ─────────
        host.RegisterRoute("GET /api/dashboards/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                if (!new HashSet<string>(UserAuth.GetPermissions(user), StringComparer.OrdinalIgnoreCase).Contains("admin"))
                { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Access denied\"}"); return; }

                var id = GetRouteParam(context, "id");
                if (string.IsNullOrWhiteSpace(id) || !uint.TryParse(id, out var dashId))
                { context.Response.StatusCode = 400; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Invalid dashboard id\"}"); return; }

                var def = await DataStoreProvider.Current.LoadAsync<DashboardDefinition>(dashId, context.RequestAborted).ConfigureAwait(false);
                if (def == null)
                { context.Response.StatusCode = 404; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Dashboard not found\"}"); return; }

                var resolvedTiles = await DashboardHtmlRenderer.ResolveTilesAsync(def.Tiles, context.RequestAborted);
                var tileProjections = new Dictionary<string, object?>[resolvedTiles.Count];
                for (int i = 0; i < resolvedTiles.Count; i++)
                {
                    var r = resolvedTiles[i];
                    Dictionary<string, object?>[]? sparklineArr = null;
                    if (r.Sparkline != null)
                    {
                        sparklineArr = new Dictionary<string, object?>[r.Sparkline.Count];
                        for (int j = 0; j < r.Sparkline.Count; j++)
                            sparklineArr[j] = new Dictionary<string, object?> { ["label"] = r.Sparkline[j].Label, ["value"] = r.Sparkline[j].Value };
                    }
                    tileProjections[i] = new Dictionary<string, object?>
                    {
                        ["title"] = r.Tile.Title,
                        ["icon"] = r.Tile.Icon,
                        ["color"] = r.Tile.Color,
                        ["entitySlug"] = r.Tile.EntitySlug,
                        ["aggregateFunction"] = r.Tile.AggregateFunction,
                        ["displayValue"] = r.DisplayValue,
                        ["rawValue"] = r.RawValue?.ToString(),
                        ["sparkline"] = sparklineArr
                    };
                }
                context.Response.ContentType = "application/json";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_indentedWriterOptions))
                {
                    w.WriteStartObject();
                    w.WriteNumber("id", def.Key);
                    w.WriteString("name", def.Name);
                    w.WriteString("description", def.Description);
                    w.WritePropertyName("tiles");
                    JsonWriterHelper.WriteValue(w, tileProjections);
                    w.WriteEndObject();
                }
            }));
    }

    // ── Module Editor Routes ──────────────────────────────────────────────────

    /// <summary>
    /// Registers JSON API routes for the Module Editor.
    /// <list type="bullet">
    ///   <item><c>GET /api/modules</c>  — list all modules</item>
    ///   <item><c>GET /api/modules/{id}</c>  — module detail with resolved owned artifacts</item>
    ///   <item><c>PUT /api/modules/{id}</c>  — update module owned-slug CSVs</item>
    /// </list>
    /// </summary>
    public static void RegisterModuleRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        // ── GET /api/modules — JSON list of all modules ──────────────────────
        host.RegisterRoute("GET /api/modules", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                if (!new HashSet<string>(UserAuth.GetPermissions(user), StringComparer.OrdinalIgnoreCase).Contains("admin"))
                { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Access denied\"}"); return; }

                var modules = await ModuleRegistry.GetModulesAsync(context.RequestAborted).ConfigureAwait(false);
                var list = new List<Dictionary<string, object?>>(modules.Count);
                foreach (var m in modules)
                {
                    list.Add(new Dictionary<string, object?>
                    {
                        ["moduleId"] = m.ModuleId,
                        ["name"] = m.Name,
                        ["version"] = m.Version,
                        ["navGroup"] = m.NavGroup,
                        ["isolation"] = m.Isolation,
                        ["enabled"] = m.Enabled,
                        ["entityCount"] = m.EntitySlugs.Count,
                        ["reportCount"] = m.ReportSlugs.Count,
                        ["actionCount"] = m.ActionKeys.Count,
                        ["permissionCount"] = m.RequiredPermissions.Count
                    });
                }
                context.Response.ContentType = "application/json";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                {
                    JsonWriterHelper.WriteValue(w, list);
                }
            }));

        // ── GET /api/modules/{id} — module detail with owned artifacts ───────
        host.RegisterRoute("GET /api/modules/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                if (!new HashSet<string>(UserAuth.GetPermissions(user), StringComparer.OrdinalIgnoreCase).Contains("admin"))
                { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Access denied\"}"); return; }

                var moduleId = GetRouteParam(context, "id") ?? string.Empty;
                var modules = await ModuleRegistry.GetModulesAsync(context.RequestAborted).ConfigureAwait(false);
                ModuleInfo? target = null;
                foreach (var m in modules)
                {
                    if (string.Equals(m.ModuleId, moduleId, StringComparison.OrdinalIgnoreCase))
                    { target = m; break; }
                }
                if (target == null)
                { context.Response.StatusCode = 404; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Module not found\"}"); return; }

                // Resolve owned entity definitions with their field schemas
                var entities = new List<Dictionary<string, object?>>();
                foreach (var slug in target.EntitySlugs)
                {
                    if (!DataScaffold.TryGetEntity(slug, out var meta)) continue;
                    var fields = new List<Dictionary<string, object?>>();
                    foreach (var f in meta.Fields)
                    {
                        fields.Add(new Dictionary<string, object?>
                        {
                            ["name"] = f.Name,
                            ["label"] = f.Label,
                            ["fieldType"] = f.FieldType.ToString(),
                            ["required"] = f.Required,
                            ["indexed"] = f.IsIndexed,
                            ["order"] = f.Order
                        });
                    }
                    entities.Add(new Dictionary<string, object?>
                    {
                        ["slug"] = slug,
                        ["name"] = meta.Name,
                        ["showOnNav"] = meta.ShowOnNav,
                        ["navGroup"] = meta.NavGroup,
                        ["navOrder"] = meta.NavOrder,
                        ["permissions"] = meta.Permissions,
                        ["fieldCount"] = meta.Fields.Count,
                        ["fields"] = fields
                    });
                }

                // Resolve owned reports
                var reports = new List<Dictionary<string, object?>>();
                foreach (var slug in target.ReportSlugs)
                {
                    if (!DataScaffold.TryGetEntity("report-definitions", out var reportMeta)) break;
                    var reportItems = await reportMeta.Handlers.QueryAsync(null, context.RequestAborted).ConfigureAwait(false);
                    foreach (var item in reportItems)
                    {
                        var name = reportMeta.FieldsByName.TryGetValue("Name", out var nf) ? nf.GetValueFn?.Invoke(item)?.ToString() : null;
                        var rootEntity = reportMeta.FieldsByName.TryGetValue("RootEntity", out var rf) ? rf.GetValueFn?.Invoke(item)?.ToString() : null;
                        if (string.Equals(name, slug, StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(item.Key.ToString(), slug, StringComparison.OrdinalIgnoreCase))
                        {
                            reports.Add(new Dictionary<string, object?>
                            {
                                ["id"] = item.Key,
                                ["name"] = name,
                                ["rootEntity"] = rootEntity
                            });
                        }
                    }
                }

                // Resolve owned actions
                var actions = new List<Dictionary<string, object?>>();
                foreach (var key in target.ActionKeys)
                {
                    if (!DataScaffold.TryGetEntity("action-definitions", out var actionMeta)) break;
                    var actionItems = await actionMeta.Handlers.QueryAsync(null, context.RequestAborted).ConfigureAwait(false);
                    foreach (var item in actionItems)
                    {
                        var name = actionMeta.FieldsByName.TryGetValue("Name", out var nf) ? nf.GetValueFn?.Invoke(item)?.ToString() : null;
                        if (string.Equals(name, key, StringComparison.OrdinalIgnoreCase) ||
                            string.Equals(item.Key.ToString(), key, StringComparison.OrdinalIgnoreCase))
                        {
                            actions.Add(new Dictionary<string, object?>
                            {
                                ["id"] = item.Key,
                                ["name"] = name,
                                ["entityId"] = actionMeta.FieldsByName.TryGetValue("EntityId", out var ef) ? ef.GetValueFn?.Invoke(item)?.ToString() : null
                            });
                        }
                    }
                }

                // Build response
                context.Response.ContentType = "application/json";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_indentedWriterOptions))
                {
                    w.WriteStartObject();
                    w.WriteString("moduleId", target.ModuleId);
                    w.WriteString("name", target.Name);
                    w.WriteString("version", target.Version);
                    w.WriteString("navGroup", target.NavGroup);
                    w.WriteString("isolation", target.Isolation);
                    w.WriteBoolean("enabled", target.Enabled);

                    w.WritePropertyName("entitySlugs");
                    JsonWriterHelper.WriteValue(w, target.EntitySlugs);
                    w.WritePropertyName("actionKeys");
                    JsonWriterHelper.WriteValue(w, target.ActionKeys);
                    w.WritePropertyName("reportSlugs");
                    JsonWriterHelper.WriteValue(w, target.ReportSlugs);
                    w.WritePropertyName("requiredPermissions");
                    JsonWriterHelper.WriteValue(w, target.RequiredPermissions);
                    w.WritePropertyName("dependencies");
                    JsonWriterHelper.WriteValue(w, target.Dependencies);

                    w.WritePropertyName("entities");
                    JsonWriterHelper.WriteValue(w, entities);
                    w.WritePropertyName("reports");
                    JsonWriterHelper.WriteValue(w, reports);
                    w.WritePropertyName("actions");
                    JsonWriterHelper.WriteValue(w, actions);

                    w.WriteEndObject();
                }
            }));

        // ── PUT /api/modules/{id} — update module ────────────────────────────
        host.RegisterRoute("PUT /api/modules/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                if (!new HashSet<string>(UserAuth.GetPermissions(user), StringComparer.OrdinalIgnoreCase).Contains("admin"))
                { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Access denied\"}"); return; }

                if (!CsrfProtection.ValidateApiToken(context))
                { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"CSRF validation failed\"}"); return; }

                var moduleId = GetRouteParam(context, "id") ?? string.Empty;
                if (!DataScaffold.TryGetEntity("modules", out var meta))
                { context.Response.StatusCode = 500; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Module entity not registered\"}"); return; }

                // Find the existing module record
                var items = await meta.Handlers.QueryAsync(null, context.RequestAborted).ConfigureAwait(false);
                BaseDataObject? existing = null;
                foreach (var item in items)
                {
                    if (meta.FieldsByName.TryGetValue("ModuleId", out var idField))
                    {
                        var val = idField.GetValueFn?.Invoke(item)?.ToString();
                        if (string.Equals(val, moduleId, StringComparison.OrdinalIgnoreCase))
                        { existing = item; break; }
                    }
                }
                if (existing == null)
                { context.Response.StatusCode = 404; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Module not found\"}"); return; }

                // Parse JSON body and apply field updates
                using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body, default, context.RequestAborted).ConfigureAwait(false);
                var root = doc.RootElement;

                void TrySetField(string fieldName, JsonElement parent)
                {
                    if (!parent.TryGetProperty(fieldName, out var prop) &&
                        !parent.TryGetProperty(char.ToLowerInvariant(fieldName[0]) + fieldName[1..], out prop))
                        return;
                    if (!meta.FieldsByName.TryGetValue(fieldName, out var field)) return;
                    if (field.SetValueFn == null) return;

                    if (prop.ValueKind == JsonValueKind.True || prop.ValueKind == JsonValueKind.False)
                        field.SetValueFn(existing, prop.GetBoolean());
                    else if (prop.ValueKind == JsonValueKind.String)
                        field.SetValueFn(existing, prop.GetString());
                    else if (prop.ValueKind == JsonValueKind.Array)
                    {
                        // Convert JSON array to CSV
                        var parts = new List<string>();
                        foreach (var el in prop.EnumerateArray())
                        {
                            var s = el.GetString();
                            if (!string.IsNullOrWhiteSpace(s)) parts.Add(s);
                        }
                        field.SetValueFn(existing, string.Join(",", parts));
                    }
                }

                TrySetField("Name", root);
                TrySetField("Version", root);
                TrySetField("NavGroup", root);
                TrySetField("Isolation", root);
                TrySetField("Enabled", root);
                TrySetField("EntitySlugs", root);
                TrySetField("ActionKeys", root);
                TrySetField("ReportSlugs", root);
                TrySetField("RequiredPermissions", root);
                TrySetField("Dependencies", root);

                await meta.Handlers.SaveAsync(existing, context.RequestAborted).ConfigureAwait(false);
                ModuleRegistry.Invalidate();

                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"ok\":true}");
            }));
    }

    // ── Chat API Routes ───────────────────────────────────────────────────────

    /// <summary>
    /// Registers JSON API routes for the Chat feature.
    /// <list type="bullet">
    ///   <item><c>GET  /api/chat/sessions</c> — list sessions for current user</item>
    ///   <item><c>POST /api/chat/sessions</c> — create a new session</item>
    ///   <item><c>GET  /api/chat/sessions/{id}</c> — session detail with messages</item>
    ///   <item><c>DELETE /api/chat/sessions/{id}</c> — delete a session</item>
    ///   <item><c>POST /api/chat/sessions/{id}/messages</c> — send message, get AI response</item>
    ///   <item><c>GET  /api/chat/sessions/{id}/messages</c> — paginated message history</item>
    /// </list>
    /// </summary>
    public static void RegisterChatRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        var raw = pageInfoFactory.RawPage("", false);

        // ── GET /api/chat/sessions — list user's sessions ────────────────────
        host.RegisterRoute("GET /api/chat/sessions", new RouteHandlerData(raw, async context =>
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            if (user == null) { context.Response.StatusCode = 401; return; }

            var query = new QueryDefinition
            {
                Clauses = new List<QueryClause>
                {
                    new() { Field = "UserName", Operator = QueryOperator.Equals, Value = (UserAuth.GetUserName(user) ?? user.Key.ToString()) }
                },
                Sorts = new List<SortClause>
                {
                    new() { Field = "UpdatedAtUtc", Direction = SortDirection.Desc }
                },
                Top = 50
            };
            var sessions = DataStoreProvider.Current.Query<Runtime.ChatSession>(query).ToList();

            context.Response.ContentType = "application/json";
            var payload = new Dictionary<string, object?>[sessions.Count];
            for (int i = 0; i < sessions.Count; i++)
            {
                var s = sessions[i];
                payload[i] = new Dictionary<string, object?>
                {
                    ["id"] = s.Key,
                    ["title"] = s.Title,
                    ["createdAtUtc"] = s.CreatedAtUtc,
                    ["updatedAtUtc"] = s.UpdatedAtUtc,
                    ["messageCount"] = s.MessageCount,
                    ["status"] = s.Status
                };
            }
            await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
            {
                JsonWriterHelper.WriteValue(w, payload);
            }
        }));

        // ── POST /api/chat/sessions — create a new session ───────────────────
        host.RegisterRoute("POST /api/chat/sessions", new RouteHandlerData(raw, async context =>
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            if (user == null) { context.Response.StatusCode = 401; return; }

            if (!CsrfProtection.ValidateApiToken(context))
            { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"CSRF validation failed\"}"); return; }

            string title = "New Chat";
            if (context.HttpRequest.ContentLength > 0)
            {
                using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body, default, context.RequestAborted).ConfigureAwait(false);
                if (doc.RootElement.TryGetProperty("title", out var titleProp))
                    title = titleProp.GetString() ?? title;
            }

            var session = new Runtime.ChatSession
            {
                UserName = (UserAuth.GetUserName(user) ?? user.Key.ToString()),
                Title = title,
                CreatedAtUtc = DateTime.UtcNow,
                UpdatedAtUtc = DateTime.UtcNow,
                MessageCount = 0,
                Status = "active"
            };
            await DataStoreProvider.Current.SaveAsync(session, context.RequestAborted).ConfigureAwait(false);

            context.Response.StatusCode = 201;
            context.Response.ContentType = "application/json";
            await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
            {
                w.WriteStartObject();
                w.WriteNumber("id", session.Key);
                w.WriteString("title", session.Title);
                w.WriteString("createdAtUtc", session.CreatedAtUtc);
                w.WriteEndObject();
            }
        }));

        // ── GET /api/chat/sessions/{id} — session detail with messages ───────
        host.RegisterRoute("GET /api/chat/sessions/{id}", new RouteHandlerData(raw, async context =>
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            if (user == null) { context.Response.StatusCode = 401; return; }

            var idStr = GetRouteParam(context, "id");
            if (!uint.TryParse(idStr, out var sessionId))
            { context.Response.StatusCode = 400; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Invalid session id\"}"); return; }

            var session = await DataStoreProvider.Current.LoadAsync<Runtime.ChatSession>(sessionId, context.RequestAborted).ConfigureAwait(false);
            if (session == null || !string.Equals(session.UserName, (UserAuth.GetUserName(user) ?? user.Key.ToString()), StringComparison.OrdinalIgnoreCase))
            { context.Response.StatusCode = 404; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Session not found\"}"); return; }

            var msgQuery = new QueryDefinition
            {
                Clauses = new List<QueryClause>
                {
                    new() { Field = "SessionId", Operator = QueryOperator.Equals, Value = sessionId }
                },
                Sorts = new List<SortClause>
                {
                    new() { Field = "TimestampUtc", Direction = SortDirection.Asc }
                },
                Top = 200
            };
            var messages = DataStoreProvider.Current.Query<Runtime.ChatMessage>(msgQuery).ToList();

            context.Response.ContentType = "application/json";
            await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
            {
                w.WriteStartObject();
                w.WriteNumber("id", session.Key);
                w.WriteString("title", session.Title);
                w.WriteString("status", session.Status);
                w.WriteString("createdAtUtc", session.CreatedAtUtc);
                w.WriteString("updatedAtUtc", session.UpdatedAtUtc);
                w.WriteNumber("messageCount", session.MessageCount);

                w.WritePropertyName("messages");
                w.WriteStartArray();
                foreach (var m in messages)
                {
                    w.WriteStartObject();
                    w.WriteNumber("id", m.Key);
                    w.WriteString("role", m.Role);
                    w.WriteString("content", m.Content);
                    w.WriteString("timestampUtc", m.TimestampUtc);
                    w.WriteNumber("tokenCount", m.TokenCount);
                    w.WriteNumber("latencyMs", m.LatencyMs);
                    w.WriteString("resolvedIntent", m.ResolvedIntent);
                    w.WriteNumber("confidence", m.Confidence);
                    w.WriteEndObject();
                }
                w.WriteEndArray();
                w.WriteEndObject();
            }
        }));

        // ── DELETE /api/chat/sessions/{id} — delete a session ────────────────
        host.RegisterRoute("DELETE /api/chat/sessions/{id}", new RouteHandlerData(raw, async context =>
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            if (user == null) { context.Response.StatusCode = 401; return; }

            if (!CsrfProtection.ValidateApiToken(context))
            { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"CSRF validation failed\"}"); return; }

            var idStr = GetRouteParam(context, "id");
            if (!uint.TryParse(idStr, out var sessionId))
            { context.Response.StatusCode = 400; return; }

            var session = await DataStoreProvider.Current.LoadAsync<Runtime.ChatSession>(sessionId, context.RequestAborted).ConfigureAwait(false);
            if (session == null || !string.Equals(session.UserName, (UserAuth.GetUserName(user) ?? user.Key.ToString()), StringComparison.OrdinalIgnoreCase))
            { context.Response.StatusCode = 404; return; }

            // Delete all messages in the session
            var msgQuery = new QueryDefinition
            {
                Clauses = new List<QueryClause>
                {
                    new() { Field = "SessionId", Operator = QueryOperator.Equals, Value = sessionId }
                }
            };
            var messages = DataStoreProvider.Current.Query<Runtime.ChatMessage>(msgQuery).ToList();
            foreach (var msg in messages)
                await DataStoreProvider.Current.DeleteAsync<Runtime.ChatMessage>(msg.Key, context.RequestAborted).ConfigureAwait(false);

            await DataStoreProvider.Current.DeleteAsync<Runtime.ChatSession>(sessionId, context.RequestAborted).ConfigureAwait(false);

            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"ok\":true}");
        }));

        // ── POST /api/chat/sessions/{id}/messages — send message, get AI reply ─
        host.RegisterRoute("POST /api/chat/sessions/{id}/messages", new RouteHandlerData(raw, async context =>
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            if (user == null) { context.Response.StatusCode = 401; return; }

            if (!CsrfProtection.ValidateApiToken(context))
            { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"CSRF validation failed\"}"); return; }

            var idStr = GetRouteParam(context, "id");
            if (!uint.TryParse(idStr, out var sessionId))
            { context.Response.StatusCode = 400; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Invalid session id\"}"); return; }

            var session = await DataStoreProvider.Current.LoadAsync<Runtime.ChatSession>(sessionId, context.RequestAborted).ConfigureAwait(false);
            if (session == null || !string.Equals(session.UserName, (UserAuth.GetUserName(user) ?? user.Key.ToString()), StringComparison.OrdinalIgnoreCase))
            { context.Response.StatusCode = 404; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Session not found\"}"); return; }

            using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body, default, context.RequestAborted).ConfigureAwait(false);
            var content = doc.RootElement.TryGetProperty("content", out var cp)
                ? cp.GetString() ?? ""
                : doc.RootElement.TryGetProperty("message", out var mp)
                    ? mp.GetString() ?? ""
                    : "";

            if (string.IsNullOrWhiteSpace(content))
            { context.Response.StatusCode = 400; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Missing message content\"}"); return; }

            // Save user message
            var userMsg = new Runtime.ChatMessage
            {
                SessionId = sessionId,
                Role = "user",
                Content = content,
                TimestampUtc = DateTime.UtcNow,
                TokenCount = EstimateTokens(content)
            };
            await DataStoreProvider.Current.SaveAsync(userMsg, context.RequestAborted).ConfigureAwait(false);

            // Invoke the IntelligenceOrchestrator
            var sw = System.Diagnostics.Stopwatch.StartNew();
            Intelligence.ChatResponse aiResponse;
            try
            {
                var orchestrator = AgentApiHandlers.GetOrCreateOrchestrator();
                aiResponse = await orchestrator.ProcessAsync(content, context.RequestAborted).ConfigureAwait(false);
            }
            catch
            {
                aiResponse = new Intelligence.ChatResponse("Sorry, an error occurred processing your request.", "error", 0f);
            }
            sw.Stop();

            // Save assistant message
            var assistantMsg = new Runtime.ChatMessage
            {
                SessionId = sessionId,
                Role = "assistant",
                Content = aiResponse.Message,
                TimestampUtc = DateTime.UtcNow,
                TokenCount = EstimateTokens(aiResponse.Message),
                LatencyMs = (int)sw.ElapsedMilliseconds,
                ResolvedIntent = aiResponse.ResolvedIntent,
                Confidence = (decimal)aiResponse.Confidence
            };
            await DataStoreProvider.Current.SaveAsync(assistantMsg, context.RequestAborted).ConfigureAwait(false);

            // Update session
            session.MessageCount += 2;
            session.UpdatedAtUtc = DateTime.UtcNow;
            if (session.MessageCount == 2 && session.Title == "New Chat")
                session.Title = content.Length > 60 ? content[..57] + "..." : content;
            await DataStoreProvider.Current.SaveAsync(session, context.RequestAborted).ConfigureAwait(false);

            // Return the assistant response
            context.Response.ContentType = "application/json";
            await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
            {
                w.WriteStartObject();
                w.WriteStartObject("userMessage");
                w.WriteNumber("id", userMsg.Key);
                w.WriteString("role", "user");
                w.WriteString("content", content);
                w.WriteString("timestampUtc", userMsg.TimestampUtc);
                w.WriteEndObject();

                w.WriteStartObject("assistantMessage");
                w.WriteNumber("id", assistantMsg.Key);
                w.WriteString("role", "assistant");
                w.WriteString("content", aiResponse.Message);
                w.WriteString("timestampUtc", assistantMsg.TimestampUtc);
                w.WriteNumber("latencyMs", assistantMsg.LatencyMs);
                w.WriteString("resolvedIntent", aiResponse.ResolvedIntent);
                w.WriteNumber("confidence", assistantMsg.Confidence);
                w.WriteEndObject();
                w.WriteEndObject();
            }
        }));

        // ── GET /api/chat/sessions/{id}/messages — paginated history ─────────
        host.RegisterRoute("GET /api/chat/sessions/{id}/messages", new RouteHandlerData(raw, async context =>
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            if (user == null) { context.Response.StatusCode = 401; return; }

            var idStr = GetRouteParam(context, "id");
            if (!uint.TryParse(idStr, out var sessionId))
            { context.Response.StatusCode = 400; return; }

            var session = await DataStoreProvider.Current.LoadAsync<Runtime.ChatSession>(sessionId, context.RequestAborted).ConfigureAwait(false);
            if (session == null || !string.Equals(session.UserName, (UserAuth.GetUserName(user) ?? user.Key.ToString()), StringComparison.OrdinalIgnoreCase))
            { context.Response.StatusCode = 404; return; }

            int skip = 0, top = 50;
            if (context.HttpRequest.Query.TryGetValue("skip", out var skipVal) && int.TryParse(skipVal.FirstOrDefault(), out var s)) skip = s;
            if (context.HttpRequest.Query.TryGetValue("top", out var topVal) && int.TryParse(topVal.FirstOrDefault(), out var t)) top = Math.Min(t, 200);

            var msgQuery = new QueryDefinition
            {
                Clauses = new List<QueryClause>
                {
                    new() { Field = "SessionId", Operator = QueryOperator.Equals, Value = sessionId }
                },
                Sorts = new List<SortClause>
                {
                    new() { Field = "TimestampUtc", Direction = SortDirection.Asc }
                },
                Skip = skip,
                Top = top
            };
            var messages = DataStoreProvider.Current.Query<Runtime.ChatMessage>(msgQuery).ToList();

            context.Response.ContentType = "application/json";
            var payload = new Dictionary<string, object?>[messages.Count];
            for (int i = 0; i < messages.Count; i++)
            {
                var m = messages[i];
                payload[i] = new Dictionary<string, object?>
                {
                    ["id"] = m.Key,
                    ["role"] = m.Role,
                    ["content"] = m.Content,
                    ["timestampUtc"] = m.TimestampUtc,
                    ["tokenCount"] = m.TokenCount,
                    ["latencyMs"] = m.LatencyMs,
                    ["resolvedIntent"] = m.ResolvedIntent,
                    ["confidence"] = m.Confidence
                };
            }
            await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
            {
                JsonWriterHelper.WriteValue(w, payload);
            }
        }));
    }

    /// <summary>Rough token estimate: ~4 chars per token.</summary>
    private static int EstimateTokens(string text) => (text.Length + 3) / 4;

    // ── View Engine Routes ────────────────────────────────────────────────────

    /// <summary>
    /// Registers HTML and JSON routes for the BMW View Engine.
    ///
    /// <list type="bullet">
    ///   <item><c>GET /views</c>  — lists all view definitions</item>
    ///   <item><c>GET /views/{id}</c>  — executes a view and renders it as HTML</item>
    ///   <item><c>GET /api/views</c>  — lists view definitions as JSON</item>
    ///   <item><c>GET /api/views/{id}</c>  — executes a view and returns JSON</item>
    ///   <item><c>POST /api/views/execute</c>  — executes an ad-hoc view definition (JSON body)</item>
    /// </list>
    /// </summary>
    public static void RegisterViewRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        var _engine = new ViewEngine();

        // ── GET /views ── list all view definitions ───────────────────────────
        // ── GET /views/{id} ── execute view → HTML ────────────────────────────
        // ── GET /api/views ── list view definitions as JSON ───────────────────
        host.RegisterRoute("GET /api/views", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                var userPermissions = new HashSet<string>(UserAuth.GetPermissions(user), StringComparer.OrdinalIgnoreCase);
                if (!userPermissions.Contains("admin")) { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Access denied\"}"); return; }

                var views = new List<ViewDefinition>(DataStoreProvider.Current.Query<ViewDefinition>(null));
                views.Sort((a, b) => string.Compare(a.ViewName, b.ViewName, StringComparison.Ordinal));

                var items = new object[views.Count];
                for (int i = 0; i < views.Count; i++)
                {
                    var v = views[i];
                    items[i] = new Dictionary<string, object?>
                    {
                        ["id"]          = v.Key,
                        ["viewName"]    = v.ViewName,
                        ["rootEntity"]  = v.RootEntity,
                        ["limit"]       = v.Limit,
                        ["offset"]      = v.Offset,
                        ["materialised"] = v.Materialised,
                    };
                }

                context.Response.ContentType = "application/json";
                await using (var w = new Utf8JsonWriter(context.Response.Body, s_indentedWriterOptions))
                {
                    JsonWriterHelper.WriteValue(w, items);
                }
            }));

        // ── GET /api/views/{id} ── execute view → JSON ────────────────────────
        host.RegisterRoute("GET /api/views/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                var userPermissions = new HashSet<string>(UserAuth.GetPermissions(user), StringComparer.OrdinalIgnoreCase);
                if (!userPermissions.Contains("admin")) { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Access denied\"}"); return; }

                var id = GetRouteParam(context, "id");
                if (string.IsNullOrWhiteSpace(id) || !uint.TryParse(id, out var viewKey))
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Missing or invalid view id\"}");
                    return;
                }

                var def = await DataStoreProvider.Current.LoadAsync<ViewDefinition>(viewKey, context.RequestAborted).ConfigureAwait(false);
                if (def == null)
                {
                    context.Response.StatusCode = 404;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"View not found\"}");
                    return;
                }

                ReportResult result;
                try
                {
                    // Materialised views served from cache when available
                    if (def.Materialised)
                    {
                        var cached = await MaterializedViewCache.Instance.GetOrRefreshAsync(def.ViewName, context.RequestAborted).ConfigureAwait(false);
                        result = cached ?? await _engine.ExecuteAsync(def, context.RequestAborted).ConfigureAwait(false);
                    }
                    else
                    {
                        result = await _engine.ExecuteAsync(def, context.RequestAborted).ConfigureAwait(false);
                    }
                }
                catch (Exception)
                {
                    context.Response.StatusCode = 500;
                    context.Response.ContentType = "application/json";
                    await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                    {
                        w.WriteStartObject();
                        w.WriteString("error", "An internal error occurred.");
                        w.WriteEndObject();
                    }
                    return;
                }

                var format = context.HttpRequest.Query.TryGetValue("format", out var fmt) ? fmt.ToString() : "json";
                if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
                {
                    context.Response.ContentType = "text/csv";
                    context.Response.Headers.ContentDisposition = $"attachment; filename=\"{Uri.EscapeDataString(def.ViewName)}.csv\"";
                    var csvSb = new StringBuilder(1024);
                    var headerCells = new string[result.ColumnLabels.Length];
                    for (int ci = 0; ci < result.ColumnLabels.Length; ci++)
                        headerCells[ci] = CsvCell(result.ColumnLabels[ci]);
                    csvSb.AppendLine(string.Join(",", headerCells));
                    foreach (var row in result.Rows)
                    {
                        var rowCells = new string[row.Length];
                        for (int ci = 0; ci < row.Length; ci++)
                            rowCells[ci] = CsvCell(row[ci] ?? string.Empty);
                        csvSb.AppendLine(string.Join(",", rowCells));
                    }
                    await context.Response.WriteAsync(csvSb.ToString());
                    return;
                }

                var rowsList = new List<Dictionary<string, string?>>();
                foreach (var r in result.Rows)
                {
                    var dict = new Dictionary<string, string?>();
                    for (int i = 0; i < r.Length; i++)
                    {
                        var key = i < result.ColumnLabels.Length ? result.ColumnLabels[i] : $"col{i}";
                        dict[key] = r[i];
                    }
                    rowsList.Add(dict);
                }

                context.Response.ContentType = "application/json";
                await WriteViewResultJsonAsync(context, def.ViewName, def.RootEntity, result, rowsList);
            }));

        // ── POST /api/views/execute ── ad-hoc view execution ──────────────────
        host.RegisterRoute("POST /api/views/execute", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                var userPermissions = new HashSet<string>(UserAuth.GetPermissions(user), StringComparer.OrdinalIgnoreCase);
                if (!userPermissions.Contains("admin")) { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Access denied\"}"); return; }

                if (!CsrfProtection.ValidateApiToken(context))
                {
                    context.Response.StatusCode = 403;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Invalid CSRF token\"}");
                    return;
                }

                ViewDefinition? def;
                try
                {
                    using var bodyDoc = await System.Text.Json.JsonDocument.ParseAsync(
                        context.HttpRequest.Body, cancellationToken: context.RequestAborted).ConfigureAwait(false);
                    def = ParseViewDefinition(bodyDoc.RootElement);
                }
                catch
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Invalid JSON body — expected a ViewDefinition\"}");
                    return;
                }

                if (def == null || string.IsNullOrWhiteSpace(def.RootEntity))
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"RootEntity is required\"}");
                    return;
                }

                ReportResult result;
                try
                {
                    result = await _engine.ExecuteAsync(def, context.RequestAborted).ConfigureAwait(false);
                }
                catch (Exception)
                {
                    context.Response.StatusCode = 500;
                    context.Response.ContentType = "application/json";
                    await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
                    {
                        w.WriteStartObject();
                        w.WriteString("error", "An internal error occurred.");
                        w.WriteEndObject();
                    }
                    return;
                }

                var rowsList = new List<Dictionary<string, string?>>();
                foreach (var r in result.Rows)
                {
                    var dict = new Dictionary<string, string?>();
                    for (int i = 0; i < r.Length; i++)
                    {
                        var key = i < result.ColumnLabels.Length ? result.ColumnLabels[i] : $"col{i}";
                        dict[key] = r[i];
                    }
                    rowsList.Add(dict);
                }

                context.Response.ContentType = "application/json";
                await WriteViewResultJsonAsync(context, def.ViewName, def.RootEntity, result, rowsList);
            }));
    }

    /// <summary>
    /// Registers in-app inbox API routes:
    /// <list type="bullet">
    ///   <item>GET  /api/inbox               — list the current user's inbox messages (newest first)</item>
    ///   <item>GET  /api/inbox/unread-count   — return unread message count for the current user</item>
    ///   <item>POST /api/inbox/{id}/read      — mark a single message as read</item>
    ///   <item>POST /api/inbox/read-all       — mark all messages for the current user as read</item>
    /// </list>
    /// </summary>
    public static void RegisterInboxRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        var raw = pageInfoFactory.RawPage("Authenticated", false);

        // GET /api/inbox — list inbox messages for the current user
        host.RegisterRoute("GET /api/inbox", new RouteHandlerData(raw, async context =>
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            if (user == null) { context.Response.StatusCode = 401; return; }

            var query = new QueryDefinition
            {
                Clauses = new List<QueryClause>
                {
                    new() { Field = "RecipientUserName", Operator = QueryOperator.Equals, Value = (UserAuth.GetUserName(user) ?? user.Key.ToString()) }
                },
                Sorts = new List<SortClause>
                {
                    new() { Field = "CreatedAtUtc", Direction = SortDirection.Desc }
                },
                Top = 50
            };
            var messages = DataStoreProvider.Current.Query<InboxMessage>(query).ToList();

            context.Response.ContentType = "application/json";
            var payload = new Dictionary<string, object?>[messages.Count];
            for (int i = 0; i < messages.Count; i++)
            {
                var m = messages[i];
                payload[i] = new Dictionary<string, object?>
                {
                    ["id"]           = m.Key,
                    ["subject"]      = m.Subject,
                    ["body"]         = m.Body,
                    ["category"]     = m.Category,
                    ["isRead"]       = m.IsRead,
                    ["createdAtUtc"] = m.CreatedAtUtc,
                    ["entitySlug"]   = m.EntitySlug,
                    ["entityId"]     = m.EntityId
                };
            }
            await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
            {
                JsonWriterHelper.WriteValue(w, payload);
            }
        }));

        // GET /api/inbox/unread-count — return the number of unread messages
        host.RegisterRoute("GET /api/inbox/unread-count", new RouteHandlerData(raw, async context =>
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            if (user == null) { context.Response.StatusCode = 401; return; }

            var query = new QueryDefinition
            {
                Clauses = new List<QueryClause>
                {
                    new() { Field = "RecipientUserName", Operator = QueryOperator.Equals, Value = (UserAuth.GetUserName(user) ?? user.Key.ToString()) },
                    new() { Field = "IsRead",            Operator = QueryOperator.Equals, Value = false }
                }
            };
            var count = DataStoreProvider.Current.Query<InboxMessage>(query).Count();

            context.Response.ContentType = "application/json";
            await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
            {
                w.WriteStartObject();
                w.WriteNumber("count", count);
                w.WriteEndObject();
            }
        }));

        // POST /api/inbox/{id}/read — mark a single message as read
        host.RegisterRoute("POST /api/inbox/{id}/read", new RouteHandlerData(raw, async context =>
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            if (user == null) { context.Response.StatusCode = 401; return; }

            var idStr = GetRouteParam(context, "id");
            if (!uint.TryParse(idStr, out var msgKey))
            { context.Response.StatusCode = 400; await context.Response.WriteAsync("{\"error\":\"Invalid id\"}"); return; }

            var msg = await DataStoreProvider.Current.LoadAsync<InboxMessage>(msgKey, context.RequestAborted).ConfigureAwait(false);
            if (msg == null || !string.Equals(msg.RecipientUserName, (UserAuth.GetUserName(user) ?? user.Key.ToString()), StringComparison.OrdinalIgnoreCase))
            { context.Response.StatusCode = 404; await context.Response.WriteAsync("{\"error\":\"Not found\"}"); return; }

            if (!msg.IsRead)
            {
                msg.IsRead = true;
                await DataStoreProvider.Current.SaveAsync(msg, context.RequestAborted).ConfigureAwait(false);
            }
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"ok\":true}");
        }));

        // POST /api/inbox/read-all — mark all current user messages as read
        host.RegisterRoute("POST /api/inbox/read-all", new RouteHandlerData(raw, async context =>
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            if (user == null) { context.Response.StatusCode = 401; return; }

            var query = new QueryDefinition
            {
                Clauses = new List<QueryClause>
                {
                    new() { Field = "RecipientUserName", Operator = QueryOperator.Equals, Value = (UserAuth.GetUserName(user) ?? user.Key.ToString()) },
                    new() { Field = "IsRead",            Operator = QueryOperator.Equals, Value = false }
                }
            };
            var unread = DataStoreProvider.Current.Query<InboxMessage>(query).ToList();
            foreach (var msg in unread)
            {
                msg.IsRead = true;
                await DataStoreProvider.Current.SaveAsync(msg, context.RequestAborted).ConfigureAwait(false);
            }
            context.Response.ContentType = "application/json";
            await using (var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions))
            {
                w.WriteStartObject();
                w.WriteNumber("marked", unread.Count);
                w.WriteEndObject();
            }
        }));
    }

    private static async ValueTask WriteViewResultJsonAsync(
        BmwContext context,
        string viewName,
        string rootEntity,
        ReportResult result,
        List<Dictionary<string, string?>> rowsList)
    {
        await using var w = new Utf8JsonWriter(context.Response.Body, s_indentedWriterOptions);
        w.WriteStartObject();
        w.WriteString("viewName", viewName);
        w.WriteString("rootEntity", rootEntity);
        w.WriteString("generatedAt", result.GeneratedAt.ToString("O"));
        w.WriteNumber("totalRows", result.TotalRows);
        w.WriteBoolean("isTruncated", result.IsTruncated);
        w.WritePropertyName("columns");
        JsonWriterHelper.WriteValue(w, result.ColumnLabels);
        w.WritePropertyName("rows");
        JsonWriterHelper.WriteValue(w, rowsList.ToArray());
        w.WriteEndObject();
    }

    private static ViewDefinition? ParseViewDefinition(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object)
            return null;

        var def = new ViewDefinition
        {
            ViewName = root.TryGetProperty("viewName", out var vn) || root.TryGetProperty("ViewName", out vn) ? vn.GetString() ?? string.Empty : string.Empty,
            RootEntity = root.TryGetProperty("rootEntity", out var re) || root.TryGetProperty("RootEntity", out re) ? re.GetString() ?? string.Empty : string.Empty,
            Limit = root.TryGetProperty("limit", out var lim) || root.TryGetProperty("Limit", out lim) ? lim.GetInt32() : 10_000,
            Offset = root.TryGetProperty("offset", out var off) || root.TryGetProperty("Offset", out off) ? off.GetInt32() : 0,
            Materialised = root.TryGetProperty("materialised", out var mat) || root.TryGetProperty("Materialised", out mat) ? mat.GetBoolean() : false,
        };

        if ((root.TryGetProperty("projectionsJson", out var pj) || root.TryGetProperty("ProjectionsJson", out pj)) && pj.ValueKind == JsonValueKind.String)
            def.ProjectionsJson = pj.GetString() ?? "[]";
        else if ((root.TryGetProperty("projections", out var pa) || root.TryGetProperty("Projections", out pa)) && pa.ValueKind == JsonValueKind.Array)
            def.ProjectionsJson = pa.GetRawText();

        if ((root.TryGetProperty("joinsJson", out var jj) || root.TryGetProperty("JoinsJson", out jj)) && jj.ValueKind == JsonValueKind.String)
            def.JoinsJson = jj.GetString() ?? "[]";
        else if ((root.TryGetProperty("joins", out var ja) || root.TryGetProperty("Joins", out ja)) && ja.ValueKind == JsonValueKind.Array)
            def.JoinsJson = ja.GetRawText();

        if ((root.TryGetProperty("filtersJson", out var fj) || root.TryGetProperty("FiltersJson", out fj)) && fj.ValueKind == JsonValueKind.String)
            def.FiltersJson = fj.GetString() ?? "[]";
        else if ((root.TryGetProperty("filters", out var fa) || root.TryGetProperty("Filters", out fa)) && fa.ValueKind == JsonValueKind.Array)
            def.FiltersJson = fa.GetRawText();

        if ((root.TryGetProperty("sortsJson", out var sj) || root.TryGetProperty("SortsJson", out sj)) && sj.ValueKind == JsonValueKind.String)
            def.SortsJson = sj.GetString() ?? "[]";
        else if ((root.TryGetProperty("sorts", out var sa) || root.TryGetProperty("Sorts", out sa)) && sa.ValueKind == JsonValueKind.Array)
            def.SortsJson = sa.GetRawText();

        return def;
    }

    // ═══════════════════════════════════════════════════════════════════════
    //  Runtime Management Routes — Bootstrap agent + admin management
    // ═══════════════════════════════════════════════════════════════════════

    public static void RegisterRuntimeRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory,
        string dataRoot)
    {
        var raw = pageInfoFactory.RawPage("", false);
        var runtimeDir = Path.Combine(dataRoot, "Runtimes");
        Directory.CreateDirectory(runtimeDir);

        // ── GET /api/runtime/desired/{nodeId} — agent polls for desired version ──
        host.RegisterRoute("GET /api/runtime/desired/{id}", new RouteHandlerData(raw, async context =>
        {
            var nodeId = GetRouteParam(context, "id");
            if (string.IsNullOrEmpty(nodeId)) { context.Response.StatusCode = 400; return; }

            // Authenticate node via Bearer token
            var authHeader = context.HttpRequest.Headers["Authorization"].ToString();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.Ordinal))
            {
                context.Response.StatusCode = 401; return;
            }
            var secret = authHeader.AsSpan(7).ToString();

            // Find the node
            var nodes = DataStoreProvider.Current.Query<DeploymentNode>(new QueryDefinition
            {
                Clauses = new List<QueryClause>
                {
                    new() { Field = "NodeId", Operator = QueryOperator.Equals, Value = nodeId }
                },
                Top = 1
            }).ToList();

            if (nodes.Count == 0) { context.Response.StatusCode = 404; return; }
            var node = nodes[0];

            // Verify secret (compare SHA256 hash)
            var secretHash = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(secret))).ToLowerInvariant();
            if (!string.Equals(node.SecretHash, secretHash, StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = 401; return;
            }

            if (!node.IsEnabled) { context.Response.StatusCode = 403; return; }

            // Update last heartbeat + current version from header
            node.LastHeartbeatUtc = DateTime.UtcNow;
            var reportedVersion = context.HttpRequest.Headers["X-BMW-Current-Version"].ToString();
            if (!string.IsNullOrEmpty(reportedVersion))
                node.CurrentVersion = reportedVersion;
            var reportedArch = context.HttpRequest.Headers["X-BMW-Architecture"].ToString();
            if (!string.IsNullOrEmpty(reportedArch))
                node.Architecture = reportedArch;
            await DataStoreProvider.Current.SaveAsync(node, context.RequestAborted).ConfigureAwait(false);

            // Find the desired release for this node's ring + architecture
            var arch = string.IsNullOrEmpty(node.Architecture) ? "Arm64" : node.Architecture;
            var releases = DataStoreProvider.Current.Query<RuntimeRelease>(new QueryDefinition
            {
                Clauses = new List<QueryClause>
                {
                    new() { Field = "IsActive", Operator = QueryOperator.Equals, Value = true },
                    new() { Field = "Architecture", Operator = QueryOperator.Equals, Value = arch }
                },
                Sorts = new List<SortClause>
                {
                    new() { Field = "PublishedAtUtc", Direction = SortDirection.Desc }
                },
                Top = 20
            }).ToList();

            // Match: release targets this node's ring or "all"
            var release = releases.FirstOrDefault(r =>
                string.Equals(r.TargetRing, node.Ring, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(r.TargetRing, "all", StringComparison.OrdinalIgnoreCase));

            context.Response.ContentType = "application/json";
            await using var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions);
            w.WriteStartObject();
            if (release != null)
            {
                w.WriteString("desiredVersion", release.Version);
                w.WriteString("sha256", release.Sha256);
                w.WriteString("downloadUrl", $"/api/runtime/download/{release.Version}?arch={arch}");
            }
            else
            {
                w.WriteNull("desiredVersion");
                w.WriteNull("sha256");
                w.WriteNull("downloadUrl");
            }
            w.WriteNumber("pollSeconds", node.PollIntervalSeconds > 0 ? node.PollIntervalSeconds : 60);
            w.WriteEndObject();
        }));

        // ── GET /api/runtime/download/{version} — serve runtime binary ──────────
        host.RegisterRoute("GET /api/runtime/download/{id}", new RouteHandlerData(raw, async context =>
        {
            var version = GetRouteParam(context, "id");
            if (string.IsNullOrEmpty(version)) { context.Response.StatusCode = 400; return; }

            // Authenticate via Bearer token (same as desired endpoint)
            var authHeader = context.HttpRequest.Headers["Authorization"].ToString();
            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer ", StringComparison.Ordinal))
            {
                context.Response.StatusCode = 401; return;
            }

            var arch = context.HttpRequest.Query["arch"].ToString();
            if (string.IsNullOrEmpty(arch)) arch = "Arm64";

            // Find the release
            var releases = DataStoreProvider.Current.Query<RuntimeRelease>(new QueryDefinition
            {
                Clauses = new List<QueryClause>
                {
                    new() { Field = "Version", Operator = QueryOperator.Equals, Value = version },
                    new() { Field = "Architecture", Operator = QueryOperator.Equals, Value = arch },
                    new() { Field = "IsActive", Operator = QueryOperator.Equals, Value = true }
                },
                Top = 1
            }).ToList();

            if (releases.Count == 0) { context.Response.StatusCode = 404; return; }
            var release = releases[0];

            // Verify the caller's secret maps to a valid enabled node
            var secret = authHeader.AsSpan(7).ToString();
            var secretHash = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    System.Text.Encoding.UTF8.GetBytes(secret))).ToLowerInvariant();
            var validNode = DataStoreProvider.Current.Query<DeploymentNode>(new QueryDefinition
            {
                Clauses = new List<QueryClause>
                {
                    new() { Field = "SecretHash", Operator = QueryOperator.Equals, Value = secretHash },
                    new() { Field = "IsEnabled", Operator = QueryOperator.Equals, Value = true }
                },
                Top = 1
            }).Any();
            if (!validNode) { context.Response.StatusCode = 401; return; }

            // Serve the binary file
            var binaryPath = Path.Combine(runtimeDir, $"bmw-{version}-{arch}");
            if (!File.Exists(binaryPath)) { context.Response.StatusCode = 404; return; }

            context.Response.ContentType = "application/octet-stream";
            context.Response.Headers["Content-Disposition"] = $"attachment; filename=\"bmw-{version}\"";
            context.Response.Headers["X-BMW-SHA256"] = release.Sha256;
            await using var fs = new FileStream(binaryPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
            context.Response.ContentLength = fs.Length;
            await fs.CopyToAsync(context.Response.Body, context.RequestAborted).ConfigureAwait(false);
        }));

        // ── POST /api/runtime/publish — upload a new runtime binary (admin) ─────
        host.RegisterRoute("POST /api/runtime/publish", new RouteHandlerData(raw, async context =>
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            if (user == null) { context.Response.StatusCode = 401; return; }
            CsrfProtection.ValidateApiToken(context);

            var version = context.HttpRequest.Query["version"].ToString();
            var arch = context.HttpRequest.Query["arch"].ToString();
            var ring = context.HttpRequest.Query["ring"].ToString();

            if (string.IsNullOrEmpty(version) || string.IsNullOrEmpty(arch))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"error\":\"version and arch query params required\"}");
                return;
            }
            if (string.IsNullOrEmpty(ring)) ring = "canary";

            // Read binary from request body and save to disk
            var binaryPath = Path.Combine(runtimeDir, $"bmw-{version}-{arch}");
            using var ms = new MemoryStream();
            await context.HttpRequest.Body.CopyToAsync(ms, context.RequestAborted).ConfigureAwait(false);
            var data = ms.ToArray();

            var sha256 = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(data)).ToLowerInvariant();

            await File.WriteAllBytesAsync(binaryPath, data, context.RequestAborted).ConfigureAwait(false);

            // Create or update release entity
            var existing = DataStoreProvider.Current.Query<RuntimeRelease>(new QueryDefinition
            {
                Clauses = new List<QueryClause>
                {
                    new() { Field = "Version", Operator = QueryOperator.Equals, Value = version },
                    new() { Field = "Architecture", Operator = QueryOperator.Equals, Value = arch }
                },
                Top = 1
            }).FirstOrDefault();

            var release = existing ?? new RuntimeRelease();
            release.Version = version;
            release.Architecture = arch;
            release.Sha256 = sha256;
            release.FileSizeBytes = data.Length;
            release.PublishedAtUtc = DateTime.UtcNow;
            release.TargetRing = ring;
            release.IsActive = true;
            await DataStoreProvider.Current.SaveAsync(release, context.RequestAborted).ConfigureAwait(false);

            context.Response.ContentType = "application/json";
            await using var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions);
            w.WriteStartObject();
            w.WriteNumber("id", release.Key);
            w.WriteString("version", release.Version);
            w.WriteString("architecture", release.Architecture);
            w.WriteString("sha256", release.Sha256);
            w.WriteNumber("fileSizeBytes", release.FileSizeBytes);
            w.WriteString("targetRing", release.TargetRing);
            w.WriteEndObject();
        }));

        // ── GET /api/runtime/releases — list published releases (admin) ─────────
        host.RegisterRoute("GET /api/runtime/releases", new RouteHandlerData(raw, async context =>
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            if (user == null) { context.Response.StatusCode = 401; return; }

            var releases = DataStoreProvider.Current.Query<RuntimeRelease>(new QueryDefinition
            {
                Sorts = new List<SortClause>
                {
                    new() { Field = "PublishedAtUtc", Direction = SortDirection.Desc }
                },
                Top = 100
            }).ToList();

            context.Response.ContentType = "application/json";
            await using var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions);
            w.WriteStartArray();
            foreach (var r in releases)
            {
                w.WriteStartObject();
                w.WriteNumber("id", r.Key);
                w.WriteString("version", r.Version);
                w.WriteString("architecture", r.Architecture);
                w.WriteString("sha256", r.Sha256);
                w.WriteNumber("fileSizeBytes", r.FileSizeBytes);
                w.WriteString("publishedAtUtc", r.PublishedAtUtc.ToString("O"));
                w.WriteString("targetRing", r.TargetRing);
                w.WriteBoolean("isActive", r.IsActive);
                w.WriteString("notes", r.Notes);
                w.WriteEndObject();
            }
            w.WriteEndArray();
        }));

        // ── POST /api/runtime/nodes — register/update a deployment node (admin) ──
        host.RegisterRoute("POST /api/runtime/nodes", new RouteHandlerData(raw, async context =>
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            if (user == null) { context.Response.StatusCode = 401; return; }
            CsrfProtection.ValidateApiToken(context);

            using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body,
                default, context.RequestAborted).ConfigureAwait(false);
            var root = doc.RootElement;

            var nodeId = root.TryGetProperty("nodeId", out var nid) ? nid.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(nodeId))
            {
                context.Response.StatusCode = 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync("{\"error\":\"nodeId required\"}");
                return;
            }

            // Find existing or create new
            var existing = DataStoreProvider.Current.Query<DeploymentNode>(new QueryDefinition
            {
                Clauses = new List<QueryClause>
                {
                    new() { Field = "NodeId", Operator = QueryOperator.Equals, Value = nodeId }
                },
                Top = 1
            }).FirstOrDefault();

            var node = existing ?? new DeploymentNode { NodeId = nodeId };

            if (root.TryGetProperty("secret", out var sec) && sec.ValueKind == JsonValueKind.String)
            {
                var plainSecret = sec.GetString() ?? "";
                node.SecretHash = Convert.ToHexString(
                    System.Security.Cryptography.SHA256.HashData(
                        System.Text.Encoding.UTF8.GetBytes(plainSecret))).ToLowerInvariant();
            }
            if (root.TryGetProperty("ring", out var rng)) node.Ring = rng.GetString() ?? "production";
            if (root.TryGetProperty("architecture", out var ar)) node.Architecture = ar.GetString() ?? "Arm64";
            if (root.TryGetProperty("pollIntervalSeconds", out var pi)) node.PollIntervalSeconds = pi.GetInt32();
            if (root.TryGetProperty("isEnabled", out var ie)) node.IsEnabled = ie.GetBoolean();
            if (root.TryGetProperty("displayName", out var dn)) node.DisplayName = dn.GetString() ?? "";
            if (root.TryGetProperty("clusterEndpoint", out var ce)) node.ClusterEndpoint = ce.GetString() ?? "";

            await DataStoreProvider.Current.SaveAsync(node, context.RequestAborted).ConfigureAwait(false);

            context.Response.ContentType = "application/json";
            await using var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions);
            w.WriteStartObject();
            w.WriteNumber("id", node.Key);
            w.WriteString("nodeId", node.NodeId);
            w.WriteString("ring", node.Ring);
            w.WriteString("architecture", node.Architecture);
            w.WriteBoolean("isEnabled", node.IsEnabled);
            w.WriteNumber("pollIntervalSeconds", node.PollIntervalSeconds);
            w.WriteEndObject();
        }));

        // ── GET /api/runtime/nodes — list deployment nodes (admin) ───────────────
        host.RegisterRoute("GET /api/runtime/nodes", new RouteHandlerData(raw, async context =>
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            if (user == null) { context.Response.StatusCode = 401; return; }

            var nodes = DataStoreProvider.Current.Query<DeploymentNode>(new QueryDefinition
            {
                Sorts = new List<SortClause>
                {
                    new() { Field = "NodeId", Direction = SortDirection.Asc }
                },
                Top = 500
            }).ToList();

            context.Response.ContentType = "application/json";
            await using var w = new Utf8JsonWriter(context.Response.Body, s_compactWriterOptions);
            w.WriteStartArray();
            foreach (var n in nodes)
            {
                w.WriteStartObject();
                w.WriteNumber("id", n.Key);
                w.WriteString("nodeId", n.NodeId);
                w.WriteString("ring", n.Ring);
                w.WriteString("architecture", n.Architecture);
                w.WriteString("currentVersion", n.CurrentVersion);
                w.WriteString("lastHeartbeatUtc", n.LastHeartbeatUtc.ToString("O"));
                w.WriteNumber("pollIntervalSeconds", n.PollIntervalSeconds);
                w.WriteBoolean("isEnabled", n.IsEnabled);
                w.WriteString("displayName", n.DisplayName);
                w.WriteString("clusterEndpoint", n.ClusterEndpoint);
                w.WriteEndObject();
            }
            w.WriteEndArray();
        }));

        // ── DELETE /api/runtime/nodes/{id} — remove a deployment node (admin) ────
        host.RegisterRoute("DELETE /api/runtime/nodes/{id}", new RouteHandlerData(raw, async context =>
        {
            var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            if (user == null) { context.Response.StatusCode = 401; return; }
            CsrfProtection.ValidateApiToken(context);

            var idStr = GetRouteParam(context, "id");
            if (!uint.TryParse(idStr, out var key)) { context.Response.StatusCode = 400; return; }

            await DataStoreProvider.Current.DeleteAsync<DeploymentNode>(key, context.RequestAborted).ConfigureAwait(false);
            context.Response.StatusCode = 204;
        }));
    }

    /// <summary>
    /// Register admin API routes for the automated WAL backup service.
    /// Only call this when the backup service is enabled and a <see cref="WalBackupService"/>
    /// instance has been created.
    /// Registers:
    /// <list type="bullet">
    ///   <item><description>POST /api/admin/backup — trigger an on-demand backup</description></item>
    ///   <item><description>GET  /api/admin/backups — list available backups</description></item>
    /// </list>
    /// </summary>
    public static void RegisterBackupRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory,
        WalBackupService backupService)
    {
        // Admin endpoint: POST /api/admin/backup — trigger on-demand backup
        host.RegisterRoute("POST /api/admin/backup", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", true),
            async context =>
            {
                try
                {
                    var backupPath = backupService.CreateBackup();
                    context.Response.StatusCode = 200;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync($"{{\"status\":\"ok\",\"path\":\"{backupPath.Replace("\\", "\\\\")}\"}}")
                        .ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    context.Response.StatusCode = 500;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync($"{{\"status\":\"error\",\"message\":\"{ex.Message}\"}}")
                        .ConfigureAwait(false);
                }
            }));

        // Admin endpoint: GET /api/admin/backups — list available backups
        host.RegisterRoute("GET /api/admin/backups", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", true),
            async context =>
            {
                var backups = backupService.ListBackups();
                context.Response.StatusCode = 200;
                context.Response.ContentType = "application/json";
                var sb = new System.Text.StringBuilder();
                sb.Append('[');
                for (int i = 0; i < backups.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    var b = backups[i];
                    sb.Append($"{{\"name\":\"{b.Name}\",\"timestamp\":\"{b.Timestamp:O}\",\"commitPtr\":\"{b.CommitPtr}\",\"files\":{b.FileCount},\"size\":\"{b.SizeDisplay}\"}}");
                }
                sb.Append(']');
                await context.Response.WriteAsync(sb.ToString()).ConfigureAwait(false);
            }));
    }

    /// <summary>
    /// Register admin API routes for the capability graph and workflow planner.
    /// Registers:
    /// <list type="bullet">
    ///   <item><description>GET  /api/admin/capabilities — returns the full capability graph as JSON</description></item>
    ///   <item><description>POST /api/admin/workflow-plan — generate a workflow plan from a natural-language intent string</description></item>
    /// </list>
    /// </summary>
    public static void RegisterCapabilityRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        // Admin endpoint: GET /api/admin/capabilities — capability graph summary
        host.RegisterRoute("GET /api/admin/capabilities", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var graph = BareMetalWeb.Runtime.CapabilityGraph.CapabilityGraphRegistry.Current;
                if (graph == null)
                {
                    context.Response.StatusCode = 503;
                    await context.Response.WriteAsync("{\"error\":\"Capability graph not yet built\"}").ConfigureAwait(false);
                    return;
                }
                context.Response.ContentType = "application/json";
                var (nodes, edges, entities) = graph.Stats;
                using var ms = new System.IO.MemoryStream(1024);
                using (var w = new System.Text.Json.Utf8JsonWriter(ms))
                {
                    w.WriteStartObject();
                    w.WriteString("builtUtc", graph.BuiltUtc.ToString("O"));
                    w.WriteNumber("nodeCount", nodes);
                    w.WriteNumber("edgeCount", edges);
                    w.WriteNumber("entityCount", entities);
                    w.WriteStartArray("nodes");
                    foreach (var n in graph.Nodes)
                    {
                        w.WriteStartObject();
                        w.WriteNumber("id", n.Id);
                        w.WriteString("type", n.Type.ToString());
                        w.WriteNumber("entityIndex", n.EntityIndex);
                        w.WriteString("label", n.Label);
                        if (n.Detail != null) w.WriteString("detail", n.Detail);
                        w.WriteEndObject();
                    }
                    w.WriteEndArray();
                    w.WriteStartArray("edges");
                    foreach (var e in graph.Edges)
                    {
                        w.WriteStartObject();
                        w.WriteNumber("from", e.FromNode);
                        w.WriteNumber("to", e.ToNode);
                        w.WriteEndObject();
                    }
                    w.WriteEndArray();
                    w.WriteStartArray("entities");
                    foreach (var ent in graph.Entities)
                    {
                        w.WriteStartObject();
                        w.WriteString("entityId", ent.EntityId);
                        w.WriteString("name", ent.Name);
                        w.WriteString("slug", ent.Slug);
                        w.WriteEndObject();
                    }
                    w.WriteEndArray();
                    w.WriteEndObject();
                }
                await context.Response.Body.WriteAsync(ms.ToArray()).ConfigureAwait(false);
            }));

        // Admin endpoint: POST /api/admin/workflow-plan — generate a workflow plan from NL intent
        host.RegisterRoute("POST /api/admin/workflow-plan", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var graph = BareMetalWeb.Runtime.CapabilityGraph.CapabilityGraphRegistry.Current;
                if (graph == null)
                {
                    context.Response.StatusCode = 503;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Capability graph not yet built\"}").ConfigureAwait(false);
                    return;
                }

                string intent;
                using (var reader = new System.IO.StreamReader(context.HttpRequest.Body, System.Text.Encoding.UTF8))
                    intent = await reader.ReadToEndAsync(context.RequestAborted).ConfigureAwait(false);

                if (string.IsNullOrWhiteSpace(intent))
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Request body must contain the workflow intent text\"}").ConfigureAwait(false);
                    return;
                }

                var planner = new BareMetalWeb.Runtime.CapabilityGraph.WorkflowPlanner(graph);
                var plan = planner.GeneratePlan(intent);

                context.Response.ContentType = "application/json";
                context.Response.StatusCode = 200;
                using var ms = new System.IO.MemoryStream(512);
                using (var w = new System.Text.Json.Utf8JsonWriter(ms))
                {
                    w.WriteStartObject();
                    w.WriteBoolean("isValid", plan.IsValid);
                    w.WriteString("createdUtc", plan.CreatedUtc.ToString("O"));
                    w.WriteString("originalInput", plan.OriginalInput);

                    w.WriteStartArray("steps");
                    foreach (var step in plan.Steps)
                    {
                        w.WriteStartObject();
                        w.WriteNumber("order", step.Order);
                        w.WriteString("type", step.Type.ToString());
                        w.WriteString("entity", step.EntitySlug);
                        w.WriteString("output", step.OutputVariable);
                        if (step.InputVariable != null) w.WriteString("input", step.InputVariable);
                        if (step.Condition != null) w.WriteString("condition", step.Condition);
                        if (step.ActionName != null) w.WriteString("action", step.ActionName);
                        w.WriteNumber("capabilityNodeId", step.CapabilityNodeId);
                        w.WriteEndObject();
                    }
                    w.WriteEndArray();

                    if (plan.ValidationErrors.Length > 0)
                    {
                        w.WriteStartArray("errors");
                        foreach (var err in plan.ValidationErrors)
                            w.WriteStringValue(err);
                        w.WriteEndArray();
                    }

                    w.WriteEndObject();
                }
                await context.Response.Body.WriteAsync(ms.ToArray()).ConfigureAwait(false);
            }));
    }
}
