using System.Linq;
using System.Net;
using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Host;

/// <summary>
/// Extension methods for registering routes on IBareWebHost in a plugin-like fashion.
/// Each method handles registration of a logical group of related routes.
/// </summary>
public static class RouteRegistrationExtensions
{
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
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Home", "<p></p>" }, "Public", false, 60),
            routeHandlers.DefaultPageHandler));

        host.RegisterRoute("GET /status", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "" }, "Public", false, 1),
            routeHandlers.BuildPageHandler(context =>
            {
                context.Response.ContentType = "text/html";
                context.SetStringValue("title", "Server Time");
                context.SetStringValue("message", $"Current server time is: {DateTime.UtcNow:O}");
            })));

        host.RegisterRoute("GET /statusRaw", new RouteHandlerData(
            pageInfoFactory.RawPage("Public", false),
            routeHandlers.TimeRawHandler));
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
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Login", "" }, "AnonymousOnly", true, 1, navAlignment: NavAlignment.Right, navRenderStyle: NavRenderStyle.Button, navColorClass: "btn-success"),
            routeHandlers.LoginHandler));
        host.RegisterRoute("POST /login", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Login", "" }, "AnonymousOnly", false, 1),
            routeHandlers.LoginPostHandler));

        // MFA
        host.RegisterRoute("GET /mfa", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Verify MFA", "" }, "AnonymousOnly", false, 1),
            routeHandlers.MfaChallengeHandler));
        host.RegisterRoute("POST /mfa", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Verify MFA", "" }, "AnonymousOnly", false, 1),
            routeHandlers.MfaChallengePostHandler));

        // Registration (conditional)
        if (allowAccountCreation)
        {
            host.RegisterRoute("GET /register", new RouteHandlerData(
                pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Create Account", "" }, "AnonymousOnly", false, 1, navAlignment: NavAlignment.Right),
                routeHandlers.RegisterHandler));
            host.RegisterRoute("POST /register", new RouteHandlerData(
                pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Create Account", "" }, "AnonymousOnly", false, 1),
                routeHandlers.RegisterPostHandler));
        }

        // Logout
        host.RegisterRoute("GET /logout", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Logout", "" }, "Authenticated", false, 1),
            routeHandlers.LogoutHandler));
        host.RegisterRoute("POST /logout", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Logout", "" }, "Authenticated", false, 1),
            routeHandlers.LogoutPostHandler));

        // Account management
        host.RegisterRoute("GET /account", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Account", "" }, "Authenticated", true, 1, navAlignment: NavAlignment.Right),
            routeHandlers.AccountHandler));

        host.RegisterRoute("GET /account/mfa", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Multi-Factor Authentication", "" }, "Authenticated", true, 1),
            routeHandlers.MfaStatusHandler));
        host.RegisterRoute("GET /account/mfa/setup", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Enable MFA", "" }, "Authenticated", false, 1),
            routeHandlers.MfaSetupHandler));
        host.RegisterRoute("POST /account/mfa/setup", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Enable MFA", "" }, "Authenticated", false, 1),
            routeHandlers.MfaSetupPostHandler));
        host.RegisterRoute("GET /account/mfa/reset", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Reset MFA", "" }, "Authenticated", false, 1),
            routeHandlers.MfaResetHandler));
        host.RegisterRoute("POST /account/mfa/reset", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Reset MFA", "" }, "Authenticated", false, 1),
            routeHandlers.MfaResetPostHandler));

        // Initial setup
        host.RegisterRoute("GET /setup", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Setup", "" }, "AnonymousOnly", false, 1),
            routeHandlers.SetupHandler));
        host.RegisterRoute("POST /setup", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Setup", "" }, "AnonymousOnly", false, 1),
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
        // Metrics
        host.RegisterRoute("GET /metrics", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Metric Viewer", "" }, "monitoring", true, 1, navGroup: "System", navAlignment: NavAlignment.Right),
            routeHandlers.BuildPageHandler(context =>
            {
                var app = context.GetApp()!;
                app.Metrics.GetMetricTable(out string[] tableColumns, out string[][] tableRows);
                context.SetStringValue("title", "Metric Viewer");
                context.AddTable(tableColumns, tableRows);
            })));

        host.RegisterRoute("GET /metrics/json", new RouteHandlerData(
            pageInfoFactory.RawPage("monitoring", false),
            routeHandlers.MetricsJsonHandler));

        // IP tracking
        host.RegisterRoute("GET /topips", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Top IPs", "" }, "monitoring", true, 1, navGroup: "System", navAlignment: NavAlignment.Right),
            routeHandlers.BuildPageHandler(context =>
            {
                var app = context.GetApp()!;
                app.ClientRequests.GetTopClientsTable(20, out var tableColumns, out var tableRows);
                context.SetStringValue("title", "Top IPs");
                context.AddTable(tableColumns, tableRows);
            })));

        host.RegisterRoute("GET /suspiciousips", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Suspicious IPs", "" }, "monitoring", true, 1, navGroup: "System", navAlignment: NavAlignment.Right),
            routeHandlers.BuildPageHandler(context =>
            {
                var app = context.GetApp()!;
                app.ClientRequests.GetSuspiciousClientsTable(20, out var tableColumns, out var tableRows);
                context.SetStringValue("title", "Suspicious IPs");
                context.AddTable(tableColumns, tableRows);
            })));
    }

    /// <summary>
    /// Register admin/system routes (logs, sample data, template reload).
    /// </summary>
    public static void RegisterAdminRoutes(
        this IBareWebHost host,
        IRouteHandlers routeHandlers,
        IPageInfoFactory pageInfoFactory,
        IHtmlTemplate mainTemplate,
        bool enableWipeData = false)
    {
        // Log management
        host.RegisterRoute("GET /admin/logs", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Logs", "" }, "monitoring", true, 1, navGroup: "System", navAlignment: NavAlignment.Right),
            routeHandlers.LogsViewerHandler));
        host.RegisterRoute("GET /admin/logs/prune", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Prune Logs", "" }, "monitoring", false, 1),
            routeHandlers.LogsPruneHandler));
        host.RegisterRoute("POST /admin/logs/prune", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Prune Logs", "" }, "monitoring", false, 1),
            routeHandlers.LogsPrunePostHandler));
        host.RegisterRoute("GET /admin/logs/download", new RouteHandlerData(
            pageInfoFactory.RawPage("monitoring", false),
            routeHandlers.LogsDownloadHandler));

        // Sample data generation
        host.RegisterRoute("GET /admin/sample-data", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Generate Sample Data", "" }, "admin", true, 1, navGroup: "System", navAlignment: NavAlignment.Right),
            routeHandlers.SampleDataHandler));
        host.RegisterRoute("POST /admin/sample-data", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Generate Sample Data", "" }, "admin", false, 1),
            routeHandlers.SampleDataPostHandler));

        // Template management
        host.RegisterRoute("GET /admin/reload-templates", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Reload Templates", "" }, "admin", true, 1, navGroup: "System", navAlignment: NavAlignment.Right),
            routeHandlers.ReloadTemplatesHandler));

        // Wipe all data — staging/dev only, disabled by default in production
        if (enableWipeData)
        {
            host.RegisterRoute("GET /admin/wipe-data", new RouteHandlerData(
                pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Wipe All Data", "" }, "admin", true, 0, navGroup: "System", navAlignment: NavAlignment.Right),
                routeHandlers.WipeDataHandler));
            host.RegisterRoute("POST /admin/wipe-data", new RouteHandlerData(
                pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Wipe All Data", "" }, "admin", false, 0),
                routeHandlers.WipeDataPostHandler));
        }
    }

    /// <summary>
    /// Register data management CRUD routes for entity browsing, editing, and export.
    /// </summary>
    public static void RegisterDataRoutes(
        this IBareWebHost host,
        IRouteHandlers routeHandlers,
        IPageInfoFactory pageInfoFactory,
        IHtmlTemplate mainTemplate)
    {
        // Entity browsing
        host.RegisterRoute("GET /admin/data", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Data", "" }, "Authenticated", true, 1, navGroup: "Admin", navAlignment: NavAlignment.Right),
            routeHandlers.DataEntitiesHandler));

        host.RegisterRoute("GET /admin/data/{type}", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Data", "" }, "Authenticated", false, 1, navGroup: "Admin", navAlignment: NavAlignment.Right),
            routeHandlers.DataListHandler));

        // Export
        host.RegisterRoute("GET /admin/data/{type}/csv", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataListCsvHandler));
        host.RegisterRoute("GET /admin/data/{type}/html", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataListHtmlHandler));
        host.RegisterRoute("GET /admin/data/{type}/export", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataListExportHandler));

        // Import
        host.RegisterRoute("GET /admin/data/{type}/import", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Import CSV", "" }, "Authenticated", false, 1),
            routeHandlers.DataImportHandler));
        host.RegisterRoute("POST /admin/data/{type}/import", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Import CSV", "" }, "Authenticated", false, 1),
            routeHandlers.DataImportPostHandler));

        // Create
        host.RegisterRoute("GET /admin/data/{type}/create", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Create", "" }, "Authenticated", false, 1),
            routeHandlers.DataCreateHandler));
        host.RegisterRoute("POST /admin/data/{type}/create", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Create", "" }, "Authenticated", false, 1),
            routeHandlers.DataCreatePostHandler));

        // View
        host.RegisterRoute("GET /admin/data/{type}/{id}", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "View", "" }, "Authenticated", false, 1),
            routeHandlers.DataViewHandler));
        host.RegisterRoute("GET /admin/data/{type}/{id}/rtf", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataViewRtfHandler));
        host.RegisterRoute("GET /admin/data/{type}/{id}/html", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataViewHtmlHandler));
        host.RegisterRoute("GET /admin/data/{type}/{id}/export", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataViewExportHandler));

        // Edit
        host.RegisterRoute("GET /admin/data/{type}/{id}/edit", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Edit", "" }, "Authenticated", false, 1),
            routeHandlers.DataEditHandler));
        host.RegisterRoute("POST /admin/data/{type}/{id}/edit", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Edit", "" }, "Authenticated", false, 1),
            routeHandlers.DataEditPostHandler));

        // Clone
        host.RegisterRoute("POST /admin/data/{type}/{id}/clone", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataClonePostHandler));
        host.RegisterRoute("POST /admin/data/{type}/{id}/clone-edit", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataCloneEditPostHandler));

        // Delete
        host.RegisterRoute("GET /admin/data/{type}/{id}/delete", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Delete", "" }, "Authenticated", false, 1),
            routeHandlers.DataDeleteHandler));
        host.RegisterRoute("POST /admin/data/{type}/{id}/delete", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Delete", "" }, "Authenticated", false, 1),
            routeHandlers.DataDeletePostHandler));

        // Bulk operations
        host.RegisterRoute("POST /admin/data/{type}/bulk-delete", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataBulkDeleteHandler));
        
        host.RegisterRoute("GET /admin/data/{type}/bulk-export", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataBulkExportHandler));
    }

    /// <summary>
    /// Register VNext JavaScript SPA routes at /vnext/{*path}.
    /// Serves the shell HTML that loads the four BareMetalWeb JS libraries
    /// (BareMetalRest, BareMetalBind, BareMetalTemplate, BareMetalRendering)
    /// plus the thin VNext router (vnext-app.js).
    /// </summary>
    public static void RegisterVNextRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        host.RegisterRoute("GET /vnext/{*path}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            async context =>
            {
                // Detect selected Bootstrap theme from cookie (mirrors main app theme logic)
                var themeCookie = context.Request.Cookies["bm-selected-theme"];
                var safeThemes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "cerulean","cosmo","cyborg","darkly","flatly","journal","litera","lumen","lux",
                    "materia","minty","morph","pulse","quartz","sandstone","simplex","sketchy",
                    "slate","solar","spacelab","superhero","united","vapor","yeti","zephyr"
                };
                string themeHref = safeThemes.Contains(themeCookie ?? "")
                    ? $"https://cdn.jsdelivr.net/npm/bootswatch@5.3.3/dist/{Uri.EscapeDataString(themeCookie!)}/bootstrap.min.css"
                    : "/static/css/bootstrap.min.css";

                context.Response.ContentType = "text/html; charset=utf-8";
                context.Response.StatusCode = 200;
                await context.Response.WriteAsync(
                    "<!DOCTYPE html><html lang=\"en\"><head>" +
                    "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
                    "<title>BareMetalWeb VNext</title>" +
                    $"<link id=\"bootswatch-theme\" rel=\"stylesheet\" href=\"{themeHref}\">" +
                    "<link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css\" integrity=\"sha384-XGjxtQfXaH2tnPFa9x+ruJTuLE3Aa6LhHSWRr1XeTyhezb4abCG4ccI5AkVDxqC+\" crossorigin=\"anonymous\">" +
                    "<link rel=\"stylesheet\" href=\"/static/css/site.css\">" +
                    "</head><body>" +
                    "<div id=\"vnext-root\"><div class=\"d-flex justify-content-center align-items-center\" style=\"height:80vh\">" +
                    "<div class=\"spinner-border\" role=\"status\"><span class=\"visually-hidden\">Loading...</span></div>" +
                    "</div></div>" +
                    "<script src=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js\" integrity=\"sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz\" crossorigin=\"anonymous\" defer></script>" +
                    "<script src=\"/static/js/BareMetalRest.js\" defer></script>" +
                    "<script src=\"/static/js/BareMetalBind.js\" defer></script>" +
                    "<script src=\"/static/js/BareMetalTemplate.js\" defer></script>" +
                    "<script src=\"/static/js/BareMetalRendering.js\" defer></script>" +
                    "<script src=\"/static/js/vnext-app.js\" defer></script>" +
                    "</body></html>");
            }));
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

                foreach (var f in meta.Fields.OrderBy(x => x.Order))
                {
                    var isId = f.Name.Equals("Id", StringComparison.OrdinalIgnoreCase);
                    var fieldDef = new Dictionary<string, object?>
                    {
                        ["type"]  = MapFieldType(f.FieldType),
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
                        var target = DataScaffold.GetEntityByType(f.Lookup.TargetType);
                        if (target != null)
                            fieldDef["lookupUrl"] = $"/api/_lookup/{target.Slug}";
                        fieldDef["lookupValueField"]   = f.Lookup.ValueField;
                        fieldDef["lookupDisplayField"] = f.Lookup.DisplayField;
                    }

                    schemaFields[f.Name] = fieldDef;
                    initialData[f.Name]  = GetFieldDefault(f.FieldType);

                    if (!f.ReadOnly && !isId && f.Edit)
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
                await context.Response.WriteAsync(
                    JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = false }));
            }));
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private static string? GetRouteParam(Microsoft.AspNetCore.Http.HttpContext context, string key)
    {
        var pageContext = context.GetPageContext();
        if (pageContext == null) return null;
        for (int i = 0; i < pageContext.PageMetaDataKeys.Length; i++)
        {
            if (string.Equals(pageContext.PageMetaDataKeys[i], key, StringComparison.OrdinalIgnoreCase))
                return WebUtility.HtmlDecode(pageContext.PageMetaDataValues[i]);
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
    /// Register RESTful API routes for entity operations.
    /// </summary>
    public static void RegisterApiRoutes(
        this IBareWebHost host,
        IRouteHandlers routeHandlers,
        IPageInfoFactory pageInfoFactory)
    {
        // List and create
        host.RegisterRoute("GET /api/{type}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataApiListHandler));
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
}
