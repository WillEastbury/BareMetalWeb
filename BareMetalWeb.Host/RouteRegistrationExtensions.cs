using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
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
using BareMetalWeb.Runtime;
using Microsoft.AspNetCore.Http;

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
                        var target = DataScaffold.GetEntityByType(f.Lookup.TargetType);
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
    /// Register lookup API routes before generic /api/{type} routes to avoid pattern conflicts.
    /// Must be called before <see cref="RegisterApiRoutes"/>.
    /// </summary>
    public static void RegisterLookupApiRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        // More specific routes must be registered first to avoid {id} matching literal segments
        host.RegisterRoute("GET /api/_lookup/{type}/_field/{id}/{fieldName}", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), LookupApiHandlers.GetEntityFieldHandler));
        host.RegisterRoute("GET /api/_lookup/{type}/_aggregate", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), LookupApiHandlers.AggregateEntitiesHandler));
        host.RegisterRoute("GET /api/_lookup/{type}/{id}", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), LookupApiHandlers.GetEntityByIdHandler));
        host.RegisterRoute("GET /api/_lookup/{type}", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), LookupApiHandlers.QueryEntitiesHandler));
    }

    /// <summary>
    /// Register RESTful API routes for entity operations.
    /// </summary>
    public static void RegisterApiRoutes(
        this IBareWebHost host,
        IRouteHandlers routeHandlers,
        IPageInfoFactory pageInfoFactory)
    {
        // Lookup API endpoints — must be registered before parameterised /api/{type}
        // routes to prevent /api/_lookup/customers matching as {type}=_lookup {id}=customers
        host.RegisterRoute("GET /api/_lookup/{type}/_field/{id}/{fieldName}", new RouteHandlerData(
            pageInfoFactory.RawPage("Public", false), LookupApiHandlers.GetEntityFieldHandler));
        host.RegisterRoute("GET /api/_lookup/{type}/_aggregate", new RouteHandlerData(
            pageInfoFactory.RawPage("Public", false), LookupApiHandlers.AggregateEntitiesHandler));
        host.RegisterRoute("GET /api/_lookup/{type}/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("Public", false), LookupApiHandlers.GetEntityByIdHandler));
        host.RegisterRoute("GET /api/_lookup/{type}", new RouteHandlerData(
            pageInfoFactory.RawPage("Public", false), LookupApiHandlers.QueryEntitiesHandler));

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

    /// <summary>
    /// Register the VNext JS SPA shell and metadata API endpoints.
    /// Metadata routes at /meta/objects and /meta/{object} provide schema info to the client.
    /// The SPA shell at /vnext and /vnext/{*path} serves the client-side application.
    /// </summary>
    public static void RegisterVNextRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        // List accessible entities for the current user
        host.RegisterRoute("GET /meta/objects", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                var userPermissions = user?.Permissions ?? Array.Empty<string>();

                var entities = DataScaffold.Entities
                    .Where(e => IsEntityAccessible(e, user, userPermissions))
                    .Select(e => (object)new Dictionary<string, object?>
                    {
                        ["slug"] = e.Slug,
                        ["name"] = e.Name,
                        ["navGroup"] = e.NavGroup,
                        ["showOnNav"] = e.ShowOnNav,
                        ["navOrder"] = e.NavOrder,
                        ["viewType"] = e.ViewType.ToString()
                    })
                    .ToArray();

                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(
                    JsonSerializer.Serialize(entities, new JsonSerializerOptions { WriteIndented = false }));
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
                await context.Response.WriteAsync(
                    JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = false }));
            }));

        // VNext SPA shell — serve for all /vnext and /vnext/{*path} routes
        host.RegisterRoute("GET /vnext", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            context => ServeVNextShell(context)));

        host.RegisterRoute("GET /vnext/{*path}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            context => ServeVNextShell(context)));
    }

    /// <summary>
    /// Registers the metadata-driven Runtime API endpoints:
    /// <list type="bullet">
    ///   <item><description>GET /meta/entity/{name} — returns a <see cref="RuntimeEntityModel"/> as JSON, including EntityId, schemaHash, indexes, and actions.</description></item>
    ///   <item><description>POST /query — accepts { entity, clauses, sorts, skip, top } and returns matching records.</description></item>
    ///   <item><description>POST /intent — accepts a <see cref="BareMetalWeb.Runtime.CommandIntent"/> and executes create/update/delete/action.</description></item>
    /// </list>
    /// Must be registered BEFORE <see cref="RegisterApiRoutes"/> to avoid slug conflicts.
    /// </summary>
    public static void RegisterRuntimeApiRoutes(
        this IBareWebHost host,
        IPageInfoFactory pageInfoFactory)
    {
        var queryService = new BareMetalWeb.Runtime.QueryService();
        var commandService = new BareMetalWeb.Runtime.CommandService();
        var jsonOptions = new JsonSerializerOptions { WriteIndented = false };

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
                    ["fields"] = runtimeModel.Fields.Select(f => (object)new Dictionary<string, object?>
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
                    }).ToArray(),
                    ["indexes"] = runtimeModel.Indexes.Select(i => (object)new Dictionary<string, object?>
                    {
                        ["indexId"] = i.IndexId,
                        ["fields"] = i.FieldNames,
                        ["type"] = i.Type
                    }).ToArray(),
                    ["actions"] = runtimeModel.Actions.Select(a => (object)new Dictionary<string, object?>
                    {
                        ["actionId"] = a.ActionId,
                        ["name"] = a.Name,
                        ["label"] = a.Label,
                        ["icon"] = a.Icon,
                        ["permission"] = a.Permission,
                        ["enabledWhen"] = a.EnabledWhen
                    }).ToArray()
                };

                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(result, jsonOptions));
            }));

        // POST /query — { "entity": "slug", "clauses": [...], "sorts": [...], "skip": 0, "top": 50 }
        host.RegisterRoute("POST /query", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            async context =>
            {
                using var reader = new System.IO.StreamReader(context.Request.Body);
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
                catch (Exception ex)
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(
                        JsonSerializer.Serialize(new { error = ex.Message }, jsonOptions));
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
                await context.Response.WriteAsync(JsonSerializer.Serialize(results, jsonOptions));
            }));

        // POST /intent — CommandIntent body
        host.RegisterRoute("POST /intent", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            async context =>
            {
                using var reader = new System.IO.StreamReader(context.Request.Body);
                var body = await reader.ReadToEndAsync(context.RequestAborted).ConfigureAwait(false);

                BareMetalWeb.Runtime.CommandIntent intent;
                try
                {
                    intent = JsonSerializer.Deserialize<BareMetalWeb.Runtime.CommandIntent>(body, jsonOptions)
                             ?? throw new InvalidOperationException("Request body could not be parsed as a CommandIntent.");
                }
                catch (Exception ex)
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(
                        JsonSerializer.Serialize(new { error = ex.Message }, jsonOptions));
                    return;
                }

                var result = await commandService.ExecuteAsync(intent, context.RequestAborted).ConfigureAwait(false);
                context.Response.StatusCode = result.Success ? 200 : 400;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(result, jsonOptions));
            }));
    }

    // ─── Private helpers ────────────────────────────────────────────────────────

    private static bool IsEntityAccessible(DataEntityMetadata entity, User? user, string[] userPermissions)
    {
        var perms = entity.Permissions ?? string.Empty;
        if (string.IsNullOrWhiteSpace(perms) || string.Equals(perms, "Public", StringComparison.OrdinalIgnoreCase))
            return true;
        if (string.Equals(perms, "Authenticated", StringComparison.OrdinalIgnoreCase))
            return user != null;

        var required = perms.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return required.Any(r => userPermissions.Any(p => string.Equals(p, r, StringComparison.OrdinalIgnoreCase)));
    }

    private static string? GetMetaRouteParam(HttpContext context, string key)
    {
        var pageContext = context.GetPageContext();
        if (pageContext == null)
            return null;
        for (int i = 0; i < pageContext.PageMetaDataKeys.Length; i++)
        {
            if (string.Equals(pageContext.PageMetaDataKeys[i], key, StringComparison.OrdinalIgnoreCase))
                return WebUtility.HtmlDecode(pageContext.PageMetaDataValues[i]);
        }
        return null;
    }

    private static Dictionary<string, object?> BuildEntitySchema(DataEntityMetadata meta)
    {
        var fields = meta.Fields.OrderBy(f => f.Order).Select(f =>
        {
            var fd = new Dictionary<string, object?>
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
                ["isIdField"] = f.IdGeneration != IdGenerationStrategy.None,
                ["idGeneration"] = f.IdGeneration.ToString(),
                ["placeholder"] = f.Placeholder
            };

            if (f.Lookup != null)
            {
                var targetMeta = DataScaffold.GetEntityByType(f.Lookup.TargetType);
                fd["lookup"] = new Dictionary<string, object?>
                {
                    ["targetSlug"] = targetMeta?.Slug,
                    ["targetName"] = targetMeta?.Name,
                    ["valueField"] = f.Lookup.ValueField,
                    ["displayField"] = f.Lookup.DisplayField,
                    ["queryField"] = f.Lookup.QueryField,
                    ["queryValue"] = f.Lookup.QueryValue,
                    ["sortField"] = f.Lookup.SortField,
                    ["sortDirection"] = f.Lookup.SortDirection.ToString()
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

            return (object)fd;
        }).ToArray();

        var commands = meta.Commands.OrderBy(c => c.Order).Select(c => (object)new Dictionary<string, object?>
        {
            ["name"] = c.Name,
            ["label"] = c.Label,
            ["icon"] = c.Icon,
            ["confirmMessage"] = c.ConfirmMessage,
            ["destructive"] = c.Destructive,
            ["permission"] = c.Permission,
            ["order"] = c.Order
        }).ToArray();

        return new Dictionary<string, object?>
        {
            ["slug"] = meta.Slug,
            ["name"] = meta.Name,
            ["permissions"] = meta.Permissions,
            ["showOnNav"] = meta.ShowOnNav,
            ["navGroup"] = meta.NavGroup,
            ["navOrder"] = meta.NavOrder,
            ["viewType"] = meta.ViewType.ToString(),
            ["idGeneration"] = meta.IdGeneration.ToString(),
            ["parentField"] = meta.ParentField != null ? (object)new Dictionary<string, object?>
            {
                ["name"] = meta.ParentField.Name,
                ["label"] = meta.ParentField.Label
            } : null,
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
        host.RegisterRoute("GET /reports", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", true),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.Redirect("/login"); return; }

                var reports = DataStoreProvider.Current.Query<ReportDefinition>(null).OrderBy(r => r.Name).ToList();

                var sb = new StringBuilder(2048);
                sb.Append("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
                sb.Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
                sb.Append("<title>Reports</title>");
                sb.Append("<style>*{box-sizing:border-box;margin:0;padding:0}");
                sb.Append("body{font-family:system-ui,-apple-system,sans-serif;background:#f4f6f9;color:#333;padding:24px}");
                sb.Append(".card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.12);padding:24px;max-width:900px;margin:0 auto}");
                sb.Append("h1{font-size:1.6em;font-weight:700;color:#1a1a2e;margin-bottom:20px;border-bottom:2px solid #e8eaf6;padding-bottom:12px}");
                sb.Append("table{width:100%;border-collapse:collapse}.th{background:#e8eaf6;text-align:left;padding:10px 12px;font-weight:600;font-size:.9em;color:#444;border-bottom:2px solid #c5cae9}");
                sb.Append("td{padding:10px 12px;border-bottom:1px solid #eee;font-size:.9em}tr:hover{background:#f5f7ff}");
                sb.Append("a.run{display:inline-block;padding:4px 12px;background:#4361ee;color:#fff;border-radius:4px;text-decoration:none;font-size:.85em;font-weight:600}");
                sb.Append("a.run:hover{background:#3a56d4}.empty{padding:40px;text-align:center;color:#999}</style></head>");
                sb.Append("<body><div class=\"card\"><h1>&#128202; Reports</h1>");

                if (reports.Count == 0)
                {
                    sb.Append("<div class=\"empty\">No reports defined yet. Create one via <a href=\"/admin/data/report-definitions/create\">Admin &rarr; Report Definitions</a>.</div>");
                }
                else
                {
                    sb.Append("<table><thead><tr><th class=\"th\">Name</th><th class=\"th\">Description</th><th class=\"th\">Root Entity</th><th class=\"th\"></th></tr></thead><tbody>");
                    foreach (var r in reports)
                    {
                        sb.Append("<tr><td><strong>");
                        sb.Append(WebUtility.HtmlEncode(r.Name));
                        sb.Append("</strong></td><td>");
                        sb.Append(WebUtility.HtmlEncode(r.Description));
                        sb.Append("</td><td>");
                        sb.Append(WebUtility.HtmlEncode(r.RootEntity));
                        sb.Append("</td><td><a class=\"run\" href=\"/reports/");
                        sb.Append(WebUtility.UrlEncode(r.Id));
                        sb.Append("\">Run</a></td></tr>");
                    }
                    sb.Append("</tbody></table>");
                }

                sb.Append("</div></body></html>");
                context.Response.ContentType = "text/html; charset=utf-8";
                await context.Response.WriteAsync(sb.ToString());
            }));

        // Run a report → HTML
        host.RegisterRoute("GET /reports/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.Redirect("/login"); return; }

                var id = GetRouteParam(context, "id");
                if (string.IsNullOrWhiteSpace(id))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsync("Missing report id.");
                    return;
                }

                var def = await DataStoreProvider.Current.LoadAsync<ReportDefinition>(id, context.RequestAborted).ConfigureAwait(false);
                if (def == null)
                {
                    context.Response.StatusCode = 404;
                    await context.Response.WriteAsync("Report not found.");
                    return;
                }

                var parameters = def.Parameters;
                var runtimeParams = parameters.Count > 0
                    ? parameters
                        .Select(p => new KeyValuePair<string, string>(
                            p.Name,
                            context.Request.Query.TryGetValue(p.Name, out var qv) ? qv.ToString() : p.DefaultValue))
                        .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase)
                    : null;

                var executor = new ReportExecutor(DataStoreProvider.Current);
                ReportResult result;
                try
                {
                    result = await executor.ExecuteAsync(def, runtimeParams, context.RequestAborted).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    context.Response.StatusCode = 500;
                    context.Response.ContentType = "text/plain";
                    await context.Response.WriteAsync($"Error executing report: {WebUtility.HtmlEncode(ex.Message)}");
                    return;
                }

                context.Response.ContentType = "text/html; charset=utf-8";
                var pipeWriter = System.IO.Pipelines.PipeWriter.Create(context.Response.Body);
                await ReportHtmlRenderer.RenderAsync(
                    pipeWriter,
                    result,
                    def.Name,
                    def.Description,
                    parameters.Count > 0 ? parameters : null,
                    runtimeParams,
                    id);
                await pipeWriter.CompleteAsync();
            }));

        // JSON results via API
        host.RegisterRoute("GET /api/reports/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }

                var id = GetRouteParam(context, "id");
                if (string.IsNullOrWhiteSpace(id))
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Missing report id\"}");
                    return;
                }

                var def = await DataStoreProvider.Current.LoadAsync<ReportDefinition>(id, context.RequestAborted).ConfigureAwait(false);
                if (def == null)
                {
                    context.Response.StatusCode = 404;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Report not found\"}");
                    return;
                }

                var parameters = def.Parameters;
                var runtimeParams = parameters.Count > 0
                    ? parameters
                        .Select(p => new KeyValuePair<string, string>(
                            p.Name,
                            context.Request.Query.TryGetValue(p.Name, out var qv) ? qv.ToString() : p.DefaultValue))
                        .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase)
                    : null;

                var executor = new ReportExecutor(DataStoreProvider.Current);
                ReportResult result;
                try
                {
                    result = await executor.ExecuteAsync(def, runtimeParams, context.RequestAborted).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    context.Response.StatusCode = 500;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(new { error = ex.Message }));
                    return;
                }

                var format = context.Request.Query.TryGetValue("format", out var fmt) ? fmt.ToString() : "json";

                if (string.Equals(format, "csv", StringComparison.OrdinalIgnoreCase))
                {
                    context.Response.ContentType = "text/csv";
                    context.Response.Headers.ContentDisposition = $"attachment; filename=\"{Uri.EscapeDataString(def.Name)}.csv\"";
                    var csvSb = new StringBuilder();
                    csvSb.AppendLine(string.Join(",", result.ColumnLabels.Select(CsvCell)));
                    foreach (var row in result.Rows)
                        csvSb.AppendLine(string.Join(",", row.Select(c => CsvCell(c ?? string.Empty))));
                    await context.Response.WriteAsync(csvSb.ToString());
                    return;
                }

                // Default: JSON
                var json = new
                {
                    name = def.Name,
                    generatedAt = result.GeneratedAt,
                    totalRows = result.TotalRows,
                    isTruncated = result.IsTruncated,
                    columns = result.ColumnLabels,
                    rows = result.Rows.Select(r => r.Select((v, i) => new KeyValuePair<string, string?>(
                        i < result.ColumnLabels.Length ? result.ColumnLabels[i] : $"col{i}", v))
                        .ToDictionary(kv => kv.Key, kv => kv.Value))
                        .ToArray()
                };
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(json, new JsonSerializerOptions { WriteIndented = false }));
            }));
    }

    private static string CsvCell(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        return value;
    }

    private static async ValueTask ServeVNextShell(HttpContext context)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        var safeToken = WebUtility.HtmlEncode(csrfToken);

        var sb = new StringBuilder(4096);
        sb.Append("<!DOCTYPE html><html lang=\"en\">");
        sb.Append("<head>");
        sb.Append("<meta charset=\"utf-8\">");
        sb.Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        sb.Append("<title>BareMetalWeb — VNext</title>");
        sb.Append("<link id=\"bootswatch-theme\" rel=\"stylesheet\" href=\"/static/css/bootstrap.min.css\">");
        sb.Append("<link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css\" crossorigin=\"anonymous\">");
        sb.Append("<link rel=\"stylesheet\" href=\"/static/css/site.css\">");
        sb.Append($"<meta name=\"csrf-token\" content=\"{safeToken}\">");
        sb.Append("<meta name=\"vnext-base\" content=\"/vnext\">");
        sb.Append("</head>");
        sb.Append("<body>");
        sb.Append("<nav id=\"vnext-navbar\" class=\"navbar navbar-expand-lg navbar-dark bg-dark\">");
        sb.Append("<div class=\"container-fluid\">");
        sb.Append("<a class=\"navbar-brand\" href=\"/vnext\"><i class=\"bi bi-lightning-charge-fill\"></i> BareMetalWeb</a>");
        sb.Append("<button class=\"navbar-toggler\" type=\"button\" data-bs-toggle=\"collapse\" data-bs-target=\"#vnext-nav-content\" aria-controls=\"vnext-nav-content\" aria-expanded=\"false\" aria-label=\"Toggle navigation\">");
        sb.Append("<span class=\"navbar-toggler-icon\"></span></button>");
        sb.Append("<div class=\"collapse navbar-collapse\" id=\"vnext-nav-content\">");
        sb.Append("<ul id=\"vnext-nav-items\" class=\"navbar-nav me-auto mb-2 mb-lg-0\"></ul>");
        sb.Append("<ul class=\"navbar-nav ms-auto\">");
        sb.Append("<li class=\"nav-item\"><a class=\"nav-link\" href=\"/account\"><i class=\"bi bi-person-circle\"></i> Account</a></li>");
        sb.Append("<li class=\"nav-item\"><a class=\"nav-link\" href=\"/logout\"><i class=\"bi bi-box-arrow-right\"></i> Logout</a></li>");
        sb.Append("</ul></div></div></nav>");
        sb.Append("<div class=\"container-fluid py-3\" id=\"vnext-content\"><div class=\"text-center py-5\"><div class=\"spinner-border\" role=\"status\"><span class=\"visually-hidden\">Loading...</span></div></div></div>");
        sb.Append("<div id=\"vnext-modal-container\"></div>");
        sb.Append("<div id=\"vnext-toast-container\" class=\"position-fixed top-0 end-0 p-3\" style=\"z-index:1100\"></div>");
        sb.Append("<script src=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js\" crossorigin=\"anonymous\"></script>");
        sb.Append("<script src=\"/static/js/BareMetalRouting.js\"></script>");
        sb.Append("<script src=\"/static/js/vnext-app.js\"></script>");
        sb.Append("</body></html>");

        context.Response.ContentType = "text/html; charset=utf-8";
        context.Response.Headers.CacheControl = "no-store";
        await context.Response.WriteAsync(sb.ToString());
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
}
