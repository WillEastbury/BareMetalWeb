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
    private static readonly JsonSerializerOptions JsonCompact = new() { WriteIndented = false };
    private static readonly JsonSerializerOptions JsonIndented = new() { WriteIndented = true };

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
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "", "" }, "Public", false, 1),
            routeHandlers.BuildPageHandler(context =>
            {
                context.Response.ContentType = "text/html";
                context.SetStringValue("title", "Server Time");
                context.SetStringValue("html_message", $"Current server time is: {DateTime.UtcNow:O}");
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

        // SSO (Entra ID)
        host.RegisterRoute("GET /auth/sso/login", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 302, Array.Empty<string>(), Array.Empty<string>(), "AnonymousOnly", false, 0),
            routeHandlers.SsoLoginHandler));
        host.RegisterRoute("GET /auth/sso/callback", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "SSO Login", "" }, "AnonymousOnly", false, 0),
            routeHandlers.SsoCallbackHandler));
        host.RegisterRoute("GET /auth/sso/logout", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 302, Array.Empty<string>(), Array.Empty<string>(), "Authenticated", false, 0),
            routeHandlers.SsoLogoutHandler));

        // Account management
        host.RegisterRoute("GET /account", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Account", "" }, "Authenticated", true, 1, navGroup: "Account", navAlignment: NavAlignment.Right),
            routeHandlers.AccountHandler));

        host.RegisterRoute("GET /account/mfa", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Multi-Factor Authentication", "" }, "Authenticated", true, 1, navGroup: "Account", navAlignment: NavAlignment.Right),
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
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Metric Viewer", "" }, "monitoring", true, 1, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "📊 Monitoring"),
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
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Top IPs", "" }, "monitoring", true, 1, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "📊 Monitoring"),
            routeHandlers.BuildPageHandler(context =>
            {
                var app = context.GetApp()!;
                app.ClientRequests.GetTopClientsTable(20, out var tableColumns, out var tableRows);
                context.SetStringValue("title", "Top IPs");
                context.AddTable(tableColumns, tableRows);
            })));

        host.RegisterRoute("GET /suspiciousips", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Suspicious IPs", "" }, "monitoring", true, 1, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "📊 Monitoring"),
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
        IHtmlTemplate mainTemplate)
    {
        // Log management
        host.RegisterRoute("GET /admin/logs", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Logs", "" }, "monitoring", true, 1, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "📊 Monitoring"),
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
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Generate Sample Data", "" }, "admin", true, 1, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "🔧 Tools"),
            routeHandlers.SampleDataHandler));
        host.RegisterRoute("POST /admin/sample-data", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Generate Sample Data", "" }, "admin", false, 1),
            routeHandlers.SampleDataPostHandler));

        // Template management
        host.RegisterRoute("GET /admin/reload-templates", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Reload Templates", "" }, "admin", true, 1, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "🔧 Tools"),
            routeHandlers.ReloadTemplatesHandler));

        // Wipe all data — always registered; returns 419 if admin.allowWipeData setting is not configured
        host.RegisterRoute("GET /admin/wipe-data", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Wipe All Data", "" }, "admin", true, 0, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "⚠️ Danger"),
            routeHandlers.WipeDataHandler));
        host.RegisterRoute("POST /admin/wipe-data", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Wipe All Data", "" }, "admin", false, 0),
            routeHandlers.WipeDataPostHandler));

        // Entity designer — visual editor for creating virtual entity JSON definitions
        host.RegisterRoute("GET /admin/entity-designer", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Entity Designer", "" }, "admin", true, 2, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "🔧 Tools"),
            routeHandlers.EntityDesignerHandler));

        // Gallery — browse and deploy pre-built sample entity schema packages
        host.RegisterRoute("GET /admin/gallery", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Sample Gallery", "" }, "admin", true, 3, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "🔧 Tools"),
            routeHandlers.GalleryHandler));
        host.RegisterRoute("POST /admin/gallery/deploy/{package}", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Sample Gallery", "" }, "admin", false, 0),
            routeHandlers.GalleryDeployPostHandler));

        // Data & Index Sizing — disk and in-memory index footprint per table
        host.RegisterRoute("GET /admin/data-sizes", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Data & Index Sizing", "" }, "admin", true, 4, navGroup: "Admin", navAlignment: NavAlignment.Right, navSubGroup: "🔧 Tools"),
            routeHandlers.DataSizingHandler));
    }

    /// <summary>
    /// Register data management CRUD routes for entity browsing, editing, and export.
    /// Routes are served at /ssr/admin/data/* (legacy SSR UI — VNext at /UI/* is the default).
    /// </summary>
    public static void RegisterDataRoutes(
        this IBareWebHost host,
        IRouteHandlers routeHandlers,
        IPageInfoFactory pageInfoFactory,
        IHtmlTemplate mainTemplate)
    {
        // Entity browsing (SSR legacy — hidden from nav; VNext /UI is the primary entry point)
        host.RegisterRoute("GET /ssr/admin/data", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Data", "" }, "Authenticated", false, 1, navGroup: "Admin", navAlignment: NavAlignment.Right),
            routeHandlers.DataEntitiesHandler));

        host.RegisterRoute("GET /ssr/admin/data/{type}", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Data", "" }, "Authenticated", false, 1, navGroup: "Admin", navAlignment: NavAlignment.Right),
            routeHandlers.DataListHandler));

        // Export
        host.RegisterRoute("GET /ssr/admin/data/{type}/csv", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataListCsvHandler));
        host.RegisterRoute("GET /ssr/admin/data/{type}/html", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataListHtmlHandler));
        host.RegisterRoute("GET /ssr/admin/data/{type}/export", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataListExportHandler));

        // Import
        host.RegisterRoute("GET /ssr/admin/data/{type}/import", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Import CSV", "" }, "Authenticated", false, 1),
            routeHandlers.DataImportHandler));
        host.RegisterRoute("POST /ssr/admin/data/{type}/import", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Import CSV", "" }, "Authenticated", false, 1),
            routeHandlers.DataImportPostHandler));

        // Create
        host.RegisterRoute("GET /ssr/admin/data/{type}/create", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Create", "" }, "Authenticated", false, 1),
            routeHandlers.DataCreateHandler));
        host.RegisterRoute("POST /ssr/admin/data/{type}/create", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Create", "" }, "Authenticated", false, 1),
            routeHandlers.DataCreatePostHandler));

        // View
        host.RegisterRoute("GET /ssr/admin/data/{type}/{id}", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "View", "" }, "Authenticated", false, 1),
            routeHandlers.DataViewHandler));
        host.RegisterRoute("GET /ssr/admin/data/{type}/{id}/rtf", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataViewRtfHandler));
        host.RegisterRoute("GET /ssr/admin/data/{type}/{id}/html", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataViewHtmlHandler));
        host.RegisterRoute("GET /ssr/admin/data/{type}/{id}/export", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataViewExportHandler));

        // Edit
        host.RegisterRoute("GET /ssr/admin/data/{type}/{id}/edit", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Edit", "" }, "Authenticated", false, 1),
            routeHandlers.DataEditHandler));
        host.RegisterRoute("POST /ssr/admin/data/{type}/{id}/edit", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Edit", "" }, "Authenticated", false, 1),
            routeHandlers.DataEditPostHandler));

        // Clone
        host.RegisterRoute("POST /ssr/admin/data/{type}/{id}/clone", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataClonePostHandler));
        host.RegisterRoute("POST /ssr/admin/data/{type}/{id}/clone-edit", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataCloneEditPostHandler));

        // Delete
        host.RegisterRoute("GET /ssr/admin/data/{type}/{id}/delete", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Delete", "" }, "Authenticated", false, 1),
            routeHandlers.DataDeleteHandler));
        host.RegisterRoute("POST /ssr/admin/data/{type}/{id}/delete", new RouteHandlerData(
            pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "Delete", "" }, "Authenticated", false, 1),
            routeHandlers.DataDeletePostHandler));

        // Bulk operations
        host.RegisterRoute("POST /ssr/admin/data/{type}/bulk-delete", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            routeHandlers.DataBulkDeleteHandler));

        host.RegisterRoute("GET /ssr/admin/data/{type}/bulk-export", new RouteHandlerData(
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
                    JsonSerializer.Serialize(result, JsonCompact));
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
        host.RegisterRoute("GET /api/_lookup/{type}/_field/{id}/{fieldName}", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), LookupApiHandlers.GetEntityFieldHandler));
        host.RegisterRoute("GET /api/_lookup/{type}/_aggregate", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), LookupApiHandlers.AggregateEntitiesHandler));
        host.RegisterRoute("POST /api/_lookup/{type}/_batch", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), LookupApiHandlers.BatchGetEntitiesHandler));
        host.RegisterRoute("GET /api/_lookup/{type}/{id}", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), LookupApiHandlers.GetEntityByIdHandler));
        host.RegisterRoute("GET /api/_lookup/{type}", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), LookupApiHandlers.QueryEntitiesHandler));
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
        host.RegisterRoute("GET /api/_binary/_key", new RouteHandlerData(raw, BinaryApiHandlers.KeyHandler));
        host.RegisterRoute("GET /api/_binary/{type}/_schema", new RouteHandlerData(raw, BinaryApiHandlers.SchemaHandler));
        host.RegisterRoute("GET /api/_binary/{type}/_aggregate", new RouteHandlerData(raw, BinaryApiHandlers.AggregateHandler));
        host.RegisterRoute("GET /api/_binary/{type}/_raw", new RouteHandlerData(raw, BinaryApiHandlers.RawListHandler));
        host.RegisterRoute("GET /api/_binary/{type}/_aggregations", new RouteHandlerData(raw, BinaryApiHandlers.AggregationDefsHandler));
        host.RegisterRoute("GET /api/_binary/{type}/_layout", new RouteHandlerData(raw, DeltaApiHandlers.LayoutHandler));
        host.RegisterRoute("GET /api/_binary/{type}/_actions", new RouteHandlerData(raw, ActionApiHandlers.ListActionsHandler));
        host.RegisterRoute("POST /api/_binary/{type}/_action/{actionId}", new RouteHandlerData(raw, ActionApiHandlers.ExecuteActionHandler));
        host.RegisterRoute("GET /api/_metrics", new RouteHandlerData(raw, EngineMetricsHandler));
        host.RegisterRoute("POST /api/graphql", new RouteHandlerData(raw, GraphQLHandler.HandleAsync));
        var adminOnly = pageInfoFactory.RawPage("admin", false);
        host.RegisterRoute("GET /api/_cluster", new RouteHandlerData(adminOnly, ClusterApiHandlers.ClusterStatusHandler));
        host.RegisterRoute("GET /api/_cluster/replicate", new RouteHandlerData(adminOnly, ClusterApiHandlers.ReplicationHandler));
        host.RegisterRoute("POST /api/_cluster/stepdown", new RouteHandlerData(adminOnly, ClusterApiHandlers.StepDownHandler));
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
        var templated = pageInfoFactory.TemplatedPage(mainTemplate, 200, new[] { "title", "message" }, new[] { "", "" }, "Public", false, 1);
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

                var jsonOpts = JsonCompact;

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
                await context.Response.WriteAsync(JsonSerializer.Serialize(result, jsonOpts));
            }));

        // Sankey graph: aggregate document chain counts across all entities with RelatedDocument fields
        host.RegisterRoute("GET /api/_document-chain-graph", new RouteHandlerData(
            pageInfoFactory.RawPage("Authenticated", false),
            async context =>
            {
                var jsonOpts = JsonCompact;

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
                await context.Response.WriteAsync(JsonSerializer.Serialize(
                    new Dictionary<string, object?> { ["nodes"] = nodes, ["links"] = links },
                    jsonOpts));
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
            pageInfoFactory.RawPage("Authenticated", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                var userPermissions = user?.Permissions ?? Array.Empty<string>();

                var entitiesList = new List<object>();
                foreach (var e in DataScaffold.Entities)
                {
                    if (!IsEntityAccessible(e, user, userPermissions)) continue;
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
                await context.Response.WriteAsync(
                    JsonSerializer.Serialize(entities, JsonCompact));
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
                await context.Response.WriteAsync(
                    JsonSerializer.Serialize(result, JsonCompact));
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
        var jsonOptions = JsonCompact;

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
                await context.Response.WriteAsync(JsonSerializer.Serialize(result, jsonOptions));
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
                using var reader = new System.IO.StreamReader(context.HttpRequest.Body);
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

        // GET /api/meta/registered-types — lists C# entity types available for metadata import
        host.RegisterRoute("GET /api/meta/registered-types", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var filteredTypes = new List<DataEntityMetadata>();
                foreach (var m in DataScaffold.Entities)
                {
                    if (m.Type != typeof(DataRecord) && m.Type.GetCustomAttribute<DataEntityAttribute>() != null)
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
                await context.Response.WriteAsync(JsonSerializer.Serialize(types, jsonOptions));
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
                await context.Response.WriteAsync(
                    JsonSerializer.Serialize(
                        new { seeded, count = seeded.Count, messages },
                        jsonOptions));
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

    private static bool IsEntityAccessible(DataEntityMetadata entity, User? user, string[] userPermissions)
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
            var resolved = PermissionResolver.ResolveAsync(user, CancellationToken.None)
                .AsTask().GetAwaiter().GetResult();
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
                ["type"] = f.Lookup != null ? FormFieldType.LookupList.ToString() : f.FieldType.ToString(),
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
                var targetMeta = DataScaffold.GetEntityByType(f.Lookup.TargetType);
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
                var enumOptions = DataScaffold.BuildEnumOptions(f.Property.PropertyType);
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
        host.RegisterRoute("GET /reports", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", true, navGroup: "Admin", navAlignment: NavAlignment.Right, navLabel: "Reports", navSubGroup: "🔧 Tools"),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.Redirect("/login"); return; }
                var userPermissions = new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
                if (!userPermissions.Contains("admin")) { context.Response.StatusCode = 403; await context.Response.WriteAsync("Access denied."); return; }

                var reports = new List<ReportDefinition>(DataStoreProvider.Current.Query<ReportDefinition>(null));
                reports.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.Ordinal));
                var csrfToken = CsrfProtection.EnsureToken(context);
                var safeToken = WebUtility.HtmlEncode(csrfToken);
                var nonce = context.GetCspNonce();
                var safeNonce = WebUtility.HtmlEncode(nonce);

                var sb = new StringBuilder(4096);
                ReportHtmlRenderer.AppendChromeHead(sb, "Reports", safeNonce, safeToken);
                ReportHtmlRenderer.AppendChromeNavbar(sb, host, safeNonce);
                sb.Append("<div class=\"container-fluid py-4 px-4 bm-content\">");
                sb.Append("<div class=\"card shadow-sm bm-page-card\">");
                sb.Append("<div class=\"card-header d-flex align-items-center justify-content-between flex-wrap gap-2\">");
                sb.Append("<h1 class=\"h5 mb-0\"><i class=\"bi bi-bar-chart-fill\"></i> Reports</h1>");
                sb.Append("<a href=\"/report-definitions/create\" class=\"btn btn-sm btn-primary\"><i class=\"bi bi-plus-lg\"></i> New Report</a>");
                sb.Append("</div><div class=\"card-body\">");

                if (reports.Count == 0)
                {
                    sb.Append("<div class=\"text-center py-5 text-muted\">No reports defined yet. Create one via <a href=\"/report-definitions/create\">Report Definitions</a>.</div>");
                }
                else
                {
                    sb.Append("<div class=\"table-responsive\"><table class=\"table table-hover table-bordered align-middle mb-0\">");
                    sb.Append("<thead class=\"table-light\"><tr><th>Name</th><th>Description</th><th>Root Entity</th><th></th></tr></thead><tbody>");
                    foreach (var r in reports)
                    {
                        sb.Append("<tr><td><strong>");
                        sb.Append(WebUtility.HtmlEncode(r.Name));
                        sb.Append("</strong></td><td>");
                        sb.Append(WebUtility.HtmlEncode(r.Description));
                        sb.Append("</td><td><code>");
                        sb.Append(WebUtility.HtmlEncode(r.RootEntity));
                        sb.Append("</code></td><td><a class=\"btn btn-sm btn-primary\" href=\"/reports/");
                        sb.Append(WebUtility.UrlEncode(r.Key.ToString()));
                        sb.Append("\"><i class=\"bi bi-play-fill\"></i> Run</a></td></tr>");
                    }
                    sb.Append("</tbody></table></div>");
                }

                sb.Append("</div></div></div>");
                ReportHtmlRenderer.AppendChromeFooter(sb, safeNonce, host, context.HttpContext);
                context.Response.ContentType = "text/html; charset=utf-8";
                await context.Response.WriteAsync(sb.ToString());
            }));

        // Run a report → HTML
        host.RegisterRoute("GET /reports/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.Redirect("/login"); return; }
                var userPermissions = new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
                if (!userPermissions.Contains("admin")) { context.Response.StatusCode = 403; await context.Response.WriteAsync("Access denied."); return; }

                var id = GetRouteParam(context, "id");
                if (string.IsNullOrWhiteSpace(id))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsync("Missing report id.");
                    return;
                }

                var def = await DataStoreProvider.Current.LoadAsync<ReportDefinition>(uint.Parse(id), context.RequestAborted).ConfigureAwait(false);
                if (def == null)
                {
                    context.Response.StatusCode = 404;
                    await context.Response.WriteAsync("Report not found.");
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
                    id,
                    host,
                    context.GetCspNonce(),
                    CsrfProtection.EnsureToken(context),
                    context.HttpContext);
                await pipeWriter.CompleteAsync();
            }));

        // JSON results via API
        host.RegisterRoute("GET /api/reports/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                var userPermissions = new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
                if (!userPermissions.Contains("admin")) { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Access denied\"}"); return; }

                var id = GetRouteParam(context, "id");
                if (string.IsNullOrWhiteSpace(id))
                {
                    context.Response.StatusCode = 400;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync("{\"error\":\"Missing report id\"}");
                    return;
                }

                var def = await DataStoreProvider.Current.LoadAsync<ReportDefinition>(uint.Parse(id), context.RequestAborted).ConfigureAwait(false);
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
                catch (Exception ex)
                {
                    context.Response.StatusCode = 500;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(new { error = ex.Message }));
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
                var json = new
                {
                    name = def.Name,
                    generatedAt = result.GeneratedAt,
                    totalRows = result.TotalRows,
                    isTruncated = result.IsTruncated,
                    columns = result.ColumnLabels,
                    rows = rowsList.ToArray()
                };
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(json, JsonCompact));
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
                await context.Response.WriteAsync(JsonSerializer.Serialize(values, JsonCompact));
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
        var userPermissions = user?.Permissions ?? Array.Empty<string>();

        // Inline /meta/objects (and optionally /meta/{slug}) to eliminate client-side round-trips
        var metaObjectsScript = TryBuildMetaObjectsScript(user, userPermissions, safeNonce);
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
        sb.Append("<div class=\"container-fluid py-3\" id=\"vnext-content\"><div class=\"text-center py-5\"><div class=\"spinner-border\" role=\"status\"><span class=\"visually-hidden\">Loading...</span></div></div></div>");
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
        if (BareMetalWeb.Rendering.HtmlRenderer.ShouldShowDiagnosticBanner(context.HttpContext, host))
            sb.Append(BareMetalWeb.Rendering.HtmlRenderer.BuildDiagnosticBannerHtml(context.HttpContext, host, sb.Length));
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
    private static string? TryBuildMetaObjectsScript(User? user, string[] userPermissions, string safeNonce)
    {
        try
        {
            var entitiesMetaList = new List<object>();
            foreach (var e in DataScaffold.Entities)
            {
                if (!IsEntityAccessible(e, user, userPermissions)) continue;
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
                var resolved = PermissionResolver.ResolveAsync(user, CancellationToken.None)
                    .AsTask().GetAwaiter().GetResult();
                hasElevated = resolved.HasElevatedPermissions;
            }

            var json = EscapeJsonForInlineScript(JsonSerializer.Serialize(entities, JsonCompact));
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
            var schemaJson = EscapeJsonForInlineScript(JsonSerializer.Serialize(schema, JsonCompact));

            var safeSlug = JsonSerializer.Serialize(slug);
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
        BmwContext context, string slug, string safeNonce, User? user, CancellationToken cancellationToken)
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
                    var userPerms = new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
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

            var initialJson = EscapeJsonForInlineScript(JsonSerializer.Serialize(initialData, JsonCompact));

            // Pre-resolve FK lookup values for all lookup fields visible in the list view.
            // This allows the client to skip the /api/_lookup/{slug}/_batch round-trips.
            var lookupPrefetch = await BuildLookupPrefetchAsync(meta, payload, cancellationToken).ConfigureAwait(false);
            string? prefetchJson = null;
            if (lookupPrefetch != null)
                prefetchJson = EscapeJsonForInlineScript(JsonSerializer.Serialize(lookupPrefetch, JsonCompact));

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
                var entity = await targetMeta.Handlers.LoadAsync(uint.Parse(id!), cancellationToken).ConfigureAwait(false);
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

    internal static void AppendVNextLeftNavItems(StringBuilder sb, List<IMenuOption> options)
    {
        var leftAligned = new List<IMenuOption>();
        foreach (var o in options)
        {
            if (!o.RightAligned && o.ShowOnNavBar)
                leftAligned.Add(o);
        }
        var renderedGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var option in leftAligned)
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
            foreach (var o in leftAligned)
            {
                if (string.Equals(o.Group, option.Group, StringComparison.OrdinalIgnoreCase))
                    groupItems.Add(o);
            }

            sb.Append($"<li class=\"nav-item dropdown\"><a class=\"nav-link dropdown-toggle\" href=\"#\" role=\"button\" data-bs-toggle=\"dropdown\" aria-expanded=\"false\">{WebUtility.HtmlEncode(option.Group)}</a>");
            sb.Append("<ul class=\"dropdown-menu\">");
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
        host.RegisterRoute("GET /dashboards", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", true, navGroup: "Admin", navAlignment: NavAlignment.Right,
                navLabel: "Dashboards", navSubGroup: "🔧 Tools"),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.Redirect("/login"); return; }
                if (!new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase).Contains("admin"))
                { context.Response.StatusCode = 403; await context.Response.WriteAsync("Access denied."); return; }

                var dashboards = new List<DashboardDefinition>(DataStoreProvider.Current.Query<DashboardDefinition>(null));
                dashboards.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.Ordinal));
                var nonce = context.GetCspNonce();
                var safeNonce = WebUtility.HtmlEncode(nonce);
                var safeToken = WebUtility.HtmlEncode(CsrfProtection.EnsureToken(context));

                var sb = new StringBuilder(4096);
                ReportHtmlRenderer.AppendChromeHead(sb, "Dashboards", safeNonce, safeToken);
                ReportHtmlRenderer.AppendChromeNavbar(sb, host, safeNonce);
                sb.Append("<div class=\"container-fluid py-4 px-4 bm-content\">");
                sb.Append("<div class=\"card shadow-sm bm-page-card\">");
                sb.Append("<div class=\"card-header d-flex align-items-center justify-content-between flex-wrap gap-2\">");
                sb.Append("<h1 class=\"h5 mb-0\"><i class=\"bi bi-speedometer2\"></i> Dashboards</h1>");
                sb.Append("<a href=\"/dashboard-definitions/create\" class=\"btn btn-sm btn-primary\"><i class=\"bi bi-plus-lg\"></i> New Dashboard</a>");
                sb.Append("</div><div class=\"card-body\">");

                if (dashboards.Count == 0)
                {
                    sb.Append("<div class=\"text-center py-5 text-muted\">No dashboards defined yet. Create one via <a href=\"/dashboard-definitions/create\">Dashboard Definitions</a>.</div>");
                }
                else
                {
                    sb.Append("<div class=\"row g-3\">");
                    foreach (var d in dashboards)
                    {
                        var tiles = d.Tiles;
                        sb.Append("<div class=\"col-sm-6 col-md-4 col-lg-3\">");
                        sb.Append("<div class=\"card h-100\">");
                        sb.Append("<div class=\"card-body\">");
                        sb.Append("<h5 class=\"card-title\"><i class=\"bi bi-speedometer2 me-2\"></i>");
                        sb.Append(WebUtility.HtmlEncode(d.Name));
                        sb.Append("</h5>");
                        if (!string.IsNullOrWhiteSpace(d.Description))
                        {
                            sb.Append("<p class=\"card-text text-muted small\">");
                            sb.Append(WebUtility.HtmlEncode(d.Description));
                            sb.Append("</p>");
                        }
                        sb.Append("<p class=\"card-text\"><small class=\"text-muted\">");
                        sb.Append(tiles.Count);
                        sb.Append(" KPI tile");
                        if (tiles.Count != 1) sb.Append('s');
                        sb.Append("</small></p>");
                        sb.Append("</div><div class=\"card-footer\">");
                        sb.Append("<a href=\"/dashboards/");
                        sb.Append(WebUtility.UrlEncode(d.Key.ToString()));
                        sb.Append("\" class=\"btn btn-sm btn-primary\"><i class=\"bi bi-eye\"></i> View</a>");
                        sb.Append("</div></div></div>");
                    }
                    sb.Append("</div>");
                }

                sb.Append("</div></div></div>");
                ReportHtmlRenderer.AppendChromeFooter(sb, safeNonce, host, context.HttpContext);
                context.Response.ContentType = "text/html; charset=utf-8";
                await context.Response.WriteAsync(sb.ToString());
            }));

        // ── GET /dashboards/{id} — HTML dashboard render ─────────────────────
        host.RegisterRoute("GET /dashboards/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.Redirect("/login"); return; }
                if (!new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase).Contains("admin"))
                { context.Response.StatusCode = 403; await context.Response.WriteAsync("Access denied."); return; }

                var id = GetRouteParam(context, "id");
                if (string.IsNullOrWhiteSpace(id) || !uint.TryParse(id, out var dashId))
                { context.Response.StatusCode = 400; await context.Response.WriteAsync("Invalid dashboard id."); return; }

                var def = await DataStoreProvider.Current.LoadAsync<DashboardDefinition>(dashId, context.RequestAborted).ConfigureAwait(false);
                if (def == null)
                { context.Response.StatusCode = 404; await context.Response.WriteAsync("Dashboard not found."); return; }

                var nonce = context.GetCspNonce();
                var safeNonce = WebUtility.HtmlEncode(nonce);
                var safeToken = WebUtility.HtmlEncode(CsrfProtection.EnsureToken(context));

                var pipeWriter = System.IO.Pipelines.PipeWriter.Create(context.Response.Body);
                context.Response.ContentType = "text/html; charset=utf-8";
                await DashboardHtmlRenderer.RenderAsync(pipeWriter, def, host, safeNonce, safeToken, context.HttpContext, context.RequestAborted);
                await pipeWriter.CompleteAsync();
            }));

        // ── GET /api/dashboards — JSON list ──────────────────────────────────
        host.RegisterRoute("GET /api/dashboards", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                if (!new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase).Contains("admin"))
                { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Access denied\"}"); return; }

                var dashboards = new List<DashboardDefinition>(DataStoreProvider.Current.Query<DashboardDefinition>(null));
                dashboards.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.Ordinal));
                var list = dashboards.Select(d => new
                {
                    id = d.Key,
                    name = d.Name,
                    description = d.Description,
                    tileCount = d.Tiles.Count
                });
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(list, JsonCompact));
            }));

        // ── GET /api/dashboards/{id} — JSON with resolved KPI values ─────────
        host.RegisterRoute("GET /api/dashboards/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                if (!new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase).Contains("admin"))
                { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Access denied\"}"); return; }

                var id = GetRouteParam(context, "id");
                if (string.IsNullOrWhiteSpace(id) || !uint.TryParse(id, out var dashId))
                { context.Response.StatusCode = 400; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Invalid dashboard id\"}"); return; }

                var def = await DataStoreProvider.Current.LoadAsync<DashboardDefinition>(dashId, context.RequestAborted).ConfigureAwait(false);
                if (def == null)
                { context.Response.StatusCode = 404; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Dashboard not found\"}"); return; }

                var resolvedTiles = await DashboardHtmlRenderer.ResolveTilesAsync(def.Tiles, context.RequestAborted);
                var tileProjections = resolvedTiles.Select(r => new
                {
                    title = r.Tile.Title,
                    icon = r.Tile.Icon,
                    color = r.Tile.Color,
                    entitySlug = r.Tile.EntitySlug,
                    aggregateFunction = r.Tile.AggregateFunction,
                    displayValue = r.DisplayValue,
                    rawValue = r.RawValue?.ToString(),
                    sparkline = r.Sparkline?.Select(b => new { label = b.Label, value = b.Value }).ToArray()
                }).ToArray();
                var json = new
                {
                    id = def.Key,
                    name = def.Name,
                    description = def.Description,
                    tiles = tileProjections
                };
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(json, JsonIndented));
            }));
    }

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
        host.RegisterRoute("GET /views", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", true, navGroup: "Admin", navAlignment: NavAlignment.Right,
                navLabel: "Views", navSubGroup: "🔧 Tools"),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.Redirect("/login"); return; }
                var userPermissions = new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
                if (!userPermissions.Contains("admin")) { context.Response.StatusCode = 403; await context.Response.WriteAsync("Access denied."); return; }

                var views = new List<ViewDefinition>(DataStoreProvider.Current.Query<ViewDefinition>(null));
                views.Sort((a, b) => string.Compare(a.ViewName, b.ViewName, StringComparison.Ordinal));
                var csrfToken = CsrfProtection.EnsureToken(context);
                var safeToken = WebUtility.HtmlEncode(csrfToken);
                var nonce = context.GetCspNonce();
                var safeNonce = WebUtility.HtmlEncode(nonce);

                var sb = new StringBuilder(4096);
                ReportHtmlRenderer.AppendChromeHead(sb, "Views", safeNonce, safeToken);
                ReportHtmlRenderer.AppendChromeNavbar(sb, host, safeNonce);
                sb.Append("<div class=\"container-fluid py-4 px-4 bm-content\">");
                sb.Append("<div class=\"card shadow-sm bm-page-card\">");
                sb.Append("<div class=\"card-header d-flex align-items-center justify-content-between flex-wrap gap-2\">");
                sb.Append("<h1 class=\"h5 mb-0\"><i class=\"bi bi-table\"></i> Views</h1>");
                sb.Append("<a href=\"/view-definitions/create\" class=\"btn btn-sm btn-primary\"><i class=\"bi bi-plus-lg\"></i> New View</a>");
                sb.Append("</div><div class=\"card-body\">");

                if (views.Count == 0)
                {
                    sb.Append("<div class=\"text-center py-5 text-muted\">No views defined yet. Create one via <a href=\"/view-definitions/create\">View Definitions</a>.</div>");
                }
                else
                {
                    sb.Append("<div class=\"table-responsive\"><table class=\"table table-hover table-bordered align-middle mb-0\">");
                    sb.Append("<thead class=\"table-light\"><tr><th>Name</th><th>Root Entity</th><th>Materialised</th><th></th></tr></thead><tbody>");
                    foreach (var v in views)
                    {
                        sb.Append("<tr><td><strong>");
                        sb.Append(WebUtility.HtmlEncode(v.ViewName));
                        sb.Append("</strong></td><td><code>");
                        sb.Append(WebUtility.HtmlEncode(v.RootEntity));
                        sb.Append("</code></td><td>");
                        sb.Append(v.Materialised ? "<span class=\"badge bg-success\">Yes</span>" : "<span class=\"badge bg-secondary\">No</span>");
                        sb.Append("</td><td><a class=\"btn btn-sm btn-primary\" href=\"/views/");
                        sb.Append(WebUtility.UrlEncode(v.Key.ToString()));
                        sb.Append("\"><i class=\"bi bi-play-fill\"></i> Run</a></td></tr>");
                    }
                    sb.Append("</tbody></table></div>");
                }

                sb.Append("</div></div></div>");
                ReportHtmlRenderer.AppendChromeFooter(sb, safeNonce, host, context.HttpContext);
                context.Response.ContentType = "text/html; charset=utf-8";
                await context.Response.WriteAsync(sb.ToString());
            }));

        // ── GET /views/{id} ── execute view → HTML ────────────────────────────
        host.RegisterRoute("GET /views/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.Redirect("/login"); return; }
                var userPermissions = new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
                if (!userPermissions.Contains("admin")) { context.Response.StatusCode = 403; await context.Response.WriteAsync("Access denied."); return; }

                var id = GetRouteParam(context, "id");
                if (string.IsNullOrWhiteSpace(id) || !uint.TryParse(id, out var viewKey))
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsync("Missing or invalid view id.");
                    return;
                }

                var def = await DataStoreProvider.Current.LoadAsync<ViewDefinition>(viewKey, context.RequestAborted).ConfigureAwait(false);
                if (def == null)
                {
                    context.Response.StatusCode = 404;
                    await context.Response.WriteAsync("View not found.");
                    return;
                }

                ReportResult result;
                try
                {
                    result = await _engine.ExecuteAsync(def, context.RequestAborted).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    context.Response.StatusCode = 500;
                    context.Response.ContentType = "text/plain";
                    await context.Response.WriteAsync($"Error executing view: {WebUtility.HtmlEncode(ex.Message)}");
                    return;
                }

                context.Response.ContentType = "text/html; charset=utf-8";
                var pipeWriter = System.IO.Pipelines.PipeWriter.Create(context.Response.Body);
                await ReportHtmlRenderer.RenderAsync(
                    pipeWriter,
                    result,
                    def.ViewName,
                    $"Root: {def.RootEntity}",
                    null,
                    null,
                    id,
                    host,
                    context.GetCspNonce(),
                    CsrfProtection.EnsureToken(context),
                    context.HttpContext);
                await pipeWriter.CompleteAsync();
            }));

        // ── GET /api/views ── list view definitions as JSON ───────────────────
        host.RegisterRoute("GET /api/views", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                var userPermissions = new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
                if (!userPermissions.Contains("admin")) { context.Response.StatusCode = 403; context.Response.ContentType = "application/json"; await context.Response.WriteAsync("{\"error\":\"Access denied\"}"); return; }

                var views = new List<ViewDefinition>(DataStoreProvider.Current.Query<ViewDefinition>(null));
                views.Sort((a, b) => string.Compare(a.ViewName, b.ViewName, StringComparison.Ordinal));

                var items = new object[views.Count];
                for (int i = 0; i < views.Count; i++)
                {
                    var v = views[i];
                    items[i] = new
                    {
                        id          = v.Key,
                        viewName    = v.ViewName,
                        rootEntity  = v.RootEntity,
                        limit       = v.Limit,
                        offset      = v.Offset,
                        materialised = v.Materialised,
                    };
                }

                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(items, JsonIndented));
            }));

        // ── GET /api/views/{id} ── execute view → JSON ────────────────────────
        host.RegisterRoute("GET /api/views/{id}", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                var userPermissions = new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
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
                catch (Exception ex)
                {
                    context.Response.StatusCode = 500;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(new { error = ex.Message }));
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

                var json = new
                {
                    viewName     = def.ViewName,
                    rootEntity   = def.RootEntity,
                    generatedAt  = result.GeneratedAt,
                    totalRows    = result.TotalRows,
                    isTruncated  = result.IsTruncated,
                    columns      = result.ColumnLabels,
                    rows         = rowsList.ToArray(),
                };
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(json, JsonIndented));
            }));

        // ── POST /api/views/execute ── ad-hoc view execution ──────────────────
        host.RegisterRoute("POST /api/views/execute", new RouteHandlerData(
            pageInfoFactory.RawPage("admin", false),
            async context =>
            {
                var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
                if (user == null) { context.Response.StatusCode = 401; return; }
                var userPermissions = new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
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
                    def = System.Text.Json.JsonSerializer.Deserialize<ViewDefinition>(bodyDoc.RootElement.GetRawText());
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
                catch (Exception ex)
                {
                    context.Response.StatusCode = 500;
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(new { error = ex.Message }));
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

                var json = new
                {
                    viewName     = def.ViewName,
                    rootEntity   = def.RootEntity,
                    generatedAt  = result.GeneratedAt,
                    totalRows    = result.TotalRows,
                    isTruncated  = result.IsTruncated,
                    columns      = result.ColumnLabels,
                    rows         = rowsList.ToArray(),
                };
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(json, JsonIndented));
            }));
    }
}
