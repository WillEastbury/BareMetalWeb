using System.Text.Json;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Admin API endpoints for tenant management: list, get, provision, and update branding/quotas.
/// All endpoints require the user to be authenticated and on the system (master) tenant.
/// </summary>
public static class TenantApiHandlers
{
    private static TenantRegistry? _registry;
    private static Func<string, string, (IDataObjectStore, IDataProvider)>? _storeFactory;
    private static IBufferedLogger? _logger;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
    };

    /// <summary>Initialize with references needed by all handlers.</summary>
    public static void Initialize(
        TenantRegistry registry,
        Func<string, string, (IDataObjectStore, IDataProvider)>? storeFactory = null,
        IBufferedLogger? logger = null)
    {
        _registry = registry;
        _storeFactory = storeFactory;
        _logger = logger;
    }

    /// <summary>GET /api/tenants — lists all registered tenants.</summary>
    public static async ValueTask ListTenantsHandler(HttpContext context)
    {
        if (!IsSystemAdmin(context))
        {
            context.Response.StatusCode = 403;
            return;
        }

        var tenants = new List<object>();
        foreach (var t in _registry!.AllTenants)
        {
            tenants.Add(new
            {
                t.TenantId,
                t.DataRoot,
                t.LogFolder,
                t.DisplayName,
                t.LogoUrl,
                t.PrimaryColor,
                t.MaxRecords,
                t.MaxStorageBytes,
            });
        }

        context.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(context.Response.Body, tenants, JsonOpts);
    }

    /// <summary>GET /api/tenants/{id} — gets a single tenant by ID.</summary>
    public static async ValueTask GetTenantHandler(HttpContext context)
    {
        if (!IsSystemAdmin(context))
        {
            context.Response.StatusCode = 403;
            return;
        }

        var tenantId = context.Request.RouteValues["id"]?.ToString();
        if (string.IsNullOrEmpty(tenantId))
        {
            context.Response.StatusCode = 400;
            return;
        }

        var tenant = _registry!.GetById(tenantId);
        if (tenant == null)
        {
            context.Response.StatusCode = 404;
            return;
        }

        context.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(context.Response.Body, new
        {
            tenant.TenantId,
            tenant.DataRoot,
            tenant.LogFolder,
            tenant.DisplayName,
            tenant.LogoUrl,
            tenant.PrimaryColor,
            tenant.MaxRecords,
            tenant.MaxStorageBytes,
        }, JsonOpts);
    }

    /// <summary>POST /api/tenants — provisions a new tenant at runtime.</summary>
    public static async ValueTask ProvisionTenantHandler(HttpContext context)
    {
        if (!IsSystemAdmin(context))
        {
            context.Response.StatusCode = 403;
            return;
        }

        if (_storeFactory == null || _logger == null)
        {
            context.Response.StatusCode = 501;
            await context.Response.WriteAsync("{\"error\":\"provisioning not configured\"}");
            return;
        }

        TenantOptions? opts;
        try
        {
            opts = await JsonSerializer.DeserializeAsync<TenantOptions>(context.Request.Body, JsonOpts);
        }
        catch
        {
            context.Response.StatusCode = 400;
            return;
        }

        if (opts == null || string.IsNullOrWhiteSpace(opts.Host))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("{\"error\":\"host is required\"}");
            return;
        }

        var tenant = _registry!.Provision(opts, _storeFactory, _logger);
        if (tenant == null)
        {
            context.Response.StatusCode = 409;
            await context.Response.WriteAsync("{\"error\":\"tenant already exists\"}");
            return;
        }

        context.Response.StatusCode = 201;
        context.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(context.Response.Body, new
        {
            tenant.TenantId,
            tenant.DataRoot,
            tenant.DisplayName,
        }, JsonOpts);
    }

    /// <summary>PUT /api/tenants/{id}/branding — updates display name, logo, primary color.</summary>
    public static async ValueTask UpdateBrandingHandler(HttpContext context)
    {
        if (!IsSystemAdmin(context))
        {
            context.Response.StatusCode = 403;
            return;
        }

        var tenantId = context.Request.RouteValues["id"]?.ToString();
        if (string.IsNullOrEmpty(tenantId))
        {
            context.Response.StatusCode = 400;
            return;
        }

        var tenant = _registry!.GetById(tenantId);
        if (tenant == null)
        {
            context.Response.StatusCode = 404;
            return;
        }

        using var doc = await JsonDocument.ParseAsync(context.Request.Body);
        var root = doc.RootElement;

        if (root.TryGetProperty("displayName", out var dn))
            tenant.DisplayName = dn.GetString();
        if (root.TryGetProperty("logoUrl", out var lu))
            tenant.LogoUrl = lu.GetString();
        if (root.TryGetProperty("primaryColor", out var pc))
            tenant.PrimaryColor = pc.GetString();

        context.Response.StatusCode = 204;
    }

    /// <summary>PUT /api/tenants/{id}/quotas — updates record and storage limits.</summary>
    public static async ValueTask UpdateQuotasHandler(HttpContext context)
    {
        if (!IsSystemAdmin(context))
        {
            context.Response.StatusCode = 403;
            return;
        }

        var tenantId = context.Request.RouteValues["id"]?.ToString();
        if (string.IsNullOrEmpty(tenantId))
        {
            context.Response.StatusCode = 400;
            return;
        }

        var tenant = _registry!.GetById(tenantId);
        if (tenant == null)
        {
            context.Response.StatusCode = 404;
            return;
        }

        using var doc = await JsonDocument.ParseAsync(context.Request.Body);
        var root = doc.RootElement;

        if (root.TryGetProperty("maxRecords", out var mr))
            tenant.MaxRecords = mr.GetInt64();
        if (root.TryGetProperty("maxStorageBytes", out var ms))
            tenant.MaxStorageBytes = ms.GetInt64();

        context.Response.StatusCode = 204;
    }

    /// <summary>GET /api/tenant/branding — returns branding for the current request's tenant.</summary>
    public static async ValueTask GetCurrentBrandingHandler(HttpContext context)
    {
        var tenant = DataStoreProvider.CurrentTenant;

        context.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(context.Response.Body, new
        {
            tenantId     = tenant?.TenantId,
            displayName  = tenant?.DisplayName,
            logoUrl      = tenant?.LogoUrl,
            primaryColor = tenant?.PrimaryColor,
            multitenancy = _registry?.IsEnabled ?? false,
        }, JsonOpts);
    }

    private static bool IsSystemAdmin(HttpContext context)
    {
        if (context.User?.Identity?.IsAuthenticated != true)
            return false;

        if (_registry == null || !_registry.IsEnabled)
            return true;

        var current = DataStoreProvider.CurrentTenant;
        return current != null && current == _registry.SystemTenant;
    }
}
