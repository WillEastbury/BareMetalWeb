using BareMetalWeb.Core;
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
    public static async ValueTask ListTenantsHandler(BmwContext context)
    {
        if (!IsSystemAdmin(context))
        {
            context.Response.StatusCode = 403;
            return;
        }

        var tenants = new List<Dictionary<string, object?>>();
        foreach (var t in _registry!.AllTenants)
        {
            tenants.Add(new Dictionary<string, object?>
            {
                ["tenantId"] = t.TenantId,
                ["dataRoot"] = t.DataRoot,
                ["logFolder"] = t.LogFolder,
                ["displayName"] = t.DisplayName,
                ["logoUrl"] = t.LogoUrl,
                ["primaryColor"] = t.PrimaryColor,
                ["maxRecords"] = t.MaxRecords,
                ["maxStorageBytes"] = t.MaxStorageBytes,
            });
        }

        await JsonWriterHelper.WriteResponseAsync(context.Response, tenants);
    }

    /// <summary>GET /api/tenants/{id} — gets a single tenant by ID.</summary>
    public static async ValueTask GetTenantHandler(BmwContext context)
    {
        if (!IsSystemAdmin(context))
        {
            context.Response.StatusCode = 403;
            return;
        }

        var tenantId = context.HttpRequest.RouteValues["id"]?.ToString();
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

        await JsonWriterHelper.WriteResponseAsync(context.Response, new Dictionary<string, object?>
        {
            ["tenantId"] = tenant.TenantId,
            ["dataRoot"] = tenant.DataRoot,
            ["logFolder"] = tenant.LogFolder,
            ["displayName"] = tenant.DisplayName,
            ["logoUrl"] = tenant.LogoUrl,
            ["primaryColor"] = tenant.PrimaryColor,
            ["maxRecords"] = tenant.MaxRecords,
            ["maxStorageBytes"] = tenant.MaxStorageBytes,
        });
    }

    /// <summary>POST /api/tenants — provisions a new tenant at runtime.</summary>
    public static async ValueTask ProvisionTenantHandler(BmwContext context)
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
            using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body);
            var root = doc.RootElement;
            opts = new TenantOptions();
            if (root.TryGetProperty("host", out var h)) opts.Host = h.GetString() ?? "";
            if (root.TryGetProperty("tenantId", out var ti)) opts.TenantId = ti.GetString();
            if (root.TryGetProperty("dataRoot", out var dr)) opts.DataRoot = dr.GetString() ?? "";
            if (root.TryGetProperty("logFolder", out var lf)) opts.LogFolder = lf.GetString() ?? "";
            if (root.TryGetProperty("displayName", out var dn2)) opts.DisplayName = dn2.GetString();
            if (root.TryGetProperty("logoUrl", out var lu2)) opts.LogoUrl = lu2.GetString();
            if (root.TryGetProperty("primaryColor", out var pc2)) opts.PrimaryColor = pc2.GetString();
            if (root.TryGetProperty("maxRecords", out var mr2)) opts.MaxRecords = mr2.GetInt64();
            if (root.TryGetProperty("maxStorageBytes", out var ms2)) opts.MaxStorageBytes = ms2.GetInt64();
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
        await JsonWriterHelper.WriteResponseAsync(context.Response, new Dictionary<string, object?>
        {
            ["tenantId"] = tenant.TenantId,
            ["dataRoot"] = tenant.DataRoot,
            ["displayName"] = tenant.DisplayName,
        });
    }

    /// <summary>PUT /api/tenants/{id}/branding — updates display name, logo, primary color.</summary>
    public static async ValueTask UpdateBrandingHandler(BmwContext context)
    {
        if (!IsSystemAdmin(context))
        {
            context.Response.StatusCode = 403;
            return;
        }

        var tenantId = context.HttpRequest.RouteValues["id"]?.ToString();
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

        using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body);
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
    public static async ValueTask UpdateQuotasHandler(BmwContext context)
    {
        if (!IsSystemAdmin(context))
        {
            context.Response.StatusCode = 403;
            return;
        }

        var tenantId = context.HttpRequest.RouteValues["id"]?.ToString();
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

        using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body);
        var root = doc.RootElement;

        if (root.TryGetProperty("maxRecords", out var mr))
            tenant.MaxRecords = mr.GetInt64();
        if (root.TryGetProperty("maxStorageBytes", out var ms))
            tenant.MaxStorageBytes = ms.GetInt64();

        context.Response.StatusCode = 204;
    }

    /// <summary>GET /api/tenant/branding — returns branding for the current request's tenant.</summary>
    public static async ValueTask GetCurrentBrandingHandler(BmwContext context)
    {
        var tenant = DataStoreProvider.CurrentTenant;

        await JsonWriterHelper.WriteResponseAsync(context.Response, new Dictionary<string, object?>
        {
            ["tenantId"] = tenant?.TenantId,
            ["displayName"] = tenant?.DisplayName,
            ["logoUrl"] = tenant?.LogoUrl,
            ["primaryColor"] = tenant?.PrimaryColor,
            ["multitenancy"] = _registry?.IsEnabled ?? false,
        });
    }

    private static bool IsSystemAdmin(BmwContext context)
    {
        if (context.HttpContext.User?.Identity?.IsAuthenticated != true)
            return false;

        if (_registry == null || !_registry.IsEnabled)
            return true;

        var current = DataStoreProvider.CurrentTenant;
        return current != null && current == _registry.SystemTenant;
    }
}
