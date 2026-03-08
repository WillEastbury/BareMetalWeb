using System.Collections.Concurrent;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Manages per-tenant <see cref="TenantContext"/> instances and resolves the correct
/// context for an incoming HTTP request by inspecting the <c>Host</c> header.
///
/// Instances are created once per unique tenant at startup (or lazily on first access)
/// and reused for the lifetime of the process — each tenant gets one elected WAL writer,
/// one isolated data root, and one isolated log folder.
///
/// <para>
/// Usage:
/// <list type="number">
///   <item>Populate and call <see cref="Initialize"/> once at startup.</item>
///   <item>Call <see cref="ResolveForRequest"/> at the top of each request to set the
///         per-request <see cref="DataStoreProvider.CurrentTenant"/>.</item>
///   <item>Dispose the returned scope at the end of the request to clear the tenant.</item>
/// </list>
/// </para>
/// </summary>
public sealed class TenantRegistry
{
    private readonly MultitenancyOptions _options;
    private readonly string _contentRoot;

    // hostname (lower-case) → TenantContext
    private readonly ConcurrentDictionary<string, TenantContext> _byHost =
        new(StringComparer.OrdinalIgnoreCase);

    // tenantId → TenantContext
    private readonly ConcurrentDictionary<string, TenantContext> _byId =
        new(StringComparer.OrdinalIgnoreCase);

    // The system/default tenant — created from the "legacy" single-tenant setup
    private TenantContext? _systemTenant;

    public TenantRegistry(MultitenancyOptions options, string contentRoot)
    {
        _options     = options;
        _contentRoot = contentRoot;
    }

    /// <summary>
    /// Whether multitenancy is enabled.
    /// When false, <see cref="ResolveForRequest"/> returns <c>null</c> and the
    /// global <see cref="DataStoreProvider.SystemStore"/> is used unchanged.
    /// </summary>
    public bool IsEnabled => _options.Enabled;

    /// <summary>
    /// Registers the system/default tenant that was created by the standard single-tenant
    /// startup path. This tenant is used as a fallback when no Host header matches a
    /// configured tenant, and also acts as the source of master users/settings.
    /// </summary>
    public void RegisterSystemTenant(TenantContext ctx)
    {
        _systemTenant = ctx;
        _byId[_options.DefaultTenantId] = ctx;
    }

    /// <summary>
    /// Builds and registers <see cref="TenantContext"/> instances for every entry in
    /// <see cref="MultitenancyOptions.Tenants"/>, creating isolated WAL data stores
    /// and wiring up the per-tenant host-name lookup.
    ///
    /// Call once at startup, after <see cref="RegisterSystemTenant"/>.
    /// </summary>
    public void Initialize(
        Func<string, string, (IDataObjectStore Store, IDataProvider Provider)> storeFactory,
        IBufferedLogger systemLogger)
    {
        foreach (var tenantOptions in _options.Tenants)
        {
            if (string.IsNullOrWhiteSpace(tenantOptions.Host))
                continue;

            var tenantId = ResolveTenantId(tenantOptions);
            if (_byId.ContainsKey(tenantId))
            {
                systemLogger.LogInfo($"[TenantRegistry] Duplicate tenant id '{tenantId}' — skipping.");
                continue;
            }

            var dataRoot   = ResolveAbsolutePath(tenantOptions.DataRoot,   $"Data/{tenantId}");
            var logFolder  = ResolveAbsolutePath(tenantOptions.LogFolder,  $"Logs/{tenantId}");
            Directory.CreateDirectory(dataRoot);
            Directory.CreateDirectory(logFolder);

            var (store, provider) = storeFactory(tenantId, dataRoot);

            var ctx = new TenantContext(tenantId, dataRoot, logFolder, store, provider)
            {
                DisplayName   = tenantOptions.DisplayName,
                LogoUrl       = tenantOptions.LogoUrl,
                PrimaryColor  = tenantOptions.PrimaryColor,
                MaxRecords    = tenantOptions.MaxRecords,
                MaxStorageBytes = tenantOptions.MaxStorageBytes,
            };
            _byId[tenantId] = ctx;

            // Register all host aliases (comma-separated list in single entry supported)
            foreach (var host in tenantOptions.Host.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                _byHost[host.ToLowerInvariant()] = ctx;
                systemLogger.LogInfo($"[TenantRegistry] Tenant '{tenantId}' registered for host '{host}' → data={dataRoot}, logs={logFolder}");
            }
        }
    }

    /// <summary>
    /// Provisions a new tenant at runtime. Creates the data store and registers the host mapping.
    /// Returns the new TenantContext, or null if the tenantId already exists.
    /// </summary>
    public TenantContext? Provision(
        TenantOptions tenantOptions,
        Func<string, string, (IDataObjectStore Store, IDataProvider Provider)> storeFactory,
        IBufferedLogger logger)
    {
        var tenantId = ResolveTenantId(tenantOptions);
        if (_byId.ContainsKey(tenantId))
            return null;

        var dataRoot  = ResolveAbsolutePath(tenantOptions.DataRoot,  $"Data/{tenantId}");
        var logFolder = ResolveAbsolutePath(tenantOptions.LogFolder, $"Logs/{tenantId}");
        Directory.CreateDirectory(dataRoot);
        Directory.CreateDirectory(logFolder);

        var (store, provider) = storeFactory(tenantId, dataRoot);
        var ctx = new TenantContext(tenantId, dataRoot, logFolder, store, provider)
        {
            DisplayName     = tenantOptions.DisplayName,
            LogoUrl         = tenantOptions.LogoUrl,
            PrimaryColor    = tenantOptions.PrimaryColor,
            MaxRecords      = tenantOptions.MaxRecords,
            MaxStorageBytes = tenantOptions.MaxStorageBytes,
        };

        if (!_byId.TryAdd(tenantId, ctx))
            return null;

        foreach (var host in tenantOptions.Host.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            _byHost[host.ToLowerInvariant()] = ctx;
            logger.LogInfo($"[TenantRegistry] Provisioned tenant '{tenantId}' for host '{host}'");
        }

        return ctx;
    }

    /// <summary>Looks up a tenant by its ID.</summary>
    public TenantContext? GetById(string tenantId) =>
        _byId.TryGetValue(tenantId, out var ctx) ? ctx : null;

    /// <summary>
    /// Resolves the <see cref="TenantContext"/> for the given HTTP request by inspecting
    /// the <c>Host</c> header, then sets it as the current per-request tenant via
    /// <see cref="DataStoreProvider.SetCurrentTenant"/>.
    ///
    /// Returns an <see cref="IDisposable"/> scope that clears the tenant when disposed.
    /// Returns <c>null</c> when multitenancy is disabled.
    /// </summary>
    public IDisposable? ResolveForRequest(BmwContext context)
    {
        if (!_options.Enabled)
            return null;

        var hostHeader = context.RequestHeaders.Host.ToString();
        var host = hostHeader.Contains(':') ? hostHeader[..hostHeader.IndexOf(':')] : hostHeader;
        if (_byHost.TryGetValue(host, out var tenant))
            return DataStoreProvider.SetCurrentTenant(tenant);

        // Fall back to system tenant
        if (_systemTenant != null)
            return DataStoreProvider.SetCurrentTenant(_systemTenant);

        return null;
    }

    /// <summary>Gets a stable snapshot of all registered tenant contexts.</summary>
    public IReadOnlyCollection<TenantContext> AllTenants
    {
        get
        {
            var list = new List<TenantContext>(_byId.Count);
            foreach (var kvp in _byId)
                list.Add(kvp.Value);
            return list.ToArray();
        }
    }

    /// <summary>Gets the system/default tenant context.</summary>
    public TenantContext? SystemTenant => _systemTenant;

    /// <summary>Resolves the tenant ID from the options, deriving from Host if not explicitly set.</summary>
    private static string ResolveTenantId(TenantOptions opts)
    {
        if (!string.IsNullOrWhiteSpace(opts.TenantId))
            return opts.TenantId;

        // Sanitize host to produce a file-system-safe id (take first host if comma-separated)
        var host = opts.Host.Split(',')[0].Trim();
        return SanitizeForFileSystem(host);
    }

    private string ResolveAbsolutePath(string configured, string fallback)
    {
        var path = string.IsNullOrWhiteSpace(configured) ? fallback : configured;
        return Path.IsPathRooted(path) ? path : Path.Combine(_contentRoot, path);
    }

    private static string SanitizeForFileSystem(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var chars = value.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
            if (Array.IndexOf(invalid, chars[i]) >= 0 || chars[i] == ':')
                chars[i] = '_';
        return new string(chars);
    }
}
