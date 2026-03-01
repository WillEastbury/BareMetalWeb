using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

public static class DataStoreProvider
{
    // ── System-wide (single-tenant / fallback) store ─────────────────────────

    private static IDataObjectStore _systemStore = new DataObjectStore();

    /// <summary>
    /// The system-wide data store used when multitenancy is disabled, or as
    /// the fallback when no per-request tenant has been set.
    /// </summary>
    public static IDataObjectStore SystemStore
    {
        get => _systemStore;
        set => _systemStore = value;
    }

    /// <summary>
    /// The primary system-wide data provider (WAL).
    /// </summary>
    public static IDataProvider? PrimaryProvider { get; set; }

    // ── Per-request tenant context (AsyncLocal) ───────────────────────────────

    /// <summary>
    /// Holds the currently active <see cref="TenantContext"/> for the executing
    /// async call chain. Set at the start of each request via
    /// <see cref="SetCurrentTenant"/> and cleared when the request completes.
    /// </summary>
    private static readonly AsyncLocal<TenantContext?> _currentTenant = new();

    /// <summary>
    /// Gets or sets the currently active data store.
    /// When multitenancy is enabled and a tenant has been resolved for the
    /// current request, returns that tenant's store.
    /// Falls back to <see cref="SystemStore"/> when no tenant is active.
    /// </summary>
    public static IDataObjectStore Current
    {
        get => _currentTenant.Value?.Store ?? _systemStore;
        // Setter kept for backward compatibility — assigns to the system store.
        set => _systemStore = value;
    }

    /// <summary>
    /// Gets the currently active tenant context, or <c>null</c> when
    /// multitenancy is disabled / not yet resolved for this request.
    /// </summary>
    public static TenantContext? CurrentTenant => _currentTenant.Value;

    /// <summary>
    /// Sets the active tenant for the current async call chain (request scope).
    /// Returns an <see cref="IDisposable"/> that clears the tenant when disposed.
    /// </summary>
    public static IDisposable SetCurrentTenant(TenantContext tenant)
    {
        _currentTenant.Value = tenant;
        return new TenantScope();
    }

    private sealed class TenantScope : IDisposable
    {
        public void Dispose() => _currentTenant.Value = null;
    }
}
