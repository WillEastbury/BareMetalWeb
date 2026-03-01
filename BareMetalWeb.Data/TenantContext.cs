using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// Holds all per-tenant state: the isolated data store, primary WAL provider,
/// root paths, and the tenant identifier.
///
/// One <see cref="TenantContext"/> is created per unique tenant at startup (or on
/// first request for that tenant) and then reused for the lifetime of the process.
/// The per-request active context is set via <see cref="DataStoreProvider.SetCurrentTenant"/>.
/// </summary>
public sealed class TenantContext
{
    /// <summary>
    /// Stable identifier for this tenant (e.g. "_system", "tenant1").
    /// </summary>
    public string TenantId { get; }

    /// <summary>
    /// Root directory for all data files belonging to this tenant.
    /// </summary>
    public string DataRoot { get; }

    /// <summary>
    /// Root directory for log files belonging to this tenant.
    /// </summary>
    public string LogFolder { get; }

    /// <summary>
    /// The isolated data object store for this tenant.
    /// </summary>
    public IDataObjectStore Store { get; }

    /// <summary>
    /// The primary data provider (WAL) for this tenant.
    /// </summary>
    public IDataProvider Provider { get; }

    public TenantContext(
        string tenantId,
        string dataRoot,
        string logFolder,
        IDataObjectStore store,
        IDataProvider provider)
    {
        TenantId   = tenantId;
        DataRoot   = dataRoot;
        LogFolder  = logFolder;
        Store      = store;
        Provider   = provider;
    }
}
