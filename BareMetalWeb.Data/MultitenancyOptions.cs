namespace BareMetalWeb.Data;

/// <summary>
/// Configuration model for the multitenancy feature.
/// Bind to the "Multitenancy" section in appsettings.json.
/// </summary>
public sealed class MultitenancyOptions
{
    /// <summary>
    /// When false (default), a single system-wide data store is used and all
    /// tenant-related logic is bypassed. Set to true to enable tenant isolation.
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// Tenant identifier used for the system/master tenant when no incoming request
    /// host header matches a configured tenant. Defaults to "_system".
    /// This is a stable key used for cache lookups and log sub-folders —
    /// it is NOT a host name pattern.
    /// </summary>
    public string DefaultTenantId { get; set; } = "_system";

    /// <summary>
    /// One entry per tenant. Each entry maps a Host header value to an isolated
    /// data root and log folder.
    /// </summary>
    public List<TenantOptions> Tenants { get; set; } = new();
}

/// <summary>
/// Per-tenant configuration entry.
/// </summary>
public sealed class TenantOptions
{
    /// <summary>
    /// The HTTP Host header value (e.g. "tenant1.example.com") that selects this tenant.
    /// Matching is case-insensitive. Port numbers in the Host header are stripped before matching.
    /// </summary>
    public string Host { get; set; } = "";

    /// <summary>
    /// Tenant identifier used in log sub-folders and as a stable key.
    /// If omitted, the Host value is used (with characters unsafe for file paths replaced).
    /// </summary>
    public string? TenantId { get; set; }

    /// <summary>
    /// Root directory for this tenant's data files (WAL segments, index files, etc.).
    /// Relative paths are resolved against the application content root.
    /// </summary>
    public string DataRoot { get; set; } = "";

    /// <summary>
    /// Root directory for this tenant's log files.
    /// Relative paths are resolved against the application content root.
    /// </summary>
    public string LogFolder { get; set; } = "";
}
