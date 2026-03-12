namespace BareMetalWeb.Data;

/// <summary>
/// Defines the access scope for a <see cref="SystemPrincipal"/>.
/// Default is <see cref="FullAccess"/> for backward compatibility with existing principals.
/// </summary>
public enum PrincipalRole
{
    /// <summary>Unrestricted access — backward-compatible default for existing principals.</summary>
    FullAccess = 0,

    /// <summary>
    /// Deployment process principal: can create registry records and assign deployment
    /// metadata, but cannot set or rotate service principal API keys.
    /// </summary>
    DeploymentProcess = 1,

    /// <summary>
    /// Deployment agent principal: can query and create records needed for
    /// registration/bootstrap, but cannot set service principal API keys.
    /// </summary>
    DeploymentAgent = 2,

    /// <summary>
    /// Tenant-scoped callback principal: can only read and update records
    /// belonging to its own tenant/instance. No broad registry mutation rights.
    /// </summary>
    TenantCallback = 3,
}
