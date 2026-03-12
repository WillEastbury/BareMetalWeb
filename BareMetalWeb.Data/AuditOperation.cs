namespace BareMetalWeb.Data;

/// <summary>
/// Types of operations that can be audited
/// </summary>
public enum AuditOperation
{
    Create,
    Update,
    Delete,
    RemoteCommand,

    /// <summary>An operation was denied by the authorization policy.</summary>
    AccessDenied,
}
