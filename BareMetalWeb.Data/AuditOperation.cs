namespace BareMetalWeb.Data;

/// <summary>
/// Types of operations that can be audited
/// </summary>
public enum AuditOperation
{
    Create,
    Update,
    Delete,
    RemoteCommand
}
