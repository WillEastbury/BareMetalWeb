using System;
using System.Collections.Generic;

namespace BareMetalWeb.Data;

/// <summary>
/// Enforces principal-role-scoped authorization for <see cref="SystemPrincipal"/> entities.
/// All methods are static to match the no-DI, no-middleware architecture.
/// </summary>
public static class PrincipalAuthorizationPolicy
{
    /// <summary>Entity slug for <see cref="SystemPrincipal"/>.</summary>
    private const string SystemPrincipalSlug = "system-principals";

    /// <summary>
    /// Determines whether <paramref name="user"/> is a role-restricted <see cref="SystemPrincipal"/>.
    /// Returns null for regular web users (session-based), which are not subject to principal-role checks.
    /// </summary>
    public static SystemPrincipal? AsRestrictedPrincipal(User? user)
    {
        if (user is SystemPrincipal sp && sp.Role != PrincipalRole.FullAccess)
            return sp;
        return null;
    }

    /// <summary>
    /// Checks whether a restricted principal may perform <paramref name="action"/> on
    /// the entity identified by <paramref name="entitySlug"/>.
    /// Returns null when the action is permitted, or a denial reason string otherwise.
    /// </summary>
    public static string? CheckEntityAction(SystemPrincipal principal, string entitySlug, string action)
    {
        return principal.Role switch
        {
            PrincipalRole.DeploymentProcess => CheckDeploymentProcess(entitySlug, action),
            PrincipalRole.DeploymentAgent => CheckDeploymentAgent(entitySlug, action),
            PrincipalRole.TenantCallback => CheckTenantCallback(entitySlug, action),
            _ => null, // FullAccess — unrestricted
        };
    }

    /// <summary>
    /// Returns true when <paramref name="principal"/> is allowed to manage API keys
    /// (create, rotate, or revoke keys on SystemPrincipal records).
    /// Only FullAccess principals may modify API keys.
    /// </summary>
    public static bool CanManageApiKeys(User? user)
    {
        if (user is not SystemPrincipal sp)
            return true; // regular session user — governed by entity permission, not role policy
        return sp.Role == PrincipalRole.FullAccess;
    }

    /// <summary>
    /// Checks whether a <see cref="PrincipalRole.TenantCallback"/> principal owns
    /// the specified record, based on matching <see cref="BaseDataObject.CreatedBy"/>
    /// against the principal's <see cref="User.UserName"/>, or matching the record's
    /// owner tenant/instance metadata when available.
    /// </summary>
    public static bool IsRecordOwner(SystemPrincipal principal, BaseDataObject record)
    {
        // Match by username (CreatedBy is set from the authenticated user's UserName)
        if (!string.IsNullOrEmpty(principal.UserName) &&
            string.Equals(record.CreatedBy, principal.UserName, StringComparison.OrdinalIgnoreCase))
            return true;

        // If the record itself is a SystemPrincipal, allow only self-access
        if (record is SystemPrincipal targetSp)
            return targetSp.Key == principal.Key;

        return false;
    }

    /// <summary>
    /// Filters a sequence of records to only those owned by the specified
    /// <see cref="PrincipalRole.TenantCallback"/> principal.
    /// </summary>
    public static List<T> FilterOwnedRecords<T>(SystemPrincipal principal, IEnumerable<T> records)
        where T : BaseDataObject
    {
        var result = new List<T>();
        foreach (var record in records)
        {
            if (IsRecordOwner(principal, record))
                result.Add(record);
        }
        return result;
    }

    // ── Role-specific action checks ──────────────────────────────────────

    private static string? CheckDeploymentProcess(string entitySlug, string action)
    {
        // Can create records and read, but cannot manage SP keys
        if (IsSpKeyOperation(entitySlug, action))
            return "DeploymentProcess principals cannot manage service principal API keys.";

        // Allow Read, Create, Update for non-SP-key operations
        if (string.Equals(action, "Delete", StringComparison.OrdinalIgnoreCase))
            return "DeploymentProcess principals cannot delete records.";

        return null;
    }

    private static string? CheckDeploymentAgent(string entitySlug, string action)
    {
        // Can query (read) and create, but cannot update/delete or manage SP keys
        if (IsSpKeyOperation(entitySlug, action))
            return "DeploymentAgent principals cannot manage service principal API keys.";

        if (string.Equals(action, "Update", StringComparison.OrdinalIgnoreCase))
            return "DeploymentAgent principals cannot update records.";

        if (string.Equals(action, "Delete", StringComparison.OrdinalIgnoreCase))
            return "DeploymentAgent principals cannot delete records.";

        return null;
    }

    private static string? CheckTenantCallback(string entitySlug, string action)
    {
        // Can only read and update own records — ownership check is handled separately
        if (IsSpKeyOperation(entitySlug, action))
            return "TenantCallback principals cannot manage service principal API keys.";

        if (string.Equals(action, "Create", StringComparison.OrdinalIgnoreCase))
            return "TenantCallback principals cannot create new records.";

        if (string.Equals(action, "Delete", StringComparison.OrdinalIgnoreCase))
            return "TenantCallback principals cannot delete records.";

        return null;
    }

    /// <summary>
    /// Returns true when the operation targets the SystemPrincipal entity for
    /// a write action (which could mutate API keys).
    /// </summary>
    private static bool IsSpKeyOperation(string entitySlug, string action)
    {
        if (!string.Equals(entitySlug, SystemPrincipalSlug, StringComparison.OrdinalIgnoreCase))
            return false;

        return string.Equals(action, "Create", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(action, "Update", StringComparison.OrdinalIgnoreCase);
    }
}
