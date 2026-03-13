using System;
using System.Collections.Generic;
using BareMetalWeb.Core;

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
    public static BaseDataObject? AsRestrictedPrincipal(BaseDataObject? user)
    {
        var role = GetPrincipalRole(user);
        if (string.IsNullOrWhiteSpace(role) || RoleEquals(role, nameof(PrincipalRole.FullAccess)))
            return null;
        return user;
    }

    /// <summary>
    /// Checks whether a restricted principal may perform <paramref name="action"/> on
    /// the entity identified by <paramref name="entitySlug"/>.
    /// Returns null when the action is permitted, or a denial reason string otherwise.
    /// </summary>
    public static string? CheckEntityAction(BaseDataObject principal, string entitySlug, string action)
    {
        var role = GetPrincipalRole(principal);
        if (string.IsNullOrWhiteSpace(role) || RoleEquals(role, nameof(PrincipalRole.FullAccess)))
            return null;

        if (RoleEquals(role, nameof(PrincipalRole.DeploymentProcess)))
            return CheckDeploymentProcess(entitySlug, action);
        if (RoleEquals(role, nameof(PrincipalRole.DeploymentAgent)))
            return CheckDeploymentAgent(entitySlug, action);
        if (RoleEquals(role, nameof(PrincipalRole.TenantCallback)))
            return CheckTenantCallback(entitySlug, action);

        return null;
    }

    /// <summary>
    /// Returns true when <paramref name="principal"/> is allowed to manage API keys
    /// (create, rotate, or revoke keys on SystemPrincipal records).
    /// Only FullAccess principals may modify API keys.
    /// </summary>
    public static bool CanManageApiKeys(BaseDataObject? user)
    {
        var role = GetPrincipalRole(user);
        return string.IsNullOrWhiteSpace(role) || RoleEquals(role, nameof(PrincipalRole.FullAccess));
    }

    /// <summary>
    /// Checks whether a <see cref="PrincipalRole.TenantCallback"/> principal owns
    /// the specified record, based on matching <see cref="BaseDataObject.CreatedBy"/>
    /// against the principal's user name, or matching the record's principal key when applicable.
    /// </summary>
    public static bool IsRecordOwner(BaseDataObject principal, BaseDataObject record)
    {
        var principalUserName = GetUserName(principal);
        if (!string.IsNullOrEmpty(principalUserName) &&
            string.Equals(record.CreatedBy, principalUserName, StringComparison.OrdinalIgnoreCase))
            return true;

        if (IsSystemPrincipal(record) && record.Key == principal.Key)
            return true;

        return false;
    }

    /// <summary>
    /// Filters a sequence of records to only those owned by the specified
    /// <see cref="PrincipalRole.TenantCallback"/> principal.
    /// </summary>
    public static List<T> FilterOwnedRecords<T>(BaseDataObject principal, IEnumerable<T> records)
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
        if (IsSpKeyOperation(entitySlug, action))
            return "DeploymentProcess principals cannot manage service principal API keys.";

        if (string.Equals(action, "Delete", StringComparison.OrdinalIgnoreCase))
            return "DeploymentProcess principals cannot delete records.";

        return null;
    }

    private static string? CheckDeploymentAgent(string entitySlug, string action)
    {
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

    private static string? GetPrincipalRole(BaseDataObject? principal)
    {
        if (principal == null)
            return null;

        var meta = ResolveAuthMeta(principal);
        return meta?.FindField("Role")?.GetValueFn(principal)?.ToString();
    }

    private static string? GetUserName(BaseDataObject principal)
    {
        var meta = ResolveAuthMeta(principal);
        if (meta == null)
            return null;

        var value = UserAuthHelper.GetUserName(principal, meta);
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static bool IsSystemPrincipal(BaseDataObject record)
    {
        var meta = ResolveAuthMeta(record);
        return meta != null && string.Equals(meta.Slug, SystemPrincipalSlug, StringComparison.OrdinalIgnoreCase);
    }

    private static bool RoleEquals(string role, string expected)
        => string.Equals(role, expected, StringComparison.OrdinalIgnoreCase);

    private static DataEntityMetadata? ResolveAuthMeta(BaseDataObject? record)
    {
        if (record == null)
            return null;

        var meta = DataScaffold.GetEntityByType(record.GetType());
        if (meta != null)
            return meta;

        if (record is DataRecord dataRecord)
        {
            var userMeta = UserAuthHelper.GetUserMeta();
            if (MatchesEntity(dataRecord.EntityTypeName, userMeta))
                return userMeta;

            var principalMeta = UserAuthHelper.GetPrincipalMeta();
            if (MatchesEntity(dataRecord.EntityTypeName, principalMeta))
                return principalMeta;
        }

        return null;
    }

    private static bool MatchesEntity(string entityTypeName, DataEntityMetadata? meta)
    {
        if (string.IsNullOrWhiteSpace(entityTypeName) || meta == null)
            return false;

        return string.Equals(entityTypeName, meta.Name, StringComparison.OrdinalIgnoreCase)
            || string.Equals(entityTypeName, meta.Slug, StringComparison.OrdinalIgnoreCase)
            || string.Equals(entityTypeName, meta.Type.Name, StringComparison.OrdinalIgnoreCase);
    }
}
