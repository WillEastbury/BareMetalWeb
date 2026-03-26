using System;
using System.Collections.Generic;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Enforces row-level security (RLS) on entities whose <see cref="DataEntityMetadata.RlsOwnerField"/>
/// is set. All methods are static to match the no-DI, no-middleware architecture.
/// 
/// When <see cref="DataEntityMetadata.RlsOwnerField"/> is non-null the following rules apply:
/// <list type="bullet">
///   <item>Admin users (having "admin" permission) bypass RLS entirely.</item>
///   <item>Anonymous / unauthenticated users see no records.</item>
///   <item>Authenticated users see only records where the owner field matches their user name.</item>
/// </list>
/// </summary>
public static class RowLevelSecurity
{
    /// <summary>
    /// Returns <c>true</c> when the entity has RLS enabled (i.e. <see cref="DataEntityMetadata.RlsOwnerField"/> is set).
    /// </summary>
    public static bool IsEnabled(DataEntityMetadata meta) =>
        !string.IsNullOrWhiteSpace(meta.RlsOwnerField);

    /// <summary>
    /// Injects an ownership filter clause into <paramref name="query"/> when the entity
    /// has RLS enabled and the caller is not an admin.
    /// Returns <c>false</c> when the caller is non-admin and unauthenticated — the query
    /// should be short-circuited with an empty result.
    /// </summary>
    /// <param name="query">The query to augment with an RLS clause.</param>
    /// <param name="meta">Entity metadata (checked for <see cref="DataEntityMetadata.RlsOwnerField"/>).</param>
    /// <param name="userName">Current user's name (null when unauthenticated).</param>
    /// <param name="userPermissions">Permission tokens for the current user (may be empty).</param>
    /// <returns><c>true</c> if the query may proceed; <c>false</c> if the caller has no access.</returns>
    public static bool TryApplyFilter(
        QueryDefinition query,
        DataEntityMetadata meta,
        string? userName,
        ReadOnlySpan<string> userPermissions)
    {
        if (!IsEnabled(meta))
            return true;

        if (IsAdmin(userPermissions))
            return true;

        if (string.IsNullOrEmpty(userName))
            return false;

        query.Clauses.Add(new QueryClause
        {
            Field = meta.RlsOwnerField!,
            Operator = QueryOperator.Equals,
            Value = userName
        });
        return true;
    }

    /// <summary>
    /// Checks whether a single loaded record passes RLS for the current user.
    /// </summary>
    /// <returns><c>true</c> if the record is visible to the user; <c>false</c> otherwise.</returns>
    public static bool IsRecordVisible(
        BaseDataObject record,
        DataEntityMetadata meta,
        string? userName,
        ReadOnlySpan<string> userPermissions)
    {
        if (!IsEnabled(meta))
            return true;

        if (IsAdmin(userPermissions))
            return true;

        if (string.IsNullOrEmpty(userName))
            return false;

        var ownerValue = GetOwnerValue(record, meta);
        return string.Equals(ownerValue, userName, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Returns <c>true</c> when the user holds the "admin" permission.
    /// </summary>
    public static bool IsAdmin(ReadOnlySpan<string> userPermissions)
    {
        for (int i = 0; i < userPermissions.Length; i++)
        {
            if (string.Equals(userPermissions[i], "admin", StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Reads the owner field value from a record using the entity metadata.
    /// Falls back to <see cref="BaseDataObject.CreatedBy"/> when the configured
    /// owner field is "CreatedBy" (base field — not always in entity metadata Fields).
    /// </summary>
    private static string? GetOwnerValue(BaseDataObject record, DataEntityMetadata meta)
    {
        // Fast path: "CreatedBy" is pre-checked at registration time — no per-record string comparison.
        if (meta.RlsUsesCreatedBy)
            return record.CreatedBy;

        var field = meta.FindField(meta.RlsOwnerField!);
        if (field != null)
        {
            var val = field.GetValueFn(record);
            return val?.ToString();
        }

        return null;
    }
}
