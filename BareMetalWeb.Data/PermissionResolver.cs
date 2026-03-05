using System.Collections.Concurrent;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Resolves effective permissions for a principal by walking the
/// Group → Role → Permission graph. Results are cached per principal key
/// and invalidated on group/role/permission changes.
/// </summary>
public static class PermissionResolver
{
    private static readonly ConcurrentDictionary<uint, ResolvedPermissionSet> _cache = new();
    private static long _generation;

    /// <summary>
    /// Get the resolved permission set for a user, walking group membership,
    /// role assignments, and individual permission entries.
    /// </summary>
    public static async ValueTask<ResolvedPermissionSet> ResolveAsync(
        BaseDataObject principal, CancellationToken ct = default)
    {
        var gen = Interlocked.Read(ref _generation);
        if (_cache.TryGetValue(principal.Key, out var cached) && cached.Generation == gen)
            return cached;

        var result = await BuildPermissionSetAsync(principal.Key, ct);
        result = result with { Generation = gen };
        _cache[principal.Key] = result;
        return result;
    }

    /// <summary>Invalidate all cached permission sets (call on group/role/permission save).</summary>
    public static void Invalidate() => Interlocked.Increment(ref _generation);

    /// <summary>Invalidate a specific principal's cache.</summary>
    public static void Invalidate(uint principalKey) => _cache.TryRemove(principalKey, out _);

    private static async ValueTask<ResolvedPermissionSet> BuildPermissionSetAsync(
        uint principalKey, CancellationToken ct)
    {
        var permissionCodes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var elevatedCodes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var entityActions = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var conditionalPerms = new List<ConditionalPermission>();

        // Load all groups, roles, permissions via metadata
        var groups = await LoadEntitiesAsync("security-groups", ct);
        var roles = await LoadEntitiesAsync("roles", ct);
        var permissions = await LoadEntitiesAsync("permissions", ct);

        // Build lookup tables
        var rolesByName = new Dictionary<string, BaseDataObject>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in roles)
        {
            var name = GetField(r, "roles", "RoleName");
            if (!string.IsNullOrEmpty(name)) rolesByName[name] = r;
        }

        var permsByCode = new Dictionary<string, BaseDataObject>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in permissions)
        {
            var code = GetField(p, "permissions", "Code");
            if (!string.IsNullOrEmpty(code)) permsByCode[code] = p;
        }

        // Find all groups this principal belongs to (with nesting)
        var memberGroups = new HashSet<uint>();
        FindMemberGroups(principalKey, groups, memberGroups, depth: 0);

        // Collect role names from all member groups
        var roleNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var g in groups)
        {
            if (!memberGroups.Contains(g.Key)) continue;
            var rn = GetField(g, "security-groups", "RoleNames");
            foreach (var r in SplitCsv(rn))
                roleNames.Add(r);
        }

        // Resolve roles → permission codes
        foreach (var rn in roleNames)
        {
            if (!rolesByName.TryGetValue(rn, out var role)) continue;
            var pc = GetField(role, "roles", "PermissionCodes");
            foreach (var c in SplitCsv(pc))
                permissionCodes.Add(c);
        }

        // Also include the principal's existing flat Permissions array (backward compat)
        if (DataScaffold.TryGetEntity("users", out var userMeta))
        {
            var user = await DataScaffold.LoadAsync(userMeta, principalKey, ct) as BaseDataObject;
            if (user != null)
            {
                var permsField = FindFieldByName(userMeta.Fields, "Permissions");
                if (permsField?.GetValueFn != null)
                {
                    var rawPerms = permsField.GetValueFn(user);
                    if (rawPerms is string[] strArr)
                        foreach (var p in strArr) permissionCodes.Add(p);
                }
            }
        }

        // Resolve permission codes → entity/action grants
        foreach (var code in permissionCodes)
        {
            if (!permsByCode.TryGetValue(code, out var perm))
            {
                // Legacy flat permission — treat as entity access grant
                if (!entityActions.TryGetValue(code, out var acts))
                    entityActions[code] = acts = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                acts.Add("*");
                continue;
            }

            var target = GetField(perm, "permissions", "TargetEntity");
            if (string.IsNullOrWhiteSpace(target)) target = "*";
            if (!entityActions.TryGetValue(target, out var actions))
                entityActions[target] = actions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            var actionsStr = GetField(perm, "permissions", "Actions");
            foreach (var a in SplitCsv(actionsStr))
                actions.Add(a);

            var reqElevation = GetBoolField(perm, "permissions", "RequiresElevation");
            if (reqElevation)
                elevatedCodes.Add(code);

            var condExpr = GetField(perm, "permissions", "ConditionExpression");
            if (!string.IsNullOrWhiteSpace(condExpr))
                conditionalPerms.Add(new ConditionalPermission(code, target, condExpr));
        }

        return new ResolvedPermissionSet
        {
            PrincipalKey = principalKey,
            PermissionCodes = permissionCodes,
            ElevatedCodes = elevatedCodes,
            EntityActions = entityActions,
            ConditionalPermissions = conditionalPerms,
        };
    }

    private static void FindMemberGroups(
        uint principalKey, IReadOnlyList<BaseDataObject> allGroups,
        HashSet<uint> result, int depth)
    {
        if (depth > 10) return;

        foreach (var g in allGroups)
        {
            if (result.Contains(g.Key)) continue;

            var memberKeys = GetField(g, "security-groups", "MemberKeys");
            foreach (var mk in SplitCsv(memberKeys))
            {
                if (uint.TryParse(mk, out var k) && k == principalKey)
                {
                    result.Add(g.Key);
                    break;
                }
            }

            var nestedKeys = GetField(g, "security-groups", "NestedGroupKeys");
            foreach (var nk in SplitCsv(nestedKeys))
            {
                if (uint.TryParse(nk, out var nestedKey) && result.Contains(nestedKey))
                {
                    result.Add(g.Key);
                    break;
                }
            }
        }

        if (depth < 10)
        {
            int prevCount = result.Count;
            FindMemberGroups(principalKey, allGroups, result, depth + 1);
            if (result.Count == prevCount) return;
        }
    }

    private static async ValueTask<IReadOnlyList<BaseDataObject>> LoadEntitiesAsync(
        string slug, CancellationToken ct)
    {
        if (!DataScaffold.TryGetEntity(slug, out var meta))
            return Array.Empty<BaseDataObject>();

        var items = await meta.Handlers.QueryAsync(null, ct);
        var list = new List<BaseDataObject>();
        foreach (var item in items)
            list.Add(item);
        return list;
    }

    private static readonly ConcurrentDictionary<string, Func<object, object?>?> _getterCache = new();

    private static string GetField(BaseDataObject obj, string entitySlug, string fieldName)
    {
        var key = $"{entitySlug}.{fieldName}";
        var getter = _getterCache.GetOrAdd(key, _ =>
        {
            if (!DataScaffold.TryGetEntity(entitySlug, out var meta)) return null;
            var field = FindFieldByName(meta.Fields, fieldName);
            return field?.GetValueFn;
        });
        return getter?.Invoke(obj)?.ToString() ?? string.Empty;
    }

    private static bool GetBoolField(BaseDataObject obj, string entitySlug, string fieldName)
    {
        var val = GetField(obj, entitySlug, fieldName);
        return string.Equals(val, "True", StringComparison.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> SplitCsv(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) yield break;
        foreach (var part in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            yield return part;
    }

    private static DataFieldMetadata? FindFieldByName(IReadOnlyList<DataFieldMetadata> fields, string name)
    {
        foreach (var f in fields)
        {
            if (string.Equals(f.Name, name, StringComparison.OrdinalIgnoreCase))
                return f;
        }
        return null;
    }
}

/// <summary>Cached resolved permission set for a principal.</summary>
public sealed record ResolvedPermissionSet
{
    public uint PrincipalKey { get; init; }
    public long Generation { get; init; }
    public HashSet<string> PermissionCodes { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> ElevatedCodes { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>Entity slug → set of allowed actions (Read, Create, Update, Delete, Execute, *).</summary>
    public Dictionary<string, HashSet<string>> EntityActions { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public List<ConditionalPermission> ConditionalPermissions { get; init; } = new();

    /// <summary>Check if principal can perform an action on an entity.</summary>
    public bool CanAccess(string entitySlug, string action = "Read")
    {
        // Global wildcard
        if (EntityActions.TryGetValue("*", out var globalActions) &&
            (globalActions.Contains("*") || globalActions.Contains(action)))
            return true;

        // Entity-specific
        if (EntityActions.TryGetValue(entitySlug, out var entityActs) &&
            (entityActs.Contains("*") || entityActs.Contains(action)))
            return true;

        // Legacy: permission code matches entity slug directly
        return PermissionCodes.Contains(entitySlug);
    }

    /// <summary>Check if any permission requires elevation.</summary>
    public bool HasElevatedPermissions => ElevatedCodes.Count > 0;
}

/// <summary>A permission with a runtime condition expression.</summary>
public sealed record ConditionalPermission(string Code, string TargetEntity, string Expression);
