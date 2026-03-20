using System;
using System.Collections.Generic;
using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Manual JSON deserialization for <see cref="SamplePackage"/> using JsonDocument + DataScaffold metadata.
/// Eliminates JsonSerializer dependency while leveraging the metadata-driven architecture.
/// </summary>
public static class SamplePackageJson
{
    public static SamplePackage? Deserialize(System.IO.Stream stream)
    {
        using var doc = JsonDocument.Parse(stream);
        return ReadPackage(doc.RootElement);
    }

    public static SamplePackage? Deserialize(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        using var doc = JsonDocument.Parse(json);
        return ReadPackage(doc.RootElement);
    }

    private static SamplePackage? ReadPackage(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) return null;

        var pkg = new SamplePackage
        {
            Name = Str(root, "name"),
            Slug = Str(root, "slug"),
            Description = Str(root, "description"),
            Icon = root.TryGetProperty("icon", out var ic) ? ic.GetString() ?? "bi-box" : "bi-box",
            Version = root.TryGetProperty("version", out var ver) ? ver.GetString() ?? "1.0" : "1.0",
        };

        if (root.TryGetProperty("entities", out var entities))
            pkg.Entities = ReadEntityList<EntityDefinition>(entities);
        if (root.TryGetProperty("fields", out var fields))
            pkg.Fields = ReadEntityList<FieldDefinition>(fields);
        if (root.TryGetProperty("indexes", out var indexes))
            pkg.Indexes = ReadEntityList<IndexDefinition>(indexes);
        if (root.TryGetProperty("actions", out var actions))
            pkg.Actions = ReadEntityList<ActionDefinition>(actions);
        if (root.TryGetProperty("actionCommands", out var cmds))
            pkg.ActionCommands = ReadEntityList<ActionCommandDefinition>(cmds);
        if (root.TryGetProperty("aggregations", out var aggs))
            pkg.Aggregations = ReadEntityList<AggregationDefinition>(aggs);
        if (root.TryGetProperty("scheduledActions", out var sched))
            pkg.ScheduledActions = ReadEntityList<ScheduledActionDefinition>(sched);
        if (root.TryGetProperty("workflowRules", out var rules))
            pkg.WorkflowRules = ReadEntityList<DomainEventSubscription>(rules);

        // Lightweight types without DataScaffold metadata
        if (root.TryGetProperty("reports", out var reports))
            pkg.Reports = ReadReports(reports);
        if (root.TryGetProperty("roles", out var roles))
            pkg.Roles = ReadRoles(roles);
        if (root.TryGetProperty("permissions", out var perms))
            pkg.Permissions = ReadPermissions(perms);

        return pkg;
    }

    /// <summary>
    /// Metadata-driven entity deserialization: uses DataScaffold field metadata and compiled
    /// setter delegates to populate entity properties from JSON without reflection.
    /// Auto-registers entity types if not already registered in DataScaffold.
    /// </summary>
    private static List<T> ReadEntityList<T>(JsonElement arr) where T : BaseDataObject, new()
    {
        if (arr.ValueKind != JsonValueKind.Array) return new List<T>();

        var meta = DataScaffold.GetEntityByType(typeof(T));
        if (meta == null)
        {
            // Auto-register the entity type so metadata-driven deserialization works.
            // RegisterEntity<T> is idempotent and uses [DynamicallyAccessedMembers]-annotated
            // reflection at startup — this is the accepted pattern for the metadata-driven architecture.
            DataScaffold.RegisterEntity<T>();
            meta = DataScaffold.GetEntityByType(typeof(T));
        }

        var list = new List<T>(arr.GetArrayLength());

        foreach (var el in arr.EnumerateArray())
        {
            if (el.ValueKind != JsonValueKind.Object) continue;
            var entity = new T();

            if (meta != null)
            {
                foreach (var prop in el.EnumerateObject())
                {
                    var field = meta.FindField(prop.Name);
                    if (field == null) continue;
                    if (DataScaffold.TryConvertJson(prop.Value, field.ClrType, out var converted))
                        field.SetValueFn(entity, converted);
                }
            }

            list.Add(entity);
        }

        return list;
    }

    private static List<SampleReport> ReadReports(JsonElement arr)
    {
        if (arr.ValueKind != JsonValueKind.Array) return new();
        var list = new List<SampleReport>(arr.GetArrayLength());
        foreach (var el in arr.EnumerateArray())
        {
            list.Add(new SampleReport
            {
                Name = Str(el, "name"),
                Description = Str(el, "description"),
                RootEntity = Str(el, "rootEntity"),
                ColumnsJson = el.TryGetProperty("columnsJson", out var cj) ? cj.GetString() ?? "[]" : "[]",
                FiltersJson = el.TryGetProperty("filtersJson", out var fj) ? fj.GetString() ?? "[]" : "[]",
                ParametersJson = el.TryGetProperty("parametersJson", out var pj) ? pj.GetString() ?? "[]" : "[]",
                SortField = Str(el, "sortField"),
                SortDescending = el.TryGetProperty("sortDescending", out var sd) && sd.ValueKind == JsonValueKind.True,
                Permission = el.TryGetProperty("permission", out var pm) ? pm.GetString() : null,
            });
        }
        return list;
    }

    private static List<SampleRole> ReadRoles(JsonElement arr)
    {
        if (arr.ValueKind != JsonValueKind.Array) return new();
        var list = new List<SampleRole>(arr.GetArrayLength());
        foreach (var el in arr.EnumerateArray())
        {
            list.Add(new SampleRole
            {
                RoleName = Str(el, "roleName"),
                Description = Str(el, "description"),
                PermissionCodes = Str(el, "permissionCodes"),
            });
        }
        return list;
    }

    private static List<SamplePermission> ReadPermissions(JsonElement arr)
    {
        if (arr.ValueKind != JsonValueKind.Array) return new();
        var list = new List<SamplePermission>(arr.GetArrayLength());
        foreach (var el in arr.EnumerateArray())
        {
            list.Add(new SamplePermission
            {
                Code = Str(el, "code"),
                Description = Str(el, "description"),
                TargetEntity = el.TryGetProperty("targetEntity", out var te) ? te.GetString() ?? "*" : "*",
                Actions = el.TryGetProperty("actions", out var ac) ? ac.GetString() ?? "*" : "*",
                RequiresElevation = el.TryGetProperty("requiresElevation", out var re) && re.ValueKind == JsonValueKind.True,
            });
        }
        return list;
    }

    private static string Str(JsonElement el, string name)
        => el.TryGetProperty(name, out var v) ? v.GetString() ?? "" : "";
}
