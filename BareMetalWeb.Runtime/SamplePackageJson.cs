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
            pkg.Entities = ReadEntityList<EntityDefinition>("EntityDefinition", entities);
        if (root.TryGetProperty("fields", out var fields))
            pkg.Fields = ReadEntityList<FieldDefinition>("FieldDefinition", fields);
        if (root.TryGetProperty("indexes", out var indexes))
            pkg.Indexes = ReadEntityList<IndexDefinition>("IndexDefinition", indexes);
        if (root.TryGetProperty("actions", out var actions))
            pkg.Actions = ReadEntityListBySlug("action-definitions", actions);
        if (root.TryGetProperty("actionCommands", out var cmds))
            pkg.ActionCommands = ReadEntityListBySlug("action-commands", cmds);
        if (root.TryGetProperty("aggregations", out var aggs))
            pkg.Aggregations = ReadEntityListBySlug("aggregation-definitions", aggs);
        if (root.TryGetProperty("scheduledActions", out var sched))
            pkg.ScheduledActions = ReadEntityListBySlug("scheduled-actions", sched);
        if (root.TryGetProperty("workflowRules", out var rules))
            pkg.WorkflowRules = ReadEntityListBySlug("domain-event-subscriptions", rules);

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
    /// Metadata-driven entity deserialization by slug: uses DataScaffold field metadata and compiled
    /// setter delegates to populate DataRecord properties from JSON without reflection.
    /// The entity must be registered with DataScaffold (by slug) before calling this method.
    /// </summary>
    private static List<BaseDataObject> ReadEntityListBySlug(string slug, JsonElement arr)
    {
        if (arr.ValueKind != JsonValueKind.Array) return new List<BaseDataObject>();

        if (!DataScaffold.TryGetEntity(slug, out var meta))
            return new List<BaseDataObject>(); // Entity not yet registered; skip gracefully

        var list = new List<BaseDataObject>(arr.GetArrayLength());

        foreach (var el in arr.EnumerateArray())
        {
            if (el.ValueKind != JsonValueKind.Object) continue;
            var entity = meta.Handlers.Create();

            foreach (var prop in el.EnumerateObject())
            {
                var field = meta.FindField(prop.Name);
                if (field == null) continue;
                if (DataScaffold.TryConvertJson(prop.Value, field.ClrType, out var converted))
                    field.SetValueFn(entity, converted);
            }

            list.Add(entity);
        }

        return list;
    }

    /// <summary>
    /// Metadata-driven entity deserialization: uses DataScaffold field metadata and compiled
    /// setter delegates to populate entity properties from JSON without reflection.
    /// The entity type must be registered with DataScaffold before calling this method.
    /// </summary>
    private static List<T> ReadEntityList<T>(string entityName, JsonElement arr) where T : BaseDataObject, new()
    {
        if (arr.ValueKind != JsonValueKind.Array) return new List<T>();

        var meta = DataScaffold.GetEntityByName(entityName)
            ?? throw new InvalidOperationException(
                $"Entity '{entityName}' is not registered with DataScaffold. " +
                "Register it before deserializing sample packages.");

        var list = new List<T>(arr.GetArrayLength());

        foreach (var el in arr.EnumerateArray())
        {
            if (el.ValueKind != JsonValueKind.Object) continue;
            var entity = (T)meta.Handlers.Create();

            foreach (var prop in el.EnumerateObject())
            {
                var field = meta.FindField(prop.Name);
                if (field == null) continue;
                if (DataScaffold.TryConvertJson(prop.Value, field.ClrType, out var converted))
                    field.SetValueFn(entity, converted);
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
