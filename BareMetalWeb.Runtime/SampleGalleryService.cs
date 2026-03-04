using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Provides access to the shipped metadata <see cref="SamplePackage"/> files and
/// supports deploying them into a data store via the gallery admin page.
/// </summary>
public static class SampleGalleryService
{
    private static readonly JsonSerializerOptions _jsonOpts = new()
    {
        PropertyNameCaseInsensitive = true
    };

    // ── Package loading ──────────────────────────────────────────────────────

    /// <summary>
    /// Returns the list of all built-in <see cref="SamplePackage"/> instances
    /// loaded from the embedded JSON resource files in this assembly.
    /// </summary>
    public static IReadOnlyList<SamplePackage> GetAllPackages()
    {
        var assembly = typeof(SampleGalleryService).Assembly;
        var packages = new List<SamplePackage>();

        foreach (var resourceName in assembly.GetManifestResourceNames()
            .Where(n => n.Contains(".Samples.") && n.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            .OrderBy(n => n))
        {
            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null) continue;

            var pkg = JsonSerializer.Deserialize<SamplePackage>(stream, _jsonOpts);
            if (pkg != null)
                packages.Add(pkg);
        }

        return packages;
    }

    /// <summary>
    /// Loads a single <see cref="SamplePackage"/> by its slug (case-insensitive).
    /// Returns <c>null</c> if no matching embedded resource is found.
    /// </summary>
    public static SamplePackage? GetPackage(string slug)
    {
        ArgumentNullException.ThrowIfNull(slug);

        var assembly = typeof(SampleGalleryService).Assembly;
        var resourceName = assembly.GetManifestResourceNames()
            .FirstOrDefault(n =>
                n.Contains(".Samples.") &&
                n.EndsWith($".{slug}.json", StringComparison.OrdinalIgnoreCase));

        if (resourceName == null) return null;

        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream == null) return null;

        return JsonSerializer.Deserialize<SamplePackage>(stream, _jsonOpts);
    }

    // ── Deployment ───────────────────────────────────────────────────────────

    /// <summary>
    /// Deploys a <see cref="SamplePackage"/> into the provided data store by importing
    /// its <see cref="EntityDefinition"/>, <see cref="FieldDefinition"/>, and
    /// <see cref="IndexDefinition"/> records.
    /// </summary>
    /// <param name="package">The package to deploy.</param>
    /// <param name="store">Target data store.</param>
    /// <param name="overwrite">
    /// When <c>true</c>, any existing entity definition with the same slug is replaced.
    /// When <c>false</c> (default), entities that already have a definition in the store are skipped.
    /// </param>
    /// <param name="logger">Optional diagnostic callback.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>Names of entity definitions that were imported (not skipped).</returns>
    public static async Task<IReadOnlyList<string>> DeployPackageAsync(
        SamplePackage package,
        IDataObjectStore store,
        bool overwrite = false,
        Action<string>? logger = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(store);

        var deployed = new List<string>();

        // Load existing EntityDefinitions so we can skip or overwrite
        var existingDefs = (await store.QueryAsync<EntityDefinition>(null, cancellationToken)
            .ConfigureAwait(false)).ToList();

        var existingBySlug = existingDefs.ToDictionary(
            e => !string.IsNullOrWhiteSpace(e.Slug) ? e.Slug! : DataScaffold.ToSlug(e.Name),
            StringComparer.OrdinalIgnoreCase);

        foreach (var srcEntity in package.Entities)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var slug = !string.IsNullOrWhiteSpace(srcEntity.Slug)
                ? srcEntity.Slug!
                : DataScaffold.ToSlug(srcEntity.Name);

            if (!overwrite && existingBySlug.ContainsKey(slug))
            {
                logger?.Invoke($"Skipping '{srcEntity.Name}' — EntityDefinition already exists in store.");
                continue;
            }

            // Assign a fresh EntityId to avoid collisions; remap child records accordingly
            var oldEntityId = srcEntity.EntityId;
            var newEntityId = Guid.NewGuid().ToString("D");

            var newEntity = new EntityDefinition
            {
                EntityId = newEntityId,
                Name = srcEntity.Name,
                Slug = slug,
                IdStrategy = srcEntity.IdStrategy,
                ShowOnNav = srcEntity.ShowOnNav,
                NavGroup = srcEntity.NavGroup,
                NavOrder = srcEntity.NavOrder,
                Permissions = srcEntity.Permissions,
                FormLayout = srcEntity.FormLayout ?? "Standard",
                Version = 1
            };

            if (overwrite && existingBySlug.TryGetValue(slug, out var existing))
            {
                // Preserve existing identity; remove stale child records
                newEntity.Key = existing.Key;
                newEntity.EntityId = existing.EntityId;
                newEntity.Version = existing.Version + 1;
                await DeleteChildRecordsAsync(store, existing.EntityId, existing.Slug, cancellationToken).ConfigureAwait(false);

                // Use preserved EntityId for remapping child records
                oldEntityId = existing.EntityId;
                newEntityId = existing.EntityId;
                newEntity.Key = existing.Key;
            }

            await store.SaveAsync(newEntity, cancellationToken).ConfigureAwait(false);

            // Import fields that belong to this entity (matched by old entity Id from the JSON)
            foreach (var srcField in package.Fields.Where(f => f.EntityId == oldEntityId))
            {
                var newField = new FieldDefinition
                {
                    FieldId = Guid.NewGuid().ToString("D"),
                    EntityId = newEntity.EntityId,
                    Name = srcField.Name,
                    Label = srcField.Label,
                    Ordinal = srcField.Ordinal,
                    Type = srcField.Type,
                    IsNullable = srcField.IsNullable,
                    Required = srcField.Required,
                    List = srcField.List,
                    View = srcField.View,
                    Edit = srcField.Edit,
                    Create = srcField.Create,
                    ReadOnly = srcField.ReadOnly,
                    DefaultValue = srcField.DefaultValue,
                    Placeholder = srcField.Placeholder,
                    MinLength = srcField.MinLength,
                    MaxLength = srcField.MaxLength,
                    RangeMin = srcField.RangeMin,
                    RangeMax = srcField.RangeMax,
                    Pattern = srcField.Pattern,
                    EnumValues = srcField.EnumValues,
                    LookupEntitySlug = srcField.LookupEntitySlug,
                    LookupValueField = srcField.LookupValueField,
                    LookupDisplayField = srcField.LookupDisplayField,
                    Multiline = srcField.Multiline
                };

                await store.SaveAsync(newField, cancellationToken).ConfigureAwait(false);
            }

            // Import indexes that belong to this entity
            foreach (var srcIndex in package.Indexes.Where(ix => ix.EntityId == oldEntityId))
            {
                var newIndex = new IndexDefinition
                {
                    EntityId = newEntity.EntityId,
                    FieldNames = srcIndex.FieldNames,
                    Type = srcIndex.Type
                };

                await store.SaveAsync(newIndex, cancellationToken).ConfigureAwait(false);
            }

            // Import actions that belong to this entity
            foreach (var srcAction in package.Actions.Where(a => a.EntityId == oldEntityId))
            {
                var newAction = new ActionDefinition
                {
                    EntityId = newEntity.EntityId,
                    Name = srcAction.Name,
                    Label = srcAction.Label,
                    Icon = srcAction.Icon,
                    Permission = srcAction.Permission,
                    EnabledWhen = srcAction.EnabledWhen,
                    Operations = srcAction.Operations,
                    Version = srcAction.Version
                };
                await store.SaveAsync(newAction, cancellationToken).ConfigureAwait(false);

                // Import action commands that belong to this action (matched by Name)
                foreach (var srcCmd in package.ActionCommands.Where(c => c.ActionId == srcAction.Name))
                {
                    var newCmd = new ActionCommandDefinition
                    {
                        ActionId = newAction.Key.ToString(),
                        CommandType = srcCmd.CommandType,
                        Order = srcCmd.Order,
                        Condition = srcCmd.Condition,
                        FieldId = srcCmd.FieldId,
                        ValueExpression = srcCmd.ValueExpression,
                        Severity = srcCmd.Severity,
                        ErrorCode = srcCmd.ErrorCode,
                        Message = srcCmd.Message
                    };
                    await store.SaveAsync(newCmd, cancellationToken).ConfigureAwait(false);
                }
            }

            // Import reports that reference this entity slug
            foreach (var srcReport in package.Reports.Where(r =>
                string.Equals(r.RootEntity, srcEntity.Slug, StringComparison.OrdinalIgnoreCase)))
            {
                var newReport = new ReportDefinition
                {
                    Name = srcReport.Name,
                    Description = srcReport.Description,
                    RootEntity = newEntity.Slug,
                    ColumnsJson = srcReport.ColumnsJson,
                    FiltersJson = srcReport.FiltersJson,
                    ParametersJson = srcReport.ParametersJson,
                    SortField = srcReport.SortField,
                    SortDescending = srcReport.SortDescending
                };
                await store.SaveAsync(newReport, cancellationToken).ConfigureAwait(false);
            }

            // Import aggregation definitions for this entity
            foreach (var srcAgg in package.Aggregations.Where(a => a.EntityId == oldEntityId))
            {
                var newAgg = new AggregationDefinition
                {
                    EntityId = newEntity.EntityId,
                    Name = srcAgg.Name,
                    GroupByFields = srcAgg.GroupByFields,
                    Measures = srcAgg.Measures
                };
                await store.SaveAsync(newAgg, cancellationToken).ConfigureAwait(false);
            }

            // Import scheduled action definitions for this entity
            foreach (var srcSched in package.ScheduledActions.Where(s => s.EntityId == oldEntityId))
            {
                var newSched = new ScheduledActionDefinition
                {
                    EntityId = newEntity.EntityId,
                    Name = srcSched.Name,
                    ActionName = srcSched.ActionName,
                    Schedule = srcSched.Schedule,
                    FilterExpression = srcSched.FilterExpression,
                    Enabled = srcSched.Enabled
                };
                await store.SaveAsync(newSched, cancellationToken).ConfigureAwait(false);
            }

            var fieldCount = package.Fields.Count(f => f.EntityId == oldEntityId);
            var indexCount = package.Indexes.Count(ix => ix.EntityId == oldEntityId);
            var actionCount = package.Actions.Count(a => a.EntityId == oldEntityId);
            var reportCount = package.Reports.Count(r =>
                string.Equals(r.RootEntity, srcEntity.Slug, StringComparison.OrdinalIgnoreCase));
            var aggCount = package.Aggregations.Count(a => a.EntityId == oldEntityId);
            logger?.Invoke($"Deployed '{srcEntity.Name}': {fieldCount} field(s), {indexCount} index(es), {actionCount} action(s), {reportCount} report(s), {aggCount} aggregation(s).");
            deployed.Add(srcEntity.Name);
        }

        // Deploy package-level RBAC definitions
        await DeployRbacAsync(package, logger, cancellationToken).ConfigureAwait(false);

        return deployed;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static async Task DeployRbacAsync(
        SamplePackage package,
        Action<string>? logger,
        CancellationToken ct)
    {
        if (package.Permissions.Count == 0 && package.Roles.Count == 0)
            return;

        // Deploy permissions
        if (package.Permissions.Count > 0 && DataScaffold.TryGetEntity("permissions", out var permMeta))
        {
            foreach (var srcPerm in package.Permissions)
            {
                var rec = permMeta.Handlers.Create();
                if (rec is DataRecord dr && dr.Schema != null)
                {
                    dr.SetField(dr.Schema, "Code", srcPerm.Code);
                    dr.SetField(dr.Schema, "Description", srcPerm.Description);
                    dr.SetField(dr.Schema, "TargetEntity", srcPerm.TargetEntity);
                    dr.SetField(dr.Schema, "Actions", srcPerm.Actions);
                    dr.SetField(dr.Schema, "RequiresElevation", srcPerm.RequiresElevation);
                    await DataScaffold.SaveAsync(permMeta, rec, ct).ConfigureAwait(false);
                }
            }
            logger?.Invoke($"Deployed {package.Permissions.Count} permission(s).");
        }

        // Deploy roles
        if (package.Roles.Count > 0 && DataScaffold.TryGetEntity("roles", out var roleMeta))
        {
            foreach (var srcRole in package.Roles)
            {
                var rec = roleMeta.Handlers.Create();
                if (rec is DataRecord dr && dr.Schema != null)
                {
                    dr.SetField(dr.Schema, "RoleName", srcRole.RoleName);
                    dr.SetField(dr.Schema, "Description", srcRole.Description);
                    dr.SetField(dr.Schema, "PermissionCodes", srcRole.PermissionCodes);
                    await DataScaffold.SaveAsync(roleMeta, rec, ct).ConfigureAwait(false);
                }
            }
            logger?.Invoke($"Deployed {package.Roles.Count} role(s).");
        }
    }

    private static async Task DeleteChildRecordsAsync(
        IDataObjectStore store,
        string entityDefId,
        string entitySlug,
        CancellationToken ct)
    {
        var entityIdQuery = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "EntityId", Operator = QueryOperator.Equals, Value = entityDefId } }
        };

        var fields = (await store.QueryAsync<FieldDefinition>(entityIdQuery, ct).ConfigureAwait(false)).ToList();
        foreach (var f in fields)
            await store.DeleteAsync<FieldDefinition>(f.Key, ct).ConfigureAwait(false);

        var idxs = (await store.QueryAsync<IndexDefinition>(entityIdQuery, ct).ConfigureAwait(false)).ToList();
        foreach (var idx in idxs)
            await store.DeleteAsync<IndexDefinition>(idx.Key, ct).ConfigureAwait(false);

        // Also delete actions and their commands
        var actionQuery = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "EntityId", Operator = QueryOperator.Equals, Value = entityDefId } }
        };
        var actions = (await store.QueryAsync<ActionDefinition>(actionQuery, ct).ConfigureAwait(false)).ToList();
        foreach (var action in actions)
        {
            var cmdQuery = new QueryDefinition
            {
                Clauses = { new QueryClause { Field = "ActionId", Operator = QueryOperator.Equals, Value = action.Key } }
            };
            var cmds = (await store.QueryAsync<ActionCommandDefinition>(cmdQuery, ct).ConfigureAwait(false)).ToList();
            foreach (var cmd in cmds)
                await store.DeleteAsync<ActionCommandDefinition>(cmd.Key, ct).ConfigureAwait(false);
            await store.DeleteAsync<ActionDefinition>(action.Key, ct).ConfigureAwait(false);
        }

        // Delete reports whose root entity matches this entity's slug
        var reportQuery = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "RootEntity", Operator = QueryOperator.Equals, Value = entitySlug } }
        };
        var reports = (await store.QueryAsync<ReportDefinition>(reportQuery, ct).ConfigureAwait(false)).ToList();
        foreach (var report in reports)
            await store.DeleteAsync<ReportDefinition>(report.Key, ct).ConfigureAwait(false);

        // Delete aggregation definitions
        var aggs = (await store.QueryAsync<AggregationDefinition>(entityIdQuery, ct).ConfigureAwait(false)).ToList();
        foreach (var agg in aggs)
            await store.DeleteAsync<AggregationDefinition>(agg.Key, ct).ConfigureAwait(false);

        // Delete scheduled actions
        var scheds = (await store.QueryAsync<ScheduledActionDefinition>(entityIdQuery, ct).ConfigureAwait(false)).ToList();
        foreach (var sched in scheds)
            await store.DeleteAsync<ScheduledActionDefinition>(sched.Key, ct).ConfigureAwait(false);
    }
}
