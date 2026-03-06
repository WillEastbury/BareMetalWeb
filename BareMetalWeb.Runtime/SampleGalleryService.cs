using System;
using System.Collections.Generic;
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

        var allResourceNames = assembly.GetManifestResourceNames();
        var matchingResources = new List<string>();
        foreach (var n in allResourceNames)
            if (n.Contains(".Samples.") && n.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                matchingResources.Add(n);
        matchingResources.Sort(StringComparer.Ordinal);

        foreach (var resourceName in matchingResources)
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
        string? resourceName = null;
        foreach (var n in assembly.GetManifestResourceNames())
        {
            if (n.Contains(".Samples.") && n.EndsWith($".{slug}.json", StringComparison.OrdinalIgnoreCase))
            {
                resourceName = n;
                break;
            }
        }

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
        var existingDefs = new List<EntityDefinition>(await store.QueryAsync<EntityDefinition>(null, cancellationToken)
            .ConfigureAwait(false));

        var existingBySlug = new Dictionary<string, EntityDefinition>(StringComparer.OrdinalIgnoreCase);
        foreach (var e in existingDefs)
        {
            var s = !string.IsNullOrWhiteSpace(e.Slug) ? e.Slug! : DataScaffold.ToSlug(e.Name);
            existingBySlug[s] = e;
        }

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
            foreach (var srcField in package.Fields)
            {
                if (srcField.EntityId != oldEntityId) continue;
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
            foreach (var srcIndex in package.Indexes)
            {
                if (srcIndex.EntityId != oldEntityId) continue;
                var newIndex = new IndexDefinition
                {
                    EntityId = newEntity.EntityId,
                    FieldNames = srcIndex.FieldNames,
                    Type = srcIndex.Type
                };

                await store.SaveAsync(newIndex, cancellationToken).ConfigureAwait(false);
            }

            // Import actions that belong to this entity
            foreach (var srcAction in package.Actions)
            {
                if (srcAction.EntityId != oldEntityId) continue;
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
                foreach (var srcCmd in package.ActionCommands)
                {
                    if (srcCmd.ActionId != srcAction.Name) continue;
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
            foreach (var srcReport in package.Reports)
            {
                if (!string.Equals(srcReport.RootEntity, srcEntity.Slug, StringComparison.OrdinalIgnoreCase)) continue;
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
            foreach (var srcAgg in package.Aggregations)
            {
                if (srcAgg.EntityId != oldEntityId) continue;
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
            foreach (var srcSched in package.ScheduledActions)
            {
                if (srcSched.EntityId != oldEntityId) continue;
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

            // Import workflow rules that watch this entity
            foreach (var srcRule in package.WorkflowRules)
            {
                if (!string.Equals(srcRule.SourceEntity, srcEntity.Slug, StringComparison.OrdinalIgnoreCase)) continue;
                var newRule = new DomainEventSubscription
                {
                    Name = srcRule.Name,
                    SourceEntity = newEntity.Slug,
                    WatchField = srcRule.WatchField,
                    FromValue = srcRule.FromValue,
                    TriggerValue = srcRule.TriggerValue,
                    TargetAction = srcRule.TargetAction,
                    TargetResolution = srcRule.TargetResolution,
                    Priority = srcRule.Priority,
                    Enabled = srcRule.Enabled
                };
                await store.SaveAsync(newRule, cancellationToken).ConfigureAwait(false);
            }

            int fieldCount = 0;
            foreach (var f in package.Fields) if (f.EntityId == oldEntityId) fieldCount++;
            int indexCount = 0;
            foreach (var ix in package.Indexes) if (ix.EntityId == oldEntityId) indexCount++;
            int actionCount = 0;
            foreach (var a in package.Actions) if (a.EntityId == oldEntityId) actionCount++;
            int reportCount = 0;
            foreach (var r in package.Reports) if (string.Equals(r.RootEntity, srcEntity.Slug, StringComparison.OrdinalIgnoreCase)) reportCount++;
            int aggCount = 0;
            foreach (var a in package.Aggregations) if (a.EntityId == oldEntityId) aggCount++;
            int ruleCount = 0;
            foreach (var r in package.WorkflowRules) if (string.Equals(r.SourceEntity, srcEntity.Slug, StringComparison.OrdinalIgnoreCase)) ruleCount++;
            logger?.Invoke($"Deployed '{srcEntity.Name}': {fieldCount} field(s), {indexCount} index(es), {actionCount} action(s), {reportCount} report(s), {aggCount} aggregation(s), {ruleCount} workflow rule(s).");
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

        var fields = new List<FieldDefinition>(await store.QueryAsync<FieldDefinition>(entityIdQuery, ct).ConfigureAwait(false));
        foreach (var f in fields)
            await store.DeleteAsync<FieldDefinition>(f.Key, ct).ConfigureAwait(false);

        var idxs = new List<IndexDefinition>(await store.QueryAsync<IndexDefinition>(entityIdQuery, ct).ConfigureAwait(false));
        foreach (var idx in idxs)
            await store.DeleteAsync<IndexDefinition>(idx.Key, ct).ConfigureAwait(false);

        // Also delete actions and their commands
        var actionQuery = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "EntityId", Operator = QueryOperator.Equals, Value = entityDefId } }
        };
        var actions = new List<ActionDefinition>(await store.QueryAsync<ActionDefinition>(actionQuery, ct).ConfigureAwait(false));
        foreach (var action in actions)
        {
            var cmdQuery = new QueryDefinition
            {
                Clauses = { new QueryClause { Field = "ActionId", Operator = QueryOperator.Equals, Value = action.Key } }
            };
            var cmds = new List<ActionCommandDefinition>(await store.QueryAsync<ActionCommandDefinition>(cmdQuery, ct).ConfigureAwait(false));
            foreach (var cmd in cmds)
                await store.DeleteAsync<ActionCommandDefinition>(cmd.Key, ct).ConfigureAwait(false);
            await store.DeleteAsync<ActionDefinition>(action.Key, ct).ConfigureAwait(false);
        }

        // Delete reports whose root entity matches this entity's slug
        var reportQuery = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "RootEntity", Operator = QueryOperator.Equals, Value = entitySlug } }
        };
        var reports = new List<ReportDefinition>(await store.QueryAsync<ReportDefinition>(reportQuery, ct).ConfigureAwait(false));
        foreach (var report in reports)
            await store.DeleteAsync<ReportDefinition>(report.Key, ct).ConfigureAwait(false);

        // Delete aggregation definitions
        var aggs = new List<AggregationDefinition>(await store.QueryAsync<AggregationDefinition>(entityIdQuery, ct).ConfigureAwait(false));
        foreach (var agg in aggs)
            await store.DeleteAsync<AggregationDefinition>(agg.Key, ct).ConfigureAwait(false);

        // Delete scheduled actions
        var scheds = new List<ScheduledActionDefinition>(await store.QueryAsync<ScheduledActionDefinition>(entityIdQuery, ct).ConfigureAwait(false));
        foreach (var sched in scheds)
            await store.DeleteAsync<ScheduledActionDefinition>(sched.Key, ct).ConfigureAwait(false);

        // Delete workflow rules watching this entity
        var rulesQuery = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "SourceEntity", Operator = QueryOperator.Equals, Value = entitySlug } }
        };
        var rules = new List<DomainEventSubscription>(await store.QueryAsync<DomainEventSubscription>(rulesQuery, ct).ConfigureAwait(false));
        foreach (var rule in rules)
            await store.DeleteAsync<DomainEventSubscription>(rule.Key, ct).ConfigureAwait(false);
    }
}
