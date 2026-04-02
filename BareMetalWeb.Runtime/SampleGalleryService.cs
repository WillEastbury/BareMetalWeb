using System;
using System.Collections.Generic;
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
    // ── Package loading ──────────────────────────────────────────────────────

    /// <summary>
    /// Returns the list of all built-in <see cref="SamplePackage"/> instances
    /// loaded from the embedded JSON resource files in this assembly.
    /// </summary>
    public static IReadOnlyList<SamplePackage> GetAllPackages()
    {
        EnsurePackageTypesRegistered();

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

            var pkg = SamplePackageJson.Deserialize(stream);
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
        EnsurePackageTypesRegistered();

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

        return SamplePackageJson.Deserialize(stream);
    }

    // ── Registration ────────────────────────────────────────────────────────

    private static int _registered;

    /// <summary>
    /// Ensures the package definition entity types (EntityDefinition, FieldDefinition, etc.)
    /// are registered with DataScaffold. Called once, idempotent.
    /// </summary>
    private static void EnsurePackageTypesRegistered()
    {
        if (Interlocked.CompareExchange(ref _registered, 1, 0) != 0)
            return;

        DataScaffold.RegisterEntity("EntityDefinition", SystemEntitySchemas.EntityDefinition,
            DataScaffold.BuildStoreHandlers("EntityDefinition", () => new EntityDefinition()));
        DataScaffold.RegisterEntity("FieldDefinition", SystemEntitySchemas.FieldDefinition,
            DataScaffold.BuildStoreHandlers("FieldDefinition", () => new FieldDefinition()));
        DataScaffold.RegisterEntity("IndexDefinition", SystemEntitySchemas.IndexDefinition,
            DataScaffold.BuildStoreHandlers("IndexDefinition", () => new IndexDefinition()));

        BinaryObjectSerializer.RegisterKnownType(typeof(EntityDefinition), () => new EntityDefinition());
        BinaryObjectSerializer.RegisterKnownType(typeof(FieldDefinition), () => new FieldDefinition());
        BinaryObjectSerializer.RegisterKnownType(typeof(IndexDefinition), () => new IndexDefinition());
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
        var deployedSlugs = new List<string>();

        // Load existing EntityDefinitions so we can skip or overwrite
        var existingDefs = (await store.QueryAsync("EntityDefinition", null, cancellationToken)
            .ConfigureAwait(false)).Cast<EntityDefinition>().ToList();

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

            await store.SaveAsync(newEntity.EntityTypeName, newEntity, cancellationToken).ConfigureAwait(false);

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

                await store.SaveAsync(newField.EntityTypeName, newField, cancellationToken).ConfigureAwait(false);
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

                await store.SaveAsync(newIndex.EntityTypeName, newIndex, cancellationToken).ConfigureAwait(false);
            }

            // Import actions that belong to this entity
            if (DataScaffold.TryGetEntity("action-definitions", out var actionMeta))
            {
                foreach (var srcAction in package.Actions)
                {
                    if (F(actionMeta, srcAction, "EntityId") != oldEntityId) continue;
                    var newAction = (DataRecord)actionMeta.Handlers.Create();
                    CopyFields(actionMeta, srcAction, newAction);
                    actionMeta.FindField("EntityId")?.SetValueFn(newAction, newEntity.EntityId);
                    await DataScaffold.ApplyAutoIdAsync(actionMeta, newAction, cancellationToken).ConfigureAwait(false);
                    await actionMeta.Handlers.SaveAsync(newAction, cancellationToken).ConfigureAwait(false);

                    // Import action commands that belong to this action (matched by Name)
                    if (DataScaffold.TryGetEntity("action-commands", out var cmdMeta))
                    {
                        foreach (var srcCmd in package.ActionCommands)
                        {
                            if (F(cmdMeta, srcCmd, "ActionId") != F(actionMeta, srcAction, "Name")) continue;
                            var newCmd = (DataRecord)cmdMeta.Handlers.Create();
                            CopyFields(cmdMeta, srcCmd, newCmd);
                            cmdMeta.FindField("ActionId")?.SetValueFn(newCmd, newAction.Key.ToString());
                            await DataScaffold.ApplyAutoIdAsync(cmdMeta, newCmd, cancellationToken).ConfigureAwait(false);
                            await cmdMeta.Handlers.SaveAsync(newCmd, cancellationToken).ConfigureAwait(false);
                        }
                    }
                }
            }

            // Import reports that reference this entity slug
            if (DataScaffold.TryGetEntity("report-definitions", out var reportMeta))
            {
                foreach (var srcReport in package.Reports)
                {
                    if (!string.Equals(srcReport.RootEntity, srcEntity.Slug, StringComparison.OrdinalIgnoreCase)) continue;
                    var newReport = (DataRecord)reportMeta.Handlers.Create();
                    reportMeta.FindField("Name")?.SetValueFn(newReport, srcReport.Name);
                    reportMeta.FindField("Description")?.SetValueFn(newReport, srcReport.Description);
                    reportMeta.FindField("RootEntity")?.SetValueFn(newReport, newEntity.Slug);
                    reportMeta.FindField("ColumnsJson")?.SetValueFn(newReport, srcReport.ColumnsJson);
                    reportMeta.FindField("FiltersJson")?.SetValueFn(newReport, srcReport.FiltersJson);
                    reportMeta.FindField("ParametersJson")?.SetValueFn(newReport, srcReport.ParametersJson);
                    reportMeta.FindField("SortField")?.SetValueFn(newReport, srcReport.SortField);
                    reportMeta.FindField("SortDescending")?.SetValueFn(newReport, srcReport.SortDescending);
                    await DataScaffold.ApplyAutoIdAsync(reportMeta, newReport, cancellationToken).ConfigureAwait(false);
                    await reportMeta.Handlers.SaveAsync(newReport, cancellationToken).ConfigureAwait(false);
                }
            }

            // Import aggregation definitions for this entity
            if (DataScaffold.TryGetEntity("aggregation-definitions", out var aggMeta))
            {
                foreach (var srcAgg in package.Aggregations)
                {
                    if (F(aggMeta, srcAgg, "EntityId") != oldEntityId) continue;
                    var newAgg = (DataRecord)aggMeta.Handlers.Create();
                    CopyFields(aggMeta, srcAgg, newAgg);
                    aggMeta.FindField("EntityId")?.SetValueFn(newAgg, newEntity.EntityId);
                    await DataScaffold.ApplyAutoIdAsync(aggMeta, newAgg, cancellationToken).ConfigureAwait(false);
                    await aggMeta.Handlers.SaveAsync(newAgg, cancellationToken).ConfigureAwait(false);
                }
            }

            // Import scheduled action definitions for this entity
            if (DataScaffold.TryGetEntity("scheduled-actions", out var schedMeta))
            {
                foreach (var srcSched in package.ScheduledActions)
                {
                    if (F(schedMeta, srcSched, "EntityId") != oldEntityId) continue;
                    var newSched = (DataRecord)schedMeta.Handlers.Create();
                    CopyFields(schedMeta, srcSched, newSched);
                    schedMeta.FindField("EntityId")?.SetValueFn(newSched, newEntity.EntityId);
                    await DataScaffold.ApplyAutoIdAsync(schedMeta, newSched, cancellationToken).ConfigureAwait(false);
                    await schedMeta.Handlers.SaveAsync(newSched, cancellationToken).ConfigureAwait(false);
                }
            }

            // Import workflow rules that watch this entity
            if (DataScaffold.TryGetEntity("domain-event-subscriptions", out var ruleMeta))
            {
                foreach (var srcRule in package.WorkflowRules)
                {
                    if (!string.Equals(F(ruleMeta, srcRule, "SourceEntity"), srcEntity.Slug, StringComparison.OrdinalIgnoreCase)) continue;
                    var newRule = (DataRecord)ruleMeta.Handlers.Create();
                    CopyFields(ruleMeta, srcRule, newRule);
                    ruleMeta.FindField("SourceEntity")?.SetValueFn(newRule, newEntity.Slug);
                    await DataScaffold.ApplyAutoIdAsync(ruleMeta, newRule, cancellationToken).ConfigureAwait(false);
                    await ruleMeta.Handlers.SaveAsync(newRule, cancellationToken).ConfigureAwait(false);
                }
            }

            int fieldCount = 0;
            foreach (var f in package.Fields) if (f.EntityId == oldEntityId) fieldCount++;
            int indexCount = 0;
            foreach (var ix in package.Indexes) if (ix.EntityId == oldEntityId) indexCount++;
            int actionCount = 0;
            if (DataScaffold.TryGetEntity("action-definitions", out var actCountMeta))
                foreach (var a in package.Actions) if (F(actCountMeta, a, "EntityId") == oldEntityId) actionCount++;
            int reportCount = 0;
            foreach (var r in package.Reports) if (string.Equals(r.RootEntity, srcEntity.Slug, StringComparison.OrdinalIgnoreCase)) reportCount++;
            int aggCount = 0;
            if (DataScaffold.TryGetEntity("aggregation-definitions", out var aggCountMeta))
                foreach (var a in package.Aggregations) if (F(aggCountMeta, a, "EntityId") == oldEntityId) aggCount++;
            int ruleCount = 0;
            if (DataScaffold.TryGetEntity("domain-event-subscriptions", out var ruleCountMeta))
                foreach (var rule in package.WorkflowRules) if (string.Equals(F(ruleCountMeta, rule, "SourceEntity"), srcEntity.Slug, StringComparison.OrdinalIgnoreCase)) ruleCount++;
            logger?.Invoke($"Deployed '{srcEntity.Name}': {fieldCount} field(s), {indexCount} index(es), {actionCount} action(s), {reportCount} report(s), {aggCount} aggregation(s), {ruleCount} workflow rule(s).");
            deployed.Add(srcEntity.Name);
            deployedSlugs.Add(slug);
        }

        // Deploy package-level RBAC definitions + auto-generate defaults for each deployed entity
        await DeployRbacAsync(package, deployedSlugs, store, logger, cancellationToken).ConfigureAwait(false);

        return deployed;
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static async Task DeployRbacAsync(
        SamplePackage package,
        IReadOnlyList<string> deployedSlugs,
        IDataObjectStore store,
        Action<string>? logger,
        CancellationToken ct)
    {
        if (!DataScaffold.TryGetEntity("permissions", out var permMeta))
            return;

        // Track which entity slugs already have explicit package-defined permissions
        var coveredSlugs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Deploy explicit package permissions
        if (package.Permissions.Count > 0)
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
                    await DataScaffold.ApplyAutoIdAsync(permMeta, rec, ct).ConfigureAwait(false);
                    await DataScaffold.SaveAsync(permMeta, rec, ct).ConfigureAwait(false);
                }
                if (!string.IsNullOrEmpty(srcPerm.TargetEntity) && srcPerm.TargetEntity != "*")
                    coveredSlugs.Add(srcPerm.TargetEntity);
            }
            logger?.Invoke($"Deployed {package.Permissions.Count} explicit permission(s).");
        }

        // Deploy explicit package roles
        DataScaffold.TryGetEntity("roles", out var roleMeta);
        if (package.Roles.Count > 0 && roleMeta != null)
        {
            foreach (var srcRole in package.Roles)
            {
                var rec = roleMeta.Handlers.Create();
                if (rec is DataRecord dr && dr.Schema != null)
                {
                    dr.SetField(dr.Schema, "RoleName", srcRole.RoleName);
                    dr.SetField(dr.Schema, "Description", srcRole.Description);
                    dr.SetField(dr.Schema, "PermissionCodes", srcRole.PermissionCodes);
                    await DataScaffold.ApplyAutoIdAsync(roleMeta, rec, ct).ConfigureAwait(false);
                    await DataScaffold.SaveAsync(roleMeta, rec, ct).ConfigureAwait(false);
                }
            }
            logger?.Invoke($"Deployed {package.Roles.Count} explicit role(s).");
        }

        // Auto-generate default CRUD permissions + admin role for each deployed entity
        // that doesn't already have explicit package permissions
        var allNewPermCodes = new List<string>();
        string[] crudActions = { "Read", "Create", "Update", "Delete" };

        foreach (var slug in deployedSlugs)
        {
            if (coveredSlugs.Contains(slug))
                continue;

            var entityPermCodes = new List<string>(4);
            foreach (var action in crudActions)
            {
                var code = $"{slug}.{action.ToLowerInvariant()}";
                entityPermCodes.Add(code);

                var rec = permMeta.Handlers.Create();
                if (rec is DataRecord dr && dr.Schema != null)
                {
                    dr.SetField(dr.Schema, "Code", code);
                    dr.SetField(dr.Schema, "Description", $"{action} access for {slug}");
                    dr.SetField(dr.Schema, "TargetEntity", slug);
                    dr.SetField(dr.Schema, "Actions", action);
                    dr.SetField(dr.Schema, "RequiresElevation", false);
                    await DataScaffold.ApplyAutoIdAsync(permMeta, rec, ct).ConfigureAwait(false);
                    await DataScaffold.SaveAsync(permMeta, rec, ct).ConfigureAwait(false);
                }
            }
            allNewPermCodes.AddRange(entityPermCodes);

            // Create an admin role for this entity with all CRUD permissions
            if (roleMeta != null)
            {
                var roleRec = roleMeta.Handlers.Create();
                if (roleRec is DataRecord dr && dr.Schema != null)
                {
                    dr.SetField(dr.Schema, "RoleName", $"{slug}-admin");
                    dr.SetField(dr.Schema, "Description", $"Full access to {slug}");
                    dr.SetField(dr.Schema, "PermissionCodes", string.Join(",", entityPermCodes));
                    await DataScaffold.ApplyAutoIdAsync(roleMeta, roleRec, ct).ConfigureAwait(false);
                    await DataScaffold.SaveAsync(roleMeta, roleRec, ct).ConfigureAwait(false);
                }
            }

            logger?.Invoke($"Auto-created CRUD permissions and admin role for '{slug}'.");
        }

        // Also include any explicit package permission codes for admin grant
        foreach (var srcPerm in package.Permissions)
        {
            if (!string.IsNullOrEmpty(srcPerm.Code))
                allNewPermCodes.Add(srcPerm.Code);
        }

        // Grant all new permission codes to admin users
        if (allNewPermCodes.Count > 0)
            await GrantPermissionsToAdminUsersAsync(store, allNewPermCodes, logger, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Finds all users with "admin" permission and adds the specified permission codes
    /// to their Permissions array if not already present.
    /// </summary>
    private static async Task GrantPermissionsToAdminUsersAsync(
        IDataObjectStore store,
        List<string> permCodes,
        Action<string>? logger,
        CancellationToken ct)
    {
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "Permissions", Operator = QueryOperator.Contains, Value = "admin" }
            }
        };

        var userMeta = UserAuthHelper.GetUserMeta();
        int grantCount = 0;
        if (userMeta != null)
        {
            var users = await userMeta.Handlers.QueryAsync(query, ct).ConfigureAwait(false);
            var permissionsField = userMeta.FindField("Permissions");

            foreach (var user in users)
            {
                if (user is null || !UserAuthHelper.GetIsActive(user, userMeta)) continue;

                var perms = new List<string>(UserAuthHelper.GetPermissions(user, userMeta));
                bool changed = false;

                foreach (var code in permCodes)
                {
                    if (string.IsNullOrWhiteSpace(code)) continue;
                    bool alreadyHas = false;
                    foreach (var p in perms)
                    {
                        if (string.Equals(p, code, StringComparison.OrdinalIgnoreCase))
                        {
                            alreadyHas = true;
                            break;
                        }
                    }
                    if (!alreadyHas)
                    {
                        perms.Add(code);
                        changed = true;
                    }
                }

                if (!changed) continue;

                permissionsField?.SetValueFn(user, perms.ToArray());
                await userMeta.Handlers.SaveAsync(user, ct).ConfigureAwait(false);
                grantCount++;
            }
        }

        if (grantCount > 0)
            logger?.Invoke($"Granted {permCodes.Count} permission(s) to {grantCount} admin user(s).");

        // Invalidate the permission resolver cache so changes take effect immediately
        PermissionResolver.Invalidate();
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

        var fields = (await store.QueryAsync("FieldDefinition", entityIdQuery, ct).ConfigureAwait(false)).Cast<FieldDefinition>().ToList();
        foreach (var f in fields)
            await store.DeleteAsync("FieldDefinition", f.Key, ct).ConfigureAwait(false);

        var idxs = (await store.QueryAsync("IndexDefinition", entityIdQuery, ct).ConfigureAwait(false)).Cast<IndexDefinition>().ToList();
        foreach (var idx in idxs)
            await store.DeleteAsync("IndexDefinition", idx.Key, ct).ConfigureAwait(false);

        // Also delete actions and their commands
        var actionQuery = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "EntityId", Operator = QueryOperator.Equals, Value = entityDefId } }
        };
        if (DataScaffold.TryGetEntity("action-definitions", out var actionMeta2))
        {
            var actions = new List<DataRecord>(await actionMeta2.Handlers.QueryAsync(actionQuery, ct).ConfigureAwait(false));
            foreach (var action in actions)
            {
                if (DataScaffold.TryGetEntity("action-commands", out var cmdMeta2))
                {
                    var cmdQuery = new QueryDefinition
                    {
                        Clauses = { new QueryClause { Field = "ActionId", Operator = QueryOperator.Equals, Value = action.Key } }
                    };
                    var cmds = new List<DataRecord>(await cmdMeta2.Handlers.QueryAsync(cmdQuery, ct).ConfigureAwait(false));
                    foreach (var cmd in cmds)
                        await cmdMeta2.Handlers.DeleteAsync(cmd.Key, ct).ConfigureAwait(false);
                }
                await actionMeta2.Handlers.DeleteAsync(action.Key, ct).ConfigureAwait(false);
            }
        }

        // Delete reports whose root entity matches this entity's slug
        var reportQuery = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "RootEntity", Operator = QueryOperator.Equals, Value = entitySlug } }
        };
        if (DataScaffold.TryGetEntity("report-definitions", out var reportMeta2))
        {
            var reports = new List<DataRecord>(await reportMeta2.Handlers.QueryAsync(reportQuery, ct).ConfigureAwait(false));
            foreach (var report in reports)
                await reportMeta2.Handlers.DeleteAsync(report.Key, ct).ConfigureAwait(false);
        }

        // Delete aggregation definitions
        if (DataScaffold.TryGetEntity("aggregation-definitions", out var aggMeta2))
        {
            var aggs = new List<DataRecord>(await aggMeta2.Handlers.QueryAsync(entityIdQuery, ct).ConfigureAwait(false));
            foreach (var agg in aggs)
                await aggMeta2.Handlers.DeleteAsync(agg.Key, ct).ConfigureAwait(false);
        }

        // Delete scheduled actions
        if (DataScaffold.TryGetEntity("scheduled-actions", out var schedMeta))
        {
            var scheds = new List<DataRecord>(await schedMeta.Handlers.QueryAsync(entityIdQuery, ct).ConfigureAwait(false));
            foreach (var sched in scheds)
                await schedMeta.Handlers.DeleteAsync(sched.Key, ct).ConfigureAwait(false);
        }

        // Delete workflow rules watching this entity
        var rulesQuery = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "SourceEntity", Operator = QueryOperator.Equals, Value = entitySlug } }
        };
        if (DataScaffold.TryGetEntity("domain-event-subscriptions", out var ruleMeta))
        {
            var rules = new List<DataRecord>(await ruleMeta.Handlers.QueryAsync(rulesQuery, ct).ConfigureAwait(false));
            foreach (var rule in rules)
                await ruleMeta.Handlers.DeleteAsync(rule.Key, ct).ConfigureAwait(false);
        }
    }

    /// <summary>Read a field value as string from a DataRecord using metadata.</summary>
    private static string F(DataEntityMetadata meta, DataRecord obj, string fieldName)
        => meta.FindField(fieldName)?.GetValueFn(obj)?.ToString() ?? string.Empty;

    /// <summary>Copy all non-core field values from source to target using metadata.</summary>
    private static void CopyFields(DataEntityMetadata meta, DataRecord source, DataRecord target)
    {
        foreach (var field in meta.Fields)
        {
            var val = field.GetValueFn(source);
            if (val != null)
                field.SetValueFn(target, val);
        }
    }
}
