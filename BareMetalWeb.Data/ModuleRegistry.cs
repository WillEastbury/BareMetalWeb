using System.Text.Json;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Module registry that manages module boundaries, validates isolation constraints,
/// and provides import/export capabilities for portable module packages.
/// </summary>
public static class ModuleRegistry
{
    private static volatile int _generation;
    private static volatile int _cachedGeneration = -1;
    private static volatile IReadOnlyList<ModuleInfo> _cachedModules = Array.Empty<ModuleInfo>();
    private static readonly object _cacheLock = new();

    /// <summary>Invalidate the module cache (call after module entity save).</summary>
    public static void Invalidate() => Interlocked.Increment(ref _generation);

    /// <summary>Get all registered modules.</summary>
    public static async ValueTask<IReadOnlyList<ModuleInfo>> GetModulesAsync(CancellationToken ct)
    {
        var gen = _generation;
        if (gen == _cachedGeneration) return _cachedModules;

        if (!DataScaffold.TryGetEntity("modules", out var meta))
            return Array.Empty<ModuleInfo>();

        var items = await meta.Handlers.QueryAsync(null, ct);
        var modules = new List<ModuleInfo>();

        foreach (var item in items)
        {
            var enabled = GetField(item, meta, "Enabled");
            modules.Add(new ModuleInfo(
                ModuleId: GetField(item, meta, "ModuleId"),
                Name: GetField(item, meta, "Name"),
                Version: GetField(item, meta, "Version"),
                EntitySlugs: SplitCsv(GetField(item, meta, "EntitySlugs")),
                ActionKeys: SplitCsv(GetField(item, meta, "ActionKeys")),
                ReportSlugs: SplitCsv(GetField(item, meta, "ReportSlugs")),
                RequiredPermissions: SplitCsv(GetField(item, meta, "RequiredPermissions")),
                NavGroup: GetField(item, meta, "NavGroup"),
                Dependencies: SplitCsv(GetField(item, meta, "Dependencies")),
                Isolation: GetField(item, meta, "Isolation"),
                Enabled: !string.Equals(enabled, "False", StringComparison.OrdinalIgnoreCase)));
        }

        lock (_cacheLock)
        {
            _cachedModules = modules;
            _cachedGeneration = gen;
        }

        return modules;
    }

    /// <summary>Check if an entity slug belongs to an enabled module (or is unowned).</summary>
    public static async ValueTask<bool> IsEntityEnabledAsync(string entitySlug, CancellationToken ct)
    {
        var modules = await GetModulesAsync(ct);

        // If no modules defined, everything is enabled
        if (modules.Count == 0) return true;

        // Find owning module
        ModuleInfo? owner = null;
        foreach (var m in modules)
        {
            bool found = false;
            foreach (var slug in m.EntitySlugs)
            {
                if (StringComparer.OrdinalIgnoreCase.Equals(slug, entitySlug))
                {
                    found = true;
                    break;
                }
            }
            if (found)
            {
                owner = m;
                break;
            }
        }

        // Unowned entities are always enabled
        if (owner == null) return true;

        return owner.Enabled;
    }

    /// <summary>
    /// Validate module isolation constraints.
    /// Returns a list of violations (empty = valid).
    /// </summary>
    public static async ValueTask<IReadOnlyList<string>> ValidateIsolationAsync(CancellationToken ct)
    {
        var modules = await GetModulesAsync(ct);
        var violations = new List<string>();

        // Build entity→module ownership map
        var entityOwner = new Dictionary<string, ModuleInfo>(StringComparer.OrdinalIgnoreCase);
        foreach (var mod in modules)
        {
            foreach (var slug in mod.EntitySlugs)
                entityOwner[slug] = mod;
        }

        // Check isolated modules don't reference external entities
        foreach (var mod in modules)
        {
            if (!string.Equals(mod.Isolation, "isolated", StringComparison.OrdinalIgnoreCase))
                continue;

            foreach (var slug in mod.EntitySlugs)
            {
                if (!DataScaffold.TryGetEntity(slug, out var meta)) continue;

                foreach (var field in meta.Fields)
                {
                    if (field.Lookup == null) continue;
                    // Resolve target entity slug from lookup type
                    string? lookupSlug = null;
                    foreach (var e in DataScaffold.Entities)
                    {
                        if (e.Type == field.Lookup.TargetType)
                        {
                            lookupSlug = e.Slug;
                            break;
                        }
                    }
                    if (string.IsNullOrEmpty(lookupSlug)) continue;

                    if (entityOwner.TryGetValue(lookupSlug, out var targetModule) &&
                        !string.Equals(targetModule.ModuleId, mod.ModuleId, StringComparison.OrdinalIgnoreCase))
                    {
                        violations.Add(
                            $"Isolation violation: {mod.ModuleId}/{slug}.{field.Name} references " +
                            $"{targetModule.ModuleId}/{lookupSlug}");
                    }
                }
            }
        }

        // Check dependencies are satisfied
        foreach (var mod in modules)
        {
            if (!mod.Enabled)
                continue;

            foreach (var dep in mod.Dependencies)
            {
                ModuleInfo? depMod = null;
                foreach (var m in modules)
                {
                    if (string.Equals(m.ModuleId, dep, StringComparison.OrdinalIgnoreCase))
                    {
                        depMod = m;
                        break;
                    }
                }

                if (depMod == null)
                    violations.Add($"Missing dependency: {mod.ModuleId} requires {dep} (not found)");
                else if (!depMod.Enabled)
                    violations.Add($"Disabled dependency: {mod.ModuleId} requires {dep} (disabled)");
            }
        }

        return violations;
    }

    /// <summary>
    /// Export a module as a JSON package containing its entity schemas,
    /// action definitions, and report definitions.
    /// </summary>
    public static async ValueTask<ModulePackage> ExportAsync(string moduleId, CancellationToken ct)
    {
        var modules = await GetModulesAsync(ct);
        ModuleInfo? mod = null;
        foreach (var m in modules)
        {
            if (string.Equals(m.ModuleId, moduleId, StringComparison.OrdinalIgnoreCase))
            {
                mod = m;
                break;
            }
        }
        if (mod == null) throw new InvalidOperationException($"Module '{moduleId}' not found.");

        var schemas = new List<ModuleEntitySchema>();
        foreach (var slug in mod.EntitySlugs)
        {
            if (!DataScaffold.TryGetEntity(slug, out var meta)) continue;
            var fieldSchemas = new List<ModuleFieldSchema>();
            foreach (var f in meta.Fields)
                fieldSchemas.Add(new ModuleFieldSchema(f.Name, f.Label, f.FieldType.ToString(), f.Required, f.IsIndexed));
            schemas.Add(new ModuleEntitySchema(
                Slug: slug,
                EntityName: meta.Name,
                Fields: fieldSchemas));
        }

        return new ModulePackage(
            ModuleId: mod.ModuleId,
            Name: mod.Name,
            Version: mod.Version,
            Schemas: schemas,
            ActionKeys: mod.ActionKeys,
            ReportSlugs: mod.ReportSlugs,
            RequiredPermissions: mod.RequiredPermissions,
            Dependencies: mod.Dependencies);
    }

    private static string GetField(BaseDataObject obj, DataEntityMetadata meta, string fieldName)
    {
        DataFieldMetadata? field = null;
        foreach (var f in meta.Fields)
        {
            if (string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase))
            {
                field = f;
                break;
            }
        }
        return field?.GetValueFn?.Invoke(obj)?.ToString() ?? string.Empty;
    }

    private static IReadOnlyList<string> SplitCsv(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return Array.Empty<string>();
        return value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}

/// <summary>Cached module info (lightweight, immutable).</summary>
public sealed record ModuleInfo(
    string ModuleId, string Name, string Version,
    IReadOnlyList<string> EntitySlugs, IReadOnlyList<string> ActionKeys,
    IReadOnlyList<string> ReportSlugs, IReadOnlyList<string> RequiredPermissions,
    string NavGroup, IReadOnlyList<string> Dependencies, string Isolation, bool Enabled);

/// <summary>Portable module package for import/export.</summary>
public sealed record ModulePackage(
    string ModuleId, string Name, string Version,
    IReadOnlyList<ModuleEntitySchema> Schemas,
    IReadOnlyList<string> ActionKeys, IReadOnlyList<string> ReportSlugs,
    IReadOnlyList<string> RequiredPermissions, IReadOnlyList<string> Dependencies);

public sealed record ModuleEntitySchema(
    string Slug, string EntityName, IReadOnlyList<ModuleFieldSchema> Fields);

public sealed record ModuleFieldSchema(
    string Name, string Label, string FieldType, bool Required, bool Indexed);
