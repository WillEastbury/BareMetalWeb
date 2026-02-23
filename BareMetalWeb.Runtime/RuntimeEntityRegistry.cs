using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Immutable registry of compiled <see cref="RuntimeEntityModel"/> instances.
/// Populated at startup from persisted <see cref="EntityDefinition"/> records,
/// then frozen — no mutations after <see cref="Freeze"/> is called.
/// Accessible as a global singleton via <see cref="Current"/>.
/// </summary>
public sealed class RuntimeEntityRegistry
{
    private static RuntimeEntityRegistry _current = new RuntimeEntityRegistry();

    private readonly Dictionary<string, RuntimeEntityModel> _bySlug;
    private readonly Dictionary<string, RuntimeEntityModel> _byEntityId;
    private bool _frozen;

    /// <summary>Creates a new, empty, unfrozen registry instance.</summary>
    public RuntimeEntityRegistry()
    {
        _bySlug = new Dictionary<string, RuntimeEntityModel>(StringComparer.OrdinalIgnoreCase);
        _byEntityId = new Dictionary<string, RuntimeEntityModel>(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Global singleton. Replaced atomically by <see cref="BuildAsync"/>.</summary>
    public static RuntimeEntityRegistry Current => _current;

    /// <summary>
    /// Returns all registered models in nav-order.
    /// </summary>
    public IReadOnlyList<RuntimeEntityModel> All
    {
        get
        {
            lock (_bySlug)
            {
                return _bySlug.Values.OrderBy(e => e.NavOrder).ThenBy(e => e.Name).ToList();
            }
        }
    }

    /// <summary>
    /// Looks up a model by entity slug.
    /// </summary>
    public bool TryGet(string slug, out RuntimeEntityModel model)
    {
        lock (_bySlug)
        {
            return _bySlug.TryGetValue(slug, out model!);
        }
    }

    /// <summary>
    /// Looks up a model by stable EntityId.
    /// </summary>
    public bool TryGetById(string entityId, out RuntimeEntityModel model)
    {
        lock (_byEntityId)
        {
            return _byEntityId.TryGetValue(entityId, out model!);
        }
    }

    /// <summary>
    /// Registers a compiled model. Throws if the registry is already frozen.
    /// </summary>
    public void Register(RuntimeEntityModel model)
    {
        if (_frozen)
            throw new InvalidOperationException("RuntimeEntityRegistry is frozen — no further registrations allowed.");

        lock (_bySlug)
        {
            _bySlug[model.Slug] = model;
            _byEntityId[model.EntityId] = model;
        }
    }

    /// <summary>
    /// Freezes the registry, preventing further registrations.
    /// </summary>
    public void Freeze()
    {
        _frozen = true;
    }

    // ── Static factory ─────────────────────────────────────────────────────────

    /// <summary>
    /// Loads all persisted <see cref="EntityDefinition"/> records from
    /// <paramref name="store"/>, compiles them with <paramref name="compiler"/>,
    /// registers each with <see cref="DataScaffold"/> (via
    /// <see cref="DataScaffold.RegisterVirtualEntity"/>) so that existing admin-UI
    /// and API routes work transparently, then freezes the new registry and
    /// installs it as <see cref="Current"/>.
    /// </summary>
    /// <param name="store">The data store to load schema records from.</param>
    /// <param name="compiler">Compiler instance to use.</param>
    /// <param name="dataRootPath">Root path for virtual entity JSON storage.</param>
    /// <param name="logger">Optional logger for warnings.</param>
    public static async Task<RuntimeEntityRegistry> BuildAsync(
        IDataObjectStore store,
        IRuntimeEntityCompiler compiler,
        string dataRootPath,
        Action<string>? logger = null)
    {
        var registry = new RuntimeEntityRegistry();
        var jsonStore = new VirtualEntityJsonStore(dataRootPath);

        // Load all schema records in parallel
        var entityDefs = (await store.QueryAsync<EntityDefinition>().ConfigureAwait(false)).ToList();
        if (entityDefs.Count == 0)
        {
            registry.Freeze();
            _current = registry;
            return registry;
        }

        var allFields = (await store.QueryAsync<FieldDefinition>().ConfigureAwait(false)).ToList();
        var allIndexes = (await store.QueryAsync<IndexDefinition>().ConfigureAwait(false)).ToList();
        var allActions = (await store.QueryAsync<ActionDefinition>().ConfigureAwait(false)).ToList();

        foreach (var entityDef in entityDefs)
        {
            // Ensure EntityId is populated (falls back to Id on first load)
            if (string.IsNullOrWhiteSpace(entityDef.EntityId))
                entityDef.EntityId = entityDef.Id;

            var entityFields = allFields
                .Where(f => string.Equals(f.EntityId, entityDef.Id, StringComparison.OrdinalIgnoreCase))
                .ToList();
            var entityIndexes = allIndexes
                .Where(i => string.Equals(i.EntityId, entityDef.Id, StringComparison.OrdinalIgnoreCase))
                .ToList();
            var entityActions = allActions
                .Where(a => string.Equals(a.EntityId, entityDef.Id, StringComparison.OrdinalIgnoreCase))
                .ToList();

            // Ensure FieldId populated
            foreach (var f in entityFields)
                if (string.IsNullOrWhiteSpace(f.FieldId))
                    f.FieldId = f.Id;

            var model = compiler.Compile(entityDef, entityFields, entityIndexes, entityActions,
                out var warnings);

            foreach (var w in warnings)
                logger?.Invoke(w);

            if (model == null)
                continue;

            registry.Register(model);

            // Register with DataScaffold so existing admin-UI/API routes work
            var entityMetadata = model.ToEntityMetadata(jsonStore);
            DataScaffold.RegisterVirtualEntity(entityMetadata);

            // Persist schema hash + version back to EntityDefinition if changed
            if (!string.Equals(entityDef.SchemaHash, model.SchemaHash, StringComparison.Ordinal))
            {
                entityDef.SchemaHash = model.SchemaHash;
                try
                {
                    await store.SaveAsync(entityDef).ConfigureAwait(false);
                    logger?.Invoke($"Schema hash updated for '{entityDef.Name}' (version {entityDef.Version}).");
                }
                catch (Exception ex)
                {
                    // Non-fatal — hash update is best-effort
                    logger?.Invoke($"Warning: could not persist schema hash for '{entityDef.Name}': {ex.Message}");
                }
            }
        }

        registry.Freeze();
        _current = registry;
        return registry;
    }
}
