using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Runtime;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Shared test fixture that compiles all gallery sample packages from JSON
/// and registers them with DataScaffold. Mirror of Data.Tests.GalleryTestFixture.
/// </summary>
internal static class HostGalleryTestFixture
{
    private static readonly Lazy<FixtureState> _state = new(Initialize);

    public static FixtureState State => _state.Value;

    private static FixtureState Initialize()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"bmw-host-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        // Register system entities first (non-generic, schema-driven)
        DataScaffold.RegisterEntity("AppSetting", SystemEntitySchemas.AppSetting,
            DataScaffold.BuildStoreHandlers("AppSetting", () => SystemEntitySchemas.AppSetting.CreateRecord()));
        DataScaffold.RegisterEntity("User", SystemEntitySchemas.User,
            DataScaffold.BuildStoreHandlers("User", () => SystemEntitySchemas.User.CreateRecord()));
        DataScaffold.RegisterEntity("AuditEntry", SystemEntitySchemas.AuditEntry,
            DataScaffold.BuildStoreHandlers("AuditEntry", () => SystemEntitySchemas.AuditEntry.CreateRecord()));
        DataScaffold.RegisterEntity("ReportDefinition", SystemEntitySchemas.ReportDefinition,
            DataScaffold.BuildStoreHandlers("ReportDefinition", () => SystemEntitySchemas.ReportDefinition.CreateRecord()));
        DataScaffold.RegisterEntity("EntityDefinition", SystemEntitySchemas.EntityDefinition,
            DataScaffold.BuildStoreHandlers("EntityDefinition", () => SystemEntitySchemas.EntityDefinition.CreateRecord()));
        DataScaffold.RegisterEntity("FieldDefinition", SystemEntitySchemas.FieldDefinition,
            DataScaffold.BuildStoreHandlers("FieldDefinition", () => SystemEntitySchemas.FieldDefinition.CreateRecord()));
        DataScaffold.RegisterEntity("IndexDefinition", SystemEntitySchemas.IndexDefinition,
            DataScaffold.BuildStoreHandlers("IndexDefinition", () => SystemEntitySchemas.IndexDefinition.CreateRecord()));
        DataScaffold.RegisterEntity("ActionDefinition", SystemEntitySchemas.ActionDefinition,
            DataScaffold.BuildStoreHandlers("ActionDefinition", () => SystemEntitySchemas.ActionDefinition.CreateRecord()));
        DataScaffold.RegisterEntity("ActionCommandDefinition", SystemEntitySchemas.ActionCommandDefinition,
            DataScaffold.BuildStoreHandlers("ActionCommandDefinition", () => SystemEntitySchemas.ActionCommandDefinition.CreateRecord()));

        BinaryObjectSerializer.RegisterKnownType(typeof(DataRecord), () => new DataRecord());

        var compiler = new RuntimeEntityCompiler();
        var walProvider = new WalDataProvider(tempDir);
        var registry = new RuntimeEntityRegistry();
        var packages = SampleGalleryService.GetAllPackages();

        var compiledModels = new List<RuntimeEntityModel>();
        foreach (var pkg in packages)
        {
            foreach (var srcEntity in pkg.Entities)
            {
                var entityId = srcEntity.EntityId;
                var entityFields = pkg.Fields
                    .Where(f => string.Equals(f.EntityId, entityId, StringComparison.OrdinalIgnoreCase))
                    .ToList();
                var entityIndexes = pkg.Indexes
                    .Where(i => string.Equals(i.EntityId, entityId, StringComparison.OrdinalIgnoreCase))
                    .ToList();

                var model = compiler.Compile(srcEntity, entityFields, entityIndexes,
                    Array.Empty<ActionDefinition>(), Array.Empty<ActionCommandDefinition>(),
                    out _);
                if (model == null) continue;

                registry.Register(model);
                compiledModels.Add(model);

                var schema = EntitySchemaFactory.FromModel(model);
                var entityMetadata = model.ToEntityMetadata(walProvider, schema);
                DataScaffold.RegisterVirtualEntity(entityMetadata);
            }
        }

        foreach (var model in compiledModels)
        {
            if (model.Fields.Any(f => f.FieldType == Rendering.Models.FormFieldType.LookupList
                && !string.IsNullOrWhiteSpace(f.LookupEntitySlug)))
            {
                var schema = EntitySchemaFactory.FromModel(model);
                var updated = model.ToEntityMetadata(walProvider, schema);
                DataScaffold.RegisterVirtualEntity(updated);
            }
        }

        // Re-register entities with ChildList fields so child entity lookups succeed
        foreach (var model in compiledModels)
        {
            if (model.Fields.Any(f => f.FieldType == Rendering.Models.FormFieldType.ChildList
                && !string.IsNullOrWhiteSpace(f.ChildEntitySlug)))
            {
                var schema = EntitySchemaFactory.FromModel(model);
                var updated = model.ToEntityMetadata(walProvider, schema);
                DataScaffold.RegisterVirtualEntity(updated);
            }
        }

        // Snapshot all virtual entity metadata so tests can restore after static-state pollution
        var allVirtualEntities = new List<DataEntityMetadata>();
        foreach (var model in compiledModels)
        {
            var schema = EntitySchemaFactory.FromModel(model);
            allVirtualEntities.Add(model.ToEntityMetadata(walProvider, schema));
        }

        registry.Freeze();

        return new FixtureState(tempDir, registry, allVirtualEntities);
    }

    /// <summary>
    /// Re-registers all gallery virtual entities with DataScaffold.
    /// Call this from tests that depend on gallery metadata when other tests
    /// in the same process may overwrite shared static state.
    /// </summary>
    public static void ReRegisterVirtualEntities()
    {
        var state = State;
        foreach (var meta in state.VirtualEntities)
            DataScaffold.RegisterVirtualEntity(meta);
    }

    public sealed class FixtureState : IDisposable
    {
        public string DataRoot { get; }
        public RuntimeEntityRegistry Registry { get; }
        internal IReadOnlyList<DataEntityMetadata> VirtualEntities { get; }

        public FixtureState(string dataRoot, RuntimeEntityRegistry registry, IReadOnlyList<DataEntityMetadata> virtualEntities)
        {
            DataRoot = dataRoot;
            Registry = registry;
            VirtualEntities = virtualEntities;
        }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(DataRoot))
                    Directory.Delete(DataRoot, recursive: true);
            }
            catch { }
        }
    }
}
