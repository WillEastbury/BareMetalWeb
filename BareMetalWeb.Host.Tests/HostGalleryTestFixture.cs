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

        // Register system entities first
        DataScaffold.RegisterEntity<AppSetting>();
        DataScaffold.RegisterEntity<User>();
        DataScaffold.RegisterEntity<SystemPrincipal>();
        DataScaffold.RegisterEntity<AuditEntry>();
        DataScaffold.RegisterEntity<ReportDefinition>();
        DataScaffold.RegisterEntity<EntityDefinition>();
        DataScaffold.RegisterEntity<FieldDefinition>();
        DataScaffold.RegisterEntity<IndexDefinition>();
        DataScaffold.RegisterEntity<ActionDefinition>();
        DataScaffold.RegisterEntity<ActionCommandDefinition>();

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

        registry.Freeze();

        return new FixtureState(tempDir, registry);
    }

    public sealed class FixtureState : IDisposable
    {
        public string DataRoot { get; }
        public RuntimeEntityRegistry Registry { get; }

        public FixtureState(string dataRoot, RuntimeEntityRegistry registry)
        {
            DataRoot = dataRoot;
            Registry = registry;
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
