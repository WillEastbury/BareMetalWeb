using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using BareMetalWeb.Data;
using BareMetalWeb.Runtime;
using Xunit;

namespace BareMetalWeb.Runtime.Tests;

/// <summary>
/// Tests for RuntimeEntityCompiler, RuntimeEntityModel, and RuntimeEntityRegistry.
/// </summary>
public class RuntimeEntityRegistryTests : IDisposable
{
    private readonly string _tempDir;

    public RuntimeEntityRegistryTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"RuntimeTests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    // ── EntityDefinition helpers ─────────────────────────────────────────────

    private static uint _nextKey = 1;
    private static EntityDefinition MakeEntity(string name, string? slug = null) => new()
    {
        Key = _nextKey++,
        EntityId = Guid.NewGuid().ToString("D"),
        Name = name,
        Slug = slug,
        IdStrategy = "guid",
        ShowOnNav = true,
        Permissions = "admin",
        NavGroup = "Test",
        NavOrder = 1,
        Version = 1
    };

    private static FieldDefinition MakeField(string entityId, string name, string type,
        int ordinal = 0, bool required = false) => new()
    {
        Key = _nextKey++,
        FieldId = Guid.NewGuid().ToString("D"),
        EntityId = entityId,
        Name = name,
        Type = type,
        Required = required,
        Ordinal = ordinal,
        IsNullable = true,
        List = true, View = true, Edit = true, Create = true
    };

    // ── RuntimeEntityCompiler tests ──────────────────────────────────────────

    [Fact]
    public void Compile_WithValidEntity_ReturnsModel()
    {
        var compiler = new RuntimeEntityCompiler();
        var entity = MakeEntity("Ticket", "tickets");
        var fields = new List<FieldDefinition>
        {
            MakeField(entity.Key.ToString(), "Title", "string", ordinal: 1, required: true),
            MakeField(entity.Key.ToString(), "Priority", "enum", ordinal: 2)
        };
        ((FieldDefinition)fields[1]).EnumValues = "Low|Medium|High";

        var model = compiler.Compile(entity, fields, Array.Empty<IndexDefinition>(),
            Array.Empty<ActionDefinition>(), out var warnings);

        Assert.NotNull(model);
        Assert.Equal("Ticket", model!.Name);
        Assert.Equal("tickets", model.Slug);
        Assert.Equal("admin", model.Permissions);
        Assert.True(model.ShowOnNav);
        Assert.Equal(2, model.Fields.Count);
        Assert.Empty(warnings);
    }

    [Fact]
    public void Compile_WithEmptyName_ReturnsNull()
    {
        var compiler = new RuntimeEntityCompiler();
        var entity = MakeEntity("");

        var model = compiler.Compile(entity, Array.Empty<FieldDefinition>(),
            Array.Empty<IndexDefinition>(), Array.Empty<ActionDefinition>(), out var warnings);

        Assert.Null(model);
        Assert.NotEmpty(warnings);
    }

    [Fact]
    public void Compile_AssignsDeterministicOrdinals()
    {
        var compiler = new RuntimeEntityCompiler();
        var entity = MakeEntity("Widget");
        // Fields with no ordinal — should get assigned deterministically
        var fields = new List<FieldDefinition>
        {
            MakeField(entity.Key.ToString(), "Zzz", "string", ordinal: 0),
            MakeField(entity.Key.ToString(), "Aaa", "string", ordinal: 0)
        };

        var model = compiler.Compile(entity, fields, Array.Empty<IndexDefinition>(),
            Array.Empty<ActionDefinition>(), out _);

        Assert.NotNull(model);
        // Fields with ordinal=0 should be ordered alphabetically and assigned ordinals
        var ordinals = model!.Fields.Select(f => f.Ordinal).ToList();
        Assert.All(ordinals, o => Assert.True(o > 0));
        // Ordinals should be strictly increasing
        for (int i = 1; i < ordinals.Count; i++)
            Assert.True(ordinals[i] > ordinals[i - 1]);
    }

    [Fact]
    public void Compile_GeneratesSchemaHash()
    {
        var compiler = new RuntimeEntityCompiler();
        var entity = MakeEntity("HashTest");
        var fields = new[] { MakeField(entity.Key.ToString(), "Name", "string", ordinal: 1) };

        var model1 = compiler.Compile(entity, fields, Array.Empty<IndexDefinition>(),
            Array.Empty<ActionDefinition>(), out _);

        // Same input → same hash
        var model2 = compiler.Compile(entity, fields, Array.Empty<IndexDefinition>(),
            Array.Empty<ActionDefinition>(), out _);

        Assert.Equal(model1!.SchemaHash, model2!.SchemaHash);
        Assert.NotEmpty(model1.SchemaHash);
    }

    [Fact]
    public void Compile_DifferentFields_ProducesDifferentHash()
    {
        var compiler = new RuntimeEntityCompiler();
        var entity = MakeEntity("HashChange");

        var fields1 = new[] { MakeField(entity.Key.ToString(), "Name", "string", ordinal: 1) };
        var fields2 = new[]
        {
            MakeField(entity.Key.ToString(), "Name", "string", ordinal: 1),
            MakeField(entity.Key.ToString(), "Email", "email", ordinal: 2)
        };

        var model1 = compiler.Compile(entity, fields1, Array.Empty<IndexDefinition>(),
            Array.Empty<ActionDefinition>(), out _);
        var model2 = compiler.Compile(entity, fields2, Array.Empty<IndexDefinition>(),
            Array.Empty<ActionDefinition>(), out _);

        Assert.NotEqual(model1!.SchemaHash, model2!.SchemaHash);
    }

    [Fact]
    public void Compile_SlugDerivedFromName_WhenNotProvided()
    {
        var compiler = new RuntimeEntityCompiler();
        var entity = MakeEntity("SalesOrder");  // No explicit slug

        var model = compiler.Compile(entity, Array.Empty<FieldDefinition>(),
            Array.Empty<IndexDefinition>(), Array.Empty<ActionDefinition>(), out _);

        Assert.NotNull(model);
        // ToSlug(Pluralize("SalesOrder")) → ToSlug("SalesOrders") → "salesorders"
        Assert.Equal("salesorders", model!.Slug);
    }

    [Fact]
    public void Compile_IndexDefinitions_AreIncluded()
    {
        var compiler = new RuntimeEntityCompiler();
        var entity = MakeEntity("IndexTest");
        var index = new IndexDefinition
        {
            Key = _nextKey++,
            EntityId = entity.Key.ToString(),
            FieldNames = "DueDate|Priority",
            Type = "composite"
        };

        var model = compiler.Compile(entity, Array.Empty<FieldDefinition>(),
            new[] { index }, Array.Empty<ActionDefinition>(), out _);

        Assert.Single(model!.Indexes);
        Assert.Equal(2, model.Indexes[0].FieldNames.Count);
        Assert.Contains("DueDate", model.Indexes[0].FieldNames);
        Assert.Equal("composite", model.Indexes[0].Type);
    }

    [Fact]
    public void Compile_ActionDefinitions_AreIncluded()
    {
        var compiler = new RuntimeEntityCompiler();
        var entity = MakeEntity("ActionTest");
        var action = new ActionDefinition
        {
            Key = _nextKey++,
            EntityId = entity.Key.ToString(),
            Name = "Resolve",
            Label = "Mark as Resolved",
            Permission = "Ticket.Resolve",
            EnabledWhen = "IsResolved == false",
            Operations = "SetField:IsResolved=true"
        };

        var model = compiler.Compile(entity, Array.Empty<FieldDefinition>(),
            Array.Empty<IndexDefinition>(), new[] { action }, out _);

        Assert.Single(model!.Actions);
        var compiled = model.Actions[0];
        Assert.Equal("Resolve", compiled.Name);
        Assert.Equal("Mark as Resolved", compiled.Label);
        Assert.Equal("Ticket.Resolve", compiled.Permission);
        Assert.Equal("IsResolved == false", compiled.EnabledWhen);
        Assert.Single(compiled.Operations);
        Assert.Equal("SetField:IsResolved=true", compiled.Operations[0]);
    }

    // ── Field type mapping tests ──────────────────────────────────────────────

    [Theory]
    [InlineData("bool", BareMetalWeb.Rendering.Models.FormFieldType.YesNo)]
    [InlineData("boolean", BareMetalWeb.Rendering.Models.FormFieldType.YesNo)]
    [InlineData("int", BareMetalWeb.Rendering.Models.FormFieldType.Integer)]
    [InlineData("integer", BareMetalWeb.Rendering.Models.FormFieldType.Integer)]
    [InlineData("decimal", BareMetalWeb.Rendering.Models.FormFieldType.Decimal)]
    [InlineData("datetime", BareMetalWeb.Rendering.Models.FormFieldType.DateTime)]
    [InlineData("date", BareMetalWeb.Rendering.Models.FormFieldType.DateOnly)]
    [InlineData("time", BareMetalWeb.Rendering.Models.FormFieldType.TimeOnly)]
    [InlineData("enum", BareMetalWeb.Rendering.Models.FormFieldType.Enum)]
    [InlineData("lookup", BareMetalWeb.Rendering.Models.FormFieldType.LookupList)]
    [InlineData("email", BareMetalWeb.Rendering.Models.FormFieldType.Email)]
    [InlineData("string", BareMetalWeb.Rendering.Models.FormFieldType.String)]
    public void Compile_FieldType_MapsCorrectly(string typeStr, BareMetalWeb.Rendering.Models.FormFieldType expected)
    {
        var compiler = new RuntimeEntityCompiler();
        var entity = MakeEntity($"TypeTest_{typeStr}");
        var field = MakeField(entity.Key.ToString(), "TestField", typeStr, ordinal: 1);

        var model = compiler.Compile(entity, new[] { field }, Array.Empty<IndexDefinition>(),
            Array.Empty<ActionDefinition>(), out _);

        Assert.Single(model!.Fields);
        Assert.Equal(expected, model.Fields[0].FieldType);
    }

    [Fact]
    public void Compile_MultilineString_HasTextAreaType()
    {
        var compiler = new RuntimeEntityCompiler();
        var entity = MakeEntity("MultilineTest");
        var field = MakeField(entity.Key.ToString(), "Notes", "string", ordinal: 1);
        field.Multiline = true;

        var model = compiler.Compile(entity, new[] { field }, Array.Empty<IndexDefinition>(),
            Array.Empty<ActionDefinition>(), out _);

        Assert.Equal(BareMetalWeb.Rendering.Models.FormFieldType.TextArea, model!.Fields[0].FieldType);
    }

    // ── RuntimeEntityRegistry tests ──────────────────────────────────────────

    [Fact]
    public void Registry_Register_ThenGet_Succeeds()
    {
        var compiler = new RuntimeEntityCompiler();
        var entity = MakeEntity("RegistryGetTest", $"registry-get-{Guid.NewGuid():N}");
        var model = compiler.Compile(entity, Array.Empty<FieldDefinition>(),
            Array.Empty<IndexDefinition>(), Array.Empty<ActionDefinition>(), out _)!;

        var registry = new RuntimeEntityRegistry();
        registry.Register(model);

        var found = registry.TryGet(model.Slug, out var retrieved);
        Assert.True(found);
        Assert.NotNull(retrieved);
        Assert.Equal(model.EntityId, retrieved.EntityId);
    }

    [Fact]
    public void Registry_TryGetById_Succeeds()
    {
        var compiler = new RuntimeEntityCompiler();
        var entity = MakeEntity("ByIdTest", $"by-id-{Guid.NewGuid():N}");
        var model = compiler.Compile(entity, Array.Empty<FieldDefinition>(),
            Array.Empty<IndexDefinition>(), Array.Empty<ActionDefinition>(), out _)!;

        var registry = new RuntimeEntityRegistry();
        registry.Register(model);

        var found = registry.TryGetById(model.EntityId, out var retrieved);
        Assert.True(found);
        Assert.Equal(model.Slug, retrieved.Slug);
    }

    [Fact]
    public void Registry_FreezeBlocksFurtherRegistrations()
    {
        var compiler = new RuntimeEntityCompiler();
        var entity = MakeEntity("FreezeTest", $"freeze-{Guid.NewGuid():N}");
        var model = compiler.Compile(entity, Array.Empty<FieldDefinition>(),
            Array.Empty<IndexDefinition>(), Array.Empty<ActionDefinition>(), out _)!;

        var registry = new RuntimeEntityRegistry();
        registry.Freeze();

        var ex = Assert.Throws<InvalidOperationException>(() => registry.Register(model));
        Assert.Contains("frozen", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Registry_All_ReturnsByNavOrder()
    {
        var compiler = new RuntimeEntityCompiler();
        var registry = new RuntimeEntityRegistry();

        foreach (var (name, slug, order) in new[]
        {
            ("C", $"c-{Guid.NewGuid():N}", 30),
            ("A", $"a-{Guid.NewGuid():N}", 10),
            ("B", $"b-{Guid.NewGuid():N}", 20)
        })
        {
            var e = MakeEntity(name, slug);
            e.NavOrder = order;
            var model = compiler.Compile(e, Array.Empty<FieldDefinition>(),
                Array.Empty<IndexDefinition>(), Array.Empty<ActionDefinition>(), out _)!;
            registry.Register(model);
        }

        var all = registry.All;
        Assert.Equal(3, all.Count);
        // Should be ordered by NavOrder: A(10), B(20), C(30)
        Assert.Equal("A", all[0].Name);
        Assert.Equal("B", all[1].Name);
        Assert.Equal("C", all[2].Name);
    }

    // ── RuntimeEntityModel.ToEntityMetadata tests ────────────────────────────

    [Fact]
    public void ToEntityMetadata_ProducesWorkingHandlers()
    {
        var compiler = new RuntimeEntityCompiler();
        var entity = MakeEntity("ToMetaTest", $"to-meta-{Guid.NewGuid():N}");
        var fields = new[] { MakeField(entity.Key.ToString(), "Title", "string", ordinal: 1) };
        var model = compiler.Compile(entity, fields, Array.Empty<IndexDefinition>(),
            Array.Empty<ActionDefinition>(), out _)!;

        var store = new VirtualEntityJsonStore(_tempDir);
        var metadata = model.ToEntityMetadata(store);

        Assert.Equal(entity.Name, metadata.Name);
        Assert.Equal(model.Slug, metadata.Slug);
        Assert.Single(metadata.Fields);
        Assert.Equal("Title", metadata.Fields[0].Name);

        // Create handler must return DynamicDataObject
        var obj = metadata.Handlers.Create();
        Assert.IsType<DynamicDataObject>(obj);
    }

    // ── CommandService / QueryService tests ──────────────────────────────────

    [Fact]
    public async Task QueryService_UnknownSlug_ReturnsEmpty()
    {
        var svc = new QueryService();
        var results = await svc.QueryAsync("nonexistent-entity-slug");
        Assert.Empty(results);
    }

    [Fact]
    public async Task CommandService_Create_WithUnknownSlug_ReturnsFail()
    {
        var svc = new CommandService();
        var result = await svc.ExecuteAsync(new CommandIntent
        {
            EntitySlug = "nonexistent-entity-cmd",
            Operation = "create",
            Fields = new Dictionary<string, string?> { ["Title"] = "Test" }
        });

        Assert.False(result.Success);
        Assert.NotNull(result.Error);
    }
}
