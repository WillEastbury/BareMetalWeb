using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for virtual entity loading, registration, and CRUD via VirtualEntityLoader and VirtualEntityJsonStore.
/// </summary>
public class VirtualEntityTests : IDisposable
{
    private readonly string _tempDir;

    public VirtualEntityTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"VirtualEntityTests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    // ── JSON file helpers ────────────────────────────────────────────────────

    private string WriteJson(string json)
    {
        var path = Path.Combine(_tempDir, $"ve_{Guid.NewGuid():N}.json");
        File.WriteAllText(path, json);
        return path;
    }

    // ── VirtualEntityDefinition parsing ─────────────────────────────────────

    [Fact]
    public void LoadFromFile_WhenFileDoesNotExist_DoesNotThrow()
    {
        VirtualEntityLoader.LoadFromFile(Path.Combine(_tempDir, "missing.json"), _tempDir);
        // No exception expected
    }

    [Fact]
    public void LoadFromFile_WithValidJson_RegistersEntity()
    {
        const string slug = "test-widget-ve-unique";
        var json = $$"""
        {
          "virtualEntities": [
            {
              "entityId": "00000000-0000-0000-0000-000000000001",
              "name": "TestWidget",
              "slug": "{{slug}}",
              "showOnNav": false,
              "fields": [
                { "fieldId": "f1", "name": "Label", "type": "string", "required": true }
              ]
            }
          ]
        }
        """;

        var filePath = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(filePath, _tempDir);

        var found = DataScaffold.TryGetEntity(slug, out var meta);
        Assert.True(found);
        Assert.NotNull(meta);
        Assert.Equal("TestWidget", meta.Name);
        Assert.Equal(slug, meta.Slug);
    }

    [Fact]
    public void LoadFromFile_EmptyVirtualEntities_DoesNotThrow()
    {
        var json = """{ "virtualEntities": [] }""";
        var filePath = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(filePath, _tempDir); // should not throw
    }

    [Fact]
    public void LoadFromFile_SetsCorrectNavAndPermissions()
    {
        const string slug = "ve-nav-test";
        var json = $$"""
        {
          "virtualEntities": [
            {
              "entityId": "00000000-0000-0000-0000-000000000002",
              "name": "NavTest",
              "slug": "{{slug}}",
              "showOnNav": true,
              "permissions": "myrole",
              "navGroup": "Custom",
              "navOrder": 50,
              "fields": []
            }
          ]
        }
        """;

        var filePath = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(filePath, _tempDir);

        DataScaffold.TryGetEntity(slug, out var meta);
        Assert.NotNull(meta);
        Assert.True(meta!.ShowOnNav);
        Assert.Equal("myrole", meta.Permissions);
        Assert.Equal("Custom", meta.NavGroup);
        Assert.Equal(50, meta.NavOrder);
    }

    // ── Field metadata ────────────────────────────────────────────────────────

    [Fact]
    public void LoadFromFile_StringField_HasCorrectMetadata()
    {
        const string slug = "ve-stringfield";
        var json = $$"""
        {
          "virtualEntities": [
            {
              "name": "StringFieldTest",
              "slug": "{{slug}}",
              "fields": [
                { "name": "Title", "type": "string", "required": true, "maxLength": 200, "order": 1 }
              ]
            }
          ]
        }
        """;

        var filePath = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(filePath, _tempDir);

        DataScaffold.TryGetEntity(slug, out var meta);
        Assert.NotNull(meta);

        var field = meta!.Fields.First(f => f.Name == "Title");
        Assert.Equal("Title", field.Name);
        Assert.Equal(FormFieldType.String, field.FieldType);
        Assert.True(field.Required);
        Assert.Equal(200, field.Validation?.MaxLength);
        Assert.Equal(typeof(string), field.Property.PropertyType);
    }

    [Fact]
    public void LoadFromFile_BoolField_HasCorrectType()
    {
        const string slug = "ve-boolfield";
        var json = $$"""
        {
          "virtualEntities": [
            {
              "name": "BoolFieldTest",
              "slug": "{{slug}}",
              "fields": [
                { "name": "IsActive", "type": "bool" }
              ]
            }
          ]
        }
        """;

        var filePath = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(filePath, _tempDir);

        DataScaffold.TryGetEntity(slug, out var meta);
        var field = meta!.Fields.First(f => f.Name == "IsActive");
        Assert.Equal(FormFieldType.YesNo, field.FieldType);
        Assert.Equal(typeof(bool?), field.Property.PropertyType);
    }

    [Fact]
    public void LoadFromFile_EnumField_CreatesRealEnumType()
    {
        const string slug = "ve-enumfield";
        var json = $$"""
        {
          "virtualEntities": [
            {
              "name": "EnumFieldTest",
              "slug": "{{slug}}",
              "fields": [
                { "name": "Priority", "type": "enum", "values": ["Low", "Medium", "High"] }
              ]
            }
          ]
        }
        """;

        var filePath = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(filePath, _tempDir);

        DataScaffold.TryGetEntity(slug, out var meta);
        var field = meta!.Fields.First(f => f.Name == "Priority");
        Assert.Equal(FormFieldType.Enum, field.FieldType);
        Assert.True(field.Property.PropertyType.IsEnum);

        var enumNames = Enum.GetNames(field.Property.PropertyType);
        Assert.Contains("Low", enumNames);
        Assert.Contains("Medium", enumNames);
        Assert.Contains("High", enumNames);
    }

    [Fact]
    public void LoadFromFile_DateTimeField_HasCorrectType()
    {
        const string slug = "ve-datetimefield";
        var json = $$"""
        {
          "virtualEntities": [
            {
              "name": "DateTimeFieldTest",
              "slug": "{{slug}}",
              "fields": [
                { "name": "DueDate", "type": "datetime", "nullable": true }
              ]
            }
          ]
        }
        """;

        var filePath = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(filePath, _tempDir);

        DataScaffold.TryGetEntity(slug, out var meta);
        var field = meta!.Fields.First(f => f.Name == "DueDate");
        Assert.Equal(FormFieldType.DateTime, field.FieldType);
        Assert.Equal(typeof(DateTime?), field.Property.PropertyType);
    }

    [Fact]
    public void LoadFromFile_MultilineField_HasTextAreaType()
    {
        const string slug = "ve-multilinefield";
        var json = $$"""
        {
          "virtualEntities": [
            {
              "name": "MultilineTest",
              "slug": "{{slug}}",
              "fields": [
                { "name": "Notes", "type": "string", "multiline": true }
              ]
            }
          ]
        }
        """;

        var filePath = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(filePath, _tempDir);

        DataScaffold.TryGetEntity(slug, out var meta);
        var field = meta!.Fields.First(f => f.Name == "Notes");
        Assert.Equal(FormFieldType.TextArea, field.FieldType);
    }

    // ── DynamicPropertyInfo ───────────────────────────────────────────────────

    [Fact]
    public void DynamicPropertyInfo_GetValue_ReadsFromDynamicDataObject()
    {
        var prop = new DynamicPropertyInfo("MyField", typeof(string));
        var obj = new DynamicDataObject();
        obj.SetField("MyField", "hello");

        var value = prop.GetValue(obj);
        Assert.Equal("hello", value);
    }

    [Fact]
    public void DynamicPropertyInfo_SetValue_WritesToDynamicDataObject()
    {
        var prop = new DynamicPropertyInfo("MyField", typeof(string));
        var obj = new DynamicDataObject();

        prop.SetValue(obj, "world");

        Assert.Equal("world", obj.GetField("MyField"));
    }

    [Fact]
    public void DynamicPropertyInfo_SetValue_ConvertsBoolToString()
    {
        var prop = new DynamicPropertyInfo("Flag", typeof(bool));
        var obj = new DynamicDataObject();

        prop.SetValue(obj, true);
        Assert.Equal("true", obj.GetField("Flag"));

        prop.SetValue(obj, false);
        Assert.Equal("false", obj.GetField("Flag"));
    }

    [Fact]
    public void DynamicPropertyInfo_GetValue_ReturnsNullForUnknownField()
    {
        var prop = new DynamicPropertyInfo("Missing", typeof(string));
        var obj = new DynamicDataObject();

        var value = prop.GetValue(obj);
        Assert.Null(value);
    }

    [Fact]
    public void DynamicPropertyInfo_HasExpectedAttributes()
    {
        var prop = new DynamicPropertyInfo("X", typeof(int));
        Assert.Equal("X", prop.Name);
        Assert.Equal(typeof(int), prop.PropertyType);
        Assert.True(prop.CanRead);
        Assert.True(prop.CanWrite);
        Assert.Empty(prop.GetCustomAttributes(inherit: false));
        Assert.False(prop.IsDefined(typeof(Attribute), inherit: false));
    }

    // ── VirtualEntityJsonStore ────────────────────────────────────────────────

    [Fact]
    public async Task VirtualEntityJsonStore_SaveAndLoad_RoundTrips()
    {
        var store = new VirtualEntityJsonStore(_tempDir);
        var obj = new DynamicDataObject { EntityTypeName = "Widget", Id = Guid.NewGuid().ToString("N") };
        obj.SetField("Title", "My Widget");
        obj.SetField("Count", "42");

        await store.SaveAsync("Widget", obj);
        var loaded = await store.LoadAsync("Widget", obj.Id);

        Assert.NotNull(loaded);
        Assert.Equal("My Widget", loaded!.GetField("Title"));
        Assert.Equal("42", loaded.GetField("Count"));
    }

    [Fact]
    public async Task VirtualEntityJsonStore_Delete_RemovesRecord()
    {
        var store = new VirtualEntityJsonStore(_tempDir);
        var id = Guid.NewGuid().ToString("N");
        var obj = new DynamicDataObject { EntityTypeName = "Widget", Id = id };
        obj.SetField("X", "1");

        await store.SaveAsync("Widget", obj);
        await store.DeleteAsync("Widget", id);

        var loaded = await store.LoadAsync("Widget", id);
        Assert.Null(loaded);
    }

    [Fact]
    public async Task VirtualEntityJsonStore_Query_ReturnsMatchingRecords()
    {
        var store = new VirtualEntityJsonStore(_tempDir);
        var entity = $"QueryTest_{Guid.NewGuid():N}";

        for (int i = 0; i < 5; i++)
        {
            var obj = new DynamicDataObject { Id = Guid.NewGuid().ToString("N") };
            obj.SetField("Priority", i < 3 ? "High" : "Low");
            await store.SaveAsync(entity, obj);
        }

        var query = new QueryDefinition();
        query.Clauses.Add(new QueryClause
        {
            Field = "Priority",
            Operator = QueryOperator.Equals,
            Value = "High"
        });

        var results = (await store.QueryAsync(entity, query)).ToList();
        Assert.Equal(3, results.Count);
        Assert.All(results, r => Assert.Equal("High", r.GetField("Priority")));
    }

    [Fact]
    public async Task VirtualEntityJsonStore_Count_ReturnsCorrectCount()
    {
        var store = new VirtualEntityJsonStore(_tempDir);
        var entity = $"CountTest_{Guid.NewGuid():N}";

        for (int i = 0; i < 4; i++)
        {
            var obj = new DynamicDataObject { Id = Guid.NewGuid().ToString("N") };
            await store.SaveAsync(entity, obj);
        }

        var count = await store.CountAsync(entity, null);
        Assert.Equal(4, count);
    }

    // ── Handlers integration ──────────────────────────────────────────────────

    [Fact]
    public async Task VirtualEntity_Handlers_CreateSaveAndLoad()
    {
        const string slug = "ve-handler-test";
        var json = $$"""
        {
          "virtualEntities": [
            {
              "name": "HandlerTest",
              "slug": "{{slug}}",
              "fields": [
                { "name": "Name", "type": "string" }
              ]
            }
          ]
        }
        """;

        var filePath = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(filePath, _tempDir);

        DataScaffold.TryGetEntity(slug, out var meta);
        Assert.NotNull(meta);

        // Create
        var instance = (DynamicDataObject)meta!.Handlers.Create();
        instance.SetField("Name", "Alice");

        // Save
        await meta.Handlers.SaveAsync(instance, default);

        // Load
        var loaded = await meta.Handlers.LoadAsync(instance.Id, default);
        Assert.NotNull(loaded);
        Assert.IsType<DynamicDataObject>(loaded);
        Assert.Equal("Alice", ((DynamicDataObject)loaded!).GetField("Name"));
    }

    [Fact]
    public async Task VirtualEntity_Handlers_QueryReturnsCreatedItems()
    {
        const string slug = "ve-query-test";
        var json = $$"""
        {
          "virtualEntities": [
            {
              "name": "QueryVETest",
              "slug": "{{slug}}",
              "fields": [
                { "name": "Category", "type": "string" }
              ]
            }
          ]
        }
        """;

        var filePath = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(filePath, _tempDir);

        DataScaffold.TryGetEntity(slug, out var meta);

        var a = (DynamicDataObject)meta!.Handlers.Create();
        a.SetField("Category", "Alpha");
        await meta.Handlers.SaveAsync(a, default);

        var b = (DynamicDataObject)meta.Handlers.Create();
        b.SetField("Category", "Beta");
        await meta.Handlers.SaveAsync(b, default);

        var all = (await meta.Handlers.QueryAsync(null, default)).ToList();
        Assert.True(all.Count >= 2);
    }

    // ── DataEntityRegistry integration ────────────────────────────────────────

    [Fact]
    public void RegisterVirtualEntitiesFromFile_CallsLoader()
    {
        const string slug = "ve-registry-test";
        var json = $$"""
        {
          "virtualEntities": [
            {
              "name": "RegistryTest",
              "slug": "{{slug}}",
              "fields": []
            }
          ]
        }
        """;

        var filePath = WriteJson(json);
        DataEntityRegistry.RegisterVirtualEntitiesFromFile(filePath, _tempDir);

        var found = DataScaffold.TryGetEntity(slug, out var meta);
        Assert.True(found);
        Assert.Equal("RegistryTest", meta!.Name);
    }

    // ── DynamicPropertyInfo access visibility ────────────────────────────────

    [Fact]
    public void DynamicPropertyInfo_IsInternalAndAccessibleFromTests()
    {
        // DynamicPropertyInfo has InternalsVisibleTo("BareMetalWeb.Data.Tests")
        var prop = new DynamicPropertyInfo("Test", typeof(string));
        Assert.NotNull(prop);
    }

    // ── ApplyValuesFromForm with virtual entity ───────────────────────────────

    [Fact]
    public void ApplyValuesFromForm_VirtualStringField_SetsValue()
    {
        const string slug = "ve-form-test";
        var json = $$"""
        {
          "virtualEntities": [
            {
              "name": "FormVETest",
              "slug": "{{slug}}",
              "fields": [
                { "name": "Title", "type": "string", "required": false }
              ]
            }
          ]
        }
        """;

        var filePath = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(filePath, _tempDir);
        DataScaffold.TryGetEntity(slug, out var meta);

        var instance = (DynamicDataObject)meta!.Handlers.Create();
        var formValues = new Dictionary<string, string?> { ["Title"] = "My Title" };
        var errors = DataScaffold.ApplyValuesFromForm(meta, instance, formValues, forCreate: true);

        Assert.Empty(errors);
        Assert.Equal("My Title", instance.GetField("Title"));
    }

    // ── VirtualEntityJsonStore.CountAsync ────────────────────────────────────

    [Fact]
    public async Task CountAsync_WithNullQuery_ReturnsAllItems()
    {
        var store = new VirtualEntityJsonStore(_tempDir);
        const string entityType = "count-test-null";
        for (var i = 1; i <= 5; i++)
        {
            var obj = new DynamicDataObject { Id = $"item-{i}" };
            await store.SaveAsync(entityType, obj);
        }

        var count = await store.CountAsync(entityType, null);

        Assert.Equal(5, count);
    }

    [Fact]
    public async Task CountAsync_WithSkipAndTop_ReturnsTotalNotPageCount()
    {
        // Regression test: CountAsync must NOT apply Skip/Top — it should always
        // return the total matching count, not the count of items on a single page.
        var store = new VirtualEntityJsonStore(_tempDir);
        const string entityType = "count-test-paginated";
        for (var i = 1; i <= 5; i++)
        {
            var obj = new DynamicDataObject { Id = $"item-{i}" };
            await store.SaveAsync(entityType, obj);
        }

        // A paginated query: skip=3, top=1 – CountAsync must still return 5 (total), not 1 (page size)
        var query = new QueryDefinition { Skip = 3, Top = 1 };
        var count = await store.CountAsync(entityType, query);

        Assert.Equal(5, count);
    }

    [Fact]
    public async Task CountAsync_WithFilterAndSkipTop_ReturnsFilteredTotalNotPageCount()
    {
        // Regression test: when filtering AND paginating, CountAsync returns the total
        // number of matching items, not the items visible on the current page.
        var store = new VirtualEntityJsonStore(_tempDir);
        const string entityType = "count-test-filter-paginated";
        for (var i = 1; i <= 4; i++)
        {
            var obj = new DynamicDataObject { Id = $"match-{i}" };
            obj.SetField("Status", "active");
            await store.SaveAsync(entityType, obj);
        }
        for (var i = 1; i <= 2; i++)
        {
            var obj = new DynamicDataObject { Id = $"other-{i}" };
            obj.SetField("Status", "inactive");
            await store.SaveAsync(entityType, obj);
        }

        // Skip=2, Top=1 on items matching Status=active: count should be 4 (total matching), not 1 (page size)
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "Status", Operator = QueryOperator.Equals, Value = "active" }
            },
            Skip = 2,
            Top = 1
        };
        var count = await store.CountAsync(entityType, query);

        Assert.Equal(4, count);
    }
}
