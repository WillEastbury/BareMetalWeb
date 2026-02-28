using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for the virtual Employee entity (issue #301): viewType, parentField,
/// self-referencing lookup, and two-pass lookup resolution.
/// </summary>
public class VirtualEmployeeTests : IDisposable
{
    private readonly string _tempDir;

    public VirtualEmployeeTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"VEmpTests_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { }
    }

    private string WriteJson(string json)
    {
        var path = Path.Combine(_tempDir, $"ve_{Guid.NewGuid():N}.json");
        File.WriteAllText(path, json);
        return path;
    }

    // ── ViewType support ────────────────────────────────────────────────────

    [Theory]
    [InlineData("treeview", ViewType.TreeView)]
    [InlineData("tree", ViewType.TreeView)]
    [InlineData("orgchart", ViewType.OrgChart)]
    [InlineData("timeline", ViewType.Timeline)]
    [InlineData("timetable", ViewType.Timetable)]
    [InlineData(null, ViewType.Table)]
    [InlineData("table", ViewType.Table)]
    public void ViewType_MapsCorrectly(string? viewTypeValue, ViewType expected)
    {
        var slug = $"vt-{Guid.NewGuid():N}";
        var vtJson = viewTypeValue != null ? $"\"viewType\": \"{viewTypeValue}\"," : "";
        var json = $$"""
        {
          "virtualEntities": [{
            "entityId": "{{Guid.NewGuid():D}}",
            "name": "VTTest",
            "slug": "{{slug}}",
            {{vtJson}}
            "fields": [{ "fieldId": "{{Guid.NewGuid():D}}", "name": "Title", "type": "string" }]
          }]
        }
        """;

        var path = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(path, _tempDir);

        Assert.True(DataScaffold.TryGetEntity(slug, out var meta));
        Assert.Equal(expected, meta!.ViewType);
    }

    // ── ParentField support ─────────────────────────────────────────────────

    [Fact]
    public void ParentField_ResolvesToMatchingFieldMetadata()
    {
        var slug = $"pf-{Guid.NewGuid():N}";
        var json = $$"""
        {
          "virtualEntities": [{
            "entityId": "{{Guid.NewGuid():D}}",
            "name": "PFTest",
            "slug": "{{slug}}",
            "viewType": "treeview",
            "parentField": "ParentId",
            "fields": [
              { "fieldId": "{{Guid.NewGuid():D}}", "name": "Name", "type": "string", "order": 1 },
              { "fieldId": "{{Guid.NewGuid():D}}", "name": "ParentId", "type": "string", "order": 2 }
            ]
          }]
        }
        """;

        var path = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(path, _tempDir);

        Assert.True(DataScaffold.TryGetEntity(slug, out var meta));
        Assert.NotNull(meta!.ParentField);
        Assert.Equal("ParentId", meta.ParentField!.Name);
    }

    [Fact]
    public void ParentField_NullWhenNotSpecified()
    {
        var slug = $"npf-{Guid.NewGuid():N}";
        var json = $$"""
        {
          "virtualEntities": [{
            "entityId": "{{Guid.NewGuid():D}}",
            "name": "NPFTest",
            "slug": "{{slug}}",
            "fields": [
              { "fieldId": "{{Guid.NewGuid():D}}", "name": "Title", "type": "string" }
            ]
          }]
        }
        """;

        var path = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(path, _tempDir);

        Assert.True(DataScaffold.TryGetEntity(slug, out var meta));
        Assert.Null(meta!.ParentField);
    }

    // ── Self-referencing lookup (two-pass resolution) ───────────────────────

    [Fact]
    public void SelfReferencingLookup_ResolvesViaTwoPassLoading()
    {
        var slug = $"selfref-{Guid.NewGuid():N}";
        var json = $$"""
        {
          "virtualEntities": [{
            "entityId": "{{Guid.NewGuid():D}}",
            "name": "SelfRefEntity",
            "slug": "{{slug}}",
            "viewType": "treeview",
            "parentField": "ParentId",
            "fields": [
              { "fieldId": "{{Guid.NewGuid():D}}", "name": "Name", "type": "string", "order": 1 },
              {
                "fieldId": "{{Guid.NewGuid():D}}",
                "name": "ParentId",
                "type": "lookup",
                "lookupEntity": "{{slug}}",
                "lookupDisplayField": "Name",
                "lookupQueryField": "Id",
                "lookupQueryOperator": "notequals",
                "order": 2
              }
            ]
          }]
        }
        """;

        var path = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(path, _tempDir);

        Assert.True(DataScaffold.TryGetEntity(slug, out var meta));
        var lookupField = meta!.Fields.FirstOrDefault(f => f.Name == "ParentId");
        Assert.NotNull(lookupField);
        Assert.NotNull(lookupField!.Lookup);
        Assert.Equal("Name", lookupField.Lookup!.DisplayField);
        Assert.Equal("Id", lookupField.Lookup.QueryField);
        Assert.Equal(QueryOperator.NotEquals, lookupField.Lookup.QueryOperator);
    }

    // ── Cross-entity lookup resolves between virtual entities ───────────────

    [Fact]
    public void CrossEntityLookup_ResolvesBetweenVirtualEntities()
    {
        var deptSlug = $"dept-{Guid.NewGuid():N}";
        var empSlug = $"emp-{Guid.NewGuid():N}";
        var json = $$"""
        {
          "virtualEntities": [
            {
              "entityId": "{{Guid.NewGuid():D}}",
              "name": "VDept",
              "slug": "{{deptSlug}}",
              "fields": [
                { "fieldId": "{{Guid.NewGuid():D}}", "name": "DeptName", "type": "string" }
              ]
            },
            {
              "entityId": "{{Guid.NewGuid():D}}",
              "name": "VEmpWithDept",
              "slug": "{{empSlug}}",
              "fields": [
                { "fieldId": "{{Guid.NewGuid():D}}", "name": "Name", "type": "string", "order": 1 },
                {
                  "fieldId": "{{Guid.NewGuid():D}}",
                  "name": "DeptId",
                  "type": "lookup",
                  "lookupEntity": "{{deptSlug}}",
                  "lookupDisplayField": "DeptName",
                  "order": 2
                }
              ]
            }
          ]
        }
        """;

        var path = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(path, _tempDir);

        Assert.True(DataScaffold.TryGetEntity(empSlug, out var meta));
        var lookup = meta!.Fields.First(f => f.Name == "DeptId").Lookup;
        Assert.NotNull(lookup);
        Assert.Equal("DeptName", lookup!.DisplayField);
    }

    // ── Full VEmployee definition matches compiled Employee shape ────────────

    [Fact]
    public void VEmployee_FromJson_MatchesCompiledEmployeeShape()
    {
        var slug = $"vemp-full-{Guid.NewGuid():N}";
        var json = $$"""
        {
          "virtualEntities": [{
            "entityId": "{{Guid.NewGuid():D}}",
            "name": "VEmployeeFull",
            "slug": "{{slug}}",
            "showOnNav": true,
            "navGroup": "Organization",
            "navOrder": 11,
            "viewType": "treeview",
            "parentField": "ManagerId",
            "idStrategy": "guid",
            "fields": [
              { "fieldId": "{{Guid.NewGuid():D}}", "name": "Name", "type": "string", "required": true, "order": 2, "list": true, "view": true, "edit": true, "create": true },
              { "fieldId": "{{Guid.NewGuid():D}}", "name": "Title", "type": "string", "order": 3, "list": true, "view": true, "edit": true, "create": true },
              { "fieldId": "{{Guid.NewGuid():D}}", "name": "Email", "type": "email", "order": 4, "list": true, "view": true, "edit": true, "create": true },
              {
                "fieldId": "{{Guid.NewGuid():D}}",
                "name": "ManagerId",
                "type": "lookup",
                "label": "Manager",
                "lookupEntity": "{{slug}}",
                "lookupDisplayField": "Name",
                "lookupQueryField": "Id",
                "lookupQueryOperator": "notequals",
                "order": 5,
                "list": true, "view": true, "edit": true, "create": true
              },
              { "fieldId": "{{Guid.NewGuid():D}}", "name": "Department", "type": "string", "order": 6, "list": true, "view": true, "edit": true, "create": true },
              { "fieldId": "{{Guid.NewGuid():D}}", "name": "HireDate", "type": "date", "nullable": true, "order": 7, "list": false, "view": true, "edit": true, "create": true }
            ]
          }]
        }
        """;

        var path = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(path, _tempDir);

        Assert.True(DataScaffold.TryGetEntity(slug, out var meta));
        Assert.NotNull(meta);

        // Entity-level properties
        Assert.True(meta!.ShowOnNav);
        Assert.Equal("Organization", meta.NavGroup);
        Assert.Equal(ViewType.TreeView, meta.ViewType);
        Assert.Equal(AutoIdStrategy.Sequential, meta.IdGeneration);

        // ParentField
        Assert.NotNull(meta.ParentField);
        Assert.Equal("ManagerId", meta.ParentField!.Name);

        // Field count (6 user fields, matching compiled Employee)
        Assert.Equal(6, meta.Fields.Count);

        // Field names in order
        var names = meta.Fields.Select(f => f.Name).ToList();
        Assert.Equal(new[] { "Name", "Title", "Email", "ManagerId", "Department", "HireDate" }, names);

        // Name is required
        Assert.True(meta.Fields.First(f => f.Name == "Name").Required);

        // Email uses Email field type
        Assert.Equal(FormFieldType.Email, meta.Fields.First(f => f.Name == "Email").FieldType);

        // HireDate is DateOnly
        Assert.Equal(FormFieldType.DateOnly, meta.Fields.First(f => f.Name == "HireDate").FieldType);
        Assert.False(meta.Fields.First(f => f.Name == "HireDate").List);

        // ManagerId has self-referencing lookup
        var mgr = meta.Fields.First(f => f.Name == "ManagerId");
        Assert.NotNull(mgr.Lookup);
        Assert.Equal("Name", mgr.Lookup!.DisplayField);
        Assert.Equal("Id", mgr.Lookup.QueryField);
        Assert.Equal(QueryOperator.NotEquals, mgr.Lookup.QueryOperator);
    }

    // ── CRUD works for virtual Employee ─────────────────────────────────────

    [Fact]
    public async Task VEmployee_CRUD_WorksWithJsonStore()
    {
        var slug = $"vemp-crud-{Guid.NewGuid():N}";
        var json = $$"""
        {
          "virtualEntities": [{
            "entityId": "{{Guid.NewGuid():D}}",
            "name": "VEmpCrud",
            "slug": "{{slug}}",
            "idStrategy": "guid",
            "fields": [
              { "fieldId": "{{Guid.NewGuid():D}}", "name": "Name", "type": "string", "required": true, "order": 1 },
              { "fieldId": "{{Guid.NewGuid():D}}", "name": "Department", "type": "string", "order": 2 }
            ]
          }]
        }
        """;

        var path = WriteJson(json);
        VirtualEntityLoader.LoadFromFile(path, _tempDir);

        Assert.True(DataScaffold.TryGetEntity(slug, out var meta));

        // Create
        var emp = (DynamicDataObject)meta!.Handlers.Create();
        emp.Key = 1;
        emp.SetField("Name", "Alice Smith");
        emp.SetField("Department", "Engineering");

        // Save
        await DataScaffold.SaveAsync(meta, emp);

        // Load
        var loaded = (DynamicDataObject?)await DataScaffold.LoadAsync(meta, emp.Key);
        Assert.NotNull(loaded);
        Assert.Equal("Alice Smith", loaded!.GetField("Name"));
        Assert.Equal("Engineering", loaded.GetField("Department"));

        // Delete
        await meta.Handlers.DeleteAsync(emp.Key, default);
        var deleted = await DataScaffold.LoadAsync(meta, emp.Key);
        Assert.Null(deleted);
    }
}
