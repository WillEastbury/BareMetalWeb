using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;
using BareMetalWeb.Runtime;
using Xunit;

namespace BareMetalWeb.Runtime.Tests;

/// <summary>
/// Tests for <see cref="MetadataExtractor"/>.
/// </summary>
public class MetadataExtractorTests
{
    // ── Sample entity types for testing ──────────────────────────────────────

    [DataEntity("Sample Widgets", Slug = "sample-widgets", Permissions = "admin",
        ShowOnNav = true, NavGroup = "Testing", NavOrder = 5,
        IdGeneration = AutoIdStrategy.Sequential)]
    private class SampleWidget : BaseDataObject
    {
        [DataField(Label = "Widget Name", Order = 1, Required = true)]
        public string Name { get; set; } = string.Empty;

        [DataField(Label = "Price", Order = 2)]
        public decimal Price { get; set; }

        [DataField(Label = "Is Active", Order = 3)]
        public bool IsActive { get; set; }

        [DataField(Label = "Created Date", Order = 4)]
        public DateTime? CreatedDate { get; set; }

        [DataField(Order = 5)]
        [DataIndex]
        public string Category { get; set; } = string.Empty;
    }

    private enum SampleStatus { Pending, Active, Closed }

    [DataEntity("Sample Orders", IdGeneration = AutoIdStrategy.Sequential)]
    private class SampleOrder : BaseDataObject
    {
        [DataField(Label = "Description", Order = 1, Required = true)]
        public string Description { get; set; } = string.Empty;

        [DataField(Order = 2)]
        public SampleStatus Status { get; set; }

        [DataField(Order = 3)]
        [DataIndex(IndexKind.BTree)]
        public DateOnly DueDate { get; set; }
    }

    // A class with no [DataEntity] attribute — uses convention-based naming
    private class ConventionEntity : BaseDataObject
    {
        [DataField(Order = 1)]
        public string Title { get; set; } = string.Empty;
    }

    // ── EntityDefinition extraction tests ─────────────────────────────────────

    [Fact]
    public void ExtractFromType_ReadsDataEntityAttribute()
    {
        var (entity, _, _) = MetadataExtractor.ExtractFromType(typeof(SampleWidget));

        Assert.Equal("Sample Widgets", entity.Name);
        Assert.Equal("sample-widgets", entity.Slug);
        Assert.Equal("admin", entity.Permissions);
        Assert.True(entity.ShowOnNav);
        Assert.Equal("Testing", entity.NavGroup);
        Assert.Equal(5, entity.NavOrder);
        Assert.Equal("sequential", entity.IdStrategy);
        Assert.Equal(1, entity.Version);
    }

    [Fact]
    public void ExtractFromType_SequentialIdStrategy_MapsCorrectly()
    {
        var (entity, _, _) = MetadataExtractor.ExtractFromType(typeof(SampleOrder));

        Assert.Equal("sequential", entity.IdStrategy);
    }

    [Fact]
    public void ExtractFromType_WithoutDataEntityAttribute_UsesConventions()
    {
        var (entity, _, _) = MetadataExtractor.ExtractFromType(typeof(ConventionEntity));

        Assert.False(string.IsNullOrWhiteSpace(entity.Name));
        Assert.False(string.IsNullOrWhiteSpace(entity.Slug));
        // Permissions defaults to the entity name
        Assert.Equal(entity.Name, entity.Permissions);
    }

    [Fact]
    public void ExtractFromType_GeneratesUniqueIds()
    {
        var (e1, _, _) = MetadataExtractor.ExtractFromType(typeof(SampleWidget));
        var (e2, _, _) = MetadataExtractor.ExtractFromType(typeof(SampleWidget));

        // Each call produces fresh GUIDs
        Assert.NotEqual(e1.EntityId, e2.EntityId);
        Assert.NotEqual(e1.EntityId, e2.EntityId);
    }

    // ── FieldDefinition extraction tests ─────────────────────────────────────

    [Fact]
    public void ExtractFromType_ProducesCorrectFieldCount()
    {
        var (_, fields, _) = MetadataExtractor.ExtractFromType(typeof(SampleWidget));

        // SampleWidget has 5 annotated properties (Name, Price, IsActive, CreatedDate, Category)
        Assert.Equal(5, fields.Count);
    }

    [Fact]
    public void ExtractFromType_FieldsHaveCorrectNames()
    {
        var (_, fields, _) = MetadataExtractor.ExtractFromType(typeof(SampleWidget));

        var names = fields.Select(f => f.Name).ToHashSet();
        Assert.Contains("Name", names);
        Assert.Contains("Price", names);
        Assert.Contains("IsActive", names);
        Assert.Contains("CreatedDate", names);
        Assert.Contains("Category", names);
    }

    [Fact]
    public void ExtractFromType_ReadsFieldLabel()
    {
        var (_, fields, _) = MetadataExtractor.ExtractFromType(typeof(SampleWidget));

        var nameField = fields.Single(f => f.Name == "Name");
        Assert.Equal("Widget Name", nameField.Label);
    }

    [Fact]
    public void ExtractFromType_ReadsRequiredFlag()
    {
        var (_, fields, _) = MetadataExtractor.ExtractFromType(typeof(SampleWidget));

        var nameField = fields.Single(f => f.Name == "Name");
        Assert.True(nameField.Required);

        var priceField = fields.Single(f => f.Name == "Price");
        Assert.False(priceField.Required);
    }

    [Fact]
    public void ExtractFromType_ReadsOrdinals()
    {
        var (_, fields, _) = MetadataExtractor.ExtractFromType(typeof(SampleWidget));

        var nameField = fields.Single(f => f.Name == "Name");
        var priceField = fields.Single(f => f.Name == "Price");

        Assert.Equal(1, nameField.Ordinal);
        Assert.Equal(2, priceField.Ordinal);
    }

    [Fact]
    public void ExtractFromType_AllFieldsReferenceEntityId()
    {
        var (entity, fields, _) = MetadataExtractor.ExtractFromType(typeof(SampleWidget));

        Assert.All(fields, f => Assert.Equal(entity.EntityId, f.EntityId));
    }

    [Fact]
    public void ExtractFromType_SkipsCoreProperties()
    {
        var (_, fields, _) = MetadataExtractor.ExtractFromType(typeof(SampleWidget));

        var names = fields.Select(f => f.Name).ToList();
        Assert.DoesNotContain("Id", names);
        Assert.DoesNotContain("CreatedOnUtc", names);
        Assert.DoesNotContain("UpdatedOnUtc", names);
        Assert.DoesNotContain("CreatedBy", names);
        Assert.DoesNotContain("UpdatedBy", names);
        Assert.DoesNotContain("ETag", names);
    }

    // ── Field type mapping tests ─────────────────────────────────────────────

    [Theory]
    [InlineData("Name", "string")]
    [InlineData("Price", "decimal")]
    [InlineData("IsActive", "bool")]
    [InlineData("CreatedDate", "datetime")]
    [InlineData("Category", "string")]
    public void ExtractFromType_FieldTypes_MappedFromClrTypes(string fieldName, string expectedType)
    {
        var (_, fields, _) = MetadataExtractor.ExtractFromType(typeof(SampleWidget));

        var field = fields.Single(f => f.Name == fieldName);
        Assert.Equal(expectedType, field.Type);
    }

    [Fact]
    public void ExtractFromType_EnumField_HasEnumType()
    {
        var (_, fields, _) = MetadataExtractor.ExtractFromType(typeof(SampleOrder));

        var statusField = fields.Single(f => f.Name == "Status");
        Assert.Equal("enum", statusField.Type);
    }

    [Fact]
    public void ExtractFromType_EnumField_PopulatesEnumValues()
    {
        var (_, fields, _) = MetadataExtractor.ExtractFromType(typeof(SampleOrder));

        var statusField = fields.Single(f => f.Name == "Status");
        Assert.NotNull(statusField.EnumValues);
        Assert.Contains("Pending", statusField.EnumValues!);
        Assert.Contains("Active", statusField.EnumValues!);
        Assert.Contains("Closed", statusField.EnumValues!);
    }

    [Fact]
    public void ExtractFromType_DateOnlyField_HasDateType()
    {
        var (_, fields, _) = MetadataExtractor.ExtractFromType(typeof(SampleOrder));

        var dueDateField = fields.Single(f => f.Name == "DueDate");
        Assert.Equal("date", dueDateField.Type);
    }

    // ── IndexDefinition extraction tests ────────────────────────────────────

    [Fact]
    public void ExtractFromType_ProducesIndexForDataIndexAttribute()
    {
        var (entity, _, indexes) = MetadataExtractor.ExtractFromType(typeof(SampleWidget));

        // SampleWidget.Category has [DataIndex]
        Assert.Single(indexes);
        Assert.Equal("Category", indexes[0].FieldNames);
        Assert.Equal(entity.EntityId, indexes[0].EntityId);
        Assert.Equal("secondary", indexes[0].Type);
    }

    [Fact]
    public void ExtractFromType_BTreeIndex_HasCorrectType()
    {
        var (_, _, indexes) = MetadataExtractor.ExtractFromType(typeof(SampleOrder));

        // SampleOrder.DueDate has [DataIndex(IndexKind.BTree)]
        Assert.Single(indexes);
        Assert.Equal("DueDate", indexes[0].FieldNames);
        Assert.Equal("btree", indexes[0].Type);
    }

    [Fact]
    public void ExtractFromType_NoDataIndex_ProducesNoIndexes()
    {
        var (_, _, indexes) = MetadataExtractor.ExtractFromType(typeof(ConventionEntity));

        Assert.Empty(indexes);
    }

    // ── MapFieldTypeString tests ─────────────────────────────────────────────

    [Theory]
    [InlineData(typeof(bool), null, false, "bool")]
    [InlineData(typeof(bool?), null, false, "bool")]
    [InlineData(typeof(int), null, false, "int")]
    [InlineData(typeof(long), null, false, "int")]
    [InlineData(typeof(decimal), null, false, "decimal")]
    [InlineData(typeof(double), null, false, "decimal")]
    [InlineData(typeof(float), null, false, "decimal")]
    [InlineData(typeof(DateTime), null, false, "datetime")]
    [InlineData(typeof(DateOnly), null, false, "date")]
    [InlineData(typeof(TimeOnly), null, false, "time")]
    [InlineData(typeof(string), null, false, "string")]
    [InlineData(typeof(string), null, true, "lookup")]
    public void MapFieldTypeString_MapsCorrectly(
        Type propertyType,
        FormFieldType? explicitType,
        bool hasLookup,
        string expected)
    {
        var result = MetadataExtractor.MapFieldTypeString(propertyType, explicitType, hasLookup);
        Assert.Equal(expected, result);
    }

    [Theory]
    [InlineData(FormFieldType.TextArea, "multiline")]
    [InlineData(FormFieldType.YesNo, "bool")]
    [InlineData(FormFieldType.Integer, "int")]
    [InlineData(FormFieldType.Decimal, "decimal")]
    [InlineData(FormFieldType.DateTime, "datetime")]
    [InlineData(FormFieldType.DateOnly, "date")]
    [InlineData(FormFieldType.TimeOnly, "time")]
    [InlineData(FormFieldType.Enum, "enum")]
    [InlineData(FormFieldType.LookupList, "lookup")]
    [InlineData(FormFieldType.Email, "email")]
    public void MapFieldTypeString_ExplicitFormFieldType_MapsCorrectly(
        FormFieldType explicitType, string expected)
    {
        var result = MetadataExtractor.MapFieldTypeString(typeof(string), explicitType, hasLookup: false);
        Assert.Equal(expected, result);
    }

    // ── ResolveEntitySlug tests ──────────────────────────────────────────────

    [Fact]
    public void ResolveEntitySlug_WithExplicitSlug_ReturnsSlug()
    {
        // SampleWidget has Slug = "sample-widgets"
        var slug = MetadataExtractor.ResolveEntitySlug(typeof(SampleWidget));
        Assert.Equal("sample-widgets", slug);
    }

    [Fact]
    public void ResolveEntitySlug_WithoutSlug_DerivesFromName()
    {
        // SampleOrder has no explicit Slug
        var slug = MetadataExtractor.ResolveEntitySlug(typeof(SampleOrder));
        Assert.False(string.IsNullOrWhiteSpace(slug));
    }
}
