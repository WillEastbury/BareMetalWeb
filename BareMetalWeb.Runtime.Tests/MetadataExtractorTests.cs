using System;
using System.Collections.Generic;
using System.Linq;
using BareMetalWeb.Core;
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
        public override string EntityTypeName => "Sample Widgets";
        private const int Ord_Category = BaseFieldCount + 0;
        private const int Ord_CreatedDate = BaseFieldCount + 1;
        private const int Ord_IsActive = BaseFieldCount + 2;
        private const int Ord_Name = BaseFieldCount + 3;
        private const int Ord_Price = BaseFieldCount + 4;
        internal new const int TotalFieldCount = BaseFieldCount + 5;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("Category", Ord_Category),
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedDate", Ord_CreatedDate),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("IsActive", Ord_IsActive),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Name", Ord_Name),
            new FieldSlot("Price", Ord_Price),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public SampleWidget() : base(TotalFieldCount) { }
        public SampleWidget(string createdBy) : base(TotalFieldCount, createdBy) { }


        [DataField(Label = "Widget Name", Order = 1, Required = true)]
        public string Name
        {
            get => (string?)_values[Ord_Name] ?? string.Empty;
            set => _values[Ord_Name] = value;
        }



        [DataField(Label = "Price", Order = 2)]
        public decimal Price
        {
            get => (decimal)(_values[Ord_Price] ?? 0m);
            set => _values[Ord_Price] = value;
        }



        [DataField(Label = "Is Active", Order = 3)]
        public bool IsActive
        {
            get => (bool)(_values[Ord_IsActive] ?? false);
            set => _values[Ord_IsActive] = value;
        }



        [DataField(Label = "Created Date", Order = 4)]
        public DateTime? CreatedDate
        {
            get => (DateTime?)_values[Ord_CreatedDate];
            set => _values[Ord_CreatedDate] = value;
        }



        [DataField(Order = 5)]
        [DataIndex]
        public string Category
        {
            get => (string?)_values[Ord_Category] ?? string.Empty;
            set => _values[Ord_Category] = value;
        }
    }

    private enum SampleStatus { Pending, Active, Closed }

    [DataEntity("Sample Orders", IdGeneration = AutoIdStrategy.Sequential)]
    private class SampleOrder : BaseDataObject
    {
        public override string EntityTypeName => "Sample Orders";
        private const int Ord_Description = BaseFieldCount + 0;
        private const int Ord_DueDate = BaseFieldCount + 1;
        private const int Ord_Status = BaseFieldCount + 2;
        internal new const int TotalFieldCount = BaseFieldCount + 3;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("Description", Ord_Description),
            new FieldSlot("DueDate", Ord_DueDate),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Status", Ord_Status),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public SampleOrder() : base(TotalFieldCount) { }
        public SampleOrder(string createdBy) : base(TotalFieldCount, createdBy) { }


        [DataField(Label = "Description", Order = 1, Required = true)]
        public string Description
        {
            get => (string?)_values[Ord_Description] ?? string.Empty;
            set => _values[Ord_Description] = value;
        }



        [DataField(Order = 2)]
        public SampleStatus Status
        {
            get => _values[Ord_Status] is SampleStatus v ? v : default;
            set => _values[Ord_Status] = value;
        }



        [DataField(Order = 3)]
        [DataIndex(IndexKind.BTree)]
        public DateOnly DueDate
        {
            get => _values[Ord_DueDate] is DateOnly d ? d : default;
            set => _values[Ord_DueDate] = value;
        }
    }

    // A class with no [DataEntity] attribute — uses convention-based naming
    private class ConventionEntity : BaseDataObject
    {
        private const int Ord_Title = BaseFieldCount + 0;
        internal new const int TotalFieldCount = BaseFieldCount + 1;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Title", Ord_Title),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public ConventionEntity() : base(TotalFieldCount) { }
        public ConventionEntity(string createdBy) : base(TotalFieldCount, createdBy) { }


        [DataField(Order = 1)]
        public string Title
        {
            get => (string?)_values[Ord_Title] ?? string.Empty;
            set => _values[Ord_Title] = value;
        }
    }

    // ── EntityDefinition extraction tests ─────────────────────────────────────

    [Fact]
    public void BuildFromMetadata_ReadsEntityAttributes()
    {
        DataScaffold.RegisterEntity<SampleWidget>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleWidget))!;
        var (entity, _, _) = MetadataExtractor.BuildFromMetadata(meta);

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
    public void BuildFromMetadata_SequentialIdStrategy_MapsCorrectly()
    {
        DataScaffold.RegisterEntity<SampleOrder>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleOrder))!;
        var (entity, _, _) = MetadataExtractor.BuildFromMetadata(meta);

        Assert.Equal("sequential", entity.IdStrategy);
    }

    [Fact]
    public void BuildFromMetadata_GeneratesUniqueIds()
    {
        DataScaffold.RegisterEntity<SampleWidget>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleWidget))!;
        var (e1, _, _) = MetadataExtractor.BuildFromMetadata(meta);
        var (e2, _, _) = MetadataExtractor.BuildFromMetadata(meta);

        // Each call produces fresh GUIDs
        Assert.NotEqual(e1.EntityId, e2.EntityId);
    }

    // ── FieldDefinition extraction tests ─────────────────────────────────────

    [Fact]
    public void BuildFromMetadata_ProducesCorrectFieldCount()
    {
        DataScaffold.RegisterEntity<SampleWidget>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleWidget))!;
        var (_, fields, _) = MetadataExtractor.BuildFromMetadata(meta);

        // SampleWidget has 5 annotated properties (Name, Price, IsActive, CreatedDate, Category)
        Assert.Equal(5, fields.Count);
    }

    [Fact]
    public void BuildFromMetadata_FieldsHaveCorrectNames()
    {
        DataScaffold.RegisterEntity<SampleWidget>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleWidget))!;
        var (_, fields, _) = MetadataExtractor.BuildFromMetadata(meta);

        var names = fields.Select(f => f.Name).ToHashSet();
        Assert.Contains("Name", names);
        Assert.Contains("Price", names);
        Assert.Contains("IsActive", names);
        Assert.Contains("CreatedDate", names);
        Assert.Contains("Category", names);
    }

    [Fact]
    public void BuildFromMetadata_ReadsFieldLabel()
    {
        DataScaffold.RegisterEntity<SampleWidget>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleWidget))!;
        var (_, fields, _) = MetadataExtractor.BuildFromMetadata(meta);

        var nameField = fields.Single(f => f.Name == "Name");
        Assert.Equal("Widget Name", nameField.Label);
    }

    [Fact]
    public void BuildFromMetadata_ReadsRequiredFlag()
    {
        DataScaffold.RegisterEntity<SampleWidget>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleWidget))!;
        var (_, fields, _) = MetadataExtractor.BuildFromMetadata(meta);

        var nameField = fields.Single(f => f.Name == "Name");
        Assert.True(nameField.Required);

        var priceField = fields.Single(f => f.Name == "Price");
        Assert.False(priceField.Required);
    }

    [Fact]
    public void BuildFromMetadata_ReadsOrdinals()
    {
        DataScaffold.RegisterEntity<SampleWidget>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleWidget))!;
        var (_, fields, _) = MetadataExtractor.BuildFromMetadata(meta);

        var nameField = fields.Single(f => f.Name == "Name");
        var priceField = fields.Single(f => f.Name == "Price");

        Assert.Equal(1, nameField.Ordinal);
        Assert.Equal(2, priceField.Ordinal);
    }

    [Fact]
    public void BuildFromMetadata_AllFieldsReferenceEntityId()
    {
        DataScaffold.RegisterEntity<SampleWidget>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleWidget))!;
        var (entity, fields, _) = MetadataExtractor.BuildFromMetadata(meta);

        Assert.All(fields, f => Assert.Equal(entity.EntityId, f.EntityId));
    }

    [Fact]
    public void BuildFromMetadata_SkipsCoreProperties()
    {
        DataScaffold.RegisterEntity<SampleWidget>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleWidget))!;
        var (_, fields, _) = MetadataExtractor.BuildFromMetadata(meta);

        var names = fields.Select(f => f.Name).ToList();
        Assert.DoesNotContain("Key", names);
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
    public void BuildFromMetadata_FieldTypes_MappedFromClrTypes(string fieldName, string expectedType)
    {
        DataScaffold.RegisterEntity<SampleWidget>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleWidget))!;
        var (_, fields, _) = MetadataExtractor.BuildFromMetadata(meta);

        var field = fields.Single(f => f.Name == fieldName);
        Assert.Equal(expectedType, field.Type);
    }

    [Fact]
    public void BuildFromMetadata_EnumField_HasEnumType()
    {
        DataScaffold.RegisterEntity<SampleOrder>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleOrder))!;
        var (_, fields, _) = MetadataExtractor.BuildFromMetadata(meta);

        var statusField = fields.Single(f => f.Name == "Status");
        Assert.Equal("enum", statusField.Type);
    }

    [Fact]
    public void BuildFromMetadata_EnumField_PopulatesEnumValues()
    {
        DataScaffold.RegisterEntity<SampleOrder>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleOrder))!;
        var (_, fields, _) = MetadataExtractor.BuildFromMetadata(meta);

        var statusField = fields.Single(f => f.Name == "Status");
        Assert.NotNull(statusField.EnumValues);
        Assert.Contains("Pending", statusField.EnumValues!);
        Assert.Contains("Active", statusField.EnumValues!);
        Assert.Contains("Closed", statusField.EnumValues!);
    }

    [Fact]
    public void BuildFromMetadata_DateOnlyField_HasDateType()
    {
        DataScaffold.RegisterEntity<SampleOrder>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleOrder))!;
        var (_, fields, _) = MetadataExtractor.BuildFromMetadata(meta);

        var dueDateField = fields.Single(f => f.Name == "DueDate");
        Assert.Equal("date", dueDateField.Type);
    }

    // ── IndexDefinition extraction tests ────────────────────────────────────

    [Fact]
    public void BuildFromMetadata_ProducesIndexForDataIndexAttribute()
    {
        DataScaffold.RegisterEntity<SampleWidget>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleWidget))!;
        var (entity, _, indexes) = MetadataExtractor.BuildFromMetadata(meta);

        // SampleWidget.Category has [DataIndex]
        Assert.Single(indexes);
        Assert.Equal("Category", indexes[0].FieldNames);
        Assert.Equal(entity.EntityId, indexes[0].EntityId);
        Assert.Equal("secondary", indexes[0].Type);
    }

    [Fact]
    public void BuildFromMetadata_BTreeIndex_HasCorrectType()
    {
        DataScaffold.RegisterEntity<SampleOrder>();
        var meta = DataScaffold.GetEntityByType(typeof(SampleOrder))!;
        var (_, _, indexes) = MetadataExtractor.BuildFromMetadata(meta);

        // SampleOrder.DueDate has [DataIndex(IndexKind.BTree)]
        Assert.Single(indexes);
        Assert.Equal("DueDate", indexes[0].FieldNames);
        Assert.Equal("btree", indexes[0].Type);
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
    public void ResolveEntitySlug_RegisteredEntity_ReturnsSlug()
    {
        DataScaffold.RegisterEntity<SampleWidget>();
        var slug = MetadataExtractor.ResolveEntitySlug(typeof(SampleWidget));
        Assert.Equal("sample-widgets", slug);
    }

    [Fact]
    public void ResolveEntitySlug_UnregisteredEntity_DerivesFromTypeName()
    {
        // ConventionEntity is not registered — falls back to convention
        var slug = MetadataExtractor.ResolveEntitySlug(typeof(ConventionEntity));
        Assert.False(string.IsNullOrWhiteSpace(slug));
    }
}
