using System.Collections.Generic;
using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Regression tests for Tags / List&lt;string&gt; field validation.
/// Issue: "VNext bug: Validation on tags not working properly."
/// The VNext SPA sends List&lt;string&gt; TextArea fields as a plain newline-separated
/// string rather than a JSON array. TryConvertJson must accept both forms.
/// </summary>
[Collection("SharedState")]
public class StringListFieldBindingTests
{
    [DataEntity("TagsTestEntities")]
    private class TagsTestEntity : BaseDataObject
    {
        public override string EntityTypeName => "TagsTestEntities";
        private const int Ord_Name = BaseFieldCount + 0;
        private const int Ord_Tags = BaseFieldCount + 1;
        internal new const int TotalFieldCount = BaseFieldCount + 2;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Name", Ord_Name),
            new FieldSlot("Tags", Ord_Tags),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public TagsTestEntity() : base(TotalFieldCount) { }
        public TagsTestEntity(string createdBy) : base(TotalFieldCount, createdBy) { }


        [DataField(Label = "Tags", Order = 1)]
        public List<string> Tags
        {
            get => (List<string>?)_values[Ord_Tags] ?? new();
            set => _values[Ord_Tags] = value;
        }



        [DataField(Label = "Name", Order = 2)]
        public string Name
        {
            get => (string?)_values[Ord_Name] ?? string.Empty;
            set => _values[Ord_Name] = value;
        }
    }

    private static DataEntityMetadata GetMeta()
    {
        DataScaffold.RegisterEntity<TagsTestEntity>();
        var meta = DataScaffold.GetEntityByType(typeof(TagsTestEntity));
        Assert.NotNull(meta);
        return meta!;
    }

    // ── ApplyValuesFromJson ──────────────────────────────────────────────────

    [Fact]
    public void ApplyValuesFromJson_TagsField_BindsFromJsonArray()
    {
        // Arrange – JSON array (ideal case)
        var meta = GetMeta();
        var instance = new TagsTestEntity();
        var json = JsonDocToDict(
            "{\"Tags\":[\"test\",\"test2\"],\"Name\":\"Widget\"}");

        // Act
        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, json, forCreate: true, allowMissing: false);

        // Assert
        Assert.Empty(errors);
        Assert.Equal(new List<string> { "test", "test2" }, instance.Tags);
    }

    [Fact]
    public void ApplyValuesFromJson_TagsField_BindsFromNewlineSeparatedString()
    {
        // Arrange – VNext SPA sends textarea value as a plain newline-separated string
        var meta = GetMeta();
        var instance = new TagsTestEntity();
        var json = JsonDocToDict(
            "{\"Tags\":\"test\\ntest2\",\"Name\":\"Widget\"}");

        // Act
        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, json, forCreate: true, allowMissing: false);

        // Assert – must succeed and parse the tags
        Assert.Empty(errors);
        Assert.Equal(new List<string> { "test", "test2" }, instance.Tags);
    }

    [Fact]
    public void ApplyValuesFromJson_TagsField_BindsFromCommaSeparatedString()
    {
        // Arrange – JS array toString produces "test,test2"
        var meta = GetMeta();
        var instance = new TagsTestEntity();
        var json = JsonDocToDict(
            "{\"Tags\":\"test,test2\",\"Name\":\"Widget\"}");

        // Act
        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, json, forCreate: true, allowMissing: false);

        // Assert
        Assert.Empty(errors);
        Assert.Equal(new List<string> { "test", "test2" }, instance.Tags);
    }

    [Fact]
    public void ApplyValuesFromJson_TagsField_BindsFromNullValue()
    {
        // Arrange – when Tags is cleared and not required, VNext sends null
        var meta = GetMeta();
        var instance = new TagsTestEntity();
        var json = JsonDocToDict(
            "{\"Tags\":null,\"Name\":\"Widget\"}");

        // Act
        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, json, forCreate: true, allowMissing: false);

        // Assert – null produces an empty list, no error
        Assert.Empty(errors);
        Assert.Empty(instance.Tags);
    }

    // ── ApplyValuesFromForm ──────────────────────────────────────────────────

    [Fact]
    public void ApplyValuesFromForm_TagsField_BindsFromNewlineSeparatedString()
    {
        // Arrange – HTML form textarea submits newline-separated value
        var meta = GetMeta();
        var instance = new TagsTestEntity();
        var formValues = new Dictionary<string, string?>
        {
            ["Tags"] = "test\ntest2",
            ["Name"] = "Widget"
        };

        // Act
        var errors = DataScaffold.ApplyValuesFromForm(meta, instance, formValues, forCreate: true);

        // Assert
        Assert.Empty(errors);
        Assert.Equal(new List<string> { "test", "test2" }, instance.Tags);
    }

    private static Dictionary<string, JsonElement> JsonDocToDict(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var dict = new Dictionary<string, JsonElement>();
        foreach (var prop in doc.RootElement.EnumerateObject())
            dict[prop.Name] = prop.Value.Clone();
        return dict;
    }
}
