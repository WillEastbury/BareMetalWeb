using System.Collections.Generic;
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
        [DataField(Label = "Tags", Order = 1)]
        public List<string> Tags { get; set; } = new();

        [DataField(Label = "Name", Order = 2)]
        public string Name { get; set; } = string.Empty;
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
