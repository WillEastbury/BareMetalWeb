using System.Collections.Generic;
using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for List&lt;string&gt; field binding in ApplyValuesFromJson.
/// Regression tests for "VNext bug: Validation on tags not working properly."
/// The VNext SPA sends textarea values (Tags) as plain newline-delimited strings,
/// not as JSON arrays, so TryConvertJson must accept both forms.
/// </summary>
public class StringListFieldBindingTests
{
    [DataEntity("TagTestEntities")]
    private class TagTestEntity : BaseDataObject
    {
        [DataField(Label = "Tags", Order = 1)]
        public List<string> Tags { get; set; } = new();

        [DataField(Label = "Name", Order = 2)]
        public string Name { get; set; } = string.Empty;
    }

    private static DataEntityMetadata GetMeta()
    {
        DataScaffold.RegisterEntity<TagTestEntity>();
        var meta = DataScaffold.GetEntityByType(typeof(TagTestEntity));
        Assert.NotNull(meta);
        return meta!;
    }

    [Fact]
    public void ApplyValuesFromJson_StringListField_AcceptsJsonArray()
    {
        // Arrange – tags sent as a proper JSON array
        var meta = GetMeta();
        var instance = new TagTestEntity();
        var json = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            """{"Tags":["test","test2"],"Name":"Widget"}""");

        // Act
        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, json!, forCreate: true, allowMissing: false);

        // Assert
        Assert.Empty(errors);
        Assert.Equal(new List<string> { "test", "test2" }, instance.Tags);
    }

    [Fact]
    public void ApplyValuesFromJson_StringListField_AcceptsNewlineDelimitedString()
    {
        // Arrange – tags sent as a newline-delimited string (how VNext textarea submits)
        var meta = GetMeta();
        var instance = new TagTestEntity();
        var json = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            """{"Tags":"test\ntest2","Name":"Widget"}""");

        // Act
        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, json!, forCreate: true, allowMissing: false);

        // Assert – must not produce "Tags is invalid"
        Assert.Empty(errors);
        Assert.Equal(new List<string> { "test", "test2" }, instance.Tags);
    }

    [Fact]
    public void ApplyValuesFromJson_StringListField_AcceptsCommaDelimitedString()
    {
        // Arrange – tags sent as a comma-delimited string
        var meta = GetMeta();
        var instance = new TagTestEntity();
        var json = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            """{"Tags":"test,test2","Name":"Widget"}""");

        // Act
        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, json!, forCreate: true, allowMissing: false);

        // Assert
        Assert.Empty(errors);
        Assert.Equal(new List<string> { "test", "test2" }, instance.Tags);
    }

    [Fact]
    public void ApplyValuesFromJson_StringListField_AcceptsNullValue()
    {
        // Arrange – tags sent as JSON null
        var meta = GetMeta();
        var instance = new TagTestEntity();
        var json = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            """{"Tags":null,"Name":"Widget"}""");

        // Act
        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, json!, forCreate: true, allowMissing: false);

        // Assert
        Assert.Empty(errors);
        Assert.Empty(instance.Tags);
    }
}
