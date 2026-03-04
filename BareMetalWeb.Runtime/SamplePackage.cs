using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Represents a shipped metadata sample package that can be deployed via the gallery page.
/// Each package bundles <see cref="EntityDefinition"/>, <see cref="FieldDefinition"/>, and
/// <see cref="IndexDefinition"/> records for a logical group of related entities.
/// </summary>
public sealed class SamplePackage
{
    /// <summary>Human-readable display name, e.g. "Sales Module".</summary>
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>Identifier that also matches the JSON file name, e.g. "sales".</summary>
    [JsonPropertyName("slug")]
    public string Slug { get; set; } = string.Empty;

    /// <summary>Short description shown on the gallery card.</summary>
    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    /// <summary>Bootstrap icon class, e.g. "bi-cart-check".</summary>
    [JsonPropertyName("icon")]
    public string Icon { get; set; } = "bi-box";

    /// <summary>Schema version of this sample file.</summary>
    [JsonPropertyName("version")]
    public string Version { get; set; } = "1.0";

    [JsonPropertyName("entities")]
    public List<EntityDefinition> Entities { get; set; } = new();

    [JsonPropertyName("fields")]
    public List<FieldDefinition> Fields { get; set; } = new();

    [JsonPropertyName("indexes")]
    public List<IndexDefinition> Indexes { get; set; } = new();

    [JsonPropertyName("actions")]
    public List<ActionDefinition> Actions { get; set; } = new();

    [JsonPropertyName("actionCommands")]
    public List<ActionCommandDefinition> ActionCommands { get; set; } = new();
}
