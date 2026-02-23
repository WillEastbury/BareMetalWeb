using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace BareMetalWeb.Data;

/// <summary>
/// A <see cref="BaseDataObject"/> that stores field values in a string dictionary.
/// Used as the runtime backing type for virtual entities defined in JSON metadata.
/// </summary>
public sealed class DynamicDataObject : BaseDataObject
{
    /// <summary>
    /// The name of the virtual entity type this instance belongs to (e.g. "Ticket").
    /// Used to locate entity metadata and route to the correct storage.
    /// </summary>
    public string EntityTypeName { get; set; } = string.Empty;

    /// <summary>
    /// Field values keyed by field name. All values are stored as strings for
    /// simple serialization and broad compatibility with existing conversion helpers.
    /// </summary>
    [JsonInclude]
    public Dictionary<string, string?> Fields { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Gets a field value by name, returning null if the field is not set.</summary>
    public string? GetField(string name)
        => Fields.TryGetValue(name, out var value) ? value : null;

    /// <summary>Sets a field value by name.</summary>
    public void SetField(string name, string? value)
        => Fields[name] = value;
}
