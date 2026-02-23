namespace BareMetalWeb.Runtime;

/// <summary>
/// Compiled, immutable representation of a single index on a <see cref="RuntimeEntityModel"/>.
/// </summary>
/// <param name="IndexId">Stable identity (from <see cref="IndexDefinition.Id"/>).</param>
/// <param name="EntityId">Entity identity this index belongs to.</param>
/// <param name="FieldNames">Ordered list of field names included in this index.</param>
/// <param name="Type">Index type hint: "secondary" or "composite".</param>
public sealed record RuntimeIndexModel(
    string IndexId,
    string EntityId,
    IReadOnlyList<string> FieldNames,
    string Type
);
