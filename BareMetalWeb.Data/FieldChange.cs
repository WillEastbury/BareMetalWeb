namespace BareMetalWeb.Data;

/// <summary>
/// Represents a change to a single field in an entity
/// </summary>
public sealed record FieldChange(
    string FieldName,
    string? OldValue,
    string? NewValue
);
