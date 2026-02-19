namespace BareMetalWeb.Data;

/// <summary>
/// Represents a change to a single field in an entity
/// </summary>
public sealed class FieldChange
{
    public string FieldName { get; set; } = string.Empty;
    public string? OldValue { get; set; }
    public string? NewValue { get; set; }

    public FieldChange() { }

    public FieldChange(string fieldName, string? oldValue, string? newValue)
    {
        FieldName = fieldName;
        OldValue = oldValue;
        NewValue = newValue;
    }
}
