namespace BareMetalWeb.Data;

/// <summary>
/// Indicates that this field's value should be auto-populated from a referenced entity on the parent
/// form when opening a new sub-entity row in a child list editor modal.
/// For example, an OrderRow.DiscountPercent can be pre-filled from the parent Order's Customer record.
/// </summary>
[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class CopyFromParentAttribute : Attribute
{
    /// <summary>The name of the lookup field on the parent form (e.g., "CustomerId").</summary>
    public string ParentFieldName { get; }

    /// <summary>The entity slug used to fetch the referenced parent entity (e.g., "customers").</summary>
    public string EntitySlug { get; }

    /// <summary>The field name to copy from the referenced parent entity (e.g., "DiscountPercent").</summary>
    public string SourceFieldName { get; }

    public CopyFromParentAttribute(string parentFieldName, string entitySlug, string sourceFieldName)
    {
        ParentFieldName = parentFieldName;
        EntitySlug = entitySlug;
        SourceFieldName = sourceFieldName;
    }
}
