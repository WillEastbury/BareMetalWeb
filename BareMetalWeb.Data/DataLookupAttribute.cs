namespace BareMetalWeb.Data;

[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class DataLookupAttribute : Attribute
{
    public Type TargetType { get; }
    public string ValueField { get; set; } = nameof(BaseDataObject.Id);
    public string DisplayField { get; set; } = "Name";
    public string? QueryField { get; set; }
    public QueryOperator QueryOperator { get; set; } = QueryOperator.Equals;
    public string? QueryValue { get; set; }
    public string? SortField { get; set; }
    public SortDirection SortDirection { get; set; } = SortDirection.Asc;
    public int CacheSeconds { get; set; } = 60;

    /// <summary>
    /// Comma-separated field copy mappings applied when a lookup value is selected in a sub-entity modal.
    /// Format: "SourceField->TargetField" or multiple: "Price->UnitPrice,Name->ProductName".
    /// When the lookup selection changes, the specified fields are copied from the referenced entity
    /// to the corresponding local fields.
    /// </summary>
    public string? CopyFields { get; set; }

    public DataLookupAttribute(Type targetType)
    {
        TargetType = targetType;
    }
}


