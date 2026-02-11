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

    public DataLookupAttribute(Type targetType)
    {
        TargetType = targetType;
    }
}


