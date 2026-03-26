namespace BareMetalWeb.Data;

[AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
public sealed class DataEntityAttribute : Attribute
{
    public string Name { get; }
    public string? Slug { get; set; }
    public string Permissions { get; set; } = string.Empty;
    public bool ShowOnNav { get; set; } = false;
    public string? NavGroup { get; set; }
    public int NavOrder { get; set; } = 0;
    public AutoIdStrategy IdGeneration { get; set; } = AutoIdStrategy.Sequential;
    public string? DefaultSortField { get; set; }
    public SortDirection DefaultSortDirection { get; set; } = SortDirection.Asc;
    /// <summary>
    /// When set, enables row-level security (RLS) on this entity.
    /// The value names the field whose value must match the current user's identifier
    /// for the record to be visible/mutable by that user. Admins bypass RLS.
    /// Typical value: <c>"CreatedBy"</c>.
    /// </summary>
    public string? RlsOwnerField { get; set; }

    public DataEntityAttribute(string name)
    {
        Name = name;
    }
}


