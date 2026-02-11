namespace BareMetalWeb.Data;

public sealed class SortClause
{
    public string Field { get; set; } = string.Empty;
    public SortDirection Direction { get; set; } = SortDirection.Asc;
}
