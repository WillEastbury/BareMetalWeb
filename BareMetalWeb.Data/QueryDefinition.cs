namespace BareMetalWeb.Data;

public sealed class QueryDefinition
{
    public List<QueryClause> Clauses { get; set; } = new();
    public List<QueryGroup> Groups { get; set; } = new();
    public QueryGroupLogic Logic { get; set; } = QueryGroupLogic.And;
    public List<SortClause> Sorts { get; set; } = new();
    public int? Skip { get; set; }
    public int? Top { get; set; }
}
