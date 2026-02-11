namespace BareMetalWeb.Data;

public sealed class QueryGroup
{
    public List<QueryClause> Clauses { get; set; } = new();
    public List<QueryGroup> Groups { get; set; } = new();
    public QueryGroupLogic Logic { get; set; } = QueryGroupLogic.And;
}
