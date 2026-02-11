namespace BareMetalWeb.Data;

public sealed class QueryClause
{
    public string Field { get; set; } = string.Empty;
    public QueryOperator Operator { get; set; } = QueryOperator.Equals;
    public object? Value { get; set; }
}
