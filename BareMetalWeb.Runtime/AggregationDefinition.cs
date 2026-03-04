using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted definition of a named aggregation view — specifies group-by levels
/// and measures (sum, count, avg, min, max) for drill-through browsing.
/// </summary>
[DataEntity("Aggregation Definitions", ShowOnNav = true, NavGroup = "Admin", NavOrder = 1005)]
public class AggregationDefinition : RenderableDataObject
{
    /// <summary>Foreign key to <see cref="EntityDefinition.EntityId"/>.</summary>
    [DataField(Label = "Entity ID", Order = 1, Required = true)]
    [DataLookup(typeof(EntityDefinition), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc)]
    public string EntityId { get; set; } = string.Empty;

    [DataField(Label = "Name", Order = 2, Required = true)]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Pipe-separated field names that define the group-by levels.
    /// E.g. "Category|SubCategory|Product" → three drill-down levels.
    /// </summary>
    [DataField(Label = "Group By (pipe-separated)", Order = 3, Required = true)]
    public string GroupByFields { get; set; } = string.Empty;

    /// <summary>
    /// Pipe-separated measure expressions: "fn:field" pairs.
    /// E.g. "sum:Amount|count:Id|avg:Price".
    /// </summary>
    [DataField(Label = "Measures (fn:field pipe-separated)", Order = 4, Required = true)]
    public string Measures { get; set; } = string.Empty;

    public IReadOnlyList<string> GetGroupByList()
        => GroupByFields
            .Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToArray();

    public IReadOnlyList<(string Function, string Field)> GetMeasureList()
        => Measures
            .Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(m =>
            {
                var parts = m.Split(':', 2);
                return parts.Length == 2
                    ? (parts[0].ToLowerInvariant(), parts[1])
                    : ("count", m);
            })
            .ToArray();

    public override string ToString() => Name;
}
