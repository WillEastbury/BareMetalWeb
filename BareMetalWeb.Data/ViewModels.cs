namespace BareMetalWeb.Data;

/// <summary>
/// Defines a projected output column for a ViewDefinition.
/// </summary>
public sealed class ViewProjection
{
    /// <summary>Entity slug (e.g. "orders"). Empty means root entity.</summary>
    public string Entity { get; set; } = string.Empty;
    /// <summary>Field name on the entity.</summary>
    public string Field { get; set; } = string.Empty;
    /// <summary>Output column alias / label.</summary>
    public string Alias { get; set; } = string.Empty;
}

/// <summary>
/// Defines a join relationship between two entities in a ViewDefinition.
/// </summary>
public sealed class ViewJoinDefinition
{
    public string SourceEntity { get; set; } = string.Empty;
    public string SourceField { get; set; } = string.Empty;
    public string TargetEntity { get; set; } = string.Empty;
    public string TargetField { get; set; } = string.Empty;
    /// <summary>Inner or Left. Right and FullOuter are also honoured by the engine.</summary>
    public JoinType Type { get; set; } = JoinType.Inner;
}

/// <summary>
/// Defines a row filter predicate for a ViewDefinition.
/// </summary>
public sealed class ViewFilterDefinition
{
    /// <summary>Entity slug. Empty means root entity.</summary>
    public string Entity { get; set; } = string.Empty;
    public string Field { get; set; } = string.Empty;
    /// <summary>Operator string: =, !=, &gt;, &gt;=, &lt;, &lt;=, contains, startswith, endswith, in, notin.</summary>
    public string Operator { get; set; } = "=";
    public string Value { get; set; } = string.Empty;
}

/// <summary>
/// Defines a sort key for a ViewDefinition.
/// </summary>
public sealed class ViewSortDefinition
{
    /// <summary>Entity slug. Empty means root entity.</summary>
    public string Entity { get; set; } = string.Empty;
    public string Field { get; set; } = string.Empty;
    public bool Descending { get; set; }
}
