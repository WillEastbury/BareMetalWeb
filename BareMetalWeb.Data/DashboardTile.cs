namespace BareMetalWeb.Data;

/// <summary>
/// Describes a single KPI tile on a dashboard.
/// Stored as part of a <see cref="DashboardDefinition"/> (serialised to JSON).
/// </summary>
public sealed class DashboardTile
{
    /// <summary>Display title shown on the tile card header.</summary>
    public string Title { get; set; } = string.Empty;

    /// <summary>Bootstrap icon class, e.g. "bi-currency-dollar" or "bi-people-fill".</summary>
    public string Icon { get; set; } = "bi-bar-chart-fill";

    /// <summary>Bootstrap colour variant — primary, success, danger, warning, info, secondary.</summary>
    public string Color { get; set; } = "primary";

    /// <summary>Slug of the entity to query (e.g. "orders").</summary>
    public string EntitySlug { get; set; } = string.Empty;

    /// <summary>Aggregate function: count | sum | avg | min | max.</summary>
    public string AggregateFunction { get; set; } = "count";

    /// <summary>Field to aggregate (required for sum/avg/min/max, leave empty for count).</summary>
    public string AggregateField { get; set; } = string.Empty;

    /// <summary>Optional filter field name used to restrict the query (e.g. "Status").</summary>
    public string FilterField { get; set; } = string.Empty;

    /// <summary>Optional filter value matched against <see cref="FilterField"/> (e.g. "Pending").</summary>
    public string FilterValue { get; set; } = string.Empty;

    /// <summary>String prepended to the result value (e.g. "$").</summary>
    public string ValuePrefix { get; set; } = string.Empty;

    /// <summary>String appended to the result value (e.g. "%").</summary>
    public string ValueSuffix { get; set; } = string.Empty;

    /// <summary>Optional number of decimal places. -1 means auto (integers stay integer).</summary>
    public int DecimalPlaces { get; set; } = -1;

    /// <summary>
    /// Optional entity slug whose records are used to draw a mini sparkline
    /// bar chart beneath the KPI value (grouped by <see cref="SparklineGroupField"/>).
    /// Leave empty to omit the sparkline.
    /// </summary>
    public string SparklineEntitySlug { get; set; } = string.Empty;

    /// <summary>Field used to group records for the sparkline (e.g. a date field or status).</summary>
    public string SparklineGroupField { get; set; } = string.Empty;

    /// <summary>Aggregate function for the sparkline bars: count | sum | avg.</summary>
    public string SparklineAggregateFunction { get; set; } = "count";

    /// <summary>Field to aggregate per sparkline group (leave empty for count).</summary>
    public string SparklineAggregateField { get; set; } = string.Empty;
}
