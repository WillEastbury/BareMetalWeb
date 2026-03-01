namespace BareMetalWeb.Data;

/// <summary>Describes a join between two entity types.</summary>
public sealed class ReportJoin
{
    public string FromEntity { get; set; } = string.Empty;
    public string FromField { get; set; } = string.Empty;
    public string ToEntity { get; set; } = string.Empty;
    public string ToField { get; set; } = string.Empty;
    public JoinType Type { get; set; } = JoinType.Inner;
}

/// <summary>Describes a projected output column in a report.</summary>
public sealed class ReportColumn
{
    public string Entity { get; set; } = string.Empty;
    public string Field { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    public string Format { get; set; } = string.Empty;
    public AggregateFunction Aggregate { get; set; } = AggregateFunction.None;
}

/// <summary>Describes a filter predicate applied to a report result.</summary>
public sealed class ReportFilter
{
    public string Entity { get; set; } = string.Empty;
    public string Field { get; set; } = string.Empty;
    public string Operator { get; set; } = "=";
    public string Value { get; set; } = string.Empty;
}

/// <summary>Describes a runtime-supplied parameter for a report.</summary>
public sealed class ReportParameter
{
    public string Name { get; set; } = string.Empty;
    public string Label { get; set; } = string.Empty;
    /// <summary>Parameter input type: string, date, number, select.</summary>
    public string Type { get; set; } = "string";
    public string DefaultValue { get; set; } = string.Empty;
    /// <summary>Static options for dropdown (Type=select). Each entry is "value|label" or just "value".</summary>
    public List<string>? Options { get; set; }
    /// <summary>Dynamic dropdown source: "entitySlug.fieldName" — distinct values loaded at render time.</summary>
    public string? FieldSource { get; set; }
}

/// <summary>The output of a report execution — column headers and data rows.</summary>
public sealed class ReportResult
{
    /// <summary>Display labels for each column, in order.</summary>
    public string[] ColumnLabels { get; init; } = Array.Empty<string>();

    /// <summary>Data rows — each entry is a string?[] aligned with ColumnLabels.</summary>
    public IReadOnlyList<string?[]> Rows { get; init; } = Array.Empty<string?[]>();

    /// <summary>Total row count (after aggregation / filtering).</summary>
    public int TotalRows { get; init; }

    /// <summary>Whether the result was capped at the row limit.</summary>
    public bool IsTruncated { get; init; }

    /// <summary>UTC timestamp of when the report was executed.</summary>
    public DateTime GeneratedAt { get; init; } = DateTime.UtcNow;
}
