using System.Text.Json;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Data;

/// <summary>
/// A stored, reusable report definition — specifies root entity, joins, columns,
/// filters, parameters and sort for the reporting layer.
/// </summary>
[DataEntity("Report Definitions", Slug = "report-definitions", ShowOnNav = true, Permissions = "admin", NavGroup = "Admin", NavOrder = 90)]
public sealed class ReportDefinition : BaseDataObject
{
    public ReportDefinition() : base() { }
    public ReportDefinition(string createdBy) : base(createdBy) { }

    [DataField(Label = "Name", Order = 1, Required = true, List = true)]
    public string Name { get; set; } = string.Empty;

    [DataField(Label = "Description", Order = 2, FieldType = FormFieldType.TextArea)]
    public string Description { get; set; } = string.Empty;

    /// <summary>Slug of the root entity to query from.</summary>
    [DataField(Label = "Root Entity (slug)", Order = 3, Required = true)]
    public string RootEntity { get; set; } = string.Empty;

    /// <summary>JSON-serialised list of <see cref="ReportJoin"/>.</summary>
    [DataField(Label = "Joins (JSON)", Order = 4, FieldType = FormFieldType.TextArea)]
    public string JoinsJson { get; set; } = "[]";

    /// <summary>JSON-serialised list of <see cref="ReportColumn"/>.</summary>
    [DataField(Label = "Columns (JSON)", Order = 5, FieldType = FormFieldType.TextArea)]
    public string ColumnsJson { get; set; } = "[]";

    /// <summary>JSON-serialised list of <see cref="ReportFilter"/>.</summary>
    [DataField(Label = "Filters (JSON)", Order = 6, FieldType = FormFieldType.TextArea)]
    public string FiltersJson { get; set; } = "[]";

    /// <summary>JSON-serialised list of <see cref="ReportParameter"/>.</summary>
    [DataField(Label = "Parameters (JSON)", Order = 7, FieldType = FormFieldType.TextArea)]
    public string ParametersJson { get; set; } = "[]";

    [DataField(Label = "Sort Field", Order = 8)]
    public string SortField { get; set; } = string.Empty;

    [DataField(Label = "Sort Descending", Order = 9, FieldType = FormFieldType.YesNo)]
    public bool SortDescending { get; set; }

    // ── Convenience typed accessors (not persisted directly) ─────────────────

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ReportJoin> Joins
    {
        get => DeserializeList(JoinsJson, BmwDataJsonContext.Default.ListReportJoin);
        set => JoinsJson = JsonSerializer.Serialize(value ?? new List<ReportJoin>(), BmwDataJsonContext.Default.ListReportJoin);
    }

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ReportColumn> Columns
    {
        get => DeserializeList(ColumnsJson, BmwDataJsonContext.Default.ListReportColumn);
        set => ColumnsJson = JsonSerializer.Serialize(value ?? new List<ReportColumn>(), BmwDataJsonContext.Default.ListReportColumn);
    }

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ReportFilter> Filters
    {
        get => DeserializeList(FiltersJson, BmwDataJsonContext.Default.ListReportFilter);
        set => FiltersJson = JsonSerializer.Serialize(value ?? new List<ReportFilter>(), BmwDataJsonContext.Default.ListReportFilter);
    }

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ReportParameter> Parameters
    {
        get => DeserializeList(ParametersJson, BmwDataJsonContext.Default.ListReportParameter);
        set => ParametersJson = JsonSerializer.Serialize(value ?? new List<ReportParameter>(), BmwDataJsonContext.Default.ListReportParameter);
    }

    private static List<T> DeserializeList<T>(string json, System.Text.Json.Serialization.Metadata.JsonTypeInfo<List<T>> typeInfo)
    {
        try
        {
            return string.IsNullOrWhiteSpace(json)
                ? new List<T>()
                : JsonSerializer.Deserialize(json, typeInfo) ?? new List<T>();
        }
        catch
        {
            return new List<T>();
        }
    }
}
