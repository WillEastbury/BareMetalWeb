using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Data;

/// <summary>
/// A stored, reusable report definition — specifies root entity, joins, columns,
/// filters, parameters and sort for the reporting layer.
/// </summary>
[DataEntity("Report Definitions", Slug = "report-definitions", ShowOnNav = false, Permissions = "admin", NavGroup = "Admin", NavOrder = 90)]
public sealed class ReportDefinition : BaseDataObject
{
    public override string EntityTypeName => "ReportDefinition";
    private const int Ord_Name = BaseFieldCount + 0;
    private const int Ord_Description = BaseFieldCount + 1;
    private const int Ord_RootEntity = BaseFieldCount + 2;
    private const int Ord_JoinsJson = BaseFieldCount + 3;
    private const int Ord_ColumnsJson = BaseFieldCount + 4;
    private const int Ord_FiltersJson = BaseFieldCount + 5;
    private const int Ord_ParametersJson = BaseFieldCount + 6;
    private const int Ord_SortField = BaseFieldCount + 7;
    private const int Ord_SortDescending = BaseFieldCount + 8;
    internal new const int TotalFieldCount = BaseFieldCount + 9;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("ColumnsJson", Ord_ColumnsJson),
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("Description", Ord_Description),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("FiltersJson", Ord_FiltersJson),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("JoinsJson", Ord_JoinsJson),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Name", Ord_Name),
        new FieldSlot("ParametersJson", Ord_ParametersJson),
        new FieldSlot("RootEntity", Ord_RootEntity),
        new FieldSlot("SortDescending", Ord_SortDescending),
        new FieldSlot("SortField", Ord_SortField),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public ReportDefinition() : base(TotalFieldCount) { }
    public ReportDefinition(string createdBy) : base(TotalFieldCount, createdBy) { }

    [DataField(Label = "Name", Order = 1, Required = true, List = true)]
    public string Name
    {
        get => (string?)_values[Ord_Name] ?? string.Empty;
        set => _values[Ord_Name] = value;
    }

    [DataField(Label = "Description", Order = 2, FieldType = FormFieldType.TextArea)]
    public string Description
    {
        get => (string?)_values[Ord_Description] ?? string.Empty;
        set => _values[Ord_Description] = value;
    }

    /// <summary>Slug of the root entity to query from.</summary>
    [DataField(Label = "Root Entity (slug)", Order = 3, Required = true)]
    public string RootEntity
    {
        get => (string?)_values[Ord_RootEntity] ?? string.Empty;
        set => _values[Ord_RootEntity] = value;
    }

    /// <summary>JSON-serialised list of <see cref="ReportJoin"/>.</summary>
    [DataField(Label = "Joins (JSON)", Order = 4, FieldType = FormFieldType.TextArea)]
    public string JoinsJson
    {
        get => (string?)_values[Ord_JoinsJson] ?? "[]";
        set => _values[Ord_JoinsJson] = value;
    }

    /// <summary>JSON-serialised list of <see cref="ReportColumn"/>.</summary>
    [DataField(Label = "Columns (JSON)", Order = 5, FieldType = FormFieldType.TextArea)]
    public string ColumnsJson
    {
        get => (string?)_values[Ord_ColumnsJson] ?? "[]";
        set => _values[Ord_ColumnsJson] = value;
    }

    /// <summary>JSON-serialised list of <see cref="ReportFilter"/>.</summary>
    [DataField(Label = "Filters (JSON)", Order = 6, FieldType = FormFieldType.TextArea)]
    public string FiltersJson
    {
        get => (string?)_values[Ord_FiltersJson] ?? "[]";
        set => _values[Ord_FiltersJson] = value;
    }

    /// <summary>JSON-serialised list of <see cref="ReportParameter"/>.</summary>
    [DataField(Label = "Parameters (JSON)", Order = 7, FieldType = FormFieldType.TextArea)]
    public string ParametersJson
    {
        get => (string?)_values[Ord_ParametersJson] ?? "[]";
        set => _values[Ord_ParametersJson] = value;
    }

    [DataField(Label = "Sort Field", Order = 8)]
    public string SortField
    {
        get => (string?)_values[Ord_SortField] ?? string.Empty;
        set => _values[Ord_SortField] = value;
    }

    [DataField(Label = "Sort Descending", Order = 9, FieldType = FormFieldType.YesNo)]
    public bool SortDescending
    {
        get => _values[Ord_SortDescending] is true;
        set => _values[Ord_SortDescending] = value;
    }

    // ── Convenience typed accessors (not persisted directly) ─────────────────

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ReportJoin> Joins
    {
        get => BmwManualJson.DeserializeReportJoins(JoinsJson);
        set => JoinsJson = BmwManualJson.SerializeReportJoins(value ?? new List<ReportJoin>());
    }

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ReportColumn> Columns
    {
        get => BmwManualJson.DeserializeReportColumns(ColumnsJson);
        set => ColumnsJson = BmwManualJson.SerializeReportColumns(value ?? new List<ReportColumn>());
    }

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ReportFilter> Filters
    {
        get => BmwManualJson.DeserializeReportFilters(FiltersJson);
        set => FiltersJson = BmwManualJson.SerializeReportFilters(value ?? new List<ReportFilter>());
    }

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ReportParameter> Parameters
    {
        get => BmwManualJson.DeserializeReportParameters(ParametersJson);
        set => ParametersJson = BmwManualJson.SerializeReportParameters(value ?? new List<ReportParameter>());
    }
}
