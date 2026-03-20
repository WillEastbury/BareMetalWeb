using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Data;

/// <summary>
/// A persisted, metadata-driven View Definition.
/// A view is a named, reusable query that supports projections, joins, filters, sorts and pagination.
/// Views compile into deterministic <see cref="ViewExecutionPlan"/> objects that are cached and
/// executed directly over BMW's in-memory arrays using vectorised selection vectors.
/// </summary>
[DataEntity("View Definitions", Slug = "view-definitions", ShowOnNav = false,
    Permissions = "admin", NavGroup = "Admin", NavOrder = 95)]
public sealed class ViewDefinition : BaseDataObject
{
    private const int Ord_ViewName = BaseFieldCount + 0;
    private const int Ord_RootEntity = BaseFieldCount + 1;
    private const int Ord_ProjectionsJson = BaseFieldCount + 2;
    private const int Ord_JoinsJson = BaseFieldCount + 3;
    private const int Ord_FiltersJson = BaseFieldCount + 4;
    private const int Ord_SortsJson = BaseFieldCount + 5;
    private const int Ord_Limit = BaseFieldCount + 6;
    private const int Ord_Offset = BaseFieldCount + 7;
    private const int Ord_Materialised = BaseFieldCount + 8;
    internal new const int TotalFieldCount = BaseFieldCount + 9;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("FiltersJson", Ord_FiltersJson),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("JoinsJson", Ord_JoinsJson),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Limit", Ord_Limit),
        new FieldSlot("Materialised", Ord_Materialised),
        new FieldSlot("Offset", Ord_Offset),
        new FieldSlot("ProjectionsJson", Ord_ProjectionsJson),
        new FieldSlot("RootEntity", Ord_RootEntity),
        new FieldSlot("SortsJson", Ord_SortsJson),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
        new FieldSlot("ViewName", Ord_ViewName),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public ViewDefinition() : base(TotalFieldCount) { }
    public ViewDefinition(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>Unique human-readable name for this view.</summary>
    [DataField(Label = "View Name", Order = 1, Required = true, List = true)]
    public string ViewName
    {
        get => (string?)_values[Ord_ViewName] ?? string.Empty;
        set => _values[Ord_ViewName] = value;
    }

    /// <summary>Slug of the root entity that drives the view scan.</summary>
    [DataField(Label = "Root Entity (slug)", Order = 2, Required = true, List = true)]
    public string RootEntity
    {
        get => (string?)_values[Ord_RootEntity] ?? string.Empty;
        set => _values[Ord_RootEntity] = value;
    }

    /// <summary>JSON-serialised list of <see cref="ViewProjection"/>.</summary>
    [DataField(Label = "Projections (JSON)", Order = 3, FieldType = FormFieldType.TextArea)]
    public string ProjectionsJson
    {
        get => (string?)_values[Ord_ProjectionsJson] ?? "[]";
        set => _values[Ord_ProjectionsJson] = value;
    }

    /// <summary>JSON-serialised list of <see cref="ViewJoinDefinition"/>.</summary>
    [DataField(Label = "Joins (JSON)", Order = 4, FieldType = FormFieldType.TextArea)]
    public string JoinsJson
    {
        get => (string?)_values[Ord_JoinsJson] ?? "[]";
        set => _values[Ord_JoinsJson] = value;
    }

    /// <summary>JSON-serialised list of <see cref="ViewFilterDefinition"/>.</summary>
    [DataField(Label = "Filters (JSON)", Order = 5, FieldType = FormFieldType.TextArea)]
    public string FiltersJson
    {
        get => (string?)_values[Ord_FiltersJson] ?? "[]";
        set => _values[Ord_FiltersJson] = value;
    }

    /// <summary>JSON-serialised list of <see cref="ViewSortDefinition"/>.</summary>
    [DataField(Label = "Sorts (JSON)", Order = 6, FieldType = FormFieldType.TextArea)]
    public string SortsJson
    {
        get => (string?)_values[Ord_SortsJson] ?? "[]";
        set => _values[Ord_SortsJson] = value;
    }

    /// <summary>Maximum rows returned. Defaults to 10 000.</summary>
    [DataField(Label = "Limit", Order = 7)]
    public int Limit
    {
        get => (int)(_values[Ord_Limit] ?? 10_000);
        set => _values[Ord_Limit] = value;
    }

    /// <summary>Number of rows to skip (for pagination).</summary>
    [DataField(Label = "Offset", Order = 8)]
    public int Offset
    {
        get => (int)(_values[Ord_Offset] ?? 0);
        set => _values[Ord_Offset] = value;
    }

    /// <summary>When true the view result is cached as a materialised view and updated from the WAL.</summary>
    [DataField(Label = "Materialised", Order = 9, FieldType = FormFieldType.YesNo)]
    public bool Materialised
    {
        get => _values[Ord_Materialised] is true;
        set => _values[Ord_Materialised] = value;
    }

    // ── Typed accessors (not persisted directly) ─────────────────────────────

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ViewProjection> Projections
    {
        get => BmwManualJson.DeserializeViewProjections(ProjectionsJson);
        set => ProjectionsJson = BmwManualJson.SerializeViewProjections(value ?? new List<ViewProjection>());
    }

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ViewJoinDefinition> Joins
    {
        get => BmwManualJson.DeserializeViewJoins(JoinsJson);
        set => JoinsJson = BmwManualJson.SerializeViewJoins(value ?? new List<ViewJoinDefinition>());
    }

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ViewFilterDefinition> Filters
    {
        get => BmwManualJson.DeserializeViewFilters(FiltersJson);
        set => FiltersJson = BmwManualJson.SerializeViewFilters(value ?? new List<ViewFilterDefinition>());
    }

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ViewSortDefinition> Sorts
    {
        get => BmwManualJson.DeserializeViewSorts(SortsJson);
        set => SortsJson = BmwManualJson.SerializeViewSorts(value ?? new List<ViewSortDefinition>());
    }
}

// ── Supporting model types ────────────────────────────────────────────────────

/// <summary>
/// Defines a projected output column.
/// <code>
/// Entity = "Order", Field = "Total", Alias = "total"
/// Entity = "Customer", Field = "Name", Alias = "customerName"
/// </code>
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
/// Defines a join relationship between two entities.
/// <code>
/// SourceEntity = "orders", SourceField = "customerId"
/// TargetEntity = "customers", TargetField = "id"
/// Type = Inner
/// </code>
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
/// Defines a row filter predicate.
/// <code>
/// Entity = "orders", Field = "status", Operator = "=", Value = "Open"
/// Entity = "orders", Field = "total",  Operator = ">", Value = "100"
/// </code>
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
/// Defines a sort key.
/// </summary>
public sealed class ViewSortDefinition
{
    /// <summary>Entity slug. Empty means root entity.</summary>
    public string Entity { get; set; } = string.Empty;
    public string Field { get; set; } = string.Empty;
    public bool Descending { get; set; }
}
