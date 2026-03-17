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
    public ViewDefinition() : base() { }
    public ViewDefinition(string createdBy) : base(createdBy) { }

    /// <summary>Unique human-readable name for this view.</summary>
    [DataField(Label = "View Name", Order = 1, Required = true, List = true)]
    public string ViewName { get; set; } = string.Empty;

    /// <summary>Slug of the root entity that drives the view scan.</summary>
    [DataField(Label = "Root Entity (slug)", Order = 2, Required = true, List = true)]
    public string RootEntity { get; set; } = string.Empty;

    /// <summary>JSON-serialised list of <see cref="ViewProjection"/>.</summary>
    [DataField(Label = "Projections (JSON)", Order = 3, FieldType = FormFieldType.TextArea)]
    public string ProjectionsJson { get; set; } = "[]";

    /// <summary>JSON-serialised list of <see cref="ViewJoinDefinition"/>.</summary>
    [DataField(Label = "Joins (JSON)", Order = 4, FieldType = FormFieldType.TextArea)]
    public string JoinsJson { get; set; } = "[]";

    /// <summary>JSON-serialised list of <see cref="ViewFilterDefinition"/>.</summary>
    [DataField(Label = "Filters (JSON)", Order = 5, FieldType = FormFieldType.TextArea)]
    public string FiltersJson { get; set; } = "[]";

    /// <summary>JSON-serialised list of <see cref="ViewSortDefinition"/>.</summary>
    [DataField(Label = "Sorts (JSON)", Order = 6, FieldType = FormFieldType.TextArea)]
    public string SortsJson { get; set; } = "[]";

    /// <summary>Maximum rows returned. Defaults to 10 000.</summary>
    [DataField(Label = "Limit", Order = 7)]
    public int Limit { get; set; } = 10_000;

    /// <summary>Number of rows to skip (for pagination).</summary>
    [DataField(Label = "Offset", Order = 8)]
    public int Offset { get; set; }

    /// <summary>When true the view result is cached as a materialised view and updated from the WAL.</summary>
    [DataField(Label = "Materialised", Order = 9, FieldType = FormFieldType.YesNo)]
    public bool Materialised { get; set; }

    // ── Typed accessors (not persisted directly) ─────────────────────────────

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ViewProjection> Projections
    {
        get => DeserializeList(ProjectionsJson, ManualJsonHelper.ReadViewProjection);
        set => ProjectionsJson = ManualJsonHelper.SerializeList(value ?? new List<ViewProjection>(), ManualJsonHelper.WriteViewProjection);
    }

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ViewJoinDefinition> Joins
    {
        get => DeserializeList(JoinsJson, ManualJsonHelper.ReadViewJoinDefinition);
        set => JoinsJson = ManualJsonHelper.SerializeList(value ?? new List<ViewJoinDefinition>(), ManualJsonHelper.WriteViewJoinDefinition);
    }

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ViewFilterDefinition> Filters
    {
        get => DeserializeList(FiltersJson, ManualJsonHelper.ReadViewFilterDefinition);
        set => FiltersJson = ManualJsonHelper.SerializeList(value ?? new List<ViewFilterDefinition>(), ManualJsonHelper.WriteViewFilterDefinition);
    }

    [System.Text.Json.Serialization.JsonIgnore]
    public List<ViewSortDefinition> Sorts
    {
        get => DeserializeList(SortsJson, ManualJsonHelper.ReadViewSortDefinition);
        set => SortsJson = ManualJsonHelper.SerializeList(value ?? new List<ViewSortDefinition>(), ManualJsonHelper.WriteViewSortDefinition);
    }

    private static List<T> DeserializeList<T>(string json, Func<System.Text.Json.JsonElement, T> readItem)
    {
        try
        {
            return string.IsNullOrWhiteSpace(json)
                ? new List<T>()
                : ManualJsonHelper.DeserializeList(json, readItem);
        }
        catch
        {
            return new List<T>();
        }
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
