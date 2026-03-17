using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted definition of a named aggregation view — specifies group-by levels
/// and measures (sum, count, avg, min, max) for drill-through browsing.
/// </summary>
[DataEntity("Aggregation Definitions", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1005)]
public class AggregationDefinition : BaseDataObject
{
    private const int Ord_EntityId = BaseFieldCount + 0;
    private const int Ord_Name = BaseFieldCount + 1;
    private const int Ord_GroupByFields = BaseFieldCount + 2;
    private const int Ord_Measures = BaseFieldCount + 3;
    internal const int TotalFieldCount = BaseFieldCount + 4;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("EntityId", Ord_EntityId),
        new FieldSlot("GroupByFields", Ord_GroupByFields),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Measures", Ord_Measures),
        new FieldSlot("Name", Ord_Name),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public AggregationDefinition() : base(TotalFieldCount) { }
    public AggregationDefinition(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>Foreign key to <see cref="EntityDefinition.EntityId"/>.</summary>
    [DataField(Label = "Entity ID", Order = 1, Required = true)]
    [DataLookup(typeof(EntityDefinition), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc)]
    public string EntityId
    {
        get => (string?)_values[Ord_EntityId] ?? string.Empty;
        set => _values[Ord_EntityId] = value;
    }

    [DataField(Label = "Name", Order = 2, Required = true)]
    public string Name
    {
        get => (string?)_values[Ord_Name] ?? string.Empty;
        set => _values[Ord_Name] = value;
    }

    /// <summary>
    /// Pipe-separated field names that define the group-by levels.
    /// E.g. "Category|SubCategory|Product" → three drill-down levels.
    /// </summary>
    [DataField(Label = "Group By (pipe-separated)", Order = 3, Required = true)]
    public string GroupByFields
    {
        get => (string?)_values[Ord_GroupByFields] ?? string.Empty;
        set => _values[Ord_GroupByFields] = value;
    }

    /// <summary>
    /// Pipe-separated measure expressions: "fn:field" pairs.
    /// E.g. "sum:Amount|count:Id|avg:Price".
    /// </summary>
    [DataField(Label = "Measures (fn:field pipe-separated)", Order = 4, Required = true)]
    public string Measures
    {
        get => (string?)_values[Ord_Measures] ?? string.Empty;
        set => _values[Ord_Measures] = value;
    }

    public IReadOnlyList<string> GetGroupByList()
        => GroupByFields
            .Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public IReadOnlyList<(string Function, string Field)> GetMeasureList()
    {
        var parts = Measures.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var result = new (string Function, string Field)[parts.Length];
        for (int i = 0; i < parts.Length; i++)
        {
            var p = parts[i].Split(':', 2);
            result[i] = p.Length == 2
                ? (p[0].ToLowerInvariant(), p[1])
                : ("count", parts[i]);
        }
        return result;
    }

    public override string ToString() => Name;
}
