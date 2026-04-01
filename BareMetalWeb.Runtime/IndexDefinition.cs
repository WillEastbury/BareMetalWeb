using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted index hint for a runtime-managed entity.
/// Describes which fields should be indexed for efficient query filtering and sorting.
/// </summary>
[DataEntity("Index Definitions", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1002)]
public class IndexDefinition : BaseDataObject
{
    public override string EntityTypeName => "IndexDefinition";
    private const int Ord_EntityId = BaseFieldCount + 0;
    private const int Ord_FieldNames = BaseFieldCount + 1;
    private const int Ord_Type = BaseFieldCount + 2;
    internal const int TotalFieldCount = BaseFieldCount + 3;
    private static readonly FieldSlot[] _fieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("EntityId", Ord_EntityId),
        new FieldSlot("FieldNames", Ord_FieldNames),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("Type", Ord_Type),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };
    protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

    public IndexDefinition() : base(TotalFieldCount) { }
    public IndexDefinition(string createdBy) : base(TotalFieldCount, createdBy) { }

    /// <summary>Foreign key to <see cref="EntityDefinition.Id"/>.</summary>
    [DataField(Label = "Entity ID", Order = 1, Required = true)]
    [DataLookup(typeof(EntityDefinition), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc)]
    public string EntityId
    {
        get => (string?)_values[Ord_EntityId] ?? string.Empty;
        set => _values[Ord_EntityId] = value;
    }

    /// <summary>
    /// Pipe-separated field names to include in this index,
    /// e.g. "DueDate" or "Priority|IsResolved".
    /// </summary>
    [DataField(Label = "Field Names (pipe-separated)", Order = 2, Required = true)]
    public string FieldNames
    {
        get => (string?)_values[Ord_FieldNames] ?? string.Empty;
        set => _values[Ord_FieldNames] = value;
    }

    /// <summary>
    /// Index type: "inverted" (full-text), "btree" (sorted/range),
    /// "treap" (balanced BST), "bloom" (membership test),
    /// "secondary" (single-field), or "composite" (multi-field).
    /// </summary>
    [DataField(Label = "Type", Order = 3)]
    public string Type
    {
        get => (string?)_values[Ord_Type] ?? "inverted";
        set => _values[Ord_Type] = value;
    }

    public IReadOnlyList<string> GetFieldList()
        => FieldNames
            .Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
