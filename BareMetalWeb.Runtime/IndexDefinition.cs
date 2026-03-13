using BareMetalWeb.Data;

namespace BareMetalWeb.Runtime;

/// <summary>
/// Persisted index hint for a runtime-managed entity.
/// Describes which fields should be indexed for efficient query filtering and sorting.
/// </summary>
[DataEntity("Index Definitions", ShowOnNav = false, NavGroup = "Admin", NavOrder = 1002)]
public class IndexDefinition : BaseDataObject
{
    /// <summary>Foreign key to <see cref="EntityDefinition.Id"/>.</summary>
    [DataField(Label = "Entity ID", Order = 1, Required = true)]
    [DataLookup(typeof(EntityDefinition), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc)]
    public string EntityId { get; set; } = string.Empty;

    /// <summary>
    /// Pipe-separated field names to include in this index,
    /// e.g. "DueDate" or "Priority|IsResolved".
    /// </summary>
    [DataField(Label = "Field Names (pipe-separated)", Order = 2, Required = true)]
    public string FieldNames { get; set; } = string.Empty;

    /// <summary>
    /// Index type: "inverted" (full-text), "btree" (sorted/range),
    /// "treap" (balanced BST), "bloom" (membership test),
    /// "secondary" (single-field), or "composite" (multi-field).
    /// </summary>
    [DataField(Label = "Type", Order = 3)]
    public string Type { get; set; } = "inverted";

    public IReadOnlyList<string> GetFieldList()
        => FieldNames
            .Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
