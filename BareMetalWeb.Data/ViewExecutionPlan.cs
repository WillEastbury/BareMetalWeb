using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// Compiled, deterministic execution plan produced by the <see cref="ViewEngine"/>
/// from a <see cref="ViewDefinition"/>.
///
/// <para>
/// Compilation resolves entity metadata, field ordinals, compiled field-accessor delegates,
/// join key extractors and filter predicates — so the hot execution loop never touches
/// reflection or string lookups.
/// </para>
///
/// <para>
/// Plans are cached keyed on <see cref="CacheKey"/>.  The cache is invalidated when
/// the underlying <see cref="ViewDefinition"/> record is modified.
/// </para>
/// </summary>
public sealed class ViewExecutionPlan
{
    /// <summary>Cache key derived from the <see cref="ViewDefinition"/> key and view name.</summary>
    public string CacheKey { get; init; } = string.Empty;

    /// <summary>Slug of the root entity (drives the outer scan loop).</summary>
    public string RootEntitySlug { get; init; } = string.Empty;

    /// <summary>Resolved metadata for the root entity — provides field descriptors and query handlers.</summary>
    public DataEntityMetadata? RootEntityMeta { get; init; }

    /// <summary>
    /// Pre-built <see cref="QueryDefinition"/> per entity slug for predicate pushdown.
    /// Pushed to the data provider's <c>QueryAsync</c> so the store can use index-assisted
    /// lookups rather than full table scans wherever possible.
    /// Key = entity slug (case-insensitive).
    /// </summary>
    public IReadOnlyDictionary<string, QueryDefinition> PushedFilters { get; init; }
        = new Dictionary<string, QueryDefinition>(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Output column descriptors, in projection order.
    /// Each entry contains the entity slug, field name, display alias and a compiled getter delegate
    /// that extracts the field value from a <see cref="DataRecord"/> without reflection.
    /// </summary>
    public ViewProjectionEntry[] ProjectionMap { get; init; } = Array.Empty<ViewProjectionEntry>();

    /// <summary>
    /// Compiled join lookup entries.  For each join the engine builds a hash map at execution time
    /// keyed on the target field, then performs O(1) lookups for every selected root row.
    /// </summary>
    public ViewJoinEntry[] JoinLookupFunctions { get; init; } = Array.Empty<ViewJoinEntry>();

    /// <summary>
    /// Compiled filter predicates.  Each entry holds a pre-compiled
    /// <see cref="Func{T,TResult}"/> that evaluates the predicate on a single row without
    /// string parsing or switch/case dispatch.
    /// </summary>
    public ViewFilterEntry[] FilterFunctions { get; init; } = Array.Empty<ViewFilterEntry>();

    /// <summary>Sort keys applied after projection (smallest index = primary sort).</summary>
    public ViewSortKey[] SortKeys { get; init; } = Array.Empty<ViewSortKey>();

    /// <summary>Maximum number of output rows.</summary>
    public int Limit { get; init; } = 10_000;

    /// <summary>Number of rows to skip (offset) after sorting.</summary>
    public int Offset { get; init; }

    /// <summary>
    /// Column header labels for the output grid, aligned with <see cref="ProjectionMap"/>.
    /// </summary>
    public string[] ColumnHeaders { get; init; } = Array.Empty<string>();

    /// <summary>True when the definition requests a materialised / cached result.</summary>
    public bool Materialised { get; init; }
}

// ── Supporting types produced during compilation ──────────────────────────────

/// <summary>Compiled projection entry for a single output column.</summary>
public sealed class ViewProjectionEntry
{
    /// <summary>Slug of the entity that owns this field.</summary>
    public string EntitySlug { get; init; } = string.Empty;
    /// <summary>Name of the field on the entity.</summary>
    public string FieldName { get; init; } = string.Empty;
    /// <summary>Display alias / column header.</summary>
    public string Alias { get; init; } = string.Empty;
    /// <summary>
    /// Compiled getter that extracts this field's value from a <see cref="DataRecord"/>
    /// without reflection.  Null when the field could not be resolved at compile time.
    /// </summary>
    public Func<object, object?>? Getter { get; init; }
}

/// <summary>Compiled join entry — holds all metadata needed to perform one join at execution time.</summary>
public sealed class ViewJoinEntry
{
    public string SourceEntitySlug { get; init; } = string.Empty;
    public string SourceFieldName { get; init; } = string.Empty;
    public string TargetEntitySlug { get; init; } = string.Empty;
    public string TargetFieldName { get; init; } = string.Empty;
    public JoinType JoinType { get; init; }
    /// <summary>Resolved metadata for the target (build-side) entity.</summary>
    public DataEntityMetadata? TargetMeta { get; init; }
    /// <summary>Compiled getter for the join key on the source row.</summary>
    public Func<object, string>? SourceKeyExtractor { get; init; }
    /// <summary>Compiled getter for the join key on the target row.</summary>
    public Func<object, string>? TargetKeyExtractor { get; init; }
}

/// <summary>Compiled filter entry — holds the predicate for one filter clause.</summary>
public sealed class ViewFilterEntry
{
    /// <summary>Entity slug this filter applies to.  Empty = root entity.</summary>
    public string EntitySlug { get; init; } = string.Empty;
    /// <summary>
    /// Compiled predicate.  Returns true when the row <em>passes</em> the filter.
    /// Null when the filter could not be compiled (falls back to unfiltered).
    /// </summary>
    public Func<object, bool>? Predicate { get; init; }
}

/// <summary>Sort key for post-projection ordering.</summary>
public sealed class ViewSortKey
{
    /// <summary>Zero-based column index in the projected output row.</summary>
    public int ColumnIndex { get; init; }
    public bool Descending { get; init; }
}
