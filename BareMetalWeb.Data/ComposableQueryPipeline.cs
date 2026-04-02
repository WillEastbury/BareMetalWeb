using BareMetalWeb.Core;

namespace BareMetalWeb.Data;

/// <summary>
/// A composable query pipeline that chains multiple index-based query steps.
/// Each step narrows the result set using a different index type.
/// 
/// Example pipeline:
///   graph traversal (org subtree under VP Engineering)
///   → filter (status = "Active")
///   → text search (keyword match)
///   → sort + paginate
/// </summary>
public sealed class ComposableQueryPipeline
{
    private readonly List<QueryStep> _steps = new();

    /// <summary>Add a step to the pipeline.</summary>
    public ComposableQueryPipeline AddStep(QueryStep step)
    {
        _steps.Add(step);
        return this;
    }

    /// <summary>Add a graph traversal step.</summary>
    public ComposableQueryPipeline GraphTraversal(uint startNodeId, int maxHops, string? edgeType = null)
    {
        _steps.Add(new QueryStep(QueryStepKind.GraphTraversal)
        {
            GraphStartId = startNodeId,
            GraphMaxHops = maxHops,
            GraphEdgeType = edgeType
        });
        return this;
    }

    /// <summary>Add a text search step using inverted/btree/treap index.</summary>
    public ComposableQueryPipeline TextSearch(string query, IndexKind kind = IndexKind.Inverted)
    {
        _steps.Add(new QueryStep(QueryStepKind.TextSearch)
        {
            SearchQuery = query,
            SearchIndexKind = kind
        });
        return this;
    }

    /// <summary>Add a field equality filter step.</summary>
    public ComposableQueryPipeline Filter(string field, string value)
    {
        _steps.Add(new QueryStep(QueryStepKind.FieldFilter)
        {
            FilterField = field,
            FilterValue = value
        });
        return this;
    }

    /// <summary>Add a bloom filter membership check.</summary>
    public ComposableQueryPipeline BloomCheck(string token)
    {
        _steps.Add(new QueryStep(QueryStepKind.BloomCheck)
        {
            SearchQuery = token
        });
        return this;
    }

    /// <summary>
    /// Execute the pipeline against the given entity type.
    /// Each step narrows the candidate set from the previous step.
    /// </summary>
    public async ValueTask<IReadOnlyCollection<uint>> ExecuteAsync(
        Type entityType,
        DataEntityMetadata meta,
        SearchIndexManager searchIndex,
        CancellationToken ct)
    {
        HashSet<uint>? candidates = null;

        foreach (var step in _steps)
        {
            HashSet<uint> stepResult;

            switch (step.Kind)
            {
                case QueryStepKind.GraphTraversal:
                    stepResult = new HashSet<uint>(searchIndex.TraverseGraph(
                        entityType, step.GraphStartId, step.GraphMaxHops,
                        () => LoadAll(meta, ct), step.GraphEdgeType));
                    break;

                case QueryStepKind.TextSearch:
                    stepResult = new HashSet<uint>(searchIndex.Search(
                        entityType, step.SearchQuery ?? "",
                        () => LoadAll(meta, ct), step.SearchIndexKind));
                    break;

                case QueryStepKind.BloomCheck:
                    stepResult = new HashSet<uint>(searchIndex.Search(
                        entityType, step.SearchQuery ?? "",
                        () => LoadAll(meta, ct), IndexKind.Bloom));
                    break;

                case QueryStepKind.FieldFilter:
                    // Load candidate objects and filter by field value
                    stepResult = new HashSet<uint>();
                    var field = meta.FindField(step.FilterField ?? "");
                    if (field != null)
                    {
                        var sourceIds = candidates ?? await LoadAllIds(meta, ct);
                        foreach (var id in sourceIds)
                        {
                            var obj = await meta.Handlers.LoadAsync(id, ct);
                            if (obj == null) continue;
                            var val = field.GetValueFn(obj)?.ToString() ?? "";
                            if (string.Equals(val, step.FilterValue, StringComparison.OrdinalIgnoreCase))
                                stepResult.Add(id);
                        }
                    }
                    break;

                default:
                    continue;
            }

            // Intersect with previous step's results
            if (candidates == null)
                candidates = stepResult;
            else
                candidates.IntersectWith(stepResult);

            // Short-circuit if empty
            if (candidates.Count == 0)
                return Array.Empty<uint>();
        }

        return candidates ?? (IReadOnlyCollection<uint>)Array.Empty<uint>();
    }

    private static IEnumerable<DataRecord> LoadAll(DataEntityMetadata meta, CancellationToken ct)
    {
        var task = meta.Handlers.QueryAsync(null, ct);
        // TODO: convert to async
        var result = task.IsCompleted ? task.Result : task.AsTask().GetAwaiter().GetResult();
        return result.Cast<DataRecord>();
    }

    private static async ValueTask<HashSet<uint>> LoadAllIds(DataEntityMetadata meta, CancellationToken ct)
    {
        var all = await meta.Handlers.QueryAsync(null, ct);
        var ids = new HashSet<uint>();
        foreach (var obj in all)
        {
            if (obj is DataRecord bdo) ids.Add(bdo.Key);
        }
        return ids;
    }
}

/// <summary>A single step in a composable query pipeline.</summary>
public sealed class QueryStep
{
    public QueryStepKind Kind { get; }
    public uint GraphStartId { get; init; }
    public int GraphMaxHops { get; init; } = 1;
    public string? GraphEdgeType { get; init; }
    public string? SearchQuery { get; init; }
    public IndexKind SearchIndexKind { get; init; } = IndexKind.Inverted;
    public string? FilterField { get; init; }
    public string? FilterValue { get; init; }

    public QueryStep(QueryStepKind kind) => Kind = kind;
}

/// <summary>Types of steps in a composable query pipeline.</summary>
public enum QueryStepKind
{
    /// <summary>Traverse the graph index from a start node.</summary>
    GraphTraversal,
    /// <summary>Full-text/inverted/btree/treap search.</summary>
    TextSearch,
    /// <summary>Filter by field equality.</summary>
    FieldFilter,
    /// <summary>Bloom filter membership check.</summary>
    BloomCheck
}
