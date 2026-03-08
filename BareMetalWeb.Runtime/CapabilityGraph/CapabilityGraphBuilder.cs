using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Runtime.CapabilityGraph;

/// <summary>
/// Builds a <see cref="MetadataCapabilityGraph"/> from the frozen
/// <see cref="RuntimeEntityRegistry"/> and optional scheduled-action data.
///
/// For each entity the builder emits Query/Create/Update/Delete nodes,
/// one RunAction node per action, and edges from relationships (lookup,
/// child-list, related-document). Scheduled actions become RunWorkflow nodes.
/// </summary>
public sealed class CapabilityGraphBuilder
{
    private readonly RuntimeEntityRegistry _registry;
    private readonly List<CapabilityNode> _nodes = new();
    private readonly List<CapabilityEdge> _edges = new();
    private readonly List<EntityDescriptor> _entities = new();
    private readonly Dictionary<string, int> _slugToEntityIndex = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, int> _slugToQueryNode = new(StringComparer.OrdinalIgnoreCase);
    private int _nextId;

    public CapabilityGraphBuilder(RuntimeEntityRegistry registry)
    {
        _registry = registry;
    }

    /// <summary>
    /// Builds the graph synchronously from the frozen registry.
    /// Optionally loads <see cref="ScheduledActionDefinition"/> records
    /// from the data store for workflow nodes.
    /// </summary>
    public async Task<MetadataCapabilityGraph> BuildAsync(IDataObjectStore? store = null)
    {
        // Phase 1: Entity CRUD nodes
        foreach (var entity in _registry.All)
        {
            int entityIdx = _entities.Count;
            _entities.Add(new EntityDescriptor(entity.EntityId, entity.Name, entity.Slug));
            _slugToEntityIndex[entity.Slug] = entityIdx;

            var queryId = AddNode(CapabilityType.QueryEntity, entityIdx, $"Query{PascalCase(entity.Name)}");
            var createId = AddNode(CapabilityType.CreateEntity, entityIdx, $"Create{PascalCase(entity.Name)}");
            var updateId = AddNode(CapabilityType.UpdateEntity, entityIdx, $"Update{PascalCase(entity.Name)}");
            var deleteId = AddNode(CapabilityType.DeleteEntity, entityIdx, $"Delete{PascalCase(entity.Name)}");

            _slugToQueryNode[entity.Slug] = queryId;

            // CRUD nodes form a natural cycle: Query → Create/Update/Delete
            AddEdge(queryId, createId);
            AddEdge(queryId, updateId);
            AddEdge(queryId, deleteId);

            // Phase 2: Action nodes for this entity
            foreach (var action in entity.Actions)
            {
                var actionId = AddNode(CapabilityType.RunAction, entityIdx,
                    $"RunAction({entity.Slug}.{action.Name})",
                    detail: action.Label ?? action.Name);
                // Query → Action (must query to find targets)
                AddEdge(queryId, actionId);
                // Action → Query (action results may need re-query)
                AddEdge(actionId, queryId);
            }
        }

        // Phase 3: Relationship edges (lookup, child-list, related-document)
        foreach (var entity in _registry.All)
        {
            if (!_slugToEntityIndex.TryGetValue(entity.Slug, out var srcEntityIdx)) continue;
            if (!_slugToQueryNode.TryGetValue(entity.Slug, out var srcQueryId)) continue;

            foreach (var field in entity.Fields)
            {
                TryAddRelationshipEdge(field.LookupEntitySlug, srcQueryId, srcEntityIdx, entity.Slug);
                TryAddRelationshipEdge(field.ChildEntitySlug, srcQueryId, srcEntityIdx, entity.Slug);
                TryAddRelationshipEdge(field.RelatedDocumentSlug, srcQueryId, srcEntityIdx, entity.Slug);
            }
        }

        // Phase 4: View nodes
        if (store != null)
        {
            try
            {
                var views = await store.QueryAsync<BareMetalWeb.Data.ViewDefinition>().ConfigureAwait(false);
                foreach (var view in views)
                {
                    var rootSlug = view.RootEntity;
                    int entityIdx = _slugToEntityIndex.TryGetValue(rootSlug ?? "", out var idx) ? idx : -1;
                    var viewNodeId = AddNode(CapabilityType.NavigateView, entityIdx,
                        $"View({view.ViewName})",
                        detail: view.ViewName);

                    // View connects to root entity's query
                    if (entityIdx >= 0 && _slugToQueryNode.TryGetValue(rootSlug!, out var rootQuery))
                    {
                        AddEdge(rootQuery, viewNodeId);
                        AddEdge(viewNodeId, rootQuery);
                    }
                }
            }
            catch { /* views are optional */ }

            // Phase 5: Scheduled action → workflow nodes
            try
            {
                var scheduledActions = await store.QueryAsync<ScheduledActionDefinition>().ConfigureAwait(false);
                foreach (var sa in scheduledActions)
                {
                    // Resolve entity by EntityId
                    int entityIdx = -1;
                    int? entityQueryId = null;
                    if (!string.IsNullOrWhiteSpace(sa.EntityId))
                    {
                        foreach (var entity in _registry.All)
                        {
                            if (string.Equals(entity.EntityId, sa.EntityId, StringComparison.OrdinalIgnoreCase))
                            {
                                entityIdx = _slugToEntityIndex.TryGetValue(entity.Slug, out var ei) ? ei : -1;
                                entityQueryId = _slugToQueryNode.TryGetValue(entity.Slug, out var qid) ? qid : null;
                                break;
                            }
                        }
                    }

                    var workflowId = AddNode(CapabilityType.RunWorkflow, entityIdx,
                        $"RunWorkflow({sa.Name})",
                        detail: $"schedule={sa.Schedule},action={sa.ActionName}");

                    if (entityQueryId.HasValue)
                    {
                        AddEdge(entityQueryId.Value, workflowId);
                        AddEdge(workflowId, entityQueryId.Value);
                    }
                }
            }
            catch { /* scheduled actions are optional */ }
        }

        return new MetadataCapabilityGraph(
            _nodes.ToArray(),
            _edges.ToArray(),
            _entities.ToArray(),
            DateTime.UtcNow);
    }

    private void TryAddRelationshipEdge(string? targetSlug, int srcQueryId, int srcEntityIdx, string srcSlug)
    {
        if (string.IsNullOrWhiteSpace(targetSlug)) return;
        if (!_slugToQueryNode.TryGetValue(targetSlug, out var targetQueryId)) return;
        if (string.Equals(targetSlug, srcSlug, StringComparison.OrdinalIgnoreCase)) return; // skip self-ref

        // Traverse from source to target entity
        var traverseId = AddNode(CapabilityType.TraverseRelationship,
            _slugToEntityIndex.TryGetValue(targetSlug, out var tei) ? tei : -1,
            $"Join{PascalCase(_entities[srcEntityIdx].Name)}→{PascalCase(_entities.FirstOrDefault(e => string.Equals(e.Slug, targetSlug, StringComparison.OrdinalIgnoreCase)).Name ?? targetSlug)}");

        AddEdge(srcQueryId, traverseId);
        AddEdge(traverseId, targetQueryId);
        // Bidirectional traversal
        AddEdge(targetQueryId, traverseId);
    }

    private int AddNode(CapabilityType type, int entityIndex, string label, string? detail = null)
    {
        int id = _nextId++;
        _nodes.Add(new CapabilityNode(id, type, entityIndex, label, detail));
        return id;
    }

    private void AddEdge(int from, int to)
    {
        _edges.Add(new CapabilityEdge(from, to));
    }

    private static string PascalCase(string name)
    {
        if (string.IsNullOrEmpty(name)) return name;
        // Strip spaces/hyphens and capitalize each word
        var sb = new System.Text.StringBuilder(name.Length);
        bool capitalizeNext = true;
        foreach (char c in name)
        {
            if (c == ' ' || c == '-' || c == '_')
            {
                capitalizeNext = true;
                continue;
            }
            sb.Append(capitalizeNext ? char.ToUpperInvariant(c) : c);
            capitalizeNext = false;
        }
        return sb.ToString();
    }
}
