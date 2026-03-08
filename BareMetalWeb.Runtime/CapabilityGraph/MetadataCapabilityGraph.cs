using System.Collections.Frozen;

namespace BareMetalWeb.Runtime.CapabilityGraph;

/// <summary>
/// Immutable directed graph of executable capabilities derived from BMW metadata.
/// Nodes represent things the system can do (query, create, run action, etc.);
/// edges represent valid transitions between capabilities based on entity
/// relationships, actions, and workflows.
///
/// The graph uses integer-indexed adjacency lists for O(1) neighbor lookup
/// and cache-friendly traversal. Built once at startup, then frozen.
/// </summary>
public sealed class MetadataCapabilityGraph
{
    /// <summary>All capability nodes, indexed by <see cref="CapabilityNode.Id"/>.</summary>
    public CapabilityNode[] Nodes { get; }

    /// <summary>All directed edges.</summary>
    public CapabilityEdge[] Edges { get; }

    /// <summary>Entity descriptors, indexed by entity-index used in nodes.</summary>
    public EntityDescriptor[] Entities { get; }

    /// <summary>UTC timestamp when this graph was built.</summary>
    public DateTime BuiltUtc { get; }

    // ── Adjacency lists (outgoing) ─────────────────────────────────────────
    // _adjStart[nodeId] = index into _adjNeighbors where this node's neighbors begin.
    // _adjStart[nodeId+1] - _adjStart[nodeId] = number of outgoing edges.
    // Sentinel at _adjStart[NodeCount] = total edge count.
    private readonly int[] _adjStart;
    private readonly int[] _adjNeighbors;

    // ── Reverse adjacency (incoming) ───────────────────────────────────────
    private readonly int[] _revStart;
    private readonly int[] _revNeighbors;

    // ── Fast lookup ────────────────────────────────────────────────────────
    private readonly FrozenDictionary<string, int> _entitySlugToIndex;

    internal MetadataCapabilityGraph(
        CapabilityNode[] nodes,
        CapabilityEdge[] edges,
        EntityDescriptor[] entities,
        DateTime builtUtc)
    {
        Nodes = nodes;
        Edges = edges;
        Entities = entities;
        BuiltUtc = builtUtc;

        // Build slug → index lookup
        var slugMap = new Dictionary<string, int>(entities.Length, StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < entities.Length; i++)
            slugMap[entities[i].Slug] = i;
        _entitySlugToIndex = slugMap.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

        // Build forward adjacency list
        (_adjStart, _adjNeighbors) = BuildAdjacency(nodes.Length, edges, e => e.FromNode, e => e.ToNode);

        // Build reverse adjacency list
        (_revStart, _revNeighbors) = BuildAdjacency(nodes.Length, edges, e => e.ToNode, e => e.FromNode);
    }

    /// <summary>Returns the outgoing neighbor node IDs for the given node.</summary>
    public ReadOnlySpan<int> GetNeighbors(int nodeId)
    {
        if ((uint)nodeId >= (uint)Nodes.Length) return ReadOnlySpan<int>.Empty;
        int start = _adjStart[nodeId];
        int count = _adjStart[nodeId + 1] - start;
        return _adjNeighbors.AsSpan(start, count);
    }

    /// <summary>Returns the incoming neighbor node IDs for the given node.</summary>
    public ReadOnlySpan<int> GetIncoming(int nodeId)
    {
        if ((uint)nodeId >= (uint)Nodes.Length) return ReadOnlySpan<int>.Empty;
        int start = _revStart[nodeId];
        int count = _revStart[nodeId + 1] - start;
        return _revNeighbors.AsSpan(start, count);
    }

    /// <summary>Returns all capability nodes for a given entity slug.</summary>
    public IEnumerable<CapabilityNode> GetCapabilities(string entitySlug)
    {
        if (!_entitySlugToIndex.TryGetValue(entitySlug, out var idx))
            yield break;

        foreach (var node in Nodes)
            if (node.EntityIndex == idx)
                yield return node;
    }

    /// <summary>Returns all nodes of a given capability type.</summary>
    public IEnumerable<CapabilityNode> GetByType(CapabilityType type)
    {
        foreach (var node in Nodes)
            if (node.Type == type)
                yield return node;
    }

    /// <summary>Resolves an entity slug to its descriptor.</summary>
    public bool TryGetEntity(string slug, out EntityDescriptor entity)
    {
        if (_entitySlugToIndex.TryGetValue(slug, out var idx))
        {
            entity = Entities[idx];
            return true;
        }
        entity = default;
        return false;
    }

    /// <summary>Summary statistics for diagnostics.</summary>
    public (int NodeCount, int EdgeCount, int EntityCount) Stats
        => (Nodes.Length, Edges.Length, Entities.Length);

    // ── Adjacency list builder ─────────────────────────────────────────────

    private static (int[] starts, int[] neighbors) BuildAdjacency(
        int nodeCount,
        CapabilityEdge[] edges,
        Func<CapabilityEdge, int> sourceSelector,
        Func<CapabilityEdge, int> targetSelector)
    {
        // Count outgoing edges per node
        var counts = new int[nodeCount];
        foreach (var edge in edges)
        {
            var src = sourceSelector(edge);
            if ((uint)src < (uint)nodeCount)
                counts[src]++;
        }

        // Compute prefix sums → start indices
        var starts = new int[nodeCount + 1];
        for (int i = 0; i < nodeCount; i++)
            starts[i + 1] = starts[i] + counts[i];

        // Fill neighbor array
        var neighbors = new int[starts[nodeCount]];
        var offsets = new int[nodeCount]; // temporary write cursor per node
        foreach (var edge in edges)
        {
            var src = sourceSelector(edge);
            if ((uint)src >= (uint)nodeCount) continue;
            neighbors[starts[src] + offsets[src]] = targetSelector(edge);
            offsets[src]++;
        }

        return (starts, neighbors);
    }
}
