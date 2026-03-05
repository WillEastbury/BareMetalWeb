using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using BareMetalWeb.Core.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// Distance metric for vector similarity comparisons.
/// </summary>
public enum DistanceMetric
{
    Cosine,
    DotProduct,
    Euclidean
}

/// <summary>
/// Quantization type for compact vector storage.
/// </summary>
public enum QuantizationType
{
    None,
    Float16,
    ProductQuantization
}

/// <summary>
/// Metadata definition for a vector index on an entity field.
/// </summary>
public sealed class VectorIndexDefinition
{
    public uint IndexId { get; init; }
    public uint EntityTypeId { get; init; }
    public ushort FieldId { get; init; }
    public ushort Dimension { get; init; }
    public DistanceMetric Metric { get; init; } = DistanceMetric.Cosine;
    public int MaxDegree { get; init; } = 32;
    public QuantizationType Quantizer { get; init; } = QuantizationType.None;
}

/// <summary>
/// A single vector node in the ANN graph: ID, embedding, and neighbour list.
/// </summary>
internal sealed class VectorNode
{
    public uint Id { get; }
    public float[] Embedding { get; }
    public List<uint> Neighbours { get; } = new();

    public VectorNode(uint id, float[] embedding)
    {
        Id = id;
        Embedding = embedding;
    }
}

/// <summary>
/// An immutable segment of vectors with a navigable small-world graph for ANN search.
/// Implements a simplified Vamana-style graph construction.
/// </summary>
internal sealed class VectorSegment
{
    public ushort Dimension { get; }
    public DistanceMetric Metric { get; }
    public int MaxDegree { get; }
    public float[] Centroid { get; private set; }

    private readonly Dictionary<uint, VectorNode> _nodes = new();
    private readonly HashSet<uint> _tombstones = new();
    private uint _entryNode;

    public int Count => _nodes.Count;
    public int LiveCount => _nodes.Count - _tombstones.Count;

    public VectorSegment(ushort dimension, DistanceMetric metric, int maxDegree)
    {
        Dimension = dimension;
        Metric = metric;
        MaxDegree = maxDegree;
        Centroid = new float[dimension];
    }

    /// <summary>
    /// Insert a vector into the segment and wire it into the graph.
    /// </summary>
    public void Insert(uint id, float[] embedding)
    {
        if (embedding.Length != Dimension)
            throw new ArgumentException($"Expected {Dimension}-d vector, got {embedding.Length}-d");

        var node = new VectorNode(id, embedding);
        _nodes[id] = node;

        if (_nodes.Count == 1)
        {
            _entryNode = id;
            RecomputeCentroid();
            return;
        }

        // Greedy search to find nearest neighbours
        var candidates = GreedySearch(embedding, MaxDegree * 2);

        // Prune to MaxDegree neighbours (Vamana-style: keep diverse set)
        var neighbours = PruneNeighbours(embedding, candidates, MaxDegree);

        foreach (var nId in neighbours)
        {
            node.Neighbours.Add(nId);
            // Reverse edge
            if (_nodes.TryGetValue(nId, out var nNode))
            {
                nNode.Neighbours.Add(id);
                // Trim if over capacity
                if (nNode.Neighbours.Count > MaxDegree * 2)
                    TrimNeighbours(nNode);
            }
        }

        RecomputeCentroid();
    }

    /// <summary>Mark a vector as deleted (tombstoned).</summary>
    public void Delete(uint id) => _tombstones.Add(id);

    /// <summary>Check if an ID is tombstoned.</summary>
    public bool IsTombstoned(uint id) => _tombstones.Contains(id);

    /// <summary>
    /// Search for the top-K nearest vectors to a query embedding.
    /// Uses beam search over the navigable graph.
    /// </summary>
    public List<(uint Id, float Distance)> Search(float[] query, int topK, int beamWidth = 64)
    {
        if (_nodes.Count == 0) return new List<(uint, float)>();

        var visited = new HashSet<uint>();
        // Min-heap by distance (closest first for candidates)
        var candidates = new SortedSet<(float Dist, uint Id)>(Comparer<(float, uint)>.Create(
            (a, b) => a.Item1 != b.Item1 ? a.Item1.CompareTo(b.Item1) : a.Item2.CompareTo(b.Item2)));
        var results = new SortedSet<(float Dist, uint Id)>(Comparer<(float, uint)>.Create(
            (a, b) => a.Item1 != b.Item1 ? a.Item1.CompareTo(b.Item1) : a.Item2.CompareTo(b.Item2)));

        if (!_nodes.ContainsKey(_entryNode))
        {
            // Entry node was deleted; pick any live node
            foreach (var kv in _nodes)
            {
                if (!_tombstones.Contains(kv.Key))
                {
                    _entryNode = kv.Key;
                    break;
                }
            }
            if (!_nodes.ContainsKey(_entryNode)) return new List<(uint, float)>();
        }

        var entryDist = ComputeDistance(query, _nodes[_entryNode].Embedding);
        candidates.Add((entryDist, _entryNode));
        visited.Add(_entryNode);

        while (candidates.Count > 0)
        {
            var (dist, currentId) = candidates.Min;
            candidates.Remove(candidates.Min);

            // If worst result is better than current candidate, stop
            if (results.Count >= topK && dist > results.Max.Dist)
                break;

            if (!_tombstones.Contains(currentId))
            {
                results.Add((dist, currentId));
                if (results.Count > topK + beamWidth)
                {
                    // Trim to keep only needed
                    while (results.Count > topK)
                        results.Remove(results.Max);
                }
            }

            if (_nodes.TryGetValue(currentId, out var node))
            {
                foreach (var nId in node.Neighbours)
                {
                    if (!visited.Add(nId)) continue;
                    if (!_nodes.TryGetValue(nId, out var nNode)) continue;
                    var nDist = ComputeDistance(query, nNode.Embedding);
                    candidates.Add((nDist, nId));
                }
            }
        }

        while (results.Count > topK)
            results.Remove(results.Max);

        var output = new List<(uint Id, float Distance)>(results.Count);
        foreach (var r in results)
            output.Add((r.Id, r.Dist));
        return output;
    }

    /// <summary>Greedy best-first search returning nearest candidate IDs.</summary>
    private List<uint> GreedySearch(float[] query, int count)
    {
        var visited = new HashSet<uint>();
        var candidates = new SortedSet<(float Dist, uint Id)>(Comparer<(float, uint)>.Create(
            (a, b) => a.Item1 != b.Item1 ? a.Item1.CompareTo(b.Item1) : a.Item2.CompareTo(b.Item2)));

        var entryDist = ComputeDistance(query, _nodes[_entryNode].Embedding);
        candidates.Add((entryDist, _entryNode));
        visited.Add(_entryNode);

        var bestList = new SortedSet<(float Dist, uint Id)>(Comparer<(float, uint)>.Create(
            (a, b) => a.Item1 != b.Item1 ? a.Item1.CompareTo(b.Item1) : a.Item2.CompareTo(b.Item2)));
        bestList.Add((entryDist, _entryNode));

        while (candidates.Count > 0)
        {
            var (dist, currentId) = candidates.Min;
            candidates.Remove(candidates.Min);

            if (bestList.Count >= count && dist > bestList.Max.Dist)
                break;

            if (_nodes.TryGetValue(currentId, out var node))
            {
                foreach (var nId in node.Neighbours)
                {
                    if (!visited.Add(nId)) continue;
                    if (!_nodes.TryGetValue(nId, out var nNode)) continue;
                    var nDist = ComputeDistance(query, nNode.Embedding);
                    candidates.Add((nDist, nId));
                    bestList.Add((nDist, nId));
                    if (bestList.Count > count * 2)
                        bestList.Remove(bestList.Max);
                }
            }
        }

        var output = new List<uint>(Math.Min(count, bestList.Count));
        int taken = 0;
        foreach (var b in bestList)
        {
            if (taken >= count) break;
            output.Add(b.Id);
            taken++;
        }
        return output;
    }

    /// <summary>Prune neighbour list to diverse subset via Vamana alpha-pruning.</summary>
    private List<uint> PruneNeighbours(float[] query, List<uint> candidates, int maxDegree)
    {
        if (candidates.Count <= maxDegree)
            return candidates;

        // Sort by distance to query
        var ranked = new List<(uint Id, float Dist)>();
        foreach (var id in candidates)
        {
            if (_nodes.ContainsKey(id))
                ranked.Add((id, ComputeDistance(query, _nodes[id].Embedding)));
        }
        ranked.Sort((a, b) => a.Dist.CompareTo(b.Dist));

        var result = new List<uint>();
        foreach (var (id, dist) in ranked)
        {
            if (result.Count >= maxDegree) break;

            // Check if this candidate is diverse enough from already-selected neighbours
            bool tooClose = false;
            foreach (var selected in result)
            {
                if (_nodes.TryGetValue(selected, out var sNode) && _nodes.TryGetValue(id, out var cNode))
                {
                    var interDist = ComputeDistance(sNode.Embedding, cNode.Embedding);
                    if (interDist < dist * 0.8f) // alpha = 0.8
                    {
                        tooClose = true;
                        break;
                    }
                }
            }
            if (!tooClose)
                result.Add(id);
        }

        return result;
    }

    private void TrimNeighbours(VectorNode node)
    {
        if (node.Neighbours.Count <= MaxDegree) return;
        var sortable = new List<(uint Id, float Dist)>();
        foreach (var id in node.Neighbours)
        {
            if (_nodes.ContainsKey(id))
                sortable.Add((id, ComputeDistance(node.Embedding, _nodes[id].Embedding)));
        }
        sortable.Sort((a, b) => a.Dist.CompareTo(b.Dist));
        int trimCount = Math.Min(MaxDegree, sortable.Count);
        var sorted = new List<uint>(trimCount);
        for (int i = 0; i < trimCount; i++)
            sorted.Add(sortable[i].Id);
        node.Neighbours.Clear();
        node.Neighbours.AddRange(sorted);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private float ComputeDistance(float[] a, float[] b) => SimdDistance.Compute(Metric, a, b);

    private void RecomputeCentroid()
    {
        var centroid = new float[Dimension];
        int count = 0;
        foreach (var kv in _nodes)
        {
            if (_tombstones.Contains(kv.Key)) continue;
            for (int i = 0; i < Dimension; i++)
                centroid[i] += kv.Value.Embedding[i];
            count++;
        }
        if (count > 0)
            for (int i = 0; i < Dimension; i++)
                centroid[i] /= count;
        Centroid = centroid;
    }
}

/// <summary>
/// Manages vector ANN indexes across entity types. Each entity/field pair gets its own
/// set of segments. Integrates with the WAL replay pipeline and compaction cycle.
/// 
/// Just another index — WAL-driven, deterministic, rebuildable.
/// </summary>
public sealed class VectorIndexManager
{
    private readonly string _indexRoot;
    private readonly IBufferedLogger? _logger;

    // (entityType, fieldName) → list of segments
    private readonly ConcurrentDictionary<(string EntityType, string Field), List<VectorSegment>> _indexes = new();
    private readonly ConcurrentDictionary<(string EntityType, string Field), VectorIndexDefinition> _definitions = new();

    private const int MaxSegmentSize = 100_000;

    public VectorIndexManager(string rootPath, IBufferedLogger? logger)
    {
        _indexRoot = Path.Combine(rootPath, "vector-indexes");
        Directory.CreateDirectory(_indexRoot);
        _logger = logger;
    }

    /// <summary>Register a vector index definition for an entity/field pair.</summary>
    public void RegisterIndex(string entityType, string field, VectorIndexDefinition definition)
    {
        var key = (entityType, field);
        _definitions[key] = definition;
        _indexes.GetOrAdd(key, _ => new List<VectorSegment>());
        _logger?.LogInfo($"[VectorIndex] Registered index for {entityType}.{field} dim={definition.Dimension} metric={definition.Metric}");
    }

    /// <summary>Upsert a vector embedding for an entity instance.</summary>
    public void Upsert(string entityType, string field, uint objectId, float[] embedding)
    {
        var key = (entityType, field);
        if (!_definitions.TryGetValue(key, out var def))
            return;

        var segments = _indexes.GetOrAdd(key, _ => new List<VectorSegment>());

        lock (segments)
        {
            // Remove from any existing segment first (update case)
            foreach (var seg in segments)
                seg.Delete(objectId);

            // Find a segment with capacity, or create a new one
            VectorSegment? target = null;
            foreach (var s in segments)
            {
                if (s.LiveCount < MaxSegmentSize)
                {
                    target = s;
                    break;
                }
            }
            if (target == null)
            {
                target = new VectorSegment(def.Dimension, def.Metric, def.MaxDegree);
                segments.Add(target);
            }

            target.Insert(objectId, embedding);
        }
    }

    /// <summary>Delete a vector by marking it as tombstoned.</summary>
    public void Delete(string entityType, string field, uint objectId)
    {
        var key = (entityType, field);
        if (!_indexes.TryGetValue(key, out var segments)) return;

        lock (segments)
        {
            foreach (var seg in segments)
                seg.Delete(objectId);
        }
    }

    /// <summary>
    /// Search for the top-K nearest vectors to a query embedding.
    /// Uses segment selection by centroid distance, then beam search within selected segments.
    /// </summary>
    public List<(uint Id, float Distance)> Search(string entityType, string field, float[] query, int topK, int maxSegments = 6)
    {
        var key = (entityType, field);
        if (!_indexes.TryGetValue(key, out var segments) || !_definitions.TryGetValue(key, out var def))
            return new List<(uint, float)>();

        List<VectorSegment> selectedSegments;
        lock (segments)
        {
            if (segments.Count == 0) return new List<(uint, float)>();

            // Select segments by centroid proximity
            if (segments.Count <= maxSegments)
            {
                selectedSegments = new List<VectorSegment>(segments);
            }
            else
            {
                var rankedSegments = new List<(VectorSegment Seg, float Dist)>(segments.Count);
                foreach (var s in segments)
                    rankedSegments.Add((s, CentroidDistance(query, s.Centroid, def.Metric)));
                rankedSegments.Sort((a, b) => a.Dist.CompareTo(b.Dist));
                int takeCount = Math.Min(maxSegments, rankedSegments.Count);
                selectedSegments = new List<VectorSegment>(takeCount);
                for (int i = 0; i < takeCount; i++)
                    selectedSegments.Add(rankedSegments[i].Seg);
            }
        }

        // Search each selected segment and merge results
        var allResults = new SortedSet<(float Dist, uint Id)>(Comparer<(float, uint)>.Create(
            (a, b) => a.Item1 != b.Item1 ? a.Item1.CompareTo(b.Item1) : a.Item2.CompareTo(b.Item2)));

        foreach (var seg in selectedSegments)
        {
            var segResults = seg.Search(query, topK);
            foreach (var (id, dist) in segResults)
                allResults.Add((dist, id));
        }

        var output = new List<(uint Id, float Distance)>(Math.Min(topK, allResults.Count));
        int resultsTaken = 0;
        foreach (var r in allResults)
        {
            if (resultsTaken >= topK) break;
            output.Add((r.Id, r.Dist));
            resultsTaken++;
        }
        return output;
    }

    /// <summary>Returns the number of indexed vectors for an entity/field pair.</summary>
    public int Count(string entityType, string field)
    {
        var key = (entityType, field);
        if (!_indexes.TryGetValue(key, out var segments)) return 0;
        lock (segments)
        {
            int total = 0;
            foreach (var s in segments)
                total += s.LiveCount;
            return total;
        }
    }

    /// <summary>Gets all registered index definitions.</summary>
    public IReadOnlyCollection<(string EntityType, string Field, VectorIndexDefinition Def)> GetDefinitions()
    {
        var result = new (string EntityType, string Field, VectorIndexDefinition Def)[_definitions.Count];
        int idx = 0;
        foreach (var kv in _definitions)
            result[idx++] = (kv.Key.EntityType, kv.Key.Field, kv.Value);
        return result;
    }

    private static float CentroidDistance(float[] query, float[] centroid, DistanceMetric metric)
        => SimdDistance.Compute(metric, query, centroid);
}
