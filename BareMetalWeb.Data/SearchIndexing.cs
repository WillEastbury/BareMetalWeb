using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// Specifies the type of index to use for a property.
/// </summary>
/// <remarks>
/// <para><b>Inverted Index:</b> (Default) Fast full-text search with prefix matching. Best for general text search.
/// Uses token-to-IDs mapping with prefix tree optimization for efficient substring matching. Excellent for text fields.</para>
/// 
/// <para><b>BTree Index:</b> Sorted index optimized for range queries and prefix searches. Uses SortedDictionary
/// internally which provides O(log n) lookups and maintains sorted order. Good for fields that need sorted access
/// or prefix-based searching (e.g., categories, codes).</para>
/// 
/// <para><b>Treap Index:</b> Randomized Binary Search Tree (BST) with heap property. Combines BST structure with
/// random priorities to maintain balanced tree without explicit rebalancing. Good for fields requiring frequent
/// insertions/deletions while maintaining search performance. Provides expected O(log n) operations.</para>
/// 
/// <para><b>Bloom Filter:</b> Probabilistic data structure for fast membership testing. Uses multiple hash functions
/// and bit array. Extremely space-efficient but can have false positives (never false negatives). Best for
/// "definitely not present" checks on large datasets where occasional false positives are acceptable.</para>
/// 
/// <para><b>Performance Characteristics:</b></para>
/// <list type="bullet">
/// <item><description>Inverted: Insert O(k) where k=tokens, Search O(m*k) where m=matches, Space O(n*k)</description></item>
/// <item><description>BTree: Insert O(log n), Search O(log n + m), Space O(n)</description></item>
/// <item><description>Treap: Insert O(log n) expected, Search O(log n) expected, Space O(n)</description></item>
/// <item><description>Bloom: Insert O(k) where k=hash functions, Search O(k), Space O(1) very compact</description></item>
/// </list>
/// </remarks>
public enum IndexKind
{
    Inverted,
    BTree,
    Treap,
    Bloom,
    /// <summary>
    /// Graph index stores nodes and typed edges as adjacency lists.
    /// Enables efficient traversal queries: neighbours, paths, multi-hop exploration.
    /// Apply to a lookup/FK field to auto-build edges from parent→child relationships.
    /// </summary>
    Graph,
    /// <summary>
    /// Spatial index for geographic coordinate data (lat/lng).
    /// Stores points in a grid-based spatial hash for fast bounding-box and radius queries.
    /// Token format: "lat,lng" (e.g. "51.5074,-0.1278").
    /// </summary>
    Spatial
}

/// <summary>
/// Marks a property for indexing with the specified index type.
/// </summary>
/// <remarks>
/// <para>Apply this attribute to properties that should be searchable via the SearchIndexManager.
/// Multiple properties on the same type can have different index types.</para>
/// 
/// <para><b>Usage Example:</b></para>
/// <code>
/// public class Product : BaseDataObject
/// {
///     [DataIndex(IndexKind.Inverted)]  // Full-text search
///     public string Name { get; set; }
///     
///     [DataIndex(IndexKind.BTree)]     // Sorted/prefix search
///     public string Category { get; set; }
///     
///     [DataIndex(IndexKind.Bloom)]     // Fast membership check
///     public string Tags { get; set; }
/// }
/// </code>
/// 
/// <para>To search with a specific index type, use the Search method overload:</para>
/// <code>
/// var results = searchManager.Search(typeof(Product), "Electronics", loadAll, IndexKind.BTree);
/// </code>
/// </remarks>
[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class DataIndexAttribute : Attribute
{
    public IndexKind Kind { get; }

    public DataIndexAttribute(IndexKind kind = IndexKind.Inverted)
    {
        Kind = kind;
    }
}

public sealed class SearchIndexManager
{
    /// <summary>Pre-compiled accessor for an indexed field — avoids PropertyInfo reflection on hot paths.</summary>
    public readonly record struct IndexedFieldAccessor(string Name, Type ClrType, Func<object, object?> Getter, DataIndexAttribute Attribute);

    private sealed class TypeMetadata
    {
        public IndexedFieldAccessor[] IndexedFields { get; init; } = Array.Empty<IndexedFieldAccessor>();
        public HashSet<IndexKind> IndexKinds { get; init; } = new();
    }

    private sealed class IndexData
    {
        public object Sync { get; } = new();
        public bool IsBuilt { get; set; }
        // Token -> IDs mapping for inverted index
        public Dictionary<string, HashSet<uint>> Tokens { get; } = new(StringComparer.OrdinalIgnoreCase);
        // ID -> Tokens mapping for efficient removal
        public Dictionary<uint, HashSet<string>> IdToTokens { get; } = new();
        // Prefix tree for efficient prefix matching (token prefix -> full tokens)
        public Dictionary<string, HashSet<string>> PrefixTree { get; } = new(StringComparer.OrdinalIgnoreCase);
        // Suffix tree for efficient suffix matching (reversed token prefix -> full tokens)
        public Dictionary<string, HashSet<string>> SuffixTree { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> WarnedKinds { get; } = new(StringComparer.OrdinalIgnoreCase);
        
        // BTree index data (sorted tokens for range queries)
        public SortedDictionary<string, HashSet<uint>>? BTreeTokens { get; set; }
        
        // Treap index data (randomized BST with priorities)
        public TreapNode? TreapRoot { get; set; }
        public Dictionary<string, HashSet<uint>>? TreapTokenToIds { get; set; }
        
        // Bloom filter data
        public BloomFilterData? BloomFilter { get; set; }

        // Graph index data (adjacency lists for relationship traversal)
        public GraphIndexData? GraphIndex { get; set; }

        // Spatial index data (grid-based spatial hash for coordinate queries)
        public SpatialIndexData? SpatialIndex { get; set; }
    }
    
    // BTree uses SortedDictionary, so no additional node class needed
    
    // Treap node for randomized BST
    private sealed class TreapNode
    {
        public string Token { get; set; } = string.Empty;
        public int Priority { get; set; }
        public HashSet<uint> Ids { get; set; } = new();
        public TreapNode? Left { get; set; }
        public TreapNode? Right { get; set; }
    }
    
    // Bloom filter implementation — bit-packed into ulong[] for POPCNT-accelerated membership tests.
    // Class is intentionally internal (not private-nested) so the .Data.Tests assembly can unit-test
    // the MightContain and PopulationCount paths directly via InternalsVisibleTo.
    /// Graph index data: adjacency lists for efficient relationship traversal.
    /// Each node (uint ID) maps to a set of typed edges (target ID + edge type).
    /// </summary>
    private sealed class GraphIndexData
    {
        /// <summary>Forward adjacency: nodeId → set of (targetId, edgeType).</summary>
        public Dictionary<uint, HashSet<GraphEdge>> Forward { get; } = new();
        /// <summary>Reverse adjacency: targetId → set of (sourceId, edgeType).</summary>
        public Dictionary<uint, HashSet<GraphEdge>> Reverse { get; } = new();

        public void AddEdge(uint from, uint to, string edgeType)
        {
            if (!Forward.TryGetValue(from, out var fwd))
            {
                fwd = new HashSet<GraphEdge>(4);
                Forward[from] = fwd;
            }
            fwd.Add(new GraphEdge(to, edgeType));

            if (!Reverse.TryGetValue(to, out var rev))
            {
                rev = new HashSet<GraphEdge>(4);
                Reverse[to] = rev;
            }
            rev.Add(new GraphEdge(from, edgeType));
        }

        public void RemoveNode(uint nodeId)
        {
            if (Forward.TryGetValue(nodeId, out var fwd))
            {
                foreach (var e in fwd)
                    Reverse.GetValueOrDefault(e.TargetId)?.RemoveWhere(x => x.TargetId == nodeId);
                Forward.Remove(nodeId);
            }
            if (Reverse.TryGetValue(nodeId, out var rev))
            {
                foreach (var e in rev)
                    Forward.GetValueOrDefault(e.TargetId)?.RemoveWhere(x => x.TargetId == nodeId);
                Reverse.Remove(nodeId);
            }
        }

        /// <summary>BFS/DFS neighbours within N hops.</summary>
        public HashSet<uint> Traverse(uint startId, int maxHops, string? edgeType = null)
        {
            var visited = new HashSet<uint>(16);
            var queue = new Queue<(uint Id, int Depth)>();
            queue.Enqueue((startId, 0));
            visited.Add(startId);
            while (queue.Count > 0)
            {
                var (current, depth) = queue.Dequeue();
                if (depth >= maxHops) continue;
                if (Forward.TryGetValue(current, out var edges))
                {
                    foreach (var e in edges)
                    {
                        if (edgeType != null && !string.Equals(e.EdgeType, edgeType, StringComparison.OrdinalIgnoreCase)) continue;
                        if (visited.Add(e.TargetId))
                            queue.Enqueue((e.TargetId, depth + 1));
                    }
                }
            }
            return visited;
        }
    }

    private readonly record struct GraphEdge(uint TargetId, string EdgeType);

    /// <summary>
    /// Grid-based spatial hash for fast bounding-box and radius queries on lat/lng coordinates.
    /// Divides the world into cells of ~1km at the equator (0.01° grid).
    /// </summary>
    private sealed class SpatialIndexData
    {
        private const double CellSize = 0.01; // ~1.1km at equator

        /// <summary>Point stored in the spatial index.</summary>
        public readonly record struct GeoPoint(uint Id, double Lat, double Lng);

        /// <summary>Grid cell key → points in that cell.</summary>
        private readonly Dictionary<(int LatCell, int LngCell), List<GeoPoint>> _grid = new();

        /// <summary>Id → point for fast removal.</summary>
        private readonly Dictionary<uint, GeoPoint> _points = new();

        public void Add(uint id, double lat, double lng)
        {
            var pt = new GeoPoint(id, lat, lng);
            _points[id] = pt;
            var cell = GetCell(lat, lng);
            if (!_grid.TryGetValue(cell, out var list))
            {
                list = new List<GeoPoint>();
                _grid[cell] = list;
            }
            list.Add(pt);
        }

        public void Remove(uint id)
        {
            if (!_points.TryGetValue(id, out var pt)) return;
            _points.Remove(id);
            var cell = GetCell(pt.Lat, pt.Lng);
            if (_grid.TryGetValue(cell, out var list))
            {
                list.RemoveAll(p => p.Id == id);
                if (list.Count == 0) _grid.Remove(cell);
            }
        }

        /// <summary>Returns all point IDs within the given bounding box.</summary>
        public HashSet<uint> SearchBoundingBox(double minLat, double maxLat, double minLng, double maxLng)
        {
            var results = new HashSet<uint>(16);
            var minCell = GetCell(minLat, minLng);
            var maxCell = GetCell(maxLat, maxLng);
            for (int latC = minCell.LatCell; latC <= maxCell.LatCell; latC++)
            {
                for (int lngC = minCell.LngCell; lngC <= maxCell.LngCell; lngC++)
                {
                    if (!_grid.TryGetValue((latC, lngC), out var list)) continue;
                    foreach (var pt in list)
                    {
                        if (pt.Lat >= minLat && pt.Lat <= maxLat && pt.Lng >= minLng && pt.Lng <= maxLng)
                            results.Add(pt.Id);
                    }
                }
            }
            return results;
        }

        /// <summary>Returns all point IDs within radiusKm of (centerLat, centerLng).</summary>
        public HashSet<uint> SearchRadius(double centerLat, double centerLng, double radiusKm)
        {
            // Convert radius to approximate degrees
            double latDelta = radiusKm / 111.0;
            double lngDelta = radiusKm / (111.0 * Math.Cos(centerLat * Math.PI / 180.0));
            if (lngDelta <= 0) lngDelta = latDelta;

            var candidates = SearchBoundingBox(
                centerLat - latDelta, centerLat + latDelta,
                centerLng - lngDelta, centerLng + lngDelta);

            // Refine with Haversine distance
            var results = new HashSet<uint>(8);
            foreach (var id in candidates)
            {
                if (_points.TryGetValue(id, out var pt) && HaversineKm(centerLat, centerLng, pt.Lat, pt.Lng) <= radiusKm)
                    results.Add(id);
            }
            return results;
        }

        /// <summary>Gets the nearest N points to a center coordinate.</summary>
        public List<(uint Id, double DistanceKm)> SearchNearest(double centerLat, double centerLng, int count)
        {
            // Start with a small radius and expand until we have enough candidates
            double radiusKm = 10;
            HashSet<uint> candidates;
            do
            {
                candidates = SearchRadius(centerLat, centerLng, radiusKm);
                radiusKm *= 2;
            } while (candidates.Count < count && radiusKm < 20_000);

            var sorted = new List<(uint Id, double DistanceKm)>();
            foreach (var id in candidates)
            {
                if (_points.TryGetValue(id, out var pt))
                    sorted.Add((id, HaversineKm(centerLat, centerLng, pt.Lat, pt.Lng)));
            }
            sorted.Sort((a, b) => a.DistanceKm.CompareTo(b.DistanceKm));
            return sorted.Count > count ? sorted.GetRange(0, count) : sorted;
        }

        private static (int LatCell, int LngCell) GetCell(double lat, double lng) =>
            ((int)Math.Floor(lat / CellSize), (int)Math.Floor(lng / CellSize));

        /// <summary>Haversine distance in kilometres.</summary>
        private static double HaversineKm(double lat1, double lng1, double lat2, double lng2)
        {
            const double R = 6371.0;
            double dLat = (lat2 - lat1) * Math.PI / 180.0;
            double dLng = (lng2 - lng1) * Math.PI / 180.0;
            double a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2) +
                       Math.Cos(lat1 * Math.PI / 180.0) * Math.Cos(lat2 * Math.PI / 180.0) *
                       Math.Sin(dLng / 2) * Math.Sin(dLng / 2);
            return R * 2.0 * Math.Atan2(Math.Sqrt(a), Math.Sqrt(1.0 - a));
        }
    }

    private readonly string _indexRoot;
    private readonly IBufferedLogger? _logger;
    private readonly ConcurrentDictionary<Type, IndexData> _indexes = new();
    private readonly ConcurrentDictionary<Type, TypeMetadata> _typeMetadata = new();

    public SearchIndexManager(string rootPath, IBufferedLogger? logger)
    {
        _indexRoot = Path.Combine(rootPath, "indexes");
        Directory.CreateDirectory(_indexRoot);
        _logger = logger;
    }

    public bool HasIndexedFields(Type type, out List<IndexedFieldAccessor> fields)
    {
        var metadata = GetOrCreateTypeMetadata(type);
        fields = new List<IndexedFieldAccessor>(metadata.IndexedFields);
        return fields.Count > 0;
    }

    private TypeMetadata GetOrCreateTypeMetadata(Type type)
    {
        return _typeMetadata.GetOrAdd(type, t =>
        {
            // Prefer DataScaffold metadata (already has compiled delegates) over raw reflection
            var entityMeta = BareMetalWeb.Core.DataScaffold.GetEntityByType(t);
            if (entityMeta != null)
            {
                var indexed = new List<IndexedFieldAccessor>();
                var kinds = new HashSet<IndexKind>(4);
                foreach (var f in entityMeta.Fields)
                {
                    if (f.DataIndex != null)
                    {
                        indexed.Add(new IndexedFieldAccessor(f.Name, f.ClrType, f.GetValueFn, f.DataIndex));
                        kinds.Add(f.DataIndex.Kind);
                    }
                }
                return new TypeMetadata
                {
                    IndexedFields = indexed.ToArray(),
                    IndexKinds = kinds
                };
            }

            // Fallback: scan properties directly (startup only, cached)
            var props = t.GetProperties(BindingFlags.Public | BindingFlags.Instance);
            var indexedProps = new List<IndexedFieldAccessor>(props.Length);
            var fallbackKinds = new HashSet<IndexKind>(4);

            foreach (var prop in props)
            {
                var attr = prop.GetCustomAttribute<DataIndexAttribute>();
                if (attr != null)
                {
                    var getter = PropertyAccessorFactory.BuildGetter(prop);
                    indexedProps.Add(new IndexedFieldAccessor(prop.Name, prop.PropertyType, getter, attr));
                    fallbackKinds.Add(attr.Kind);
                }
            }

            return new TypeMetadata
            {
                IndexedFields = indexedProps.ToArray(),
                IndexKinds = fallbackKinds
            };
        });
    }

    public void EnsureBuilt(Type type, Func<IEnumerable<BaseDataObject>> loadAll)
    {
        var index = _indexes.GetOrAdd(type, LoadIndex);
        if (index.IsBuilt)
            return;

        lock (index.Sync)
        {
            if (index.IsBuilt)
                return;

            BuildFrom(index, loadAll);
            index.IsBuilt = true;
            SaveIndex(type, index);
        }
    }

    public void IndexObject(BaseDataObject obj)
    {
        if (obj == null || obj.Key == 0)
            return;

        var type = obj.GetType();
        var index = _indexes.GetOrAdd(type, LoadIndex);
        var metadata = GetOrCreateTypeMetadata(type);
        var tokens = BuildTokens(obj, index);

        lock (index.Sync)
        {
            RemoveObjectInternal(index, obj.Key, metadata);
            if (tokens.Count == 0)
            {
                index.IsBuilt = true;
                SaveIndex(type, index);
                return;
            }

            index.IdToTokens[obj.Key] = tokens;
            foreach (var token in tokens)
            {
                // Add to Inverted index (always present for backward compatibility)
                if (!index.Tokens.TryGetValue(token, out var ids))
                {
                    ids = new HashSet<uint>(8);
                    index.Tokens[token] = ids;
                }
                ids.Add(obj.Key);
                AddToPrefixTree(index, token);

                // Add to other index types as needed
                if (metadata.IndexKinds.Contains(IndexKind.BTree))
                    AddToBTree(index, token, obj.Key);
                
                if (metadata.IndexKinds.Contains(IndexKind.Treap))
                    AddToTreap(index, token, obj.Key);
                
                if (metadata.IndexKinds.Contains(IndexKind.Bloom))
                    AddToBloomFilter(index, token, obj.Key);

                if (metadata.IndexKinds.Contains(IndexKind.Graph) && uint.TryParse(token, out var targetId))
                    AddToGraphIndex(index, obj.Key, targetId, type.Name);

                if (metadata.IndexKinds.Contains(IndexKind.Spatial) && TryParseCoordinate(token, out var lat, out var lng))
                    AddToSpatialIndex(index, obj.Key, lat, lng);
            }

            index.IsBuilt = true;
            SaveIndex(type, index);
        }
    }

    private static void AddToPrefixTree(IndexData index, string token)
    {
        // Skip tokens shorter than 3 chars (no prefix tree entry for them)
        if (token.Length < 3)
            return;
        
        // Add all prefixes of length 3+ to the prefix tree
        for (int len = 3; len <= token.Length; len++)
        {
            var prefix = token.Substring(0, len);
            if (!index.PrefixTree.TryGetValue(prefix, out var fullTokens))
            {
                fullTokens = new HashSet<string>(8, StringComparer.OrdinalIgnoreCase);
                index.PrefixTree[prefix] = fullTokens;
            }
            fullTokens.Add(token);
        }

        // Add reversed suffixes for suffix matching (e.g. "hello" → reversed suffixes "ol", "oll", "olle", "olleh")
        AddToSuffixTree(index, token);
    }

    private static void AddToSuffixTree(IndexData index, string token)
    {
        if (token.Length < 3) return;
        // Reverse the token, then store prefixes of the reversed string
        var reversed = ReverseString(token);
        for (int len = 3; len <= reversed.Length; len++)
        {
            var suffix = reversed.Substring(0, len);
            if (!index.SuffixTree.TryGetValue(suffix, out var fullTokens))
            {
                fullTokens = new HashSet<string>(8, StringComparer.OrdinalIgnoreCase);
                index.SuffixTree[suffix] = fullTokens;
            }
            fullTokens.Add(token);
        }
    }

    private static string ReverseString(string s)
    {
        var arr = s.ToCharArray();
        Array.Reverse(arr);
        return new string(arr);
    }

    public void RemoveObject(BaseDataObject obj)
    {
        if (obj == null || obj.Key == 0)
            return;

        var type = obj.GetType();
        var metadata = GetOrCreateTypeMetadata(type);
        var index = _indexes.GetOrAdd(type, LoadIndex);
        lock (index.Sync)
        {
            RemoveObjectInternal(index, obj.Key, metadata);
            SaveIndex(type, index);
        }
    }

    public void RemoveObject(Type type, uint id)
    {
        if (type == null || id == 0)
            return;

        var metadata = GetOrCreateTypeMetadata(type);
        var index = _indexes.GetOrAdd(type, LoadIndex);
        lock (index.Sync)
        {
            RemoveObjectInternal(index, id, metadata);
            SaveIndex(type, index);
        }
    }

    public IReadOnlyCollection<uint> Search(Type type, string queryText, Func<IEnumerable<BaseDataObject>> loadAll)
    {
        return Search(type, queryText, loadAll, null);
    }

    /// <summary>
    /// Search using only the suffix tree layer. Finds tokens that end with the query text.
    /// Useful for searching by file extension, domain suffix, or word endings.
    /// </summary>
    public IReadOnlyCollection<uint> SearchSuffix(Type type, string suffixText, Func<IEnumerable<BaseDataObject>> loadAll)
    {
        if (string.IsNullOrWhiteSpace(suffixText) || suffixText.Length < 3)
            return Array.Empty<uint>();

        EnsureBuilt(type, loadAll);
        var index = _indexes.GetOrAdd(type, LoadIndex);
        var results = new HashSet<uint>(8);
        lock (index.Sync)
        {
            var reversed = ReverseString(suffixText.ToLowerInvariant());
            if (index.SuffixTree.TryGetValue(reversed, out var matchedTokens))
            {
                foreach (var token in matchedTokens)
                {
                    if (index.Tokens.TryGetValue(token, out var ids))
                    {
                        foreach (var id in ids)
                            results.Add(id);
                    }
                }
            }
        }
        return results;
    }

    public IReadOnlyCollection<uint> Search(Type type, string queryText, Func<IEnumerable<BaseDataObject>> loadAll, IndexKind? preferredKind)
    {
        if (string.IsNullOrWhiteSpace(queryText))
            return Array.Empty<uint>();

        EnsureBuilt(type, loadAll);
        var index = _indexes.GetOrAdd(type, LoadIndex);
        var metadata = GetOrCreateTypeMetadata(type);
        
        // Determine which index to use
        IndexKind useKind;
        if (preferredKind.HasValue)
        {
            useKind = preferredKind.Value;
        }
        else
        {
            useKind = IndexKind.Inverted;
            foreach (var k in metadata.IndexKinds)
            {
                useKind = k;
                break;
            }
        }
        
        var results = new HashSet<uint>(8);
        lock (index.Sync)
        {
            // Use Span-based tokenization for zero allocations during query parsing
            TokenizeToHashSet(queryText, out var queryTokens);
            if (queryTokens.Count == 0)
                return Array.Empty<uint>();

            // Search using the appropriate index type
            foreach (var queryToken in queryTokens)
            {
                IEnumerable<uint> tokenResults;
                
                switch (useKind)
                {
                    case IndexKind.BTree:
                        tokenResults = SearchBTree(index, queryToken);
                        break;
                    
                    case IndexKind.Treap:
                        tokenResults = SearchTreap(index, queryToken);
                        break;
                    
                    case IndexKind.Bloom:
                        tokenResults = SearchBloomFilter(index, queryToken);
                        break;

                    case IndexKind.Graph:
                        // For graph, treat query as a node ID and return neighbours
                        if (uint.TryParse(queryToken, out var nodeId) && index.GraphIndex != null)
                            tokenResults = index.GraphIndex.Traverse(nodeId, 1);
                        else
                            tokenResults = SearchInverted(index, queryToken);
                        break;

                    case IndexKind.Spatial:
                        tokenResults = SearchSpatialFromToken(index, queryToken);
                        break;
                    
                    case IndexKind.Inverted:
                    default:
                        tokenResults = SearchInverted(index, queryToken);
                        break;
                }
                
                foreach (var id in tokenResults)
                    results.Add(id);
            }
        }

        return results;
    }

    private IEnumerable<uint> SearchInverted(IndexData index, string queryToken)
    {
        var results = new HashSet<uint>(8);
        
        // Check for exact match first (fastest path)
        if (index.Tokens.TryGetValue(queryToken, out var exactIds))
        {
            foreach (var id in exactIds)
                results.Add(id);
            return results;
        }

        // Use prefix tree for prefix matching if available
        if (queryToken.Length >= 3 && index.PrefixTree.TryGetValue(queryToken, out var prefixMatches))
        {
            foreach (var matchedToken in prefixMatches)
            {
                if (index.Tokens.TryGetValue(matchedToken, out var ids))
                {
                    foreach (var id in ids)
                        results.Add(id);
                }
            }
            return results;
        }

        // Use suffix tree for suffix matching (reverse the query and look up in suffix tree)
        if (queryToken.Length >= 3)
        {
            var reversed = ReverseString(queryToken);
            if (index.SuffixTree.TryGetValue(reversed, out var suffixMatches))
            {
                foreach (var matchedToken in suffixMatches)
                {
                    if (index.Tokens.TryGetValue(matchedToken, out var ids))
                    {
                        foreach (var id in ids)
                            results.Add(id);
                    }
                }
                if (results.Count > 0) return results;
            }
        }

        // Fallback to contains search only for short query tokens
        foreach (var entry in index.Tokens)
        {
            if (entry.Key.Contains(queryToken, StringComparison.OrdinalIgnoreCase))
            {
                foreach (var id in entry.Value)
                    results.Add(id);
            }
        }
        
        return results;
    }

    private IndexData LoadIndex(Type type)
    {
        var index = new IndexData();
        var path = GetIndexPath(type);
        if (!File.Exists(path))
            return index;

        try
        {
            // Use binary format for faster loading and smaller file size
            using var stream = File.OpenRead(path);
            using var reader = new BinaryReader(stream, Encoding.UTF8);

            // Read version header
            var version = reader.ReadInt32();
            if (version == 1)
            {
                // Old format with string IDs — force rebuild
                index.IsBuilt = false;
                return index;
            }
            if (version != 2)
            {
                _logger?.LogError($"Unknown index version {version} for {type.Name}. Will rebuild.", new InvalidDataException($"Version {version}"));
                index.IsBuilt = false; // Force rebuild on next EnsureBuilt
                return index;
            }

            // Read Tokens dictionary
            var tokenCount = reader.ReadInt32();
            for (int i = 0; i < tokenCount; i++)
            {
                var token = reader.ReadString();
                var idsCount = reader.ReadInt32();
                var ids = new HashSet<uint>(idsCount);
                for (int j = 0; j < idsCount; j++)
                {
                    ids.Add(reader.ReadUInt32());
                }
                index.Tokens[token] = ids;
            }

            // Read IdToTokens dictionary
            var idToTokensCount = reader.ReadInt32();
            for (int i = 0; i < idToTokensCount; i++)
            {
                var id = reader.ReadUInt32();
                var tokensCount = reader.ReadInt32();
                var tokens = new HashSet<string>(tokensCount, StringComparer.OrdinalIgnoreCase);
                for (int j = 0; j < tokensCount; j++)
                {
                    tokens.Add(reader.ReadString());
                }
                index.IdToTokens[id] = tokens;
            }

            // Rebuild prefix tree from loaded tokens
            foreach (var token in index.Tokens.Keys)
            {
                AddToPrefixTree(index, token);
            }

            index.IsBuilt = true;
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Failed to load index for {type.Name}.", ex);
        }

        return index;
    }

    private void SaveIndex(Type type, IndexData index)
    {
        try
        {
            // Use binary format for faster saving and smaller file size
            var path = GetIndexPath(type);
            var tempPath = path + ".tmp";

            using (var stream = File.Create(tempPath))
            using (var writer = new BinaryWriter(stream, Encoding.UTF8))
            {
                // Write version
                writer.Write(2);

                // Write Tokens dictionary
                writer.Write(index.Tokens.Count);
                foreach (var entry in index.Tokens)
                {
                    writer.Write(entry.Key);
                    writer.Write(entry.Value.Count);
                    foreach (var id in entry.Value)
                    {
                        writer.Write((uint)id);
                    }
                }

                // Write IdToTokens dictionary
                writer.Write(index.IdToTokens.Count);
                foreach (var entry in index.IdToTokens)
                {
                    writer.Write((uint)entry.Key);
                    writer.Write(entry.Value.Count);
                    foreach (var token in entry.Value)
                    {
                        writer.Write(token);
                    }
                }
            }

            // Atomic replace using overwrite parameter (available in .NET 6+)
            File.Move(tempPath, path, overwrite: true);
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Failed to save index for {type.Name}.", ex);
        }
    }

    private void BuildFrom(IndexData index, Func<IEnumerable<BaseDataObject>> loadAll)
    {
        index.Tokens.Clear();
        index.IdToTokens.Clear();
        index.PrefixTree.Clear();
        
        // Load all objects once to avoid calling loadAll multiple times
        var allObjects = new List<BaseDataObject>();
        foreach (var obj in loadAll())
            allObjects.Add(obj);
        if (allObjects.Count == 0)
            return;
        
        // Get metadata to determine which index types to build
        var metadata = GetOrCreateTypeMetadata(allObjects[0].GetType());
        
        // Clear other index types
        if (metadata.IndexKinds.Contains(IndexKind.BTree))
        {
            index.BTreeTokens?.Clear();
            InitializeBTreeIndex(index);
        }
        
        if (metadata.IndexKinds.Contains(IndexKind.Treap))
        {
            index.TreapRoot = null;
            index.TreapTokenToIds?.Clear();
            InitializeTreapIndex(index);
        }
        
        if (metadata.IndexKinds.Contains(IndexKind.Bloom))
        {
            index.BloomFilter = null;
            InitializeBloomFilter(index);
        }
        
        foreach (var obj in allObjects)
        {
            if (obj == null || obj.Key == 0)
                continue;

            var tokens = BuildTokens(obj, index);
            if (tokens.Count == 0)
                continue;

            index.IdToTokens[obj.Key] = tokens;
            foreach (var token in tokens)
            {
                // Build inverted index
                if (!index.Tokens.TryGetValue(token, out var ids))
                {
                    ids = new HashSet<uint>(8);
                    index.Tokens[token] = ids;
                }
                ids.Add(obj.Key);
                AddToPrefixTree(index, token);
                
                // Build other index types
                if (metadata.IndexKinds.Contains(IndexKind.BTree))
                    AddToBTree(index, token, obj.Key);
                
                if (metadata.IndexKinds.Contains(IndexKind.Treap))
                    AddToTreap(index, token, obj.Key);
                
                if (metadata.IndexKinds.Contains(IndexKind.Bloom))
                    AddToBloomFilter(index, token, obj.Key);
            }
        }
    }

    private HashSet<string> BuildTokens(BaseDataObject obj, IndexData index)
    {
        var tokens = new HashSet<string>(8, StringComparer.OrdinalIgnoreCase);
        var type = obj.GetType();
        var metadata = GetOrCreateTypeMetadata(type);

        for (int i = 0; i < metadata.IndexedFields.Length; i++)
        {
            var accessor = metadata.IndexedFields[i];

            var value = accessor.Getter(obj);
            if (value == null)
                continue;

            var valueType = Nullable.GetUnderlyingType(accessor.ClrType) ?? accessor.ClrType;
            if (valueType == typeof(string))
            {
                AddTokensFromString(tokens, value.ToString());
                continue;
            }

            if (IsIntegralType(valueType))
            {
                var strValue = Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture);
                if (!string.IsNullOrEmpty(strValue))
                    tokens.Add(strValue);
                continue;
            }

            if (value is IEnumerable<string> stringList)
            {
                foreach (var item in stringList)
                    AddTokensFromString(tokens, item);
                continue;
            }

            if (value is IEnumerable enumerable && value is not string)
            {
                foreach (var item in enumerable)
                    AddTokensFromString(tokens, item?.ToString());
            }
        }

        tokens.Remove(string.Empty);
        return tokens;
    }

    private void RemoveObjectInternal(IndexData index, uint id, TypeMetadata metadata)
    {
        if (!index.IdToTokens.TryGetValue(id, out var tokens))
            return;

        foreach (var token in tokens)
        {
            // Remove from inverted index
            if (index.Tokens.TryGetValue(token, out var ids))
            {
                ids.Remove(id);
                if (ids.Count == 0)
                {
                    index.Tokens.Remove(token);
                    
                    // Remove from prefix tree if this was the last occurrence
                    if (token.Length >= 3)
                    {
                        for (int len = 3; len <= token.Length; len++)
                        {
                            var prefix = token.Substring(0, len);
                            if (index.PrefixTree.TryGetValue(prefix, out var fullTokens))
                            {
                                fullTokens.Remove(token);
                                if (fullTokens.Count == 0)
                                    index.PrefixTree.Remove(prefix);
                            }
                        }
                        // Remove from suffix tree
                        var reversed = ReverseString(token);
                        for (int len = 3; len <= reversed.Length; len++)
                        {
                            var suffix = reversed.Substring(0, len);
                            if (index.SuffixTree.TryGetValue(suffix, out var suffixTokens))
                            {
                                suffixTokens.Remove(token);
                                if (suffixTokens.Count == 0)
                                    index.SuffixTree.Remove(suffix);
                            }
                        }
                    }
                }
            }

            // Remove from other index types
            if (metadata.IndexKinds.Contains(IndexKind.BTree))
                RemoveFromBTree(index, token, id);
            
            if (metadata.IndexKinds.Contains(IndexKind.Treap))
                RemoveFromTreap(index, token, id);
            
            if (metadata.IndexKinds.Contains(IndexKind.Bloom))
                RemoveFromBloomFilter(index, token, id);
        }

        // Remove graph index entries for this node
        if (metadata.IndexKinds.Contains(IndexKind.Graph))
            RemoveFromGraphIndex(index, id);

        // Remove spatial index entries for this point
        if (metadata.IndexKinds.Contains(IndexKind.Spatial))
            RemoveFromSpatialIndex(index, id);

        index.IdToTokens.Remove(id);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void AddTokensFromString(HashSet<string> tokens, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return;

        TokenizeToHashSet(value, out var newTokens);
        foreach (var token in newTokens)
            tokens.Add(token);
    }

    // High-performance tokenization using Span<char> to minimize allocations
    private static void TokenizeToHashSet(ReadOnlySpan<char> value, out HashSet<string> tokens)
    {
        tokens = new HashSet<string>(8, StringComparer.OrdinalIgnoreCase);
        
        if (value.IsEmpty)
            return;

        const int MaxStackTokenSize = 256;
        Span<char> buffer = stackalloc char[MaxStackTokenSize];
        int bufferPos = 0;
        List<char>? overflowBuffer = null;

        for (int i = 0; i < value.Length; i++)
        {
            var ch = value[i];

            // ASCII fast path: range check + bitwise lowercase (no Unicode table lookup)
            if (ch <= 127)
            {
                if ((uint)(ch - 'a') <= 'z' - 'a' || (uint)(ch - 'A') <= 'Z' - 'A' || (uint)(ch - '0') <= '9' - '0')
                {
                    // Bitwise OR 0x20 lowercases A-Z, is a no-op for 0-9
                    var lowerCh = (char)(ch | 0x20);
                    if (bufferPos < MaxStackTokenSize)
                    {
                        buffer[bufferPos++] = lowerCh;
                    }
                    else
                    {
                        if (overflowBuffer == null)
                        {
                            overflowBuffer = new List<char>(MaxStackTokenSize * 2);
                            for (int j = 0; j < bufferPos; j++)
                                overflowBuffer.Add(buffer[j]);
                        }
                        overflowBuffer.Add(lowerCh);
                    }

                    // SIMD fast-skip: consume run of already-lowercase ASCII alphanumerics
                    // IndexOfAnyExceptInRange is JIT SIMD-accelerated in .NET 8+
                    if (i + 1 < value.Length && overflowBuffer == null)
                    {
                        var remaining = value.Slice(i + 1);
                        int runLen = remaining.IndexOfAnyExceptInRange('0', 'z');
                        // IndexOfAnyExceptInRange('0','z') covers 0-9, A-Z, a-z plus a few
                        // symbols (: ; < = > ? @ [ \ ] ^ _  `). Re-check the boundary char.
                        if (runLen < 0)
                            runLen = remaining.Length;

                        // Copy the run, lowercasing each char
                        for (int r = 0; r < runLen; r++)
                        {
                            var rc = remaining[r];
                            // Filter out the non-alphanumeric chars in the '0'-'z' range
                            if (!((uint)(rc - 'a') <= 'z' - 'a' || (uint)(rc - 'A') <= 'Z' - 'A' || (uint)(rc - '0') <= '9' - '0'))
                            {
                                runLen = r;
                                break;
                            }
                            var lowered = (char)(rc | 0x20);
                            if (bufferPos < MaxStackTokenSize)
                            {
                                buffer[bufferPos++] = lowered;
                            }
                            else
                            {
                                if (overflowBuffer == null)
                                {
                                    overflowBuffer = new List<char>(MaxStackTokenSize * 2);
                                    for (int j = 0; j < bufferPos; j++)
                                        overflowBuffer.Add(buffer[j]);
                                }
                                overflowBuffer.Add(lowered);
                            }
                        }
                        i += runLen;
                    }

                    continue;
                }
            }
            else if (char.IsLetterOrDigit(ch))
            {
                // Unicode path: full table lookup + invariant lowercase
                var lowerCh = char.ToLowerInvariant(ch);
                if (bufferPos < MaxStackTokenSize)
                {
                    buffer[bufferPos++] = lowerCh;
                }
                else
                {
                    if (overflowBuffer == null)
                    {
                        overflowBuffer = new List<char>(MaxStackTokenSize * 2);
                        for (int j = 0; j < bufferPos; j++)
                            overflowBuffer.Add(buffer[j]);
                    }
                    overflowBuffer.Add(lowerCh);
                }
                continue;
            }

            // End of token - flush buffer
            if (bufferPos > 0 || overflowBuffer?.Count > 0)
            {
                if (overflowBuffer != null)
                {
                    tokens.Add(string.Create(overflowBuffer.Count, overflowBuffer, static (span, list) => { for (int i = 0; i < list.Count; i++) span[i] = list[i]; }));
                    overflowBuffer.Clear();
                    bufferPos = 0;
                }
                else
                {
                    tokens.Add(new string(buffer.Slice(0, bufferPos)));
                    bufferPos = 0;
                }
            }
        }

        // Flush final token if any
        if (bufferPos > 0 || overflowBuffer?.Count > 0)
        {
            if (overflowBuffer != null)
            {
                tokens.Add(string.Create(overflowBuffer.Count, overflowBuffer, static (span, list) => { for (int i = 0; i < list.Count; i++) span[i] = list[i]; }));
            }
            else
            {
                tokens.Add(new string(buffer.Slice(0, bufferPos)));
            }
        }
    }

    private static bool IsIntegralType(Type type)
    {
        return type == typeof(short)
            || type == typeof(int)
            || type == typeof(long)
            || type == typeof(ushort)
            || type == typeof(uint)
            || type == typeof(ulong)
            || type == typeof(byte)
            || type == typeof(sbyte);
    }

    private string GetIndexPath(Type type)
        => Path.Combine(_indexRoot, $"{type.Name}.idx");

    // ===== BTree Index Methods =====
    private void InitializeBTreeIndex(IndexData index)
    {
        if (index.BTreeTokens == null)
            index.BTreeTokens = new SortedDictionary<string, HashSet<uint>>(StringComparer.OrdinalIgnoreCase);
    }

    private void AddToBTree(IndexData index, string token, uint id)
    {
        InitializeBTreeIndex(index);
        if (!index.BTreeTokens!.TryGetValue(token, out var ids))
        {
            ids = new HashSet<uint>(8);
            index.BTreeTokens[token] = ids;
        }
        ids.Add(id);
    }

    private void RemoveFromBTree(IndexData index, string token, uint id)
    {
        if (index.BTreeTokens == null)
            return;
        
        if (index.BTreeTokens.TryGetValue(token, out var ids))
        {
            ids.Remove(id);
            if (ids.Count == 0)
                index.BTreeTokens.Remove(token);
        }
    }

    private IEnumerable<uint> SearchBTree(IndexData index, string queryToken)
    {
        if (index.BTreeTokens == null)
            return Array.Empty<uint>();

        var results = new HashSet<uint>(8);
        
        // Exact match
        if (index.BTreeTokens.TryGetValue(queryToken, out var exactIds))
        {
            foreach (var id in exactIds)
                results.Add(id);
        }
        
        // Prefix match using SortedDictionary's ordered nature
        foreach (var entry in index.BTreeTokens)
        {
            if (entry.Key.StartsWith(queryToken, StringComparison.OrdinalIgnoreCase))
            {
                foreach (var id in entry.Value)
                    results.Add(id);
            }
            else if (string.Compare(entry.Key, queryToken, StringComparison.OrdinalIgnoreCase) > 0 &&
                     !entry.Key.StartsWith(queryToken, StringComparison.OrdinalIgnoreCase))
            {
                // Stop early when we've passed the range of possible matches
                break;
            }
        }
        
        return results;
    }

    // ===== Treap Index Methods =====
    private static readonly Random _random = new Random();

    private void InitializeTreapIndex(IndexData index)
    {
        if (index.TreapTokenToIds == null)
            index.TreapTokenToIds = new Dictionary<string, HashSet<uint>>(StringComparer.OrdinalIgnoreCase);
    }

    private void AddToTreap(IndexData index, string token, uint id)
    {
        InitializeTreapIndex(index);
        
        if (!index.TreapTokenToIds!.TryGetValue(token, out var ids))
        {
            ids = new HashSet<uint>(8);
            index.TreapTokenToIds[token] = ids;
        }
        ids.Add(id);
        
        // Insert into treap structure
        index.TreapRoot = TreapInsert(index.TreapRoot, token, _random.Next());
    }

    private TreapNode? TreapInsert(TreapNode? node, string token, int priority)
    {
        if (node == null)
            return new TreapNode { Token = token, Priority = priority };

        var cmp = string.Compare(token, node.Token, StringComparison.OrdinalIgnoreCase);
        
        if (cmp == 0)
        {
            // Token already exists
            return node;
        }
        else if (cmp < 0)
        {
            node.Left = TreapInsert(node.Left, token, priority);
            if (node.Left != null && node.Left.Priority > node.Priority)
                node = TreapRotateRight(node);
        }
        else
        {
            node.Right = TreapInsert(node.Right, token, priority);
            if (node.Right != null && node.Right.Priority > node.Priority)
                node = TreapRotateLeft(node);
        }
        
        return node;
    }

    private TreapNode TreapRotateRight(TreapNode node)
    {
        var left = node.Left!;
        node.Left = left.Right;
        left.Right = node;
        return left;
    }

    private TreapNode TreapRotateLeft(TreapNode node)
    {
        var right = node.Right!;
        node.Right = right.Left;
        right.Left = node;
        return right;
    }

    private void RemoveFromTreap(IndexData index, string token, uint id)
    {
        if (index.TreapTokenToIds == null)
            return;
        
        if (index.TreapTokenToIds.TryGetValue(token, out var ids))
        {
            ids.Remove(id);
            if (ids.Count == 0)
            {
                index.TreapTokenToIds.Remove(token);
                index.TreapRoot = TreapDelete(index.TreapRoot, token);
            }
        }
    }

    private TreapNode? TreapDelete(TreapNode? node, string token)
    {
        if (node == null)
            return null;

        var cmp = string.Compare(token, node.Token, StringComparison.OrdinalIgnoreCase);
        
        if (cmp < 0)
        {
            node.Left = TreapDelete(node.Left, token);
        }
        else if (cmp > 0)
        {
            node.Right = TreapDelete(node.Right, token);
        }
        else
        {
            // Found the node to delete
            if (node.Left == null)
                return node.Right;
            if (node.Right == null)
                return node.Left;
            
            // Both children exist, rotate based on priority
            if (node.Left.Priority > node.Right.Priority)
            {
                node = TreapRotateRight(node);
                node.Right = TreapDelete(node.Right, token);
            }
            else
            {
                node = TreapRotateLeft(node);
                node.Left = TreapDelete(node.Left, token);
            }
        }
        
        return node;
    }

    private IEnumerable<uint> SearchTreap(IndexData index, string queryToken)
    {
        if (index.TreapTokenToIds == null)
            return Array.Empty<uint>();

        var results = new HashSet<uint>(8);
        
        // Exact match
        if (index.TreapTokenToIds.TryGetValue(queryToken, out var exactIds))
        {
            foreach (var id in exactIds)
                results.Add(id);
        }
        
        // Prefix/substring match - traverse the treap
        TreapSearch(index.TreapRoot, queryToken, index.TreapTokenToIds, results);
        
        return results;
    }

    private void TreapSearch(TreapNode? node, string queryToken, Dictionary<string, HashSet<uint>> tokenToIds, HashSet<uint> results)
    {
        if (node == null)
            return;

        // Check current node
        if (node.Token.Contains(queryToken, StringComparison.OrdinalIgnoreCase))
        {
            if (tokenToIds.TryGetValue(node.Token, out var ids))
            {
                foreach (var id in ids)
                    results.Add(id);
            }
        }

        // Search both subtrees (treap doesn't guarantee all matches are in one subtree for substring search)
        TreapSearch(node.Left, queryToken, tokenToIds, results);
        TreapSearch(node.Right, queryToken, tokenToIds, results);
    }

    // ===== Bloom Filter Methods =====
    private void InitializeBloomFilter(IndexData index, int size = 10000, int hashCount = 3)
    {
        if (index.BloomFilter == null)
            index.BloomFilter = new BloomFilterData(size, hashCount);
    }

    private void AddToBloomFilter(IndexData index, string token, uint id)
    {
        InitializeBloomFilter(index);
        
        var bloom = index.BloomFilter!;
        
        // Set bits using packed ulong array (POPCNT-friendly)
        for (int i = 0; i < bloom.HashCount; i++)
        {
            var bitIndex = ComputeBloomHash(token, i, bloom.Size);
            bloom.SetBit(bitIndex);
        }
        
        // Store in backing dictionary for retrieval
        if (!bloom.TokenToIds.TryGetValue(token, out var ids))
        {
            ids = new HashSet<uint>(8);
            bloom.TokenToIds[token] = ids;
        }
        ids.Add(id);
    }

    private int ComputeBloomHash(string token, int hashIndex, int size)
    {
        var baseHash = StringComparer.OrdinalIgnoreCase.GetHashCode(token);
        var hash = ((baseHash ^ (hashIndex * 0x9e3779b9)) & 0x7FFFFFFF);
        return (int)(hash % size);
    }

    private void RemoveFromBloomFilter(IndexData index, string token, uint id)
    {
        // Note: Bloom filters don't support removal (bits can't be unset safely)
        // We only remove from the backing dictionary
        if (index.BloomFilter == null)
            return;
        
        if (index.BloomFilter.TokenToIds.TryGetValue(token, out var ids))
        {
            ids.Remove(id);
            if (ids.Count == 0)
                index.BloomFilter.TokenToIds.Remove(token);
        }
    }

    private IEnumerable<uint> SearchBloomFilter(IndexData index, string queryToken)
    {
        if (index.BloomFilter == null)
            return Array.Empty<uint>();

        var bloom = index.BloomFilter;
        var results = new HashSet<uint>(8);

        // Pre-compute all hash bit indices on the stack, then test them with a
        // 4-wide unrolled word scan (MightContain) for ILP and cache streaming.
        Span<int> bitIndices = stackalloc int[bloom.HashCount];
        for (int i = 0; i < bloom.HashCount; i++)
            bitIndices[i] = ComputeBloomHash(queryToken, i, bloom.Size);

        bool mightExist = bloom.MightContain(bitIndices);
        
        if (mightExist)
        {
            // Check exact match in backing dictionary
            if (bloom.TokenToIds.TryGetValue(queryToken, out var exactIds))
            {
                foreach (var id in exactIds)
                    results.Add(id);
            }
        }
        
        // For substring search, we still need to check all tokens
        // (Bloom filter only helps with exact membership testing)
        foreach (var entry in bloom.TokenToIds)
        {
            if (entry.Key.Contains(queryToken, StringComparison.OrdinalIgnoreCase))
            {
                foreach (var id in entry.Value)
                    results.Add(id);
            }
        }
        
        return results;
    }

    // ── Graph Index ──────────────────────────────────────────────────────────

    private static void AddToGraphIndex(IndexData index, uint sourceId, uint targetId, string edgeType)
    {
        index.GraphIndex ??= new GraphIndexData();
        index.GraphIndex.AddEdge(sourceId, targetId, edgeType);
    }

    private static void RemoveFromGraphIndex(IndexData index, uint nodeId)
    {
        index.GraphIndex?.RemoveNode(nodeId);
    }

    /// <summary>
    /// Traverse the graph index starting from a node, returning all reachable nodes
    /// within the specified number of hops. Use for org-chart ancestry, document chains, etc.
    /// </summary>
    public IReadOnlyCollection<uint> TraverseGraph(Type type, uint startId, int maxHops, Func<IEnumerable<BaseDataObject>> loadAll, string? edgeType = null)
    {
        EnsureBuilt(type, loadAll);
        var index = _indexes.GetOrAdd(type, LoadIndex);
        lock (index.Sync)
        {
            if (index.GraphIndex == null) return Array.Empty<uint>();
            return index.GraphIndex.Traverse(startId, maxHops, edgeType);
        }
    }

    /// <summary>
    /// Get direct neighbours (1-hop) from the graph index.
    /// </summary>
    public IReadOnlyCollection<uint> GetNeighbours(Type type, uint nodeId, Func<IEnumerable<BaseDataObject>> loadAll)
    {
        EnsureBuilt(type, loadAll);
        var index = _indexes.GetOrAdd(type, LoadIndex);
        lock (index.Sync)
        {
            if (index.GraphIndex == null) return Array.Empty<uint>();
            if (!index.GraphIndex.Forward.TryGetValue(nodeId, out var edges)) return Array.Empty<uint>();
            var result = new uint[edges.Count];
            int idx = 0;
            foreach (var e in edges)
                result[idx++] = e.TargetId;
            return result;
        }
    }

    /// <summary>
    /// Get reverse neighbours (who points to this node).
    /// </summary>
    public IReadOnlyCollection<uint> GetReverseNeighbours(Type type, uint nodeId, Func<IEnumerable<BaseDataObject>> loadAll)
    {
        EnsureBuilt(type, loadAll);
        var index = _indexes.GetOrAdd(type, LoadIndex);
        lock (index.Sync)
        {
            if (index.GraphIndex == null) return Array.Empty<uint>();
            if (!index.GraphIndex.Reverse.TryGetValue(nodeId, out var edges)) return Array.Empty<uint>();
            var result = new uint[edges.Count];
            int idx = 0;
            foreach (var e in edges)
                result[idx++] = e.TargetId;
            return result;
        }
    }

    // ── Spatial index helpers ────────────────────────────────────────────

    private static void AddToSpatialIndex(IndexData index, uint id, double lat, double lng)
    {
        index.SpatialIndex ??= new SpatialIndexData();
        index.SpatialIndex.Add(id, lat, lng);
    }

    private static void RemoveFromSpatialIndex(IndexData index, uint id)
    {
        index.SpatialIndex?.Remove(id);
    }

    /// <summary>
    /// Parses a spatial query token. Supported formats:
    /// "lat,lng" — exact point (used during indexing)
    /// "lat,lng,radiusKm" — radius search
    /// "minLat,maxLat,minLng,maxLng" — bounding box
    /// </summary>
    private static bool TryParseCoordinate(string token, out double lat, out double lng)
    {
        lat = lng = 0;
        var span = token.AsSpan();
        int sep = span.IndexOf(',');
        if (sep < 0) return false;
        return double.TryParse(span[..sep].Trim(), System.Globalization.NumberStyles.Float,
                   System.Globalization.CultureInfo.InvariantCulture, out lat) &&
               double.TryParse(span[(sep + 1)..].Trim(), System.Globalization.NumberStyles.Float,
                   System.Globalization.CultureInfo.InvariantCulture, out lng);
    }

    private static IEnumerable<uint> SearchSpatialFromToken(IndexData index, string queryToken)
    {
        if (index.SpatialIndex == null) return Array.Empty<uint>();

        var span = queryToken.AsSpan();
        // Count commas to determine format
        int commaCount = 0;
        foreach (var c in span) { if (c == ',') commaCount++; }

        const System.Globalization.NumberStyles floatStyle = System.Globalization.NumberStyles.Float;
        var inv = System.Globalization.CultureInfo.InvariantCulture;

        if (commaCount == 2)
        {
            int c1 = span.IndexOf(',');
            int c2 = span[(c1 + 1)..].IndexOf(',') + c1 + 1;
            if (double.TryParse(span[..c1].Trim(), floatStyle, inv, out var lat) &&
                double.TryParse(span[(c1 + 1)..c2].Trim(), floatStyle, inv, out var lng) &&
                double.TryParse(span[(c2 + 1)..].Trim(), floatStyle, inv, out var radius))
            {
                return index.SpatialIndex.SearchRadius(lat, lng, radius);
            }
        }
        if (commaCount == 3)
        {
            int c1 = span.IndexOf(',');
            int c2 = span[(c1 + 1)..].IndexOf(',') + c1 + 1;
            int c3 = span[(c2 + 1)..].IndexOf(',') + c2 + 1;
            if (double.TryParse(span[..c1].Trim(), floatStyle, inv, out var minLat) &&
                double.TryParse(span[(c1 + 1)..c2].Trim(), floatStyle, inv, out var maxLat) &&
                double.TryParse(span[(c2 + 1)..c3].Trim(), floatStyle, inv, out var minLng) &&
                double.TryParse(span[(c3 + 1)..].Trim(), floatStyle, inv, out var maxLng))
            {
                return index.SpatialIndex.SearchBoundingBox(minLat, maxLat, minLng, maxLng);
            }
        }
        return Array.Empty<uint>();
    }

    /// <summary>
    /// Search for points within a radius of a center coordinate.
    /// </summary>
    public IReadOnlyCollection<uint> SearchRadius(Type type, double centerLat, double centerLng, double radiusKm, Func<IEnumerable<BaseDataObject>> loadAll)
    {
        EnsureBuilt(type, loadAll);
        var index = _indexes.GetOrAdd(type, LoadIndex);
        lock (index.Sync)
        {
            if (index.SpatialIndex == null) return Array.Empty<uint>();
            return index.SpatialIndex.SearchRadius(centerLat, centerLng, radiusKm);
        }
    }

    /// <summary>
    /// Search for points within a bounding box.
    /// </summary>
    public IReadOnlyCollection<uint> SearchBoundingBox(Type type, double minLat, double maxLat, double minLng, double maxLng, Func<IEnumerable<BaseDataObject>> loadAll)
    {
        EnsureBuilt(type, loadAll);
        var index = _indexes.GetOrAdd(type, LoadIndex);
        lock (index.Sync)
        {
            if (index.SpatialIndex == null) return Array.Empty<uint>();
            return index.SpatialIndex.SearchBoundingBox(minLat, maxLat, minLng, maxLng);
        }
    }

    /// <summary>
    /// Find the nearest N points to a center coordinate.
    /// </summary>
    public IReadOnlyList<(uint Id, double DistanceKm)> SearchNearest(Type type, double centerLat, double centerLng, int count, Func<IEnumerable<BaseDataObject>> loadAll)
    {
        EnsureBuilt(type, loadAll);
        var index = _indexes.GetOrAdd(type, LoadIndex);
        lock (index.Sync)
        {
            if (index.SpatialIndex == null) return Array.Empty<(uint, double)>();
            return index.SpatialIndex.SearchNearest(centerLat, centerLng, count);
        }
    }
}

/// <summary>
/// Bloom filter bit array — bit-packed into <c>ulong[]</c> words for POPCNT-accelerated
/// membership tests and ILP-friendly 4-wide word scanning.
/// Internal so the <c>BareMetalWeb.Data.Tests</c> assembly can unit-test the
/// <see cref="MightContain"/> and <see cref="PopulationCount"/> paths directly.
/// </summary>
internal sealed class BloomFilterData
{
    /// <summary>Bit array packed into 64-bit words for POPCNT / cache efficiency.</summary>
    public ulong[] Bits { get; set; }
    public int HashCount { get; set; }
    /// <summary>Number of logical bits (not ulong elements).</summary>
    public int Size { get; set; }
    // We still need to store IDs for retrieval (Bloom only tells us "maybe present")
    public Dictionary<string, HashSet<uint>> TokenToIds { get; set; }

    public BloomFilterData(int size = 10000, int hashCount = 3)
    {
        Size = size;
        HashCount = hashCount;
        Bits = new ulong[(size + 63) / 64];
        TokenToIds = new Dictionary<string, HashSet<uint>>(StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>Sets bit at <paramref name="bitIndex"/>.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetBit(int bitIndex)
    {
        Bits[bitIndex >> 6] |= 1UL << (bitIndex & 63);
    }

    /// <summary>Tests bit at <paramref name="bitIndex"/>.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TestBit(int bitIndex) =>
        (Bits[bitIndex >> 6] & (1UL << (bitIndex & 63))) != 0UL;

    /// <summary>
    /// Tests whether all bit positions in <paramref name="bitIndices"/> are set,
    /// using a 4-wide unrolled loop for improved instruction-level parallelism
    /// and cache streaming. Returns <see langword="true"/> if every bit is set
    /// ("might contain"); returns <see langword="false"/> as soon as any bit is clear.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool MightContain(ReadOnlySpan<int> bitIndices)
    {
        var bits = Bits;
        int n = bitIndices.Length;
        int i = 0;

        // 4-wide unrolled: four independent loads let the CPU issue them in parallel.
        for (; i <= n - 4; i += 4)
        {
            ulong w0 = bits[bitIndices[i]     >> 6];
            ulong w1 = bits[bitIndices[i + 1] >> 6];
            ulong w2 = bits[bitIndices[i + 2] >> 6];
            ulong w3 = bits[bitIndices[i + 3] >> 6];

            ulong m0 = 1UL << (bitIndices[i]     & 63);
            ulong m1 = 1UL << (bitIndices[i + 1] & 63);
            ulong m2 = 1UL << (bitIndices[i + 2] & 63);
            ulong m3 = 1UL << (bitIndices[i + 3] & 63);

            if ((w0 & m0) == 0UL || (w1 & m1) == 0UL || (w2 & m2) == 0UL || (w3 & m3) == 0UL)
                return false;
        }

        // Scalar tail for remaining indices.
        for (; i < n; i++)
        {
            if ((bits[bitIndices[i] >> 6] & (1UL << (bitIndices[i] & 63))) == 0UL)
                return false;
        }

        return true;
    }

    /// <summary>
    /// Returns the total number of set bits using hardware POPCNT
    /// (<see cref="BitOperations.PopCount"/>) — useful for estimating
    /// Bloom filter fill rate and false-positive probability.
    /// Uses a 4-wide unrolled loop for improved instruction-level parallelism.
    /// </summary>
    public int PopulationCount()
    {
        var bits = Bits;
        int len = bits.Length;
        int count = 0;
        int i = 0;

        // 4-wide unrolled loop — four independent POPCNT instructions per iteration.
        for (; i <= len - 4; i += 4)
        {
            ulong w0 = bits[i];
            ulong w1 = bits[i + 1];
            ulong w2 = bits[i + 2];
            ulong w3 = bits[i + 3];
            count += BitOperations.PopCount(w0) + BitOperations.PopCount(w1)
                   + BitOperations.PopCount(w2) + BitOperations.PopCount(w3);
        }

        // Scalar tail.
        for (; i < len; i++)
            count += BitOperations.PopCount(bits[i]);

        return count;
    }
}
