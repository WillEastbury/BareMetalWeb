using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

public enum IndexKind
{
    Inverted,
    BTree,
    Treap,
    Bloom
}

[AttributeUsage(AttributeTargets.Property, Inherited = true, AllowMultiple = false)]
public sealed class DataIndexAttribute : Attribute
{
    public IndexKind Kind { get; }

    public DataIndexAttribute(IndexKind kind = IndexKind.Inverted)
    {
        Kind = kind;
    }
}

internal sealed class SearchIndexManager
{
    // Cache reflection metadata per type to avoid repeated GetProperties calls
    private sealed class TypeMetadata
    {
        public PropertyInfo[] IndexedProperties { get; init; } = Array.Empty<PropertyInfo>();
        public DataIndexAttribute[] Attributes { get; init; } = Array.Empty<DataIndexAttribute>();
        public HashSet<IndexKind> IndexKinds { get; init; } = new();
    }

    private sealed class IndexData
    {
        public object Sync { get; } = new();
        public bool IsBuilt { get; set; }
        // Token -> IDs mapping for inverted index
        public Dictionary<string, HashSet<string>> Tokens { get; } = new(StringComparer.OrdinalIgnoreCase);
        // ID -> Tokens mapping for efficient removal
        public Dictionary<string, HashSet<string>> IdToTokens { get; } = new(StringComparer.OrdinalIgnoreCase);
        // Prefix tree for efficient prefix matching (token prefix -> full tokens)
        public Dictionary<string, HashSet<string>> PrefixTree { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> WarnedKinds { get; } = new(StringComparer.OrdinalIgnoreCase);
        
        // BTree index data (sorted tokens for range queries)
        public SortedDictionary<string, HashSet<string>>? BTreeTokens { get; set; }
        
        // Treap index data (randomized BST with priorities)
        public TreapNode? TreapRoot { get; set; }
        public Dictionary<string, HashSet<string>>? TreapTokenToIds { get; set; }
        
        // Bloom filter data
        public BloomFilterData? BloomFilter { get; set; }
    }
    
    // BTree uses SortedDictionary, so no additional node class needed
    
    // Treap node for randomized BST
    private sealed class TreapNode
    {
        public string Token { get; set; } = string.Empty;
        public int Priority { get; set; }
        public HashSet<string> Ids { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public TreapNode? Left { get; set; }
        public TreapNode? Right { get; set; }
    }
    
    // Bloom filter implementation
    private sealed class BloomFilterData
    {
        public BitArray Bits { get; set; }
        public int HashCount { get; set; }
        public int Size { get; set; }
        // We still need to store IDs for retrieval (Bloom only tells us "maybe present")
        public Dictionary<string, HashSet<string>> TokenToIds { get; set; }
        
        public BloomFilterData(int size = 10000, int hashCount = 3)
        {
            Size = size;
            HashCount = hashCount;
            Bits = new BitArray(size);
            TokenToIds = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
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

    public bool HasIndexedFields(Type type, out List<PropertyInfo> fields)
    {
        var metadata = GetOrCreateTypeMetadata(type);
        fields = new List<PropertyInfo>(metadata.IndexedProperties);
        return fields.Count > 0;
    }

    private TypeMetadata GetOrCreateTypeMetadata(Type type)
    {
        return _typeMetadata.GetOrAdd(type, t =>
        {
            var props = t.GetProperties(BindingFlags.Public | BindingFlags.Instance);
            var indexedProps = new List<PropertyInfo>();
            var attrs = new List<DataIndexAttribute>();
            var kinds = new HashSet<IndexKind>();

            foreach (var prop in props)
            {
                var attr = prop.GetCustomAttribute<DataIndexAttribute>();
                if (attr != null)
                {
                    indexedProps.Add(prop);
                    attrs.Add(attr);
                    kinds.Add(attr.Kind);
                }
            }

            return new TypeMetadata
            {
                IndexedProperties = indexedProps.ToArray(),
                Attributes = attrs.ToArray(),
                IndexKinds = kinds
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
        if (obj == null || string.IsNullOrWhiteSpace(obj.Id))
            return;

        var type = obj.GetType();
        var index = _indexes.GetOrAdd(type, LoadIndex);
        var metadata = GetOrCreateTypeMetadata(type);
        var tokens = BuildTokens(obj, index);

        lock (index.Sync)
        {
            RemoveObjectInternal(index, obj.Id, metadata);
            if (tokens.Count == 0)
            {
                index.IsBuilt = true;
                SaveIndex(type, index);
                return;
            }

            index.IdToTokens[obj.Id] = tokens;
            foreach (var token in tokens)
            {
                // Add to Inverted index (always present for backward compatibility)
                if (!index.Tokens.TryGetValue(token, out var ids))
                {
                    ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    index.Tokens[token] = ids;
                }
                ids.Add(obj.Id);
                AddToPrefixTree(index, token);

                // Add to other index types as needed
                if (metadata.IndexKinds.Contains(IndexKind.BTree))
                    AddToBTree(index, token, obj.Id);
                
                if (metadata.IndexKinds.Contains(IndexKind.Treap))
                    AddToTreap(index, token, obj.Id);
                
                if (metadata.IndexKinds.Contains(IndexKind.Bloom))
                    AddToBloomFilter(index, token, obj.Id);
            }

            index.IsBuilt = true;
            SaveIndex(type, index);
        }
    }

    private static void AddToPrefixTree(IndexData index, string token)
    {
        // Add all prefixes of length 3+ to the prefix tree
        var minPrefixLen = Math.Min(3, token.Length);
        for (int len = minPrefixLen; len <= token.Length; len++)
        {
            var prefix = token.Substring(0, len);
            if (!index.PrefixTree.TryGetValue(prefix, out var fullTokens))
            {
                fullTokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                index.PrefixTree[prefix] = fullTokens;
            }
            fullTokens.Add(token);
        }
    }

    public void RemoveObject(BaseDataObject obj)
    {
        if (obj == null || string.IsNullOrWhiteSpace(obj.Id))
            return;

        var type = obj.GetType();
        var metadata = GetOrCreateTypeMetadata(type);
        var index = _indexes.GetOrAdd(type, LoadIndex);
        lock (index.Sync)
        {
            RemoveObjectInternal(index, obj.Id, metadata);
            SaveIndex(type, index);
        }
    }

    public IReadOnlyCollection<string> Search(Type type, string queryText, Func<IEnumerable<BaseDataObject>> loadAll)
    {
        return Search(type, queryText, loadAll, null);
    }

    public IReadOnlyCollection<string> Search(Type type, string queryText, Func<IEnumerable<BaseDataObject>> loadAll, IndexKind? preferredKind)
    {
        if (string.IsNullOrWhiteSpace(queryText))
            return Array.Empty<string>();

        EnsureBuilt(type, loadAll);
        var index = _indexes.GetOrAdd(type, LoadIndex);
        var metadata = GetOrCreateTypeMetadata(type);
        
        // Determine which index to use
        var useKind = preferredKind ?? (metadata.IndexKinds.FirstOrDefault());
        
        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        lock (index.Sync)
        {
            // Use Span-based tokenization for zero allocations during query parsing
            TokenizeToHashSet(queryText, out var queryTokens);
            if (queryTokens.Count == 0)
                return Array.Empty<string>();

            // Search using the appropriate index type
            foreach (var queryToken in queryTokens)
            {
                IEnumerable<string> tokenResults;
                
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

    private IEnumerable<string> SearchInverted(IndexData index, string queryToken)
    {
        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        // Check for exact match first (fastest path)
        if (index.Tokens.TryGetValue(queryToken, out var exactIds))
        {
            foreach (var id in exactIds)
                results.Add(id);
            return results;
        }

        // Use prefix tree for substring matching if available
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
            if (version != 1)
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
                var ids = new HashSet<string>(idsCount, StringComparer.OrdinalIgnoreCase);
                for (int j = 0; j < idsCount; j++)
                {
                    ids.Add(reader.ReadString());
                }
                index.Tokens[token] = ids;
            }

            // Read IdToTokens dictionary
            var idToTokensCount = reader.ReadInt32();
            for (int i = 0; i < idToTokensCount; i++)
            {
                var id = reader.ReadString();
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
                writer.Write(1);

                // Write Tokens dictionary
                writer.Write(index.Tokens.Count);
                foreach (var entry in index.Tokens)
                {
                    writer.Write(entry.Key);
                    writer.Write(entry.Value.Count);
                    foreach (var id in entry.Value)
                    {
                        writer.Write(id);
                    }
                }

                // Write IdToTokens dictionary
                writer.Write(index.IdToTokens.Count);
                foreach (var entry in index.IdToTokens)
                {
                    writer.Write(entry.Key);
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
        
        // Get metadata to determine which index types to build
        var firstObj = loadAll().FirstOrDefault();
        if (firstObj == null)
            return;
        
        var metadata = GetOrCreateTypeMetadata(firstObj.GetType());
        
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
        
        foreach (var obj in loadAll())
        {
            if (obj == null || string.IsNullOrWhiteSpace(obj.Id))
                continue;

            var tokens = BuildTokens(obj, index);
            if (tokens.Count == 0)
                continue;

            index.IdToTokens[obj.Id] = tokens;
            foreach (var token in tokens)
            {
                // Build inverted index
                if (!index.Tokens.TryGetValue(token, out var ids))
                {
                    ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    index.Tokens[token] = ids;
                }
                ids.Add(obj.Id);
                AddToPrefixTree(index, token);
                
                // Build other index types
                if (metadata.IndexKinds.Contains(IndexKind.BTree))
                    AddToBTree(index, token, obj.Id);
                
                if (metadata.IndexKinds.Contains(IndexKind.Treap))
                    AddToTreap(index, token, obj.Id);
                
                if (metadata.IndexKinds.Contains(IndexKind.Bloom))
                    AddToBloomFilter(index, token, obj.Id);
            }
        }
    }

    private HashSet<string> BuildTokens(BaseDataObject obj, IndexData index)
    {
        var tokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var type = obj.GetType();
        var metadata = GetOrCreateTypeMetadata(type);

        for (int i = 0; i < metadata.IndexedProperties.Length; i++)
        {
            var prop = metadata.IndexedProperties[i];
            var attr = metadata.Attributes[i];

            var value = prop.GetValue(obj);
            if (value == null)
                continue;

            var valueType = Nullable.GetUnderlyingType(prop.PropertyType) ?? prop.PropertyType;
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

    private void RemoveObjectInternal(IndexData index, string id, TypeMetadata metadata)
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
                    var minPrefixLen = Math.Min(3, token.Length);
                    for (int len = minPrefixLen; len <= token.Length; len++)
                    {
                        var prefix = token.Substring(0, len);
                        if (index.PrefixTree.TryGetValue(prefix, out var fullTokens))
                        {
                            fullTokens.Remove(token);
                            if (fullTokens.Count == 0)
                                index.PrefixTree.Remove(prefix);
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
        tokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        if (value.IsEmpty)
            return;

        // Use stack-allocated buffer for tokens up to 256 chars
        // For longer tokens, we'll fall back to slower path with array rental
        const int MaxStackTokenSize = 256;
        Span<char> buffer = stackalloc char[MaxStackTokenSize];
        int bufferPos = 0;
        List<char>? overflowBuffer = null;

        for (int i = 0; i < value.Length; i++)
        {
            var ch = value[i];
            
            if (char.IsLetterOrDigit(ch))
            {
                var lowerCh = char.ToLowerInvariant(ch);
                
                if (bufferPos < MaxStackTokenSize)
                {
                    buffer[bufferPos++] = lowerCh;
                }
                else
                {
                    // Rare case: token exceeds stack buffer, switch to heap allocation
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
                    tokens.Add(new string(overflowBuffer.ToArray()));
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
                tokens.Add(new string(overflowBuffer.ToArray()));
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
            index.BTreeTokens = new SortedDictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
    }

    private void AddToBTree(IndexData index, string token, string id)
    {
        InitializeBTreeIndex(index);
        if (!index.BTreeTokens!.TryGetValue(token, out var ids))
        {
            ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            index.BTreeTokens[token] = ids;
        }
        ids.Add(id);
    }

    private void RemoveFromBTree(IndexData index, string token, string id)
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

    private IEnumerable<string> SearchBTree(IndexData index, string queryToken)
    {
        if (index.BTreeTokens == null)
            return Array.Empty<string>();

        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
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
            index.TreapTokenToIds = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
    }

    private void AddToTreap(IndexData index, string token, string id)
    {
        InitializeTreapIndex(index);
        
        if (!index.TreapTokenToIds!.TryGetValue(token, out var ids))
        {
            ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
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

    private void RemoveFromTreap(IndexData index, string token, string id)
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

    private IEnumerable<string> SearchTreap(IndexData index, string queryToken)
    {
        if (index.TreapTokenToIds == null)
            return Array.Empty<string>();

        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
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

    private void TreapSearch(TreapNode? node, string queryToken, Dictionary<string, HashSet<string>> tokenToIds, HashSet<string> results)
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

    private void AddToBloomFilter(IndexData index, string token, string id)
    {
        InitializeBloomFilter(index);
        
        var bloom = index.BloomFilter!;
        
        // Add to bloom filter bits
        for (int i = 0; i < bloom.HashCount; i++)
        {
            var hash = ComputeBloomHash(token, i, bloom.Size);
            bloom.Bits[hash] = true;
        }
        
        // Store in backing dictionary for retrieval
        if (!bloom.TokenToIds.TryGetValue(token, out var ids))
        {
            ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bloom.TokenToIds[token] = ids;
        }
        ids.Add(id);
    }

    private int ComputeBloomHash(string token, int hashIndex, int size)
    {
        // Use a simple but effective hash combining the token and hash index
        var baseHash = token.ToLowerInvariant().GetHashCode();
        var hash = ((baseHash ^ (hashIndex * 0x9e3779b9)) & 0x7FFFFFFF); // Mix with golden ratio, ensure positive
        return (int)(hash % size);
    }

    private void RemoveFromBloomFilter(IndexData index, string token, string id)
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

    private IEnumerable<string> SearchBloomFilter(IndexData index, string queryToken)
    {
        if (index.BloomFilter == null)
            return Array.Empty<string>();

        var bloom = index.BloomFilter;
        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        // Check if token might be in the bloom filter
        bool mightExist = true;
        for (int i = 0; i < bloom.HashCount; i++)
        {
            var hash = ComputeBloomHash(queryToken, i, bloom.Size);
            if (!bloom.Bits[hash])
            {
                mightExist = false;
                break;
            }
        }
        
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
}
