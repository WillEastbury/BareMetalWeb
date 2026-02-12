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

            foreach (var prop in props)
            {
                var attr = prop.GetCustomAttribute<DataIndexAttribute>();
                if (attr != null)
                {
                    indexedProps.Add(prop);
                    attrs.Add(attr);
                }
            }

            return new TypeMetadata
            {
                IndexedProperties = indexedProps.ToArray(),
                Attributes = attrs.ToArray()
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
        var tokens = BuildTokens(obj, index);

        lock (index.Sync)
        {
            RemoveObjectInternal(index, obj.Id);
            if (tokens.Count == 0)
            {
                index.IsBuilt = true;
                SaveIndex(type, index);
                return;
            }

            index.IdToTokens[obj.Id] = tokens;
            foreach (var token in tokens)
            {
                if (!index.Tokens.TryGetValue(token, out var ids))
                {
                    ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    index.Tokens[token] = ids;
                }
                ids.Add(obj.Id);

                // Build prefix tree for efficient prefix matching
                AddToPrefixTree(index, token);
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
        var index = _indexes.GetOrAdd(type, LoadIndex);
        lock (index.Sync)
        {
            RemoveObjectInternal(index, obj.Id);
            SaveIndex(type, index);
        }
    }

    public IReadOnlyCollection<string> Search(Type type, string queryText, Func<IEnumerable<BaseDataObject>> loadAll)
    {
        if (string.IsNullOrWhiteSpace(queryText))
            return Array.Empty<string>();

        EnsureBuilt(type, loadAll);
        var index = _indexes.GetOrAdd(type, LoadIndex);
        
        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        lock (index.Sync)
        {
            // Use Span-based tokenization for zero allocations during query parsing
            TokenizeToHashSet(queryText, out var queryTokens);
            if (queryTokens.Count == 0)
                return Array.Empty<string>();

            // Efficient search using inverted index with prefix optimization
            foreach (var queryToken in queryTokens)
            {
                // Check for exact match first (fastest path)
                if (index.Tokens.TryGetValue(queryToken, out var exactIds))
                {
                    foreach (var id in exactIds)
                        results.Add(id);
                    continue;
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
                    continue;
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
                _logger?.LogError($"Unknown index version {version} for {type.Name}.", new InvalidDataException($"Version {version}"));
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

            // Atomic replace
            if (File.Exists(path))
                File.Delete(path);
            File.Move(tempPath, path);
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
                if (!index.Tokens.TryGetValue(token, out var ids))
                {
                    ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    index.Tokens[token] = ids;
                }
                ids.Add(obj.Id);

                // Build prefix tree
                AddToPrefixTree(index, token);
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

            if (attr.Kind != IndexKind.Inverted)
            {
                var warningKey = $"{type.FullName}:{prop.Name}:{attr.Kind}";
                var shouldLog = false;
                lock (index.WarnedKinds)
                {
                    if (index.WarnedKinds.Add(warningKey))
                        shouldLog = true;
                }

                if (shouldLog)
                    _logger?.LogInfo($"Index kind {attr.Kind} not implemented; using inverted index for {type.Name}.{prop.Name}.");
            }

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

    private static void RemoveObjectInternal(IndexData index, string id)
    {
        if (!index.IdToTokens.TryGetValue(id, out var tokens))
            return;

        foreach (var token in tokens)
        {
            if (!index.Tokens.TryGetValue(token, out var ids))
                continue;

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
        Span<char> buffer = stackalloc char[256];
        int bufferPos = 0;

        for (int i = 0; i < value.Length; i++)
        {
            var ch = value[i];
            
            if (char.IsLetterOrDigit(ch))
            {
                if (bufferPos < buffer.Length)
                {
                    buffer[bufferPos++] = char.ToLowerInvariant(ch);
                }
                // If token exceeds buffer, we'll truncate it (rare case)
                continue;
            }

            // End of token - flush buffer
            if (bufferPos > 0)
            {
                tokens.Add(new string(buffer.Slice(0, bufferPos)));
                bufferPos = 0;
            }
        }

        // Flush final token if any
        if (bufferPos > 0)
        {
            tokens.Add(new string(buffer.Slice(0, bufferPos)));
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
}
