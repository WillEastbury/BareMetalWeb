using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.Json;
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
    private sealed class IndexData
    {
        public object Sync { get; } = new();
        public bool IsBuilt { get; set; }
        public Dictionary<string, HashSet<string>> Tokens { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, HashSet<string>> IdToTokens { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> WarnedKinds { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class IndexFile
    {
        public Dictionary<string, string[]> Tokens { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string[]> IdToTokens { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private readonly string _indexRoot;
    private readonly IBufferedLogger? _logger;
    private readonly ConcurrentDictionary<Type, IndexData> _indexes = new();

    public SearchIndexManager(string rootPath, IBufferedLogger? logger)
    {
        _indexRoot = Path.Combine(rootPath, "indexes");
        Directory.CreateDirectory(_indexRoot);
        _logger = logger;
    }

    public bool HasIndexedFields(Type type, out List<PropertyInfo> fields)
    {
        fields = type
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.GetCustomAttribute<DataIndexAttribute>() != null)
            .ToList();

        return fields.Count > 0;
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
            }

            index.IsBuilt = true;
            SaveIndex(type, index);
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
        var queryTokens = Tokenize(queryText);
        if (queryTokens.Count == 0)
            return Array.Empty<string>();

        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        lock (index.Sync)
        {
            foreach (var queryToken in queryTokens)
            {
                foreach (var entry in index.Tokens)
                {
                    if (!entry.Key.Contains(queryToken, StringComparison.OrdinalIgnoreCase))
                        continue;

                    foreach (var id in entry.Value)
                        results.Add(id);
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
            var bytes = File.ReadAllBytes(path);
            var data = JsonSerializer.Deserialize<IndexFile>(bytes);
            if (data != null)
            {
                foreach (var entry in data.Tokens)
                    index.Tokens[entry.Key] = new HashSet<string>(entry.Value ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
                foreach (var entry in data.IdToTokens)
                    index.IdToTokens[entry.Key] = new HashSet<string>(entry.Value ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
                index.IsBuilt = true;
            }
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
            var data = new IndexFile
            {
                Tokens = index.Tokens.ToDictionary(k => k.Key, v => v.Value.ToArray(), StringComparer.OrdinalIgnoreCase),
                IdToTokens = index.IdToTokens.ToDictionary(k => k.Key, v => v.Value.ToArray(), StringComparer.OrdinalIgnoreCase)
            };

            var bytes = JsonSerializer.SerializeToUtf8Bytes(data);
            File.WriteAllBytes(GetIndexPath(type), bytes);
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
            }
        }
    }

    private HashSet<string> BuildTokens(BaseDataObject obj, IndexData index)
    {
        var tokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var type = obj.GetType();
        var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.GetCustomAttribute<DataIndexAttribute>() != null)
            .ToArray();

        foreach (var prop in properties)
        {
            var attr = prop.GetCustomAttribute<DataIndexAttribute>();
            if (attr == null)
                continue;

            if (attr.Kind != IndexKind.Inverted)
            {
                var warningKey = $"{type.FullName}:{prop.Name}:{attr.Kind}";
                var shouldLog = false;
                // Protect shared warning set from concurrent tokenization.
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
                AddTokens(tokens, value.ToString());
                continue;
            }

            if (IsIntegralType(valueType))
            {
                tokens.Add(Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty);
                continue;
            }

            if (value is IEnumerable<string> stringList)
            {
                foreach (var item in stringList)
                    AddTokens(tokens, item);
                continue;
            }

            if (value is IEnumerable enumerable && value is not string)
            {
                foreach (var item in enumerable)
                    AddTokens(tokens, item?.ToString());
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
                index.Tokens.Remove(token);
        }

        index.IdToTokens.Remove(id);
    }

    private static void AddTokens(HashSet<string> tokens, string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return;

        foreach (var token in Tokenize(value))
            tokens.Add(token);
    }

    private static HashSet<string> Tokenize(string value)
    {
        var tokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var buffer = new List<char>();

        foreach (var ch in value)
        {
            if (char.IsLetterOrDigit(ch))
            {
                buffer.Add(char.ToLowerInvariant(ch));
                continue;
            }

            if (buffer.Count > 0)
            {
                tokens.Add(new string(buffer.ToArray()));
                buffer.Clear();
            }
        }

        if (buffer.Count > 0)
            tokens.Add(new string(buffer.ToArray()));

        return tokens;
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
        => Path.Combine(_indexRoot, $"{type.Name}.json");
}
