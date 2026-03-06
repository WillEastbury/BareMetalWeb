using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;

using System.Reflection;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

public sealed class LocalFolderBinaryDataProvider : IDataProvider
{
    private const string DefaultIndexFolderName = "Index";
    private const string DefaultIndexLogExtension = ".log";
    private const string DefaultIndexSnapshotExtension = ".snap";
    private const string DefaultIndexTempExtension = ".tmp";
    private const string DefaultPagedFolderName = "Paged";
    private const string DefaultPagedFileExtension = ".page";
    private const string DataPagedFilePrefix = "data_";
    private const int DefaultDataPageSize = 4096;
    private const int DataLengthPrefixSize = 4;
    private const string ClusteredIndexFieldName = "_clustered";
    private const int ClusteredPageSize = 16384;
    private readonly string _rootPath;
    private readonly ISchemaAwareObjectSerializer _serializer;
    private readonly IDataQueryEvaluator _queryEvaluator;
    private readonly IBufferedLogger? _logger;
    private IndexStore _indexStore;
    private SearchIndexManager _searchIndexManager;
    private readonly ConcurrentDictionary<string, ClusteredPagedObjectStore> _clusteredStores = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, string>> _clusteredLocationMaps = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<Type, SchemaCache> _schemaCache = new();
    private readonly ConcurrentDictionary<Type, object> _schemaLocks = new();
    private readonly ConcurrentDictionary<string, SeqIdRange> _seqIdRanges = new(StringComparer.OrdinalIgnoreCase);
    private const int SeqIdBatchSize = 64;
    private readonly ConcurrentDictionary<(Type, int), MemberSignature[]> _schemaMemberCache = new();

    private sealed class SchemaCache
    {
        public int CurrentVersion { get; set; }
        public Dictionary<int, SchemaDefinitionFile> Versions { get; } = new();
        public Dictionary<uint, int> HashToVersion { get; } = new();
    }

    public LocalFolderBinaryDataProvider(string rootPath, ISchemaAwareObjectSerializer? serializer = null, IDataQueryEvaluator? queryEvaluator = null, IBufferedLogger? logger = null)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
            throw new ArgumentException("Root path cannot be null or whitespace.", nameof(rootPath));

        _rootPath = rootPath;
        _serializer = serializer ?? BinaryObjectSerializer.CreateDefault(rootPath);
        _queryEvaluator = queryEvaluator ?? new DataQueryEvaluator();
        _logger = logger;
        _indexStore = new IndexStore(this, logger!);
        _searchIndexManager = new SearchIndexManager(rootPath, logger);
        Directory.CreateDirectory(_rootPath);
    }

    public string Name => "LocalFolderBinary";

    public string IndexRootPath => _rootPath;

    public string IndexFolderName => DefaultIndexFolderName;

    public string IndexLogExtension => DefaultIndexLogExtension;

    public string IndexSnapshotExtension => DefaultIndexSnapshotExtension;

    public string IndexTempExtension => DefaultIndexTempExtension;

    public bool CanHandle(Type type) => true;

    public IDisposable AcquireIndexLock(string entityName, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(entityName))
            throw new ArgumentException("Entity name cannot be empty.", nameof(entityName));
        if (string.IsNullOrWhiteSpace(fieldName))
            throw new ArgumentException("Field name cannot be empty.", nameof(fieldName));

        var logPath = GetIndexLogPath(entityName, fieldName);
        Directory.CreateDirectory(Path.GetDirectoryName(logPath) ?? _rootPath);
        var lockPath = logPath + ".lock";

        // Retry with exponential backoff to handle transient lock contention
        const int maxRetries = 5;
        const int initialDelayMs = 10;
        
        for (int attempt = 0; attempt <= maxRetries; attempt++)
        {
            try
            {
                return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (attempt < maxRetries)
            {
                // Exponential backoff: 10ms, 20ms, 40ms, 80ms, 160ms
                var delayMs = initialDelayMs * (1 << attempt);
                Thread.Sleep(delayMs);
            }
        }

        // Final attempt without catching - let the exception propagate
        return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }

    public bool IndexFileExists(string entityName, string fieldName, IndexFileKind kind)
    {
        var path = GetIndexPath(entityName, fieldName, kind);
        return File.Exists(path);
    }

    public Stream OpenIndexRead(string entityName, string fieldName, IndexFileKind kind)
    {
        var path = GetIndexPath(entityName, fieldName, kind);
        return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
    }

    public Stream OpenIndexAppend(string entityName, string fieldName, IndexFileKind kind)
    {
        var path = GetIndexPath(entityName, fieldName, kind);
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? _rootPath);
        return new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.Read);
    }

    public Stream OpenIndexWriteTemp(string entityName, string fieldName, IndexFileKind kind, out string tempToken)
    {
        var targetPath = GetIndexPath(entityName, fieldName, kind);
        Directory.CreateDirectory(Path.GetDirectoryName(targetPath) ?? _rootPath);
        tempToken = targetPath + IndexTempExtension;
        return new FileStream(tempToken, FileMode.Create, FileAccess.Write, FileShare.None);
    }

    public void CommitIndexTemp(string entityName, string fieldName, IndexFileKind kind, string tempToken)
    {
        if (string.IsNullOrWhiteSpace(tempToken))
            throw new ArgumentException("Temp token cannot be empty.", nameof(tempToken));

        var targetPath = GetIndexPath(entityName, fieldName, kind);
        File.Move(tempToken, targetPath, overwrite: true);
    }

    public bool PagedFileExists(string entityName, string fileName)
    {
        var path = GetPagedFilePath(entityName, fileName);
        return File.Exists(path);
    }

    public IPagedFile OpenPagedFile(string entityName, string fileName, int pageSize, FileAccess access)
    {
        if (string.IsNullOrWhiteSpace(entityName))
            throw new ArgumentException("Entity name cannot be empty.", nameof(entityName));
        if (string.IsNullOrWhiteSpace(fileName))
            throw new ArgumentException("File name cannot be empty.", nameof(fileName));
        if (pageSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(pageSize), "Page size must be greater than zero.");

        var path = GetPagedFilePath(entityName, fileName);
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? _rootPath);

        var options = FileOptions.RandomAccess | FileOptions.Asynchronous;
        var exists = File.Exists(path);

        if (access == FileAccess.Read && !exists)
        {
            using (var initStream = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read, 4096, options))
            {
                using var initializer = new LocalPagedFile(initStream, pageSize);
                initializer.Flush();
            }
        }

        var fileShare = access == FileAccess.Read ? FileShare.ReadWrite : FileShare.Read;
        var stream = new FileStream(path, FileMode.OpenOrCreate, access, fileShare, 4096, options);
        return new LocalPagedFile(stream, pageSize);
    }

    public ValueTask DeletePagedFileAsync(string entityName, string fileName, CancellationToken cancellationToken = default)
    {
        var path = GetPagedFilePath(entityName, fileName);
        if (File.Exists(path))
            File.Delete(path);

        return ValueTask.CompletedTask;
    }

    public uint NextSequentialKey(string entityName)
    {
        if (string.IsNullOrWhiteSpace(entityName))
            throw new ArgumentException("Entity name cannot be empty.", nameof(entityName));

        var path = GetSeqIdFilePath(entityName);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var range = _seqIdRanges.GetOrAdd(entityName, _ => new SeqIdRange());
        return range.Next(path, SeqIdBatchSize);
    }

    public void SeedSequentialKey(string entityName, uint floor)
    {
        if (string.IsNullOrWhiteSpace(entityName))
            throw new ArgumentException("Entity name cannot be empty.", nameof(entityName));
        if (floor == 0)
            return;

        var path = GetSeqIdFilePath(entityName);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var range = _seqIdRanges.GetOrAdd(entityName, _ => new SeqIdRange());

        const int maxRetries = 4;
        const int initialDelayMs = 10;

        for (int attempt = 0; attempt < maxRetries; attempt++)
        {
            try
            {
                lock (range.SyncRoot) { SeedSeqKeyFileIfLower(path, floor); }
                range.Invalidate();
                return;
            }
            catch (IOException)
            {
                Thread.Sleep(initialDelayMs * (1 << attempt));
            }
        }

        lock (range.SyncRoot) { SeedSeqKeyFileIfLower(path, floor); }
        range.Invalidate();
    }

    /// <inheritdoc />
    public ValueTask WipeStorageAsync(CancellationToken cancellationToken = default)
    {
        // 1. Delete and recreate the entire data root so every artefact is removed:
        //    per-entity type folders (binary data files, schema JSON files, _seqid.dat),
        //    Index/ (secondary field indexes), indexes/ (search-index files), Paged/ (paged files).
        if (Directory.Exists(_rootPath))
            Directory.Delete(_rootPath, recursive: true);
        Directory.CreateDirectory(_rootPath);

        // 2. Clear all in-memory caches so the next access starts fresh.
        _schemaCache.Clear();
        _schemaLocks.Clear();
        _seqIdRanges.Clear();
        _clusteredStores.Clear();
        _clusteredLocationMaps.Clear();
        _schemaMemberCache.Clear();

        // 3. Reinitialise the secondary-index components.
        _indexStore         = new IndexStore(this, _logger!);
        _searchIndexManager = new SearchIndexManager(_rootPath, _logger);

        return ValueTask.CompletedTask;
    }

    private static uint AllocateBatch(string path, int batchSize)
    {
        Span<byte> buf = stackalloc byte[4];
        using var file = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        uint current = 0;
        if (file.Length >= 4)
        {
            file.ReadExactly(buf);
            current = BinaryPrimitives.ReadUInt32LittleEndian(buf);
        }
        var ceiling = current + (uint)batchSize;
        BinaryPrimitives.WriteUInt32LittleEndian(buf, ceiling);
        file.Position = 0;
        file.Write(buf);
        file.Flush(true);
        return current;
    }

    private static void SeedSeqKeyFileIfLower(string path, uint floor)
    {
        Span<byte> buf = stackalloc byte[4];
        using var file = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        uint current = 0;
        if (file.Length >= 4)
        {
            file.ReadExactly(buf);
            current = BinaryPrimitives.ReadUInt32LittleEndian(buf);
        }
        if (current < floor)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(buf, floor);
            file.Position = 0;
            file.Write(buf);
            file.Flush(true);
        }
    }

    private string GetSeqIdFilePath(string entityName)
    {
        return Path.Combine(_rootPath, SanitizeFilePart(entityName), "_seqid.dat");
    }

    private sealed class SeqIdRange
    {
        public readonly object SyncRoot = new();
        private uint _next;
        private uint _ceiling; // exclusive upper bound

        public uint Next(string path, int batchSize)
        {
            lock (SyncRoot)
            {
                if (_next < _ceiling)
                    return ++_next;

                // Exhausted — allocate a new batch from disk (single fsync).
                const int maxRetries = 4;
                const int initialDelayMs = 10;
                uint baseId = 0;

                for (int attempt = 0; attempt <= maxRetries; attempt++)
                {
                    try
                    {
                        baseId = AllocateBatch(path, batchSize);
                        break;
                    }
                    catch (IOException) when (attempt < maxRetries)
                    {
                        Thread.Sleep(initialDelayMs * (1 << attempt));
                    }
                }

                _next = baseId;
                _ceiling = baseId + (uint)batchSize;
                return ++_next;
            }
        }

        public void Invalidate()
        {
            lock (SyncRoot)
            {
                _next = 0;
                _ceiling = 0;
            }
        }
    }

    private string GetIndexLogPath(string entityName, string fieldName)
    {
        return GetIndexPath(entityName, fieldName, IndexFileKind.Log);
    }

    private string GetIndexPath(string entityName, string fieldName, IndexFileKind kind)
    {
        var folder = Path.Combine(IndexRootPath, IndexFolderName, SanitizeFilePart(entityName));
        var extension = kind == IndexFileKind.Snapshot ? IndexSnapshotExtension : IndexLogExtension;
        return Path.Combine(folder, SanitizeFilePart(fieldName) + extension);
    }

    private string GetPagedFilePath(string entityName, string fileName)
    {
        var folder = Path.Combine(_rootPath, DefaultPagedFolderName, SanitizeFilePart(entityName));
        return Path.Combine(folder, SanitizeFilePart(fileName) + DefaultPagedFileExtension);
    }

    private static string SanitizeFilePart(string value)
    {
        var name = value ?? string.Empty;
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name;
    }

    public void Save<T>(T obj) where T : BaseDataObject
    {
        if (obj is null) throw new ArgumentNullException(nameof(obj));
        if (obj.Key == 0)
            throw new ArgumentException("DataObject must have a non-zero Key.", nameof(obj));

        // Enforce singleton flag: when a boolean property marked [SingletonFlag] is true,
        // clear that flag on all other records of this type before saving.
        ClearSingletonFlagsOnOtherRecords(obj);

        var now = DateTime.UtcNow;
        if (obj.CreatedOnUtc == default)
            obj.CreatedOnUtc = now;
        obj.UpdatedOnUtc = now;
        obj.ETag = Guid.NewGuid().ToString("N");

        var type = typeof(T);
        var typeFolder = GetTypeFolder(type);
        Directory.CreateDirectory(typeFolder);

        var cache = LoadSchemaCache(type);
        var currentSchema = BuildSchemaFor(_serializer, type);
        int schemaVersion;
        lock (GetSchemaLock(type))
        {
            // Serialize schema cache updates per type to avoid version races.
            SchemaDefinitionFile? existing = null;
            if (cache.HashToVersion.TryGetValue(currentSchema.Hash, out var existingVersion))
                cache.Versions.TryGetValue(existingVersion, out existing);

            if (existing == null)
            {
                schemaVersion = 1;
                if (cache.Versions.Count > 0)
                {
                    var maxKey = int.MinValue;
                    foreach (var k in cache.Versions.Keys)
                    {
                        if (k > maxKey) maxKey = k;
                    }
                    schemaVersion = maxKey + 1;
                }
                var schemaFile = BuildSchemaFile(currentSchema, schemaVersion);
                cache.Versions[schemaVersion] = schemaFile;
                cache.HashToVersion[currentSchema.Hash] = schemaVersion;
                cache.CurrentVersion = schemaVersion;
                SaveSchemaFile(type, schemaFile);
                _logger?.LogInfo($"Schema updated for {type.Name}. New version {schemaVersion} (hash {currentSchema.Hash}).");
            }
            else
            {
                schemaVersion = existing.Version;
            }

            cache.CurrentVersion = schemaVersion;
        }

        try
        {
            var bytes = SerializeFor(_serializer, obj, schemaVersion);
            var store = GetClusteredStore(type.Name);
            var keyStr = obj.Key.ToString();

            // Load existing object only on updates (existing location found) to track previous indexed field values.
            // New inserts skip this load since there are no prior index entries to clean up.
            T? oldObj = null;
            List<PropertyInfo> indexedFields = new();
            if (_searchIndexManager.HasIndexedFields(type, out indexedFields) && TryGetClusteredLocation(type.Name, keyStr, out _))
                oldObj = Load<T>(obj.Key);

            var location = store.Write(keyStr, bytes);
            var map = GetClusteredLocationMap(type.Name);
            map.TryGetValue(keyStr, out var existingLocation);

            // Batch append operations to avoid lock contention
            var entries = new List<(string key, string id, char op, long? expiresAtUtcTicks)>
            {
                (keyStr, location, 'A', null)
            };

            if (!string.IsNullOrWhiteSpace(existingLocation)
                && !string.Equals(existingLocation, location, StringComparison.OrdinalIgnoreCase))
            {
                entries.Add((keyStr, existingLocation, 'D', null));
            }

            _indexStore.AppendEntries(type.Name, ClusteredIndexFieldName, entries, normalizeKey: false);
            map[keyStr] = location;

            if (!string.IsNullOrWhiteSpace(existingLocation)
                && !string.Equals(existingLocation, location, StringComparison.OrdinalIgnoreCase))
            {
                store.Delete(existingLocation);
            }

            // Update secondary field indexes and full-text search index
            if (indexedFields.Count > 0)
            {
                foreach (var prop in indexedFields)
                {
                    var newValue = prop.GetValue(obj)?.ToString() ?? string.Empty;
                    if (oldObj != null)
                    {
                        var oldValue = prop.GetValue(oldObj)?.ToString() ?? string.Empty;
                        if (string.Equals(oldValue, newValue, StringComparison.OrdinalIgnoreCase))
                            continue; // value unchanged — existing index entry is still valid
                        _indexStore.AppendEntry(type.Name, prop.Name, oldValue, keyStr, 'D');
                    }
                    _indexStore.AppendEntry(type.Name, prop.Name, newValue, keyStr, 'A');
                }
                _searchIndexManager.IndexObject(obj);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Serialization failed for {type.Name} with Key {obj.Key}.", ex);
            throw;
        }
    }

    public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        Save(obj);
        return ValueTask.CompletedTask;
    }

    private static readonly ConcurrentDictionary<Type, PropertyInfo[]> _singletonFlagPropsCache = new();

    /// <summary>
    /// For each boolean property on <paramref name="obj"/> decorated with <see cref="SingletonFlagAttribute"/>
    /// that is currently <c>true</c>, find all other persisted records of the same type and set that
    /// property to <c>false</c>, then persist the change. This enforces the invariant that at most one
    /// record in the set can hold the singleton flag at a time.
    /// </summary>
    private void ClearSingletonFlagsOnOtherRecords<T>(T obj) where T : BaseDataObject
    {
        var type = typeof(T);
        var candidateProps = _singletonFlagPropsCache.GetOrAdd(type, static t =>
        {
            var allProps = t.GetProperties(BindingFlags.Public | BindingFlags.Instance);
            var result = new List<PropertyInfo>();
            foreach (var p in allProps)
            {
                if (p.PropertyType == typeof(bool)
                    && p.GetCustomAttribute<SingletonFlagAttribute>() != null
                    && p.CanRead && p.CanWrite)
                {
                    result.Add(p);
                }
            }
            return result.ToArray();
        });

        var singletonProps = new List<PropertyInfo>();
        foreach (var p in candidateProps)
        {
            if (true.Equals(p.GetValue(obj)))
                singletonProps.Add(p);
        }

        if (singletonProps.Count == 0)
            return;

        // Only load all records if there is at least one active singleton flag.
        var allRecords = Query<T>();
        foreach (var record in allRecords)
        {
            if (record.Key == obj.Key)
                continue;

            bool changed = false;
            foreach (var prop in singletonProps)
            {
                if (true.Equals(prop.GetValue(record)))
                {
                    prop.SetValue(record, false);
                    changed = true;
                }
            }

            if (changed)
                Save(record);
        }
    }

    public T? Load<T>(uint key) where T : BaseDataObject
    {
        if (key == 0)
            throw new ArgumentException("Key cannot be zero.", nameof(key));

        var type = typeof(T);
        var keyStr = key.ToString();
        if (!TryGetClusteredLocation(type.Name, keyStr, out var location))
            return default;

        var store = GetClusteredStore(type.Name);
        var bytes = store.Read(location);
        if (bytes == null)
        {
            // Location may be stale: a concurrent Save may have moved the record to a new slot.
            // Evict the cache entry and retry once using the index store as the authoritative source.
            if (_clusteredLocationMaps.TryGetValue(type.Name, out var locationMap))
            {
                locationMap.TryRemove(keyStr, out _);
                bool foundFresh = _indexStore.TryGetLatestValue(type.Name, ClusteredIndexFieldName, keyStr, out var freshLocation, normalizeKey: false);
                bool isDifferentLocation = foundFresh
                    && !string.IsNullOrWhiteSpace(freshLocation)
                    && !string.Equals(freshLocation, location, StringComparison.OrdinalIgnoreCase);
                if (isDifferentLocation)
                {
                    bytes = store.Read(freshLocation);
                    if (bytes != null)
                        locationMap[keyStr] = freshLocation;
                }
            }
            if (bytes == null)
                return default;
        }

        try
        {
            var schemaVersion = _serializer.ReadSchemaVersion(bytes);
            var schemaFile = GetSchemaDefinition(type, schemaVersion);
            if (schemaFile == null)
            {
                _logger?.LogInfo($"Schema fallback for {type.Name} with Key {key}. Missing version {schemaVersion}; returning null.");
                return default;
            }

            var schemaMembers = GetCachedSchemaMembers(type, schemaFile);
            var schemaArchitecture = ParseArchitecture(schemaFile.Architecture);
            var schema = _serializer.CreateSchema(schemaFile.Version, schemaMembers, schemaArchitecture, schemaFile.Hash);

            return DeserializeFor<T>(_serializer, bytes, schema);
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Deserialization failed for {type.Name} with Key {key}.", ex);
            throw;
        }
    }

    public ValueTask<T?> LoadAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        return ValueTask.FromResult(Load<T>(key));
    }

    public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject
    {
        var type = typeof(T);
        if (!GetClusteredStore(type.Name).Exists())
            return Array.Empty<T>();

        var skip = query?.Skip ?? 0;
        var top = query?.Top ?? int.MaxValue;
        if (skip < 0)
            skip = 0;
        if (top <= 0)
            return Array.Empty<T>();

        // Index-accelerated path: use secondary field index for simple Equals clauses
        if (query != null && query.Clauses.Count > 0 && query.Groups.Count == 0
            && _searchIndexManager.HasIndexedFields(type, out var indexedFields))
        {
            foreach (var clause in query.Clauses)
            {
                if (clause.Operator == QueryOperator.Equals && clause.Value != null)
                {
                    var prop = indexedFields.Find(p => string.Equals(p.Name, clause.Field, StringComparison.OrdinalIgnoreCase));
                    if (prop != null)
                    {
                        var fieldValue = clause.Value.ToString() ?? string.Empty;
                        var fieldIndex = _indexStore.ReadIndex(type.Name, prop.Name);
                        if (fieldIndex.Count == 0)
                            break; // No index entries yet (empty store or index not yet populated); fall through to full scan

                        IEnumerable<T> candidates;
                        if (fieldIndex.TryGetValue(fieldValue, out var candidateIds))
                        {
                            var loaded = new List<T>(candidateIds.Count);
                            foreach (var candidateKey in candidateIds)
                            {
                                var obj = Load<T>(candidateKey);
                                if (obj != null)
                                    loaded.Add(obj);
                            }
                            candidates = loaded;
                        }
                        else
                        {
                            return Array.Empty<T>();
                        }

                        var filtered = new List<T>();
                        foreach (var item in candidates)
                        {
                            if (_queryEvaluator.Matches(item, query))
                                filtered.Add(item);
                        }
                        var sorted = _queryEvaluator.ApplySorts(filtered, query);
                        var resultList = new List<T>();
                        var skipped = 0;
                        var taken = 0;
                        foreach (var item in sorted)
                        {
                            if (skipped < skip) { skipped++; continue; }
                            resultList.Add(item);
                            taken++;
                            if (taken >= top) break;
                        }
                        return resultList;
                    }
                }
            }
        }

        var locations = GetClusteredLocationMap(type.Name);
        var canShortCircuit = query == null || query.Sorts.Count == 0;
        if (canShortCircuit)
        {
            var results = top == int.MaxValue ? new List<T>() : new List<T>(Math.Min(top, 256));
            var matched = 0;
            foreach (var entry in locations)
            {
                try
                {
                    var bytes = GetClusteredStore(type.Name).Read(entry.Value);
                    if (bytes == null)
                    {
                        locations.TryRemove(entry.Key, out _);
                        continue;
                    }

                    var schemaVersion = _serializer.ReadSchemaVersion(bytes);
                    var schemaFile = GetSchemaDefinition(type, schemaVersion);
                    if (schemaFile == null)
                    {
                        _logger?.LogInfo($"Schema fallback for {type.Name} while querying. Missing version {schemaVersion}; skipping paged item {entry.Key}.");
                        continue;
                    }

                    var schemaMembers = GetCachedSchemaMembers(type, schemaFile);
                    var schemaArchitecture = ParseArchitecture(schemaFile.Architecture);
                    var schema = _serializer.CreateSchema(schemaFile.Version, schemaMembers, schemaArchitecture, schemaFile.Hash);
                    var obj = DeserializeFor<T>(_serializer, bytes, schema);
                    if (obj == null)
                        continue;

                    if (!_queryEvaluator.Matches(obj, query))
                        continue;

                    if (matched < skip)
                    {
                        matched++;
                        continue;
                    }

                    results.Add(obj);
                    matched++;
                    if (results.Count >= top)
                        break;
                }
                catch (Exception ex)
                {
                    _logger?.LogError($"Deserialization failed for {type.Name} while querying clustered item {entry.Key}.", ex);
                }
            }

            return results;
        }

        var all = new List<T>();
        foreach (var entry in locations)
        {
            try
            {
                var bytes = GetClusteredStore(type.Name).Read(entry.Value);
                if (bytes == null)
                {
                    locations.TryRemove(entry.Key, out _);
                    continue;
                }

                var schemaVersion = _serializer.ReadSchemaVersion(bytes);
                var schemaFile = GetSchemaDefinition(type, schemaVersion);
                if (schemaFile == null)
                {
                    _logger?.LogInfo($"Schema fallback for {type.Name} while querying. Missing version {schemaVersion}; skipping paged item {entry.Key}.");
                    continue;
                }

                var schemaMembers = GetCachedSchemaMembers(type, schemaFile);
                var schemaArchitecture = ParseArchitecture(schemaFile.Architecture);
                var schema = _serializer.CreateSchema(schemaFile.Version, schemaMembers, schemaArchitecture, schemaFile.Hash);
                var obj = DeserializeFor<T>(_serializer, bytes, schema);
                if (obj != null)
                    all.Add(obj);
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Deserialization failed for {type.Name} while querying clustered item {entry.Key}.", ex);
            }
        }

        var filteredAll = new List<T>();
        foreach (var item in all)
        {
            if (_queryEvaluator.Matches(item, query))
                filteredAll.Add(item);
        }
        var sortedAll = _queryEvaluator.ApplySorts(filteredAll, query);
        var resultAll = new List<T>();
        var skippedAll = 0;
        var takenAll = 0;
        foreach (var item in sortedAll)
        {
            if (skippedAll < skip) { skippedAll++; continue; }
            resultAll.Add(item);
            takenAll++;
            if (takenAll >= top) break;
        }
        return resultAll;
    }

    public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        return ValueTask.FromResult(Query<T>(query));
    }

    public int Count<T>(QueryDefinition? query = null) where T : BaseDataObject
    {
        var type = typeof(T);
        if (!GetClusteredStore(type.Name).Exists())
            return 0;

        var locations = GetClusteredLocationMap(type.Name);
        if (query == null || (query.Clauses.Count == 0 && query.Groups.Count == 0))
            return locations.Count;

        var count = 0;
        foreach (var entry in locations)
        {
            try
            {
                var bytes = GetClusteredStore(type.Name).Read(entry.Value);
                if (bytes == null)
                    continue;

                var schemaVersion = _serializer.ReadSchemaVersion(bytes);
                var schemaFile = GetSchemaDefinition(type, schemaVersion);
                if (schemaFile == null)
                {
                    _logger?.LogInfo($"Schema fallback for {type.Name} while counting. Missing version {schemaVersion}; skipping paged item {entry.Key}.");
                    continue;
                }

                var schemaMembers = GetCachedSchemaMembers(type, schemaFile);
                var schemaArchitecture = ParseArchitecture(schemaFile.Architecture);
                var schema = _serializer.CreateSchema(schemaFile.Version, schemaMembers, schemaArchitecture, schemaFile.Hash);
                var obj = DeserializeFor<T>(_serializer, bytes, schema);
                if (obj != null && _queryEvaluator.Matches(obj, query))
                    count++;
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Deserialization failed for {type.Name} while counting clustered item {entry.Key}.", ex);
            }
        }

        return count;
    }

    public ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        return ValueTask.FromResult(Count<T>(query));
    }

    public void Delete<T>(uint key) where T : BaseDataObject
    {
        if (key == 0)
            throw new ArgumentException("Key cannot be zero.", nameof(key));

        var type = typeof(T);
        var keyStr = key.ToString();
        if (TryGetClusteredLocation(type.Name, keyStr, out var location))
        {
            // Load old object for field index cleanup before deleting
            T? oldObj = null;
            List<PropertyInfo> indexedFields = new();
            if (_searchIndexManager.HasIndexedFields(type, out indexedFields))
                oldObj = Load<T>(key);

            var store = GetClusteredStore(type.Name);
            store.Delete(location);
            _indexStore.AppendEntry(type.Name, ClusteredIndexFieldName, keyStr, location, 'D', normalizeKey: false);
            if (_clusteredLocationMaps.TryGetValue(type.Name, out var map))
                map.TryRemove(keyStr, out _);

            // Remove from secondary field indexes and full-text search index
            if (indexedFields.Count > 0 && oldObj != null)
            {
                foreach (var prop in indexedFields)
                {
                    var value = prop.GetValue(oldObj)?.ToString() ?? string.Empty;
                    _indexStore.AppendEntry(type.Name, prop.Name, value, keyStr, 'D');
                }
                _searchIndexManager.RemoveObject(type, key);
            }
        }
    }

    public ValueTask DeleteAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        Delete<T>(key);
        return ValueTask.CompletedTask;
    }

    public void CompactClusteredEntity<T>() where T : BaseDataObject
    {
        CompactClusteredEntityCore(typeof(T).Name);
    }

    public void CompactClusteredEntity(Type type)
    {
        if (type == null)
            throw new ArgumentNullException(nameof(type));
        if (!typeof(BaseDataObject).IsAssignableFrom(type))
            throw new ArgumentException("Type must derive from BaseDataObject.", nameof(type));

        CompactClusteredEntityCore(type.Name);
    }

    private void CompactClusteredEntityCore(string entityName)
    {
        var map = GetClusteredLocationMap(entityName);
        if (map.Count == 0)
            return;

        var store = GetClusteredStore(entityName);
        var newMap = store.Compact(map);
        foreach (var entry in map)
            _indexStore.AppendEntry(entityName, ClusteredIndexFieldName, entry.Key, entry.Value, 'D', normalizeKey: false);
        foreach (var entry in newMap)
            _indexStore.AppendEntry(entityName, ClusteredIndexFieldName, entry.Key, entry.Value, 'A', normalizeKey: false);

        map.Clear();
        foreach (var entry in newMap)
            map[entry.Key] = entry.Value;
    }

    private ClusteredPagedObjectStore GetClusteredStore(string entityName)
    {
        return _clusteredStores.GetOrAdd(entityName, name => new ClusteredPagedObjectStore(this, name, ClusteredPageSize, _logger));
    }

    private ConcurrentDictionary<string, string> GetClusteredLocationMap(string entityName)
    {
        return _clusteredLocationMaps.GetOrAdd(entityName, name => new ConcurrentDictionary<string, string>(
            _indexStore.ReadLatestValueIndex(name, ClusteredIndexFieldName, normalizeKey: false),
            StringComparer.OrdinalIgnoreCase));
    }

    private bool TryGetClusteredLocation(string entityName, string id, out string location)
    {
        location = string.Empty;
        var map = GetClusteredLocationMap(entityName);
        if (map.TryGetValue(id, out var tempLocation))
        {
            location = tempLocation;
            return true;
        }

        if (_indexStore.TryGetLatestValue(entityName, ClusteredIndexFieldName, id, out location, normalizeKey: false)
            && !string.IsNullOrWhiteSpace(location))
        {
            map[id] = location;
            return true;
        }

        return false;
    }

    private string GetTypeFolder(Type type) => Path.Combine(_rootPath, type.Name);

    private string GetFilePath(Type type, uint key) => Path.Combine(GetTypeFolder(type), $"{key}.bin");

    private string GetPagedEntityFolder(string entityName)
        => Path.Combine(_rootPath, DefaultPagedFolderName, SanitizeFilePart(entityName));

    private static bool TryParseDataPagedFileName(string baseName, out string id)
    {
        id = string.Empty;
        if (string.IsNullOrWhiteSpace(baseName))
            return false;
        if (!baseName.StartsWith(DataPagedFilePrefix, StringComparison.OrdinalIgnoreCase))
            return false;

        id = baseName.Substring(DataPagedFilePrefix.Length);
        return !string.IsNullOrWhiteSpace(id);
    }

    private IEnumerable<string> EnumeratePagedDataIds(Type type)
    {
        var folder = GetPagedEntityFolder(type.Name);
        if (!Directory.Exists(folder))
            yield break;

        var pattern = $"{DataPagedFilePrefix}*{DefaultPagedFileExtension}";
        foreach (var file in Directory.EnumerateFiles(folder, pattern, SearchOption.TopDirectoryOnly))
        {
            var baseName = Path.GetFileNameWithoutExtension(file);
            if (TryParseDataPagedFileName(baseName, out var id))
                yield return id;
        }
    }

    private byte[]? ReadPagedPayload(string entityName, string fileName)
    {
        if (!PagedFileExists(entityName, fileName))
            return null;

        using var pagedFile = OpenPagedFile(entityName, fileName, DefaultDataPageSize, FileAccess.Read);
        var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
        try
        {
            var bytesRead = pagedFile.ReadPage(0, buffer);
            if (bytesRead == 0)
                return Array.Empty<byte>();

            var span = buffer.AsSpan(0, pagedFile.PageSize);
            var length = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(0, DataLengthPrefixSize));
            if (length < 0)
                return Array.Empty<byte>();

            var result = new byte[length];
            var offset = 0;
            var firstCopy = Math.Min(length, pagedFile.PageSize - DataLengthPrefixSize);
            if (firstCopy > 0)
            {
                span.Slice(DataLengthPrefixSize, firstCopy).CopyTo(result);
                offset = firstCopy;
            }

            var pageIndex = 1L;
            while (offset < length)
            {
                pagedFile.ReadPage(pageIndex++, buffer);
                var toCopy = Math.Min(length - offset, pagedFile.PageSize);
                buffer.AsSpan(0, toCopy).CopyTo(result.AsSpan(offset, toCopy));
                offset += toCopy;
            }

            return result;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private void WritePagedPayload(string entityName, string fileName, ReadOnlySpan<byte> payload)
    {
        using var pagedFile = OpenPagedFile(entityName, fileName, DefaultDataPageSize, FileAccess.ReadWrite);
        var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
        try
        {
            var totalLength = payload.Length;
            var totalBytes = totalLength + DataLengthPrefixSize;
            var pageCount = (totalBytes + pagedFile.PageSize - 1) / pagedFile.PageSize;

            var offset = 0;
            for (long pageIndex = 0; pageIndex < pageCount; pageIndex++)
            {
                var span = buffer.AsSpan(0, pagedFile.PageSize);
                span.Clear();

                if (pageIndex == 0)
                {
                    BinaryPrimitives.WriteInt32LittleEndian(span.Slice(0, DataLengthPrefixSize), totalLength);
                    var firstCopy = Math.Min(totalLength, pagedFile.PageSize - DataLengthPrefixSize);
                    if (firstCopy > 0)
                    {
                        payload.Slice(0, firstCopy).CopyTo(span.Slice(DataLengthPrefixSize, firstCopy));
                        offset = firstCopy;
                    }
                }
                else
                {
                    var remaining = totalLength - offset;
                    var toCopy = Math.Min(remaining, pagedFile.PageSize);
                    if (toCopy > 0)
                    {
                        payload.Slice(offset, toCopy).CopyTo(span.Slice(0, toCopy));
                        offset += toCopy;
                    }
                }

                pagedFile.WritePage(pageIndex, span);
            }

            pagedFile.Flush();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private string GetSchemaFilePath(Type type, int version)
        => Path.Combine(GetTypeFolder(type), $"schema-{type.Name}-{version}.json");

    private string GetSchemaFilePattern(Type type)
        => $"schema-{type.Name}-*.json";

    private SchemaCache LoadSchemaCache(Type type)
        => _schemaCache.GetOrAdd(type, LoadSchemaCacheCore);

    private SchemaCache LoadSchemaCacheCore(Type type)
    {
        var cache = new SchemaCache();
        var typeFolder = GetTypeFolder(type);
        Directory.CreateDirectory(typeFolder);

        foreach (var file in Directory.EnumerateFiles(typeFolder, GetSchemaFilePattern(type), SearchOption.TopDirectoryOnly))
        {
            if (!TryParseSchemaVersion(type, Path.GetFileName(file), out var version))
                continue;

            var schemaFile = LoadSchemaFile(file);
            if (schemaFile == null)
                continue;

            schemaFile.Version = version;
            cache.Versions[version] = schemaFile;
            cache.HashToVersion[schemaFile.Hash] = version;
        }

        if (cache.Versions.Count > 0)
        {
            var maxVer = int.MinValue;
            foreach (var k in cache.Versions.Keys)
            {
                if (k > maxVer) maxVer = k;
            }
            cache.CurrentVersion = maxVer;
        }

        return cache;
    }

    private SchemaDefinitionFile? GetSchemaDefinition(Type type, int version)
    {
        var cache = _schemaCache.GetOrAdd(type, LoadSchemaCacheCore);
        lock (GetSchemaLock(type))
        {
            if (cache.Versions.TryGetValue(version, out var cached))
                return cached;
        }

        var filePath = GetSchemaFilePath(type, version);
        if (!File.Exists(filePath))
            return null;

        var schemaFile = LoadSchemaFile(filePath);
        if (schemaFile == null)
            return null;

        schemaFile.Version = version;
        lock (GetSchemaLock(type))
        {
            cache.Versions[version] = schemaFile;
            cache.HashToVersion[schemaFile.Hash] = version;
        }

        return schemaFile;
    }

    private SchemaDefinitionFile? LoadSchemaFile(string path)
    {
        try
        {
            var bytes = File.ReadAllBytes(path);
            return JsonSerializer.Deserialize(bytes, BmwDataJsonContext.Default.SchemaDefinitionFile);
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Schema definition load failed for {Path.GetFileName(path)}.", ex);
            return null;
        }
    }

    private void SaveSchemaFile(Type type, SchemaDefinitionFile schema)
    {
        var path = GetSchemaFilePath(type, schema.Version);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(schema, BmwDataJsonContext.Default.SchemaDefinitionFile);
        File.WriteAllBytes(path, bytes);
    }

    private static SchemaDefinitionFile BuildSchemaFile(SchemaDefinition schema, int version)
    {
        var members = new List<MemberSignatureFile>(schema.Members.Length);
        foreach (var m in schema.Members)
        {
            members.Add(new MemberSignatureFile { Name = m.Name, TypeName = m.TypeName, BlittableSize = m.BlittableSize });
        }
        return new SchemaDefinitionFile
        {
            Version = version,
            Hash = schema.Hash,
            Architecture = schema.Architecture.ToString(),
            Members = members
        };
    }

    private static bool TryParseSchemaVersion(Type type, string fileName, out int version)
    {
        version = 0;
        var prefix = $"schema-{type.Name}-";
        if (!fileName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || !fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            return false;

        var numberSpan = fileName.Substring(prefix.Length, fileName.Length - prefix.Length - ".json".Length);
        return int.TryParse(numberSpan, out version) && version > 0;
    }

    private object GetSchemaLock(Type type)
        => _schemaLocks.GetOrAdd(type, _ => new object());

    private static BinaryArchitecture ParseArchitecture(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return BinaryArchitecture.Unknown;

        return Enum.TryParse<BinaryArchitecture>(value, ignoreCase: true, out var result)
            ? result
            : BinaryArchitecture.Unknown;
    }

    private static Type AssumePublicMembers(Type type) => type;

    private MemberSignature[] GetCachedSchemaMembers(Type type, SchemaDefinitionFile schemaFile)
        => _schemaMemberCache.GetOrAdd((type, schemaFile.Version), _ =>
        {
            var members = schemaFile.Members;
            var result = new MemberSignature[members.Count];
            for (var i = 0; i < members.Count; i++)
            {
                var m = members[i];
                result[i] = new MemberSignature(m.Name, m.TypeName, AssumePublicMembers(_serializer.ResolveTypeName(m.TypeName)), m.BlittableSize);
            }
            return result;
        });

    private static SchemaDefinition BuildSchemaFor(ISchemaAwareObjectSerializer serializer, Type type)
        => serializer.BuildSchema(type);

    private static byte[] SerializeFor<T>(ISchemaAwareObjectSerializer serializer, T obj, int schemaVersion)
        => serializer.Serialize(obj, schemaVersion);

    private static T? DeserializeFor<T>(ISchemaAwareObjectSerializer serializer, byte[] bytes, SchemaDefinition schema)
    {
        // Use BestEffort mode to support schema evolution: records saved before a field was added or
        // removed will still load correctly, with missing fields receiving their default values.
        if (serializer is BinaryObjectSerializer binarySerializer)
            return binarySerializer.Deserialize<T>(bytes, schema, SchemaReadMode.BestEffort);
        return serializer.Deserialize<T>(bytes, schema);
    }

    // LocalPagedFile is now a shared internal class in LocalPagedFile.cs
}


