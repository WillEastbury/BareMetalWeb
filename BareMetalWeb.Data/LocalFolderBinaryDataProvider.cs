using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
    private readonly IndexStore _indexStore;
    private readonly ConcurrentDictionary<string, ClusteredPagedObjectStore> _clusteredStores = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, string>> _clusteredLocationMaps = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<Type, SchemaCache> _schemaCache = new();
    private readonly ConcurrentDictionary<Type, object> _schemaLocks = new();

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
        if (string.IsNullOrWhiteSpace(obj.Id))
            throw new ArgumentException("DataObject must have a non-empty Id.", nameof(obj));

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
                schemaVersion = cache.Versions.Count == 0 ? 1 : cache.Versions.Keys.Max() + 1;
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
            var location = store.Write(obj.Id, bytes);
            var map = GetClusteredLocationMap(type.Name);
            map.TryGetValue(obj.Id, out var existingLocation);

            // Append the new location first so a crash never loses the last committed record.
            _indexStore.AppendEntry(type.Name, ClusteredIndexFieldName, obj.Id, location, 'A', normalizeKey: false);
            map[obj.Id] = location;

            if (!string.IsNullOrWhiteSpace(existingLocation)
                && !string.Equals(existingLocation, location, StringComparison.OrdinalIgnoreCase))
            {
                _indexStore.AppendEntry(type.Name, ClusteredIndexFieldName, obj.Id, existingLocation, 'D', normalizeKey: false);
                store.Delete(existingLocation);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Serialization failed for {type.Name} with Id {obj.Id}.", ex);
            throw;
        }
    }

    public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        Save(obj);
        return ValueTask.CompletedTask;
    }

    public T? Load<T>(string id) where T : BaseDataObject
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("Id cannot be null or whitespace.", nameof(id));

        var type = typeof(T);
        if (!TryGetClusteredLocation(type.Name, id, out var location))
            return default;

        var store = GetClusteredStore(type.Name);
        var bytes = store.Read(location);
        if (bytes == null)
        {
            if (_clusteredLocationMaps.TryGetValue(type.Name, out var map))
                map.TryRemove(id, out _);
            return default;
        }

        try
        {
            var schemaVersion = _serializer.ReadSchemaVersion(bytes);
            var schemaFile = GetSchemaDefinition(type, schemaVersion);
            if (schemaFile == null)
            {
                _logger?.LogInfo($"Schema fallback for {type.Name} with Id {id}. Missing version {schemaVersion}; returning null.");
                return default;
            }

            var schemaMembers = schemaFile.Members
                .Select(m => new MemberSignature(m.Name, m.TypeName, AssumePublicMembers(_serializer.ResolveTypeName(m.TypeName)), m.BlittableSize))
                .ToArray();
            var schemaArchitecture = ParseArchitecture(schemaFile.Architecture);
            var schema = _serializer.CreateSchema(schemaFile.Version, schemaMembers, schemaArchitecture, schemaFile.Hash);

            return DeserializeFor<T>(_serializer, bytes, schema);
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Deserialization failed for {type.Name} with Id {id}.", ex);
            throw;
        }
    }

    public ValueTask<T?> LoadAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        return ValueTask.FromResult(Load<T>(id));
    }

    public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject
    {
        var type = typeof(T);
        if (!GetClusteredStore(type.Name).Exists())
            return Array.Empty<T>();

        var locations = GetClusteredLocationMap(type.Name);
        var skip = query?.Skip ?? 0;
        var top = query?.Top ?? int.MaxValue;
        if (skip < 0)
            skip = 0;
        if (top <= 0)
            return Array.Empty<T>();

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
                        continue;

                    var schemaVersion = _serializer.ReadSchemaVersion(bytes);
                    var schemaFile = GetSchemaDefinition(type, schemaVersion);
                    if (schemaFile == null)
                    {
                        _logger?.LogInfo($"Schema fallback for {type.Name} while querying. Missing version {schemaVersion}; skipping paged item {entry.Key}.");
                        continue;
                    }

                    var schemaMembers = schemaFile.Members
                        .Select(m => new MemberSignature(m.Name, m.TypeName, AssumePublicMembers(_serializer.ResolveTypeName(m.TypeName)), m.BlittableSize))
                        .ToArray();
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
                    continue;

                var schemaVersion = _serializer.ReadSchemaVersion(bytes);
                var schemaFile = GetSchemaDefinition(type, schemaVersion);
                if (schemaFile == null)
                {
                    _logger?.LogInfo($"Schema fallback for {type.Name} while querying. Missing version {schemaVersion}; skipping paged item {entry.Key}.");
                    continue;
                }

                var schemaMembers = schemaFile.Members
                    .Select(m => new MemberSignature(m.Name, m.TypeName, AssumePublicMembers(_serializer.ResolveTypeName(m.TypeName)), m.BlittableSize))
                    .ToArray();
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

        var filtered = all.Where(item => _queryEvaluator.Matches(item, query));
        var sorted = _queryEvaluator.ApplySorts(filtered, query);
        if (skip > 0 || top != int.MaxValue)
            sorted = sorted.Skip(skip).Take(top);
        return sorted.ToList();
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

                var schemaMembers = schemaFile.Members
                    .Select(m => new MemberSignature(m.Name, m.TypeName, AssumePublicMembers(_serializer.ResolveTypeName(m.TypeName)), m.BlittableSize))
                    .ToArray();
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

    public void Delete<T>(string id) where T : BaseDataObject
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("Id cannot be null or whitespace.", nameof(id));

        if (TryGetClusteredLocation(typeof(T).Name, id, out var location))
        {
            var store = GetClusteredStore(typeof(T).Name);
            store.Delete(location);
            _indexStore.AppendEntry(typeof(T).Name, ClusteredIndexFieldName, id, location, 'D', normalizeKey: false);
            if (_clusteredLocationMaps.TryGetValue(typeof(T).Name, out var map))
                map.TryRemove(id, out _);
        }
    }

    public ValueTask DeleteAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
    {
        Delete<T>(id);
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

    private string GetFilePath(Type type, string id) => Path.Combine(GetTypeFolder(type), $"{id}.bin");

    private string GetPagedEntityFolder(string entityName)
        => Path.Combine(_rootPath, DefaultPagedFolderName, SanitizeFilePart(entityName));

    private static string GetDataPagedFileName(string id) => $"{DataPagedFilePrefix}{id}";

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

    private string GetLegacySchemaPath(Type type) => Path.Combine(GetTypeFolder(type), "schema.json");

    private string GetLegacySchemaBinPath(Type type) => Path.Combine(GetTypeFolder(type), "schema.bin");

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
            cache.CurrentVersion = cache.Versions.Keys.Max();

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
            return JsonSerializer.Deserialize<SchemaDefinitionFile>(bytes);
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
        var bytes = JsonSerializer.SerializeToUtf8Bytes(schema);
        File.WriteAllBytes(path, bytes);
    }

    private static SchemaDefinitionFile BuildSchemaFile(SchemaDefinition schema, int version)
        => new SchemaDefinitionFile
        {
            Version = version,
            Hash = schema.Hash,
            Architecture = schema.Architecture.ToString(),
            Members = schema.Members
                .Select(m => new MemberSignatureFile { Name = m.Name, TypeName = m.TypeName, BlittableSize = m.BlittableSize })
                .ToList()
        };

    private static bool TryParseSchemaVersion(Type type, string fileName, out int version)
    {
        version = 0;
        var prefix = $"schema-{type.Name}-";
        if (!fileName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) || !fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            return false;

        var numberSpan = fileName.Substring(prefix.Length, fileName.Length - prefix.Length - ".json".Length);
        return int.TryParse(numberSpan, out version) && version > 0;
    }

    private void MigrateLegacySchemas(Type type, SchemaCache cache)
    {
        var legacyPath = GetLegacySchemaPath(type);
        var legacyBinPath = GetLegacySchemaBinPath(type);
        SchemaRegistryFile? registry = null;

        if (File.Exists(legacyBinPath))
        {
            try
            {
                var bytes = File.ReadAllBytes(legacyBinPath);
                var schema = _serializer.BuildSchema(typeof(SchemaRegistryFile));
                if (_serializer is BinaryObjectSerializer binarySerializer)
                {
                    registry = binarySerializer.Deserialize<SchemaRegistryFile>(bytes, schema, SchemaReadMode.BestEffort);
                }
                else
                {
                    registry = _serializer.Deserialize<SchemaRegistryFile>(bytes, schema);
                }
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Legacy schema.bin load failed for {type.Name}.", ex);
            }
        }

        if (registry == null && File.Exists(legacyPath))
        {
            try
            {
                var legacyBytes = File.ReadAllBytes(legacyPath);
                registry = ParseLegacySchema(legacyBytes);
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Legacy schema.json load failed for {type.Name}.", ex);
            }
        }

        if (registry == null)
            return;

        lock (GetSchemaLock(type))
        {
            foreach (var schema in registry.Versions)
            {
                cache.Versions[schema.Version] = schema;
                cache.HashToVersion[schema.Hash] = schema.Version;
                SaveSchemaFile(type, schema);
            }

            cache.CurrentVersion = registry.CurrentVersion > 0
                ? registry.CurrentVersion
                : (cache.Versions.Count == 0 ? 0 : cache.Versions.Keys.Max());
        }
    }

    private object GetSchemaLock(Type type)
        => _schemaLocks.GetOrAdd(type, _ => new object());

    private static SchemaRegistryFile ParseLegacySchema(ReadOnlySpan<byte> bytes)
    {
        try
        {
            using var doc = JsonDocument.Parse(bytes.ToArray());
            var root = doc.RootElement;
            var registry = new SchemaRegistryFile();

            if (root.TryGetProperty("CurrentVersion", out var currentVersion) && currentVersion.TryGetInt32(out var current))
                registry.CurrentVersion = current;

            if (root.TryGetProperty("Versions", out var versions) && versions.ValueKind == JsonValueKind.Array)
            {
                foreach (var versionElement in versions.EnumerateArray())
                {
                    var schema = new SchemaDefinitionFile();
                    if (versionElement.TryGetProperty("Version", out var versionValue) && versionValue.TryGetInt32(out var version))
                        schema.Version = version;
                    if (versionElement.TryGetProperty("Hash", out var hashValue) && hashValue.TryGetUInt32(out var hash))
                        schema.Hash = hash;
                    if (versionElement.TryGetProperty("Architecture", out var archValue) && archValue.ValueKind == JsonValueKind.String)
                        schema.Architecture = archValue.GetString();

                    if (versionElement.TryGetProperty("Members", out var members) && members.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var memberElement in members.EnumerateArray())
                        {
                            var member = new MemberSignatureFile();
                            if (memberElement.TryGetProperty("Name", out var nameValue) && nameValue.ValueKind == JsonValueKind.String)
                                member.Name = nameValue.GetString() ?? string.Empty;
                            if (memberElement.TryGetProperty("TypeName", out var typeNameValue) && typeNameValue.ValueKind == JsonValueKind.String)
                                member.TypeName = typeNameValue.GetString() ?? string.Empty;
                            if (memberElement.TryGetProperty("BlittableSize", out var sizeValue) && sizeValue.TryGetInt32(out var size))
                                member.BlittableSize = size;
                            schema.Members.Add(member);
                        }
                    }

                    registry.Versions.Add(schema);
                }
            }

            return registry;
        }
        catch
        {
            return new SchemaRegistryFile();
        }
    }

    private static BinaryArchitecture ParseArchitecture(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return BinaryArchitecture.Unknown;

        return Enum.TryParse<BinaryArchitecture>(value, ignoreCase: true, out var result)
            ? result
            : BinaryArchitecture.Unknown;
    }

    private static Type AssumePublicMembers(Type type) => type;

    private static SchemaDefinition BuildSchemaFor(ISchemaAwareObjectSerializer serializer, Type type)
        => serializer.BuildSchema(type);

    private static byte[] SerializeFor<T>(ISchemaAwareObjectSerializer serializer, T obj, int schemaVersion)
        => serializer.Serialize(obj, schemaVersion);

    private static T? DeserializeFor<T>(ISchemaAwareObjectSerializer serializer, byte[] bytes, SchemaDefinition schema)
        => serializer.Deserialize<T>(bytes, schema);

    private sealed class LocalPagedFile : IPagedFile
    {
        private const uint HeaderMagic = 0x50414745; // 'PAGE'
        private const int HeaderVersion = 1;
        private const int HeaderMagicOffset = 0;
        private const int HeaderVersionOffset = 4;
        private const int HeaderPageSizeOffset = 8;
        private const int HeaderMapPageCountOffset = 12;
        private const int HeaderDataStartOffset = 16;

        private readonly FileStream _stream;
        private readonly int _pageSize;
        private int _mapPageCount;
        private int _dataStartPage;
        private byte[] _mapBytes;
        private readonly byte[] _pageCache;
        private bool _mapDirty;
        private bool _cacheDirty;
        private long _cachedPageIndex = -1;

        public LocalPagedFile(FileStream stream, int pageSize)
        {
            _stream = stream ?? throw new ArgumentNullException(nameof(stream));
            if (pageSize <= 0)
                throw new ArgumentOutOfRangeException(nameof(pageSize), "Page size must be greater than zero.");

            _pageSize = pageSize;
            _mapPageCount = 1;
            _dataStartPage = 1 + _mapPageCount;
            _mapBytes = ArrayPool<byte>.Shared.Rent(_pageSize * _mapPageCount);
            _pageCache = ArrayPool<byte>.Shared.Rent(_pageSize);
            Array.Clear(_mapBytes, 0, _pageSize * _mapPageCount);

            try
            {
                InitializeOrLoad();
            }
            catch
            {
                ArrayPool<byte>.Shared.Return(_mapBytes);
                ArrayPool<byte>.Shared.Return(_pageCache);
                throw;
            }
        }

        public int PageSize => _pageSize;

        public long Length => _stream.Length;

        public long PageCount
        {
            get
            {
                var totalPages = (_stream.Length + _pageSize - 1) / _pageSize;
                return Math.Max(0, totalPages - _dataStartPage);
            }
        }

        public bool CanWrite => _stream.CanWrite;

        public int ReadPage(long pageIndex, Span<byte> buffer)
        {
            if (buffer.Length < _pageSize)
                throw new ArgumentException("Buffer must be at least one page in size.", nameof(buffer));

            var bytesRead = EnsureCacheLoaded(pageIndex);
            if (bytesRead == 0)
                return 0;

            _pageCache.AsSpan(0, bytesRead).CopyTo(buffer);
            return bytesRead;
        }

        public async ValueTask<int> ReadPageAsync(long pageIndex, Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.Length < _pageSize)
                throw new ArgumentException("Buffer must be at least one page in size.", nameof(buffer));

            var bytesRead = await EnsureCacheLoadedAsync(pageIndex, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
                return 0;

            _pageCache.AsSpan(0, bytesRead).CopyTo(buffer.Span);
            return bytesRead;
        }

        public void WritePage(long pageIndex, ReadOnlySpan<byte> data)
        {
            EnsureWritable();
            if (data.Length != _pageSize)
                throw new ArgumentException("Data must be exactly one page in size.", nameof(data));

            EnsureCacheForWrite(pageIndex);
            data.CopyTo(_pageCache.AsSpan(0, _pageSize));
            _cacheDirty = true;
            MarkPageAllocated(pageIndex);
        }

        public ValueTask WritePageAsync(long pageIndex, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default)
        {
            EnsureWritable();
            if (data.Length != _pageSize)
                throw new ArgumentException("Data must be exactly one page in size.", nameof(data));

            EnsureCacheForWrite(pageIndex);
            data.CopyTo(_pageCache.AsMemory(0, _pageSize));
            _cacheDirty = true;
            MarkPageAllocated(pageIndex);
            return ValueTask.CompletedTask;
        }

        public void Flush()
        {
            FlushCache();
            FlushMap();
            _stream.Flush();
        }

        public async ValueTask FlushAsync(CancellationToken cancellationToken = default)
        {
            await FlushCacheAsync(cancellationToken).ConfigureAwait(false);
            await FlushMapAsync(cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        public void Dispose()
        {
            try
            {
                Flush();
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(_mapBytes);
                ArrayPool<byte>.Shared.Return(_pageCache);
                _stream.Dispose();
            }
        }

        private void InitializeOrLoad()
        {
            if (_stream.Length == 0)
            {
                if (!_stream.CanWrite)
                    throw new InvalidOperationException("Cannot initialize a read-only paged file.");

                WriteHeader();
                WriteMapPages();
                _stream.Flush();
                return;
            }

            ReadHeader();
            EnsureMapBufferSize();
            ReadMapPages();
        }

        private void WriteHeader()
        {
            var buffer = ArrayPool<byte>.Shared.Rent(_pageSize);
            try
            {
                Array.Clear(buffer, 0, _pageSize);
                var span = buffer.AsSpan(0, _pageSize);
                BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(HeaderMagicOffset, 4), HeaderMagic);
                BinaryPrimitives.WriteInt32LittleEndian(span.Slice(HeaderVersionOffset, 4), HeaderVersion);
                BinaryPrimitives.WriteInt32LittleEndian(span.Slice(HeaderPageSizeOffset, 4), _pageSize);
                BinaryPrimitives.WriteInt32LittleEndian(span.Slice(HeaderMapPageCountOffset, 4), _mapPageCount);
                BinaryPrimitives.WriteInt32LittleEndian(span.Slice(HeaderDataStartOffset, 4), _dataStartPage);
                _stream.Seek(0, SeekOrigin.Begin);
                _stream.Write(span);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private void ReadHeader()
        {
            var buffer = ArrayPool<byte>.Shared.Rent(_pageSize);
            try
            {
                var span = buffer.AsSpan(0, _pageSize);
                _stream.Seek(0, SeekOrigin.Begin);
                ReadExact(span);

                var magic = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(HeaderMagicOffset, 4));
                if (magic != HeaderMagic)
                    throw new InvalidOperationException("Paged file header magic mismatch.");

                var version = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(HeaderVersionOffset, 4));
                if (version != HeaderVersion)
                    throw new InvalidOperationException("Paged file header version mismatch.");

                var pageSize = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(HeaderPageSizeOffset, 4));
                if (pageSize != _pageSize)
                    throw new InvalidOperationException("Paged file page size mismatch.");

                var mapPageCount = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(HeaderMapPageCountOffset, 4));
                if (mapPageCount <= 0)
                    throw new InvalidOperationException("Paged file map page count invalid.");

                var dataStartPage = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(HeaderDataStartOffset, 4));
                if (dataStartPage <= 0)
                    throw new InvalidOperationException("Paged file data start invalid.");

                _mapPageCount = mapPageCount;
                _dataStartPage = dataStartPage;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private void WriteMapPages()
        {
            _stream.Seek(_pageSize, SeekOrigin.Begin);
            _stream.Write(_mapBytes, 0, _pageSize * _mapPageCount);
            _mapDirty = false;
        }

        private void ReadMapPages()
        {
            _stream.Seek(_pageSize, SeekOrigin.Begin);
            var length = _pageSize * _mapPageCount;
            var bytesRead = ReadExact(_mapBytes.AsSpan(0, length));
            if (bytesRead < length)
                Array.Clear(_mapBytes, bytesRead, length - bytesRead);
        }

        private int EnsureCacheLoaded(long pageIndex)
        {
            if (_cachedPageIndex == pageIndex)
                return _cacheDirty ? _pageSize : GetCachedBytesAvailable(pageIndex);

            FlushCache();
            _cachedPageIndex = pageIndex;
            _cacheDirty = false;
            return ReadPageIntoCache(pageIndex);
        }

        private async ValueTask<int> EnsureCacheLoadedAsync(long pageIndex, CancellationToken cancellationToken)
        {
            if (_cachedPageIndex == pageIndex)
                return _cacheDirty ? _pageSize : GetCachedBytesAvailable(pageIndex);

            await FlushCacheAsync(cancellationToken).ConfigureAwait(false);
            _cachedPageIndex = pageIndex;
            _cacheDirty = false;
            return await ReadPageIntoCacheAsync(pageIndex, cancellationToken).ConfigureAwait(false);
        }

        private void EnsureCacheForWrite(long pageIndex)
        {
            if (_cachedPageIndex == pageIndex)
                return;

            FlushCache();
            _cachedPageIndex = pageIndex;
            _cacheDirty = false;
        }

        private int ReadPageIntoCache(long pageIndex)
        {
            var offset = GetOffset(pageIndex);
            if (offset >= _stream.Length)
            {
                Array.Clear(_pageCache, 0, _pageSize);
                return 0;
            }

            _stream.Seek(offset, SeekOrigin.Begin);
            var bytesRead = ReadExact(_pageCache.AsSpan(0, _pageSize));
            if (bytesRead < _pageSize)
                Array.Clear(_pageCache, bytesRead, _pageSize - bytesRead);
            return bytesRead;
        }

        private async ValueTask<int> ReadPageIntoCacheAsync(long pageIndex, CancellationToken cancellationToken)
        {
            var offset = GetOffset(pageIndex);
            if (offset >= _stream.Length)
            {
                Array.Clear(_pageCache, 0, _pageSize);
                return 0;
            }

            _stream.Seek(offset, SeekOrigin.Begin);
            var bytesRead = await _stream.ReadAsync(_pageCache.AsMemory(0, _pageSize), cancellationToken).ConfigureAwait(false);
            if (bytesRead < _pageSize)
                Array.Clear(_pageCache, bytesRead, _pageSize - bytesRead);
            return bytesRead;
        }

        private void FlushCache()
        {
            if (!_cacheDirty || _cachedPageIndex < 0)
                return;

            WriteCacheToDisk();
        }

        private async ValueTask FlushCacheAsync(CancellationToken cancellationToken)
        {
            if (!_cacheDirty || _cachedPageIndex < 0)
                return;

            await WriteCacheToDiskAsync(cancellationToken).ConfigureAwait(false);
        }

        private void WriteCacheToDisk()
        {
            var offset = GetOffset(_cachedPageIndex);
            _stream.Seek(offset, SeekOrigin.Begin);
            _stream.Write(_pageCache, 0, _pageSize);
            _cacheDirty = false;
        }

        private async ValueTask WriteCacheToDiskAsync(CancellationToken cancellationToken)
        {
            var offset = GetOffset(_cachedPageIndex);
            _stream.Seek(offset, SeekOrigin.Begin);
            await _stream.WriteAsync(_pageCache.AsMemory(0, _pageSize), cancellationToken).ConfigureAwait(false);
            _cacheDirty = false;
        }

        private void FlushMap()
        {
            if (!_mapDirty)
                return;

            WriteMapPages();
        }

        private async ValueTask FlushMapAsync(CancellationToken cancellationToken)
        {
            if (!_mapDirty)
                return;

            _stream.Seek(_pageSize, SeekOrigin.Begin);
            await _stream.WriteAsync(_mapBytes.AsMemory(0, _pageSize * _mapPageCount), cancellationToken).ConfigureAwait(false);
            _mapDirty = false;
        }

        private void MarkPageAllocated(long pageIndex)
        {
            EnsureMapCapacity(pageIndex);
            var mapCapacity = (long)_mapPageCount * _pageSize * 8;
            if (pageIndex >= mapCapacity)
                throw new InvalidOperationException("Page index exceeds map capacity.");

            var bitIndex = pageIndex;
            var byteIndex = bitIndex / 8;
            if (byteIndex > int.MaxValue)
                throw new InvalidOperationException("Page index exceeds supported map size.");

            var byteIndexInt = (int)byteIndex;
            var bitOffset = (int)(bitIndex % 8);
            var mask = (byte)(1 << bitOffset);
            if ((_mapBytes[byteIndexInt] & mask) == 0)
            {
                _mapBytes[byteIndexInt] |= mask;
                _mapDirty = true;
            }
        }

        private int ReadExact(Span<byte> buffer)
        {
            var totalRead = 0;
            while (totalRead < buffer.Length)
            {
                var read = _stream.Read(buffer.Slice(totalRead));
                if (read == 0)
                    break;
                totalRead += read;
            }
            return totalRead;
        }

        private int GetCachedBytesAvailable(long pageIndex)
        {
            var remaining = _stream.Length - GetOffset(pageIndex);
            if (remaining <= 0)
                return 0;

            var available = Math.Min((long)_pageSize, remaining);
            return (int)available;
        }

        private long GetOffset(long pageIndex)
        {
            if (pageIndex < 0)
                throw new ArgumentOutOfRangeException(nameof(pageIndex), "Page index cannot be negative.");
            if (pageIndex > long.MaxValue / _pageSize)
                throw new ArgumentOutOfRangeException(nameof(pageIndex), "Page index is too large.");

            return (pageIndex + _dataStartPage) * (long)_pageSize;
        }

        private void EnsureMapBufferSize()
        {
            var requiredLength = _pageSize * _mapPageCount;
            if (_mapBytes.Length >= requiredLength)
                return;

            var newBuffer = ArrayPool<byte>.Shared.Rent(requiredLength);
            Array.Copy(_mapBytes, newBuffer, Math.Min(_mapBytes.Length, requiredLength));
            ArrayPool<byte>.Shared.Return(_mapBytes);
            _mapBytes = newBuffer;
        }

        private void EnsureMapCapacity(long pageIndex)
        {
            var requiredBytes = (pageIndex / 8) + 1;
            var requiredMapPagesLong = (requiredBytes + _pageSize - 1) / _pageSize;
            if (requiredMapPagesLong > int.MaxValue)
                throw new InvalidOperationException("Paged file map exceeds supported size.");

            var requiredMapPages = (int)requiredMapPagesLong;
            if (requiredMapPages <= _mapPageCount)
                return;

            GrowMapPages(requiredMapPages);
        }

        private void GrowMapPages(int newMapPageCount)
        {
            if (newMapPageCount <= _mapPageCount)
                return;

            EnsureWritable();
            FlushCache();

            var deltaPages = newMapPageCount - _mapPageCount;
            var oldDataStartOffset = (long)_dataStartPage * _pageSize;
            var dataLength = Math.Max(0, _stream.Length - oldDataStartOffset);
            var shiftBytes = (long)deltaPages * _pageSize;

            if (dataLength > 0)
                ShiftDataForward(oldDataStartOffset, dataLength, shiftBytes);

            _mapPageCount = newMapPageCount;
            _dataStartPage = 1 + _mapPageCount;
            _cachedPageIndex = -1;
            _cacheDirty = false;
            Array.Clear(_pageCache, 0, _pageCache.Length);

            var requiredLength = _pageSize * _mapPageCount;
            var newBuffer = ArrayPool<byte>.Shared.Rent(requiredLength);
            Array.Copy(_mapBytes, newBuffer, _pageSize * (_mapPageCount - deltaPages));
            Array.Clear(newBuffer, _pageSize * (_mapPageCount - deltaPages), _pageSize * deltaPages);
            ArrayPool<byte>.Shared.Return(_mapBytes);
            _mapBytes = newBuffer;
            _mapDirty = true;

            WriteHeader();
            WriteMapPages();
        }

        private void ShiftDataForward(long oldDataStartOffset, long dataLength, long shiftBytes)
        {
            var newLength = _stream.Length + shiftBytes;
            _stream.SetLength(newLength);

            var buffer = ArrayPool<byte>.Shared.Rent(1024 * 1024);
            try
            {
                var remaining = dataLength;
                var readPos = oldDataStartOffset + dataLength;

                while (remaining > 0)
                {
                    var chunk = (int)Math.Min(buffer.Length, remaining);
                    readPos -= chunk;
                    _stream.Seek(readPos, SeekOrigin.Begin);
                    var bytesRead = ReadExact(buffer.AsSpan(0, chunk));
                    _stream.Seek(readPos + shiftBytes, SeekOrigin.Begin);
                    _stream.Write(buffer, 0, bytesRead);
                    remaining -= bytesRead;
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private void EnsureWritable()
        {
            if (!_stream.CanWrite)
                throw new InvalidOperationException("Paged file is not writable.");
        }
    }
}


