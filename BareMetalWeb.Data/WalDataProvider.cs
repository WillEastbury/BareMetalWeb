using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// WAL-backed <see cref="IDataProvider"/> using <see cref="WalStore"/> for durable,
/// log-structured record storage.
///
/// <para>
/// All records are stored as commit-log payloads in a single <see cref="WalStore"/>
/// at <c>{rootPath}/wal/</c>.  Each entity type is assigned a stable <c>uint32</c>
/// table-ID derived from the type name; each string record-ID is mapped to a
/// monotonic <c>uint32</c> record-ID via a per-entity id-map file, giving a packed
/// <c>ulong</c> key consumed by the WAL store.
/// </para>
///
/// <para>
/// Schema versioning follows the same file layout as
/// <see cref="LocalFolderBinaryDataProvider"/> so the two providers can coexist in
/// the same data root with full binary-serializer schema-evolution support.
/// </para>
/// </summary>
public sealed class WalDataProvider : IDataProvider, IDisposable
{
    // ── Constants ────────────────────────────────────────────────────────────

    private const string WalSubFolder          = "wal";
    private const uint   IdMapMagic            = 0x494D4150u; // "IMAP"
    private const ushort IdMapVersion          = 2;
    private const int    DefaultQueryLimit     = int.MaxValue;
    private const string PagedFolderName       = "Paged";
    private const string PagedFileExtension    = ".page";

    // Monotonic ETag counter — cheaper than Guid.NewGuid() per save
    private static long _etagCounter = DateTime.UtcNow.Ticks;

    // ── Fields ────────────────────────────────────────────────────────────────

    private readonly string                    _rootPath;
    private readonly ISchemaAwareObjectSerializer _serializer;
    private readonly IDataQueryEvaluator       _queryEvaluator;
    private readonly IBufferedLogger?          _logger;
    private readonly WalStore                  _walStore;
    private readonly IndexStore                _indexStore;
    private readonly SearchIndexManager        _searchIndexManager;

    // Per-entity uint-key → packed-ulong-WAL-key map (loaded lazily from the id-map file)
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<uint, ulong>> _idMaps
        = new(StringComparer.OrdinalIgnoreCase);

    // Per-entity lock objects used when persisting the id-map file
    private readonly ConcurrentDictionary<string, object> _idMapLocks
        = new(StringComparer.OrdinalIgnoreCase);

    // Stable uint32 table-ID per entity type (derived from type name at runtime – no need to persist)
    private readonly ConcurrentDictionary<string, uint> _tableIds
        = new(StringComparer.OrdinalIgnoreCase);

    // Schema version cache (same pattern as LocalFolderBinaryDataProvider)
    private readonly ConcurrentDictionary<Type, SchemaCache>  _schemaCache  = new();
    private readonly ConcurrentDictionary<Type, object>       _schemaLocks  = new();

    // Sequential-ID file locks
    private readonly ConcurrentDictionary<string, SeqIdRange> _seqIdRanges
        = new(StringComparer.OrdinalIgnoreCase);
    private const int SeqIdBatchSize = 64;

    // ── Construction / disposal ───────────────────────────────────────────────

    public WalDataProvider(
        string rootPath,
        ISchemaAwareObjectSerializer? serializer    = null,
        IDataQueryEvaluator?          queryEvaluator = null,
        IBufferedLogger?               logger         = null)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
            throw new ArgumentException("Root path cannot be null or whitespace.", nameof(rootPath));

        _rootPath      = rootPath;
        _serializer    = serializer     ?? BinaryObjectSerializer.CreateDefault(rootPath);
        _queryEvaluator = queryEvaluator ?? new DataQueryEvaluator();
        _logger        = logger;

        var walDir = Path.Combine(rootPath, WalSubFolder);
        Directory.CreateDirectory(walDir);
        _walStore = new WalStore(walDir);
        _indexStore = new IndexStore(this, logger);
        _searchIndexManager = new SearchIndexManager(rootPath, logger);
    }

    public void Dispose()
    {
        _walStore.Dispose();
    }

    // ── IDataProvider: identity properties ───────────────────────────────────

    public string Name                  => "WalDataProvider";
    public string IndexRootPath         => _rootPath;
    public string IndexFolderName       => "Index";
    public string IndexLogExtension     => ".log";
    public string IndexSnapshotExtension => ".snap";
    public string IndexTempExtension    => ".tmp";
    public bool   CanHandle(Type type)  => true;

    // ── IDataProvider: CRUD ───────────────────────────────────────────────────

    public void Save<T>(T obj) where T : BaseDataObject
    {
        if (obj is null)
            throw new ArgumentNullException(nameof(obj));
        if (obj.Key == 0)
            throw new ArgumentException("DataObject must have a non-zero Key.", nameof(obj));

        ClearSingletonFlagsOnOtherRecords(obj);

        var now = DateTime.UtcNow;
        if (obj.CreatedOnUtc == default) obj.CreatedOnUtc = now;
        obj.UpdatedOnUtc = now;
        obj.ETag = Interlocked.Increment(ref _etagCounter).ToString("x");

        var type       = typeof(T);
        var typeFolder = GetTypeFolder(type);
        Directory.CreateDirectory(typeFolder);

        // ── Schema management ─────────────────────────────────────────────
        var cache         = LoadSchemaCache(type);
        var currentSchema = _serializer.BuildSchema(type);
        int schemaVersion;

        lock (GetSchemaLock(type))
        {
            SchemaDefinitionFile? existing = null;
            if (cache.HashToVersion.TryGetValue(currentSchema.Hash, out var existingVersion))
                cache.Versions.TryGetValue(existingVersion, out existing);

            if (existing == null)
            {
                schemaVersion = cache.Versions.Count == 0 ? 1 : cache.Versions.Keys.Max() + 1;
                var schemaFile = BuildSchemaFile(currentSchema, schemaVersion);
                cache.Versions[schemaVersion]           = schemaFile;
                cache.HashToVersion[currentSchema.Hash] = schemaVersion;
                cache.CurrentVersion                    = schemaVersion;
                SaveSchemaFile(type, schemaFile);
                _logger?.LogInfo($"Schema updated for {type.Name}. New version {schemaVersion} (hash {currentSchema.Hash}).");
            }
            else
            {
                schemaVersion = existing.Version;
            }

            cache.CurrentVersion = schemaVersion;
        }

        // ── Serialize and commit to WAL ────────────────────────────────────
        try
        {
            // Load the existing object before overwriting, so we can remove stale index entries
            var idMap    = GetOrLoadIdMap(type.Name);
            T? oldObj    = null;
            List<PropertyInfo> indexedFields = new();
            if (_searchIndexManager.HasIndexedFields(type, out indexedFields) && idMap.ContainsKey(obj.Key))
                oldObj = Load<T>(obj.Key);

            var bytes  = _serializer.Serialize(obj, schemaVersion);
            var walKey = GetOrAllocateKey(type.Name, obj.Key);

            var commitTask = _walStore.CommitAsync(new[] { WalOp.Upsert(walKey, bytes) });
            if (!commitTask.IsCompleted)
                commitTask.GetAwaiter().GetResult();

            PersistIdMap(type.Name);

            // ── Update secondary field indexes ────────────────────────────
            if (indexedFields.Count > 0)
            {
                var keyStr = obj.Key.ToString();
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
            _logger?.LogError($"Save failed for {type.Name} with Key {obj.Key}.", ex);
            throw;
        }
    }

    public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default)
        where T : BaseDataObject
    {
        Save(obj);
        return ValueTask.CompletedTask;
    }

    public T? Load<T>(uint key) where T : BaseDataObject
    {
        if (key == 0)
            throw new ArgumentException("Key cannot be zero.", nameof(key));

        var typeName = typeof(T).Name;
        var idMap    = GetOrLoadIdMap(typeName);

        if (!idMap.TryGetValue(key, out var walKey)) return default;
        if (!_walStore.TryGetHead(walKey, out var ptr)) return default;
        if (!_walStore.TryReadOpPayload(ptr, walKey, out var payload)) return default;
        if (payload.IsEmpty) return default;  // tombstone

        return DeserializePayload<T>(payload, key);
    }

    public ValueTask<T?> LoadAsync<T>(uint key, CancellationToken cancellationToken = default)
        where T : BaseDataObject
        => ValueTask.FromResult(Load<T>(key));

    public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject
    {
        var typeName = typeof(T).Name;
        var idMap    = GetOrLoadIdMap(typeName);
        if (idMap.Count == 0) return Array.Empty<T>();

        var skip = query?.Skip ?? 0;
        var top  = query?.Top  ?? DefaultQueryLimit;
        if (skip < 0) skip = 0;
        if (top <= 0) return Array.Empty<T>();

        // ── Index-accelerated path: use secondary field index for simple Equals clauses ──
        // If a [DataIndex]-decorated field with an Equals clause is found in the index,
        // load only the candidate IDs rather than deserializing every WAL record.
        // Falls through to the full scan below when no usable index entry exists yet.
        if (query != null && query.Clauses.Count > 0 && query.Groups.Count == 0
            && _searchIndexManager.HasIndexedFields(typeof(T), out var indexedFields))
        {
            foreach (var clause in query.Clauses)
            {
                if (clause.Operator == QueryOperator.Equals && clause.Value != null)
                {
                    var prop = indexedFields.Find(p => string.Equals(p.Name, clause.Field, StringComparison.OrdinalIgnoreCase));
                    if (prop != null)
                    {
                        var fieldValue = clause.Value.ToString() ?? string.Empty;
                        var fieldIndex = _indexStore.ReadIndex(typeName, prop.Name);
                        if (fieldIndex.Count == 0)
                            break; // No index entries yet; fall through to full scan

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

                        var filtered = candidates.Where(item => _queryEvaluator.Matches(item, query));
                        var sorted   = _queryEvaluator.ApplySorts(filtered, query);
                        if (skip > 0 || top != DefaultQueryLimit)
                            sorted = sorted.Skip(skip).Take(top);
                        return sorted.ToList();
                    }
                }
            }
        }
        // ── Full scan (no usable index) ───────────────────────────────────────

        var canShortCircuit = query == null || query.Sorts.Count == 0;
        var results         = new List<T>();
        int matched         = 0;

        foreach (var (objKey, walKey) in idMap)  // ConcurrentDictionary supports safe concurrent enumeration
        {
            if (!_walStore.TryGetHead(walKey, out var ptr)) continue;
            if (!_walStore.TryReadOpPayload(ptr, walKey, out var payload)) continue;
            if (payload.IsEmpty) continue;  // tombstone

            T? obj;
            try
            {
                obj = DeserializePayload<T>(payload, objKey);
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Deserialization failed for {typeName} with Key {objKey}.", ex);
                continue;
            }

            if (obj == null) continue;
            if (!_queryEvaluator.Matches(obj, query)) continue;

            if (canShortCircuit)
            {
                if (matched < skip) { matched++; continue; }
                results.Add(obj);
                matched++;
                if (results.Count >= top) break;
            }
            else
            {
                results.Add(obj);
            }
        }

        if (!canShortCircuit)
        {
            IEnumerable<T> sorted = _queryEvaluator.ApplySorts(results, query);
            if (skip > 0 || top != int.MaxValue)
                sorted = sorted.Skip(skip).Take(top);
            return sorted.ToList();
        }

        return results;
    }

    public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null,
        CancellationToken cancellationToken = default) where T : BaseDataObject
        => ValueTask.FromResult(Query<T>(query));

    public int Count<T>(QueryDefinition? query = null) where T : BaseDataObject
    {
        var typeName = typeof(T).Name;
        var idMap    = GetOrLoadIdMap(typeName);
        if (idMap.Count == 0) return 0;

        // Fast-path: no filter, just count non-tombstone keys
        if (query == null || (query.Clauses.Count == 0 && query.Groups.Count == 0))
        {
            int live = 0;
            foreach (var (_, walKey) in idMap)  // ConcurrentDictionary supports safe concurrent enumeration
            {
                if (!_walStore.TryGetHead(walKey, out var ptr)) continue;
                if (!_walStore.TryReadOpPayload(ptr, walKey, out var payload)) continue;
                if (!payload.IsEmpty) live++;
            }
            return live;
        }

        return Query<T>(query).Count();
    }

    public ValueTask<int> CountAsync<T>(QueryDefinition? query = null,
        CancellationToken cancellationToken = default) where T : BaseDataObject
        => ValueTask.FromResult(Count<T>(query));

    public void Delete<T>(uint key) where T : BaseDataObject
    {
        if (key == 0)
            throw new ArgumentException("Key cannot be zero.", nameof(key));

        var type     = typeof(T);
        var typeName = type.Name;
        var idMap    = GetOrLoadIdMap(typeName);
        if (!idMap.TryGetValue(key, out var walKey)) return;

        // Load the old object before deleting so we can remove its index entries
        T? oldObj = null;
        List<PropertyInfo> indexedFields = new();
        if (_searchIndexManager.HasIndexedFields(type, out indexedFields))
            oldObj = Load<T>(key);

        var commitTask = _walStore.CommitAsync(new[] { WalOp.Delete(walKey) });
        if (!commitTask.IsCompleted)
            commitTask.GetAwaiter().GetResult();

        idMap.TryRemove(key, out _);
        PersistIdMap(typeName);

        // ── Remove from secondary field indexes ────────────────────────────
        if (indexedFields.Count > 0 && oldObj != null)
        {
            var keyStr = key.ToString();
            foreach (var prop in indexedFields)
            {
                var value = prop.GetValue(oldObj)?.ToString() ?? string.Empty;
                _indexStore.AppendEntry(typeName, prop.Name, value, keyStr, 'D');
            }
            _searchIndexManager.RemoveObject(type, key);
        }
    }

    public ValueTask DeleteAsync<T>(uint key, CancellationToken cancellationToken = default)
        where T : BaseDataObject
    {
        Delete<T>(key);
        return ValueTask.CompletedTask;
    }

    // ── Sequential IDs ────────────────────────────────────────────────────────

    public uint NextSequentialKey(string entityName)
    {
        if (string.IsNullOrWhiteSpace(entityName))
            throw new ArgumentException("Entity name cannot be empty.", nameof(entityName));

        var path  = GetSeqIdFilePath(entityName);
        var range = _seqIdRanges.GetOrAdd(entityName, _ => new SeqIdRange());
        return range.Next(path, SeqIdBatchSize);
    }

    public void SeedSequentialKey(string entityName, uint floor)
    {
        if (string.IsNullOrWhiteSpace(entityName))
            throw new ArgumentException("Entity name cannot be empty.", nameof(entityName));

        var path  = GetSeqIdFilePath(entityName);
        var range = _seqIdRanges.GetOrAdd(entityName, _ => new SeqIdRange());

        const int maxRetries    = 5;
        const int initialDelayMs = 10;

        for (int attempt = 0; attempt <= maxRetries; attempt++)
        {
            try
            {
                lock (range.SyncRoot)
                    SeedSeqKeyFileIfLower(path, floor);
                range.Invalidate();
                return;
            }
            catch (IOException) when (attempt < maxRetries)
            {
                Thread.Sleep(initialDelayMs * (1 << attempt));
            }
        }

        lock (range.SyncRoot)
            SeedSeqKeyFileIfLower(path, floor);
        range.Invalidate();
    }

    // ── IDataProvider: index / paged-file plumbing (not used by WalDataProvider) ─

    public IDisposable AcquireIndexLock(string entityName, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(entityName))
            throw new ArgumentException("Entity name cannot be empty.", nameof(entityName));
        if (string.IsNullOrWhiteSpace(fieldName))
            throw new ArgumentException("Field name cannot be empty.", nameof(fieldName));

        var lockPath = Path.Combine(_rootPath, IndexFolderName, SanitizeFilePart(entityName),
                                    SanitizeFilePart(fieldName) + IndexLogExtension + ".lock");
        Directory.CreateDirectory(Path.GetDirectoryName(lockPath) ?? _rootPath);

        const int maxRetries    = 5;
        const int initialDelayMs = 10;

        for (int attempt = 0; attempt <= maxRetries; attempt++)
        {
            try
            {
                return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException) when (attempt < maxRetries)
            {
                Thread.Sleep(initialDelayMs * (1 << attempt));
            }
        }

        return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
    }

    public bool IndexFileExists(string entityName, string fieldName, IndexFileKind kind)
        => false;

    public Stream OpenIndexRead(string entityName, string fieldName, IndexFileKind kind)
        => throw new NotSupportedException("WalDataProvider does not use legacy index files.");

    public Stream OpenIndexAppend(string entityName, string fieldName, IndexFileKind kind)
        => throw new NotSupportedException("WalDataProvider does not use legacy index files.");

    public Stream OpenIndexWriteTemp(string entityName, string fieldName, IndexFileKind kind,
        out string tempToken)
        => throw new NotSupportedException("WalDataProvider does not use legacy index files.");

    public void CommitIndexTemp(string entityName, string fieldName, IndexFileKind kind,
        string tempToken)
        => throw new NotSupportedException("WalDataProvider does not use legacy index files.");

    public bool PagedFileExists(string entityName, string fileName)
    {
        var path = GetPagedFilePath(entityName, fileName);
        return File.Exists(path);
    }

    public IPagedFile OpenPagedFile(string entityName, string fileName, int pageSize,
        FileAccess access)
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
        var exists  = File.Exists(path);

        if (access == FileAccess.Read && !exists)
        {
            using (var initStream = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read, 4096, options))
            {
                using var initializer = new LocalPagedFile(initStream, pageSize);
                initializer.Flush();
            }
        }

        var fileShare = access == FileAccess.Read ? FileShare.ReadWrite : FileShare.Read;
        var stream    = new FileStream(path, FileMode.OpenOrCreate, access, fileShare, 4096, options);
        return new LocalPagedFile(stream, pageSize);
    }

    public ValueTask DeletePagedFileAsync(string entityName, string fileName,
        CancellationToken cancellationToken = default)
    {
        var path = GetPagedFilePath(entityName, fileName);
        if (File.Exists(path))
            File.Delete(path);
        return ValueTask.CompletedTask;
    }

    private string GetPagedFilePath(string entityName, string fileName)
    {
        var folder = Path.Combine(_rootPath, PagedFolderName, SanitizeFilePart(entityName));
        return Path.Combine(folder, SanitizeFilePart(fileName) + PagedFileExtension);
    }

    // ── WAL key management ────────────────────────────────────────────────────

    /// <summary>Returns the stable <c>uint32</c> table-ID for <paramref name="typeName"/>.</summary>
    private uint GetOrCreateTableId(string typeName)
        => _tableIds.GetOrAdd(typeName, static name =>
        {
            // FNV-1a-32 over the lowercase type name — stable, deterministic, no file I/O.
            uint h = 2166136261u;
            foreach (char c in name)
            {
                h ^= (byte)(c >= 'A' && c <= 'Z' ? c | 0x20 : c);
                h *= 16777619u;
            }
            return h == 0 ? 1u : h;
        });

    private ulong GetOrAllocateKey(string typeName, uint key)
    {
        var map = GetOrLoadIdMap(typeName);
        return map.GetOrAdd(key, _ =>
            _walStore.AllocateKey(GetOrCreateTableId(typeName)));
    }

    // ── Id-map persistence ────────────────────────────────────────────────────

    private string GetIdMapPath(string typeName)
        => Path.Combine(_rootPath, WalSubFolder, SanitizeFilePart(typeName) + "_idmap.bin");

    private ConcurrentDictionary<uint, ulong> GetOrLoadIdMap(string typeName)
        => _idMaps.GetOrAdd(typeName, LoadIdMapCore);

    private ConcurrentDictionary<uint, ulong> LoadIdMapCore(string typeName)
    {
        var map  = new ConcurrentDictionary<uint, ulong>();
        var path = GetIdMapPath(typeName);
        if (!File.Exists(path)) return map;

        try
        {
            var bytes = File.ReadAllBytes(path);
            if (bytes.Length < 16) return map;  // header(12) + crc(4)

            var span = bytes.AsSpan();
            if (BinaryPrimitives.ReadUInt32LittleEndian(span)        != IdMapMagic)   return map;
            if (BinaryPrimitives.ReadUInt16LittleEndian(span[4..])   != IdMapVersion) return map;

            int entryCount = (int)BinaryPrimitives.ReadUInt32LittleEndian(span[8..]);

            // Verify CRC over everything except the trailing 4-byte CRC field
            uint storedCrc   = BinaryPrimitives.ReadUInt32LittleEndian(span[^4..]);
            uint computedCrc = WalCrc32C.Compute(span[..^4]);
            if (storedCrc != computedCrc) return map;

            int offset = 12;
            for (int i = 0; i < entryCount; i++)
            {
                if (offset + 12 > bytes.Length - 4) break;
                uint objKey  = BinaryPrimitives.ReadUInt32LittleEndian(span[offset..]); offset += 4;
                ulong walKey = BinaryPrimitives.ReadUInt64LittleEndian(span[offset..]); offset += 8;
                map[objKey] = walKey;
            }
        }
        catch (IOException) { /* treat file as missing */ }

        return map;
    }

    private void PersistIdMap(string typeName)
    {
        var map     = GetOrLoadIdMap(typeName);
        var lockObj = _idMapLocks.GetOrAdd(typeName, _ => new object());

        lock (lockObj)
        {
            int entryCount = map.Count;
            // Compute total buffer size: header(12) + entries(12 each) + CRC(4)
            int size = 12 + entryCount * 12 + 4;

            var buf = ArrayPool<byte>.Shared.Rent(size);
            try
            {
                var span = buf.AsSpan(0, size);
                int o    = 0;

                BinaryPrimitives.WriteUInt32LittleEndian(span[o..], IdMapMagic);         o += 4;
                BinaryPrimitives.WriteUInt16LittleEndian(span[o..], IdMapVersion);       o += 2;
                BinaryPrimitives.WriteUInt16LittleEndian(span[o..], 0);                  o += 2;  // reserved
                BinaryPrimitives.WriteUInt32LittleEndian(span[o..], (uint)entryCount);   o += 4;

                foreach (var (objKey, walKey) in map)
                {
                    BinaryPrimitives.WriteUInt32LittleEndian(span[o..], objKey);  o += 4;
                    BinaryPrimitives.WriteUInt64LittleEndian(span[o..], walKey);  o += 8;
                }

                uint crc = WalCrc32C.Compute(span[..o]);
                BinaryPrimitives.WriteUInt32LittleEndian(span[o..], crc);

                var path    = GetIdMapPath(typeName);
                var tmpPath = path + ".tmp";
                using (var fs = new FileStream(tmpPath, FileMode.Create, FileAccess.Write, FileShare.None))
                    fs.Write(buf, 0, size);
                File.Move(tmpPath, path, overwrite: true);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buf);
            }
        }
    }

    // ── Schema management (mirrors LocalFolderBinaryDataProvider) ─────────────

    private sealed class SchemaCache
    {
        public int CurrentVersion { get; set; }
        public Dictionary<int, SchemaDefinitionFile> Versions    { get; } = new();
        public Dictionary<uint, int>                 HashToVersion { get; } = new();
    }

    private SchemaCache LoadSchemaCache(Type type)
        => _schemaCache.GetOrAdd(type, LoadSchemaCacheCore);

    private SchemaCache LoadSchemaCacheCore(Type type)
    {
        var cache      = new SchemaCache();
        var typeFolder = GetTypeFolder(type);
        Directory.CreateDirectory(typeFolder);

        foreach (var file in Directory.EnumerateFiles(
            typeFolder, GetSchemaFilePattern(type), SearchOption.TopDirectoryOnly))
        {
            if (!TryParseSchemaVersion(type, Path.GetFileName(file), out var version)) continue;
            var schemaFile = LoadSchemaFile(file);
            if (schemaFile == null) continue;
            schemaFile.Version    = version;
            cache.Versions[version]           = schemaFile;
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
            if (cache.Versions.TryGetValue(version, out var cached)) return cached;
        }

        var filePath = GetSchemaFilePath(type, version);
        if (!File.Exists(filePath)) return null;

        var schemaFile = LoadSchemaFile(filePath);
        if (schemaFile == null) return null;

        schemaFile.Version = version;
        lock (GetSchemaLock(type))
        {
            cache.Versions[version]              = schemaFile;
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
            _logger?.LogError($"Schema load failed for {Path.GetFileName(path)}.", ex);
            return null;
        }
    }

    private void SaveSchemaFile(Type type, SchemaDefinitionFile schema)
    {
        var path  = GetSchemaFilePath(type, schema.Version);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(schema);
        File.WriteAllBytes(path, bytes);
    }

    private object GetSchemaLock(Type type)
        => _schemaLocks.GetOrAdd(type, _ => new object());

    private string GetTypeFolder(Type type)
        => Path.Combine(_rootPath, SanitizeFilePart(type.Name));

    private string GetSchemaFilePath(Type type, int version)
        => Path.Combine(GetTypeFolder(type), $"schema-{type.Name}-{version}.json");

    private static string GetSchemaFilePattern(Type type)
        => $"schema-{type.Name}-*.json";

    private static SchemaDefinitionFile BuildSchemaFile(SchemaDefinition schema, int version)
        => new()
        {
            Version      = version,
            Hash         = schema.Hash,
            Architecture = schema.Architecture.ToString(),
            Members      = schema.Members
                .Select(m => new MemberSignatureFile
                {
                    Name          = m.Name,
                    TypeName      = m.TypeName,
                    BlittableSize = m.BlittableSize,
                })
                .ToList()
        };

    private static bool TryParseSchemaVersion(Type type, string fileName, out int version)
    {
        version = 0;
        var prefix = $"schema-{type.Name}-";
        if (!fileName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
            || !fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            return false;

        var numberPart = fileName.Substring(prefix.Length,
            fileName.Length - prefix.Length - ".json".Length);
        return int.TryParse(numberPart, out version) && version > 0;
    }

    private static BinaryArchitecture ParseArchitecture(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return BinaryArchitecture.Unknown;
        return Enum.TryParse<BinaryArchitecture>(value, ignoreCase: true, out var result)
            ? result
            : BinaryArchitecture.Unknown;
    }

    private static Type AssumePublicMembers(Type type) => type;

    // ── Deserialization helper ────────────────────────────────────────────────

    // Cache: (type, schemaVersion) → MemberSignature[]
    private readonly ConcurrentDictionary<(Type, int), MemberSignature[]> _schemaMemberCache = new();

    private T? DeserializePayload<T>(ReadOnlyMemory<byte> memory, uint key) where T : BaseDataObject
    {
        var bytes         = memory.Span;
        var type          = typeof(T);
        var schemaVersion = _serializer.ReadSchemaVersion(bytes);
        var schemaFile    = GetSchemaDefinition(type, schemaVersion);

        if (schemaFile == null)
        {
            _logger?.LogInfo(
                $"Schema fallback for {type.Name} Key={key}: missing version {schemaVersion}; returning null.");
            return default;
        }

        var schemaMembers = _schemaMemberCache.GetOrAdd((type, schemaVersion), _ =>
            schemaFile.Members
                .Select(m => new MemberSignature(
                    m.Name, m.TypeName,
                    AssumePublicMembers(_serializer.ResolveTypeName(m.TypeName)),
                    m.BlittableSize))
                .ToArray());

        var arch   = ParseArchitecture(schemaFile.Architecture);
        var schema = _serializer.CreateSchema(schemaFile.Version, schemaMembers, arch, schemaFile.Hash);

        // Materialize to array only at the serializer boundary
        var arr = memory.ToArray();
        if (_serializer is BinaryObjectSerializer bin)
            return bin.Deserialize<T>(arr, schema, SchemaReadMode.BestEffort);
        return _serializer.Deserialize<T>(arr, schema);
    }

    // ── Singleton-flag enforcement ────────────────────────────────────────────

    private void ClearSingletonFlagsOnOtherRecords<T>(T obj) where T : BaseDataObject
    {
        var type           = typeof(T);
        var singletonProps = type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.PropertyType == typeof(bool)
                        && p.GetCustomAttribute<SingletonFlagAttribute>() != null
                        && p.CanRead && p.CanWrite
                        && true.Equals(p.GetValue(obj)))
            .ToList();

        if (singletonProps.Count == 0) return;

        foreach (var record in Query<T>())
        {
            if (record.Key == obj.Key) continue;
            bool changed = false;
            foreach (var prop in singletonProps)
            {
                if (true.Equals(prop.GetValue(record)))
                {
                    prop.SetValue(record, false);
                    changed = true;
                }
            }
            if (changed) Save(record);
        }
    }

    // ── Sequential-ID helpers ─────────────────────────────────────────────────

    private string GetSeqIdFilePath(string entityName)
        => Path.Combine(_rootPath, SanitizeFilePart(entityName), "_seqid.dat");

    private sealed class SeqIdRange
    {
        public readonly object SyncRoot = new();
        private uint _next;
        private uint _ceiling;

        public uint Next(string path, int batchSize)
        {
            lock (SyncRoot)
            {
                if (_next < _ceiling)
                    return ++_next;

                const int maxRetries = 5;
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

    private static uint AllocateBatch(string path, int batchSize)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? Path.GetTempPath());
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
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? Path.GetTempPath());
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

    // ── Utility ───────────────────────────────────────────────────────────────

    private static string SanitizeFilePart(string value)
    {
        var name = value ?? string.Empty;
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name;
    }
}
