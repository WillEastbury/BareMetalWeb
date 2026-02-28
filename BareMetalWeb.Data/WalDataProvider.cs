using System;
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
    private const ushort IdMapVersion          = 1;

    // ── Fields ────────────────────────────────────────────────────────────────

    private readonly string                    _rootPath;
    private readonly ISchemaAwareObjectSerializer _serializer;
    private readonly IDataQueryEvaluator       _queryEvaluator;
    private readonly IBufferedLogger?          _logger;
    private readonly WalStore                  _walStore;

    // Per-entity string-ID → packed-ulong-key map (loaded lazily from the id-map file)
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, ulong>> _idMaps
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
    private readonly ConcurrentDictionary<string, object> _seqIdLocks
        = new(StringComparer.OrdinalIgnoreCase);

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
        if (string.IsNullOrWhiteSpace(obj.Id))
            throw new ArgumentException("DataObject must have a non-empty Id.", nameof(obj));

        ClearSingletonFlagsOnOtherRecords(obj);

        var now = DateTime.UtcNow;
        if (obj.CreatedOnUtc == default) obj.CreatedOnUtc = now;
        obj.UpdatedOnUtc = now;
        obj.ETag = Guid.NewGuid().ToString("N");

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
            var bytes = _serializer.Serialize(obj, schemaVersion);
            var key   = GetOrAllocateKey(type.Name, obj.Id);

            _walStore.CommitAsync(new[] { WalOp.Upsert(key, bytes) })
                     .GetAwaiter().GetResult();

            PersistIdMap(type.Name);
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Save failed for {type.Name} with Id {obj.Id}.", ex);
            throw;
        }
    }

    public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default)
        where T : BaseDataObject
    {
        Save(obj);
        return ValueTask.CompletedTask;
    }

    public T? Load<T>(string id) where T : BaseDataObject
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("Id cannot be null or whitespace.", nameof(id));

        var typeName = typeof(T).Name;
        var idMap    = GetOrLoadIdMap(typeName);

        if (!idMap.TryGetValue(id, out var key)) return default;
        if (!_walStore.TryGetHead(key, out var ptr)) return default;
        if (!_walStore.TryReadOpPayload(ptr, key, out var payload)) return default;
        if (payload.IsEmpty) return default;  // tombstone

        return DeserializePayload<T>(payload.ToArray(), id);
    }

    public ValueTask<T?> LoadAsync<T>(string id, CancellationToken cancellationToken = default)
        where T : BaseDataObject
        => ValueTask.FromResult(Load<T>(id));

    public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject
    {
        var typeName = typeof(T).Name;
        var idMap    = GetOrLoadIdMap(typeName);
        if (idMap.Count == 0) return Array.Empty<T>();

        var skip = query?.Skip ?? 0;
        var top  = query?.Top  ?? int.MaxValue;
        if (skip < 0) skip = 0;
        if (top <= 0) return Array.Empty<T>();

        var canShortCircuit = query == null || query.Sorts.Count == 0;
        var results         = new List<T>();
        int matched         = 0;

        foreach (var (stringId, key) in idMap)  // ConcurrentDictionary supports safe concurrent enumeration
        {
            if (!_walStore.TryGetHead(key, out var ptr)) continue;
            if (!_walStore.TryReadOpPayload(ptr, key, out var payload)) continue;
            if (payload.IsEmpty) continue;  // tombstone

            T? obj;
            try
            {
                obj = DeserializePayload<T>(payload.ToArray(), stringId);
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Deserialization failed for {typeName} with Id {stringId}.", ex);
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
            foreach (var (_, key) in idMap)  // ConcurrentDictionary supports safe concurrent enumeration
            {
                if (!_walStore.TryGetHead(key, out var ptr)) continue;
                if (!_walStore.TryReadOpPayload(ptr, key, out var payload)) continue;
                if (!payload.IsEmpty) live++;
            }
            return live;
        }

        return Query<T>(query).Count();
    }

    public ValueTask<int> CountAsync<T>(QueryDefinition? query = null,
        CancellationToken cancellationToken = default) where T : BaseDataObject
        => ValueTask.FromResult(Count<T>(query));

    public void Delete<T>(string id) where T : BaseDataObject
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("Id cannot be null or whitespace.", nameof(id));

        var typeName = typeof(T).Name;
        var idMap    = GetOrLoadIdMap(typeName);
        if (!idMap.TryGetValue(id, out var key)) return;

        _walStore.CommitAsync(new[] { WalOp.Delete(key) })
                 .GetAwaiter().GetResult();

        idMap.TryRemove(id, out _);
        PersistIdMap(typeName);
    }

    public ValueTask DeleteAsync<T>(string id, CancellationToken cancellationToken = default)
        where T : BaseDataObject
    {
        Delete<T>(id);
        return ValueTask.CompletedTask;
    }

    // ── Sequential IDs ────────────────────────────────────────────────────────

    public string NextSequentialId(string entityName)
    {
        if (string.IsNullOrWhiteSpace(entityName))
            throw new ArgumentException("Entity name cannot be empty.", nameof(entityName));

        var path    = GetSeqIdFilePath(entityName);
        var lockObj = _seqIdLocks.GetOrAdd(entityName, _ => new object());

        const int maxRetries   = 5;
        const int initialDelayMs = 10;

        for (int attempt = 0; attempt <= maxRetries; attempt++)
        {
            try
            {
                lock (lockObj)
                    return IncrementAndReadSeqIdFile(path);
            }
            catch (IOException) when (attempt < maxRetries)
            {
                Thread.Sleep(initialDelayMs * (1 << attempt));
            }
        }

        lock (lockObj)
            return IncrementAndReadSeqIdFile(path);
    }

    public void SeedSequentialId(string entityName, long floor)
    {
        if (string.IsNullOrWhiteSpace(entityName))
            throw new ArgumentException("Entity name cannot be empty.", nameof(entityName));

        var path    = GetSeqIdFilePath(entityName);
        var lockObj = _seqIdLocks.GetOrAdd(entityName, _ => new object());

        const int maxRetries    = 5;
        const int initialDelayMs = 10;

        for (int attempt = 0; attempt <= maxRetries; attempt++)
        {
            try
            {
                lock (lockObj)
                    SeedSeqIdFileIfLower(path, floor);
                return;
            }
            catch (IOException) when (attempt < maxRetries)
            {
                Thread.Sleep(initialDelayMs * (1 << attempt));
            }
        }

        lock (lockObj)
            SeedSeqIdFileIfLower(path, floor);
    }

    // ── IDataProvider: index / paged-file plumbing (not used by WalDataProvider) ─

    public IDisposable AcquireIndexLock(string entityName, string fieldName)
    {
        // WalDataProvider does not use the legacy IndexStore; return a no-op handle.
        return new NoOpDisposable();
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
        => false;

    public IPagedFile OpenPagedFile(string entityName, string fileName, int pageSize,
        FileAccess access)
        => throw new NotSupportedException("WalDataProvider does not use paged files.");

    public ValueTask DeletePagedFileAsync(string entityName, string fileName,
        CancellationToken cancellationToken = default)
        => ValueTask.CompletedTask;  // no-op — no paged files to delete

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

    private ulong GetOrAllocateKey(string typeName, string id)
    {
        var map = GetOrLoadIdMap(typeName);
        return map.GetOrAdd(id, _ =>
            _walStore.AllocateKey(GetOrCreateTableId(typeName)));
    }

    // ── Id-map persistence ────────────────────────────────────────────────────

    private string GetIdMapPath(string typeName)
        => Path.Combine(_rootPath, WalSubFolder, SanitizeFilePart(typeName) + "_idmap.bin");

    private ConcurrentDictionary<string, ulong> GetOrLoadIdMap(string typeName)
        => _idMaps.GetOrAdd(typeName, LoadIdMapCore);

    private ConcurrentDictionary<string, ulong> LoadIdMapCore(string typeName)
    {
        var map  = new ConcurrentDictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);
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
                if (offset + 2 > bytes.Length - 4) break;
                ushort idLen = BinaryPrimitives.ReadUInt16LittleEndian(span[offset..]); offset += 2;
                if (offset + idLen + 8 > bytes.Length - 4) break;
                string id    = Encoding.UTF8.GetString(span[offset..(offset + idLen)]); offset += idLen;
                ulong  key   = BinaryPrimitives.ReadUInt64LittleEndian(span[offset..]);  offset += 8;
                map[id] = key;
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
            var snapshot = map.ToArray();

            // Compute total buffer size
            int size = 12;  // header: magic(4) + version(2) + reserved(2) + count(4)
            foreach (var kv in snapshot)
                size += 2 + Encoding.UTF8.GetByteCount(kv.Key) + 8;
            size += 4;  // CRC

            var buf  = new byte[size];
            var span = buf.AsSpan();
            int o    = 0;

            BinaryPrimitives.WriteUInt32LittleEndian(span[o..], IdMapMagic);         o += 4;
            BinaryPrimitives.WriteUInt16LittleEndian(span[o..], IdMapVersion);       o += 2;
            BinaryPrimitives.WriteUInt16LittleEndian(span[o..], 0);                  o += 2;  // reserved
            BinaryPrimitives.WriteUInt32LittleEndian(span[o..], (uint)snapshot.Length); o += 4;

            foreach (var (id, key) in snapshot)
            {
                var idBytes = Encoding.UTF8.GetBytes(id);
                BinaryPrimitives.WriteUInt16LittleEndian(span[o..], (ushort)idBytes.Length); o += 2;
                idBytes.AsSpan().CopyTo(span[o..]);                                           o += idBytes.Length;
                BinaryPrimitives.WriteUInt64LittleEndian(span[o..], key);                     o += 8;
            }

            uint crc = WalCrc32C.Compute(span[..o]);
            BinaryPrimitives.WriteUInt32LittleEndian(span[o..], crc);

            var path    = GetIdMapPath(typeName);
            var tmpPath = path + ".tmp";
            File.WriteAllBytes(tmpPath, buf);
            File.Move(tmpPath, path, overwrite: true);
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

    private T? DeserializePayload<T>(byte[] bytes, string id) where T : BaseDataObject
    {
        var type          = typeof(T);
        var schemaVersion = _serializer.ReadSchemaVersion(bytes);
        var schemaFile    = GetSchemaDefinition(type, schemaVersion);

        if (schemaFile == null)
        {
            _logger?.LogInfo(
                $"Schema fallback for {type.Name} Id={id}: missing version {schemaVersion}; returning null.");
            return default;
        }

        var schemaMembers = schemaFile.Members
            .Select(m => new MemberSignature(
                m.Name, m.TypeName,
                AssumePublicMembers(_serializer.ResolveTypeName(m.TypeName)),
                m.BlittableSize))
            .ToArray();
        var arch   = ParseArchitecture(schemaFile.Architecture);
        var schema = _serializer.CreateSchema(schemaFile.Version, schemaMembers, arch, schemaFile.Hash);

        if (_serializer is BinaryObjectSerializer bin)
            return bin.Deserialize<T>(bytes, schema, SchemaReadMode.BestEffort);
        return _serializer.Deserialize<T>(bytes, schema);
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
            if (string.Equals(record.Id, obj.Id, StringComparison.OrdinalIgnoreCase)) continue;
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

    private static string IncrementAndReadSeqIdFile(string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? Path.GetTempPath());
        var buf = new byte[8];
        using var file = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        long current = 0;
        if (file.Length >= 8)
        {
            file.ReadExactly(buf, 0, 8);
            current = BinaryPrimitives.ReadInt64LittleEndian(buf);
        }
        var next = current + 1;
        BinaryPrimitives.WriteInt64LittleEndian(buf, next);
        file.Position = 0;
        file.Write(buf, 0, 8);
        file.Flush(true);
        return next.ToString();
    }

    private static void SeedSeqIdFileIfLower(string path, long floor)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? Path.GetTempPath());
        var buf = new byte[8];
        using var file = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        long current = 0;
        if (file.Length >= 8)
        {
            file.ReadExactly(buf, 0, 8);
            current = BinaryPrimitives.ReadInt64LittleEndian(buf);
        }
        if (current < floor)
        {
            BinaryPrimitives.WriteInt64LittleEndian(buf, floor);
            file.Position = 0;
            file.Write(buf, 0, 8);
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

    private sealed class NoOpDisposable : IDisposable
    {
        public void Dispose() { }
    }
}
