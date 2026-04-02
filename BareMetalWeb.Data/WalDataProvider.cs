using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Numerics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
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
/// Schema versioning uses a file-per-type layout in the data root with full
/// binary-serializer schema-evolution support.
/// </para>
/// </summary>
public sealed class WalDataProvider : IDataProvider, IRawBinaryProvider, IDisposable
{
    internal static Action<TimeSpan>? OnWalReadComplete;

    // ── Constants ────────────────────────────────────────────────────────────

    private const string WalSubFolder          = "wal";
    private const uint   IdMapMagic            = 0x494D4150u; // "IMAP"
    private const ushort IdMapVersion          = 2;
    private const int    DefaultQueryLimit     = 1000;
    private const string PagedFolderName       = "Paged";
    private const string PagedFileExtension    = ".page";

    private static readonly HashSet<uint> s_emptyUintSet = new();

    // Monotonic ETag counter — cheaper than Guid.NewGuid() per save
    private static long _etagCounter = DateTime.UtcNow.Ticks;

    /// <summary>Format a long as lowercase hex using string.Create to avoid intermediate ToString allocation.</summary>
    private static string FormatETagHex(long value)
    {
        int bits = 64 - BitOperations.LeadingZeroCount((ulong)value);
        int len = Math.Max(1, (bits + 3) >> 2);
        return string.Create(len, value, static (span, val) =>
        {
            for (int i = span.Length - 1; i >= 0; i--)
            {
                span[i] = "0123456789abcdef"[(int)(val & 0xF)];
                val >>>= 4;
            }
        });
    }

    // ── Fields ────────────────────────────────────────────────────────────────

    private readonly string                    _rootPath;
    private readonly ISchemaAwareObjectSerializer _serializer;
    private readonly IDataQueryEvaluator       _queryEvaluator;
    private readonly IBufferedLogger?          _logger;
    private WalStore                  _walStore;

    /// <summary>Exposes the underlying WAL store for background services (e.g. compaction, backup).</summary>
    public WalStore WalStore => _walStore;

    private IndexStore                _indexStore;
    private SearchIndexManager        _searchIndexManager;

    // Per-entity uint-key → packed-ulong-WAL-key map (loaded lazily from the id-map file)
    private readonly ConcurrentDictionary<string, ConcurrentDictionary<uint, ulong>> _idMaps
        = new(StringComparer.OrdinalIgnoreCase);

    // Per-entity lock objects used when persisting the id-map file
    private readonly ConcurrentDictionary<string, object> _idMapLocks
        = new(StringComparer.OrdinalIgnoreCase);

    // Stable uint32 table-ID per entity type (derived from type name at runtime – no need to persist)
    private readonly ConcurrentDictionary<string, uint> _tableIds
        = new(StringComparer.OrdinalIgnoreCase);

    // Schema version cache

    // Live record counts maintained on Save/Delete to avoid tombstone walks.
    // Initialised lazily from the id-map (only non-tombstone entries) on first
    // Count() call with no filter; updated atomically on Save (insert) / Delete.
    private readonly ConcurrentDictionary<string, int> _liveCounts
        = new(StringComparer.OrdinalIgnoreCase);

    // Deserialization cache — avoids repeated binary→object for unchanged WAL entries.
    // Keyed by (typeName, objKey, walPointer). Invalidated on Save (walPtr changes).
    private const int DeserCacheMaxSize = 4096;
    private readonly ConcurrentDictionary<(string TypeName, uint Key, ulong WalPtr), object> _deserCache = new();
    private readonly ConcurrentDictionary<(string TypeName, uint Key, ulong WalPtr), long> _deserCacheAccess = new();

    // Sequential-ID file locks
    private readonly ConcurrentDictionary<string, SeqIdRange> _seqIdRanges
        = new(StringComparer.OrdinalIgnoreCase);
    private const int SeqIdBatchSize = 64;

    // Columnar store cache — per-entity in-memory columnar layout for SIMD queries.
    // Lazily built on first vectorised query, invalidated on Save/Delete.
    private readonly ConcurrentDictionary<string, ColumnarStore> _columnarStores
        = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, long> _columnarVersions
        = new(StringComparer.OrdinalIgnoreCase);

    // Optional cluster state for write fencing
    private ClusterState? _clusterState;

    // ── Construction / disposal ───────────────────────────────────────────────

    public WalDataProvider(
        string rootPath,
        ISchemaAwareObjectSerializer? serializer    = null,
        IDataQueryEvaluator?          queryEvaluator = null,
        IBufferedLogger?               logger         = null)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
            throw new ArgumentException("Root path cannot be null or whitespace.", nameof(rootPath));

        Console.WriteLine($"[BMW WAL] Initializing WalDataProvider (root: {rootPath})");
        _rootPath      = rootPath;
        _serializer    = serializer     ?? BinaryObjectSerializer.CreateDefault(rootPath);
        _queryEvaluator = queryEvaluator ?? new DataQueryEvaluator();
        _logger        = logger;

        var walDir = Path.Combine(rootPath, WalSubFolder);
        Directory.CreateDirectory(walDir);
        Console.WriteLine($"[BMW WAL] Creating WalStore (dir: {walDir})");
        _walStore = new WalStore(walDir);
        Console.WriteLine($"[BMW WAL] WalStore ready — creating IndexStore + SearchIndexManager");
        _indexStore = new IndexStore(this, logger);
        _searchIndexManager = new SearchIndexManager(rootPath, logger);
        Console.WriteLine($"[BMW WAL] WalDataProvider initialized");
    }

    /// <summary>
    /// Attach cluster state for write fencing. When set, all writes validate
    /// that this instance is the elected leader before proceeding.
    /// </summary>
    public void SetClusterState(ClusterState clusterState) => _clusterState = clusterState;

    /// <summary>
    /// Pre-warms the search index type metadata cache for all registered entity
    /// types so that the first real query does not pay the reflection cost.
    /// Safe to call from a background thread after startup.
    /// </summary>
    public void WarmSearchIndexMetadata()
    {
        foreach (var meta in BareMetalWeb.Core.DataScaffold.Entities)
        {
            try { _searchIndexManager.WarmTypeMetadata(meta.Type); }
            catch { /* index metadata will be built on first query */ }
        }
    }

    public void Dispose()
    {
        _walStore.Dispose();
    }

    /// <inheritdoc />
    public ValueTask WipeStorageAsync(CancellationToken cancellationToken = default)
    {
        // 1. Close the active WAL segment cleanly (writes snapshot + footer, closes handles).
        _walStore.Dispose();

        // 2. Delete and recreate the entire data root so every artefact is removed:
        //    wal/ (WAL segments + id-maps), Index/ (secondary field indexes),
        //    indexes/ (search-index files), Paged/ (paged files), and per-entity
        //    type folders (schema JSON files + _seqid.dat).
        if (Directory.Exists(_rootPath))
            Directory.Delete(_rootPath, recursive: true);
        Directory.CreateDirectory(_rootPath);

        // 3. Clear all in-memory caches so the next access starts fresh.
        _idMaps.Clear();
        _idMapLocks.Clear();
        _tableIds.Clear();
        _seqIdRanges.Clear();

        // 4. Reinitialise the WAL store on the new empty directory.
        var walDir = Path.Combine(_rootPath, WalSubFolder);
        Directory.CreateDirectory(walDir);
        _walStore = new WalStore(walDir);

        // 5. Reinitialise the secondary-index components.
        _indexStore         = new IndexStore(this, _logger);
        _searchIndexManager = new SearchIndexManager(_rootPath, _logger);

        return ValueTask.CompletedTask;
    }

    // ── IDataProvider: identity properties ───────────────────────────────────

    public string Name                  => "WalDataProvider";
    public string IndexRootPath         => _rootPath;
    public string IndexFolderName       => "Index";
    public string IndexLogExtension     => ".log";
    public string IndexSnapshotExtension => ".snap";
    public string IndexTempExtension    => ".tmp";
    private void EvictDeserCache()
    {
        // LRU eviction — remove ~25% of entries with oldest access times.
        // Single-pass min-scan avoids O(n log n) sort on the full cache.
        int toRemove = _deserCache.Count / 4;
        if (toRemove == 0) toRemove = 1;

        var evictKeys = new ((string TypeName, uint Key, ulong WalPtr) key, long access)[toRemove];
        int evictCount = 0;

        foreach (var kvp in _deserCacheAccess)
        {
            if (evictCount < toRemove)
            {
                evictKeys[evictCount++] = (kvp.Key, kvp.Value);
                continue;
            }

            // Find the max (youngest) entry in our evict set and replace it
            // if this entry is older (smaller tick count)
            int maxIdx = 0;
            for (int i = 1; i < evictCount; i++)
                if (evictKeys[i].access > evictKeys[maxIdx].access)
                    maxIdx = i;

            if (kvp.Value < evictKeys[maxIdx].access)
                evictKeys[maxIdx] = (kvp.Key, kvp.Value);
        }

        for (int i = 0; i < evictCount; i++)
        {
            _deserCache.TryRemove(evictKeys[i].key, out _);
            _deserCacheAccess.TryRemove(evictKeys[i].key, out _);
        }
    }

    /// <inheritdoc/>
    public ReadOnlyMemory<byte> LoadBinary(string typeName, uint key)
    {
        if (key == 0) return ReadOnlyMemory<byte>.Empty;

        var idMap = GetOrLoadIdMap(typeName);
        if (!idMap.TryGetValue(key, out var walKey)) return ReadOnlyMemory<byte>.Empty;
        if (!_walStore.TryGetHead(walKey, out var ptr)) return ReadOnlyMemory<byte>.Empty;
        if (!_walStore.TryReadOpPayload(ptr, walKey, out var payload)) return ReadOnlyMemory<byte>.Empty;

        return payload;
    }

    /// <inheritdoc/>
    public IReadOnlyList<ReadOnlyMemory<byte>> QueryBinary(string typeName, QueryDefinition? query = null)
    {
        var sw = Stopwatch.StartNew();
        var idMap = GetOrLoadIdMap(typeName);
        if (idMap.Count == 0) { sw.Stop(); OnWalReadComplete?.Invoke(sw.Elapsed); return Array.Empty<ReadOnlyMemory<byte>>(); }

        int skip = query?.Skip ?? 0;
        int top  = query?.Top  ?? DefaultQueryLimit;

        var results = new List<ReadOnlyMemory<byte>>(Math.Min(top, idMap.Count));
        int skipped = 0;
        int taken = 0;

        foreach (var kvp in idMap)
        {
            if (taken >= top) break;

            var walKey = kvp.Value;
            if (!_walStore.TryGetHead(walKey, out var ptr)) continue;
            if (!_walStore.TryReadOpPayload(ptr, walKey, out var payload)) continue;
            if (payload.IsEmpty) continue;

            if (skipped < skip) { skipped++; continue; }

            results.Add(payload);
            taken++;
        }

        sw.Stop();
        OnWalReadComplete?.Invoke(sw.Elapsed);
        return results;
    }

    // ── WAL compaction ────────────────────────────────────────────────────────

    /// <summary>
    /// Compacts the given WAL segment by rebuilding it from the in-memory materialised
    /// view.  Delegates to <see cref="WalStore.CompactSegmentFromMaterialisedView"/>.
    ///
    /// The segment is rebuilt without reading the full original segment from disk;
    /// only the latest version of each live record in that segment is written,
    /// eliminating the read phase and reducing disk IO roughly by half compared
    /// to a sequential read-deduplicate-write approach.
    ///
    /// Precondition: <paramref name="segmentId"/> must not be the currently active
    /// (still-being-written) segment.
    /// </summary>
    public void CompactSegmentFromMaterialisedView(uint segmentId)
        => _walStore.CompactSegmentFromMaterialisedView(segmentId);
    //
    // Fully AOT-safe code path for DataRecord entities. Uses EntitySchema
    // parallel arrays and ordinal-indexed closures instead of generic type
    // parameters and reflection-based schema building.

    private readonly ConcurrentDictionary<string, BinaryObjectSerializer.FieldPlan[]> _recordPlans
        = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int> _recordSchemaVersions
        = new(StringComparer.OrdinalIgnoreCase);

    private BinaryObjectSerializer GetBinarySerializer()
    {
        if (_serializer is BinaryObjectSerializer bos)
            return bos;
        throw new InvalidOperationException("FieldPlan serialization requires a BinaryObjectSerializer instance.");
    }

    private BinaryObjectSerializer.FieldPlan[] GetOrBuildRecordPlan(EntitySchema schema)
    {
        return _recordPlans.GetOrAdd(schema.EntityName, _ =>
        {
            var descriptors = schema.BuildFieldPlanDescriptors();
            return BinaryObjectSerializer.BuildPlanUncached(descriptors);
        });
    }

    /// <summary>
    /// Saves a <see cref="DataRecord"/> to WAL storage using metadata-driven serialization.
    /// No reflection, no generic type parameter — fully AOT-safe.
    /// </summary>
    public void SaveRecord(DataRecord record, EntitySchema schema)
    {
        if (record is null) throw new ArgumentNullException(nameof(record));
        if (record.Key == 0) throw new ArgumentException("DataRecord must have a non-zero Key.", nameof(record));

        _clusterState?.ValidateWritePermission();

        var now = DateTime.UtcNow;
        if (record.CreatedOnUtc == default) record.CreatedOnUtc = now;
        record.UpdatedOnUtc = now;
        record.ETag = FormatETagHex(Interlocked.Increment(ref _etagCounter));

        var entityName = schema.EntityName;
        record.EntityTypeName = entityName;

        var entityFolder = Path.Combine(_rootPath, entityName);
        Directory.CreateDirectory(entityFolder);

        int schemaVersion = _recordSchemaVersions.GetOrAdd(entityName, _ => 1);

        try
        {
            var idMap = GetOrLoadIdMap(entityName);
            bool isInsert = !idMap.ContainsKey(record.Key);

            DataRecord? oldRecord = null;
            if (!isInsert)
            {
                for (int i = 0; i < schema.FieldCount; i++)
                {
                    if (schema.IsIndexed[i]) { oldRecord = LoadRecord(record.Key, schema); break; }
                }
            }

            var plan = GetOrBuildRecordPlan(schema);
            var serializer = GetBinarySerializer();
            var bytes = serializer.Serialize(record, plan, schemaVersion);
            var walKey = GetOrAllocateKey(entityName, record.Key);

            // Capture old head pointer for cache eviction before commit
            ulong oldPtr = 0;
            if (!isInsert)
                _walStore.TryGetHead(walKey, out oldPtr);

            var commitTask = _walStore.CommitAsync(new[] { WalOp.Upsert(walKey, bytes, encryption: _walStore.Encryption) });
            if (!commitTask.IsCompleted)
                commitTask.GetAwaiter().GetResult();

            PersistIdMap(entityName);

            if (isInsert)
                _liveCounts.AddOrUpdate(entityName, 1, (_, c) => c + 1);

            // Evict deserialization cache entry using exact old key
            if (!isInsert && oldPtr != 0)
            {
                var evictKey = (entityName, record.Key, oldPtr);
                _deserCache.TryRemove(evictKey, out _);
                _deserCacheAccess.TryRemove(evictKey, out _);
            }

            var keyStr = record.Key.ToString();
            for (int i = 0; i < schema.FieldCount; i++)
            {
                if (!schema.IsIndexed[i]) continue;
                var ord = DataRecord.BaseFieldCount + i;
                var newValue = record.GetValue(ord)?.ToString() ?? string.Empty;
                if (oldRecord != null)
                {
                    var oldValue = oldRecord.GetValue(ord)?.ToString() ?? string.Empty;
                    if (string.Equals(oldValue, newValue, StringComparison.OrdinalIgnoreCase))
                        continue;
                    _indexStore.AppendEntry(entityName, schema.Names[i], oldValue, keyStr, 'D');
                }
                _indexStore.AppendEntry(entityName, schema.Names[i], newValue, keyStr, 'A');
            }

            // Invalidate columnar store
            if (_columnarStores.TryGetValue(entityName, out var colStore))
                colStore.Invalidate();
        }
        catch (Exception ex)
        {
            _logger?.LogError($"SaveRecord failed for {entityName} Key={record.Key}.", ex);
            throw;
        }
    }

    /// <summary>Saves a <see cref="DataRecord"/> asynchronously.</summary>
    public ValueTask SaveRecordAsync(DataRecord record, EntitySchema schema, CancellationToken cancellationToken = default)
    {
        SaveRecord(record, schema);
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Loads a <see cref="DataRecord"/> from WAL storage by key.
    /// Returns null if not found or if the payload is corrupt.
    /// </summary>
    public DataRecord? LoadRecord(uint key, EntitySchema schema)
    {
        if (key == 0) throw new ArgumentException("Key cannot be zero.", nameof(key));

        var entityName = schema.EntityName;
        var idMap = GetOrLoadIdMap(entityName);

        if (!idMap.TryGetValue(key, out var walKey)) return null;
        if (!_walStore.TryGetHead(walKey, out var ptr)) return null;

        var cacheKey = (entityName, key, ptr);
        if (_deserCache.TryGetValue(cacheKey, out var cachedObj))
        {
            _deserCacheAccess[cacheKey] = Environment.TickCount64;
            return cachedObj as DataRecord;
        }

        if (!_walStore.TryReadOpPayload(ptr, walKey, out var payload)) return null;
        if (payload.IsEmpty) return null;

        DataRecord? result;
        try
        {
            var plan = GetOrBuildRecordPlan(schema);
            var serializer = GetBinarySerializer();
            result = schema.CreateRecord();
            result.Key = key;
            serializer.DeserializeInto(payload.Span, plan, result);
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Corrupt DataRecord payload for {entityName} Key={key}: {ex.Message}", ex);
            return null;
        }

        if (result != null)
        {
            if (_deserCache.Count >= DeserCacheMaxSize)
                EvictDeserCache();
            _deserCache[cacheKey] = result;
            _deserCacheAccess[cacheKey] = Environment.TickCount64;
        }
        return result;
    }

    /// <summary>Loads a <see cref="DataRecord"/> asynchronously.</summary>
    public ValueTask<DataRecord?> LoadRecordAsync(uint key, EntitySchema schema, CancellationToken cancellationToken = default)
        => new(LoadRecord(key, schema));

    /// <summary>
    /// Queries <see cref="DataRecord"/> entities with optional filtering, sorting and paging.
    /// </summary>
    public IEnumerable<DataRecord> QueryRecords(EntitySchema schema, QueryDefinition? query = null)
    {
        var entityName = schema.EntityName;
        var idMap = GetOrLoadIdMap(entityName);
        if (idMap.Count == 0) return Array.Empty<DataRecord>();

        var skip = query?.Skip ?? 0;
        var top = query?.Top ?? DefaultQueryLimit;
        if (skip < 0) skip = 0;
        if (top <= 0) return Array.Empty<DataRecord>();

        var results = new List<DataRecord>(Math.Min(top, idMap.Count));
        foreach (var kvp in idMap)
        {
            var record = LoadRecord(kvp.Key, schema);
            if (record == null) continue;
            if (query != null && query.Clauses.Count > 0 && !MatchesRecordQuery(record, schema, query))
                continue;
            results.Add(record);
        }

        if (query?.Sorts.Count > 0)
        {
            results.Sort((a, b) =>
            {
                foreach (var sc in query.Sorts)
                {
                    if (!schema.TryGetOrdinal(sc.Field, out var ord)) continue;
                    int cmp = CompareFieldValues(a.GetValue(ord), b.GetValue(ord));
                    if (sc.Direction == SortDirection.Desc) cmp = -cmp;
                    if (cmp != 0) return cmp;
                }
                return 0;
            });
        }

        if (skip > 0 || top < DefaultQueryLimit)
        {
            int end = (top < DefaultQueryLimit) ? Math.Min(skip + top, results.Count) : results.Count;
            var paged = new List<DataRecord>(Math.Max(0, end - skip));
            for (int i = skip; i < end; i++)
                paged.Add(results[i]);
            return paged;
        }
        return results;
    }

    /// <summary>Queries <see cref="DataRecord"/> entities asynchronously.</summary>
    public ValueTask<IEnumerable<DataRecord>> QueryRecordsAsync(EntitySchema schema, QueryDefinition? query = null, CancellationToken cancellationToken = default)
        => new(QueryRecords(schema, query));

    /// <summary>Counts <see cref="DataRecord"/> entities with optional filtering.</summary>
    public int CountRecords(EntitySchema schema, QueryDefinition? query = null)
    {
        var entityName = schema.EntityName;
        if (query == null || query.Clauses.Count == 0)
            return _liveCounts.TryGetValue(entityName, out var c) ? c : GetOrLoadIdMap(entityName).Count;
        int count = 0;
        foreach (var _ in QueryRecords(schema, query))
            count++;
        return count;
    }

    /// <summary>Counts <see cref="DataRecord"/> entities asynchronously.</summary>
    public ValueTask<int> CountRecordsAsync(EntitySchema schema, QueryDefinition? query = null, CancellationToken cancellationToken = default)
        => new(CountRecords(schema, query));

    /// <summary>Deletes a <see cref="DataRecord"/> from WAL storage.</summary>
    public void DeleteRecord(uint key, EntitySchema schema)
    {
        if (key == 0) throw new ArgumentException("Key cannot be zero.", nameof(key));

        _clusterState?.ValidateWritePermission();

        var entityName = schema.EntityName;
        var idMap = GetOrLoadIdMap(entityName);
        if (!idMap.TryGetValue(key, out var walKey)) return;

        DataRecord? oldRecord = null;
        for (int i = 0; i < schema.FieldCount; i++)
        {
            if (schema.IsIndexed[i]) { oldRecord = LoadRecord(key, schema); break; }
        }

        var commitTask = _walStore.CommitAsync(new[] { WalOp.Delete(walKey) });
        if (!commitTask.IsCompleted)
            commitTask.GetAwaiter().GetResult();

        idMap.TryRemove(key, out _);
        PersistIdMap(entityName);
        _liveCounts.AddOrUpdate(entityName, 0, (_, c) => Math.Max(0, c - 1));

        foreach (var ck in _deserCache.Keys)
        {
            if (ck.TypeName == entityName && ck.Key == key)
            {
                _deserCache.TryRemove(ck, out _);
                _deserCacheAccess.TryRemove(ck, out _);
            }
        }

        if (oldRecord != null)
        {
            var keyStr = key.ToString();
            for (int i = 0; i < schema.FieldCount; i++)
            {
                if (!schema.IsIndexed[i]) continue;
                var value = oldRecord.GetValue(DataRecord.BaseFieldCount + i)?.ToString() ?? string.Empty;
                _indexStore.AppendEntry(entityName, schema.Names[i], value, keyStr, 'D');
            }
        }
    }

    /// <summary>Deletes a <see cref="DataRecord"/> asynchronously.</summary>
    public ValueTask DeleteRecordAsync(uint key, EntitySchema schema, CancellationToken cancellationToken = default)
    {
        DeleteRecord(key, schema);
        return ValueTask.CompletedTask;
    }

    // ── Entity-name-based overloads (IDataProvider non-generic) ─────────────
    //
    // These resolve a system EntitySchema by name, coerce the object to a
    // DataRecord when necessary, and delegate to the existing Record-based
    // methods above.  Fully AOT-safe — no reflection, no generic dispatch.

    /// <summary>Resolves an <see cref="EntitySchema"/> by entity type name, or throws.</summary>
    private static EntitySchema ResolveSchemaByName(string entityTypeName)
    {
        return SystemEntitySchemas.GetByName(entityTypeName)
            ?? throw new InvalidOperationException(
                $"No EntitySchema registered for entity type '{entityTypeName}'. " +
                "Register it in SystemEntitySchemas or use the generic overload.");
    }

    /// <summary>
    /// If a typed factory is registered for this entity (e.g. EntityDefinition),
    /// creates a new typed instance and copies the _values array from the DataRecord.
    /// This allows callers to cast results to the expected typed entity.
    /// Returns the original record if no factory is registered.
    /// </summary>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, bool> _typedFactoryCache = new(StringComparer.OrdinalIgnoreCase);

    private static DataRecord? HydrateTyped(DataRecord? record, string entityTypeName)
    {
        if (record is null) return null;
        var meta = BareMetalWeb.Core.DataScaffold.GetEntityByName(entityTypeName);
        if (meta is null) return record;
        // Check (and cache) whether the factory produces a derived entity type (not plain DataRecord)
        bool isTyped = _typedFactoryCache.GetOrAdd(entityTypeName, _ =>
        {
            var instance = meta.Handlers.Create();
            return instance.GetType() != typeof(DataRecord);
        });
        if (!isTyped) return record;
        var typed = meta.Handlers.Create();
        typed.EnsureCapacity(record.FieldCount);
        System.Array.Copy(record._values, typed._values, record.FieldCount);
        return typed;
    }

    /// <summary>
    /// Ensures <paramref name="obj"/> is a <see cref="DataRecord"/> compatible with
    /// <paramref name="schema"/>.  If it already is one, returns it directly; otherwise
    /// copies base + entity field values into a new record.
    /// </summary>
    private static DataRecord AsDataRecord(DataRecord obj, EntitySchema schema)
    {
        if (obj is DataRecord dr)
        {
            dr.EntityTypeName = schema.EntityName;
            dr.Schema = schema;
            return dr;
        }

        var record = schema.CreateRecord();
        record.Key = obj.Key;
        record.Identifier = obj.Identifier;
        record.CreatedOnUtc = obj.CreatedOnUtc;
        record.UpdatedOnUtc = obj.UpdatedOnUtc;
        record.CreatedBy = obj.CreatedBy;
        record.UpdatedBy = obj.UpdatedBy;
        record.ETag = obj.ETag;
        record.Version = obj.Version;

        int total = DataRecord.BaseFieldCount + schema.FieldCount;
        int copyEnd = Math.Min(total, obj.FieldCount);
        for (int i = DataRecord.BaseFieldCount; i < copyEnd; i++)
        {
            var val = obj.GetFieldValue(i);
            // Flatten string arrays to comma-separated strings for StringUtf8 schema fields
            if (val is string[] arr)
                val = string.Join(",", arr);
            record.SetValue(i, val);
        }

        return record;
    }

    /// <inheritdoc />
    public void Save(string entityTypeName, DataRecord obj)
    {
        if (obj is null) throw new ArgumentNullException(nameof(obj));
        var schema = ResolveSchemaByName(entityTypeName);
        var record = AsDataRecord(obj, schema);
        if (record.Key == 0)
            record.Key = NextSequentialKey(entityTypeName);
        SaveRecord(record, schema);
        obj.Key = record.Key;
        obj.ETag = record.ETag;
        obj.CreatedOnUtc = record.CreatedOnUtc;
        obj.UpdatedOnUtc = record.UpdatedOnUtc;
    }

    /// <inheritdoc />
    public ValueTask SaveAsync(string entityTypeName, DataRecord obj, CancellationToken cancellationToken = default)
    {
        Save(entityTypeName, obj);
        return ValueTask.CompletedTask;
    }

    /// <inheritdoc />
    public DataRecord? Load(string entityTypeName, uint key)
    {
        var schema = ResolveSchemaByName(entityTypeName);
        return HydrateTyped(LoadRecord(key, schema), entityTypeName);
    }

    /// <inheritdoc />
    public ValueTask<DataRecord?> LoadAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default)
        => new(Load(entityTypeName, key));

    /// <inheritdoc />
    public IEnumerable<DataRecord> Query(string entityTypeName, QueryDefinition? query = null)
    {
        var schema = ResolveSchemaByName(entityTypeName);
        var records = QueryRecords(schema, query);
        var meta = BareMetalWeb.Core.DataScaffold.GetEntityByName(entityTypeName);
        if (meta is null) return records;
        bool isTyped = _typedFactoryCache.GetOrAdd(entityTypeName, _ =>
        {
            var instance = meta.Handlers.Create();
            return instance.GetType() != typeof(DataRecord);
        });
        if (!isTyped) return records;
        return HydrateAll(records, entityTypeName);
    }

    private static IEnumerable<DataRecord> HydrateAll(IEnumerable<DataRecord> records, string entityTypeName)
    {
        foreach (var r in records)
            yield return HydrateTyped(r, entityTypeName)!;
    }

    /// <inheritdoc />
    public ValueTask<IEnumerable<DataRecord>> QueryAsync(string entityTypeName, QueryDefinition? query = null, CancellationToken cancellationToken = default)
        => new(Query(entityTypeName, query));

    /// <inheritdoc />
    public int Count(string entityTypeName, QueryDefinition? query = null)
    {
        var schema = ResolveSchemaByName(entityTypeName);
        return CountRecords(schema, query);
    }

    /// <inheritdoc />
    public ValueTask<int> CountAsync(string entityTypeName, QueryDefinition? query = null, CancellationToken cancellationToken = default)
        => new(Count(entityTypeName, query));

    /// <inheritdoc />
    public void Delete(string entityTypeName, uint key)
    {
        var schema = ResolveSchemaByName(entityTypeName);
        DeleteRecord(key, schema);
    }

    /// <inheritdoc />
    public ValueTask DeleteAsync(string entityTypeName, uint key, CancellationToken cancellationToken = default)
    {
        Delete(entityTypeName, key);
        return ValueTask.CompletedTask;
    }

    private static bool MatchesRecordQuery(DataRecord record, EntitySchema schema, QueryDefinition query)
    {
        foreach (var clause in query.Clauses)
        {
            if (!schema.TryGetOrdinal(clause.Field, out var ord)) continue;
            var rawValue = record.GetValue(ord);
            var clauseVal = clause.Value?.ToString() ?? string.Empty;

            // For Contains on array/collection fields, check if any element matches
            if (clause.Operator == QueryOperator.Contains && rawValue is System.Collections.IEnumerable enumerable && rawValue is not string)
            {
                bool found = false;
                foreach (var item in enumerable)
                {
                    if (item != null && string.Equals(item.ToString(), clauseVal, StringComparison.OrdinalIgnoreCase))
                    { found = true; break; }
                }
                if (!found) return false;
                continue;
            }

            var valueStr = rawValue?.ToString() ?? string.Empty;

            bool match = clause.Operator switch
            {
                QueryOperator.Equals => string.Equals(valueStr, clauseVal, StringComparison.OrdinalIgnoreCase),
                QueryOperator.NotEquals => !string.Equals(valueStr, clauseVal, StringComparison.OrdinalIgnoreCase),
                QueryOperator.Contains => valueStr.Contains(clauseVal, StringComparison.OrdinalIgnoreCase),
                QueryOperator.StartsWith => valueStr.StartsWith(clauseVal, StringComparison.OrdinalIgnoreCase),
                QueryOperator.EndsWith => valueStr.EndsWith(clauseVal, StringComparison.OrdinalIgnoreCase),
                QueryOperator.GreaterThan => string.Compare(valueStr, clauseVal, StringComparison.OrdinalIgnoreCase) > 0,
                QueryOperator.LessThan => string.Compare(valueStr, clauseVal, StringComparison.OrdinalIgnoreCase) < 0,
                QueryOperator.GreaterThanOrEqual => string.Compare(valueStr, clauseVal, StringComparison.OrdinalIgnoreCase) >= 0,
                QueryOperator.LessThanOrEqual => string.Compare(valueStr, clauseVal, StringComparison.OrdinalIgnoreCase) <= 0,
                _ => true,
            };
            if (!match) return false;
        }
        return true;
    }

    private static int CompareFieldValues(object? a, object? b)
    {
        if (a is null && b is null) return 0;
        if (a is null) return -1;
        if (b is null) return 1;
        if (a is IComparable ca) return ca.CompareTo(b);
        return string.Compare(a.ToString(), b.ToString(), StringComparison.OrdinalIgnoreCase);
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

        // Use memory-mapped paged file for read-only access (index loading)
        if (access == FileAccess.Read)
        {
            try { return new MappedPagedFile(path, pageSize); }
            catch { /* fall through to FileStream path */ }
        }

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

    public void RenamePagedFile(string entityName, string oldFileName, string newFileName)
    {
        var oldPath = GetPagedFilePath(entityName, oldFileName);
        var newPath = GetPagedFilePath(entityName, newFileName);
        File.Move(oldPath, newPath, overwrite: true);
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
            var fileContext = $"idmap:{typeName}";
            var bytes = EncryptedFileIO.ReadDecrypted(path, fileContext);
            if (bytes.Length < 16) return map;  // header(12) + crc(4)

            var span = bytes.AsSpan();
            if (BinaryPrimitives.ReadUInt32LittleEndian(span)        != IdMapMagic)   return map;
            if (BinaryPrimitives.ReadUInt16LittleEndian(span[4..])   != IdMapVersion) return map;

            uint rawCount = BinaryPrimitives.ReadUInt32LittleEndian(span[8..]);
            if (rawCount > (uint)((bytes.Length - 16) / 12)) return map;
            int entryCount = (int)rawCount;

            // #1169: Reject truncated files that pass the rough check above
            // but are too short for the exact header + entries + CRC layout.
            int expectedSize = 12 + entryCount * 12 + 4;
            if (bytes.Length < expectedSize) return map;

            // Verify CRC over everything except the trailing 4-byte CRC field
            uint storedCrc   = BinaryPrimitives.ReadUInt32LittleEndian(span[^4..]);
            uint computedCrc = WalCrc32C.Compute(span[..^4]);
            if (storedCrc != computedCrc) return map;

            int offset = 12;
            int liveCount = 0;
            bool needsCompaction = false;
            for (int i = 0; i < entryCount; i++)
            {
                if (offset + 12 > bytes.Length - 4) break;
                uint objKey  = BinaryPrimitives.ReadUInt32LittleEndian(span[offset..]); offset += 4;
                ulong walKey = BinaryPrimitives.ReadUInt64LittleEndian(span[offset..]); offset += 8;

                // Skip tombstoned entries — no point loading keys for deleted records
                if (_walStore.TryGetHead(walKey, out var ptr)
                    && _walStore.TryReadOpPayload(ptr, walKey, out var payload)
                    && !payload.IsEmpty)
                {
                    map[objKey] = walKey;
                    liveCount++;
                }
                else
                {
                    needsCompaction = true;
                }
            }

            _liveCounts[typeName] = liveCount;

            // Re-persist without tombstoned entries so future loads are clean
            if (needsCompaction)
                Task.Run(() =>
                {
                    try { PersistIdMap(typeName); }
                    catch (Exception ex) { _logger?.LogError($"Background id-map compaction failed for {typeName}.", ex); }
                });
        }
        catch (IOException) { /* treat file as missing */ }

        return map;
    }

    private void PersistIdMap(string typeName)
    {
        var lockObj = _idMapLocks.GetOrAdd(typeName, _ => new object());
        lock (lockObj)
        {
            PersistIdMapCore(typeName);
        }
    }

    /// <summary>
    /// Inner persist logic — caller must already hold <c>_idMapLocks[typeName]</c>.
    /// </summary>
    private void PersistIdMapCore(string typeName)
    {
        var map = GetOrLoadIdMap(typeName);
        int entryCount = map.Count;
        // Compute total buffer size: header(12) + entries(12 each) + CRC(4)
        int size = 12 + entryCount * 12 + 4;

        // #1160: Use a plain allocation instead of ArrayPool on this cold path
        // to eliminate the race where two threads could receive the same pooled buffer.
        var buf  = new byte[size];
        var span = buf.AsSpan();
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

        // #1167: Atomic write — write to tmp, fsync, then rename so a crash
        // mid-write never corrupts the primary IdMap file.
        var path    = GetIdMapPath(typeName);
        var tmpPath = path + ".tmp";

        // Encrypt at rest when BMW_WAL_ENCRYPTION_KEY is configured
        var fileContext = $"idmap:{typeName}";
        var encrypted = EncryptedFileIO.Encrypt(buf.AsSpan(0, size), fileContext);
        using (var fs = new FileStream(tmpPath, FileMode.Create, FileAccess.Write, FileShare.None))
        {
            fs.Write(encrypted, 0, encrypted.Length);
            fs.Flush(flushToDisk: true);
        }
        File.Move(tmpPath, path, overwrite: true);
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
