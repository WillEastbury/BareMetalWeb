using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Numerics;
using System.Reflection;
using System.Text;
using System.Text.Json;
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
/// Schema versioning follows the same file layout as
/// <see cref="LocalFolderBinaryDataProvider"/> so the two providers can coexist in
/// the same data root with full binary-serializer schema-evolution support.
/// </para>
/// </summary>
public sealed class WalDataProvider : IDataProvider, IRawBinaryProvider, IDisposable
{
    internal static Action<TimeSpan>? OnWalReadComplete;

    // ── Constants ────────────────────────────────────────────────────────────

    private const string WalSubFolder          = "wal";
    private const uint   IdMapMagic            = 0x494D4150u; // "IMAP"
    private const ushort IdMapVersion          = 2;
    private const int    DefaultQueryLimit     = int.MaxValue;
    private const string PagedFolderName       = "Paged";
    private const string PagedFileExtension    = ".page";

    private static readonly HashSet<uint> s_emptyUintSet = new();

    // Monotonic ETag counter — cheaper than Guid.NewGuid() per save
    private static long _etagCounter = DateTime.UtcNow.Ticks;

    // ── Fields ────────────────────────────────────────────────────────────────

    private readonly string                    _rootPath;
    private readonly ISchemaAwareObjectSerializer _serializer;
    private readonly IDataQueryEvaluator       _queryEvaluator;
    private readonly IBufferedLogger?          _logger;
    private WalStore                  _walStore;

    /// <summary>Exposes the underlying WAL store for background services (e.g. compaction).</summary>
    internal WalStore WalStore => _walStore;

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

    // Schema version cache (same pattern as LocalFolderBinaryDataProvider)
    private readonly ConcurrentDictionary<Type, SchemaCache>  _schemaCache  = new();
    private readonly ConcurrentDictionary<Type, object>       _schemaLocks  = new();

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

    /// <summary>
    /// Attach cluster state for write fencing. When set, all writes validate
    /// that this instance is the elected leader before proceeding.
    /// </summary>
    public void SetClusterState(ClusterState clusterState) => _clusterState = clusterState;

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
        _schemaCache.Clear();
        _schemaLocks.Clear();
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
    public bool   CanHandle(Type type)  => true;

    // ── IDataProvider: CRUD ───────────────────────────────────────────────────

    public void Save<T>(T obj) where T : BaseDataObject
    {
        if (obj is null)
            throw new ArgumentNullException(nameof(obj));
        if (obj.Key == 0)
            throw new ArgumentException("DataObject must have a non-zero Key.", nameof(obj));

        ClearSingletonFlagsOnOtherRecords(obj);

        // ── Write fence: validate leader lease before mutating ────────────
        _clusterState?.ValidateWritePermission();

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
                int maxVer = int.MinValue;
                foreach (var k in cache.Versions.Keys)
                {
                    if (k > maxVer) maxVer = k;
                }
                schemaVersion = cache.Versions.Count == 0 ? 1 : maxVer + 1;
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
            bool isInsert = !idMap.ContainsKey(obj.Key);
            T? oldObj    = null;
            List<PropertyInfo> indexedFields = new();
            if (_searchIndexManager.HasIndexedFields(type, out indexedFields) && !isInsert)
                oldObj = Load<T>(obj.Key);

            var bytes  = _serializer.Serialize(obj, schemaVersion);
            var walKey = GetOrAllocateKey(type.Name, obj.Key);

            // Capture old head pointer for cache eviction before commit changes it
            ulong oldPtr = 0;
            if (!isInsert)
                _walStore.TryGetHead(walKey, out oldPtr);

            var commitTask = _walStore.CommitAsync(new[] { WalOp.Upsert(walKey, bytes, encryption: _walStore.Encryption) });
            if (!commitTask.IsCompleted)
                commitTask.GetAwaiter().GetResult();

            PersistIdMap(type.Name);

            // Bump live count on insert (updates don't change count)
            if (isInsert)
                _liveCounts.AddOrUpdate(type.Name, 1, (_, c) => c + 1);

            // Evict stale deserialization cache entry using exact old key
            if (!isInsert && oldPtr != 0)
            {
                var evictKey = (type.Name, obj.Key, oldPtr);
                _deserCache.TryRemove(evictKey, out _);
                _deserCacheAccess.TryRemove(evictKey, out _);
            }

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

            // Update columnar store incrementally: upsert the row so SIMD queries stay hot.
            // Falls back to a full rebuild on the next query if the store hasn't been built yet.
            if (_columnarStores.TryGetValue(type.Name, out var colStore))
            {
                var meta = DataScaffold.GetEntityByType(type);
                if (meta == null || !colStore.UpsertRow(obj, meta))
                    colStore.Invalidate();
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
        var sw = Stopwatch.StartNew();
        if (key == 0)
            throw new ArgumentException("Key cannot be zero.", nameof(key));

        var typeName = typeof(T).Name;
        var idMap    = GetOrLoadIdMap(typeName);

        if (!idMap.TryGetValue(key, out var walKey)) { sw.Stop(); OnWalReadComplete?.Invoke(sw.Elapsed); return default; }
        if (!_walStore.TryGetHead(walKey, out var ptr)) { sw.Stop(); OnWalReadComplete?.Invoke(sw.Elapsed); return default; }

        // Check deserialization cache — hit if WAL pointer unchanged
        var cacheKey = (typeName, key, ptr);
        if (_deserCache.TryGetValue(cacheKey, out var cachedObj))
        {
            _deserCacheAccess[cacheKey] = Environment.TickCount64;
            sw.Stop();
            OnWalReadComplete?.Invoke(sw.Elapsed);
            return cachedObj as T;
        }

        if (!_walStore.TryReadOpPayload(ptr, walKey, out var payload)) { sw.Stop(); OnWalReadComplete?.Invoke(sw.Elapsed); return default; }
        if (payload.IsEmpty) { sw.Stop(); OnWalReadComplete?.Invoke(sw.Elapsed); return default; }

        T? result;
        try
        {
            result = DeserializePayload<T>(payload, key);
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Corrupt payload for {typeName} Key={key} WalPtr={ptr}: {ex.Message}", ex);
            sw.Stop();
            OnWalReadComplete?.Invoke(sw.Elapsed);
            return default;
        }
        if (result != null)
        {
            if (_deserCache.Count >= DeserCacheMaxSize)
                EvictDeserCache();
            _deserCache[cacheKey] = result;
            _deserCacheAccess[cacheKey] = Environment.TickCount64;
        }
        sw.Stop();
        OnWalReadComplete?.Invoke(sw.Elapsed);
        return result;
    }

    private void EvictDeserCache()
    {
        // LRU eviction — remove ~25% of entries with oldest access times.
        // Single-pass min-scan avoids O(n log n) sort on the full cache.
        int toRemove = _deserCache.Count / 4;
        if (toRemove == 0) toRemove = 1;

        var evictKeys = new List<((string TypeName, uint Key, ulong WalPtr) key, long access)>(toRemove);

        foreach (var kvp in _deserCacheAccess)
        {
            if (evictKeys.Count < toRemove)
            {
                evictKeys.Add((kvp.Key, kvp.Value));
                continue;
            }

            // Find the max (youngest) entry in our evict set and replace it
            // if this entry is older (smaller tick count)
            int maxIdx = 0;
            for (int i = 1; i < evictKeys.Count; i++)
                if (evictKeys[i].access > evictKeys[maxIdx].access)
                    maxIdx = i;

            if (kvp.Value < evictKeys[maxIdx].access)
                evictKeys[maxIdx] = (kvp.Key, kvp.Value);
        }

        foreach (var (key, _) in evictKeys)
        {
            _deserCache.TryRemove(key, out _);
            _deserCacheAccess.TryRemove(key, out _);
        }
    }

    public ValueTask<T?> LoadAsync<T>(uint key, CancellationToken cancellationToken = default)
        where T : BaseDataObject
        => ValueTask.FromResult(Load<T>(key));

    // ── IRawBinaryProvider ────────────────────────────────────────────────────

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

        var results = new List<ReadOnlyMemory<byte>>();

        int skip = query?.Skip ?? 0;
        int top  = query?.Top  ?? DefaultQueryLimit;
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

    // ── Query ────────────────────────────────────────────────────────────────

    public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject
    {
        var typeName = typeof(T).Name;
        var idMap    = GetOrLoadIdMap(typeName);
        if (idMap.Count == 0) return Array.Empty<T>();

        var skip = query?.Skip ?? 0;
        var top  = query?.Top  ?? DefaultQueryLimit;
        if (skip < 0) skip = 0;
        if (top <= 0) return Array.Empty<T>();

        // ── Index-accelerated path: use secondary field index for Equals/StartsWith clauses ──
        // Intersects candidate sets from ALL indexed Equals clauses (#758), supports
        // StartsWith via prefix scan on cached index keys (#757), and uses cached
        // index reads (#756).
        if (query != null && query.Clauses.Count > 0 && query.Groups.Count == 0
            && _searchIndexManager.HasIndexedFields(typeof(T), out var indexedFields))
        {
            HashSet<uint>? candidateIds = null;
            int indexedClauseCount = 0;

            foreach (var clause in query.Clauses)
            {
                if (clause.Value == null) continue;
                var prop = indexedFields.Find(p => string.Equals(p.Name, clause.Field, StringComparison.OrdinalIgnoreCase));
                if (prop == null) continue;

                HashSet<uint>? clauseCandidates = null;

                if (clause.Operator == QueryOperator.Equals)
                {
                    var fieldValue = clause.Value.ToString() ?? string.Empty;
                    var fieldIndex = _indexStore.ReadIndex(typeName, prop.Name);
                    if (fieldIndex.Count == 0) break;
                    clauseCandidates = fieldIndex.TryGetValue(fieldValue, out var ids) ? ids : s_emptyUintSet;
                }
                else if (clause.Operator == QueryOperator.StartsWith)
                {
                    var prefix = clause.Value.ToString() ?? string.Empty;
                    var fieldIndex = _indexStore.ReadIndex(typeName, prop.Name);
                    if (fieldIndex.Count == 0) break;
                    clauseCandidates = new HashSet<uint>(16);
                    foreach (var kvp in fieldIndex)
                    {
                        if (kvp.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                            clauseCandidates.UnionWith(kvp.Value);
                    }
                }

                if (clauseCandidates == null) continue;
                indexedClauseCount++;

                if (candidateIds == null)
                    candidateIds = new HashSet<uint>(clauseCandidates);
                else
                    candidateIds.IntersectWith(clauseCandidates);

                if (candidateIds.Count == 0)
                    return Array.Empty<T>();
            }

            if (candidateIds != null && indexedClauseCount > 0)
            {
                var hasSorts = query.Sorts.Count > 0;
                bool needRecheck = indexedClauseCount < query.Clauses.Count;

                if (!hasSorts)
                {
                    var results = new List<T>(Math.Min(top, candidateIds.Count));
                    int matched = 0;
                    foreach (var candidateKey in candidateIds)
                    {
                        var obj = Load<T>(candidateKey);
                        if (obj == null) continue;
                        if (needRecheck && !_queryEvaluator.Matches(obj, query)) continue;
                        if (matched < skip) { matched++; continue; }
                        results.Add(obj);
                        matched++;
                        if (results.Count >= top) break;
                    }
                    return results;
                }

                // Has sorts — load intersected candidates, sort, then slice
                var loaded = new List<T>(candidateIds.Count);
                foreach (var candidateKey in candidateIds)
                {
                    var obj = Load<T>(candidateKey);
                    if (obj != null)
                        loaded.Add(obj);
                }

                List<T> filtered;
                if (needRecheck)
                {
                    filtered = new List<T>(loaded.Count);
                    foreach (var item in loaded)
                    {
                        if (_queryEvaluator.Matches(item, query))
                            filtered.Add(item);
                    }
                }
                else
                {
                    filtered = loaded;
                }
                var sortedList = new List<T>();
                foreach (var item in _queryEvaluator.ApplySorts(filtered, query))
                    sortedList.Add(item);
                if (skip > 0 || top != DefaultQueryLimit)
                {
                    int end = Math.Min(skip + top, sortedList.Count);
                    var paged = new List<T>(Math.Max(0, end - skip));
                    for (int i = skip; i < end; i++)
                        paged.Add(sortedList[i]);
                    return paged;
                }
                return sortedList;
            }
        }
        // ── Full scan (no usable index) ───────────────────────────────────────

        // ── No filter, no sort — idMap is tombstone-free, keys are sequential,
        //    just skip N entries and deserialize only the page ───────────────
        if (query == null || (query.Clauses.Count == 0 && query.Groups.Count == 0 && query.Sorts.Count == 0))
        {
            var pageResults = new List<T>(Math.Min(top, idMap.Count));
            int seen = 0;
            foreach (var (objKey, _) in idMap)
            {
                if (seen < skip) { seen++; continue; }
                var obj = Load<T>(objKey);
                if (obj != null) pageResults.Add(obj);
                seen++;
                if (pageResults.Count >= top) break;
            }
            return pageResults;
        }

        // ── Index-accelerated sort path ──────────────────────────────────────
        // When the only reason we can't short-circuit is a sort, and the sort
        // field is either "Key" or an indexed field, pre-sort the keys without
        // deserializing all entities, then load only the page (skip+top).
        if (query != null && query.Sorts.Count > 0 && query.Clauses.Count == 0 && query.Groups.Count == 0)
        {
            var sort = query.Sorts[0];

            // Sort by Key — idMap is tombstone-free, keys are sequential uint32s.
            // Asc: stream skip/take directly. Desc: collect, reverse, slice.
            if (string.Equals(sort.Field, "Key", StringComparison.OrdinalIgnoreCase))
            {
                if (sort.Direction == SortDirection.Desc)
                {
                    var allKeys = new List<uint>(idMap.Count);
                    foreach (var (objKey, _) in idMap)
                        allKeys.Add(objKey);
                    allKeys.Reverse();
                    int descEnd = Math.Min(skip + top, allKeys.Count);
                    var descResults = new List<T>(Math.Max(0, descEnd - skip));
                    for (int i = skip; i < descEnd; i++)
                    {
                        var obj = Load<T>(allKeys[i]);
                        if (obj != null) descResults.Add(obj);
                    }
                    return descResults;
                }
                else
                {
                    var ascResults = new List<T>(Math.Min(top, idMap.Count));
                    int ascSeen = 0;
                    foreach (var (objKey, _) in idMap)
                    {
                        if (ascSeen < skip) { ascSeen++; continue; }
                        var obj = Load<T>(objKey);
                        if (obj != null) ascResults.Add(obj);
                        ascSeen++;
                        if (ascResults.Count >= top) break;
                    }
                    return ascResults;
                }
            }

            // Sort by an indexed field — use forward index to sort keys by value
            if (_searchIndexManager.HasIndexedFields(typeof(T), out var sortIndexedFields))
            {
                var sortProp = sortIndexedFields.Find(p => string.Equals(p.Name, sort.Field, StringComparison.OrdinalIgnoreCase));
                if (sortProp != null)
                {
                    var forwardIndex = _indexStore.ReadLatestValueIndex(typeName, sortProp.Name);
                    if (forwardIndex.Count > 0)
                    {
                        var keysWithValues = new List<(uint Key, string Value)>(idMap.Count);
                        foreach (var (objKey, _) in idMap)
                        {
                            var keyStr = objKey.ToString();
                            forwardIndex.TryGetValue(keyStr, out var fieldVal);
                            keysWithValues.Add((objKey, fieldVal ?? string.Empty));
                        }

                        keysWithValues.Sort((a, b) =>
                        {
                            var cmp = string.Compare(a.Value, b.Value, StringComparison.OrdinalIgnoreCase);
                            return sort.Direction == SortDirection.Desc ? -cmp : cmp;
                        });

                        int sortEnd = Math.Min(skip + top, keysWithValues.Count);
                        var sortResults = new List<T>(Math.Max(0, sortEnd - skip));
                        for (int i = skip; i < sortEnd; i++)
                        {
                            var obj = Load<T>(keysWithValues[i].Key);
                            if (obj != null)
                                sortResults.Add(obj);
                        }
                        return sortResults;
                    }
                }
            }
        }

        // ── Fallback: filter/sort on non-indexed fields ─────────────────────
        var canShortCircuit = query == null || query.Sorts.Count == 0;

        // ── Columnar store path: SIMD scan over pre-built typed arrays ──────
        // Avoids loading all objects just to extract columns — scans arrays
        // directly, then loads only matching rows.
        if (query != null
            && idMap.Count >= ColumnQueryExecutor.VectorizationThreshold
            && query.Groups.Count == 0
            && query.Clauses.Count > 0)
        {
            var meta = DataScaffold.GetEntityByType(typeof(T));
            if (meta != null)
            {
                var store = GetOrBuildColumnarStore<T>(typeName, idMap, meta);
                if (store != null && store.RowCount >= ColumnQueryExecutor.VectorizationThreshold)
                {
                    // Check if all clauses can be served by columnar store
                    bool allColumnar = true;
                    foreach (var clause in query.Clauses)
                    {
                        if (string.IsNullOrEmpty(clause.Field) || !store.HasColumn(clause.Field))
                        {
                            allColumnar = false;
                            break;
                        }
                    }

                    if (allColumnar)
                    {
                        // Use Capacity (= HighWater) as the scan range — covers all allocated
                        // ordinals including reused slots.  ScanWordCount accounts for freed
                        // slots between live rows; the validity mask in ScanClause ensures
                        // freed ordinals never appear in results.
                        int n         = store.Capacity;
                        int wordCount = store.ScanWordCount;
                        ulong[]? combined = null;

                        foreach (var clause in query.Clauses)
                        {
                            var clauseMask = store.ScanClause(clause.Field, clause.Operator, clause.Value, wordCount);
                            if (clauseMask == null) { combined = new ulong[wordCount]; break; }

                            if (combined == null)
                                combined = clauseMask;
                            else
                                AndBitmaskInPlace(combined, clauseMask);
                        }

                        // Materialise matching rows — only load objects that passed the filter
                        var results = new List<T>(Math.Min(top, n));
                        int matched = 0;

                        if (combined != null)
                        {
                            for (int wordIdx = 0; wordIdx < combined.Length && results.Count < top; wordIdx++)
                            {
                                ulong word = combined[wordIdx];
                                while (word != 0)
                                {
                                    int bit = BitOperations.TrailingZeroCount(word);
                                    int rowIdx = (wordIdx << 6) | bit;
                                    word &= word - 1;

                                    if (rowIdx >= n) break;

                                    uint objKey = store.GetKeyAtRow(rowIdx);
                                    if (objKey == 0) continue; // defensive: freed ordinals are already masked by the validity bitmap

                                    if (matched++ < skip) continue;
                                    try
                                    {
                                        T? obj = Load<T>(objKey);
                                        if (obj != null)
                                        {
                                            if (canShortCircuit)
                                            {
                                                results.Add(obj);
                                            }
                                            else
                                            {
                                                results.Add(obj); // will sort below
                                            }
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        _logger?.LogError($"Deserialization failed for {typeName} Key {objKey}.", ex);
                                    }

                                    if (canShortCircuit && results.Count >= top) break;
                                }
                            }
                        }

                        if (canShortCircuit)
                            return results;

                        // With sorts: sort filtered results, then slice
                        var sortedList = new List<T>(_queryEvaluator.ApplySorts(results, query));
                        if (skip > 0 || top != int.MaxValue)
                        {
                            int end = Math.Min(skip + top, sortedList.Count);
                            var paged = new List<T>(Math.Max(0, end - skip));
                            for (int i = skip; i < end; i++) paged.Add(sortedList[i]);
                            return paged;
                        }
                        return sortedList;
                    }
                }
            }
        }

        // ── Vectorised path: pre-load all objects, then apply SIMD column scan ──
        // Fallback when columnar store doesn't cover all clauses.
        if (query != null
            && idMap.Count >= ColumnQueryExecutor.VectorizationThreshold
            && query.Groups.Count == 0
            && query.Clauses.Count > 0)
        {
            var allObjects = new List<T>(idMap.Count);
            foreach (var (objKey, _) in idMap)
            {
                T? obj;
                try { obj = Load<T>(objKey); }
                catch (Exception ex)
                {
                    _logger?.LogError($"Deserialization failed for {typeName} with Key {objKey}.", ex);
                    continue;
                }
                if (obj != null) allObjects.Add(obj);
            }

            if (canShortCircuit)
            {
                return ColumnQueryExecutor.Filter(allObjects, query, skip, top);
            }

            // With sorts: filter first (vectorised), then sort, then slice.
            var filtered = ColumnQueryExecutor.Filter(allObjects, query);
            var sortedList = new List<T>(_queryEvaluator.ApplySorts(filtered, query));
            if (skip > 0 || top != int.MaxValue)
            {
                int end = Math.Min(skip + top, sortedList.Count);
                var paged = new List<T>(Math.Max(0, end - skip));
                for (int i = skip; i < end; i++) paged.Add(sortedList[i]);
                return paged;
            }
            return sortedList;
        }

        var scanResults     = new List<T>(Math.Min(top, idMap.Count));
        int scanMatched     = 0;

        foreach (var (objKey, _) in idMap)
        {
            T? obj;
            try
            {
                obj = Load<T>(objKey);
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
                if (scanMatched < skip) { scanMatched++; continue; }
                scanResults.Add(obj);
                scanMatched++;
                if (scanResults.Count >= top) break;
            }
            else
            {
                scanResults.Add(obj);
            }
        }

        if (!canShortCircuit)
        {
            var sortedList = new List<T>();
            foreach (var item in _queryEvaluator.ApplySorts(scanResults, query))
                sortedList.Add(item);
            if (skip > 0 || top != int.MaxValue)
            {
                int end = Math.Min(skip + top, sortedList.Count);
                var paged = new List<T>(Math.Max(0, end - skip));
                for (int i = skip; i < end; i++)
                    paged.Add(sortedList[i]);
                return paged;
            }
            return sortedList;
        }

        return scanResults;
    }

    public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null,
        CancellationToken cancellationToken = default) where T : BaseDataObject
        => ValueTask.FromResult(Query<T>(query));

    public int Count<T>(QueryDefinition? query = null) where T : BaseDataObject
    {
        var typeName = typeof(T).Name;
        var idMap    = GetOrLoadIdMap(typeName);
        if (idMap.Count == 0) return 0;

        // Fast-path: no filter — use cached live count (O(1)), seed on first call
        if (query == null || (query.Clauses.Count == 0 && query.Groups.Count == 0))
        {
            return _liveCounts.GetOrAdd(typeName, _ =>
            {
                int live = 0;
                foreach (var (__, walKey) in idMap)
                {
                    if (!_walStore.TryGetHead(walKey, out var ptr)) continue;
                    if (!_walStore.TryReadOpPayload(ptr, walKey, out var payload)) continue;
                    if (!payload.IsEmpty) live++;
                }
                return live;
            });
        }

        // ── Index-accelerated count: Equals/StartsWith with compound intersection ──
        if (query.Clauses.Count > 0 && query.Groups.Count == 0
            && _searchIndexManager.HasIndexedFields(typeof(T), out var indexedFields))
        {
            HashSet<uint>? candidateIds = null;
            int indexedClauseCount = 0;

            foreach (var clause in query.Clauses)
            {
                if (clause.Value == null) continue;
                var prop = indexedFields.Find(p => string.Equals(p.Name, clause.Field, StringComparison.OrdinalIgnoreCase));
                if (prop == null) continue;

                HashSet<uint>? clauseCandidates = null;

                if (clause.Operator == QueryOperator.Equals)
                {
                    var fieldValue = clause.Value.ToString() ?? string.Empty;
                    var fieldIndex = _indexStore.ReadIndex(typeName, prop.Name);
                    if (fieldIndex.Count == 0) break;
                    clauseCandidates = fieldIndex.TryGetValue(fieldValue, out var ids) ? ids : s_emptyUintSet;
                }
                else if (clause.Operator == QueryOperator.StartsWith)
                {
                    var prefix = clause.Value.ToString() ?? string.Empty;
                    var fieldIndex = _indexStore.ReadIndex(typeName, prop.Name);
                    if (fieldIndex.Count == 0) break;
                    clauseCandidates = new HashSet<uint>(16);
                    foreach (var kvp in fieldIndex)
                    {
                        if (kvp.Key.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                            clauseCandidates.UnionWith(kvp.Value);
                    }
                }

                if (clauseCandidates == null) continue;
                indexedClauseCount++;

                if (candidateIds == null)
                    candidateIds = new HashSet<uint>(clauseCandidates);
                else
                    candidateIds.IntersectWith(clauseCandidates);

                if (candidateIds.Count == 0) return 0;
            }

            if (candidateIds != null && indexedClauseCount > 0)
            {
                // All clauses indexed — direct count
                if (indexedClauseCount == query.Clauses.Count)
                    return candidateIds.Count;

                // Partial — load intersected set, match remaining
                int count = 0;
                foreach (var candidateKey in candidateIds)
                {
                    var obj = Load<T>(candidateKey);
                    if (obj != null && _queryEvaluator.Matches(obj, query))
                        count++;
                }
                return count;
            }
        }

        // Count matching items — idMap is tombstone-free, deserialize and match
        int fullCount = 0;
        foreach (var (objKey, _) in idMap)
        {
            T? obj;
            try
            {
                obj = Load<T>(objKey);
            }
            catch
            {
                continue;
            }

            if (obj != null && _queryEvaluator.Matches(obj, query))
                fullCount++;
        }
        return fullCount;
    }

    public ValueTask<int> CountAsync<T>(QueryDefinition? query = null,
        CancellationToken cancellationToken = default) where T : BaseDataObject
        => ValueTask.FromResult(Count<T>(query));

    public void Delete<T>(uint key) where T : BaseDataObject
    {
        if (key == 0)
            throw new ArgumentException("Key cannot be zero.", nameof(key));

        // ── Write fence: validate leader lease before mutating ────────────
        _clusterState?.ValidateWritePermission();

        var type     = typeof(T);
        var typeName = type.Name;
        var idMap    = GetOrLoadIdMap(typeName);
        if (!idMap.TryGetValue(key, out var walKey)) return;

        // Capture old head pointer for cache eviction before commit
        _walStore.TryGetHead(walKey, out ulong oldPtr);

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

        // Decrement live count
        _liveCounts.AddOrUpdate(typeName, 0, (_, c) => Math.Max(0, c - 1));

        // Evict deserialization cache entry using exact old key
        if (oldPtr != 0)
        {
            var evictKey = (typeName, key, oldPtr);
            _deserCache.TryRemove(evictKey, out _);
            _deserCacheAccess.TryRemove(evictKey, out _);
        }

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

        // Update columnar store incrementally: remove the row so SIMD queries stay hot.
        if (_columnarStores.TryGetValue(typeName, out var colStore))
            colStore.RemoveRow(key);
    }

    public ValueTask DeleteAsync<T>(uint key, CancellationToken cancellationToken = default)
        where T : BaseDataObject
    {
        Delete<T>(key);
        return ValueTask.CompletedTask;
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

    private readonly ConcurrentDictionary<string, MetadataWireSerializer.FieldPlan[]> _recordPlans
        = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, int> _recordSchemaVersions
        = new(StringComparer.OrdinalIgnoreCase);
    private MetadataWireSerializer? _metaSerializer;

    private MetadataWireSerializer GetMetaSerializer()
    {
        if (_metaSerializer != null) return _metaSerializer;
        byte[] key;
        if (_serializer is BinaryObjectSerializer bos)
            key = bos.GetSigningKeyCopy();
        else
            key = new byte[32];
        _metaSerializer = new MetadataWireSerializer(key);
        return _metaSerializer;
    }

    private MetadataWireSerializer.FieldPlan[] GetOrBuildRecordPlan(EntitySchema schema)
    {
        return _recordPlans.GetOrAdd(schema.EntityName, _ =>
        {
            var descriptors = schema.BuildFieldPlanDescriptors();
            return MetadataWireSerializer.BuildPlanUncached(descriptors);
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
        record.ETag = Interlocked.Increment(ref _etagCounter).ToString("x");

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
            var serializer = GetMetaSerializer();
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
                var newValue = record.GetValue(i)?.ToString() ?? string.Empty;
                if (oldRecord != null)
                {
                    var oldValue = oldRecord.GetValue(i)?.ToString() ?? string.Empty;
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
            var serializer = GetMetaSerializer();
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

        var results = new List<DataRecord>();
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
                var value = oldRecord.GetValue(i)?.ToString() ?? string.Empty;
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

    private static bool MatchesRecordQuery(DataRecord record, EntitySchema schema, QueryDefinition query)
    {
        foreach (var clause in query.Clauses)
        {
            if (!schema.TryGetOrdinal(clause.Field, out var ord)) continue;
            var valueStr = record.GetValue(ord)?.ToString() ?? string.Empty;
            var clauseVal = clause.Value?.ToString() ?? string.Empty;

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
                Task.Run(() => PersistIdMap(typeName));
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
        {
            int maxVersion = int.MinValue;
            foreach (var key in cache.Versions.Keys)
            {
                if (key > maxVersion) maxVersion = key;
            }
            cache.CurrentVersion = maxVersion;
        }

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
            return JsonSerializer.Deserialize(bytes, BmwDataJsonContext.Default.SchemaDefinitionFile);
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
        var bytes = JsonSerializer.SerializeToUtf8Bytes(schema, BmwDataJsonContext.Default.SchemaDefinitionFile);
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
            Members      = BuildMemberSignatureFiles(schema.Members)
        };

    private static List<MemberSignatureFile> BuildMemberSignatureFiles(MemberSignature[] members)
    {
        var list = new List<MemberSignatureFile>(members.Length);
        for (int i = 0; i < members.Length; i++)
        {
            var m = members[i];
            list.Add(new MemberSignatureFile
            {
                Name          = m.Name,
                TypeName      = m.TypeName,
                BlittableSize = m.BlittableSize,
            });
        }
        return list;
    }

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

    /// <summary>
    /// Gets or lazily builds a columnar store for the given entity type.
    /// Returns null if building fails (e.g. no numeric fields).
    /// </summary>
    private ColumnarStore? GetOrBuildColumnarStore<T>(
        string typeName,
        ConcurrentDictionary<uint, ulong> idMap,
        DataEntityMetadata meta) where T : BaseDataObject
    {
        var store = _columnarStores.GetOrAdd(typeName, _ => new ColumnarStore(idMap.Count));
        var lastVersion = _columnarVersions.GetOrAdd(typeName, -1L);

        // Rebuild if stale (version changed due to Save/Delete)
        if (lastVersion != store.Version || store.RowCount == 0)
        {
            var allObjects = new List<T>(idMap.Count);
            foreach (var (objKey, _) in idMap)
            {
                try
                {
                    T? obj = Load<T>(objKey);
                    if (obj != null) allObjects.Add(obj);
                }
                catch (Exception ex)
                {
                    _logger?.LogError($"Columnar build: deserialization failed for {typeName} Key {objKey}.", ex);
                }
            }

            if (allObjects.Count < ColumnQueryExecutor.VectorizationThreshold)
                return null;

            store.Build(allObjects, meta);
            _columnarVersions[typeName] = store.Version;
        }

        return store;
    }

    /// <summary>SIMD-accelerated bitmask AND (same as ColumnQueryExecutor.AndInPlace).</summary>
    private static void AndBitmaskInPlace(ulong[] dest, ulong[] src)
    {
        int vLen = Vector<ulong>.Count;
        int i = 0;
        for (; i <= dest.Length - vLen; i += vLen)
        {
            var d = new Vector<ulong>(dest, i);
            var s = new Vector<ulong>(src, i);
            (d & s).CopyTo(dest, i);
        }
        for (; i < dest.Length; i++) dest[i] &= src[i];
    }

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
        {
            var members = schemaFile.Members;
            var arr = new MemberSignature[members.Count];
            for (int i = 0; i < members.Count; i++)
            {
                var m = members[i];
                arr[i] = new MemberSignature(
                    m.Name, m.TypeName,
                    AssumePublicMembers(_serializer.ResolveTypeName(m.TypeName)),
                    m.BlittableSize);
            }
            return arr;
        });

        var arch   = ParseArchitecture(schemaFile.Architecture);
        var schema = _serializer.CreateSchema(schemaFile.Version, schemaMembers, arch, schemaFile.Hash);

        // Use .Span to avoid allocating an intermediate byte[] copy
        if (_serializer is BinaryObjectSerializer bin)
            return bin.Deserialize<T>(memory.Span, schema, SchemaReadMode.BestEffort);
        return _serializer.Deserialize<T>(memory.Span, schema);
    }

    // ── Singleton-flag enforcement ────────────────────────────────────────────

    private void ClearSingletonFlagsOnOtherRecords<T>(T obj) where T : BaseDataObject
    {
        var type           = typeof(T);
        var allProps = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);
        var singletonProps = new List<PropertyInfo>();
        foreach (var p in allProps)
        {
            if (p.PropertyType == typeof(bool)
                && p.GetCustomAttribute<SingletonFlagAttribute>() != null
                && p.CanRead && p.CanWrite
                && true.Equals(p.GetValue(obj)))
            {
                singletonProps.Add(p);
            }
        }

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
