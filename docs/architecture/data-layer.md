# Data Layer & Storage Architecture

This document covers BareMetalWeb's data storage, entity registration, CRUD lifecycle, and virtual entity system.

---

## Storage Stack

Two `IDataProvider` implementations ship out of the box.  `Program.cs` (`CreateDataStore`) selects one at startup.

### LocalFolderBinaryDataProvider (classic)

```mermaid
graph TD
    Consumer["Route handler / service"] -->|IDataObjectStore| DSP["DataStoreProvider<br/>(static singleton)"]
    DSP -->|PrimaryProvider| LFB["LocalFolderBinaryDataProvider<br/>(IDataProvider)"]
    LFB -->|serialize| BOS["BinaryObjectSerializer<br/>(ISchemaAwareObjectSerializer)"]
    LFB -->|extent files| FS["File system<br/>{dataRoot}/{EntityType}/{id}.bin"]
    LFB -->|secondary indexes| SIM["SearchIndexManager"]
    SIM -->|binary .idx files| FS2["File system<br/>{dataRoot}/{EntityType}/_idx/{field}.idx"]
    LFB -->|sequential IDs| SeqID["_seqid.dat<br/>(int64 binary)"]
    BOS -->|schema versioning| SHA["Field hash registry<br/>(schema evolution)"]
```

### WalDataProvider (WAL-backed)

```mermaid
graph TD
    Consumer["Route handler / service"] -->|IDataObjectStore| DSP["DataStoreProvider<br/>(static singleton)"]
    DSP -->|PrimaryProvider| WAL["WalDataProvider<br/>(IDataProvider)"]
    WAL -->|write/read| WS["WalStore<br/>({dataRoot}/wal/)"]
    WS -->|segment files| SEG["WalSegmentWriter / WalSegmentReader<br/>(append-only segments)"]
    WAL -->|id mapping| IDMap["Per-entity _idmap.bin<br/>(string ID → packed ulong WAL key)"]
    WAL -->|schema files| BOS["BinaryObjectSerializer<br/>(shared with LocalFolderBinaryDataProvider)"]
    WAL -->|secondary field indexes| IS["IndexStore<br/>({dataRoot}/Paged/{Entity}/{field}_index.page)"]
    WAL -->|full-text search| SIM["SearchIndexManager<br/>({dataRoot}/indexes/)"]
```

**Key points:**
- `DataStoreProvider.Current` is the one-stop shop for all data access.
- `LocalFolderBinaryDataProvider` stores each entity instance as a single binary file, grouped by entity type.  Used when WAL is not configured.
- `WalDataProvider` stores all records as commit-log payloads inside a `WalStore` at `{dataRoot}/wal/`.  Each entity type gets a stable `uint32` table-ID derived from the type name; each string record-ID is mapped to a monotonic `uint32` record-ID via a per-entity `_idmap.bin` file, giving a packed `ulong` key consumed by the WAL store.
- **Striped head map** — `WalStore` holds a `WalHeadMap` that tracks the latest committed WAL pointer for every live key.  The map is partitioned into `N` independent shards (default 16, configurable power-of-two) keyed by `tableId & shardMask` (upper 32 bits of the packed key).  Each shard carries its own `ReaderWriterLockSlim` and a pair of sorted `ulong[]` arrays.  Reads (`TryGetHead`) and writes (`BatchSetHeads`) touch only the shard(s) relevant to the keys involved, so concurrent reads against different entity types never contend on the same lock stripe.  The `CopyArrays` snapshot helper merges all shards into a single globally-sorted array for checkpoint writes.
- `WalDataProvider` maintains secondary field indexes via `IndexStore` (paged files under `{dataRoot}/Paged/`) and `SearchIndexManager` for full-text search. `Query<T>` consults `IndexStore` for `Equals` clauses on `[DataIndex]`-decorated fields before falling back to a full WAL scan, reducing deserializations from O(n) to O(matches).
- Schema evolution is handled via `SchemaReadMode.BestEffort` in both providers: old records with extra/missing fields still load; new fields receive default values.
- Schema files are shared between the two providers so they can coexist in the same data root.
- `LocalPagedFile` is a shared `internal` class (extracted from `LocalFolderBinaryDataProvider`) used by both providers to implement `IPagedFile` paged file storage for `IndexStore`.

---

## Entity Registration Pipeline

```mermaid
flowchart TD
    A["[DataEntity] attribute<br/>on a class"] --> B["DataEntityRegistry.RegisterAllEntities()<br/>(startup, reflection scan)"]
    B --> C["DataEntityRegistry.Entities list<br/>(DataEntityAttribute metadata)"]
    C --> D["DataScaffold.Entities<br/>(compiled field metadata)"]
    D --> E["DataScaffold.BuildEntityHtml()<br/>(form HTML fragments)"]
    D --> F["DataScaffold.BuildEntityListHtml()<br/>(list HTML fragments)"]

    VE["virtualEntities.json"] --> VL["VirtualEntityLoader.LoadFromFile()"]
    VL --> VJStore["VirtualEntityJsonStore<br/>(IDataProvider for virtual types)"]
    VL --> DSP2["DataScaffold.RegisterVirtualEntity()"]
    VJStore --> FS3["File system<br/>{dataRoot}/virtual/{entity}/{id}.json"]
```

### Runtime Entity Definitions

```mermaid
flowchart TD
    RDef["EntityDefinition<br/>(stored as BaseDataObject)"] --> RReg["RuntimeEntityRegistry.BuildAsync()"]
    RReg --> RC["RuntimeEntityCompiler.Compile()"]
    RC --> RM["RuntimeEntityModel<br/>(frozen at startup)"]
    RM --> Routes["/meta/entity/{name}<br/>POST /query<br/>POST /intent"]
```

### Gallery-First Mode (default)

Gallery-first mode (`Data:LoadCompiledEntities=false`, the default) boots the
server with only system entities registered via metadata.  Application entities
are deployed from gallery packages through the admin UI.

```mermaid
flowchart TD
    Boot["Server startup"] --> Sys["Register 10 system entities<br/>(User, UserSession, AuditEntry,<br/>AppSetting, ReportDefinition, …)"]
    Sys --> Build["RuntimeEntityRegistry.BuildAsync()"]
    Build --> Ready["Server ready<br/>(no application entities)"]
    Ready --> Setup["POST /setup<br/>→ redirect to /admin/gallery"]
    Setup --> Deploy["Deploy gallery package<br/>(e.g. todo, sales, employee)"]
    Deploy --> Rebuild["RuntimeEntityRegistry.RebuildAsync()<br/>(hot-reload, atomic swap)"]
    Rebuild --> Live["New entities live<br/>(CRUD + admin UI)"]
```

**Key behaviours:**
- `LoadCompiledEntities=true` restores classic mode: all `[DataEntity]`-decorated
  classes are registered via `DataEntityRegistry.RegisterAllEntities()` at startup.
- `RebuildAsync()` caches the init parameters from the first `BuildAsync()` call
  and re-runs `BuildCoreAsync` to pick up newly deployed `EntityDefinition` records.
  Entity lists are atomically swapped — no restart required.
- Setup wizard redirects to `/admin/gallery` after creating the root user so
  new installations are guided to deploy modules.
- Sample data generation requires compiled entities (`LoadCompiledEntities=true`);
  in gallery-first mode the UI directs users to deploy modules from the gallery.

### DataRecord + EntitySchema (ordinal-indexed storage)

`DataRecord` is a `BaseDataObject` subclass that stores field values in an
ordinal-indexed `object?[]` array. `EntitySchema` provides the parallel-array
type descriptor (shared per entity type, not per instance).

```
EntitySchema (per type, shared):
  string[]     Names         Names[ord] → "Email"
  FieldType[]  Types         Types[ord] → StringUtf8
  Type[]       ClrTypes      ClrTypes[ord] → typeof(string)
  bool[]       IsNullable    IsNullable[ord] → false
  bool[]       IsRequired    IsRequired[ord] → true
  bool[]       IsIndexed     IsIndexed[ord] → true
  int[]        MaxLengths    MaxLengths[ord] → 255
  FrozenDictionary<string,int>  NameToOrdinal  (boundary only)

DataRecord (per instance):
  object?[]    _values       _values[ord] → "alice@x.com"
```

**Performance:** ~1–2 ns per field access (array index = base pointer + offset),
matching compiled C# property access and 25–50× faster than dictionary lookup.

**AOT-safe:** FieldPlan getter/setter closures capture the ordinal — no
`Expression.Lambda().Compile()`, no `PropertyInfo`, fully Native AOT compatible.
BaseDataObject structural properties (Key, timestamps, audit trail, ETag, Version)
are serialized as a prefix via dedicated closures — no Activator.CreateInstance.

`EntitySchemaFactory.FromModel(RuntimeEntityModel)` bridges the runtime
compilation pipeline to the data layer.

### WAL Storage for DataRecord

`WalDataProvider` provides non-generic save/load/query/delete methods for
`DataRecord` entities:

- `SaveRecord(DataRecord, EntitySchema)` — serializes via `MetadataWireSerializer`
  with FieldPlan closures, commits to WAL, updates secondary indexes
- `LoadRecord(uint key, EntitySchema)` — reads WAL payload, deserializes into
  pre-created `DataRecord` via `DeserializeInto()` (AOT-safe, no `Activator.CreateInstance`)
- `QueryRecords(EntitySchema, QueryDefinition?)` — full scan with ordinal-based
  clause matching, sorting, and paging
- `DeleteRecord(uint key, EntitySchema)` — WAL tombstone, index cleanup
- All methods share the same deser cache as generic `Load<T>`, keyed by
  `(entityName, key, walPointer)`

---

## CRUD Lifecycle

```mermaid
sequenceDiagram
    participant H as Route handler
    participant SC as DataScaffold
    participant CF as CalculatedFieldService
    participant DS as DataStoreProvider
    participant LFB as LocalFolderBinaryDataProvider
    participant SIM as SearchIndexManager
    participant BOS as BinaryObjectSerializer

    H->>SC: Validate form fields (DataField rules)
    H->>CF: EvaluateCalculatedFieldsAsync(entity)
    H->>DS: Save(entity)
    DS->>LFB: Save(entity)
    LFB->>BOS: Serialize(entity) → byte[]
    LFB->>FS: Write {id}.bin
    loop For each [DataIndex] field
        LFB->>SIM: IndexObject(entity)
        SIM->>IndexStore: AppendEntry(field, value, id)
        IndexStore->>FS: Append to {field}.idx
    end
    LFB->>AuditLog: Record change (if AuditEntry enabled)
    LFB-->>DS: success
    DS-->>H: saved entity
```

### Delete Lifecycle

```mermaid
sequenceDiagram
    participant H as Route handler
    participant DS as DataStoreProvider
    participant LFB as LocalFolderBinaryDataProvider
    participant SIM as SearchIndexManager

    H->>DS: Delete<T>(id)
    DS->>LFB: Delete(type, id)
    LFB->>FS: Remove {id}.bin
    loop For each [DataIndex] field
        LFB->>SIM: RemoveObject(type, id)
        SIM->>IndexStore: AppendEntry('D', id)
    end
```

---

## Field Metadata & Computed Fields

```mermaid
graph LR
    DF["[DataField] attribute"] --> FMD["DataFieldMetadata<br/>(name, type, required, …)"]
    DL["[DataLookup] attribute"] --> LMD["LookupConfig<br/>(entity slug, display field, copy fields)"]
    CA["[CalculatedField] attribute"] --> CFS["CalculatedFieldService<br/>(ExpressionNode evaluation)"]
    CF2["[ComputedField] attribute"] --> CFC["ComputedFieldService<br/>(async snapshots / live lookups)"]
    CP["[CopyFromParent] attribute"] --> CPH["Pre-fill child modal<br/>from parent entity"]

    FMD --> Scaffold["DataScaffold<br/>(form + list HTML generation)"]
    LMD --> Scaffold
    CFS --> Scaffold
    CF2 --> Scaffold
    CP --> Scaffold
```

---

## Binary Serializer Format

```mermaid
graph LR
    Obj["BaseDataObject<br/>instance"] --> BOS["BinaryObjectSerializer"]
    BOS --> Header["8-byte header:<br/>magic + schema hash"]
    Header --> Fields["Length-prefixed field values<br/>(type tag + data)"]
    Fields --> Bytes["byte[] written to .bin file"]

    Bytes2["byte[] read from .bin file"] --> BOS2["BinaryObjectSerializer<br/>(BestEffort mode)"]
    BOS2 --> Hash{"Schema hash<br/>matches?"}
    Hash -->|Yes| Exact["Exact deserialize"]
    Hash -->|No| BestEffort["BestEffort: skip unknown,<br/>default missing fields"]
```

**Type tags supported:** bool, byte, short, int, long, float, double, decimal, DateTime, Guid, string, byte[], List&lt;string&gt;, List&lt;T&gt; (known types registered in `BinaryObjectSerializer.CreateDefault`).

---

## Sequential ID Generation

Sequential IDs are persisted so they survive restarts:

```
{dataRoot}/{EntityType}/_seqid.dat   ← int64 binary, incremented atomically
```

`DefaultIdGenerator` uses `DataStoreProvider.PrimaryProvider.NextSequentialId(entityName)` with an in-memory fallback when the provider is unavailable.

---

## Storage Layout Summary

### LocalFolderBinaryDataProvider layout

```
{dataRoot}/
├── {EntityType}/
│   ├── {id}.bin          ← binary-serialized entity instance
│   ├── _seqid.dat        ← sequential ID counter
│   └── _idx/
│       └── {FieldName}.idx  ← append-only binary index file
├── virtual/
│   └── {entityName}/
│       └── {id}.json     ← JSON-stored virtual entity instance
└── sessions/
    └── {sessionId}.bin   ← binary-serialized UserSession
```

### WalDataProvider layout

```
{dataRoot}/
├── wal/                          ← WalStore root
│   ├── {EntityType}_idmap.bin    ← string ID → packed ulong WAL key
│   └── wal_seg_*.log             ← append-only WAL segment files (CRC32C verified)
├── {EntityType}/
│   ├── schema-{EntityType}-*.json ← schema version files (shared with LocalFolderBinaryDataProvider)
│   └── _seqid.dat                ← sequential ID counter
├── Index/
│   ├── index.registry            ← IndexStore tracked-index registry
│   └── {EntityType}/
│       └── {FieldName}.log.lock  ← per-field exclusive lock file
├── Paged/
│   └── {EntityType}/
│       └── {FieldName}_index.page ← IndexStore secondary field index (LocalPagedFile format)
└── indexes/
    └── {EntityType}.idx          ← SearchIndexManager full-text index (Inverted only)
```

---

## Hardware Acceleration in the Data Layer

BareMetalWeb uses CPU-specific SIMD intrinsics in several hot paths.  All paths
are guarded by `IsSupported` checks and fall back gracefully to portable code.
The `DataLayerCapabilities` class exposes the active code paths as human-readable
strings for the metrics dashboard.

### CRC-32C (WAL checksums) — `WalCrc32C`

Each WAL segment entry includes a CRC-32C checksum.  The implementation selects
the fastest available hardware path at runtime:

| CPU feature | Code path | Granularity |
|---|---|---|
| ARM64 CRC | `Crc32.Arm64.ComputeCrc32C` | 8-byte lanes |
| x86-64 SSE4.2 | `Sse42.X64.Crc32` | 8-byte lanes |
| x86 SSE4.2 | `Sse42.Crc32` | 4-byte lanes |
| Portable | Slicing-by-4 lookup tables (~4× byte-at-a-time) | 4-byte lanes |

### Vector Distance (ANN search) — `SimdDistance`

Cosine, dot-product, and Euclidean distance computations dispatch to the widest
available SIMD instruction set.  All paths use fused multiply-add (FMA) where
available to reduce rounding error and improve throughput:

| CPU feature | Code path | Width |
|---|---|---|
| AVX-512F | `Avx512F.FusedMultiplyAdd` | 16 floats/iter |
| AVX2 + FMA | `Fma.MultiplyAdd` | 8 floats/iter |
| ARM64 AdvSimd | `AdvSimd.FusedMultiplyAdd` (NEON) | 4 floats/iter |
| Portable | `System.Numerics.Vector<float>` (auto-vectorised by JIT) | platform width |

### Key Comparison — `WalLatin1Key32.CompareTo`

The 32-byte Latin-1 index key is stored internally as four `ulong` words.
`CompareTo` byte-swaps each word with `BinaryPrimitives.ReverseEndianness` and
compares the resulting big-endian values directly — a zero-allocation,
branch-minimal comparison that avoids the prior stackalloc + `SequenceCompareTo`.

### Vectorised Column Query Scan — `ColumnQueryExecutor`

When a full-table scan is required (no usable secondary index) and the entity set
contains at least **256 rows**, `WalDataProvider.Query<T>` activates a
batch-vectorised filter path instead of the per-row reflection loop.

**How it works:**

1. All rows are pre-loaded into a `List<T>`.
2. For each `QueryClause` in the query, a typed column array is extracted from the
   loaded objects using the compiled `GetValueFn` delegate (no reflection at scan
   time):
   - Numeric fields (`int`, `long`, `double`, `float`, `bool`, `enum`, `DateTime`,
     `DateOnly`, `TimeOnly`, `TimeSpan`, `decimal`) → typed column array.
   - String / GUID / other fields → scalar per-row evaluation.
3. The column array is swept with `System.Numerics.Vector<T>` portable SIMD
   comparisons (`Equals`, `GreaterThan`, `LessThan`, `GreaterThanOrEqual`,
   `LessThanOrEqual`, `NotEquals`), writing matching row indices into a
   `ulong[]` bitmask.
4. Multi-clause AND queries compose bitmasks via SIMD `ulong` AND (using
   `Vector<ulong>`).
5. The final result is materialised by iterating set bits with
   `BitOperations.TrailingZeroCount`, honouring `skip`/`top` pagination.

**Expected throughput:** `Vector<int>.Count` rows per comparison cycle on the SIMD
path (4–8× on SSE2/AVX2, 4× on ARM NEON). The integer-mask bitmask AND step adds
negligible overhead and enables free multi-clause composition.

**Eligibility gates:**
- `idMap.Count >= 256` (vectorisation threshold)
- `query.Groups.Count == 0` (no nested OR groups; use scalar path for complex logic)
- `query.Clauses.Count > 0` (at least one predicate)

**Fallback:** Clauses with unsupported operators (Contains, StartsWith, EndsWith,
In, NotIn) or non-numeric field types fall back to the scalar
`DataQueryEvaluator.Matches()` per-row loop for that clause, while vectorisable
clauses in the same query still use the SIMD path. Results are AND-composed via
bitmask intersection, so correctness is maintained for any mix of clause types.

`DataLayerCapabilities.ColumnQueryPath` reports the active SIMD tier, lane width,
and activation threshold at runtime (logged at startup and shown in the metrics
dashboard).

---

### Columnstore Ordinal Indirection — `ColumnarStore` / `OrdinalMap` / `FreeOrdinalStack`

`ColumnarStore` is a per-entity in-memory cache of dense typed arrays (one per
numeric field) that enables SIMD column scans without reloading all objects.  It is
lazily built on the first vectorised query and maintained incrementally thereafter.

#### Stable id → ordinal mapping (`OrdinalMap`)

Each live row is addressed by a **stable ordinal** (`uint`) — its position in the
dense column arrays.  Ordinals are allocated and tracked by `OrdinalMap`:

```
OrdinalMap:
  Dictionary<uint,uint>  _idToOrdinal   id   → ordinal  (live rows only)
  uint[]                 _ordinalToId   ordinal → id     (0 = freed slot)
  uint                   HighWater      one past the highest ever-allocated ordinal
  FreeOrdinalStack       FreeStack      freed ordinals available for reuse
```

- **Upsert(id)**: returns `(ordinal, isNew)`.  New ids pop from the free stack first;
  if the stack is empty the `HighWater` mark is incremented.
- **Remove(id)**: writes `0` into `_ordinalToId[ordinal]` (tombstone) and pushes the
  ordinal onto the `FreeOrdinalStack`.

Indexes always reference **IDs**; ordinals are a private layout detail of
`ColumnarStore`.

#### Freed-ordinal pooling (`FreeOrdinalStack`)

`FreeOrdinalStack` is a simple LIFO stack of `uint` values.  When a row is deleted
its ordinal is pushed onto the stack; the next insert pops that ordinal rather than
allocating a new slot, keeping column arrays dense and avoiding unbounded growth
under steady-state insert/delete churn.

#### Validity bitmap

Because freed ordinals are reused lazily there can be a brief window where a slot
is freed but not yet reused.  A `ulong[]` validity bitmap (one bit per ordinal)
tracks which slots are live.  `ScanClause` ANDs every scan result against this
bitmap before returning, so stale column values in freed slots are never visible
to callers.

#### Incremental update protocol

| Event | `ColumnarStore` call | Effect |
|---|---|---|
| `Save<T>` (insert or update) | `UpsertRow<T>(obj, meta)` | Upserts ordinal; grows arrays if needed; writes column values; sets validity bit |
| `Delete<T>` | `RemoveRow(key)` | Clears validity bit; pushes ordinal onto free stack |
| `SaveRecord` (DataRecord path) | `Invalidate()` | Marks stale; next query triggers full rebuild |
| First query after startup | `Build<T>(objects, meta)` | Full rebuild; ordinals 0, 1, 2, … assigned in input order |

`UpsertRow` and `RemoveRow` do **not** change `Version` — that stamp is reserved for
`Build()` and `Invalidate()`.  `GetOrBuildColumnarStore` therefore only rebuilds
when `Invalidate()` is called (e.g. from the `SaveRecord` path), not on every write.

#### Scan range vs live count

| Property | Meaning |
|---|---|
| `RowCount` | Number of live rows (`OrdinalMap.Count`) |
| `Capacity` | `OrdinalMap.HighWater` — size of column arrays; scan loops run `[0, Capacity)` |
| `ScanWordCount` | `(Capacity + 63) >> 6` — number of `ulong` bitmask words required |

Callers should use `store.ScanWordCount` (not `(RowCount + 63) >> 6`) when there
are freed slots between live rows.

---

_Status: Updated @ commit HEAD (2026-03-06) — added Columnstore Ordinal Indirection section describing OrdinalMap, FreeOrdinalStack, validity bitmap, and incremental UpsertRow/RemoveRow protocol_
