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
│   └── wal_seg_*.log             ← append-only WAL segment files
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
    └── {EntityType}.idx          ← SearchIndexManager full-text index
```

---

_Status: Verified against codebase @ commit bd580ba_
