# Data Layer & Storage Architecture

This document covers BareMetalWeb's data storage, entity registration, CRUD lifecycle, and virtual entity system.

---

## Storage Stack

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

**Key points:**
- `DataStoreProvider.Current` is the one-stop shop for all data access.
- `LocalFolderBinaryDataProvider` stores each entity instance as a single binary file, grouped by entity type.
- Schema evolution is handled via `SchemaReadMode.BestEffort`: old records with extra/missing fields still load; new fields receive default values.

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
