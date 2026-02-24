# Indexing Pipeline

This document covers BareMetalWeb's secondary-index architecture, the index creation/update/delete lifecycle, and how indexes accelerate queries.

---

## SearchIndexManager Architecture

```mermaid
graph TD
    subgraph SearchIndexManager
        SIM["SearchIndexManager"]
        PrefixTree["In-memory prefix tree<br/>(field value → Set&lt;id&gt;)"]
        IS["IndexStore<br/>(per entity+field)"]
    end

    DA["[DataIndex] attribute<br/>on entity field"] --> SIM
    SIM --> PrefixTree
    SIM --> IS

    IS --> IdxFile["{dataRoot}/{Type}/_idx/{Field}.idx<br/>(append-only binary file)"]

    subgraph IdxEntry["Index entry format"]
        Op["Op byte: 'I'=insert, 'D'=delete"]
        Id["Record ID (string)"]
        Val["Field value (string)"]
    end
    IdxFile --> IdxEntry
```

**Key facts:**
- Indexes are stored as append-only `.idx` files — deletes write a tombstone `'D'` entry rather than rewriting the file.
- On startup `SearchIndexManager` replays the `.idx` log to rebuild the in-memory prefix tree.
- Average query lookup time: **30–43 microseconds** (sub-millisecond).

---

## Index Creation / Update Lifecycle

```mermaid
sequenceDiagram
    participant RH as Route handler
    participant DS as DataStoreProvider
    participant LFB as LocalFolderBinaryDataProvider
    participant SIM as SearchIndexManager
    participant IS as IndexStore
    participant FS as File system

    RH->>DS: Save(entity)
    DS->>LFB: Save(entity)
    LFB->>FS: Write {id}.bin
    loop For each property marked [DataIndex]
        LFB->>SIM: IndexObject(entity)
        SIM->>SIM: Update prefix tree<br/>(remove old value, insert new value)
        SIM->>IS: AppendEntry('I', id, fieldValue)
        IS->>FS: Append to {Field}.idx
    end
```

---

## Delete Lifecycle

```mermaid
sequenceDiagram
    participant RH as Route handler
    participant DS as DataStoreProvider
    participant LFB as LocalFolderBinaryDataProvider
    participant SIM as SearchIndexManager
    participant IS as IndexStore
    participant FS as File system

    RH->>DS: Delete<T>(id)
    DS->>LFB: Delete(type, id)
    LFB->>FS: Remove {id}.bin
    loop For each [DataIndex] field
        LFB->>SIM: RemoveObject(type, id)
        SIM->>SIM: Remove id from prefix tree node
        SIM->>IS: AppendEntry('D', id)
        IS->>FS: Append tombstone to {Field}.idx
    end
```

---

## Startup Replay

```mermaid
flowchart TD
    Start["Application startup"] --> Scan["Scan {dataRoot}/{Type}/_idx/*.idx"]
    Scan --> Replay["Replay entries in order"]
    Replay --> Insert{"Op = 'I' ?"}
    Insert -->|Yes| AddTree["Add id to prefix tree node<br/>(fieldValue → id)"]
    Insert -->|No| DelTree["Remove id from prefix tree node"]
    AddTree --> Next["Next entry"]
    DelTree --> Next
    Next --> Done["Prefix tree ready<br/>(all indexes in memory)"]
```

---

## Query Path: Index Lookup vs Full Scan

```mermaid
flowchart TD
    Q["Query(type, QueryDefinition)"] --> Check{"Any clause uses<br/>[DataIndex] field<br/>with Equals operator?"}
    Check -->|Yes| Idx["SearchIndexManager.Lookup(field, value)<br/>→ Set of matching IDs"]
    Check -->|No| Full["Full scan: read all {id}.bin files<br/>and evaluate in memory"]

    Idx --> Load["Load only matching entities<br/>from disk by ID"]
    Load --> PostFilter["Apply remaining filter clauses<br/>in memory"]
    PostFilter --> Result["Return IQueryable result"]

    Full --> Result2["Return IQueryable result"]
```

**Performance implication:** Always mark high-selectivity filter fields (e.g. `Email`, `UserId`, `CustomerId`) with `[DataIndex]` to avoid full scans on large entity stores.

---

## [DataIndex] Field Mapping

The following fields in the built-in data objects are indexed:

| Entity | Indexed fields |
|--------|---------------|
| `User` | `UserName`, `Email` |
| `UserSession` | `UserId` |
| `Customer` | `Email`, `Company` |
| `Order` | `CustomerId`, `Status` |
| `Product` | `Name`, `Category` |
| `Invoice` | `CustomerId` |
| `OrderLine` | `ProductId` |

Add `[DataIndex]` to any property in a `[DataEntity]` class to create a secondary index automatically.

---

## Index File Format

Each `.idx` file is an append-only binary log:

```
┌──────────────────────────────────────┐
│ Entry 1                              │
│  Op     : 1 byte  ('I' or 'D')      │
│  IdLen  : 4 bytes (int32)            │
│  Id     : IdLen bytes (UTF-8)        │
│  ValLen : 4 bytes (int32)            │
│  Value  : ValLen bytes (UTF-8)       │
├──────────────────────────────────────┤
│ Entry 2 ...                          │
└──────────────────────────────────────┘
```

Compaction (rewriting the file to remove superseded entries) is not currently implemented; the append-only log is replayed on each startup.
