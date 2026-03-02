# Query Index Architecture

## Overview

BareMetalWeb uses two index systems that serve different purposes:

1. **Secondary Field Indexes** (this document) — accelerate `Query()` and `Count()` operations on `[DataIndex]`-decorated properties via the `IndexStore`
2. **Search Indexes** — full-text search via `SearchIndexManager` (see [SEARCH_INDEX_TYPES.md](SEARCH_INDEX_TYPES.md))

This document covers how secondary field indexes work and where they are used in the query path.

## How It Works

### Marking Fields for Indexing

Decorate entity properties with `[DataIndex]` to enable query acceleration:

```csharp
public class Order : RenderableDataObject
{
    [DataIndex]
    [DataField(Label = "Status")]
    public string Status { get; set; } = string.Empty;

    [DataIndex]
    [DataField(Label = "Customer")]
    public string CustomerId { get; set; } = string.Empty;
}
```

### Index Storage

Each indexed field gets an append-only paged file at `<dataRoot>/Index/<Entity>/<Field>.idx`. Two views are derived on read:

| View | Method | Structure | Used For |
|------|--------|-----------|----------|
| **Inverted index** | `IndexStore.ReadIndex()` | `fieldValue → Set<uint keys>` | Filtering (Equals) |
| **Forward index** | `IndexStore.ReadLatestValueIndex()` | `uint key → fieldValue` | Sorting |

### Write Path

On every `Save()`, the `SearchIndexManager` detects `[DataIndex]` properties and calls `IndexStore.AppendEntry()` with the new value. Old values get a delete (`D`) entry; new values get an add (`A`) entry. The index file is append-only — no in-place updates.

## Query Acceleration Paths

`WalDataProvider.Query<T>()` uses indexes in this priority order:

### 1. Index-Accelerated Filter (Equals)

When a query has an `Equals` clause on an indexed field:

```
GET /api/orders?Status=Active
```

→ Reads the inverted index for `Status`, gets `Set<uint>` of keys where Status="Active", loads only those entities. **O(k)** where k = matching records instead of O(n) full scan.

### 2. Index-Accelerated Sort (Key)

When sorting by `Key` with no filters:

```
GET /api/orders?sort=Key&direction=Asc&top=25
```

→ Collects live uint32 keys from the idMap, sorts them (O(n log n) on integers), loads only the page (25 items). No deserialization for sorting.

### 3. Index-Accelerated Sort (Indexed Field)

When sorting by an indexed field with no filters:

```
GET /api/orders?sort=Status&direction=Asc&top=25
```

→ Reads the forward index to get `(key, fieldValue)` pairs, sorts by fieldValue (O(n log n) on strings), loads only the page. No deserialization for sorting.

### 4. Index-Accelerated Count

When counting with an `Equals` filter on an indexed field:

```
GET /api/orders?Status=Active  (count header)
```

→ Reads the inverted index, returns `candidateIds.Count` directly. **O(1)** after index read — zero deserialization.

### 5. Full Scan (Fallback)

For queries with non-indexed filters, complex operators (Contains, GreaterThan), or grouped clauses:

→ Iterates all WAL entries, deserializes each entity, applies filter/sort in memory. Short-circuits after `top` matches when no sort is needed.

## Indexed Fields by Entity

| Entity | Indexed Properties |
|--------|--------------------|
| **User** | UserName, Email |
| **UserSession** | UserId |
| **AppSetting** | SettingId |
| **Permission** | Code |
| **SecurityRole** | RoleName |
| **SecurityGroup** | GroupName |
| **Product** | Name, Sku, Category, UnitOfMeasureId, CurrencyId |
| **Customer** | Name, Email, Company, AddressId |
| **Order** | OrderNumber, CustomerId, Status, CurrencyId |
| **OrderRow** | ProductId |
| **Address** | Label, City |
| **Currency** | IsoCode |
| **Employee** | Name, Email, ManagerId |
| **Quote** | QuoteNumber, CustomerId, Status |
| **Page** | Slug, Status |
| **ProductCategory** | Name, Slug |
| **Subject** | Name |
| **TimeTablePlan** | SubjectId |
| **LessonLog** | SubjectId |
| **ToDo** | Title |
| **SessionLog** | UserName |
| **ModuleDefinition** | ModuleId |
| **DomainEventSubscription** | Name, SourceEntity |
| **UnitOfMeasure** | Name |

## Performance Characteristics

| Query Pattern | With Index | Without Index |
|---------------|-----------|---------------|
| Filter (Equals) | O(k) load k matches | O(n) deserialize all |
| Sort (no filter) | O(n log n) keys + O(p) load page | O(n) deserialize + O(n log n) sort |
| Count (no filter) | O(n) tombstone check | O(n) tombstone check |
| Count (Equals filter) | O(1) after index read | O(n) deserialize + match |
| Filter + Sort | O(k) load + O(k log k) sort | O(n) deserialize + O(n log n) sort |

Where n = total entities, k = matching entities, p = page size (typically 25).
