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
public class Order : BaseDataObject
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
| **Inverted index** | `IndexStore.ReadIndex()` | `fieldValue → Set<uint keys>` | Filtering (Equals, StartsWith) |
| **Forward index** | `IndexStore.ReadLatestValueIndex()` | `uint key → fieldValue` | Sorting |

Both views are cached in-memory (`ConcurrentDictionary`) and invalidated on every write via `AppendEntry()` / `AppendEntries()`.

### Write Path

On every `Save()`, the `SearchIndexManager` detects `[DataIndex]` properties and calls `IndexStore.AppendEntry()` with the new value. Old values get a delete (`D`) entry; new values get an add (`A`) entry. The index file is append-only — no in-place updates. Each write invalidates the in-memory cache for that `(entity, field)` pair.

### IdMap and Tombstone Handling

The `idMap` (`uint objKey → ulong walKey`) is filtered at load time — tombstoned (deleted) WAL entries are excluded. This means **query and count paths never need to check tombstones during iteration**. If stale tombstone entries are found on load, a compacted idMap is re-persisted in the background.

### Deserialization Cache

`Load<T>(key)` uses an in-memory deserialization cache keyed by `(typeName, key, walPointer)`. When the WAL pointer hasn't changed (same version), the cached deserialized object is returned without binary parsing. The cache holds up to 4096 entries with **LRU eviction** — when full, the oldest 25% by last-access timestamp are evicted. Access timestamps are tracked via `Environment.TickCount64` on each cache hit. Entries are invalidated on `Save()` and `Delete()`.

## Query Acceleration Paths

`WalDataProvider.Query<T>()` uses indexes in this priority order:

### 1. Index-Accelerated Filter (Equals / StartsWith)

When a query has `Equals` or `StartsWith` clauses on indexed fields:

```
GET /api/orders?Status=Active
GET /api/orders?Name__startswith=Wid
```

→ Reads the cached inverted index for each indexed clause, gets `Set<uint>` candidate keys. **Multiple indexed clauses are intersected** before loading any entities (`Status[Active] ∩ CustomerId[123]`). Non-indexed clauses are applied as a post-filter on the intersected set.

**StartsWith** iterates the cached index keys with a case-insensitive prefix match, unioning all matching candidate sets.

**Pagination**: When no sorts are present, short-circuits after `skip + top` matches — does not load all candidates.

### 2. No Filter, No Sort (Sequential Scan)

When there are no clauses and no sorts, or a null query:

```
GET /api/orders?top=25&skip=50
```

→ Walks the idMap sequentially (keys are in insertion order, idMap is tombstone-free), skips `N` entries without deserializing, loads only the `top` records. **O(skip) iteration + O(top) deserialization.**

### 3. Index-Accelerated Sort (Key)

When sorting by `Key` with no filters:

```
GET /api/orders?sort=Key&direction=Asc&top=25&skip=50
```

→ **Asc**: Streams idMap sequentially, skips `N` entries, loads `top` records. No sorting needed — keys are already sequential. **O(skip + top).**

→ **Desc**: Collects all live keys from idMap, reverses, slices, loads page. **O(n) collect + O(top) load.**

### 4. Index-Accelerated Sort (Indexed Field)

When sorting by an indexed field with no filters:

```
GET /api/orders?sort=Status&direction=Asc&top=25
```

→ Reads the cached forward index to get `(key, fieldValue)` pairs for all live entities, sorts by fieldValue, loads only the page. No entity deserialization for sorting. **O(n log n) sort + O(top) load.**

### 5. Index-Accelerated Count

Counting with filters on indexed fields:

```
GET /api/orders?Status=Active  (count header)
```

→ Reads cached inverted indexes for all indexed `Equals`/`StartsWith` clauses, intersects candidate sets. If ALL clauses are indexed, returns `candidateIds.Count` directly — **O(1)** after cache hit, zero deserialization. If some clauses are non-indexed, loads only the intersected set and applies remaining filters.

**Unfiltered count** uses a cached `_liveCounts` dictionary — **O(1)** after first call. Maintained atomically on `Save()` (increment on insert) and `Delete()` (decrement).

### 6. Full Scan (Fallback)

For queries with non-indexed filters, complex operators (Contains, GreaterThan, LessThan), or grouped clauses:

→ Iterates all idMap entries (tombstone-free), calls `Load<T>()` (hits deser cache when possible), applies filter/sort in memory. Short-circuits after `top` matches when no sort is needed.

## Caching Summary

| Cache | Location | Key | Invalidation | Size |
|-------|----------|-----|--------------|------|
| **Inverted index** | `IndexStore._invertedCache` | `(entity, field)` | On `AppendEntry()` | Unbounded (one per indexed field) |
| **Forward index** | `IndexStore._forwardCache` | `(entity, field)` | On `AppendEntry()` | Unbounded (one per indexed field) |
| **Deserialization** | `WalDataProvider._deserCache` | `(typeName, key, walPtr)` | On `Save()` / `Delete()` | 4096 entries, LRU eviction (oldest 25%) |
| **Live count** | `WalDataProvider._liveCounts` | `typeName` | `Save()` increments, `Delete()` decrements | One per entity type |
| **Schema members** | `WalDataProvider._schemaMemberCache` | `(type, version)` | Never (immutable) | One per schema version |

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

| Query Pattern | Complexity | Notes |
|---------------|-----------|-------|
| No filter, no sort + Skip/Top | O(skip + top) | Sequential idMap walk, zero deser for skipped |
| Filter (Equals, indexed) | O(k) | k = matching records, from cached index |
| Filter (StartsWith, indexed) | O(keys + k) | Prefix scan on cached index keys |
| Multi-filter (all indexed) | O(k₁ ∩ k₂) | Intersect cached index sets |
| Sort by Key Asc (no filter) | O(skip + top) | Stream sequential idMap |
| Sort by Key Desc (no filter) | O(n + top) | Collect all keys, reverse, load page |
| Sort by indexed field | O(n log n + top) | Forward index sort, load page only |
| Count (no filter) | O(1) | Cached `_liveCounts` |
| Count (Equals, indexed) | O(1) | Cached index `.Count` |
| Count (multi-filter, all indexed) | O(1) | Intersect cached sets, `.Count` |
| Filter + Sort | O(k log k + top) | Index filter → sort candidates → load page |
| Full scan fallback | O(n) | Deser cache reduces per-entity cost |

Where n = total entities, k = matching entities, top = page size (typically 25).

## Query Plan History

`QueryPlanner` produces an optimised `QueryPlan` for every `ReportExecutor.ExecuteAsync` call. After execution, the plan (plus timing and row counts) is recorded in the static `QueryPlanHistory` circular buffer (max 100 entries, newest-first).

### Missing Index Recommendations

The planner detects three classes of suboptimal access patterns and emits `MissingIndexRecommendation` entries in the plan:

| Pattern | Recommendation trigger |
|---------|----------------------|
| Filter on unindexed field | Filter pushdown step touches a field with no `[DataIndex]` |
| Unindexed hash-join build side | Join `toField` has no `[DataIndex]` (forces linear probe) |
| Sort on unindexed field | `OrderBy` field has no `[DataIndex]` (requires full in-memory sort) |

### Admin UI

Navigate to **⚙ Tools → 📊 Query Plan History** in the VNext admin SPA (`/UI/_query-plans`) to see:
- Execution timeline with latency colour-coding (green < 10 ms, amber < 100 ms, red ≥ 100 ms)
- Per-step graph showing entity, estimated rows, indexed fields, and join strategy
- Missing-index recommendations at the bottom of each plan card

### API Endpoint

`GET /api/admin/query-plans` — requires `admin` role; returns JSON array (max 100 items, newest first).

_Status: current as of commit after issue #query-plan-history_
