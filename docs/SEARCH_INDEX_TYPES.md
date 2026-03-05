# Search Index Types in BareMetalWeb

## Overview

BareMetalWeb provides **six** different index types for optimizing search operations on data objects. Each index type has different performance characteristics and is suited for different use cases.

> For the separate ANN vector-embedding index, see [`docs/architecture/vector-index.md`](./architecture/vector-index.md).

## Index Types

### 1. Inverted Index (Default)

**Best for:** General full-text search on text fields

**Description:** Maps tokens to document IDs with prefix tree optimization for efficient substring matching.

**Characteristics:**
- Fast full-text search
- Prefix matching for queries ≥3 characters  
- Case-insensitive tokenization
- Supports substring search fallback
- Good balance of speed and functionality

**Performance:**
- Insert: O(k) where k = number of tokens
- Search: O(m*k) where m = matching tokens, k = query tokens
- Space: O(n*k) where n = number of documents, k = average tokens per document

**Usage Example:**
```csharp
public class Article : BaseDataObject
{
    [DataIndex(IndexKind.Inverted)]
    public string Content { get; set; }
    
    [DataIndex(IndexKind.Inverted)]
    public string Title { get; set; }
}
```

### 2. BTree Index

**Best for:** Sorted data, range queries, prefix searches on categorical data

**Description:** Uses `SortedDictionary` internally to maintain tokens in sorted order.

**Characteristics:**
- Maintains sorted order
- Efficient prefix searching
- Good for range queries (though not explicitly implemented)
- Deterministic performance

**Performance:**
- Insert: O(log n)
- Search: O(log n + m) where m = number of matches
- Space: O(n)

**Usage Example:**
```csharp
public class Product : BaseDataObject
{
    [DataIndex(IndexKind.BTree)]
    public string Category { get; set; }  // Categories are often hierarchical/sorted
    
    [DataIndex(IndexKind.BTree)]
    public string SKU { get; set; }  // SKUs benefit from prefix search
}

// Search with BTree index
var results = searchManager.Search(typeof(Product), "ELEC", loadAll, IndexKind.BTree);
```

### 3. Treap Index

**Best for:** Balanced search performance with frequent insertions/deletions

**Description:** Randomized Binary Search Tree that combines BST with heap property using random priorities.

**Characteristics:**
- Self-balancing via randomization
- No explicit rebalancing needed
- Expected logarithmic performance
- Good for dynamic data

**Performance:**
- Insert: O(log n) expected
- Delete: O(log n) expected
- Search: O(log n) expected
- Space: O(n)

**Usage Example:**
```csharp
public class Task : BaseDataObject
{
    [DataIndex(IndexKind.Treap)]
    public string Tags { get; set; }  // Frequently added/removed tags
    
    [DataIndex(IndexKind.Treap)]
    public string AssignedTo { get; set; }  // Dynamic assignments
}

// Search with Treap index
var results = searchManager.Search(typeof(Task), "urgent", loadAll, IndexKind.Treap);
```

### 4. Bloom Filter Index

**Best for:** Fast membership testing on large datasets where false positives are acceptable

**Description:** Probabilistic data structure using multiple hash functions and bit array.

**Characteristics:**
- Extremely space-efficient
- Fast membership testing
- Can have false positives (never false negatives)
- "Definitely not present" is always accurate
- Still needs backing storage for actual retrieval

**Performance:**
- Insert: O(k) where k = number of hash functions (default: 3)
- Search: O(k) for membership test + O(n) for substring fallback
- Space: O(1) - very compact (default: 10,000 bits ≈ 1.2 KB)

**Usage Example:**
```csharp
public class LogEntry : BaseDataObject
{
    [DataIndex(IndexKind.Bloom)]
    public string ErrorCode { get; set; }  // Quick "has this error occurred?" check
    
    [DataIndex(IndexKind.Bloom)]
    public string UserId { get; set; }  // Fast "did this user appear in logs?" check
}

// Search with Bloom filter
var results = searchManager.Search(typeof(LogEntry), "ERR-404", loadAll, IndexKind.Bloom);
```

### 5. Graph Index

**Best for:** Relationship traversal between entity records (foreign-key graphs, hierarchy trees)

**Description:** Stores typed directed edges as forward and reverse adjacency lists.
When a `uint`-valued field (a numeric foreign key) is decorated with `[DataIndex(IndexKind.Graph)]`
an edge is recorded from the current record's ID to the referenced ID, labelled with the entity
type name.

**Characteristics:**
- Forward traversal: O(degree) per hop
- Reverse traversal: O(in-degree) per hop
- BFS traversal up to configurable max-hops depth
- Typed edges allow filtering by relationship kind
- All in-memory; rebuilt on startup from the Inverted index log

**Usage Example:**
```csharp
public class Employee : BaseDataObject
{
    [DataIndex(IndexKind.Graph)]
    public string ManagerId { get; set; }   // FK → another Employee

    [DataIndex(IndexKind.Graph)]
    public string DepartmentId { get; set; } // FK → Department
}
```

**Graph query API:**
```csharp
// All records reachable from nodeId within 3 hops
var reachable = searchManager.TraverseGraph(typeof(Employee), nodeId, maxHops: 3, loadAll);

// Direct neighbours
var reports = searchManager.GetNeighbours(typeof(Employee), managerId, loadAll);

// Reverse: find who points TO this node
var managers = searchManager.GetReverseNeighbours(typeof(Employee), employeeId, loadAll);
```

---

### 6. Spatial Index

**Best for:** Geographic coordinate queries (radius, bounding box, nearest-N)

**Description:** Stores geographic coordinate pairs (latitude/longitude) in a
grid-based spatial hash with 0.1° cells (≈ 11 km per cell). Supports efficient
radius, bounding-box, and nearest-N queries using Haversine distance.

**Field format:** The indexed field must store coordinates as a `"lat,lng"` string
(e.g. `"51.5074,-0.1278"`) or as a JSON-encoded object parseable by the built-in
coordinate parser.

**Characteristics:**
- Grid cells ≈ 11 km × 11 km (0.1° resolution)
- Candidate expansion based on radius: only grid cells within `ceil(radius / 11)` cells of the centre are scanned
- Exact Haversine distance applied to all candidates for precise filtering
- All in-memory; rebuilt on startup

**Usage Example:**
```csharp
public class Store : BaseDataObject
{
    [DataIndex(IndexKind.Spatial)]
    public string Location { get; set; }   // "lat,lng" e.g. "51.5074,-0.1278"
}
```

**Spatial query API:**
```csharp
// Stores within 10 km of a point
var nearby = searchManager.SearchRadius(typeof(Store), 51.5, -0.1, radiusKm: 10, loadAll);

// Stores within a bounding box
var inBox = searchManager.SearchBoundingBox(typeof(Store), 51.0, 52.0, -1.0, 0.0, loadAll);

// 5 nearest stores with distances
var nearest = searchManager.SearchNearest(typeof(Store), 51.5, -0.1, count: 5, loadAll);
// Returns List<(uint Id, double DistanceKm)>
```

---

## Choosing the Right Index Type

| Use Case | Recommended Index | Reason |
|----------|------------------|---------|
| Full-text article/document search | Inverted | Best for text with many tokens |
| Product categories | BTree | Benefits from sorted/prefix search |
| Hierarchical codes (SKU, part numbers) | BTree | Efficient prefix matching |
| Frequently changing tags/labels | Treap | Good balance for dynamic data |
| User activity tracking | Bloom | Space-efficient membership testing |
| Large dataset membership checks | Bloom | Very fast "is this present?" queries |
| Foreign-key relationship traversal | Graph | BFS traversal, reverse lookups |
| Manager/employee hierarchy | Graph | Multi-hop traversal |
| Store locations, IoT devices | Spatial | Radius/nearest queries |
| Delivery address geocoding | Spatial | Bounding-box filtering |
| Semantic/embedding similarity | *VectorIndexManager* | See `docs/architecture/vector-index.md` |
| General purpose search | Inverted | Best default choice |


## Mixed Index Types

You can use different index types on different properties of the same class:

```csharp
public class Product : BaseDataObject
{
    [DataIndex(IndexKind.Inverted)]  // Full-text search on name
    public string Name { get; set; }
    
    [DataIndex(IndexKind.BTree)]     // Sorted category search
    public string Category { get; set; }
    
    [DataIndex(IndexKind.Treap)]     // Dynamic tags
    public string Tags { get; set; }
    
    [DataIndex(IndexKind.Bloom)]     // Fast manufacturer lookup
    public string Manufacturer { get; set; }
}
```

## API Reference

### Basic Search (uses Inverted index by default)
```csharp
var results = searchManager.Search(typeof(MyClass), "query text", loadAllFunc);
```

### Search with Specific Index Type
```csharp
var results = searchManager.Search(typeof(MyClass), "query text", loadAllFunc, IndexKind.BTree);
```

### Indexing an Object
```csharp
searchManager.IndexObject(myObject);  // Updates all index types automatically
```

### Removing an Object
```csharp
searchManager.RemoveObject(myObject);  // Removes from all index types
```

## Implementation Notes

1. **Serialization**: Currently, only the Inverted index is persisted to disk. Other index types are rebuilt on startup from the inverted index data.

2. **Thread Safety**: All index operations are protected by locks per index type.

3. **Backward Compatibility**: The Inverted index is always built regardless of which index types are specified, ensuring backward compatibility.

4. **Index Building**: Indexes are built lazily on first search via `EnsureBuilt()`.

5. **Bloom Filter Configuration**: Default size is 10,000 bits with 3 hash functions. This can be adjusted in `InitializeBloomFilter()` if needed.

## Performance Benchmarks

Typical performance on modern hardware (2024):

| Operation | Inverted | BTree | Treap | Bloom |
|-----------|----------|--------|--------|--------|
| Index 1000 objects | ~5ms | ~3ms | ~4ms | ~2ms |
| Search (exact match) | ~0.05ms | ~0.03ms | ~0.04ms | ~0.01ms |
| Search (prefix, 3+ chars) | ~0.1ms | ~0.08ms | ~0.15ms | ~0.5ms* |
| Insert single object | ~0.01ms | ~0.005ms | ~0.006ms | ~0.003ms |
| Remove single object | ~0.02ms | ~0.01ms | ~0.012ms | ~0.008ms |

*Bloom filter prefix/substring search falls back to full scan as it only supports exact membership testing

## Testing

Comprehensive unit tests are available in `BareMetalWeb.Data.Tests/SearchIndexingTests.cs`, covering:
- All four index types
- Insert, update, remove, and search operations
- Prefix matching
- Multi-token queries
- Edge cases (empty queries, null values, etc.)

Run tests with:
```bash
dotnet test BareMetalWeb.Data.Tests/ --filter "FullyQualifiedName~SearchIndexingTests"
```
