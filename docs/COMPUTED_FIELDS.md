# Computed Fields Feature

Computed/derived properties on data entities allow you to automatically calculate field values from related entities or aggregate data from child collections.

## Overview

The computed fields feature supports three strategies:

1. **Snapshot** - Copy value at a specific point in time (create/update)
2. **CachedLive** - Compute on access with configurable caching
3. **AlwaysLive** - Always compute the latest value on every access

## Basic Usage

### 1. Snapshot Strategy

Use when you need to freeze a value at a specific point in time (e.g., order line prices, invoice totals).

```csharp
[DataEntity("Orders")]
public class Order : BaseDataObject
{
    [DataLookup(typeof(Product))]
    public string ProductId { get; set; }
    
    // Price frozen at order creation
    [ComputedField(
        SourceEntity = typeof(Product),
        SourceField = nameof(Product.BasePrice),
        ForeignKeyField = nameof(ProductId),
        Strategy = ComputedStrategy.Snapshot,
        Trigger = ComputedTrigger.OnCreate)]
    [DataField(Label = "Unit Price")]
    public decimal UnitPrice { get; set; }
}
```

**How it works:**
- Value is computed and stored when the trigger fires (OnCreate, OnUpdate, or both)
- Persisted to storage like any normal field
- Does NOT change if the source changes later
- Rendered as readonly in edit forms

### 2. CachedLive Strategy

Use for frequently accessed values that don't need real-time accuracy (e.g., dashboard metrics, derived totals).

```csharp
[ComputedField(
    SourceEntity = typeof(Product),
    SourceField = nameof(Product.Price),
    ForeignKeyField = nameof(ProductId),
    Strategy = ComputedStrategy.CachedLive,
    CacheSeconds = 60)]
[DataField(Label = "Current Price")]
public decimal CurrentPrice { get; set; }
```

**How it works:**
- Value is computed on first access and cached
- Cache expires after `CacheSeconds` (default: 60)
- Balances performance with freshness
- NOT persisted to storage - computed on demand
- Rendered as readonly with visual indicator

### 3. AlwaysLive Strategy

Use when you need real-time values on every access (e.g., stock levels, dynamic pricing).

```csharp
[ComputedField(
    SourceEntity = typeof(Inventory),
    SourceField = nameof(Inventory.StockLevel),
    ForeignKeyField = nameof(InventoryId),
    Strategy = ComputedStrategy.AlwaysLive)]
[DataField(Label = "Available Stock")]
public int AvailableStock { get; set; }
```

**How it works:**
- Value is computed fresh on every access
- No caching - always reflects current state
- NOT persisted to storage
- Rendered as readonly with visual indicator
- **Warning**: Can impact performance on list views

## Aggregations

Compute values from child collections using aggregate functions.

```csharp
[DataEntity("Orders")]
public class Order : BaseDataObject
{
    public List<OrderLine> Lines { get; set; } = new();
    
    // Sum of all line totals
    [ComputedField(
        ChildCollectionProperty = nameof(Lines),
        SourceField = nameof(OrderLine.LineTotal),
        Strategy = ComputedStrategy.AlwaysLive,
        Aggregate = AggregateFunction.Sum)]
    [DataField(Label = "Order Total")]
    public decimal Total { get; set; }
    
    // Count of items
    [ComputedField(
        ChildCollectionProperty = nameof(Lines),
        Strategy = ComputedStrategy.Snapshot,
        Trigger = ComputedTrigger.OnCreate,
        Aggregate = AggregateFunction.Count)]
    [DataField(Label = "Item Count")]
    public int LineCount { get; set; }
}
```

**Supported Aggregate Functions:**
- `None` - Direct field value (default)
- `Sum` - Sum of numeric values
- `Count` - Count of items
- `Min` - Minimum value
- `Max` - Maximum value
- `Average` - Average of numeric values

## Attribute Properties

### Required

- **Strategy** - Computation strategy (`Snapshot`, `CachedLive`, `AlwaysLive`)

### For Single-Entity Lookups

- **SourceEntity** - Type of the related entity (e.g., `typeof(Product)`)
- **SourceField** - Name of the field to read (e.g., `nameof(Product.Price)`)
- **ForeignKeyField** - Name of the FK field on current entity (e.g., `nameof(ProductId)`)

### For Aggregations

- **ChildCollectionProperty** - Name of the collection property (e.g., `nameof(Lines)`)
- **SourceField** - Name of the field to aggregate (not required for `Count`)
- **Aggregate** - Aggregate function to apply

### Optional

- **Trigger** - When to compute for Snapshot strategy (default: `OnCreate`)
  - `OnCreate` - Only when creating new records
  - `OnUpdate` - Only when updating existing records
  - `OnCreateAndUpdate` - Both create and update
  
- **CacheSeconds** - Cache duration for CachedLive strategy (default: 60)

## Form Rendering

Computed fields are automatically rendered with special treatment:

1. **Snapshot fields** (OnCreate trigger):
   - Excluded from create forms (auto-populated)
   - Shown as readonly in edit forms
   
2. **Live fields** (CachedLive/AlwaysLive):
   - Always readonly
   - Rendered with calculator icon (🧮)
   - Strategy shown in tooltip

3. **Visual Indicator**:
   ```html
   <div class="input-group">
     <input type="text" class="form-control" readonly disabled>
     <span class="input-group-text" title="Computed field (Snapshot)">
       <i class="bi bi-calculator"></i>
     </span>
   </div>
   ```

## API Integration

Computed values are included in API responses automatically:

```json
{
  "id": "ORD-001",
  "productId": "PROD-123",
  "quantity": 5,
  "unitPriceSnapshot": 49.99,      // Frozen at creation
  "currentPriceCached": 54.99,     // Current with cache
  "currentPriceLive": 54.99        // Real-time current
}
```

## Performance Considerations

### Snapshot Strategy
- ✅ Best performance - stored value
- ✅ No runtime overhead
- ⚠️ May be stale (by design)

### CachedLive Strategy
- ✅ Good performance with caching
- ⚠️ First access incurs lookup cost
- ⚠️ May show stale data within cache window

### AlwaysLive Strategy
- ❌ Performance cost on every access
- ⚠️ Avoid on list views with many items
- ✅ Always accurate and current

### Recommendations

1. **Use Snapshot** for:
   - Historical data (prices, rates)
   - Audit trail values
   - Values that should never change

2. **Use CachedLive** for:
   - Dashboard metrics
   - Frequently accessed derived values
   - Read-heavy scenarios where slight staleness is acceptable

3. **Use AlwaysLive** for:
   - Critical real-time data
   - Stock levels
   - Status fields
   - Detail views (not lists)

## Example: Order Management

See `ExampleComputedEntities.cs` for a complete working example demonstrating all three strategies in an Order/Product scenario.

The example shows:
- Product entity with base pricing
- Order entity with three computed price fields:
  - Snapshot: Historical price at order time
  - CachedLive: Current price with 60s cache
  - AlwaysLive: Real-time current price

## Integration in RouteHandlers

The framework automatically applies computed values:

```csharp
// On Create
await DataScaffold.ApplyAutoIdAsync(meta, instance, cancellationToken);
await DataScaffold.ApplyComputedFieldsAsync(meta, instance, ComputedTrigger.OnCreate, cancellationToken);
await DataScaffold.SaveAsync(meta, instance);

// On Update
await DataScaffold.ApplyComputedFieldsAsync(meta, instance, ComputedTrigger.OnUpdate, cancellationToken);
await DataScaffold.SaveAsync(meta, instance);
```

## Programmatic Access

For live strategies, use `ComputedFieldService`:

```csharp
// Get computed value
var value = await ComputedFieldService.GetComputedValueAsync(metadata, instance, field, cancellationToken);

// Clear cache for an entity
ComputedFieldService.ClearCache(metadata, instanceId);

// Clear all caches
ComputedFieldService.ClearAllCache();
```

## Testing

See `ComputedFieldTests.cs` for comprehensive unit tests covering:
- Attribute detection and metadata
- Form field rendering
- Snapshot computation on create/update
- Cached live with cache validation
- Always live with real-time updates
- Aggregations (Sum, Count, etc.)
- Cache management

## Limitations

1. Circular dependencies are not detected - avoid them
2. Cross-entity queries require entities to be registered
3. Aggregations require child collection to be loaded or queryable
4. Live strategies add overhead - use judiciously
5. No automatic cascade updates on source changes

## Future Enhancements

Potential future additions:
- Cascade update triggers
- Circular dependency detection
- Query-based aggregations for unloaded collections
- Formula-based computed fields
- Computed field indexing support
