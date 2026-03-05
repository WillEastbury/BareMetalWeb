# Export Nested/Embedded Components

## Overview

BareMetalWeb now supports exporting entities with their nested/embedded components (child lists) in multiple formats:

1. **Simple CSV** - Top-level entity fields only (original behavior)
2. **Flat CSV** - Parent fields repeated for each child row (denormalized)
3. **Multi-sheet ZIP** - Separate CSV files for parent and children with foreign keys
4. **Hierarchical JSON** - Nested structure with child arrays

## Usage

### UI: Export Dropdown

Both entity list and view pages now display an **Export** dropdown button instead of a simple CSV link. The dropdown provides options based on whether the entity has nested components.

#### For Entities Without Nested Components
- CSV (simple)
- JSON

#### For Entities With Nested Components (e.g., Order with OrderRows)
- CSV (simple) - parent fields only
- CSV (flat with nested) - parent repeated per child
- ZIP (multi-sheet) - orders.csv + orders_OrderRows.csv
- JSON (with nested) - hierarchical structure

### API: Query Parameters

Export endpoints support the following query parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `format` | string | SimpleCSV | Export format: `SimpleCSV`, `FlatCSV`, `MultiSheetZip`, `HierarchicalJSON` |
| `depth` | int | 1 | Maximum nesting depth (0-10) |
| `includeNested` | bool | true | Whether to include nested components |
| `components` | string | (all) | Comma-separated list of component field names to include |

### Examples

#### List Export - Simple CSV
```
GET /admin/data/orders/export?format=SimpleCSV
```
Returns CSV with Order fields only (OrderNumber, Customer, OrderDate, etc.)

#### List Export - Flat CSV
```
GET /admin/data/orders/export?format=FlatCSV
```
Returns denormalized CSV:
```csv
Id,OrderNumber,Customer,OrderDate,OrderRows.Product,OrderRows.Quantity,OrderRows.UnitPrice
ORD-001,12345,CUST-001,2026-01-15,PROD-001,2,10.50
ORD-001,12345,CUST-001,2026-01-15,PROD-002,1,5.00
ORD-002,67890,CUST-002,2026-01-16,PROD-003,5,2.50
```

#### List Export - Multi-sheet ZIP
```
GET /admin/data/orders/export?format=MultiSheetZip
```
Returns ZIP file containing:
- `orders.csv` - Parent entity data
- `orders_OrderRows.csv` - Child data with ParentId column

#### Single Entity Export - Hierarchical JSON
```
GET /admin/data/orders/ORD-001/export?format=HierarchicalJSON
```
Returns:
```json
{
  "Id": "ORD-001",
  "OrderNumber": "12345",
  "CustomerId": "CUST-001",
  "OrderDate": "2026-01-15",
  "Status": "Open",
  "CurrencyId": "USD",
  "OrderRows": [
    {
      "ProductId": "PROD-001",
      "Quantity": 2,
      "UnitPrice": 10.50,
      "LineTotal": 21.00,
      "Notes": "Item 1"
    },
    {
      "ProductId": "PROD-002",
      "Quantity": 1,
      "UnitPrice": 5.00,
      "LineTotal": 5.00,
      "Notes": "Item 2"
    }
  ]
}
```

#### Selective Component Export
```
GET /admin/data/orders/export?format=FlatCSV&components=OrderRows
```
Includes only the OrderRows component (useful if entity has multiple child lists)

#### Depth Control
```
GET /admin/data/orders/export?format=HierarchicalJSON&depth=2
```
Exports nested components up to 2 levels deep

## Implementation Details

### Routes

- **List Export**: `GET /admin/data/{type}/export`
- **Single Entity Export**: `GET /admin/data/{type}/{id}/export`

### Backward Compatibility

The original CSV export routes remain unchanged:
- `GET /admin/data/{type}/csv` - Still works, returns simple CSV
- `GET /admin/data/{type}/html` - Still works, returns HTML table

### Performance

- **Streaming**: All export formats use streaming to handle large datasets efficiently
- **Memory**: Multi-sheet ZIP uses `MemoryStream` with `leaveOpen: true` for minimal allocations
- **Permissions**: Existing field-level and entity-level permission checks are enforced

### Security

- All exports respect existing authentication and authorization
- Field-level permissions are honored
- CSRF protection not required (GET requests, read-only)

## Example Entity Structure

```csharp
[DataEntity("Orders", ShowOnNav = true, NavGroup = "Sales")]
public class Order : BaseDataObject
{
    [DataField(Label = "Order Number", Order = 1)]
    public string OrderNumber { get; set; } = string.Empty;
    
    [DataField(Label = "Customer", Order = 2)]
    [DataLookup(typeof(Customer), DisplayField = "Name")]
    public string CustomerId { get; set; } = string.Empty;
    
    [DataField(Label = "Order Rows", Order = 8)]
    public List<OrderRow> OrderRows { get; set; } = new();
}

public class OrderRow
{
    [DataField(Label = "Product", Order = 1)]
    [DataLookup(typeof(Product), DisplayField = "Name")]
    public string ProductId { get; set; } = string.Empty;
    
    [DataField(Label = "Quantity", Order = 2)]
    public int Quantity { get; set; } = 1;
    
    [DataField(Label = "Unit Price", Order = 3)]
    public decimal UnitPrice { get; set; }
}
```

The `OrderRows` field is automatically detected as a nested component because:
1. It's a `List<T>` where T is a class
2. OrderRow has `[DataField]` attributes
3. The field is marked as viewable

## Testing

Run export tests:
```bash
dotnet test BareMetalWeb.Host.Tests --filter "FullyQualifiedName~ExportTests"
```

All 9 export tests should pass, covering:
- ExportOptions parsing from query strings
- Nested component detection
- Data extraction from nested lists
- Empty list handling
