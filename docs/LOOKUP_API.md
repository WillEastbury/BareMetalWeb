# Lookup API — Client-Side Data Queries

> **⚠️ EXPLORATION / EXPERIMENTAL** — This feature is under active development.

## Overview

The Lookup API provides a set of REST endpoints and a client-side JavaScript library (`bmw.lookup()`) for fetching entity data on demand. It enables dynamic client-side functionality like dependent dropdowns, live field population, inline validation, and aggregate queries — all without page reloads.

## Server-Side API Endpoints

All endpoints are under `/api/_lookup/` and return JSON responses.

### GET `/api/_lookup/{entityType}/{id}`

Fetch a single entity by its ID.

**Example:**
```
GET /api/_lookup/products/prod-123
```

**Response:**
```json
{
  "id": "prod-123",
  "name": "Widget",
  "sku": "WDG-001",
  "price": 29.99
}
```

### GET `/api/_lookup/{entityType}?filter=field:value`

Query entities with optional filters, sorting, and pagination.

**Parameters:**
| Parameter | Description | Example |
|-----------|-------------|---------|
| `filter`  | Field filter (repeatable) | `filter=IsActive:true&filter=Category:Electronics` |
| `sort`    | Sort field | `sort=Name` |
| `dir`     | Sort direction | `dir=asc` or `dir=desc` |
| `skip`    | Pagination offset | `skip=10` |
| `top`     | Page size | `top=25` |

**Example:**
```
GET /api/_lookup/products?filter=IsActive:true&sort=Name&dir=asc&top=10
```

**Response:**
```json
{
  "data": [
    { "id": "prod-1", "name": "Gadget", "price": 19.99 },
    { "id": "prod-2", "name": "Widget", "price": 29.99 }
  ],
  "count": 2
}
```

### GET `/api/_lookup/{entityType}/_field/{id}/{fieldName}`

Fetch a single field value from an entity.

**Example:**
```
GET /api/_lookup/products/_field/prod-123/Price
```

**Response:**
```json
{
  "field": "Price",
  "value": 29.99
}
```

### GET `/api/_lookup/{entityType}/_aggregate?fn={function}&field={field}&filter={filter}`

Perform aggregate operations on entity data.

**Supported functions:** `count`, `sum`, `avg`, `min`, `max`

**Parameters:**
| Parameter | Description | Required |
|-----------|-------------|----------|
| `fn`      | Aggregate function | Yes |
| `field`   | Field to aggregate (not needed for `count`) | For sum/avg/min/max |
| `filter`  | Field filter (repeatable) | No |

**Examples:**
```
GET /api/_lookup/products/_aggregate?fn=count
GET /api/_lookup/products/_aggregate?fn=sum&field=Price
GET /api/_lookup/orders/_aggregate?fn=count&filter=CustomerId:cust-1
```

**Response:**
```json
{
  "function": "count",
  "result": 42
}
```

### Error Responses

All endpoints return JSON error responses:
```json
{
  "error": "Entity with ID 'xyz' not found.",
  "status": 404
}
```

| Status | Meaning |
|--------|---------|
| 400    | Bad request (missing parameters) |
| 403    | Access denied (insufficient permissions) |
| 404    | Entity type, ID, or field not found |
| 500    | Internal server error |

## Client-Side JavaScript API

The `bmw-lookup.js` library is automatically loaded on all pages via the footer template.

### `bmw.lookup(entityType, idOrFilter, options)`

Fetch entity data from the server.

**Parameters:**
- `entityType` (string) — Entity type slug (e.g. `"products"`, `"customers"`)
- `idOrFilter` (string | object) — Entity ID string or filter object
- `options` (object, optional):
  - `aggregate` — Aggregate function (`"count"`, `"sum"`, `"avg"`, `"min"`, `"max"`)
  - `field` — Field name for aggregate operations
  - `sort` — Sort field name
  - `dir` — Sort direction (`"asc"` or `"desc"`)
  - `skip` — Pagination offset
  - `top` — Page size
  - `ttl` — Cache TTL in milliseconds (default: 30000)
  - `noCache` — Skip cache for this request (default: false)

**Returns:** `Promise<object>` — Parsed JSON response

**Examples:**
```javascript
// Fetch a single entity by ID
var product = await bmw.lookup("products", "prod-123");
console.log(product.name);   // "Widget"
console.log(product.price);  // 29.99

// Query entities with a filter
var activeProducts = await bmw.lookup("products", { IsActive: true });
console.log(activeProducts.data.length);

// Query with sorting and pagination
var topProducts = await bmw.lookup("products", null, {
    sort: "Price", dir: "desc", top: 5
});

// Aggregate: count
var orderCount = await bmw.lookup("orders", { CustomerId: "cust-1" }, {
    aggregate: "count"
});
console.log(orderCount.result); // 12

// Aggregate: sum
var totalSpend = await bmw.lookup("order-lines", { OrderId: "ord-5" }, {
    aggregate: "sum", field: "LineTotal"
});
console.log(totalSpend.result); // 459.97
```

### `bmw.lookupField(entityType, id, fieldName, options)`

Convenience wrapper to fetch a single field value.

**Parameters:**
- `entityType` (string) — Entity type slug
- `id` (string) — Entity ID
- `fieldName` (string) — Field name
- `options` (object, optional): `{ ttl, noCache }`

**Returns:** `Promise<{ field: string, value: any }>`

**Example:**
```javascript
var result = await bmw.lookupField("products", "prod-123", "Price");
console.log(result.value); // 29.99
```

### `bmw.lookupClearCache(entityType)`

Invalidate cached lookup data.

**Parameters:**
- `entityType` (string, optional) — If provided, only clears cache for this entity type. If omitted, clears all cached data.

**Example:**
```javascript
// Clear all cached data
bmw.lookupClearCache();

// Clear only product cache (e.g. after saving a product)
bmw.lookupClearCache("products");
```

## Caching & Deduplication

- **Client-side cache**: Results are cached for 30 seconds by default (configurable via `ttl` option)
- **Request deduplication**: Multiple concurrent requests for the same URL share the same in-flight promise
- **Cache invalidation**: Call `bmw.lookupClearCache()` after save operations to ensure fresh data

## Use Cases

### Dependent Dropdowns
```javascript
// When customer dropdown changes, load their orders
document.getElementById('CustomerId').addEventListener('change', async function() {
    var orders = await bmw.lookup("orders", { CustomerId: this.value });
    var select = document.getElementById('OrderId');
    select.innerHTML = '<option value="">Select order...</option>';
    orders.data.forEach(function(order) {
        var opt = document.createElement('option');
        opt.value = order.id;
        opt.textContent = order.orderNumber || order.id;
        select.appendChild(opt);
    });
});
```

### Live Field Population
```javascript
// When product is selected, auto-fill price
document.getElementById('ProductId').addEventListener('change', async function() {
    var result = await bmw.lookupField("products", this.value, "Price");
    document.getElementById('UnitPrice').value = result.value || '';
});
```

### Inline Validation
```javascript
// Check if email already exists
document.getElementById('Email').addEventListener('blur', async function() {
    var count = await bmw.lookup("users", { Email: this.value }, { aggregate: "count" });
    if (count.result > 0) {
        this.setCustomValidity('This email is already in use.');
    } else {
        this.setCustomValidity('');
    }
});
```

## Security Considerations

- **Entity-level permissions**: The server enforces entity permissions on every lookup request. Users can only query entities they have permission to access.
- **Field visibility**: Only fields marked with `View = true` are returned in responses.
- **Session cookies**: The JavaScript client sends session cookies with every request (`credentials: 'same-origin'`).
- **CSP**: Fetch calls to the same origin work with the existing `connect-src 'self'` policy.
- **Rate limiting**: All lookup endpoints are subject to the server's standard rate limiting via ClientRequestTracker.
- **Input sanitisation**: Filter values are parsed server-side with explicit field matching against registered entity metadata.

## Integration Points

- **Calculated fields (#66)**: Expressions can reference `lookup()` for cross-entity values
- **Computed fields (#58)**: Live strategy can use `lookup()` client-side instead of server render
- **Forms**: Dependent dropdowns, auto-populate fields on selection change
- **Remote commands (#59)**: Pre-validate before execution
- **Virtual objects (#57)**: Lookup works the same regardless of compiled vs virtual
- **Client-side rendering (#67)**: `lookup()` serves as a core data-fetching primitive
