# BareMetalWeb — Background Usage Guide

This document details the REST API endpoints, Service Principal authentication, and query language for programmatic access to BareMetalWeb.

---

## Table of Contents

- [REST API Endpoints](#rest-api-endpoints)
- [Authentication](#authentication)
  - [Session-Based (Browser)](#session-based-browser)
  - [Service Principal (API Key)](#service-principal-api-key)
  - [Creating a Service Principal](#creating-a-service-principal)
- [Query Language](#query-language)
  - [Query Parameters](#query-parameters)
  - [Operators](#operators)
  - [Sorting](#sorting)
  - [Full-Text Search](#full-text-search)
  - [Pagination](#pagination)
- [Data Entities](#data-entities)
  - [DataEntity Attribute](#dataentity-attribute)
  - [Slug Generation](#slug-generation)
  - [Auto-Generated Routes](#auto-generated-routes)
- [Response Format](#response-format)
- [Examples](#examples)

---

## REST API Endpoints

All data entities registered with the `[DataEntity]` attribute automatically receive six REST endpoints under `/api/{slug}`:

| HTTP Verb | Path                  | Operation                           |
|-----------|-----------------------|-------------------------------------|
| `GET`     | `/api/{slug}`         | List / query entities               |
| `POST`    | `/api/{slug}`         | Create a new entity                 |
| `GET`     | `/api/{slug}/{id}`    | Read a single entity by ID          |
| `PUT`     | `/api/{slug}/{id}`    | Replace an entity (full update)     |
| `PATCH`   | `/api/{slug}/{id}`    | Partial update of an entity         |
| `DELETE`  | `/api/{slug}/{id}`    | Delete an entity                    |

All API routes require authentication — either a valid session cookie or a Service Principal API key.

### Query Endpoints

| Verb  | Path              | Description                          | Auth Required |
|-------|-------------------|--------------------------------------|---------------|
| `GET` | `/query/ideas`    | Mock idea lookup (returns stub)      | No            |

**Parameters:**

| Parameter | Type   | Description          |
|-----------|--------|----------------------|
| `idea`    | string | The idea text to search for |

**Example:**

```bash
curl "https://your-site.azurewebsites.net/query/ideas?idea=my+cool+idea"
```

**Response:**

```json
{"result":"idea not found"}
```

This is a public, unauthenticated endpoint that accepts an optional `idea` query string and always returns `"idea not found"` as a mock stub.

### Additional Endpoints

| Verb   | Path                  | Description                      | Auth Required |
|--------|-----------------------|----------------------------------|---------------|
| `GET`  | `/status`             | Health check page                | No            |
| `GET`  | `/statusRaw`          | Raw status text                  | No            |
| `GET`  | `/metrics`            | Application metrics (HTML)       | Yes           |
| `GET`  | `/metrics/json`       | Application metrics (JSON)       | Yes           |
| `GET`  | `/admin/data/{type}`  | Admin data browser               | Yes (Admin)   |
| `GET`  | `/admin/logs`         | Application logs viewer          | Yes (Admin)   |

---

## Authentication

### Session-Based (Browser)

Standard browser authentication uses session cookies:

1. `POST /login` with `username` and `password` form fields.
2. On success, a session cookie is issued.
3. All subsequent requests include the cookie automatically.
4. MFA is supported via `/mfa` if enabled for the user.

### Service Principal (API Key)

For background services, scripts, and automation, use a **Service Principal** with an API key. Two header formats are supported:

**Option 1 — `ApiKey` header (recommended):**

```
ApiKey: <raw-api-key>
```

**Option 2 — `Authorization` header:**

```
Authorization: ApiKey <raw-api-key>
```

Both formats supply the raw API key string. The server resolves the key to a `SystemPrincipal` entity, which inherits from `User` and carries the same permissions.

#### Authentication Flow

1. The server checks for a session cookie first.
2. If no session and the request path starts with `/api`, it checks for an API key header.
3. The raw API key is encoded as Base64 of `principalName:rawApiKey`.
4. Each `SystemPrincipal` stores PBKDF2-hashed keys (100,000 iterations with per-key salt).
5. The server iterates active principals, verifying the key against stored hashes.
6. On match, the request proceeds with that principal's identity and permissions.

### Creating a Service Principal

1. Log in to the admin UI.
2. Navigate to `/admin/data/system-principals/create`.
3. Fill in a name and set `IsActive = true`.
4. Generate an API key — the raw key is a 32-character hex string (`Guid.NewGuid().ToString("N")`).
5. Add the key via `AddApiKey(rawKey)` which hashes it with PBKDF2 before storage.
6. Store the raw key securely — it cannot be retrieved after creation, only verified.

---

## Query Language

The list endpoint (`GET /api/{slug}`) accepts query parameters to filter, sort, and paginate results.

### Query Parameters

| Parameter | Description                                   | Example                        |
|-----------|-----------------------------------------------|--------------------------------|
| `q`       | Full-text search across all list-visible fields | `?q=john`                     |
| `field`   | Field name to filter on                        | `?field=Status`               |
| `value`   | Value to match against the field               | `?value=Active`               |
| `op`      | Comparison operator (default: `eq`)            | `?op=contains`                |
| `sort`    | Field name to sort by                          | `?sort=CreatedAt`             |
| `dir`     | Sort direction: `asc` or `desc`                | `?dir=desc`                   |
| `skip`    | Number of results to skip (offset)             | `?skip=20`                    |
| `top`     | Maximum number of results to return            | `?top=10`                     |

### Operators

Use the `op` parameter to specify how `field` and `value` are compared:

| Operator      | `op` value    | Description                              |
|---------------|---------------|------------------------------------------|
| Equals        | `eq`          | Exact match (default)                    |
| Not Equals    | `ne`          | Does not match                           |
| Contains      | `contains`    | Substring match (case-insensitive)       |
| Starts With   | `startswith`  | Value starts with the given string       |
| Ends With     | `endswith`    | Value ends with the given string         |
| In            | `in`          | Value is in a comma-separated list       |
| Not In        | `notin`       | Value is not in a comma-separated list   |
| Greater Than  | `gt`          | Numeric/date greater than                |
| Less Than     | `lt`          | Numeric/date less than                   |
| Greater or Equal | `gte`      | Greater than or equal                    |
| Less or Equal | `lte`         | Less than or equal                       |

### Sorting

Sort by any entity field using `sort` and `dir`:

```
GET /api/customers?sort=DisplayName&dir=asc
GET /api/orders?sort=CreatedAt&dir=desc
```

### Full-Text Search

The `q` parameter searches across all fields marked as list-visible. Matching uses `Contains` with `OR` logic — any field containing the search text qualifies the result:

```
GET /api/customers?q=smith
```

This searches `DisplayName`, `Email`, and any other list-visible field for "smith".

### Pagination

Use `skip` and `top` for offset-based pagination:

```
GET /api/customers?skip=0&top=10    # First page
GET /api/customers?skip=10&top=10   # Second page
GET /api/customers?skip=20&top=10   # Third page
```

### Combined Queries

Parameters can be combined:

```
GET /api/customers?field=Status&value=Active&op=eq&sort=DisplayName&dir=asc&skip=0&top=25
GET /api/orders?q=pending&sort=CreatedAt&dir=desc&top=50
```

---

## Data Entities

### DataEntity Attribute

Classes decorated with `[DataEntity]` are automatically exposed through the API and admin UI:

```csharp
[DataEntity("Customers", ShowOnNav = true, NavGroup = "CRM", Permissions = "Admin")]
public sealed class Customer : BaseDataObject
{
    [DataField(Label = "Name", Order = 1, Required = true, List = true)]
    public string DisplayName { get; set; } = string.Empty;

    [DataField(Label = "Email", Order = 2, List = true)]
    public string Email { get; set; } = string.Empty;
}
```

**DataEntity properties:**

| Property     | Type     | Description                                   |
|--------------|----------|-----------------------------------------------|
| `Name`       | `string` | Display name for the entity type              |
| `Slug`       | `string?`| Custom URL slug (auto-generated if omitted)   |
| `Permissions`| `string` | Required permission to access (e.g. `"Admin"`)|
| `ShowOnNav`  | `bool`   | Show in the admin navigation bar              |
| `NavGroup`   | `string?`| Group label in navigation                     |
| `NavOrder`   | `int`    | Sort order within navigation group            |

### Slug Generation

If no custom `Slug` is specified, one is generated from the entity name:

1. Convert to lowercase.
2. Keep only letters, digits; replace spaces/underscores/hyphens with `-`.
3. Collapse consecutive hyphens.
4. Trim leading/trailing hyphens.

Examples: `"Customers"` → `customers`, `"My API Keys"` → `my-api-keys`, `"System Principals"` → `system-principals`.

### Auto-Generated Routes

Once registered, each entity gets the full set of CRUD routes at `/api/{slug}` plus admin UI pages at `/admin/data/{slug}` for browsing, creating, editing, importing, cloning, and deleting records.

---

## Response Format

All API responses use `application/json` with pretty-printed output. The server uses a custom `Utf8JsonWriter`-based serializer (not `System.Text.Json.JsonSerializer`).

### List Response

```json
[
  {
    "Id": "abc123",
    "DisplayName": "John Smith",
    "Email": "john@example.com",
    "CreatedAt": "2025-01-15T10:30:00Z"
  },
  {
    "Id": "def456",
    "DisplayName": "Jane Doe",
    "Email": "jane@example.com",
    "CreatedAt": "2025-01-16T14:20:00Z"
  }
]
```

### Single Entity Response

```json
{
  "Id": "abc123",
  "DisplayName": "John Smith",
  "Email": "john@example.com",
  "CreatedAt": "2025-01-15T10:30:00Z"
}
```

### Error Responses

| Status Code | Meaning                                      |
|-------------|----------------------------------------------|
| `400`       | Bad request (invalid input or missing fields) |
| `401`       | Not authenticated                             |
| `403`       | Authenticated but insufficient permissions    |
| `404`       | Entity type or record not found               |
| `500`       | Internal server error                         |

---

## Examples

### List all customers

```bash
curl -H "ApiKey: your-api-key" \
  https://your-site.azurewebsites.net/api/customers
```

### Search customers by name

```bash
curl -H "ApiKey: your-api-key" \
  "https://your-site.azurewebsites.net/api/customers?q=smith"
```

### Filter by field with operator

```bash
curl -H "ApiKey: your-api-key" \
  "https://your-site.azurewebsites.net/api/customers?field=Status&value=Active&op=eq"
```

### Create a new entity

```bash
curl -X POST \
  -H "ApiKey: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"DisplayName":"New Customer","Email":"new@example.com"}' \
  https://your-site.azurewebsites.net/api/customers
```

### Update an entity

```bash
curl -X PATCH \
  -H "ApiKey: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{"Email":"updated@example.com"}' \
  https://your-site.azurewebsites.net/api/customers/abc123
```

### Delete an entity

```bash
curl -X DELETE \
  -H "ApiKey: your-api-key" \
  https://your-site.azurewebsites.net/api/customers/abc123
```

### Paginated, sorted, filtered query

```bash
curl -H "Authorization: ApiKey your-api-key" \
  "https://your-site.azurewebsites.net/api/orders?field=Status&value=Pending&op=eq&sort=CreatedAt&dir=desc&skip=0&top=25"
```
