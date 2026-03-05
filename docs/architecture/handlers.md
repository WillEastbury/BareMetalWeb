# HTTP Handler Reference

This document catalogues every HTTP route registered by BareMetalWeb, which handler
method services it, what it does, its authentication requirement, and any notable
implementation details.

> **Architecture note:** BareMetalWeb has **no middleware pipeline**.  All routes are
> stored in `BareMetalWebServer.routes` (a plain `Dictionary<string, RouteHandlerData>`)
> and are dispatched by a single `RequestDelegate` wired via `app.Run(…)`.  Handlers are
> plain `ValueTask` methods (or lambdas) that receive the raw `HttpContext` — no
> controller base class, no action filters, no model binding framework.

---

## Route Registration Functions

Routes are registered during startup from `BareMetalWebExtensions.UseBareMetalWeb()`.
Each group of related routes has a dedicated `Register*` extension method on
`IBareWebHost`:

| Registration method | Routes registered |
|---|---|
| `RegisterStaticRoutes` | `/`, `/status`, `/statusRaw`, `/time` |
| `RegisterAuthRoutes` | `/login`, `/logout`, `/register`, `/mfa`, `/account`, SSO, `/setup` |
| `RegisterMonitoringRoutes` | `/metrics`, `/metrics/json`, `/topips`, `/suspiciousips` |
| `RegisterAdminRoutes` | `/admin/*`, `/admin/gallery`, data-size |
| `RegisterDataRoutes` | `/ssr/admin/data/*` (legacy SSR CRUD) |
| `RegisterEntityMetadataRoute` | `GET /api/metadata/{entity}` |
| `RegisterLookupApiRoutes` | `GET/POST /api/_lookup/*` |
| `RegisterBinaryApiRoutes` | `GET/POST/PUT/DELETE/PATCH /api/_binary/*`, `/api/_metrics`, `POST /api/graphql`, cluster, tenant, vector, agent, pages, products, basket, checkout |
| `RegisterApiRoutes` | `GET/POST/PUT/PATCH/DELETE /api/{type}`, `/api/jobs/*`, `/api/admin/*`, document chain, remote commands |
| `RegisterVNextRoutes` | `GET /meta/objects`, `GET /meta/{object}`, `GET /d`, `GET /{*path}` |
| `RegisterRuntimeApiRoutes` | `GET /meta/entity/{name}`, `POST /query`, `POST /intent`, `/api/meta/*` |
| `RegisterMcpRoutes` | `POST /mcp` |
| `RegisterOpenApiRoute` | `GET /openapi.json` |
| `RegisterReportRoutes` | `GET/GET /reports/*`, `GET /api/reports/*` |

---

## Static & Infrastructure Routes

### `GET /`

**Handler:** `RouteHandlers.DefaultPageHandler`  
**Auth:** Public (no login required)  
**Description:** Renders the home / landing page using the HTML template system.
Returns the `index.html` template filled with app metadata tokens.

---

### `GET /status`

**Handler:** Inline lambda (returns HTML)  
**Auth:** Public  
**Description:** Returns a minimal HTML "OK" status page.  Used for load-balancer
health checks.  Does not touch the database or template engine.

---

### `GET /statusRaw`

**Handler:** Inline lambda  
**Auth:** Public  
**Description:** Returns the plain-text string `OK`.  Preferred for programmatic
health checks (avoids HTML parsing).

---

### `GET /time`

**Handler:** `RouteHandlers.TimeRawHandler`  
**Auth:** Public  
**Description:** Returns the current UTC time as a plain-text string.  Useful for
clock-skew debugging in cluster or proxy scenarios.

---

## Authentication Routes

### `GET /login` / `POST /login`

**Handler:** `RouteHandlers.LoginHandler` / `RouteHandlers.LoginPostHandler`  
**Auth:** Public  
**Description:** Renders the login form (GET) and processes credentials (POST).
POST validates username + PBKDF2 password hash, creates a signed session cookie, and
redirects to `/`.  If the user has TOTP MFA enabled the session is flagged
`MfaPending` and they are redirected to `/mfa`.

---

### `GET /mfa` / `POST /mfa`

**Handler:** `RouteHandlers.MfaChallengeHandler` / `RouteHandlers.MfaChallengePostHandler`  
**Auth:** Session cookie (MfaPending state)  
**Description:** Challenges the user for their 6-digit TOTP code (GET renders the
form, POST validates and promotes the session to fully-authenticated).

---

### `GET /register` / `POST /register`

**Handler:** `RouteHandlers.RegisterHandler` / `RouteHandlers.RegisterPostHandler`  
**Auth:** Public (only when `Auth:AllowSelfRegistration=true`)  
**Description:** Self-registration flow.  POST validates the submitted user data,
hashes the password, and creates a new `User` record.

---

### `GET /logout` / `POST /logout`

**Handler:** `RouteHandlers.LogoutHandler` / `RouteHandlers.LogoutPostHandler`  
**Auth:** Authenticated  
**Description:** Invalidates the session cookie and deletes the `UserSession` record.
GET renders a confirmation page; POST performs the deletion.

---

### `GET /auth/sso/login`

**Handler:** `RouteHandlers.SsoLoginHandler`  
**Auth:** Public  
**Description:** Initiates an Entra ID (Azure AD) OAuth2 / OIDC authorization-code
flow by redirecting the browser to the Microsoft identity platform authorization
endpoint.  The `state` parameter includes a CSRF nonce to prevent open-redirect
attacks.

---

### `GET /auth/sso/callback`

**Handler:** `RouteHandlers.SsoCallbackHandler`  
**Auth:** Public (callback from identity provider)  
**Description:** Receives the authorization code from the identity provider, exchanges
it for tokens via `EntraIdService`, loads or provisions the local `User` record, and
sets the session cookie.

---

### `GET /auth/sso/logout`

**Handler:** `RouteHandlers.SsoLogoutHandler`  
**Auth:** Authenticated  
**Description:** Signs the user out locally and redirects to the Azure AD global
logout endpoint (single sign-out).

---

### `GET /account`

**Handler:** `RouteHandlers.AccountHandler`  
**Auth:** Authenticated  
**Description:** Account management page: display name, email, current permissions.

---

### `GET /account/mfa` / `GET /account/mfa/setup` / `POST /account/mfa/setup`

**Handler:** `RouteHandlers.MfaStatusHandler` / `MfaSetupHandler` / `MfaSetupPostHandler`  
**Auth:** Authenticated  
**Description:** View current MFA status (GET `/account/mfa`); display QR code and
secret for enrolment (GET `/account/mfa/setup`); confirm first-time TOTP code and
persist the secret (POST `/account/mfa/setup`).

---

### `GET /account/mfa/reset` / `POST /account/mfa/reset`

**Handler:** `RouteHandlers.MfaResetHandler` / `RouteHandlers.MfaResetPostHandler`  
**Auth:** Admin  
**Description:** Admin-level MFA reset: disables TOTP for a target user so they can
re-enrol on next login.

---

### `GET /setup` / `POST /setup`

**Handler:** `RouteHandlers.SetupHandler` / `RouteHandlers.SetupPostHandler`  
**Auth:** Public (only accessible when no admin user exists)  
**Description:** First-run setup wizard.  Creates the initial admin user account and
seeds the default report definitions.  Once an admin user exists the route redirects
to `/login`.

---

## Monitoring Routes

### `GET /metrics`

**Handler:** Inline lambda (SSR HTML)  
**Auth:** `monitoring` permission  
**Description:** Renders an SSR HTML dashboard showing real-time request metrics
from `MetricsTracker`: request counts, latency histogram, error rates, and top-N
IP addresses.

---

### `GET /metrics/json`

**Handler:** `RouteHandlers.MetricsJsonHandler`  
**Auth:** `monitoring` permission  
**Description:** Returns the same metrics as `/metrics` but as a JSON object suitable
for scraping by Prometheus / Grafana dashboards or monitoring scripts.

---

### `GET /topips`

**Handler:** Inline lambda  
**Auth:** `monitoring` permission  
**Description:** Lists the top IP addresses by request volume over the rolling window
tracked by `ClientRequestTracker`.

---

### `GET /suspiciousips`

**Handler:** Inline lambda  
**Auth:** `monitoring` permission  
**Description:** Lists IP addresses that have been throttled (429 responses) or exceed
the suspicious-activity threshold in `ClientRequestTracker`.

---

## Admin Routes

### `GET /admin/logs`

**Handler:** `RouteHandlers.LogsViewerHandler`  
**Auth:** Admin  
**Description:** Paged SSR log viewer.  Reads per-hour log files written by
`DiskBufferedLogger` and renders them with syntax highlighting.  Supports date/time
range filtering via query parameters.

---

### `GET /admin/logs/prune` / `POST /admin/logs/prune`

**Handler:** `RouteHandlers.LogsPruneHandler` / `RouteHandlers.LogsPrunePostHandler`  
**Auth:** Admin  
**Description:** GET shows a form to choose how many days of logs to retain.
POST deletes log files older than the specified cutoff.

---

### `GET /admin/logs/download`

**Handler:** `RouteHandlers.LogsDownloadHandler`  
**Auth:** Admin  
**Description:** Streams a ZIP archive containing all log files from the current
log directory for offline analysis.

---

### `GET /admin/sample-data` / `POST /admin/sample-data`

**Handler:** `RouteHandlers.SampleDataHandler` / `RouteHandlers.SampleDataPostHandler`  
**Auth:** Admin  
**Description:** SSR form that triggers generation of sample / demo data for all
registered entity types.  POST kicks off a `BackgroundJobService` job and redirects
to a progress page.

---

### `GET /admin/reload-templates`

**Handler:** `RouteHandlers.ReloadTemplatesHandler`  
**Auth:** Admin  
**Description:** Hot-reloads all HTML templates from disk without restarting the
server.  Useful during active development.

---

### `GET /admin/wipe-data` / `POST /admin/wipe-data`

**Handler:** `RouteHandlers.WipeDataHandler` / `RouteHandlers.WipeDataPostHandler`  
**Auth:** Admin  
**Description:** Completely deletes all entity data (not users / sessions).
POST validates the CSRF token, launches a background job, and shows a progress page.

---

### `GET /admin/entity-designer`

**Handler:** `RouteHandlers.EntityDesignerHandler`  
**Auth:** Admin  
**Description:** Renders the AI-assisted entity designer UI.  Allows defining new
entity types visually; uses the `BareMetalWeb.AI` tools to suggest field layouts.

---

### `GET /admin/gallery`

**Handler:** `RouteHandlers.GalleryHandler`  
**Auth:** Admin  
**Description:** Lists available gallery packages (pre-built entity bundles).

---

### `POST /admin/gallery/deploy/{package}`

**Handler:** `RouteHandlers.GalleryDeployPostHandler`  
**Auth:** Admin  
**Description:** Deploys a gallery package: registers entity types, seeds default
data, and refreshes the navigation menu.

---

### `GET /admin/data-sizes`

**Handler:** `RouteHandlers.DataSizingHandler`  
**Auth:** Admin  
**Description:** Displays disk usage per entity type: file count, total bytes, and
average record size.  Reads directly from the data directory without touching the
`IDataProvider` layer.

---

## Legacy SSR Data Routes (`/ssr/admin/data/*`)

All routes in this group are served by `RegisterDataRoutes` and use the SSR HTML
template engine.  The VNext SPA at `/d` is the preferred entry point; these routes
remain for fallback and direct linking.

| Route | Handler | Description |
|---|---|---|
| `GET /ssr/admin/data` | `DataEntitiesHandler` | List entity types |
| `GET /ssr/admin/data/{type}` | `DataListHandler` | Paginated list of records |
| `GET /ssr/admin/data/{type}/csv` | `DataListCsvHandler` | CSV export of all records |
| `GET /ssr/admin/data/{type}/html` | `DataListHtmlHandler` | HTML fragment for embedding |
| `GET /ssr/admin/data/{type}/export` | `DataListExportHandler` | Multi-format export (JSON/CSV/ZIP) |
| `GET /ssr/admin/data/{type}/import` | `DataImportHandler` | Import form |
| `POST /ssr/admin/data/{type}/import` | `DataImportPostHandler` | Process uploaded file |
| `GET /ssr/admin/data/{type}/create` | `DataCreateHandler` | New record form |
| `POST /ssr/admin/data/{type}/create` | `DataCreatePostHandler` | Save new record |
| `GET /ssr/admin/data/{type}/{id}` | `DataViewHandler` | Record detail view |
| `GET /ssr/admin/data/{type}/{id}/rtf` | `DataViewRtfHandler` | Download record as RTF |
| `GET /ssr/admin/data/{type}/{id}/html` | `DataViewHtmlHandler` | Record as HTML fragment |
| `GET /ssr/admin/data/{type}/{id}/export` | `DataViewExportHandler` | Single-record export |
| `GET /ssr/admin/data/{type}/{id}/edit` | `DataEditHandler` | Edit form |
| `POST /ssr/admin/data/{type}/{id}/edit` | `DataEditPostHandler` | Save edits |
| `POST /ssr/admin/data/{type}/{id}/clone` | `DataClonePostHandler` | Clone record |
| `POST /ssr/admin/data/{type}/{id}/clone-edit` | `DataCloneEditPostHandler` | Clone + open in editor |
| `GET /ssr/admin/data/{type}/{id}/delete` | `DataDeleteHandler` | Delete confirmation page |
| `POST /ssr/admin/data/{type}/{id}/delete` | `DataDeletePostHandler` | Execute delete |
| `POST /ssr/admin/data/{type}/bulk-delete` | `DataBulkDeleteHandler` | Delete multiple records by ID list |
| `GET /ssr/admin/data/{type}/bulk-export` | `DataBulkExportHandler` | Export selected records |

**Auth:** All routes require at minimum the `Authenticated` permission; write
operations check entity-level permission annotations (`[DataEntity(Permissions=…)]`).

---

## Entity Metadata Route

### `GET /api/metadata/{entity}`

**Handler:** Inline lambda (registered by `RegisterEntityMetadataRoute`)  
**Auth:** Authenticated  
**Description:** Returns the compiled `DataEntityMetadata` for the named entity slug
as JSON.  Used by the VNext SPA to build forms and grids without a round-trip to
`/meta/{object}`.  Must be registered before the generic `/api/{type}` route.

---

## Lookup API Routes (`/api/_lookup/*`)

Registered by `RegisterLookupApiRoutes`.  All routes require Authenticated permission.
Field/sort inputs are validated against entity metadata to prevent injection.

| Route | Handler | Description |
|---|---|---|
| `GET /api/_lookup/{type}` | `LookupApiHandlers.QueryEntitiesHandler` | Paginated, filterable entity list for dropdown population. Supports `?search=`, `?searchField=`, `?from=`, `?via=` (relationship validation). |
| `GET /api/_lookup/{type}/{id}` | `LookupApiHandlers.GetEntityByIdHandler` | Load a single entity by ID with all display fields resolved. |
| `POST /api/_lookup/{type}/_batch` | `LookupApiHandlers.BatchGetEntitiesHandler` | Load multiple entities by ID list (JSON body `{ "ids": [...] }`). Used by the SPA to pre-fetch FK display values. |
| `GET /api/_lookup/{type}/_field/{id}/{fieldName}` | `LookupApiHandlers.GetEntityFieldHandler` | Read a single field value from a specific record. Validates `fieldName` against `meta.Fields[View=true]`. |
| `GET /api/_lookup/{type}/_aggregate` | `LookupApiHandlers.AggregateEntitiesHandler` | Returns aggregate statistics (count, sum, avg, min, max) for a field. |

---

## Binary / Core CRUD API Routes (`/api/_binary/*`)

Registered by `RegisterBinaryApiRoutes`.  These routes expose a fully schema-aware
binary CRUD API that is independent of the generic `/api/{type}` routes.  They are
driven by `BinaryArchitecture` entity layouts.

| Route | Handler | Description |
|---|---|---|
| `GET /api/_binary/_key` | `BinaryApiHandlers.KeyHandler` | Returns the current server-side AES encryption key fingerprint for client key negotiation. |
| `GET /api/_binary/{type}/_schema` | `BinaryApiHandlers.SchemaHandler` | Returns the `BinaryArchitecture` field layout for an entity type as JSON. |
| `GET /api/_binary/{type}/_aggregate` | `BinaryApiHandlers.AggregateHandler` | Runs an aggregation query over the entity store. |
| `GET /api/_binary/{type}/_raw` | `BinaryApiHandlers.RawListHandler` | Raw (un-projected) list query with field selector support. |
| `GET /api/_binary/{type}/_aggregations` | `BinaryApiHandlers.AggregationDefsHandler` | Lists defined aggregations for an entity type. |
| `GET /api/_binary/{type}/_layout` | `DeltaApiHandlers.LayoutHandler` | Returns the entity layout, including field deltas and versioning metadata. |
| `GET /api/_binary/{type}/_actions` | `ActionApiHandlers.ListActionsHandler` | Lists all `ActionDefinition` records for an entity type. |
| `POST /api/_binary/{type}/_action/{actionId}` | `ActionApiHandlers.ExecuteActionHandler` | Executes a named `ActionDefinition` against a set of records, running through `ActionExpander` → `TransactionEnvelope` → WAL commit. |
| `GET /api/_binary/{type}/{id}` | `BinaryApiHandlers.GetHandler` | Load a single record by ID (binary-serialized entity). |
| `GET /api/_binary/{type}` | `BinaryApiHandlers.ListHandler` | Paginated list with optional filter/sort/projection. |
| `POST /api/_binary/{type}` | `BinaryApiHandlers.CreateHandler` | Create a new record. |
| `PUT /api/_binary/{type}/{id}` | `BinaryApiHandlers.UpdateHandler` | Full replace of a record by ID. |
| `DELETE /api/_binary/{type}/{id}` | `BinaryApiHandlers.DeleteHandler` | Delete a record by ID. |
| `PATCH /api/_binary/{type}/{id}` | `DeltaApiHandlers.DeltaHandler` | Partial update using a field-delta payload (only changed fields transmitted). |

---

## Engine Metrics Route

### `GET /api/_metrics`

**Handler:** `RouteHandlers.EngineMetricsJsonHandler` (inline lambda in `RegisterBinaryApiRoutes`)  
**Auth:** Admin  
**Description:** Returns internal engine metrics from `EngineMetrics`: WAL write
throughput, serializer call counts, query plan cache hit/miss rates, and index
lookup timings.

---

## GraphQL Route

### `POST /api/graphql`

**Handler:** `GraphQLHandler.HandleAsync`  
**Auth:** Authenticated (raw page, no CSRF required)  
**Description:** A minimal GraphQL execution engine built without external libraries.
Accepts `{ "query": "...", "variables": { } }`.  Supports `query` and `mutation`
operations over all entities registered with `DataScaffold`.  Introspection is
supported.  The resolver uses `DataStoreProvider.Current` directly.

**Security note:** The GraphQL engine applies the same entity-level permission checks
as the REST API.  Fields marked `View=false` are excluded from schema introspection
and query results.

---

## Cluster API Routes

Registered by `RegisterBinaryApiRoutes`. All routes require Admin permission.

| Route | Handler | Description |
|---|---|---|
| `GET /api/_cluster` | `ClusterApiHandlers.ClusterStatusHandler` | Returns current `ClusterState`: node role (Leader / Follower), last heartbeat, peer list, and WAL head position. |
| `GET /api/_cluster/replicate` | `ClusterApiHandlers.ReplicationHandler` | Triggers a WAL replication pull from the current leader.  Used during follower catch-up. |
| `POST /api/_cluster/stepdown` | `ClusterApiHandlers.StepDownHandler` | Requests the current leader to step down and trigger a new election. |

---

## Tenant API Routes

Registered by `RegisterBinaryApiRoutes`. All routes require Admin permission unless noted.

| Route | Handler | Description |
|---|---|---|
| `GET /api/tenants` | `TenantApiHandlers.ListTenantsHandler` | Lists all provisioned tenants (multitenancy must be enabled). |
| `GET /api/tenants/{id}` | `TenantApiHandlers.GetTenantHandler` | Returns configuration for a specific tenant. |
| `POST /api/tenants` | `TenantApiHandlers.ProvisionTenantHandler` | Provisions a new tenant (creates data root, registers data store). |
| `PUT /api/tenants/{id}/branding` | `TenantApiHandlers.UpdateBrandingHandler` | Updates branding settings (app name, logo URL, primary colour) for a tenant. |
| `PUT /api/tenants/{id}/quotas` | `TenantApiHandlers.UpdateQuotasHandler` | Updates resource quotas (storage limit, max users) for a tenant. |
| `GET /api/tenant/branding` | `TenantApiHandlers.GetCurrentBrandingHandler` | Returns branding for the tenant inferred from the current request's `Host` header. Auth: Public. |

---

## Vector Index API Routes

Registered by `RegisterBinaryApiRoutes`.

> See also: [`vector-index.md`](./vector-index.md) for the full ANN engine architecture.

| Route | Handler | Auth | Description |
|---|---|---|---|
| `POST /api/vector/search` | `VectorApiHandlers.SearchHandler` | Authenticated | ANN top-K search.  Body: `{ entity, field, vector: float[], top? }`.  Returns `{ results: [{id, distance}] }`. |
| `POST /api/vector/upsert` | `VectorApiHandlers.UpsertHandler` | Authenticated | Insert or update an embedding.  Body: `{ entity, field, objectId: uint, embedding: float[] }`. Returns 204. |
| `POST /api/vector/delete` | `VectorApiHandlers.DeleteHandler` | Authenticated | Tombstone a vector.  Body: `{ entity, field, objectId: uint }`. Returns 204. |
| `GET /api/vector/indexes` | `VectorApiHandlers.ListIndexesHandler` | Authenticated | Lists all registered vector index definitions (entity, field, dimension, metric, degree, live count). |
| `POST /api/vector/register` | `VectorApiHandlers.RegisterHandler` | Admin | Registers a new vector index definition.  Body: `{ entity, field, dimension: ushort, metric?, maxDegree? }`. Returns 201. |

---

## Agent Chat Route

### `POST /api/agent/chat`

**Handler:** `AgentApiHandlers.ChatHandler`  
**Auth:** Authenticated (raw page, no CSRF required)  
**Description:** Natural-language query interface backed by `AgentApiHandlers`.
Accepts `{ "message": "..." }` and returns `{ "reply": "..." }`.

Supported commands:

| Command | Action |
|---|---|
| `help` / `?` | Lists available commands |
| `entities` / `types` | Lists all registered entity types |
| `status` | Reports entity count and active data provider |
| `schema <entity>` | Shows field names and types for an entity |
| `count <entity>` | Returns record count for an entity |
| `list <entity>` | Returns top 10 records |
| `show <entity> <id>` | Returns a link to the detail view |
| `search <entity> <term>` | Full-text search on `Name` field |

**Note:** `AgentApiHandlers` is a simple rule-based NLP engine.  For richer AI
interactions (function-calling, tool use) see `BareMetalWeb.AI.AdminAssistantService`
which registers full tool definitions with `IChatClient`.

---

## Page & Product Routes

### `GET /page/{slug}`

**Handler:** `RouteHandlers.BuildPageHandler(PageRenderer.ConfigurePageAsync)`  
**Auth:** Public  
**Description:** Serves CMS-managed pages stored as `PageInfo` records.
`PageRenderer.ConfigurePageAsync` loads the page by slug, applies template
replacement, and streams the result.

---

### `GET /api/pages`

**Handler:** `PageRenderer.ListPagesHandler`  
**Auth:** Authenticated  
**Description:** Returns all published pages as JSON (slug, title, template).

---

### `GET /products`

**Handler:** `RouteHandlers.BuildPageHandler(ProductRenderer.ConfigureCategoryBrowseAsync)`  
**Auth:** Public  
**Description:** Product catalogue root: renders a category browser from the
`Product` entity store.

---

### `GET /products/{category}`

**Handler:** `RouteHandlers.BuildPageHandler(ProductRenderer.ConfigureProductGridAsync)`  
**Auth:** Public  
**Description:** Renders the product grid for a specific category with pagination.

---

## Basket & Checkout Routes

| Route | Handler | Auth | Description |
|---|---|---|---|
| `GET /api/basket` | `BasketApiHandlers.GetBasketHandler` | Public | Returns the current session's basket as JSON. |
| `POST /api/basket/add` | `BasketApiHandlers.AddItemHandler` | Public | Add an item to the basket. Body: `{ productId, quantity }`. |
| `POST /api/basket/remove` | `BasketApiHandlers.RemoveItemHandler` | Public | Remove an item from the basket by product ID. |
| `POST /api/basket/clear` | `BasketApiHandlers.ClearBasketHandler` | Public | Empty the basket. |
| `POST /api/checkout` | `CheckoutApiHandlers.CheckoutHandler` | Public | Convert the basket to an order, run validation and payment pre-auth. |
| `POST /api/checkout/confirm` | `CheckoutApiHandlers.ConfirmPaymentHandler` | Public | Confirm payment intent and finalize the order. |

---

## Generic REST CRUD Routes (`/api/{type}/*`)

These routes map the `{type}` path segment to an entity slug registered with
`DataScaffold`.  They are registered last by `RegisterApiRoutes` so more-specific
routes take precedence.

| Route | Handler | Description |
|---|---|---|
| `GET /api/{type}` | `DataApiListHandler` | Paginated list.  Supports `?skip`, `?top`, `?sort`, `?dir`, `?search`, and filter clauses as query parameters. |
| `POST /api/{type}/import` | `DataApiImportHandler` | Bulk import from JSON or CSV file (multipart/form-data). |
| `POST /api/{type}` | `DataApiPostHandler` | Create a new record.  JSON body; runs validation, calculated fields, and file upload handling. |
| `GET /api/{type}/{id}` | `DataApiGetHandler` | Load a single record by ID.  Returns JSON object. |
| `PUT /api/{type}/{id}` | `DataApiPutHandler` | Full replace of a record. |
| `PATCH /api/{type}/{id}` | `DataApiPatchHandler` | Partial update (RFC 7396 merge-patch semantics). |
| `DELETE /api/{type}/{id}` | `DataApiDeleteHandler` | Delete a record. |
| `GET /api/{type}/{id}/files/{field}` | `DataApiFileGetHandler` | Download an uploaded file attached to the named field. |
| `POST /api/{type}/{id}/_command/{command}` | `DataCommandHandler` | Execute a named remote command decorated with `[RemoteCommand]` on the entity. |

**Auth:** All routes require `Authenticated`.  Write routes additionally check
`DataEntityMetadata.Permissions`.

---

## Document Chain Routes

### `GET /api/{type}/{id}/_related-chain`

**Handler:** Inline lambda (registered in `RegisterApiRoutes`)  
**Auth:** Authenticated  
**Description:** Returns the upstream/downstream document chain for a record.
Upstream: records this record links to (via `[RelatedDocument]` FK fields).
Downstream: records that have a `[RelatedDocument]` field pointing to this record.
Used to populate the Sankey chart in the VNext detail view.

Response shape:
```json
{
  "sourceSlug": "order",
  "sourceId": "42",
  "upstream":   [{ "fieldName", "fieldLabel", "targetSlug", "targetName", "id", "label" }],
  "downstream": [{ "fieldName", "fieldLabel", "targetSlug", "targetName", "id", "label" }]
}
```

---

### `GET /api/_document-chain-graph`

**Handler:** Inline lambda (registered in `RegisterApiRoutes`)  
**Auth:** Authenticated  
**Description:** Aggregate Sankey graph data across all entities.  Returns node
counts and edge weights (linked-record counts) for rendering a flow diagram of the
entire document-chain topology.

---

## Background Job Routes

| Route | Handler | Auth | Description |
|---|---|---|---|
| `GET /api/jobs` | `JobsListHandler` | Authenticated | Lists all running and recently completed background jobs. |
| `GET /api/jobs/{jobId}` | `JobStatusHandler` | Authenticated | Returns status of a specific job (`{ jobId, status, progress, result }`).  202 while running, 200 on completion. |
| `DELETE /api/jobs/{jobId}` | `CancelJobHandler` | Admin | Requests cancellation of a running job. |
| `POST /api/admin/sample-data` | `AdminSampleDataJsonHandler` | Admin | JSON API version of sample-data generation (for VNext SPA; validates `X-CSRF-Token` header). |
| `POST /api/admin/wipe-data` | `AdminWipeDataJsonHandler` | Admin | JSON API version of data wipe (for VNext SPA; validates `X-CSRF-Token` header). |

---

## Query Plan History Route

### `GET /api/admin/query-plans`

**Handler:** `RouteHandlers.QueryPlanHistoryHandler`  
**Auth:** Admin  
**Description:** Returns the in-memory circular buffer from `QueryPlanHistory`:
the last N query plans executed (entity, clauses, chosen strategy, duration, index
used or full-scan).  Used to identify slow queries and missing indexes.

---

## VNext SPA Shell Routes

Registered by `RegisterVNextRoutes`.

### `GET /meta/objects`

**Handler:** Inline lambda  
**Auth:** Authenticated  
**Description:** Returns the list of entity types accessible to the current user
(filtered by `IsEntityAccessible`), including slug, name, nav group/order, and view
type.  Cached by the client for 5 minutes.  Used by the SPA to build the navigation
sidebar.

---

### `GET /meta/{object}`

**Handler:** Inline lambda  
**Auth:** Authenticated  
**Description:** Returns the full schema for a single entity: field definitions
(with lookup metadata, computed flag, copy-from-parent), sub-field schemas for
`List<T>` fields, and available commands.  Cached by the client for 5 minutes.

---

### `GET /d`

**Handler:** `ServeVNextShell` helper  
**Auth:** Authenticated  
**Description:** Primary VNext SPA entry point.  Appears in the Admin nav dropdown
as "Data".  Serves the SPA shell HTML which inlines `__BMW_META_OBJECTS__` and
`__BMW_LOOKUP_PREFETCH__` window globals to eliminate API round-trips on first
paint.

---

### `GET /{*path}`

**Handler:** `ServeVNextShell` helper  
**Auth:** Authenticated  
**Description:** Catch-all SPA fallback.  Any path not matched by a more-specific
route is served the SPA shell (0 literal segments, so it sorts last).  Enables
client-side routing via the History API.

---

## Runtime API Routes

Registered by `RegisterRuntimeApiRoutes`.  These use `RuntimeEntityRegistry`
(metadata-driven entity definitions stored in the database rather than compiled
C# classes).

| Route | Auth | Description |
|---|---|---|
| `GET /meta/entity/{name}` | Authenticated | Full `RuntimeEntityModel` JSON: entityId, schemaHash, fields, indexes, actions. |
| `POST /query` | Authenticated | Dynamic query over a runtime entity: `{ entity, clauses, sorts, skip, top }`. |
| `POST /intent` | Authenticated | Execute a `CommandIntent`: create, update, delete, or action against a runtime entity. |
| `GET /api/meta/registered-types` | Admin | Lists C# `[DataEntity]`-annotated types available for metadata import. |
| `POST /api/meta/seed-from-types` | Admin | Seeds `EntityDefinition` records from registered C# types. `?overwrite=true` replaces existing records. |

---

## MCP Route

### `POST /mcp`

**Handler:** `McpRouteHandler.HandleAsync`  
**Auth:** Authenticated  
**Description:** Model Context Protocol (MCP) server endpoint.  Accepts JSON-RPC 2.0
requests and exposes all registered BareMetalWeb entities as MCP tools:

- `query_{entity}` — filter/sort/paginate records
- `get_{entity}` — load a single record
- `create_{entity}` — create a record
- `update_{entity}` — update a record
- `delete_{entity}` — delete a record
- `command_{entity}_{commandName}` — execute a remote command

This allows AI assistants (e.g. GitHub Copilot, Claude) to manage application data
via the standard MCP protocol without a custom integration layer.

---

## OpenAPI Route

### `GET /openapi.json`

**Handler:** `OpenApiHandler.HandleAsync`  
**Auth:** Authenticated  
**Description:** Generates and returns an OpenAPI 3.0.3 specification built from
`DataScaffold.Entities`.  No Swagger / NSwag library is used; the JSON is
constructed manually by iterating entity metadata.  Only entities accessible to
the authenticated user are included in the spec.

---

## Report Routes

Registered by `RegisterReportRoutes`.  All routes require Admin permission.

| Route | Description |
|---|---|
| `GET /reports` | List all `ReportDefinition` records with "Run" links. |
| `GET /reports/{id}` | Execute a report and render the result as a styled HTML page using `ReportHtmlRenderer` (streamed via `PipeWriter`).  Accepts query parameters matching the report's `Parameters` list. |
| `GET /api/reports/{id}` | Execute a report and return JSON or CSV (`?format=csv`). |
| `GET /api/reports/_distinct/{entity}/{field}` | Returns distinct field values for a given entity field; used to populate parameter dropdowns in report forms. |

---

## Handler Implementation Patterns

### Authentication Check Flow

Every non-public route follows this pattern:

```
1. Throttle check (ClientRequestTracker — token bucket per IP)
2. HTTPS redirect (if HttpsRedirectMode != Off and HTTPS endpoint exists)
3. CORS pre-flight (if CORS origins configured)
4. Session cookie validation (UserAuth.GetRequestUserAsync)
5. Permission check against RouteHandlerData.RequiredPermission
6. CSRF validation (for POST/PUT/DELETE form routes)
7. Handler delegate invoked
```

### Error Responses

All API routes use consistent JSON error shapes:
```json
{ "error": "Human-readable message" }
```

HTML routes use the `ErrorPageInfo` template via `HtmlRenderer`.

### Streaming

HTML responses (SSR routes) use `PipeWriter` for zero-copy streaming.
`StringBuilder` is used for shorter fragment assembly where the full response
must be computed before writing (e.g. the metrics page).

### CSRF Protection

- **Form routes** (`POST /admin/*`, `POST /ssr/admin/data/*`) validate a hidden
  `_csrf` form field via `CsrfProtection.Validate`.
- **JSON API routes** (`POST /api/admin/*`) validate the `X-CSRF-Token` HTTP header
  via `CsrfProtection.ValidateApiToken`.
- Routes marked `raw` (e.g. `/api/*`) do not enforce CSRF; they rely on
  `SameSite=Strict` cookie policy and/or require authentication instead.

---

_Status: Verified against codebase @ commit HEAD (2026-03-05)_
