# UI Rendering Architecture

This document covers BareMetalWeb's two rendering paths: the classic server-side rendering (SSR) pipeline and the VNext single-page application (SPA).

---

## SSR Rendering Pipeline

```mermaid
sequenceDiagram
    participant RH as Route handler delegate
    participant TS as TemplateStore
    participant DS as DataStoreProvider
    participant HR as HtmlRenderer
    participant SF as StaticHTMLFragments
    participant PW as PipeWriter (response)

    RH->>DS: Load entity / list data
    DS-->>RH: entity objects
    RH->>SF: Build form / list HTML fragments
    SF-->>RH: HTML string fragments
    RH->>HR: RenderAsync(template, replacements)
    HR->>TS: Get base template (e.g. Index.html)
    TS-->>HR: raw template bytes
    HR->>HR: Stream template through PipeReader
    HR->>HR: Replace {{tokens}}, evaluate {{Loop}}, {{For}}
    HR->>PW: Write rendered bytes
    PW-->>Client: HTTP 200 text/html (chunked transfer)
```

**Why `PipeWriter`?**  Streaming directly to the response pipe avoids buffering the entire HTML page in memory, enabling consistent sub-0.15 ms render times even for large pages.

---

## Template Syntax

```mermaid
graph LR
    T["Template file (.html)"] --> Token["{{tokenName}}<br/>simple value replacement"]
    T --> Loop["{{Loop%%loopKey}}<br/>  … repeated block …<br/>{{EndLoop}}<br/>(foreach iteration)"]
    T --> ForBlock["{{For%%i|from|to|increment}}<br/>  … repeated block …<br/>{{EndFor}}<br/>(numeric for loop)"]
    T --> Cond["{{If%%condition}}<br/>  … conditional block …<br/>{{EndIf}}"]
    Token --> HR["HtmlRenderer<br/>(streaming replacement)"]
    Loop --> HR
    ForBlock --> HR
    Cond --> HR
```

**Template location:** `wwwroot/static/*.html` (served from the `TemplateStore`).  
**Evaluation:** Single forward-pass over the template byte stream — no AST, no re-allocation, no Razor compilation.

---

## Form Rendering: DataFieldMetadata → HTML

```mermaid
flowchart TD
    DE["[DataEntity] class"] --> DF["[DataField] attributes<br/>(name, type, required, order, …)"]
    DF --> SC["DataScaffold.BuildEntityHtml()"]
    SC --> FT{"FormFieldType"}
    FT --> TBox["TextBox / NumberBox / DateBox"]
    FT --> CB["CheckBox"]
    FT --> TA["TextArea"]
    FT --> DP["DatePicker"]
    FT --> Lookup["LookupSelect<br/>(dropdown or high-cardinality search)"]
    FT --> FileUp["FileUpload"]
    FT --> SubList["SubList editor<br/>(List&lt;T&gt; → modal grid)"]
    FT --> Custom["CustomHtml"]

    Lookup --> HiCard{"High-cardinality?<br/>(count > LargeListThreshold)"}
    HiCard -->|No| Dropdown["Full &lt;select&gt; dropdown"]
    HiCard -->|Yes| Search["Hidden input + readonly display<br/>+ search button → /api/_lookup/{slug}"]

    TBox --> HTML["HTML fragment string"]
    CB --> HTML
    TA --> HTML
    DP --> HTML
    Dropdown --> HTML
    Search --> HTML
    FileUp --> HTML
    SubList --> HTML
    Custom --> HTML

    HTML --> SF["StaticHTMLFragments.RenderForm()"]
    SF --> HR["HtmlRenderer → PipeWriter"]
```

---

## Commerce & CMS SSR Views

The public-facing commerce storefront and CMS page views are fully server-side rendered.  They reuse the same SSR pipeline as the rest of the application — the route handler populates context values (`title`, `html_message`) and `HtmlRenderer` streams the platform screenchrome (nav, header, footer) together with the page-specific content fragment in a single pass.

```mermaid
sequenceDiagram
    participant Browser
    participant Host as BareMetalWeb.Host
    participant PR as ProductRenderer / PageRenderer
    participant DS as DataStoreProvider
    participant HR as HtmlRenderer (main template)
    participant PW as PipeWriter (response)

    Browser->>Host: GET /products  (or /products/{category}  or /page/{slug})
    Host->>PR: ConfigureCategoryBrowseAsync / ConfigureProductGridAsync / ConfigurePageAsync
    PR->>DS: QueryAsync(entity)
    DS-->>PR: entity objects
    PR->>PR: Build HTML fragment (Bootstrap cards / product grid / page body)
    PR->>Host: context.SetStringValue("title", …) + ("html_message", fragment)
    Host->>HR: RenderAsync(mainTemplate, replacements)
    HR->>PW: Stream screenchrome + content (sub-0.15 ms)
    PW-->>Browser: 200 text/html — fully rendered page
```

**Route table — Commerce & CMS SSR endpoints:**

| Route | Handler | Description |
|-------|---------|-------------|
| `GET /products` | `ProductRenderer.ConfigureCategoryBrowseAsync` | Category listing wrapped in platform screenchrome |
| `GET /products/{category}` | `ProductRenderer.ConfigureProductGridAsync` | Product grid with search/tag filter, inside screenchrome |
| `GET /page/{slug}` | `PageRenderer.ConfigurePageAsync` | CMS page body rendered server-side inside screenchrome |
| `GET /api/pages` | `PageRenderer.ListPagesHandler` | Raw JSON list of published pages |

All four routes are registered with a `TemplatedPage` `PageInfo` (using the main `IHtmlTemplate`), so the full platform screenchrome — navigation bar, header, and footer — is server-rendered on every request.

---

## VNext SPA Path

VNext is the default admin UI served at `/UI` (and `/UI/{*path}`).  The shell itself is server-rendered (nav bar extracted from the main template) but **all content is rendered client-side** by `vnext-app.js` after loading entity schemas and data from the JSON API.

```mermaid
sequenceDiagram
    participant Browser
    participant Host as BareMetalWeb.Host
    participant MetaEP as GET /meta/objects
    participant ApiEP as GET /api/{type}
    participant MetaObj as GET /api/_meta
    participant JsBundle as /static/js bundle

    Browser->>Host: GET /UI
    Host-->>Browser: SPA shell HTML<br/>(nav from SSR template + vnext-bundle.js)
    Browser->>JsBundle: Load JS libraries<br/>(BareMetalRest/Bind/Template/Rendering)
    Browser->>MetaObj: GET /api/_meta
    MetaObj-->>Browser: [{slug, displayName, …}]<br/>(all registered entities)
    Browser->>MetaEP: GET /meta/objects
    MetaEP-->>Browser: [{fields, viewType, commands, …}]<br/>(full schema per entity)
    Browser->>ApiEP: GET /api/{type}?…
    ApiEP-->>Browser: JSON entity list
    Browser->>Browser: Client-side render<br/>(BareMetalRendering.js)
```

**Key distinction from commerce/CMS SSR views:** The VNext shell reuses only the `<nav>` and `<footer>` sections of the main template.  The `#vnext-content` `<div>` is populated entirely by client-side JavaScript — no server-side HTML fragment is injected for the page body.

### VNext JS Library Responsibilities

| Library | Responsibility |
|---------|---------------|
| `BareMetalRouting.js` | Client-side hash/path routing; decides if a path is a VNext path |
| `BareMetalRest.js` | Thin fetch wrapper for all API calls |
| `BareMetalBind.js` | Two-way data binding between JS objects and DOM inputs |
| `BareMetalTemplate.js` | Mustache-style client-side template evaluation |
| `BareMetalRendering.js` | High-level list/form/sublist HTML generation |
| `vnext-app.js` | Top-level SPA router; wires everything together |

### VNext API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /api/_meta` | Discover all registered entity types |
| `GET /meta/objects` | Full schema for all entities |
| `GET /meta/{object}` | Schema for a single entity |
| `GET /api/{type}` | List entities (with filtering/sorting/paging) |
| `GET /api/{type}/{id}` | Get a single entity |
| `POST /api/{type}` | Create entity |
| `PUT /api/{type}/{id}` | Update entity |
| `DELETE /api/{type}/{id}` | Delete entity |
| `GET /api/_lookup/{slug}` | High-cardinality lookup search |
| `GET /api/metadata/{entity}` | Enhanced per-entity metadata (viewType, parentField, commands) |

### VNext Entity View Types

Each entity can declare a `ViewType` (via `[DataViewType]` attribute) that changes how the list is rendered in the SPA.  Additional view types may be available as optional overlays (toggled via the view-switcher toolbar) when `canShow*` flags are set on the entity metadata.

| ViewType | `canShow*` flag | Trigger condition | Description |
|----------|----------------|-------------------|-------------|
| `Table` | — | default | Paginated sortable/filterable table |
| `TreeView` | — | `[DataViewType(ViewType.TreeView)]` + `parentField` | Nested expandable tree |
| `OrgChart` | — | `[DataViewType(ViewType.OrgChart)]` + `parentField` | Hierarchy org-chart boxes |
| `Timeline` | `canShowTimeline` | entity has a date range (start + end date fields) | Gantt-style horizontal timeline |
| `Timetable` | `canShowTimetable` | entity has a `DayOfWeek` field + time field | Weekly schedule grid |
| `Sankey` | `canShowSankey` | entity has a self-referential FK (document chain) | Sankey flow diagram |
| `Calendar` | `canShowCalendar` | entity has any `DateOnly` or `DateTime` field | **Calendar view — day / week / month** (see below) |
| `Workflow` | `canShowWorkflow` | entity has an `Enum` field | Kanban board grouped by enum stage |
| `Aggregation` | always available | — | Drill-through aggregation tree |
| `Chart` | always available | — | Bar/line/pie charts for numeric fields |

#### Calendar View (day / week / month)

The calendar view (`ViewType.Calendar` or the `view=Calendar` URL parameter) renders entity records as calendar events pinned to their date field.

**Sub-views** — selected via the `calMode` URL parameter:

| `calMode` | Description | Navigation params |
|-----------|-------------|-------------------|
| `month` (default) | Monthly grid, one cell per day | `calYear`, `calMonth` (0-based) |
| `week` | 7-column week grid | `calWeekStart` (YYYY-MM-DD of the Sunday) |
| `day` | Single-day detail card | `calDay` (YYYY-MM-DD) |

**Click to create** — each day cell shows a `+` button (visible on hover) that navigates to `/{slug}/create?{dateField}={YYYY-MM-DD}`, pre-filling the date field on the new-record form.

**Drag to move** — event badges are `draggable="true"`.  Dropping an event onto a different day cell calls `PUT /api/{type}/{id}` with the new date value, then refreshes the view.

---

## Report Rendering

```mermaid
sequenceDiagram
    participant Browser
    participant Host as RouteHandlers
    participant RE as ReportExecutor
    participant RHR as ReportHtmlRenderer
    participant PW as PipeWriter

    Browser->>Host: GET /reports/{id}
    Host->>RE: ExecuteAsync(reportDefinition)
    RE->>RE: Hash-map JOIN across entity stores
    RE-->>Host: ReportResult (rows + columns)
    Host->>RHR: RenderAsync(result, PipeWriter)
    RHR->>PW: Stream HTML table (no buffering)
    PW-->>Browser: 200 text/html
```

CSV export is available via `GET /api/reports/{id}` (returns `text/csv`).

---

## CSS Theme Bundle System

`CssBundleService` (in `BareMetalWeb.Host`) manages per-theme CSS bundles served at `/static/css/themes/{theme}.min.css`. Each bundle is self-contained: Bootstrap Icons CSS (with local font path rewritten) + the theme's Bootstrap CSS (Google Fonts `@import` stripped for CSP compliance).

### Theme types

| Type | Source | Count |
|---|---|---|
| **Bootswatch** (`DefaultThemes`) | Downloaded from `cdn.jsdelivr.net/npm/bootswatch` at startup or lazily on first request | 25 |
| **Custom exclusive** (`CustomThemeDefinitions`) | Download a named Bootswatch base theme, then append hand-crafted CSS overrides | 4 |

### Custom exclusive themes

| Theme | Base | Design intent |
|---|---|---|
| `jigsaw` | `lumen` | Muted, desaturated palette; reduced motion — sensory-friendly for autistic users |
| `rave` | `cyborg` | Neon colours on near-black; glow effects — 80s dance-culture energy |
| `luminescent` | `darkly` | Deep-space dark with glowing cyan/violet accents — everything emits light |
| `geography` | `sandstone` | Cartographic palette: parchment, stone, slate and muted earth tones |

### Lifecycle

1. **Startup** — `EnsureAssetsAsync(staticRoot)` downloads/writes all Bootswatch themes and builds all custom themes to `wwwroot/static/css/themes/*.min.css`, then calls `BuildBundles` to load them into the in-memory cache (with Brotli and Gzip pre-compressed variants).
2. **Request** — `TryServeAsync(context)` serves from the in-memory cache. On a cache miss for a known theme, a `Lazy<Task<bool>>` per theme name ensures the bundle is built/downloaded at most once (lazy first-hit load).
3. **Cache headers** — `Cache-Control: public, max-age=31536000, immutable` + ETag + Last-Modified for aggressive browser caching.

---



`OutputCache` (in `BareMetalWeb.Rendering`) stores rendered HTML fragments keyed by a cache key.  It is used for fragments that are expensive to regenerate (e.g. navigation menus) with a configurable TTL.  Dynamic per-request content is never cached.

---

## Diagnostic Host Banner

A server-info overlay can be injected into any rendered HTML page for scaleout debugging.

**Activation:** Two conditions must both be true:
1. System setting `diagnostics.showHostInfo` set to `True` (managed via the admin settings UI — `WellKnownSettings.ShowHostInfo`)
2. `?showhst=true` query parameter present on the request

The setting is seeded into the system settings store at startup with a default value of `False` and can be toggled at runtime from the admin settings UI without redeploying.

**Content (injected before `</body>` in the response):**

| Field | Source |
|---|---|
| `init` | `X-Forwarded-Host` header (when behind a proxy) or `Request.Host` |
| `svr` | `Dns.GetHostName()` — the machine serving the request |
| `rtt` | `MetricsTracker.GetSnapshot().RecentAverageResponseTime` (last 5-min avg) |
| `payload` | Response HTML byte count before banner injection |

**Coverage:** SSR pages (`HtmlRenderer.RenderPage`), VNext SPA shell (`ServeVNextShell`), and Report pages (`ReportHtmlRenderer.AppendChromeFooter`).

**Security:** Both conditions must be met simultaneously to show the banner. The default system-setting value is `False`; never enable in production without authentication controls.

---

_Status: Updated to document CSS Theme Bundle System (custom exclusive themes: jigsaw, rave, luminescent, geography). Verified against codebase._
