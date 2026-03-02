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

## Output Caching

`OutputCache` (in `BareMetalWeb.Rendering`) stores rendered HTML fragments keyed by a cache key.  It is used for fragments that are expensive to regenerate (e.g. navigation menus) with a configurable TTL.  Dynamic per-request content is never cached.

---

_Status: Updated to clarify VNext (client-side, `/UI`) vs SSR screenchrome rendering (commerce & CMS pages). Verified against codebase @ commit e38d19057e1a55fc1d9a563f5ec6228bb991a0b5_
