# System Architecture Overview

This document provides a high-level view of BareMetalWeb's component structure, project dependencies, and request lifecycle.

---

## Component Diagram

```mermaid
graph TD
    subgraph Host["BareMetalWeb.Host (entry point)"]
        Program["Program.cs<br/>WebApplication.Create"]
        Extensions["BareMetalWebExtensions<br/>UseBareMetalWeb()"]
        Server["BareMetalWebServer<br/>(IBareWebHost)"]
        RouteReg["RouteRegistrationExtensions<br/>(Register*Routes)"]
        RouteHandlers["RouteHandlers"]
        UserAuth["UserAuth<br/>(session cookie)"]
        CsrfProt["CsrfProtection"]
        StaticFile["StaticFileService"]
        Proxy["ProxyRouteHandler"]
        Logger["DiskBufferedLogger"]
        Throttle["ClientRequestTracker<br/>(token-bucket)"]
    end

    subgraph Core["BareMetalWeb.Core"]
        Interfaces["Interfaces<br/>(IDataObjectStore, IHtmlRenderer, …)"]
        Models["Models<br/>(PageInfo, PageContext, RouteHandlerData)"]
        Extensions2["HttpContext extensions"]
        WwwRoot["wwwroot/static<br/>(JS, CSS, templates)"]
    end

    subgraph Data["BareMetalWeb.Data"]
        DataStore["LocalFolderBinaryDataProvider<br/>(IDataProvider)"]
        DataStoreProvider["DataStoreProvider (singleton)"]
        BinSerializer["BinaryObjectSerializer"]
        EntityReg["DataEntityRegistry"]
        Scaffold["DataScaffold"]
        SearchIdx["SearchIndexManager"]
        IndexStore["IndexStore"]
        VirtualLoader["VirtualEntityLoader"]
        DynObject["DynamicDataObject"]
        ExprEngine["ExpressionEngine<br/>(CalculatedFieldService)"]
        ReportExec["ReportExecutor"]
    end

    subgraph Rendering["BareMetalWeb.Rendering"]
        HtmlRenderer["HtmlRenderer"]
        FragStore["HtmlFragmentStore"]
        FragRenderer["HtmlFragmentRenderer"]
        Templates["TemplateStore<br/>(file-based .html)"]
        StaticFrags["StaticHTMLFragments"]
        OutputCache["OutputCache"]
        CsrfRend["CsrfProtection (rendering)"]
    end

    subgraph Runtime["BareMetalWeb.Runtime"]
        RuntimeReg["RuntimeEntityRegistry"]
        RuntimeComp["RuntimeEntityCompiler"]
        RuntimeModel["RuntimeEntityModel"]
    end

    subgraph API["BareMetalWeb.API"]
        ApiHandlers["API route handlers"]
    end

    subgraph UserClasses["BareMetalWeb.UserClasses"]
        DataObjects["Customer, Order, Product, …<br/>[DataEntity] decorated"]
    end

    Program --> Extensions
    Extensions --> Server
    Extensions --> RouteReg
    Extensions --> Logger
    Extensions --> Throttle
    RouteReg --> RouteHandlers
    RouteReg --> StaticFile
    RouteReg --> Proxy
    Server --> UserAuth
    Server --> CsrfProt

    Extensions --> DataStoreProvider
    DataStoreProvider --> DataStore
    DataStore --> BinSerializer
    DataStore --> SearchIdx
    SearchIdx --> IndexStore
    Extensions --> EntityReg
    EntityReg --> Scaffold
    Extensions --> VirtualLoader
    VirtualLoader --> DynObject

    Extensions --> RuntimeReg
    RuntimeReg --> RuntimeComp
    RuntimeComp --> RuntimeModel

    Extensions --> HtmlRenderer
    HtmlRenderer --> FragRenderer
    FragRenderer --> FragStore
    HtmlRenderer --> Templates
    RouteHandlers --> StaticFrags
    RouteHandlers --> CsrfRend

    RouteHandlers --> DataStoreProvider
    RouteHandlers --> Scaffold
    RouteHandlers --> ExprEngine
    RouteHandlers --> ReportExec

    UserClasses --> EntityReg
    API --> DataStoreProvider
```

---

## Project Dependency Map

| Project | Depends on |
|---------|-----------|
| `BareMetalWeb.Host` | Core, Data, Rendering, Runtime, API |
| `BareMetalWeb.Core` | *(no project dependencies — interfaces only)* |
| `BareMetalWeb.Data` | Core |
| `BareMetalWeb.Rendering` | Core |
| `BareMetalWeb.Runtime` | Core, Data |
| `BareMetalWeb.API` | Core, Data |
| `BareMetalWeb.UserClasses` | Data |
| `BareMetalWeb.CLI` | *(standalone — uses HTTP only)* |

---

## Request Lifecycle

```mermaid
sequenceDiagram
    participant K as Kestrel (TCP/TLS)
    participant H as BareMetalWebServer<br/>(single handler)
    participant T as Throttle<br/>(token-bucket)
    participant A as UserAuth
    participant R as RouteMatching
    participant RH as RouteHandler delegate
    participant Ren as HtmlRenderer / PipeWriter
    participant DS as DataStoreProvider

    K->>H: HTTP request
    H->>T: Check rate limit (per-IP)
    T-->>H: allow / 429
    H->>A: Validate session cookie
    A-->>H: User / null
    H->>R: Match route (verb + path)
    R-->>H: RouteHandlerData + PageContext
    H->>RH: Invoke handler delegate

    alt Static file request
        RH->>RH: StaticFileService.ServeAsync
        RH-->>K: 200 + file bytes (streamed)
    else Proxy route
        RH->>RH: ProxyRouteHandler.ForwardAsync
        RH-->>K: upstream response
    else API route (JSON)
        RH->>DS: Load / Save / Query
        DS-->>RH: entity / list
        RH-->>K: 200 application/json
    else SSR HTML page
        RH->>DS: Load data
        RH->>Ren: RenderAsync (template replacement)
        Ren-->>K: 200 text/html (streamed)
    else VNext SPA shell
        RH->>Ren: Serve SPA shell HTML
        Ren-->>K: 200 text/html
    end
```

---

## Route Divergence

```mermaid
flowchart TD
    Req[Incoming HTTP request] --> Static{Path starts with<br/>/static ?}
    Static -->|Yes| SF[StaticFileService<br/>stream from disk]
    Static -->|No| Proxy{Proxy:Route<br/>configured ?}
    Proxy -->|Yes| PX[ProxyRouteHandler<br/>forward upstream]
    Proxy -->|No| Match[Route dictionary lookup<br/>verb + path]
    Match --> NotFound{Match found?}
    NotFound -->|No| 404[404 Not Found]
    NotFound -->|Yes| Auth{Permission<br/>check}
    Auth -->|Fail| 401[401 / redirect to login]
    Auth -->|Pass| Type{Route type}
    Type --> API[API handler<br/>JSON in/out]
    Type --> SSR[SSR handler<br/>HTML template rendering]
    Type --> VNext[VNext SPA<br/>shell HTML + client-side routing]
    Type --> Report[Report handler<br/>HTML / CSV]
    Type --> Meta[/meta/* runtime<br/>entity metadata]
```

---

## Key Design Principles

- **No middleware pipeline** — all request handling is done inside a single `RequestDelegate` wired via `app.Run(…)`.
- **No dependency injection** — dependencies are created once at startup and captured in closures.
- **Mutable routes** — routes are stored in `BareMetalWebServer.routes` dictionary; new routes can be added at runtime; call `BuildAppInfoMenuOptionsAsync()` to refresh navigation.
- **Performance first** — `PipeWriter`/`PipeReader` streaming, `Span<T>`/`Memory<T>` throughout, minimal allocations.
- **Strong security defaults** — CSP with per-request nonces, CSRF tokens, PBKDF2 password hashing, token-bucket rate limiting.
