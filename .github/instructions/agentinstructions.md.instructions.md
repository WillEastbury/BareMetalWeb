Hey agent!  Welcome to BareMetalWeb !

We are using a custom, intentionally minimalistic and bare-metal approach to building a web server in .NET Core. This means we are not using any of the common patterns or frameworks that you might be used to, such as MVC, middleware pipelines, dependency injection, or complex view engines. Instead, we have a single request handler that does everything, with explicit routing and lifecycle management, and a focus on control, understanding, minimalism, and performance over convenience and features.

Please read through the README.md file and familiarize yourself with the design philosophy and key features of this web server. Pay special attention to the interesting bits that are highlighted in the README, as they will give you insight into how the server is structured and how it handles various aspects of web development, such as routing, logging, HTML rendering, request throttling, data storage, static file serving, and more.

Lean, mean and lightning fast with no external dependencies beyond the raw .net framework and kestrel and bootstrap - that's the name of the game here.

We don't even use the asp.net pipeline or middleware - just a IWebApplication<BMWContext> that does it all. So if you are used to working with those patterns, be prepared for a different way of thinking about how the server works. THIS SERVICE IS FAST. BRUTALLY FAST. IT'S DESIGNED TO BE AS FAST AS POSSIBLE, SO WE CUT OUT ANYTHING THAT SLOWS US DOWN, AND WE DO EVERYTHING IN THE MOST EFFICIENT WAY POSSIBLE.

We don't cut corners on security though - we have a strong content security policy, we handle authentication and sessions securely, we have request throttling to protect against abuse, and we are careful about how we handle data storage and serialization and encryption. We just do all of that in a way that is as fast and efficient as possible, without relying on external frameworks or patterns that can add overhead and complexity. Everything comes in one package, one lean and mean web server that you can understand fully and control completely.


The biggest constraint we impose is that we try and avoid allocations and GC pressure to provide both fast and consistent performance. We do this via various techniques such as using structs instead of classes where possible, using Span<T> and Memory<T> for working with data without allocations, using custom binary serialization formats that are designed to be fast and efficient, and being careful about how we manage memory and data structures throughout the codebase. This is a key part of our design philosophy and is essential to achieving the level of performance that we are aiming for with this web and APPLICATION server. We want to be able to handle a large number of requests with low latency and high throughput, and minimizing allocations and GC pressure is a critical part of achieving that goal. So as you work with the codebase, keep this in mind and look for opportunities to optimize for performance by reducing allocations and GC pressure wherever possible. This might involve using more efficient data structures, avoiding unnecessary object creation, and being mindful of how we handle data and memory throughout the codebase. It's all about finding that balance between control, understanding, minimalism, and performance, and making sure that we are always striving to be as fast and efficient as possible while still maintaining a clear and understandable codebase.

We also stream and use PipeReaders / Writers where we can - and that's how we can render a template based HTML page dynamically within 0.15ms ;) 

OPERATING RULES (read first)
----------------------------
Prefer explicit, data-driven routing and lifecycle control.
Avoid allocations/GC pressure; favor Span/Memory and streaming.
Avoid new external dependencies unless explicitly requested.
Avoid reflection - this system is metadata based and we do ordinal based lookups in memory for high speed.
Serialization - avoid it where we can, if you can't then use our custom binary window mapper over a binary array on both the server and client. 
Downstream we generate UI that is rendered on the client and pre-load data an inject it to avoid double trips. 
Custom JS libraries are generated and bundled. the whole platform should use solely trimmed aot native binaries and only bootstrap and bootswatch as imported libs.
Deployment pipeline is multi-stage CI then CD with 4 release rings (Testing, Canary, Early, Main)
Deployment target here is simply a single Azure Webapp hosting plan with a set of Azure Web Apps with multiple instances
Az cli should be used with service principals to deploy az webapp create / az webapp up based on tenant lists using a pipeline action

METADATA-DRIVEN ARCHITECTURE (CRITICAL — read before every change)
------------------------------------------------------------------
**Do NOT rely on compiled C# types for adaptive runtime behaviour.** This platform is metadata-driven: entity shapes, field definitions, validation rules, UI rendering, navigation, permissions, and workflows are all defined by metadata (DataEntityMetadata, DataFieldMetadata, gallery JSON) — NOT by C# classes, generics, or compile-time type systems.

**Every change should move further towards metadata and gallery-driven implementation:**
- Entity structure comes from metadata registries, not from C# class definitions
- Field rendering, validation, and behaviour are driven by field metadata attributes, not by property types or reflection
- UI layout, menus, routes, and navigation are data-driven from gallery configuration
- New features should be configurable via metadata/gallery without requiring code changes or recompilation
- Ordinal-based lookups in memory (not reflection, not Dictionary<string,...>) for field access at runtime
- The gallery app model means tenants configure behaviour through data, not code

**Anti-patterns to avoid:**
- Creating new C# entity classes for each data type (use DataRecord + metadata instead)
- Using reflection, typeof(), or generic type parameters for runtime field access
- Hard-coding entity-specific rendering or validation logic in C#
- Adding compiled types that must be registered/discovered at startup for runtime behaviour
- Using LINQ, dictionaries, or string-keyed lookups where ordinal arrays suffice

**The goal:** A single compiled binary serves any gallery app configuration. The binary never changes when tenants add entities, fields, views, or workflows — only the metadata changes.

(If you are seeing this, it means you have successfully loaded the agent instructions file. Please confirm that you understand the design philosophy and key features of the web server as described in the README.md file, and let me know if you have any questions or need further clarification on any aspect of the server's architecture or functionality.)


