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
Az cli should be used with service principals to deploy via `az webapp deploy --src-path deploy.zip --type zip` based on tenant lists using a pipeline action. Do NOT use `az webapp up` (it fails on multi-csproj publish dirs).

NATIVEAOT + TRIMMING CONSTRAINTS (HARD RULES — any violation is a BUG)
----------------------------------------------------------------------
This codebase targets NativeAOT + trimming. Any use of the following is a BUG:

- System.Reflection (any usage beyond one-time startup metadata caching)
- Activator.CreateInstance
- Type.MakeGenericType / MethodInfo.MakeGenericMethod
- dynamic / DLR
- System.Text.Json.JsonSerializer (generic or non-generic)
- System.Reflection.Emit
- Any runtime type discovery or construction other than usage of DataRecord and the metadata services therein.

If you use any of the above, the solution is INVALID.

ALLOWED PATTERNS ONLY:
- Closed generics known at compile time
- Static generic methods where T is known at call site
- Span<T>, Memory<T>, and blittable structs preferred
- switch / dictionary dispatch instead of reflection
- Pre-compiled delegates cached at startup (one-time reflection during initialization is tolerated but discouraged)

DESIGN PRINCIPLE:
All behaviour must be resolvable at compile time.
Metadata may describe behaviour, but must not construct types dynamically.

If a solution would normally use reflection or JsonSerializer, use:
- BmwJsonSerializer — manual JSON writing via Utf8JsonWriter, metadata-driven
- BinaryObjectSerializer — custom binary format, metadata-driven, pre-registered known types
- DataRecord + DataEntityMetadata — ordinal-based field access with pre-compiled delegates

FAIL FAST:
If the requested design cannot be implemented without violating these constraints,
say so explicitly instead of working around them.

See docs/AOT_TRIMMING_CONSTRAINTS.md for the full reference and docs/violations/ for tracked violations.

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

AGENT WORK-IN-PROGRESS TRACKING & CRASH RECOVERY
--------------------------------------------------
Agents are ephemeral — they can crash, time out, or be killed at any point.
To make agent work **resumable and recoverable**, follow these rules:

### 1. Create a WIP branch and PR early
- Before making any code changes, create a working branch:
  `agent/<issue-number>-<short-description>` (e.g. `agent/1380-reflection-audit`)
- Open a **Draft PR** immediately with a `[WIP]` title prefix targeting the appropriate base branch.
- Tag the PR with the GitHub issue number so the link is visible.

### 2. Commit early and often
- Make small, incremental commits as you complete each logical unit of work.
- Each commit message should summarise what was done and what remains:
  ```
  [WIP] Remove reflection from SessionSerializer

  Done: replaced typeof() calls with ordinal lookup in SessionSerializer
  Remaining: DataEntityRegistry, SearchIndexManager still use reflection
  ```
- Push after every commit — unpushed work is lost work.

### 3. Comment plan and state on the PR
- After opening the PR, post an **initial plan comment** listing:
  - The goal / issue being addressed
  - The planned steps (checklist format)
  - Current status
- After each significant commit (or batch of commits), post a **progress comment** updating:
  - What was just completed
  - What remains
  - Any blockers or decisions needed
- This creates a recoverable audit trail another agent (or human) can read.

### 4. Tag with machine/process identity
- Include the following in your **first PR comment** so observers can detect a stalled agent:
  - `Machine: <hostname>` — from `hostname` or `$HOSTNAME`
  - `PID: <process-id>` — from `$$` or `$PPID`
  - `Session: <session-id>` — if available from the agent runtime
  - `Started: <ISO-8601 timestamp>`
- If another agent sees a PR tagged with a different machine/PID that has gone stale
  (no commits or comments for >30 minutes), it may pick up the work by posting a
  takeover comment and continuing from the last committed state.

### 5. Record worktree status before and after work
- At the start of a session, record `git status`, `git branch`, and `git log --oneline -5`
  in your initial PR comment so recovery agents know the exact starting state.
- Before any long-running operation, commit or stash uncommitted changes.
- If resuming from a crashed agent's branch, start by reviewing the PR comments and
  the diff (`git diff main..HEAD`) to understand what was already done.

### 6. Recovery procedure (for a new agent picking up crashed work)
1. Find the WIP PR by searching: `is:pr is:open author:app/copilot label:in-progress`
   or by checking the issue for linked PRs.
2. Read ALL PR comments to reconstruct plan and progress state.
3. Check out the existing branch — do NOT create a new one.
4. Run `git log --oneline -10` and `git diff main..HEAD` to see what's done.
5. Post a **takeover comment** with your own machine/PID/session/timestamp.
6. Continue from where the previous agent left off.

(If you are seeing this, it means you have successfully loaded the agent instructions file. Please confirm that you understand the design philosophy and key features of the web server as described in the README.md file, and let me know if you have any questions or need further clarification on any aspect of the server's architecture or functionality.)


