# AUTONOMOUS AGENT WORKFLOW (MANDATORY)

BareMetalWeb uses a multi-agent development model where autonomous agents resolve GitHub issues via isolated git worktrees and pull requests.

## 1. Issue Discovery
- Use GitHub CLI to list issues: `gh issue list`
- Select only OPEN issues that are not assigned and do not have a label starting with `claimed:`
- Claim the issue using:
  ```bash
  gh issue edit <issue-number> --add-label claimed:<agent-name>
  ```

## 2. Workspace Isolation (Git Worktrees)
- Every issue must be worked in a dedicated git worktree
- Never modify the main working tree
- Create worktree with:
  ```bash
  git worktree add ../agent-<issue-number> -b agent/<issue-number>-<slug>
  ```
- Then `cd` into `../agent-<issue-number>`

## 3. Development Rules
- Implement minimal surgical changes
- Follow BareMetalWeb architectural rules
- Do not introduce MVC, middleware, DI, reflection on hot paths, or unnecessary allocations
- Respect AOT, trim, and performance constraints already defined in the instructions

## 4. Mandatory Verification
Before committing:
- Run `dotnet build BareMetalWeb.sln`
- Run `dotnet test BareMetalWeb.sln --no-build -v quiet`
- ARM64/proot environments must follow the runsettings guidance already present in the instructions

## 5. Commit Format
Commit messages must follow:
```
<short description>

Fixes #<issue-number>
```

## 6. Push Branch
Push using:
```bash
git push -u origin agent/<issue-number>-<slug>
```

## 7. Pull Request Creation
Create PR using:
```bash
gh pr create --title "<short description>" --body "Closes #<issue-number>"
```
Agents must never merge PRs themselves.

## 8. CI Feedback Loop
- Wait for CI results
- If CI fails, fix the issue and push to the same branch
- Do not create additional PRs

## 9. Completion
- When CI passes, return to issue discovery and select another unclaimed issue

## Multi-Agent Safety Rules
- Keep changes minimal
- Avoid broad refactors
- Avoid formatting-only commits
- Avoid touching unrelated files
- Never force push
- Never rewrite history
- Never merge PRs

If an issue is unclear, the agent must comment on the GitHub issue asking for clarification instead of guessing.

---

# BareMetalWeb Copilot instructions

## Project Overview

BareMetalWeb is a minimalistic, high-performance web server built on bare-metal ASP.NET Core. It's designed for **control, understanding, minimalism, and performance** over convenience and features. Think ASP.NET Classic-era ASHX handlers but in modern .NET 9+ form.

**Key Philosophy:**
- No MVC, no Razor, no middleware pipeline, no DI containers
- Single-handler architecture with explicit routing and lifecycle
- Everything built from scratch for brutal speed (0.1-0.15ms page renders)
- Zero external dependencies beyond Kestrel/ASP.NET Core (used only for HTTP/SSL)

## Repository Structure

- **BareMetalWeb.Host** - Main host application with routing and request handling
- **BareMetalWeb.Core** - Core interfaces, models, and HTTP extensions
- **BareMetalWeb.Data** - Binary serialization, data storage, and search indexing
- **BareMetalWeb.Rendering** - HTML template rendering and CSRF protection
- **BareMetalWeb.API** - API route handlers
- **BareMetalWeb.UserClasses** - User data models
- **\*.Tests** - xUnit test projects for each library
- **BareMetalWeb.PerformanceTests** - Performance benchmarking console app

## Build and Test Commands

```bash
# Build the solution
dotnet build BareMetalWeb.sln

# Run all unit tests
dotnet test BareMetalWeb.sln

# Run specific test project
dotnet test BareMetalWeb.Core.Tests/
dotnet test BareMetalWeb.Data.Tests/

# Run the web server
dotnet run --project BareMetalWeb.Host

# Run performance benchmarks
dotnet run --project BareMetalWeb.PerformanceTests
```

## Architecture and Flow

- **Single-handler architecture**: One request handler does everything (no middleware chain)
- **Explicit routing**: Routes are data-driven via `PageData` and delegates
- **Mutable routes**: Add routes dynamically, then call `appinfo.BuildAppInfoMenuOptions()` to update the header menu
- **Kestrel only for HTTP/SSL**: Everything else (routing, rendering, storage, auth) is custom-built

## Rendering

- **Template replacement** (not Razor): Uses `{{replacetoken}}` syntax for fast on-the-fly replacement
- **Loop syntax**: `{{Loop%%loopKey}}...{{EndLoop}}` for foreach, `{{For%%i|from|to|increment}}...{{EndFor}}` for for-loops
- **Streaming**: Uses `PipeReader`/`PipeWriter` for zero-allocation rendering
- **Performance**: Typical page render in 0.1-0.15ms vs 10ms+ for MVC/Razor

## Data and Storage

- **Custom binary serializer**: Ultra-fast, compact binary format for sessions and data
- **Pluggable storage**: Repository pattern with file-based binary default (easily swappable)
- **SearchIndexManager**: Sub-millisecond search (30-43 microseconds avg) using prefix trees and binary .idx files
- **Data entity registry**: When adding new data types, update `DataEntityRegistry`, `BinaryObjectSerializer` known types, JSON context/type registry

## Performance and Security Conventions

**Performance:**
- Avoid allocations and GC pressure at all costs
- Prefer `Span<T>`, `Memory<T>`, structs over classes
- Use streaming patterns with `PipeReader`/`PipeWriter`
- Use stackalloc for temporary buffers
- Cached reflection metadata to avoid runtime lookups

**Security:**
- Strong Content Security Policy (CSP)
- Secure authentication and session handling
- Request throttling (token bucket algorithm) to prevent abuse
- CSRF protection built-in
- Be cautious with user input and data serialization

## ⚠️ MANDATORY Code Quality Requirements

All code contributed to this project — whether by humans or AI agents — **MUST** adhere to the following non-negotiable requirements:

### Performance & AOT Safety
- **No unnecessary allocations on the hot path.** Every allocation in request handling must be justified. Prefer stackalloc, `Span<T>`, `Memory<T>`, ArrayPool, and struct-based patterns.
- **No reflection on the hot path.** Reflection is only acceptable at startup for one-time metadata caching. Never use `Type.GetMethod()`, `Activator.CreateInstance()`, or similar in request processing.
- **AOT and trim safe.** All code must be compatible with Native AOT compilation and IL trimming. No `dynamic`, no unconstrained `MakeGenericType`, no runtime code generation. Use `[DynamicallyAccessedMembers]` or source generators where needed.
- **Use hardware acceleration where possible.** Leverage `Vector<T>`, `Vector128<T>`/`Vector256<T>`, `System.Numerics`, SIMD intrinsics, and hardware-accelerated APIs (`Crc32`, `AesGcm`, `SHA256.HashData`) for any compute-intensive operations (hashing, searching, serialisation, crypto).

### Security & Privacy
- **No OWASP vulnerabilities.** Code must be free of injection (SQL, command, header, log), XSS, CSRF, path traversal, insecure deserialisation, broken access control, and all other OWASP Top 10 categories.
- **No bounds-checking exploits or buffer overruns.** Always validate indices, lengths, and offsets before accessing buffers. Use `Span<T>` slicing (which throws on out-of-range) rather than raw pointer arithmetic. Never trust user-supplied lengths.
- **Privacy safe.** Never log PII, tokens, passwords, or session data. Sanitise all user input before storage or display. Follow data minimisation principles.
- **Production ready.** Code must be deployable as-is — no TODO stubs, no placeholder error handling, no `Console.WriteLine` debugging. Proper error handling, proper logging, proper resource disposal.

### Summary Checklist (for every change)
- [ ] Zero unnecessary allocations on hot path
- [ ] No reflection at runtime (startup-only if needed)
- [ ] AOT/trim compatible
- [ ] No OWASP vulnerabilities
- [ ] Bounds-checked, no buffer overruns
- [ ] Privacy safe (no PII leakage)
- [ ] Hardware-accelerated where applicable
- [ ] Production ready and secure by design

## Static Files and Proxy

- **Static files**: Custom handler (no middleware) with caching/ETag/Last-Modified support
- **Configuration**: `appsettings.json` under `StaticFiles` (path prefix, root directory, cache settings, MIME types)
- **Proxy routing**: `Proxy:Route` and `Proxy:TargetBaseUrl` forward requests (headers/body preserved, excludes auth cookie)

## Logging

- **Asynchronous buffered disk logging**: Non-blocking for request handling
- **Per-hour/minute log files**: Manageable size, easy to find relevant logs
- **Clean shutdown records**: Flush on graceful shutdown, best-effort on hard kill

## Code Style Guidelines

1. **No magic**: Explicit over implicit, clarity over cleverness
2. **Minimal dependencies**: Avoid adding external packages unless absolutely necessary
3. **Performance first**: Always consider allocation and GC impact
4. **Follow existing patterns**: Match the style and structure of surrounding code
5. **Test naming**: `MethodName_Scenario_ExpectedBehavior`
6. **AAA pattern**: Arrange-Act-Assert in tests

## Important Constraints

- **No middleware**: Do not add ASP.NET middleware or use the pipeline pattern
- **No MVC/Razor**: Use the custom template replacement system
- **No DI containers**: Keep dependencies explicit and straightforward
- **Avoid allocations**: Use Span/Memory, structs, and streaming wherever possible
- **Thread safety**: PageStore uses single-writer queues per extent for lock-free writes
- **Route parameters**: Extract from `PageContext.PageMetaDataKeys/Values`, not `HttpContext.Request.RouteValues`

## UI Development Guidelines

- **Lookup / FK fields in UI**: When building UI code (forms, grids, dropdowns), cross-entity reference fields (foreign keys) MUST always be resolved to their display/lookup value in the UI. Never show raw FK IDs to the user — always render the human-readable label from the referenced entity. Dropdowns must populate their option text from the lookup entity, and read-only displays must show the resolved name/label, not the underlying ID.

- **Sub-entity (List&lt;T&gt;) rendering**: Fields that are `List<T>` on a parent entity (e.g. `Order.OrderRows` where `T` is `OrderRow`) represent sub-entities that are rendered as inline sub-grids or sub-list editors. These sub-grids MUST respect all the same field constraints, validation rules, lookup resolution, and rendering logic that apply to top-level entities. In particular: lookup/FK fields inside sub-entity rows must also display their resolved display values (not raw IDs), required fields must be validated, and the sub-grid must honour any `[DataLookup]`, `[CopyFromParent]`, and `[CalculatedField]` attributes on the sub-entity type.

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


## Documentation Sync Pass (MANDATORY — End of Every Session)

> **At the end of every coding session (before the final commit), perform a documentation sync pass.**

**Steps:**
1. Review all files modified in this session (use `git diff --name-only main`)
2. For each modified file, check whether any `docs/` file describes the affected area
3. If a doc exists and is now stale, update it to match the actual code
4. If a new subsystem/feature was added with no existing doc, create one in `docs/` or `docs/architecture/`
5. **Read the code, not the old doc** — rewrite sections from what the code actually does, not what the doc previously said

**Key docs to check:**
- `docs/QUERY_INDEX_ARCHITECTURE.md` — Query paths, index usage, caching, performance characteristics
- `docs/PROXY.md` — Proxy configuration, load balancing, affinity cookies
- `docs/architecture/data-layer.md` — Storage stack, WAL, serialization, idMap
- `docs/architecture/rendering.md` — VNext SPA, screen chrome, template syntax
- `docs/architecture/system-overview.md` — Component diagram, route divergence

**A session is considered incomplete if code was changed but affected docs were not updated.**

## Documentation Invariants

> **The codebase is always canonical over documentation. When discrepancies exist, correct the docs — do not extend or preserve stale text.**

Any change to the following areas **MUST** update the corresponding `docs/architecture/` file(s) in the same PR:

| Changed area | Affected doc(s) |
|---|---|
| WAL behaviour (`WalStore`, `WalSegmentWriter`, `WalDataProvider`, `WalTransaction`) | `docs/architecture/data-layer.md` |
| Transaction pipeline (`TransactionEnvelope`, `CommandService`, `ActionExpander`) | `docs/architecture/domain-transition-kernel.md` |
| Locking semantics (`AggregateLockManager`) | `docs/architecture/domain-transition-kernel.md` |
| Delta format (`FieldValueChange`, `AggregateMutation`) | `docs/architecture/domain-transition-kernel.md` |
| Action primitives (`ActionDefinition`, `ActionCommandDefinition`, `ActionCommands`) | `docs/architecture/domain-transition-kernel.md` |
| Storage layout (file paths, index format, entity registration) | `docs/architecture/data-layer.md`, `docs/architecture/indexing.md` |
| Auth / session / CSRF | `docs/architecture/auth.md` |
| Rendering pipeline, template syntax, VNext SPA | `docs/architecture/rendering.md` |
| Component diagram, request lifecycle, route divergence | `docs/architecture/system-overview.md` |

**A PR is considered incomplete if:**
- Architecture-affecting code was changed, and
- The corresponding architecture doc was not updated.

**Required steps when updating architecture docs:**
1. Search `docs/architecture/` for all text describing the affected concept.
2. Correct outdated descriptions — do not append "also" or "alternatively" to preserve stale text.
3. Append or update the `_Status_` line at the bottom of the affected doc(s) with the current commit hash.

## Development Workflow

1. Make minimal, surgical changes focused on the specific issue
2. Build and test frequently to catch issues early
3. Use existing linters/build tools (do not add new ones unless required)
4. For data entity changes, update all registries (see Data and Storage section)
5. Store useful codebase facts using the memory tool for future reference
6. When architecture changes, update the relevant `docs/architecture/` file(s) immediately (see Documentation Invariants above)

## Documentation Requirements (MANDATORY)

When making code changes, you **MUST** update the corresponding architecture documentation in `docs/architecture/` if your changes affect any of the following:

1. **New components or subsystems** — Add to `system-overview.md` component diagram
2. **New API routes or endpoints** — Add to `system-overview.md` route divergence diagram and `rendering.md` endpoint tables
3. **Storage or data layer changes** — Update `data-layer.md` (storage stack, CRUD lifecycle, serializer format, storage layout)
4. **Index changes** — Update `indexing.md` (file format, data types, index types)
5. **Auth or security changes** — Update `auth.md` (cookie settings, API key methods, permission model)
6. **UI/rendering changes** — Update `rendering.md` (new JS modules, view types, client libraries)
7. **Transaction, action, or mutation engine changes** — Update `docs/architecture/` transaction/action documentation
8. **New project dependencies** — Update project dependency table in `system-overview.md`

**Architecture docs location:** `docs/architecture/`
- `system-overview.md` — Component diagram, project dependencies, request lifecycle, route divergence
- `data-layer.md` — Storage stack, entity registration, CRUD lifecycle, binary serializer, storage layout
- `indexing.md` — Search index types, file format, lookup mechanism
- `auth.md` — Login flow, session validation, permission model, API keys
- `rendering.md` — VNext SPA pipeline, JS libraries, view types

**Rule:** If you add a new class, endpoint, or subsystem, ask yourself: "Does any architecture doc describe this area?" If yes, update it. If no doc exists for the area, create one in `docs/architecture/`.

## Pre-Commit Requirements (MANDATORY)

**BEFORE making any commits or checking in ANY code changes:**

1. **MUST run full build**: `dotnet build BareMetalWeb.sln`
   - Build must succeed with zero errors
   - Build warnings are acceptable (document if new warnings are introduced)

2. **MUST run complete test suite**: `dotnet test BareMetalWeb.sln --no-build -v quiet`
   - All tests must pass, OR
   - Any failures must be pre-existing and unrelated to your changes (document these)
   - Alternative: Use helper script `./run-tests.sh` (includes build)

3. **If tests fail due to your changes**: You MUST fix them before committing

4. **If build fails**: You MUST fix compilation errors before committing

**Test Commands:**
- Full build: `dotnet build BareMetalWeb.sln`
- Full test suite: `dotnet test BareMetalWeb.sln --no-build -v quiet`
- Specific project: `dotnet test BareMetalWeb.Core.Tests/ --no-build -v quiet`
- Helper script: `./run-tests.sh` (builds and tests in one step)

**ARM64 / proot Test Runner Fix:**
This environment runs under proot on ARM64 (Termux). The vstest runner's `DotnetHostHelper` fails to detect the dotnet muxer because the process appears as `libproot-loader.so` instead of `dotnet`. This causes `"Could not find 'dotnet' host for the 'ARM64' architecture"` errors.

**Fix:** Always pass a `.runsettings` file with `DotNetHostPath` set:

```bash
# Create the runsettings file (one-time)
cat > /tmp/test.runsettings << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<RunSettings>
  <RunConfiguration>
    <EnvironmentVariables>
      <DOTNET_ROOT>/usr/lib/dotnet</DOTNET_ROOT>
    </EnvironmentVariables>
    <TargetPlatform>ARM64</TargetPlatform>
    <DotNetHostPath>/usr/lib/dotnet/dotnet</DotNetHostPath>
  </RunConfiguration>
</RunSettings>
EOF

# Then run tests with:
dotnet test BareMetalWeb.sln --no-build -s /tmp/test.runsettings -v quiet
dotnet test BareMetalWeb.Data.Tests/BareMetalWeb.Data.Tests.csproj --no-build -s /tmp/test.runsettings
```

Without this, `dotnet test` will abort with `"Test Run Aborted"` on every test project. Setting `DOTNET_ROOT` or `DOTNET_ROOT_ARM64` alone is **not** sufficient — `DotNetHostPath` in runsettings is required.

**Additional ARM64/proot quirks:**
- Test output (pass/fail counts, test names) may not appear in stdout — the test runner's console logger sometimes fails to write under proot. **Trust the exit code**: `0` = all passed, non-zero = failures.
- If test output is needed, use `--logger "console;verbosity=detailed"` but expect intermittent blank output.
- Integration tests requiring network listeners may fail under proot. Exclude them with `--filter "FullyQualifiedName!~IntegrationTests"`.
- The runsettings file must exist before running tests. If `/tmp/test.runsettings` is missing (e.g. after a reboot), recreate it using the snippet above.

**Why This Matters:**
- Prevents broken code from being committed
- Maintains code quality and stability
- Protects the CI/CD pipeline from preventable failures
- Ensures all changes are validated before integration

- (If you are seeing this, it means you have successfully loaded the agent instructions file. Please confirm that you understand the design philosophy and key features of the web server as described in the README.md file, and let me know if you have any questions or need further clarification on any aspect of the server's architecture or functionality.)

