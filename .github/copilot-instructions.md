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
- `rendering.md` — SSR pipeline, VNext SPA, JS libraries, view types

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

**Why This Matters:**
- Prevents broken code from being committed
- Maintains code quality and stability
- Protects the CI/CD pipeline from preventable failures
- Ensures all changes are validated before integration
