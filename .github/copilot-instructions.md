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

## Development Workflow

1. Make minimal, surgical changes focused on the specific issue
2. Build and test frequently to catch issues early
3. Use existing linters/build tools (do not add new ones unless required)
4. For data entity changes, update all registries (see Data and Storage section)
5. Store useful codebase facts using the memory tool for future reference
