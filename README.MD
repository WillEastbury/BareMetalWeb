# BareMetalWeb

**A raw, high-performance web framework built on bare-metal ASP.NET Core.**

No MVC. No middleware pipeline. No DI containers. No Razor. No magic.

Just Kestrel, explicit routing, streaming HTML templates, a custom binary serializer, and total control.

[![Build and Deploy](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/deploy.yml/badge.svg)](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/deploy.yml)
[![Build CLI](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/build-cli.yml/badge.svg)](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/build-cli.yml)

## What is this?

BareMetalWeb is a lean, mean web server that uses ASP.NET Core **only** for HTTP/SSL — everything else is built from scratch for minimalism, performance, and clarity. Think classic-era `.ashx` handlers and `HttpModules` reborn in modern .NET 9.

### Key Features

- **Explicit data-driven routing** — routes are mutable at runtime, no convention magic
- **Streaming HTML templates** — `{{token}}` replacement, `{{Loop%%key}}` / `{{For%%i|from|to|step}}` blocks via `PipeReader`/`PipeWriter`
- **Custom binary serializer** — fast, compact session and data storage with schema versioning
- **Pluggable data storage** — file-based binary provider by default, swap in anything via interfaces
- **Auto-scaffolded CRUD** — decorate a class with `[DataEntity]` and get REST API + admin UI for free
- **Built-in auth** — session cookies, MFA, Service Principal API keys (PBKDF2 hashed)
- **Request throttling** — per-IP token bucket rate limiting
- **Strong CSP & security** — secure headers, cookie hardening, request validation
- **Async buffered logging** — per-minute log files, non-blocking, clean shutdown records
- **Static file serving** — streaming with ETag/Last-Modified/Cache-Control, MIME mapping
- **Reverse proxy** — route-based forwarding with cookie stripping
- **Native AOT CLI tool** — `bmw` binary for managing any BareMetalWeb instance from the terminal

### Live Instances

| Environment | URL |
|-------------|-----|
| Development | https://baremetalweb.azurewebsites.net |
| Production  | https://baremetalweb-prod.azurewebsites.net |

---

//////////////////////////////
// Welcome to BareMetalWeb !// 
//////////////////////////////
// this is intentionally not MVC
// this is intentionally single-handler, NOT middleware-based or minimal-api-based
// this is intentionally NOT using any frameworks beyond bare-metal ASP.NET Core
// we are using kestrel and asp.net core only for handling ssl and the http protocol
// everything else is built from scratch and is RAW and BARE METAL
// routing is data-driven and explicit
// lifecycle is explicit
// magic is banned, this approach is about CONTROL and UNDERSTANDING over convenience
// and it is about MINIMALISM and PERFORMANCE over features
// this is a LEAN and MEAN web server example
// this will be lightning fast and efficient
// think asp.net classic era ashx handlers and httpmodules but in modern .net 7+ form
// and with a focus on clarity and simplicity over cleverness and complexity

// interesting bits: 
// “routes are NOT immutable after startup” - if you want to add routes on the fly - knock yourself out - just call appinfo.BuildAppInfoMenuOptions() to update the header menu afterwards

// “logging is buffered to disk asynchronously” - so logging does not block request handling, EXCEPT for exception logging - which during app shutdown is strictly best effort on flush to console - but we do write a clean shutdown record so you can see no data loss in logs even if the app is killed hard - and we do flush the buffer on graceful shutdown so you can see a clean shutdown record in the logs as well.
also the logs are written per-day-per-hour-per-minute log files to keep them manageable and easy to find relevant logs for a given time period, and to avoid giant log files that are hard to work with, and we close those with a record on cycle too. 

// “html rendering is done via simple template replacement” - no razor, no cshtml, no complex view engines, just simple and fast on the fly streaming replacement inside basic text templates with {{replacetoken}}, foreach blocks with {{Loop%%loopKey}}...{{EndLoop}}, and for blocks with {{For%%i|from|to|increment}}...{{EndFor}}

// “no dependency injection, no service containers” - everything is explicit and straightforward - we do use interfaces for key components to allow easy swapping if needed, so nothing is technically stopping you from injecting different interfaces we just don't use that pattern for both speed of skipping the DI container and simplicity and readability.
// “no middleware pipeline” - just a single request handler that does everything - no complex middleware chains to understand or manage, register a route with pagedata and a handler via a delegate and boom away you go.

// We have a simple request throttling system to protect against abuse and overload - maybe a simple token bucket algorithm that tracks request counts per IP and shortcuts the handler to 429, the values are configurable. 

// We have a super-fast binary serializer for session data and other data storage needs - it's a custom format that is designed to be as fast as possible to serialize and deserialize, and to be compact on disk and in memory - it's not human-readable but it's lightning fast and efficient for our needs.

// We also have a pluggable data abstraction storage framework and repository pattern that allows you to easily swap out different storage implementations - we have a simple file-based binary implementation for user accounts and sessions, but you could easily swap in a database-backed implementation if you wanted to - the interfaces are designed to be flexible and easy to work with, and the file-based implementation is designed to be simple and easy to understand as well.

//Static file / content streaming with caching headers
// - configured in appsettings.json (StaticFiles)
// - serves files from a fixed folder (default: wwwroot/static) via a fixed prefix (default: /static)
// - streams file bytes directly from disk (no MVC, no middleware)
// - supports cache headers (Cache-Control, ETag, Last-Modified) with configurable max-age
// - supports MIME type mapping via StaticFiles:MimeTypes (defaults provided, override/add as needed)
// - unknown MIME types are blocked by default (AllowUnknownMime=false) unless you opt in
// - example: request /static/site.css -> reads wwwroot/static/site.css
//
// appsettings.json snippet:
// "StaticFiles": {
//   "Enabled": true,
//   "RequestPathPrefix": "/static",
//   "RootDirectory": "wwwroot/static",
//   "EnableCaching": true,
//   "CacheSeconds": 86400,
//   "AddETag": true,
//   "AddLastModified": true,
//   "AllowUnknownMime": false,
//   "DefaultMimeType": "application/octet-stream",
//   "MimeTypes": { ".webmanifest": "application/manifest+json", ".wasm": "application/wasm" }
// }

// 4.7 a rudimentary service proxy / router
// Configure Proxy:Route and Proxy:TargetBaseUrl in appsettings*.json
// Requests to the route are forwarded to the target (headers/body preserved), excluding the auth session cookie

---

## BareMetalWeb CLI (`bmw`)

A cross-platform, native AOT-compiled command-line tool for managing BareMetalWeb instances. No .NET runtime required — download the single binary for your platform and go.

### Download

Pre-built binaries are available as GitHub Actions artifacts from the **Build CLI Binaries** workflow. Each platform has its own downloadable artifact:

| Platform             | Artifact Name     | Binary                    | Architecture |
|----------------------|-------------------|---------------------------|--------------|
| Windows x64          | `bmw-win-x64`     | `bmw-win-x64.exe`        | Intel/AMD 64-bit |
| Windows ARM64        | `bmw-win-arm64`   | `bmw-win-arm64.exe`      | ARM 64-bit (Surface Pro X, etc.) |
| Linux x64            | `bmw-linux-x64`   | `bmw-linux-x64`          | Intel/AMD 64-bit |
| Linux ARM64          | `bmw-linux-arm64`  | `bmw-linux-arm64`        | ARM 64-bit (Raspberry Pi 4+, AWS Graviton, Android/Termux) |
| **All platforms**    | `bmw-all-platforms`| All of the above          | Combined download |

**To download:** Go to [Actions → Build CLI Binaries](../../actions/workflows/build-cli.yml), click the latest successful run, and download the artifact for your platform from the bottom of the page.

On Linux, make the binary executable after download:
```bash
chmod +x bmw-linux-x64
```

**Termux / Android (proot):** The .NET runtime requires a GC heap limit in memory-constrained environments:
```bash
export DOTNET_GCHeapHardLimit=0x10000000
./bmw-linux-arm64 help
```

### Quick Start

```bash
# 1. Connect to a BareMetalWeb instance (with API key)
bmw connect https://mysite.azurewebsites.net my-api-key-here

# 2. Login via device code flow (opens browser, approve in browser)
bmw connect https://mysite.azurewebsites.net
bmw login

# 3. Login via device code (headless/SSH - shows code to enter manually)
bmw login --outofband

# 4. Or login directly with credentials
bmw login admin mypassword

# 5. Discover what entity types are available
bmw types

# 4. List all records of a type
bmw list to-do

# 5. Create a new record
bmw create to-do Title="Buy milk" Notes="From the store" IsCompleted=false

# 6. Get a single record
bmw get to-do abc123

# 7. Update a record
bmw update to-do abc123 IsCompleted=true

# 8. Delete a record
bmw delete to-do abc123
```

### Commands

#### Connection & Auth

| Command | Description |
|---------|-------------|
| `bmw connect <url> [api-key]` | Set the server URL and optional API key |
| `bmw login` | Login via device code flow (opens browser for approval) |
| `bmw login --outofband` | Login via device code (displays code for manual entry) |
| `bmw login <user> <pass>` | Login directly with username/password |
| `bmw config` | Show current connection configuration |

Authentication priority: API key (if configured) → Session cookie (from login).

Configuration is stored in `~/.bmw/config.json`. Session cookies are persisted in `~/.bmw/cookies`.

#### Entity Operations

| Command | Description |
|---------|-------------|
| `bmw types` | List all entity types on the server (via `/api/_meta`) |
| `bmw list <type>` | List all entities of a type |
| `bmw get <type> <id>` | Get a single entity by ID (JSON output) |
| `bmw create <type> key=value [...]` | Create a new entity |
| `bmw update <type> <id> key=value [...]` | Partial update an entity (PATCH) |
| `bmw delete <type> <id>` | Delete an entity |

#### Querying

```bash
# Full-text search
bmw query to-do q=milk

# Filter by field with operator
bmw query to-do field=Title op=contains value=milk

# Sort and paginate
bmw query to-do sort=Deadline dir=desc skip=0 top=10

# Combine filters, sort, and pagination
bmw query to-do field=IsCompleted op=eq value=false sort=Deadline dir=asc top=5
```

**Available operators:** `eq`, `ne`, `contains`, `startswith`, `endswith`, `in`, `notin`, `gt`, `lt`, `gte`, `lte`

### Dynamic Entity Discovery

The CLI uses `GET /api/_meta` to discover entity types at runtime. This means **one CLI binary works with any BareMetalWeb instance** — it dynamically adapts to whatever entities are registered on that server. Different BareMetalWeb editions with different data objects all work with the same CLI.

### Building from Source

The CLI is in `BareMetalWeb.CLI/` and can be built locally:

```bash
# Standard build (requires .NET 9 SDK)
dotnet build BareMetalWeb.CLI

# Native AOT publish for your current platform
dotnet publish BareMetalWeb.CLI -c Release -p:PublishAot=true -p:PublishTrimmed=true

# Cross-compile for a specific target (Linux ARM64 example, requires cross toolchain)
dotnet publish BareMetalWeb.CLI -c Release --runtime linux-arm64 -p:PublishAot=true -p:PublishTrimmed=true
```


