# BareMetalWeb

**A raw, high-performance web framework built on bare-metal ASP.NET Core.**

No MVC. No middleware pipeline. No DI containers. No Razor. No magic.

Just Kestrel, explicit routing, streaming HTML templates, a custom binary serializer, and total control.

[![1 · CI1 — Tests & JIT Build](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/unit-tests.yml)
[![2 · CI2 — AOT & Containers](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/container.yml/badge.svg)](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/container.yml)
[![3 · CD1 — Canary & Extended Tests](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/cd-canary.yml/badge.svg)](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/cd-canary.yml)
[![4 · CD2 — Early Adopters](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/cd-early-adopters.yml/badge.svg)](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/cd-early-adopters.yml)
[![5 · CD3 — Full Rollout](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/cd-full-rollout.yml/badge.svg)](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/cd-full-rollout.yml)
[![Build CLI](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/build-cli.yml/badge.svg)](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/build-cli.yml)
[![Large Performance Stress Tests](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/perf-large.yml/badge.svg)](https://github.com/WillEastbury/BareMetalWeb/actions/workflows/perf-large.yml)

📚 **[Full Documentation Index →](docs/index.md)** | 🗺️ **[Architecture Diagrams →](docs/architecture/system-overview.md)**

---

## What is this?

BareMetalWeb is a lean, mean web server that uses ASP.NET Core **only** for HTTP/SSL — everything else is built from scratch for minimalism, performance, and clarity. Think classic-era `.ashx` handlers and `HttpModules` reborn in modern .NET 10.

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
- **Native AOT CLI tool** — `metal` binary for managing any BareMetalWeb instance from the terminal

### Live Instances

| Environment | URL |
|-------------|-----|
| Development | https://baremetalweb.azurewebsites.net |
| Production  | https://baremetalweb-prod.azurewebsites.net |

---

## Quick Start

```bash
# Prerequisites: .NET 10 SDK
dotnet --version   # should be 10.x

# Build
dotnet build

# Run tests
dotnet test --no-build

# Run the server
cd BareMetalWeb.Host
dotnet run
# → BareMetalWeb server is ready — PID 12345 — listening for requests on http://localhost:5232
```

The first run triggers the **Out-of-Box Experience (OOBE)** setup wizard at `http://localhost:5232/setup` where you create the admin account and seed sample data.

### Project Structure

| Project | Purpose |
|---------|---------|
| `BareMetalWeb.Host` | Kestrel server, routes, request handlers |
| `BareMetalWeb.Core` | Shared models, enums, static assets (JS/CSS/templates) |
| `BareMetalWeb.Data` | Storage, serialization, scaffolding, settings, auth |
| `BareMetalWeb.Rendering` | SSR HTML fragment rendering |
| `BareMetalWeb.Runtime` | Runtime/virtual entity definitions |
| `BareMetalWeb.API` | REST API controller layer |
| `BareMetalWeb.Intelligence` | BitNet b1.58 ternary inference engine (zero-dependency, AOT-safe) |
| `BareMetalWeb.Intelligence.CLI` | Interactive REPL for testing the inference engine |
| `BareMetalWeb.CLI` | Native AOT `metal` command-line tool |

---

## BareMetalWeb CLI (`metal`)

A cross-platform, native AOT-compiled command-line tool for managing BareMetalWeb instances. No .NET runtime required — download the single binary for your platform and go.

### Download

Pre-built binaries are available as GitHub Actions artifacts from the **Build CLI Binaries** workflow. Each platform has its own downloadable artifact:

| Platform             | Artifact Name     | Binary                    | Architecture |
|----------------------|-------------------|---------------------------|--------------|
| Windows x64          | `metal-win-x64`     | `metal-win-x64.exe`        | Intel/AMD 64-bit |
| Windows ARM64        | `metal-win-arm64`   | `metal-win-arm64.exe`      | ARM 64-bit (Surface Pro X, etc.) |
| Linux x64            | `metal-linux-x64`   | `metal-linux-x64`          | Intel/AMD 64-bit |
| Linux ARM64          | `metal-linux-arm64`  | `metal-linux-arm64`        | ARM 64-bit (Raspberry Pi 4+, AWS Graviton, Android/Termux) |
| **All platforms**    | `metal-all-platforms`| All of the above          | Combined download |

**To download:** Go to [Actions → Build CLI Binaries](../../actions/workflows/build-cli.yml), click the latest successful run, and download the artifact for your platform from the bottom of the page.

On Linux, make the binary executable after download:
```bash
chmod +x metal-linux-x64
```

**Termux / Android (proot):** The .NET runtime requires a GC heap limit in memory-constrained environments:
```bash
export DOTNET_GCHeapHardLimit=0x10000000
./metal-linux-arm64 help
```

### Quick Start

```bash
# 1. Connect to a BareMetalWeb instance (with API key)
metal connect https://mysite.azurewebsites.net my-api-key-here

# 2. Login via device code flow (opens browser, approve in browser)
metal connect https://mysite.azurewebsites.net
metal login

# 3. Login via device code (headless/SSH - shows code to enter manually)
metal login --outofband

# 4. Or login directly with credentials
metal login admin mypassword

# 5. Discover what entity types are available
metal types

# 4. List all records of a type
metal list to-do

# 5. Create a new record
metal create to-do Title="Buy milk" Notes="From the store" IsCompleted=false

# 6. Get a single record
metal get to-do abc123

# 7. Update a record
metal update to-do abc123 IsCompleted=true

# 8. Delete a record
metal delete to-do abc123
```

### Commands

#### Connection & Auth

| Command | Description |
|---------|-------------|
| `metal connect <url> [api-key]` | Set the server URL and optional API key |
| `metal login` | Login via device code flow (opens browser for approval) |
| `metal login --outofband` | Login via device code (displays code for manual entry) |
| `metal login <user> <pass>` | Login directly with username/password |
| `metal config` | Show current connection configuration |

Authentication priority: API key (if configured) → Session cookie (from login).

Configuration is stored in `~/.metal/config.json`. Session cookies are persisted in `~/.metal/cookies`.

#### Entity Operations

| Command | Description |
|---------|-------------|
| `metal types` | List all entity types on the server (via `/api/_meta`) |
| `metal list <type>` | List all entities of a type |
| `metal get <type> <id>` | Get a single entity by ID (JSON output) |
| `metal create <type> key=value [...]` | Create a new entity |
| `metal update <type> <id> key=value [...]` | Partial update an entity (PATCH) |
| `metal delete <type> <id>` | Delete an entity |

#### Querying

```bash
# Full-text search
metal query to-do q=milk

# Filter by field with operator
metal query to-do field=Title op=contains value=milk

# Sort and paginate
metal query to-do sort=Deadline dir=desc skip=0 top=10

# Combine filters, sort, and pagination
metal query to-do field=IsCompleted op=eq value=false sort=Deadline dir=asc top=5
```

**Available operators:** `eq`, `ne`, `contains`, `startswith`, `endswith`, `in`, `notin`, `gt`, `lt`, `gte`, `lte`

### Dynamic Entity Discovery

The CLI uses `GET /api/_meta` to discover entity types at runtime. This means **one CLI binary works with any BareMetalWeb instance** — it dynamically adapts to whatever entities are registered on that server. Different BareMetalWeb editions with different data objects all work with the same CLI.

### Building from Source

The CLI is in `BareMetalWeb.CLI/` and can be built locally:

```bash
# Standard build (requires .NET 10 SDK)
dotnet build BareMetalWeb.CLI

# Native AOT publish for your current platform
dotnet publish BareMetalWeb.CLI -c Release -p:PublishAot=true -p:PublishTrimmed=true

# Cross-compile for a specific target (Linux ARM64 example, requires cross toolchain)
dotnet publish BareMetalWeb.CLI -c Release --runtime linux-arm64 -p:PublishAot=true -p:PublishTrimmed=true
```

---

## Running Tests with Clean Output

The repository includes a helper script for running tests with minimal, scannable output:

```bash
# Run all tests with clean output (no build noise)
./run-tests.sh --no-build

# Run all tests (includes build)
./run-tests.sh

# Run specific test project
./run-tests.sh --no-build BareMetalWeb.Core.Tests/
```

For more details, see [TESTING.md](docs/TESTING.md).
