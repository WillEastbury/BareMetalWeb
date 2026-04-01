# CI Pipeline

BareMetalWeb uses a CI-only pipeline. Automated CD workflows were removed — deployment is handled manually or via local scripts. The pipeline validates every push and PR through tests, architectural guards, AOT builds, and container image publishing.

## Pipeline Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  CI1 · Unit Tests (unit-tests.yml)                                 │
│  ─────────────────────────────────                                 │
│  Build (Debug) → parallel test shards → tests-passed gate          │
│  Trigger: push to main, PRs, workflow_dispatch                     │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ workflow_run (success, main only)
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CI2 · AOT & Containers (container.yml)                            │
│  ───────────────────────────────────────                            │
│  JIT publish AnyCPU (deploy-package artifact)                      │
│  AOT publish linux-arm64 → Build thin container (Dockerfile.prebuilt)│
│  → Push to ACR with version tag + OCI labels                       │
│  → Build Agent container (Dockerfile.agent)                        │
│  → Upload JIT deploy-package + AOT aot-linux-arm64 artifacts       │
└─────────────────────────────────────────────────────────────────────┘
```

## Supporting Workflows

These workflows run independently of the CI1 → CI2 chain:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `bmw-guard.yml` | Push, PRs | Scans for forbidden APIs and architectural violations |
| `build-cli.yml` | Push to `BareMetalWeb.CLI/`, manual | Cross-platform Native AOT CLI binary builds |
| `codeql.yml` | Nightly schedule, manual | GitHub CodeQL security scanning |
| `perf-large.yml` | Nightly schedule, manual | Heavy stress tests with large datasets (trend analysis) |
| `download-static-assets.yml` | Manual | Downloads Bootstrap themes, fonts, JS from CDNs |

## Workflow Details

### CI1 · Unit Tests (`unit-tests.yml`)

| Property    | Value |
|-------------|-------|
| **Trigger** | Push to main, pull requests, workflow_dispatch |
| **Runners** | ubuntu-latest |

Builds the solution in Debug mode, then fans out to parallel test shards:
- Data tests
- Host tests
- Rendering tests
- Runtime tests
- Core tests
- API tests
- Intelligence tests
- Jest tests (JavaScript)

All shards must pass for the `tests-passed` gate job to succeed, which triggers CI2.

### CI2 · AOT & Containers (`container.yml`)

| Property    | Value |
|-------------|-------|
| **Trigger** | CI1 success on main, workflow_dispatch |
| **Runners** | ubuntu-latest (JIT + summary), ubuntu-24.04-arm (arm64 AOT + container) |

Two parallel builds:

1. **JIT AnyCPU Publish** — Produces a framework-dependent Release package (`deploy-package`) — runs anywhere .NET 10 is installed.
2. **AOT Publish (linux-arm64)** — Produces a native self-contained binary on the native ARM runner, then packaged into a thin container using `Dockerfile.prebuilt` (just copies the pre-built binary into `runtime-deps:10.0-noble-chiseled`).

The host container image is tagged `{version}-linux-arm64` and pushed to Azure Container Registry (`metalclusterregistry.azurecr.io`).

The agent container is built from `Dockerfile.agent` and the agent binary artifact is uploaded separately.

**Artifacts uploaded:** `deploy-package` (JIT, 3-day retention), `aot-linux-arm64` (3-day retention), `agent-linux-arm64` (3-day retention).

## Local Script Equivalents

For Linux/ARM local development, the GitHub Actions pipeline maps to bash scripts under `infra/`:

| Workflow | Local script | Purpose |
|----------|--------------|---------|
| `unit-tests.yml` (CI1) | `./infra/local-ci.sh` | Restore, Debug build, run .NET test shards, run Jest |
| `container.yml` (CI2) | `./infra/local-ci2.sh` | Compute version, JIT publish, AOT publish (`linux-arm64`), optional Docker build/push |

These scripts are intentionally simpler than the Actions workflows:

- no artifact upload/download between jobs
- sequential execution instead of matrix fan-out
- local environment variables replace GitHub secrets/contexts

## Version Tagging

All versions follow the format: `{MAJOR}.{YYYYMMDD}.{BUILD_NUMBER}`

- **MAJOR** — set via the `MAJOR_VERSION` repository variable (default: `1`)
- **Date** — build date in `YYYYMMDD` format
- **Build** — GitHub Actions run number

Container image tags append the platform: `1.20260309.42-linux-arm64`

## Required Secrets

| Secret | Used by | Purpose |
|--------|---------|---------|
| `AZURE_CLIENT_ID` | CI2 | OIDC app registration for ACR |
| `AZURE_TENANT_ID` | CI2 | Azure AD tenant |
| `AZURE_SUBSCRIPTION_ID` | CI2 | Azure subscription |

## Dockerfiles

| File | Purpose |
|------|---------|
| `Dockerfile` | Multi-stage (SDK → AOT → chiseled). For local development. |
| `Dockerfile.prebuilt` | Thin single-stage (chiseled only). Used by CI2 for the linux-arm64 host container. |
| `Dockerfile.agent` | Agent container image built by CI2. |
