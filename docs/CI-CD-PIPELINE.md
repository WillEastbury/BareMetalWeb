# CI/CD Pipeline

BareMetalWeb uses a 5-workflow pipeline that chains automated CI with gated CD rollouts. Each workflow triggers the next, with manual gates at the production deployment stages.

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
│  CI2 · AOT Build & Container Push (container.yml)                  │
│  ────────────────────────────────────────────────                   │
│  AOT publish (linux-amd64, linux-arm64, windows-amd64)             │
│  → Build thin containers (Dockerfile.prebuilt)                     │
│  → Push to GHCR + ACR with version tags + OCI labels               │
│  → Upload AOT artifacts                                            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ workflow_run (success, main only)
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CD1 · Canary Deploy & Extended Tests (cd-canary.yml)              │
│  ────────────────────────────────────────────────────               │
│  Deploy container to AKS → health check                            │
│  → Setup test (fresh deploy + Playwright smoke)                    │
│  → Upgrade test (existing data + integration tests)                │
│  → Performance test (small + large datasets)                       │
│  ■ STOPS HERE — review results before proceeding                   │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ manual workflow_dispatch (image_tag)
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CD2 · Early Adopter Rollout (cd-early-adopters.yml)               │
│  ───────────────────────────────────────────────────                │
│  Generate release notes → create GitHub Release                    │
│  → Deploy to early-access tenants (from deploy-list.json)          │
│  ■ STOPS HERE — validate early adopter tenants                     │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ manual workflow_dispatch (image_tag)
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│  CD3 · Full Production Rollout (cd-full-rollout.yml)               │
│  ───────────────────────────────────────────────────                │
│  Gated by "production-rollout" environment (manual approval)       │
│  → Deploy to remaining production tenants                          │
│  → Deploy to AKS production                                       │
│  → Health check + summary                                          │
└─────────────────────────────────────────────────────────────────────┘
```

## Concurrency & Cancellation

CI1, CI2, and CD1 share a single concurrency group (`deploy-pipeline-<ref>`). When a new
push lands on `main`, any in-progress run across those three stages is **cancelled** and
the pipeline restarts from CI1. This guarantees only the latest commit is ever being
validated or deployed — no overlapping or stale deployments.

| Workflows | Concurrency group | cancel-in-progress |
|-----------|------------------|--------------------|
| CI1, CI2, CD1 | `deploy-pipeline-${{ github.ref }}` | **true** — new push abandons old run |
| CD2 | `cd2-early-adopters` | **false** — queues if already running |
| CD3 | `cd3-full-rollout` | **false** — queues if already running |

PR runs of CI1 are in their own group (`deploy-pipeline-refs/pull/…`) so they never
cancel or block the main-branch pipeline.

## Workflow Details

### CI1 · Unit Tests (`unit-tests.yml`)

| Property    | Value |
|-------------|-------|
| **Trigger** | Push to main, pull requests, workflow_dispatch |
| **Runners** | ubuntu-latest |
| **Duration** | ~3–5 minutes |

Builds the solution in Debug mode, then fans out to parallel test shards:
- Data tests
- Host tests
- Rendering tests
- Runtime tests
- Core tests
- API tests
- Jest tests (JavaScript)

All shards must pass for the `tests-passed` gate job to succeed, which triggers CI2.

### CI2 · AOT Build & Container Push (`container.yml`)

| Property    | Value |
|-------------|-------|
| **Trigger** | CI1 success on main, workflow_dispatch |
| **Runners** | ubuntu-latest (amd64), ubuntu-24.04-arm (arm64), windows-2022 |
| **Duration** | ~10–15 minutes |

1. **AOT Publish** — Produces native AOT binaries for three platforms:
   - `linux-x64` on ubuntu-latest
   - `linux-arm64` on native ARM runner
   - `win-x64` on Windows Server 2022
2. **Container Build** — Packages each binary into a thin container using `Dockerfile.prebuilt` (no SDK layer, no `dotnet publish` inside Docker — just copies the pre-built binary into `runtime-deps:10.0-noble-chiseled`).
3. **Push** — Tags each image with `{version}-{platform}` and pushes to:
   - GitHub Container Registry (`ghcr.io`)
   - Azure Container Registry (`metalclusterregistry.azurecr.io`)
4. **OCI Labels** — Each image carries standard metadata: title, version, revision, source URL, creation timestamp.

**Artifacts uploaded:** `aot-linux-amd64`, `aot-linux-arm64`, `aot-windows-amd64` (3-day retention).

### CD1 · Canary Deploy & Extended Tests (`cd-canary.yml`)

| Property    | Value |
|-------------|-------|
| **Trigger** | CI2 success on main, workflow_dispatch (optional image_tag) |
| **Environment** | AKS canary (same namespace) |
| **Duration** | ~15–30 minutes |

Deploys the newly built container to the AKS StatefulSet using `kubectl set image`, then runs three extended test stages:

| Test | Purpose | Method |
|------|---------|--------|
| **Setup Test** | Fresh deploy validation | Deploys to `baremetalweb-cireset` with `reset-data.flag`, runs Playwright smoke tests |
| **Upgrade Test** | Migration path validation | Deploys to `baremetalweb-upgrade` (preserves data), runs integration test suite |
| **Performance Test** | Regression check | Runs performance benchmarks with small (100 addresses) and large (10K addresses) datasets |

If any test fails, the pipeline stops and CD2 is not available.

### CD2 · Early Adopter Rollout (`cd-early-adopters.yml`)

| Property    | Value |
|-------------|-------|
| **Trigger** | Manual workflow_dispatch |
| **Input** | `image_tag` — the tag validated by CD1 |
| **Duration** | ~5–10 minutes |

1. Verifies the image tag exists in ACR.
2. Generates release notes by scanning merged PRs since the last `v*` tag. Categorizes into Features, Bug Fixes, and Other Changes.
3. Creates a GitHub Release with the release notes.
4. Reads `deploy-list.json` for tenants with `"ring": "early-access"` and deploys to each in parallel using the reusable `deploy-tenant.yml` workflow.
5. Health-checks each tenant after deployment.

### CD3 · Full Production Rollout (`cd-full-rollout.yml`)

| Property    | Value |
|-------------|-------|
| **Trigger** | Manual workflow_dispatch |
| **Input** | `image_tag` — same tag from CD2 |
| **Gate** | `production-rollout` GitHub Environment (requires manual approval) |
| **Duration** | ~10–15 minutes |

1. Verifies the image tag exists in ACR (gated by environment approval).
2. Reads `deploy-list.json` for tenants with `"ring": "production"` and deploys in parallel.
3. Deploys the same image to the AKS production StatefulSet.
4. Health-checks everything and produces a final summary.

## Version Tagging

All versions follow the format: `{MAJOR}.{YYYYMMDD}.{BUILD_NUMBER}`

- **MAJOR** — set via the `MAJOR_VERSION` repository variable (default: `1`)
- **Date** — build date in `YYYYMMDD` format
- **Build** — GitHub Actions run number

Container image tags append the platform: `1.20260309.42-linux-arm64`

## Tenant Deployment Rings

Defined in `deploy-list.json` at the repository root:

| Ring | Stage | Deployment |
|------|-------|------------|
| `ci-reset` | CD1 | Fresh deploy with data wipe |
| `ci-upgrade` | CD1 | Upgrade deploy preserving data |
| `canary` | CD1 | AKS canary pod |
| `early-access` | CD2 | Early adopter tenants (parallel) |
| `production` | CD3 | Remaining tenants (parallel, gated) |

## Required Secrets

| Secret | Used by | Purpose |
|--------|---------|---------|
| `AZURE_CLIENT_ID` | CI2, CD1, CD3 | OIDC app registration for ACR + AKS |
| `AZURE_TENANT_ID` | CI2, CD1, CD3 | Azure AD tenant |
| `AZURE_SUBSCRIPTION_ID` | CI2, CD1, CD3 | Azure subscription |
| `AZURE_CREDENTIALS` | CD1 | SP for baremetalweb-cireset (setup test) |
| `AZURE_CREDENTIALS_UPGRADE` | CD1 | SP for baremetalweb-upgrade (upgrade test) |
| `AZURE_CREDENTIALS_TENANTS` | CD2, CD3 | SP for tenant Web Apps |
| `CIMIGRATE_TEST_USERNAME` | CD1 | Test user login |
| `CIMIGRATE_TEST_DISPLAYNAME` | CD1 | Test user display name |
| `CIMIGRATE_TEST_PASSWORD` | CD1 | Test user password |

## Required GitHub Environments

| Environment | Workflow | Purpose |
|-------------|----------|---------|
| `production-rollout` | CD3 | Manual approval gate before full production deploy |

## Dockerfiles

| File | Purpose |
|------|---------|
| `Dockerfile` | Original multi-stage (SDK → AOT → chiseled). Retained for local development. |
| `Dockerfile.prebuilt` | Thin single-stage (chiseled only). Used by CI2 for Linux containers. |
| `Dockerfile.windows` | Original multi-stage for Windows Nano Server. Retained for local development. |
| `Dockerfile.windows.prebuilt` | Thin single-stage for Windows. Used by CI2 for Windows containers. |

## How to Deploy Manually

### Deploy a specific version to early adopters
1. Go to **Actions** → **CD2 · Early Adopter Rollout** → **Run workflow**
2. Enter the image tag (e.g., `1.20260309.42-linux-arm64`)
3. Click **Run workflow**

### Deploy to full production
1. Go to **Actions** → **CD3 · Full Production Rollout** → **Run workflow**
2. Enter the same image tag used in CD2
3. Click **Run workflow**
4. Approve the `production-rollout` environment when prompted

## Other Workflows

These workflows run independently of the main pipeline:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `build-cli.yml` | Push to `BareMetalWeb.CLI/`, manual | Cross-platform CLI binary builds |
| `codeql.yml` | Nightly schedule, manual | GitHub CodeQL security scanning |
| `deploy-tenant.yml` | Reusable (called by CD2/CD3) | Template for deploying to a single Azure tenant |
| `download-static-assets.yml` | Manual | Downloads Bootstrap themes, fonts, JS from CDNs |
| `perf-large.yml` | Nightly schedule, manual | Heavy stress tests with large datasets (trend analysis) |
