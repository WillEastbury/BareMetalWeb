# Deployment Rollback Runbook

## Purpose

Step-by-step procedure for rolling back to a previous BareMetalWeb version when a deployment causes issues.

---

## Deployment Architecture

BareMetalWeb uses GitHub Actions workflows for deployment:

| Workflow | Target | Purpose |
|----------|--------|---------|
| `deploy.yml` | Production | Main deployment pipeline |
| `deploy-prod.yml` | Production | Direct production deploy |
| `deploy-cimigrate.yml` | CI Migration | Build → publish → deploy to Azure |
| `deploy-cireset.yml` | CI Reset | Clean-slate testing with data reset |
| `deploy-tenant.yml` | Tenant-specific | Multi-tenant deployments |

**Docker image:** Multi-stage AOT build → chiseled runtime (distroless, non-root user `app` UID 1654)

**Persistent data:** Mounted at `/app/Data` (WAL segments, snapshots, logs, config)

---

## Symptoms

- Error rate spike immediately after deployment
- New version fails health checks (`/readyz` returns 503)
- New features broken, regressions in existing functionality
- Performance degradation after deploy

---

## Diagnosis

### Confirm Deployment Caused the Issue

```bash
# Check when the current version started
curl -s http://localhost:5232/health | jq .uptime_seconds

# Compare error rates before/after deploy
curl -s http://localhost:5232/metrics/prometheus | grep 'bmw_http_requests_total{class="5xx"}'

# Check recent logs for new errors
tail -50 Data/Logs/*.log | grep '"level":"Error\|Fatal"'
```

### Identify Current and Previous Versions

```bash
# Check the running container/process
docker ps --format "table {{.Image}}\t{{.Created}}\t{{.Status}}"

# Or check recent GitHub Actions runs
gh run list --repo WillEastbury/BareMetalWeb --limit 5
```

---

## Resolution: Rollback Procedures

### Option A: Docker Rollback

```bash
# List available images
docker images | grep baremetalweb

# Stop current container
docker stop bmw-prod

# Start previous version (data volume persists)
docker run -d \
  --name bmw-prod \
  -p 5232:5232 \
  -v /data/bmw:/app/Data \
  -e BMW_WAL_ENCRYPTION_KEY="$BMW_WAL_ENCRYPTION_KEY" \
  baremetalweb:previous-tag

# Verify health
curl -s http://localhost:5232/healthz | jq .
curl -s http://localhost:5232/readyz | jq .
```

### Option B: Azure App Service Rollback

```bash
# List recent deployments
az webapp deployment list --resource-group <rg> --name <app-name> --query "[].{id:id,time:receivedTime,status:status}"

# Swap back to previous slot (if using deployment slots)
az webapp deployment slot swap \
  --resource-group <rg> \
  --name <app-name> \
  --slot staging \
  --target-slot production

# Or redeploy previous commit
gh workflow run deploy-prod.yml \
  --repo WillEastbury/BareMetalWeb \
  --ref <previous-commit-sha>
```

### Option C: Git Revert + Redeploy

```bash
# Identify the problematic commit
git log --oneline -10

# Revert the commit
git revert <bad-commit-sha> --no-edit

# Push and let CI/CD redeploy
git push origin main
```

---

## Post-Rollback Verification

```bash
# 1. Health check
curl -s http://localhost:5232/health | jq .

# 2. Error rate should return to baseline
curl -s http://localhost:5232/metrics/prometheus | grep 'bmw_http_requests_total{class="5xx"}'

# 3. WAL operations normal
curl -s http://localhost:5232/metrics/prometheus | grep bmw_wal

# 4. Functional smoke test
curl -s http://localhost:5232/ -o /dev/null -w "%{http_code}"
```

---

## Data Compatibility

**Important:** BareMetalWeb WAL format changes may make data incompatible between versions.

### Safe to Rollback

- Code-only changes (route handlers, rendering, business logic)
- New endpoints added (old version simply won't serve them)
- Configuration changes (revert `Metal.config` if needed)

### Risky to Rollback

- **WAL format changes:** If the new version wrote segments in a new format, the old version may not be able to read them
- **Schema migrations:** New entity definitions may have been created
- **Encryption changes:** If encryption was enabled in the new version, old version must have the same `BMW_WAL_ENCRYPTION_KEY` and encryption support

### Mitigation for Risky Rollbacks

1. **Take a backup before rollback:** `cp -r Data/ Data.pre-rollback/`
2. **Test the old version** against the current data in a staging environment first
3. **If WAL format incompatible:** Restore from a backup taken before the problematic deployment

---

## Prevention

- **Use deployment slots** (staging → production swap) for zero-downtime deployments
- **Run CI tests** before deploying (`deploy-cireset.yml` does clean-slate testing)
- **Canary deployments:** Route small percentage of traffic to new version first
- **Take automated backups** before each deployment (`Backup.Enabled|true`)
- **Keep previous Docker images** tagged and available for quick rollback

---

## Escalation

| Condition | Action |
|-----------|--------|
| Rollback also fails | Restore from backup (see [Data Recovery](data-recovery.md)) |
| Data format incompatibility | Engage developer who made the WAL format change |
| Cannot identify previous working version | Check GitHub Actions history, Docker registry |
