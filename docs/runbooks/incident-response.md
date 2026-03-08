# Incident Response Runbook

## Purpose

Step-by-step procedure for triaging, diagnosing, and resolving production incidents on BareMetalWeb.

---

## Severity Levels

| Level | Description | Response Time | Examples |
|-------|-------------|---------------|----------|
| **SEV1** | Service down, data loss risk | Immediate | WAL corruption, leader election failure, full disk |
| **SEV2** | Degraded service, partial outage | < 15 min | High error rate, slow responses, auth failures |
| **SEV3** | Minor impact, single feature broken | < 1 hour | Rendering errors, single-tenant issue |
| **SEV4** | Cosmetic, no user impact | Next business day | Log noise, non-critical warnings |

---

## 1. Triage

### Check Service Health

```bash
# Liveness probe (always 200 if process is running)
curl -s http://localhost:5232/healthz | jq .

# Readiness probe (503 if not ready)
curl -s -o /dev/null -w "%{http_code}" http://localhost:5232/readyz

# Full health with uptime
curl -s http://localhost:5232/health | jq .
```

### Check Metrics

```bash
# Prometheus metrics (error rates, request counts, WAL ops)
curl -s http://localhost:5232/metrics/prometheus | grep -E "bmw_http_requests|bmw_wal|bmw_errors"

# Key indicators:
# - bmw_http_requests_total{class="5xx"} — rising = server errors
# - bmw_http_requests_in_flight — stuck high = resource exhaustion
# - bmw_wal_commits_total — zero = WAL writes stopped (leader lost?)
# - bmw_gc_collections_total — rapid increase = memory pressure
```

### Check Logs

```bash
# Recent errors (logs are JSON, optionally encrypted)
tail -100 Data/Logs/*.log | grep -i '"level":"Error\|Fatal"'

# WAL-specific messages
grep '\[BMW WAL\]' Data/Logs/*.log | tail -20

# Auth failures
grep '"statusCode":401\|"statusCode":403' Data/Logs/*.log | tail -20
```

---

## 2. Diagnose

### Common Patterns

| Symptom | Likely Cause | Jump To |
|---------|-------------|---------|
| `/readyz` returns 503 | Server still initializing or WAL recovery in progress | Wait or check WAL recovery logs |
| 5xx spike | Unhandled exception, resource exhaustion | Check logs, memory, disk |
| All writes fail | Leader lease lost | [Leader Election Failure](leader-election-failure.md) |
| Slow responses | Disk I/O, compaction running, memory pressure | [Disk Pressure](disk-pressure.md) |
| 401/403 spike | Auth system issue, session store corruption | Check UserAuth logs |
| Process crash | OOM, segfault in unsafe code | Check system journal, core dumps |

### System-Level Checks

```bash
# Process status
ps aux | grep BareMetalWeb

# Memory usage
cat /proc/$(pgrep -f BareMetalWeb)/status | grep -E "VmRSS|VmSize"

# Disk usage
df -h /app/Data

# Open file descriptors (important for mmap)
ls /proc/$(pgrep -f BareMetalWeb)/fd | wc -l

# Network connections
ss -tlnp | grep 5232
```

---

## 3. Mitigate

### Immediate Actions by Severity

**SEV1 — Service Down:**
1. Check if process is running; restart if crashed
2. If WAL corruption suspected, stop writes immediately (see [Data Recovery](data-recovery.md))
3. If disk full, free space immediately (see [Disk Pressure](disk-pressure.md))
4. If leader election stuck, see [Leader Election Failure](leader-election-failure.md)

**SEV2 — Degraded:**
1. Check rate limiter metrics — throttling may be protecting the system
2. If high error rate, check recent deployments and consider rollback (see [Deployment Rollback](deployment-rollback.md))
3. If auth broken, check session store and encryption key availability

**SEV3/4 — Minor:**
1. Document the issue
2. Check logs for root cause
3. Schedule fix

---

## 4. Resolve

After mitigation, confirm resolution:

```bash
# Verify health restored
curl -s http://localhost:5232/health | jq .

# Verify error rate has dropped
curl -s http://localhost:5232/metrics/prometheus | grep 'bmw_http_requests_total{class="5xx"}'

# Verify WAL operations resumed
curl -s http://localhost:5232/metrics/prometheus | grep bmw_wal_commits_total
```

---

## 5. Post-Mortem Template

After any SEV1 or SEV2 incident, complete a post-mortem:

```markdown
## Incident Post-Mortem

**Date:** YYYY-MM-DD
**Duration:** HH:MM start → HH:MM resolved
**Severity:** SEV1/SEV2
**Impact:** (users affected, data lost, SLA breached)

### Timeline
- HH:MM — First alert / symptom observed
- HH:MM — Triage began
- HH:MM — Root cause identified
- HH:MM — Mitigation applied
- HH:MM — Service restored

### Root Cause
(What broke and why)

### Resolution
(What was done to fix it)

### Prevention
- [ ] Action item 1 (owner, due date)
- [ ] Action item 2 (owner, due date)

### Lessons Learned
(What we'd do differently)
```

---

## Escalation

| Condition | Action |
|-----------|--------|
| Cannot identify root cause within 30 min | Escalate to senior engineer |
| Data loss confirmed or suspected | Immediately stop writes, escalate to data team |
| Security breach suspected | See [Security Incident](security-incident.md) |
| Multiple systems affected | Coordinate cross-team response |
