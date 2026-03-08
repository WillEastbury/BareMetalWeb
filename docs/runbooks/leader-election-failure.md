# Leader Election Failure Runbook

## Purpose

Diagnose and resolve leader election failures in BareMetalWeb's `ClusterState` system.

---

## Architecture

BareMetalWeb uses a lease-based leader election for write access:

- **ClusterState** manages leader role, epoch tracking, and LSN assignment
- **ILeaseAuthority** provides the lease mechanism:
  - `LocalLeaseAuthority` — single-instance (always leader, epoch=1)
  - `FileLeaseAuthority` — multi-instance using shared storage (`.cluster-lease` file)
- **CompactorState** — independent lease for the compaction instance
- **Lease duration:** 15 seconds (configurable), renewed every 5 seconds
- **Stale detection:** 2× lease duration (30 seconds)
- **Epoch:** Monotonically increasing counter, incremented on each acquisition

### Invariants

- No two instances hold the write lease simultaneously
- Every WAL append requires `ValidateWritePermission()` — throws if lease lost
- On renewal failure, immediate demotion via `RoleChanged` event
- Lost lease = all writes fail until re-acquired

---

## Symptoms

- All write operations return errors (POST/PUT/PATCH/DELETE fail)
- `[BMW WAL]` logs show "write permission denied" or "not leader"
- `RoleChanged` event fired with demotion
- `.cluster-lease` file exists but is stale
- Multiple instances fighting for lease (rapid epoch increments)

---

## Diagnosis

### Check Current Leader Status

```bash
# Check server health — if writes are failing, health may report degraded
curl -s http://localhost:5232/health | jq .

# Check WAL commit metrics — zero commits = no leader or leader lost
curl -s http://localhost:5232/metrics/prometheus | grep bmw_wal_commits_total

# Check logs for leadership changes
grep -i "leader\|lease\|epoch\|role\|demotion" Data/Logs/*.log | tail -20
```

### Check Lease Files (FileLeaseAuthority)

```bash
# Check lease file existence and age
ls -la Data/.cluster-lease 2>/dev/null
ls -la Data/.cluster-epoch 2>/dev/null

# Read current epoch
cat Data/.cluster-epoch 2>/dev/null

# Check if lease file is locked (indicates active holder)
fuser Data/.cluster-lease 2>/dev/null
# Output: PID of the process holding the lock

# Check lease file staleness (>30 seconds = stale)
stat -c %Y Data/.cluster-lease 2>/dev/null
echo "Current time: $(date +%s)"
```

### Check for Split-Brain

```bash
# If multiple instances are running, check which one holds the lease
ps aux | grep BareMetalWeb

# Each instance should log its role
grep "RoleChanged\|became leader\|lost leader" Data/Logs/*.log
```

---

## Resolution

### Scenario 1: Single Instance, LocalLeaseAuthority

With `LocalLeaseAuthority`, the instance is always the leader. If writes are failing:

1. The issue is not leader election — investigate other causes (disk full, WAL corruption)
2. Check that the server started successfully: `curl http://localhost:5232/healthz`

### Scenario 2: Stale Lease File

If the previous leader crashed without releasing the lease:

1. **Wait for stale detection** (30 seconds by default) — the surviving instance will detect the stale lease and acquire it automatically

2. **If auto-recovery doesn't work:**
   ```bash
   # Stop all instances
   # Remove the stale lease file
   rm Data/.cluster-lease

   # Restart the primary instance — it will acquire the lease
   ```

### Scenario 3: Shared Storage Unavailable

If the shared storage (NFS, Azure Files) holding `.cluster-lease` is down:

1. No instance can acquire or renew the lease
2. All instances will demote themselves

**Resolution:**
1. Restore shared storage connectivity
2. Instances will automatically re-acquire the lease

**Temporary workaround (single instance only):**
1. Switch to `LocalLeaseAuthority` (modify configuration)
2. Restart the instance — it becomes leader immediately
3. Switch back to `FileLeaseAuthority` when shared storage is restored

### Scenario 4: Rapid Epoch Increment (Flapping)

If instances are rapidly acquiring and losing the lease:

1. Check shared storage latency — high latency causes renewal timeouts
2. Check clock synchronization between instances
3. Check for resource exhaustion (CPU, memory) causing the renewal timer to miss deadlines

```bash
# Check epoch progression speed
cat Data/.cluster-epoch
sleep 30
cat Data/.cluster-epoch
# If epoch increased significantly in 30 seconds, flapping is occurring
```

**Resolution:**
1. Reduce the number of competing instances to 1
2. Fix underlying storage/network issue
3. Gradually add instances back

### Scenario 5: Manual Leader Assignment

To force a specific instance to become leader:

1. Stop all other instances
2. Remove the lease file: `rm Data/.cluster-lease`
3. Start only the desired leader instance
4. Once it acquires the lease, start read-only replicas

---

## Prevention

- **Monitor lease renewals** — alert if lease acquisition/renewal failures exceed threshold
- **Use stable shared storage** — reliable, low-latency shared filesystem for lease files
- **Set appropriate timeouts** — lease duration should accommodate worst-case storage latency
- **Single-writer principle** — only one instance needs the write lease; others serve reads
- **Health monitoring** — `/readyz` will report not-ready if the instance has no write capability and writes are expected

---

## Escalation

| Condition | Action |
|-----------|--------|
| Lease flapping persists after storage fix | Increase lease duration; reduce competing instances |
| Shared storage permanently lost | Switch to LocalLeaseAuthority on single instance |
| Split-brain suspected (two leaders) | Immediately stop all but one instance; verify data integrity |
| Epoch counter overflow | Extremely unlikely (uint64); restart all instances to reset |
