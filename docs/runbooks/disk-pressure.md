# Disk Pressure Runbook

## Purpose

Diagnose and resolve disk pressure issues including WAL growth, log accumulation, and compaction procedures.

---

## Disk Layout

```
/app/Data/                          # Persistent data volume
├── wal_seg_*.log                   # WAL segments (~64 MB each, append-only)
├── wal_snapshot.bin                # HeadMap checkpoint
├── wal_seqids.bin                  # Key allocator state
├── Logs/                           # Application logs (JSON, 30-day retention)
├── Backups/                        # Automated backups (configurable retention)
│   └── backup_YYYYMMDD_HHMM/
├── .cluster-lease                  # Leader election lease file
├── .cluster-epoch                  # Epoch counter
└── <entity-data>/                  # Entity definition files, indexes
```

---

## Symptoms

- Disk usage alerts from monitoring
- Write operations fail with I/O errors
- Server fails to start (cannot create new WAL segment)
- `df -h` shows > 90% usage on data volume
- WAL segment rotation creates many files

---

## Diagnosis

```bash
# Overall disk usage
df -h /app/Data

# Breakdown by component
echo "=== WAL Segments ==="
du -sh Data/wal_seg_*.log 2>/dev/null | tail -10
echo "Total WAL: $(du -sh Data/wal_seg_*.log 2>/dev/null | awk '{sum+=$1} END {print sum}')M"
ls Data/wal_seg_*.log | wc -l
echo "segments"

echo "=== Logs ==="
du -sh Data/Logs/ 2>/dev/null

echo "=== Backups ==="
du -sh Data/Backups/ 2>/dev/null
ls Data/Backups/ 2>/dev/null | wc -l
echo "backup sets"

echo "=== Snapshot ==="
ls -lh Data/wal_snapshot.bin 2>/dev/null

echo "=== Other ==="
du -sh Data/ --exclude='wal_seg_*' --exclude='Logs' --exclude='Backups' 2>/dev/null
```

### Identify Largest Consumers

```bash
# Top 10 largest files in data directory
find Data/ -type f -exec du -h {} + | sort -rh | head -10

# WAL segment sizes (identify bloated segments)
ls -lhS Data/wal_seg_*.log | head -10
```

---

## Resolution

### 1. Log Cleanup

Logs have a 30-day retention policy enforced by `DiskBufferedLogger`, but manual cleanup is safe for older logs:

```bash
# Check log retention
ls -lt Data/Logs/*.log | tail -10

# Remove logs older than 7 days (emergency)
find Data/Logs/ -name "*.log" -mtime +7 -delete

# Check reclaimed space
df -h /app/Data
```

### 2. Backup Cleanup

```bash
# List backups by date
ls -lt Data/Backups/

# Remove backups older than retention period (default 30 days)
# The server does this automatically via PurgeExpiredBackups()
# For emergency cleanup, manually remove old backups:
ls -d Data/Backups/backup_* | head -n -3 | xargs rm -rf
# (keeps the 3 most recent backups)

# Reduce retention in Metal.config:
# Backup.RetentionDays|7
```

### 3. WAL Compaction

Compaction removes dead keys (overwritten/deleted records) from WAL segments, reclaiming disk space.

**How compaction works:**
1. Reads all keys from a segment via `SegmentIndex`
2. Checks which keys are still live in the HeadMap
3. Rewrites only live records to a `.compact` temp file
4. Atomic rename replaces the original segment
5. Updates HeadMap pointers

**Compaction is automatic** when a dedicated compactor instance is running. To verify:

```bash
# Check compaction metrics
curl -s http://localhost:5232/metrics/prometheus | grep bmw_wal_compactions

# Check compaction logs
grep '\[BMW WAL\].*compact' Data/Logs/*.log | tail -10
```

**If compaction is not running or not keeping up:**

1. Verify compactor instance is healthy
2. Check if compaction is blocked by lock contention
3. Consider adding a dedicated compactor instance (separate from the write leader)

### 4. Temporary File Cleanup

```bash
# Remove orphaned compact temp files (from interrupted compactions)
find Data/ -name "*.compact" -mmin +60 -delete

# Remove orphaned lock files
find Data/ -name "*.lock" -mmin +60 -delete
```

### 5. Emergency: Expand Storage

If cleanup isn't sufficient:

```bash
# Azure: Expand managed disk
az disk update --resource-group <rg> --name <disk-name> --size-gb <new-size>

# Docker: Expand volume
# (depends on storage driver — consult Docker documentation)

# Kubernetes: Expand PVC (if storage class supports it)
kubectl patch pvc data-pvc -p '{"spec":{"resources":{"requests":{"storage":"100Gi"}}}}'
```

---

## Prevention

- **Monitor disk usage** — alert at 70% and 85% thresholds
- **Enable automated compaction** — run a dedicated compactor instance
- **Set log retention** — `Logging.RetentionDays` in configuration (default: 30)
- **Set backup retention** — `Backup.RetentionDays|30` in `Metal.config`
- **Size data volume appropriately:**
  - Estimate: `(daily_writes × avg_record_size × retention_days × 2)` (2× for compaction overhead)
  - Add 20% headroom for logs and backups
- **Monitor WAL segment count** — rapidly growing segment count indicates high write volume

### Monitoring Queries (Prometheus)

```promql
# Disk usage alert (requires node_exporter or similar)
node_filesystem_avail_bytes{mountpoint="/app/Data"} / node_filesystem_size_bytes{mountpoint="/app/Data"} < 0.15

# WAL growth rate
rate(bmw_wal_commits_total[5m])

# Compaction effectiveness
rate(bmw_wal_compactions_total[1h])
```

---

## Escalation

| Condition | Action |
|-----------|--------|
| Disk 100% full, writes failing | Emergency cleanup (logs first, then old backups) |
| Compaction not reclaiming space | Investigate — may indicate many live records; expand storage |
| Storage expansion not possible | Archive old WAL segments to cold storage; implement data tiering |
| Repeated disk pressure | Revisit capacity planning (see [Scaling](scaling.md)) |
