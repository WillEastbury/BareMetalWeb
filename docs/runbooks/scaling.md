# Scaling Runbook

## Purpose

Guidelines for capacity planning, scaling decisions, and performance tuning for BareMetalWeb.

---

## Architecture Constraints

BareMetalWeb uses a single-writer WAL architecture with optional read replicas:

- **Single leader** holds the write lease (via `ClusterState` / `FileLeaseAuthority`)
- **Read replicas** can serve queries from the shared WAL directory
- **Dedicated compactor** instance can run compaction independently
- **No external database** — all state is in WAL segments on local/shared disk

---

## Symptoms That Indicate Scaling Need

| Symptom | Metric | Threshold | Action |
|---------|--------|-----------|--------|
| Slow response times | `bmw_request_duration_seconds{quantile="p99"}` | > 500ms sustained | Scale up compute or add read replicas |
| Request throttling | `bmw_requests_throttled_total` | Rising steadily | Increase rate limits or add capacity |
| High memory usage | `bmw_memory_working_set_bytes` | > 80% of available RAM | Scale up memory or optimize data |
| Disk I/O saturation | OS `iostat` metrics | > 90% utilization | Move to faster storage (SSD/NVMe) |
| WAL segment growth | Disk usage of `Data/wal_seg_*.log` | > 80% disk | Trigger compaction or expand storage |
| GC pressure | `bmw_gc_collections_total{generation="2"}` | Frequent Gen2 GCs | Increase memory, review allocations |

---

## Diagnosis

### Current Load Assessment

```bash
# Request rates and error rates
curl -s http://localhost:5232/metrics/prometheus | grep -E "bmw_http_requests_total|bmw_requests_throttled"

# In-flight requests (concurrency)
curl -s http://localhost:5232/metrics/prometheus | grep bmw_http_requests_in_flight

# Memory
curl -s http://localhost:5232/metrics/prometheus | grep bmw_memory

# WAL operation rates
curl -s http://localhost:5232/metrics/prometheus | grep bmw_wal

# Disk usage
df -h /app/Data
du -sh Data/wal_seg_*.log | sort -h | tail -10
```

### Capacity Planning Formula

```
Estimated WAL growth = (writes_per_second × avg_record_bytes × 86400) per day
Estimated memory = (total_live_records × 8 bytes for DirectIndex) + (working set for mmap pages)
Estimated IOPS = reads_per_second + writes_per_second + compaction_overhead
```

---

## Scaling Strategies

### Vertical Scaling (Scale Up)

**When:** Single instance is resource-constrained.

1. **CPU:** BareMetalWeb is single-threaded for writes; reads are concurrent. More cores help with concurrent reads and compaction.
2. **Memory:** Increase for larger HeadMap (WalDirectIndex), mmap page cache, and reducing GC pressure.
3. **Storage:** Use SSD/NVMe for WAL. IOPS matter more than throughput for random reads.

### Horizontal Scaling (Scale Out)

**When:** Read load exceeds single-instance capacity.

#### Read Replicas

1. Deploy additional instances pointing to the same WAL directory (shared NFS/Azure Files)
2. Configure as read-only (they won't acquire the leader lease)
3. Load-balance read traffic across replicas
4. Write traffic routes to the leader only

```
Metal.config on replicas:
# No special config needed — FileLeaseAuthority will fail to acquire lease
# and the instance will operate in read-only mode
```

#### Dedicated Compactor

1. Deploy a separate instance for WAL compaction
2. It acquires the compactor lease via `CompactorState`
3. Frees the leader from compaction I/O overhead

### Connection Tuning

Adjust in `appsettings.json`:

```json
{
  "Kestrel": {
    "Limits": {
      "MaxConcurrentConnections": 1000,
      "Http2": {
        "MaxStreamsPerConnection": 100,
        "InitialConnectionWindowSize": 131072,
        "InitialStreamWindowSize": 98304
      }
    }
  }
}
```

### Rate Limit Tuning

Adjust in `ApiRateLimiter.cs` constants (requires rebuild):

| Parameter | Default | Description |
|-----------|---------|-------------|
| `MaxReadsPerMinute` | 300 | GET requests per identity per minute |
| `MaxWritesPerMinute` | 60 | POST/PUT/PATCH/DELETE per identity per minute |

For higher-throughput deployments, increase these proportionally to your capacity.

---

## Resolution

### Quick Wins

1. **Enable compaction** if not running — reduces WAL size and improves read performance
2. **Increase mmap cache** — more cached segments = fewer disk reads
3. **Move logs to separate disk** — prevent log I/O from competing with WAL I/O
4. **Enable HTTP/2** — `Kestrel.Http2Enabled|true` reduces connection overhead

### Medium-Term

1. Deploy read replicas for read-heavy workloads
2. Set up dedicated compactor instance
3. Tune Kestrel connection limits for your load profile

### Long-Term

1. Shard data across multiple WAL stores by tenant (`Multitenancy.Enabled|true`)
2. Move to faster storage tier
3. Consider CDN for static assets (`StaticFiles.CacheSeconds` already set to 86400)

---

## Prevention

- **Monitor key metrics** via Prometheus/Grafana using `/metrics/prometheus`
- **Set alerts** on error rate, response latency, disk usage, memory usage
- **Regular load testing** to understand capacity limits before production load increases
- **Review compaction effectiveness** — if WAL grows faster than compaction reclaims, investigate write patterns

---

## Escalation

| Condition | Action |
|-----------|--------|
| Single instance cannot handle write load | Evaluate write batching, request queuing |
| Shared storage becomes bottleneck | Consider dedicated storage per instance with replication |
| Memory exceeds available RAM | Profile allocation hot spots, consider data tiering |
