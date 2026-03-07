# Cluster State & Leader Election

This document specifies the cluster state model for BareMetalWeb: deterministic
single-writer leader election, fenced WAL commits, follower replication, and
recovery semantics.

**Design philosophy:** No consensus, no quorum, no voting. Just fencing + durability.

---

## Lease Authority

External lease controls leadership. The lease holder is the **sole writer**.

| Property | Value |
|----------|-------|
| Default lease duration | 15 seconds |
| Renewal interval | 5 seconds |
| Stale detection | 2× lease duration (30s) |
| On renewal failure | Immediate demotion |
| Lease storage | Pluggable (`ILeaseAuthority`) |

**Implementations:**
- `LocalLeaseAuthority` — single-instance (always leader, epoch=1)
- `FileLeaseAuthority` — file-based lock for shared storage deployments

### FileLeaseAuthority — How It Works

The file-based election uses **atomic file creation** as a distributed mutex:

```
Acquire:
  1. FileStream(path, FileMode.CreateNew, FileOptions.DeleteOnClose)
     - CreateNew fails with IOException if file already exists
     - DeleteOnClose ensures the lease file is removed when the process exits
  2. Write InstanceId to file
  3. IncrementEpoch() — read-increment-write to .cluster-epoch file
  4. Set expiry = UtcNow + leaseDuration

Stale Recovery:
  If CreateNew fails (lease file exists):
    - Stat the file's LastWriteTimeUtc
    - If age > 2× leaseDuration → file is stale (holder crashed)
    - Delete stale file, retry CreateNew exactly once
    - If retry fails → another instance won the race (safe)

Renew:
  1. Verify lease file still exists on disk
  2. Seek to 0, truncate, write "InstanceId|timestamp"
  3. Flush with fsync
  4. Reset expiry = UtcNow + leaseDuration
  If any step fails → immediate Demote()

Release:
  1. Dispose FileStream (triggers DeleteOnClose)
  2. Clear internal state
```

### Epoch Store

Each leadership acquisition increments a monotonic **Epoch**.

```
On leadership acquisition:
  1. Acquire lease
  2. Read current epoch from .cluster-epoch file
  3. Increment epoch
  4. Write to temp file, rename over original (near-atomic)
  5. This value becomes CurrentEpoch
```

**Epoch must be strictly increasing forever.** No two leaders share the same epoch.

> ⚠️ **Known issue (#1139):** `File.Move(temp, target, overwrite:true)` is
> near-atomic on POSIX but not guaranteed on Windows/NTFS. A crash during the
> move could leave the epoch file in an inconsistent state.

---

## WAL Fencing

Every WAL commit is fenced by the leader's lease and epoch.

### Write Fence Call Sites

All mutations in `WalDataProvider` are guarded by `_clusterState?.ValidateWritePermission()`:

| Method | Purpose |
|--------|---------|
| `Save<T>()` | Save a typed DataObject |
| `Delete<T>()` | Delete a typed DataObject by key |
| `SaveRecord()` | Save a dynamic DataRecord |
| `DeleteRecord()` | Delete a dynamic DataRecord by key |

The `?.` operator means the fence is a no-op in single-instance mode (where
`_clusterState` is null), adding zero overhead.

### Commit Algorithm (Leader Only)

```
1. ValidateWritePermission()     — check lease still held
2. AssignLsn()                   — (epoch, lsn) = next sequential pair
3. Serialize payload
4. Compute CRC32C
5. Revalidate lease               — if lost, ABORT (no write)
6. AppendCommitBatch + Flush      — durable fsync
7. Update HeadMap
8. Return success
```

**Critical invariant:** No write occurs without a valid lease. Step 5 re-checks
the lease *after* serialization but *before* the durable append.

### ValidateWritePermission — Double-Check Pattern

```csharp
public long ValidateWritePermission()
{
    if (!IsLeader)                  // 1. Check in-memory role flag
        throw ...;
    if (!_lease.IsLeader)           // 2. Check lease validity (file still locked?)
    {
        Demote();                   //    Lost lease between checks — demote
        throw ...;
    }
    return _lease.CurrentEpoch;     // 3. Return epoch for WAL fence token
}
```

This double-check ensures that even if the renewal loop hasn't fired yet,
a stale leader cannot write after losing its file lock.

---

## Recovery Algorithm

### On Startup

```
1. Scan WAL segments sequentially
2. Stop at first CRC failure or partial entry
3. Set LastLsn to last valid entry
4. Discard corrupted tail
```

### On New Leader Election

```
1. Acquire lease
2. Increment Epoch
3. Replay WAL (data replay only — no behavior re-execution)
4. Resume accepting writes
```

**New leader does NOT trust in-memory state. WAL is canonical.**

---

## Follower Replication

Followers poll the leader:

```
GET /api/_cluster/replicate?afterLsn=X
```

Leader returns ordered entries. Follower applies sequentially.

### Follower State

```
LastAppliedLsn    — watermark of last applied entry
LastSeenEpoch     — tracks leadership changes
```

If follower sees an Epoch jump, it accepts — that means leadership changed.

---

## Compactor Lease

The system supports an independent **compactor lease** via `CompactorState`.
On single-node deployments, the same instance holds both writer and compactor
leases. On multi-node deployments, compaction can run on a dedicated node.

```
CompactorState mirrors ClusterState:
  - TryBecomeCompactorAsync()     — acquire compactor lease
  - ValidateCompactionPermission() — fence before compacting
  - StepDownAsync()               — voluntary release
  - Background renewal loop (5s interval)
  - Immediate demotion on any failure
```

The compactor uses a separate `ILeaseAuthority` instance (with a distinct
lease name) so that writer and compactor elections are independent.

---

## Cluster API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/_cluster` | Cluster state snapshot (role, epoch, LSN, instance ID) |
| GET | `/api/_cluster/replicate?afterLsn=X` | Replication endpoint for followers |
| POST | `/api/_cluster/stepdown` | Voluntary leadership stepdown |

All endpoints require admin authentication.

---

## Invariants

These must never be violated:

1. No two leaders share the same Epoch
2. No WAL entry is written without valid lease
3. LSN strictly increases
4. Recovery truncates invalid WAL tail
5. Old leader cannot append after losing lease

If these hold, the system is safe.

---

## Failure Semantics

| Scenario | Outcome |
|----------|---------|
| Leader dies before fsync | Entry not durable. Client times out. Retry safe. |
| Leader dies after fsync | Entry durable. New leader resumes from WAL. No loss. |
| Leader crashes (DeleteOnClose) | Lease file auto-deleted. Next instance acquires. |
| Leader hangs (no crash) | Lease file stale after 30s. Follower reclaims. |
| Follower stale read | Allowed within bounded staleness. |
| Election window | Writes temporarily unavailable. Reads continue. |

---

## Role Transitions

```
              TryBecomeLeader()
  Follower ─────────────────────→ Leader
     ↑                              │
     │    Renewal failure /         │
     │    StepDown() /              │
     │    Lease expired             │
     └──────────────────────────────┘
```

Role changes emit a `ClusterState.RoleChanged` event for observers.

---

## Pluggable Strategy

The `ILeaseAuthority` interface enables pluggable leader election:

```csharp
public interface ILeaseAuthority
{
    ValueTask<bool> TryAcquireAsync(CancellationToken ct);
    ValueTask<bool> TryRenewAsync(CancellationToken ct);
    ValueTask ReleaseAsync(CancellationToken ct);
    bool IsLeader { get; }
    long CurrentEpoch { get; }
    string InstanceId { get; }
}
```

Implementations can target:
- Local file locks (shared storage)
- Azure Blob leases
- Redis SETNX
- etcd/Consul sessions

The system initializes with `LocalLeaseAuthority` by default (single-instance mode).

---

_Status: Implemented in ClusterState.cs, LeaseAuthority.cs, ClusterApiHandlers.cs_
_See also: #1139 (epoch atomicity on Windows)_
