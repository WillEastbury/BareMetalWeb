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
| On renewal failure | Immediate demotion |
| Lease storage | Pluggable (`ILeaseAuthority`) |

**Implementations:**
- `LocalLeaseAuthority` — single-instance (always leader, epoch=1)
- `FileLeaseAuthority` — file-based lock for shared storage deployments

### Epoch Store

Each leadership acquisition increments a monotonic **Epoch**.

```
On leadership acquisition:
  1. Acquire lease
  2. Read current epoch
  3. Increment epoch
  4. Write back (CAS where supported)
  5. This value becomes CurrentEpoch
```

**Epoch must be strictly increasing forever.** No two leaders share the same epoch.

---

## WAL Fencing

Every WAL commit is fenced by the leader's lease and epoch.

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

## Cluster API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/_cluster` | Cluster state snapshot (role, epoch, LSN, instance ID) |
| GET | `/api/_cluster/replicate?afterLsn=X` | Replication endpoint for followers |
| POST | `/api/_cluster/stepdown` | Voluntary leadership stepdown |

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
