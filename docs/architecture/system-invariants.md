# System Invariants

Hard rules. Not negotiable. These are not conventions—they are load-bearing constraints.
Breaking any one of them breaks the correctness model.

---

## 1. WAL is the source of truth

Committed state lives in the append-only WAL segments (`WalStore`).
In-memory projections (`WalHeadMap`, secondary indexes) are derived views.
On crash, recovery replays the WAL tail from the last valid snapshot.
Any data path that bypasses the WAL is a bug.

**Enforced by:** `WalStore.CommitAsync` (fsync before head-map update), `WalStore` startup replay.
**Source:** `BareMetalWeb.Data/WalStore.cs`, `BareMetalWeb.Data/WalSnapshot.cs`

---

## 2. All mutation is delta

The canonical unit of change is a field-level delta (`WalOp`).
Full-image writes (`OpTypeUpsertFullImage`) are also accepted, but they are still a delta
relative to the previous head pointer.
There is no in-place mutation of committed records.

**Enforced by:** `WalOp` op types (`OpTypeUpsertFullImage`, `OpTypeUpsertPatchRuns`, `OpTypeDeleteTombstone`).
**Source:** `BareMetalWeb.Data/WalOp.cs`, `BareMetalWeb.Data/WalConstants.cs`

---

## 3. No direct state mutation

Callers never modify the in-memory head map or index directly.
All writes go through `WalStore.CommitAsync`, which atomically fsyncs the segment
and then updates `WalHeadMap`.
`ProjectionManager` receives dispatched ops after commit—it never writes to the WAL itself.

**Enforced by:** `WalStore._writeLock` (single writer), projection dispatch happens post-commit.
**Source:** `BareMetalWeb.Data/WalStore.cs`, `BareMetalWeb.Data/WalProjectionManager.cs`

---

## 4. Server validates end state, not client path

Clients submit action intent (an action name + parameters).
The server re-expands the action, re-evaluates all expressions against current aggregate state,
and generates the authoritative delta.
Client-supplied deltas are never trusted.

**Enforced by:** `ActionExpander.Expand` (always called server-side; client input ignored for delta generation).
**Source:** `BareMetalWeb.Runtime/ActionExpander.cs`

---

## 5. Single writer guarantees deterministic ordering

All writes to a `WalStore` instance are serialised under `_writeLock`.
Cross-aggregate transactions acquire aggregate locks in deterministic (sorted) order via
`AggregateLockManager` to eliminate deadlocks.
There is exactly one commit watermark (`VisibleCommitPtr`) that advances monotonically.

**Enforced by:** `WalStore._writeLock`, `AggregateLockManager` sorted acquisition.
**Source:** `BareMetalWeb.Data/WalStore.cs`, `BareMetalWeb.Runtime/AggregateLockManager.cs`

---

## 6. Actions are expanded, not executed remotely

Actions are metadata-defined transition macros stored as `RuntimeActionModel`.
`ActionExpander.Expand` converts them into a `TransactionEnvelope` (field-level mutations +
assertions) entirely on the server.
Actions are not replayed from history; stored history is mutation data only.
Nested `InvokeIf` chains are rejected at expansion time.

**Enforced by:** `ActionExpander` (throws on depth > 0), server-side-only expansion path.
**Source:** `BareMetalWeb.Runtime/ActionExpander.cs`, `BareMetalWeb.Runtime/TransactionEnvelope.cs`

---

## 7. Storage is blind to business semantics

`WalStore`, `LocalFolderBinaryDataProvider`, and the binary serializer deal only in bytes,
keys, and schema signatures.
They have no knowledge of field meaning, validation rules, permissions, or workflow state.
Business rules are enforced by the layers above (route handlers, `ActionExpander`, validators).

**Enforced by design:** `WalStore` accepts `WalOp` byte payloads with no interpretation.
**Source:** `BareMetalWeb.Data/WalStore.cs`, `BareMetalWeb.Data/LocalFolderBinaryDataProvider.cs`

---

## 8. Business invariants live above storage

Validation, permission checks, calculated-field evaluation, and action guard assertions
all execute before `CommitAsync` is called.
The storage layer is the last step, not the correctness gate.

**Enforced by call order:** validate → `CalculatedFieldService.EvaluateCalculatedFieldsAsync`
→ `ActionExpander.Expand` → assertion checks → `WalStore.CommitAsync`.
**Source:** `BareMetalWeb.Runtime/ActionExpander.cs`, `BareMetalWeb.Data/ExpressionEngine/CalculatedFieldService.cs`

---

## Quick-reference table

| # | Invariant | Where enforced |
|---|-----------|----------------|
| 1 | WAL is the source of truth | `WalStore` fsync + recovery |
| 2 | All mutation is delta | `WalOp` op types |
| 3 | No direct state mutation | `WalStore._writeLock`; projections post-commit only |
| 4 | Server validates end state, not client path | `ActionExpander.Expand` |
| 5 | Single writer; deterministic ordering | `_writeLock` + `AggregateLockManager` |
| 6 | Actions are expanded, not executed remotely | `ActionExpander`; depth guard |
| 7 | Storage is blind to business semantics | `WalStore` / `LocalFolderBinaryDataProvider` |
| 8 | Business invariants live above storage | Validate before `CommitAsync` |
