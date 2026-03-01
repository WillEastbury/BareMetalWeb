# Deterministic Domain Transition Kernel

This document captures the core runtime target for BareMetalWeb's action/transaction model.

---

## Implementation Status

The following kernel components are **implemented** in the current codebase:

| Component | Location | Status |
|-----------|----------|--------|
| `ActionExpander` | `BareMetalWeb.Runtime/ActionExpander.cs` | ✅ Implemented — expands `RuntimeActionModel.Commands` into a `TransactionEnvelope` |
| `AggregateLockManager` | `BareMetalWeb.Runtime/AggregateLockManager.cs` | ✅ Implemented — process-scoped in-memory pessimistic locking with sorted acquisition order |
| `TransactionEnvelope` | `BareMetalWeb.Runtime/TransactionEnvelope.cs` | ✅ Implemented — holds `AggregateMutation` (field-level deltas) and `AssertionResult` list |
| `CommandService` | `BareMetalWeb.Runtime/CommandService.cs` | ✅ Implemented — dispatches create/update/delete and named action operations |
| `WalDataProvider` | `BareMetalWeb.Data/WalDataProvider.cs` | ✅ Implemented — WAL-backed `IDataProvider`; all records stored as commit-log payloads in `WalStore` |
| `WalStore` / `WalSegmentWriter` | `BareMetalWeb.Data/WalStore.cs`, `WalSegmentWriter.cs` | ✅ Implemented — append-only WAL segments with `CRC-32C` checksums |
| `ActionDefinition` / `ActionCommandDefinition` | `BareMetalWeb.Runtime/ActionDefinition.cs`, `ActionCommandDefinition.cs` | ✅ Implemented — persisted child entity for structured action commands |

---

BareMetalWeb is targeting a **deterministic domain transition kernel** backed by a **write-ahead log (WAL, append-only log)** and **invariant-based transactional correctness**.

### Explicit Non-Goals

- Not a general-purpose SQL database
- Not an ORM abstraction
- Not a workflow/orchestration engine
- Not a scripting runtime
- Not a low-code imperative automation layer

---

## Fundamental Model

### 1) Mutation is the primitive

The canonical unit of change is a **field-level delta**.

At commit time, all requests reduce to:

1. Expand action intent
2. Generate canonical delta
3. Validate invariants
4. Persist durably (WAL)

### 2) Actions are transition macros

Actions are metadata-defined transition macros that expand into deterministic commands and deltas.

- Actions are not replayed from history
- Stored history is mutation data, not executable behavior
- Server re-expands action intent and never trusts client-authored delta

### 3) Correctness comes from invariants

Commit acceptance is based on whether invariants hold in canonical state under lock scope.

- Storage/version metadata can assist diagnostics
- Invariant validity is the final correctness gate

### 4) Workflow is emergent

There is no separate workflow engine. Legal state transitions emerge from:

- Current state
- Action guard conditions/assertions
- Permission checks

### 5) Cross-aggregate mutation is explicit

Cross-aggregate effects must be declared explicitly and flattened into one transaction envelope (the full set of touched aggregates plus field-level changes/assertions for one commit).

- No hidden mutation cascades
- No unbounded nested invoke chains
- Deterministic lock ordering for all touched aggregates

### 6) Isolation is pessimistic and scoped

- Fine-grained in-memory aggregate locks
- Deterministic acquisition order
- Short-lived lock scope around validation + commit
- WAL durability handles crash safety; locks remain ephemeral

### 7) Client is untrusted

Client input may request an action, but authoritative mutation is always generated server-side.

---

## Implementation Checklist

The items below track the implementation progress of kernel fundamentals:

- ✅ WAL record durability — `WalSegmentWriter` / `WalStore` with CRC-32C checksums
- ✅ Deterministic lock acquisition order — `AggregateLockManager.TryAcquireAll` (sorted ascending by aggregate ID)
- ✅ Server-side action expansion — `ActionExpander.Expand()` always runs server-side; client deltas are never trusted
- ✅ Field-level delta envelope — `TransactionEnvelope` + `AggregateMutation` + `FieldValueChange`
- ✅ Assertion / invariant evaluation — `AssertIfCommand` / `AssertionResult` within `ActionExpander`
- ⬜ Canonical envelope ordering rules (stable field/aggregate ordering for deterministic hashing/auditing)
- ⬜ WAL record contract schema (assertions, touched aggregate keys, checksum spec)
- ⬜ Replay contract (data replay only, never behavior replay)
- ⬜ Snapshot/compaction policy and recovery bounds (RPO/RTO expectations)
- ⬜ Invariant catalog boundaries (precondition vs commit-time invariant)
- ⬜ Side-effect boundary (outbox/dispatch policy so external effects are not in transaction expansion)
- ⬜ Projection/versioning policy (UI/API payloads as projections over kernel state)

These are architectural guardrails; implementation details can evolve as long as these constraints remain true.

---

_Status: Verified against codebase @ commit e38d19057e1a55fc1d9a563f5ec6228bb991a0b5_
