# Deterministic Domain Transition Kernel

This document captures the core runtime specification for BareMetalWeb's action/transaction model.
It is the authoritative reference for the commit pipeline, concurrency model, DSL semantics, and
crash-recovery contract.

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

BareMetalWeb targets a **deterministic domain transition kernel** backed by a
**write-ahead log (WAL, append-only log)** and **invariant-based transactional correctness**.

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

All requests reduce at commit time to a `TransactionEnvelope` — a flat, ordered list of
`AggregateMutation` records, each carrying zero or more `FieldValueChange` entries.

The envelope is the **atomic commit unit**.  Individual aggregate row updates are not
independently atomic; the entire envelope commits or the entire envelope is rejected.

### 2) Actions are transition macros

Actions are metadata-defined transition macros that expand into deterministic commands and deltas.

- Actions are not replayed from history
- Stored history is mutation data (field-level deltas), not executable behavior
- Server re-expands action intent and **never trusts client-authored deltas**

### 3) Correctness comes from invariants

Commit acceptance is based on whether invariants hold in canonical state under lock scope.

- Storage/version metadata can assist diagnostics
- Invariant validity is the final correctness gate — not row version equality, not MVCC

### 4) Workflow is emergent

There is no separate workflow engine.  Legal state transitions emerge from:

- Current aggregate state
- Action guard conditions/assertions
- Permission checks

### 5) Cross-aggregate mutation is explicit

Cross-aggregate effects must be declared explicitly and flattened into one `TransactionEnvelope`.

- No hidden mutation cascades
- No unbounded nested invoke chains (flat only — see §Invocation Order)
- Deterministic lock ordering for all touched aggregates

### 6) Isolation is pessimistic and scoped

- Fine-grained in-memory per-aggregate locks (`AggregateLockManager`)
- Deterministic acquisition order (ascending `aggregateId` sort — §Aggregate Locking)
- Short-lived lock scope around re-validation and WAL append
- WAL durability handles crash safety; locks are ephemeral and never persisted

### 7) Client is untrusted

Client input may request an action by name, but authoritative mutation is always generated
server-side.  Client-proposed deltas are advisory only and are never used as commit input.

---

## Aggregate Locking & Deadlock-Free Ordering

All aggregate locks are held by `AggregateLockManager` (process-scoped, in-memory only).

**Protocol:**

1. Collect all aggregate IDs that will be touched by the `TransactionEnvelope`.
2. Sort IDs deterministically (ascending ordinal string order) — this is the global deadlock-
   prevention rule; every transaction acquires locks in the same order.
3. Call `TryAcquireAll` — this is a **try-lock** (non-blocking).  If any lock is held by
   another live transaction, the attempt fails immediately.
4. On failure, apply **exponential back-off retry** (up to a bounded maximum).  If all
   retries are exhausted, return a transient failure to the caller.
5. On success, hold the locks for the duration of re-validation + WAL append, then release.

**Invariants about locks:**

- Locks carry a safety expiry timestamp.  An expired lock is treated as released.
  Expiry is a **safety net for abnormal termination**, not the primary flow-control
  mechanism — normal code must always call `ReleaseAll` in a `finally` block.
- Locks are **never written to disk** and do not survive a process crash or restart.
- No blocking waits occur inside lock scope.

---

## Commit Path Pipeline

The exact sequence executed by `CommandService.ExecuteStructuredActionAsync` is:

```
Receive ActionRequest (entity slug + action name + aggregate id)
  → Look up action definition from RuntimeEntityRegistry
  → Load canonical aggregate state from data store
  → Server-side expand: ActionExpander.Expand(action, context)
      → Evaluate commands in declared order
      → Collect field deltas (AggregateMutation[]) + assertion results
      → Produce TransactionEnvelope
  → Validate assertions (IsValid check)
      → Any AssertSeverity.Error with Fired=true → reject immediately, no locks acquired
  → Determine touched aggregates from envelope.AggregateMutations
  → Sort aggregate IDs (ascending ordinal)
  → TryAcquireAll (with back-off retry)
      → Failure after max retries → return transient error
  → Re-load canonical state (post-lock, authoritative read)
  → Re-run invariant assertions cross-aggregates under lock
  → Apply field deltas to in-memory object
  → Atomic WAL append (commit batch record, CRC-protected)
  → Persist / save object
  → ReleaseAll locks (in finally block)
  → Return CommandResult.Ok / CommandResult.Fail
```

This is **not** "execute then save".  It is deterministic validation under locks with a
single atomic durability point.

---

## Action Command Primitives (DSL v1.1)

The v1.1 DSL defines exactly seven executable command primitives.  All others are rejected.

| Primitive               | Mutates state? | Description |
|-------------------------|---------------|-------------|
| `AssertIf`              | **No**        | Evaluates a boolean condition; records an `AssertionResult` (Error/Warning/Info). Never changes field values. |
| `SetIf`                 | Yes           | If condition is true, assigns a literal or expression result to a named field. |
| `CalculateAndSetIf`     | Yes           | Identical semantics to `SetIf` but marks the delta as derived-field intent (tooling/audit marker). |
| `ForSet`                | Yes           | Iterates a list field; applies sub-commands to each matching item using **snapshot semantics** — mutations are not visible to subsequent iterations. |
| `ForSetSequential`      | Yes           | Like `ForSet` but uses **progressive semantics** — each mutation is applied to the working copy immediately and is visible to subsequent iterations. Required for allocation scenarios where order matters. |
| `InvokeIf`              | Yes (indirect)| If condition is true, expands a named action on a target entity and merges its deltas into the enclosing `TransactionEnvelope`. Flat only — see §Invocation Order. |
| `Get`                   | **No**        | Read-only context lookup; result is available to subsequent expressions but produces no delta. |

Commands are evaluated in ascending `Order` value.  Order within the persisted
`ActionCommandDefinition` records is the sole sequencing contract.

### ForSet Modes

| Mode               | Visibility of loop mutations to next iteration |
|--------------------|-----------------------------------------------|
| Snapshot (`ForSet`)          | Not visible — each item sees the original list state |
| Sequential (`ForSetSequential`) | Visible — each item sees mutations from previous iterations |

---

## Invariant Execution Semantics

Invariants are expressed exclusively as `AssertIfCommand` primitives.

```
AssertIf(condition: <BoolExpr>, code: <string>, severity: Error|Warning|Info, message: <string>)
```

**Evaluation contract:**

- `AssertIf` is **not a mutation**.  It never changes field values.  It is evaluated during
  action expansion and produces an `AssertionResult` in the envelope.
- The `code` field is an **immutable business rule identifier** (e.g. `"NEG_BALANCE"`).
  Codes must not be reused across semantically different rules.
- **Error** severity with `Fired=true`: the entire envelope is aborted before any locks are
  acquired.  No partial mutations are committed.
- **Warning** severity with `Fired=true`: recorded in the envelope, visible in the response,
  but does not abort the commit.  Used for non-fatal telemetry.
- **Info** severity: always recorded; never aborts.
- Invariant evaluation occurs **twice** in the commit pipeline:
  1. Before lock acquisition (fast-path rejection).
  2. Under locks after re-loading canonical state (authoritative cross-aggregate check).

---

## Invariant vs. Transition Logic Distinction

The DSL enforces a strict separation:

| Phase                   | Primitives                          | Effect on state |
|-------------------------|-------------------------------------|-----------------|
| Precondition (Assert)   | `AssertIf`                          | None — read-only |
| Mutation (Set)          | `SetIf`, `CalculateAndSetIf`        | Field deltas |
| Collection mutation     | `ForSet`, `ForSetSequential`        | Field deltas over list items |
| Cross-aggregate invoke  | `InvokeIf`                          | Merges another action's deltas |
| Post-state validation   | `AssertIf` (placed after mutations) | None — read-only |

**Assert is not a mutation.**  An `AssertIf` that evaluates to `true` records a result
and (for `Error` severity) aborts — it does not set or clear any field.

---

## Concurrency Model

BareMetalWeb's concurrency model is **invariant-driven pessimistic locking**.

It is deliberately **not**:

- MVCC (multi-version concurrency control)
- Optimistic locking via version-number equality checks
- Stored locks in the database

The model relies on:

1. In-memory pessimistic aggregate locks (`AggregateLockManager`) with deadlock-free sorted
   acquisition (§Aggregate Locking).
2. Invariant validation at commit time under those locks — this is the correctness gate.
3. WAL atomic append as the durability guarantee — not transactional row isolation.

Locks are scoped to the **commit phase only** and are always ephemeral.

---

## Client Trust Boundary

The client is **untrusted**.

```
Client sends:  { entitySlug, actionName, aggregateId }
                                    ↓
Server performs:
  - Load canonical state from authoritative store
  - Re-expand action server-side (ActionExpander.Expand)
  - Generate authoritative TransactionEnvelope
  - Client's proposed delta (if any) is ignored
                                    ↓
Commit input:  server-generated TransactionEnvelope only
```

The client may provide parameter hints (e.g. field values for context), but these are
used only as inputs to the server-side expansion context.  The resulting delta is
computed entirely by the server.

This is a critical security and engineering boundary — it prevents a compromised client
from bypassing invariant checks or injecting arbitrary field changes.

---

## Deterministic Invocation Order (Flat Only)

The DSL explicitly rejects:

- Nested `InvokeIf` chains (depth > 1)
- Recursive action graphs
- DSL loops beyond the controlled `ForSet`/`ForSetSequential` primitives

**Rule:** `InvokeIf` may expand a target action exactly one level deep.  The target action
may not itself contain `InvokeIf`.  `ActionExpander` enforces this with a `depth` guard:
any attempt to expand at depth > 0 throws `InvalidOperationException`.

This constraint:

- Keeps static analysis of the action graph feasible
- Guarantees replay safety (no unbounded expansion chains)
- Prevents accidental exponential lock acquisition

---

## Atomic Transaction Envelope

```
TransactionEnvelope {
    TransactionId:       string           // unique per expansion
    AggregateMutations:  AggregateMutation[]  // all touched aggregates
    Assertions:          AssertionResult[] // all invariant results
}

AggregateMutation {
    AggregateType:  string          // entity slug
    AggregateId:    string          // instance identity
    Changes:        FieldValueChange[]
}
```

The `TransactionEnvelope` is the **single atomic commit unit**.

- All `AggregateMutation` entries in an envelope commit together or not at all.
- No individual aggregate row is committed independently of the envelope.
- The envelope is declared completely before lock acquisition — there is no dynamic
  aggregate discovery during the commit phase.

---

## Crash + Recovery Model

### WAL Atomic Append

Each commit writes one **commit-batch record** to the active WAL segment.  The record format
includes:

- `RecordMagic` sentinel at the record start
- Commit-batch header: `TxId(8) + OpCount(4) + PayloadFlags(4)`
- Per-op headers: `Key(8) + PrevPtr(8) + SchemaSignature(8) + OpType(2) + Codec(2) +
  UncompressedLen(4) + CompressedLen(4) + Flags(4) + Reserved(4)` (44 bytes each)
- Record trailer: `TrailerMagic(4) + TotalRecordBytes(4) + CRC32C(4) + Reserved(4)`

The **CRC32C checksum** covers the entire record (both CRC fields are zeroed for computation,
then patched in place).  A record is only considered committed once the checksum is flushed
to disk.

### Recovery Procedure

On startup, `WalSegmentReader` applies the following strategy:

1. **Footer path (normal):** Read the segment footer index.  Verify the footer CRC32C.
   If valid, use the index to seek directly to the latest op per key.
2. **Linear scan (crash path):** If no valid footer exists, scan records from the beginning
   of the segment, stopping at the first corrupt or truncated record (`RecordMagic` mismatch,
   short read, or record-length overrun vs. file size).
3. **Incomplete record truncation:** Any record that was partially written at the time of
   crash is silently discarded.  The WAL tail is logically truncated at the last fully
   committed record.  No partial mutations are ever applied.

### Lock Behaviour Across Crashes

**Aggregate locks do not survive a crash or process restart.**  `AggregateLockManager` is
entirely in-memory.  After a restart, all locks are implicitly released and the commit
pipeline resumes from a clean lock state.  WAL replay is purely data replay — no behavioral
re-execution and no lock reconstruction.

---

## Architectural Guardrails (Ongoing)

These constraints must remain true across all future implementation work:

- Canonical envelope ordering rules (stable field/aggregate ordering for deterministic hashing/auditing)
- WAL record contract (schema, assertions, touched aggregate keys, checksum) — no schema changes without migration
- Replay contract: data replay only, never behavior replay
- Snapshot/compaction policy and recovery bounds (RPO/RTO expectations)
- Invariant catalog boundaries (which rules are precondition vs. commit-time invariant)
- Side-effect boundary (outbox/dispatch policy so external effects are not inside the transaction expansion)
- Projection/versioning policy (UI/API payloads as projections over kernel state)
- DSL flatness: `InvokeIf` depth must remain bounded at 1

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
