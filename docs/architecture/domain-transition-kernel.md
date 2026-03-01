# Deterministic Domain Transition Kernel

This document captures the core runtime target for BareMetalWeb's action/transaction model.

---

## Core Intent

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

## Missing Fundamentals Checklist

To keep the kernel direction concrete, these fundamentals should remain explicit in implementation reviews and roadmap work:

- Canonical envelope ordering rules (stable field/aggregate ordering for deterministic hashing/auditing)
- WAL record contract for transactions (schema, assertions, touched aggregate keys, checksum)
- Replay contract (data replay only, never behavior replay)
- Snapshot/compaction policy and recovery bounds (RPO/RTO expectations)
- Invariant catalog boundaries (which rules are precondition vs commit-time invariant)
- Side-effect boundary (outbox/dispatch policy so external effects are not in transaction expansion)
- Projection/versioning policy (UI/API payloads as projections over kernel state)

These are architectural guardrails; implementation details can evolve as long as these constraints remain true.
