# NativeAOT + Trimming Constraints

> **This codebase targets NativeAOT + trimming. Any use of the banned patterns listed below is a BUG.**

## Banned APIs and Patterns

Any usage of the following in production code is a violation. Test code is exempt.

| # | Banned API / Pattern | Category | Why It Breaks |
|---|---|---|---|
| 1 | `System.Reflection` (any usage beyond one-time startup caching) | Reflection | Types/members stripped by trimmer; runtime failures in AOT |
| 2 | `Activator.CreateInstance` | Reflection | Runtime type construction; trimmer cannot see the dependency |
| 3 | `Type.MakeGenericType` | Reflection | Runtime generic instantiation; not AOT-safe |
| 4 | `MethodInfo.MakeGenericMethod` | Reflection | Runtime generic instantiation; not AOT-safe |
| 5 | `dynamic` / DLR | Code generation | Requires `System.Linq.Expressions` and runtime IL emit |
| 6 | `System.Text.Json.JsonSerializer` (all overloads) | Serialization | Reflection-based by default; source-gen context not used here |
| 7 | `System.Reflection.Emit` (`AssemblyBuilder`, `TypeBuilder`, etc.) | Code generation | Not available in NativeAOT; generates types at runtime |
| 8 | `AppDomain.CurrentDomain.GetAssemblies()` | Assembly scanning | Not trim-safe; scanned types may be stripped |
| 9 | `Type.GetType(string)` with dynamic names | Reflection | Trimmer cannot preserve types referenced only by string |
| 10 | Runtime type discovery or construction (any pattern) | Architecture | Use `DataRecord` and metadata services instead |

## Allowed Patterns

| Pattern | When to Use |
|---|---|
| Closed generics known at compile time | `List<Customer>`, `Dictionary<string, int>` — types resolved at compile time |
| Static generic methods where `T` is known at call site | `Serialize<Customer>(obj)` — compiler resolves `T` |
| `Span<T>`, `Memory<T>`, blittable structs | Data processing without heap allocation |
| `switch` / dictionary dispatch | Type discrimination without reflection |
| Pre-compiled delegates cached at startup | One-time reflection to build `Func<>` delegates, then cached forever |
| `[DynamicallyAccessedMembers]` annotations | When startup reflection is unavoidable, annotate to guide the trimmer |

## Design Principle

**All behaviour must be resolvable at compile time.**

Metadata may describe behaviour (entity shapes, field definitions, validation rules, UI rendering),
but metadata must **never** construct types dynamically. The metadata system uses ordinal-based
lookups in memory — not reflection, not `Dictionary<string, ...>` — for field access at runtime.

## Approved Alternatives

| Instead of… | Use… |
|---|---|
| `System.Text.Json.JsonSerializer` | `BmwJsonSerializer` (manual `Utf8JsonWriter`, metadata-driven) |
| `BinaryFormatter` / `JsonSerializer` for persistence | `BinaryObjectSerializer` (custom binary, pre-registered known types) |
| Reflection-based property access | `DataRecord` + `DataEntityMetadata` (ordinal-based, pre-compiled delegates) |
| `Activator.CreateInstance(type)` | Pre-registered factory delegates in `DataEntityRegistry` / `DataScaffold` |
| `Type.GetProperties()` at request time | `EntityLayout` / `DataFieldMetadata` with pre-compiled getter/setter delegates |
| `Reflection.Emit` for dynamic enums | `RuntimeEnumDefinition` with `string[] Labels` (ordinal = index) |

## Fail Fast Rule

If a requested design **cannot** be implemented without violating these constraints,
say so explicitly instead of working around them. Do not silently introduce reflection
or dynamic code generation.

## Enforcement

- The `docs/violations/` directory tracks all known violations
- Each violation has a corresponding GitHub Issue labelled `violation`
- New code that introduces any banned pattern should be rejected in code review
- Violations are classified by severity:
  - 🔴 **Critical** — blocks NativeAOT deployment, must be fixed before release
  - 🟠 **High** — on request-handling hot path, causes runtime failures or GC pressure
  - 🟡 **Medium** — startup-only but should be migrated to metadata-driven patterns
  - 🟢 **Low** — cosmetic or minimal impact, fix when convenient

## Current Violation Status

See [`docs/violations/README.md`](./violations/README.md) for the full tracker.

---

_Last updated: 2026-03-20_
