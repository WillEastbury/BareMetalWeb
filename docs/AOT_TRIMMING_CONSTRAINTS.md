# NativeAOT + Trimming Constraints

> **This codebase targets NativeAOT + trimming. Any use of the banned patterns listed below is a BUG.**

## Banned APIs and Patterns

Any usage of the following in production code is a violation. Test code is exempt.

| # | Banned API / Pattern | Category | Why It Breaks |
|---|---|---|---|
| 1 | `System.Reflection` (any usage AT ALL, USE THE METADATA SYSTEM INSTEAD) | Reflection | Types/members stripped by trimmer; runtime failures in AOT |
| 2 | `Activator.CreateInstance` | Reflection | Runtime type construction; trimmer cannot see the dependency |
| 3 | `Type.MakeGenericType` | Reflection | Runtime generic instantiation; not AOT-safe |
| 4 | `MethodInfo.MakeGenericMethod` | Reflection | Runtime generic instantiation; not AOT-safe |
| 5 | `dynamic` / DLR | Code generation | Requires `System.Linq.Expressions` and runtime IL emit |
| 6 | `System.Text.Json.JsonSerializer` (all overloads) | Serialization | Reflection-based by default; source-gen context not used here, Use our custom streaming metadata based serializers (BinaryObjectSerializer, BmwJsonSerializer only|
| 7 | `System.Reflection.Emit` (`AssemblyBuilder`, `TypeBuilder`, etc.) | Code generation | Not available in NativeAOT; generates types at runtime |
| 8 | `AppDomain.CurrentDomain.GetAssemblies()` | Assembly scanning | Not trim-safe; scanned types may be stripped |
| 9 | `Type.GetType(string)` with dynamic names | Reflection | Trimmer cannot preserve types referenced only by string |
| 10 | Runtime type discovery or construction (any pattern) | Architecture | Use `DataRecord` and metadata services instead |
| 11 | Static generic methods followed by typeof(T) | Generics | Antipattern where reflection and dynamic typing hides - use metadata instead and / or use a switch with hardcoded, predictable known types of T |
| 12 | `Span<T>`, `Memory<T>`, blittable structs | Generics | Data processing without heap allocation is good, but use a known type so AOT is happy and we can trim heavily to reduce memory usage and compiler bloat |
| 13 | Pre-compiled delegates cached at startup | Reflection | Dont do this, it's just redirection - and we want the trimmer to eliminate System.Reflection if possible |
| `[DynamicallyAccessedMembers]` annotations | Reflection | Dont do this - same as above, the whole point of this platform is to use a dispatch jump table for metadata access over linear scan / ordinal based lookup for speed. 

## Allowed Patterns that are OK

| Pattern | When to Use |
| Closed generics known at compile time | `List<Customer>`, `Dictionary<string, int>` — types resolved at compile time |
| `switch` / dictionary dispatch | Type discrimination without reflection |
| Ordinal based lookup through arrays | The metadata system / allows usage and serialization of compact primitive object types that act like structs but are transferrable across systems and are guaranteed to serialize in the same order and will be lightning fast and compact on the wire / in memory. 
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
