# Codebase Guideline Violations

This directory documents violations of the BareMetalWeb NativeAOT + trimming constraints found
during codebase scans. Each file corresponds to a tracked violation. Violations are grouped by severity.

> **See also:** [`docs/AOT_TRIMMING_CONSTRAINTS.md`](../AOT_TRIMMING_CONSTRAINTS.md) for the full
> constraints reference document.

## Banned APIs (any usage is a BUG)

| Banned API / Pattern | Why |
|---|---|
| `System.Reflection` (any usage beyond startup metadata caching) | Stripped by trimmer; not AOT-safe |
| `Activator.CreateInstance` | Runtime type construction; not AOT-safe |
| `Type.MakeGenericType` / `MethodInfo.MakeGenericMethod` | Runtime generic construction; not AOT-safe |
| `dynamic` / DLR | Requires runtime code generation |
| `System.Text.Json.JsonSerializer` (generic or non-generic) | Use `BmwJsonSerializer` or `BinaryObjectSerializer` instead |
| `System.Reflection.Emit` | Runtime IL generation; not available in NativeAOT |
| Runtime type discovery or construction | Use `DataRecord` and the metadata services instead |

## Guideline Summary

- **No reflection** — use metadata-based ordinal lookups in memory for high speed
- **No allocations in hot paths** — avoid GC pressure; use `Span<T>`, `Memory<T>`, structs
- **AOT/trim safety** — no assembly scanning, no `Activator.CreateInstance` on unknown types, no `Reflection.Emit`
- **Metadata-driven** — entity shapes, fields, validation driven by metadata, NOT by C# reflection on CLR types at runtime
- **UI FK resolution** — cross-entity reference fields MUST always show resolved display values, never raw IDs
- **Sub-entity constraints** — sub-grids must honour all field constraints, validation, and lookup resolution

---

## All Violations

| ID | Severity | Status | File | Title |
|----|----------|--------|------|-------|
| 1 | 🔴 Critical | **Open** | `BareMetalWeb.Runtime/RuntimeEntityCompiler.cs` | [Reflection.Emit used to generate dynamic CLR enum types at runtime](./001-reflection-emit-dynamic-enum.md) |
| 2 | 🔴 Critical | ✅ **RESOLVED** | `BareMetalWeb.Data/BinaryObjectSerializer.cs` | [Assembly scanning → KnownTypes map](./002-assembly-scanning-type-resolution.md) |
| 3 | 🟠 High | ✅ **RESOLVED** | ~~`BareMetalWeb.Data/JsonTypeInfoRegistry.cs`~~ *(deleted)* | [JsonTypeInfoRegistry deleted; Utf8JsonWriter everywhere](./003-reflection-based-json-typeinfo.md) |
| 4 | 🟠 High | **Open** | `BareMetalWeb.Data/DataScaffold.cs` | [GetChildFieldMetadata uses runtime reflection (GetProperties, GetCustomAttribute) in request path](./004-child-field-metadata-reflection.md) |
| 5 | 🟠 High | **Open** | `BareMetalWeb.Data/DataScaffold.cs` | [TryConvertJsonChildList / TryParseChildList use Activator.CreateInstance and PropertyInfo.SetValue](./005-child-list-json-reflection.md) |
| 6 | 🟡 Medium | **Open** | `BareMetalWeb.Data/ReportExecutor.cs` | [FindAccessorOnObject uses reflection per row cell in report projection](./006-report-executor-reflection-per-row.md) |
| 7 | 🟡 Medium | ✅ **RESOLVED** | ~~`BareMetalWeb.Data/DataScaffold.cs`~~ *(PropertyCache removed)* | [PropertyCache removed; uses compiled delegates](./007-propertycache-reflection-backed.md) |
| 8 | 🟡 Medium | ✅ **RESOLVED** | `BareMetalWeb.Data/BinaryObjectSerializer.cs` | [All accessors use compiled Expression.Lambda delegates](./008-binary-serializer-reflection-accessors.md) |
| 9 | 🟢 Low | ✅ **RESOLVED** | `BareMetalWeb.Host/McpRouteHandler.cs` | [Assembly.GetName().Version replaces GetCustomAttributes](./009-mcp-handler-assembly-version-reflection.md) |
| 10 | 🟡 Medium | ✅ **RESOLVED** | `BareMetalWeb.Runtime/SamplePackageJson.cs` | [Reflection fallback replaced with auto-registration via DataScaffold](./010-sample-package-json-reflection-fallback.md) |
| 11 | 🟡 Medium | ✅ **RESOLVED** | `BareMetalWeb.Data/AuditService.cs` | [Reflection fallback removed; metadata-only change detection](./011-audit-service-reflection-accessors.md) |
| 12 | 🟡 Medium | ✅ **RESOLVED** | `BareMetalWeb.Data/EntityLayoutCompiler.cs` | [Uses meta.AllProperties (cached, DynamicallyAccessedMembers-annotated)](./012-entity-layout-compiler-reflection.md) |
| 13 | 🟡 Medium | ✅ **RESOLVED** | `BareMetalWeb.Data/WalDataProvider.cs` | [Reflection fallback removed; metadata-only singleton flag enforcement](./013-wal-data-provider-singleton-reflection.md) |
| 14 | 🟡 Medium | 🟧 **MITIGATED** | `BareMetalWeb.Data/ValidationService.cs` | [DynamicallyAccessedMembers annotation added; startup-only attribute scan](./014-validation-service-attribute-scanning.md) |
| 15 | 🟡 Medium | 🟧 **MITIGATED** | `BareMetalWeb.Runtime/MetadataExtractor.cs` | [DynamicallyAccessedMembers added; EnumValues preferred over Enum.GetNames](./015-metadata-extractor-reflection-chain.md) |
| 16 | 🟢 Low | ✅ **RESOLVED** | `BareMetalWeb.Host/BareMetalWebServer.cs` + others | [Assembly reflection replaced with MSBuild-generated BuildVersion constant](./016-assembly-version-reflection.md) |
| 17 | 🟡 Medium | 🟧 **MITIGATED** | `BareMetalWeb.Data/DataScaffold.cs` | [Startup-only; DynamicallyAccessedMembers + Delegate.CreateDelegate](./017-data-scaffold-remote-command-discovery.md) |
| 18 | 🟡 Medium | ✅ **RESOLVED** | `BareMetalWeb.Data/MetadataWireSerializer.cs` + others | [RuntimeHelpers.GetUninitializedObject replaced with factory/Activator patterns](./018-runtime-helpers-uninitialized-object.md) |

### Summary

- **Total violations tracked:** 18
- **Resolved:** 11 (IDs 2, 3, 7, 8, 9, 10, 11, 12, 13, 16, 18)
- **Mitigated:** 3 (IDs 14, 15, 17 — startup-only, annotated with `[DynamicallyAccessedMembers]`)
- **Open — Critical:** 1 (ID 1)
- **Open — High:** 2 (IDs 4, 5)
- **Open — Medium:** 1 (ID 6)
- **Open — Low:** 0

---

_Last updated: 2026-03-20_
