# Codebase Guideline Violations

This directory documents violations of the BareMetalWeb design guidelines found during a codebase scan.
Each file corresponds to a GitHub Issue to be created. Violations are grouped by severity.

## Guideline Summary (from agent instructions)

- **No reflection** — use metadata-based ordinal lookups in memory for high speed
- **No allocations in hot paths** — avoid GC pressure; use `Span<T>`, `Memory<T>`, structs
- **AOT/trim safety** — no assembly scanning, no `Activator.CreateInstance` on unknown types, no `Reflection.Emit`
- **Metadata-driven** — entity shapes, fields, validation driven by metadata, NOT by C# reflection on CLR types at runtime
- **UI FK resolution** — cross-entity reference fields MUST always show resolved display values, never raw IDs
- **Sub-entity constraints** — sub-grids must honour all field constraints, validation, and lookup resolution

---

## Open Violations

| ID | Severity | Status | File | Title |
|----|----------|--------|------|-------|
| 1 | 🔴 Critical | **Open** | `BareMetalWeb.Runtime/RuntimeEntityCompiler.cs` | [Reflection.Emit used to generate dynamic CLR enum types at runtime](./001-reflection-emit-dynamic-enum.md) |
| 2 | 🔴 Critical | ✅ **RESOLVED** | `BareMetalWeb.Data/BinaryObjectSerializer.cs` | [Assembly scanning → KnownTypes map](./002-assembly-scanning-type-resolution.md) |
| 3 | 🟠 High | ✅ **RESOLVED** | ~~`BareMetalWeb.Data/JsonTypeInfoRegistry.cs`~~ *(deleted)* | [JsonTypeInfoRegistry deleted; Utf8JsonWriter everywhere](./003-reflection-based-json-typeinfo.md) |
| 4 | 🟠 High | **Open** | `BareMetalWeb.Data/DataScaffold.cs` | [GetChildFieldMetadata uses runtime reflection (GetProperties, GetCustomAttribute) in request path](./004-child-field-metadata-reflection.md) |
| 5 | 🟠 High | **Open** | `BareMetalWeb.Data/DataScaffold.cs` | [TryConvertJsonChildList / TryParseChildList use Activator.CreateInstance and PropertyInfo.SetValue](./005-child-list-json-reflection.md) |
| 6 | 🟡 Medium | **Open** | `BareMetalWeb.Data/ReportExecutor.cs` | [FindAccessorOnObject uses reflection per row cell in report projection](./006-report-executor-reflection-per-row.md) |
| 7 | 🟡 Medium | ✅ **RESOLVED** | ~~`BareMetalWeb.Data/DataScaffold.cs`~~ *(PropertyCache removed)* | [PropertyCache removed; uses compiled delegates](./007-propertycache-reflection-backed.md) |
| 8 | 🟡 Medium | ⚠️ **PARTIAL** | `BareMetalWeb.Data/BinaryObjectSerializer.cs` | [Property accessors fixed; field accessors pending](./008-binary-serializer-reflection-accessors.md) |
| 9 | 🟢 Low | ✅ **RESOLVED** | `BareMetalWeb.Host/McpRouteHandler.cs` | [Assembly.GetName().Version replaces GetCustomAttributes](./009-mcp-handler-assembly-version-reflection.md) |
