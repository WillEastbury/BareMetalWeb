# [VIOLATION] EntityLayoutCompiler uses GetProperties reflection

**Severity:** 🟡 Medium  
**File:** `BareMetalWeb.Data/EntityLayoutCompiler.cs`  
**Lines:** 51–58  
**Labels:** `violation`, `reflection`, `aot-unsafe`

## Description

`EntityLayoutCompiler` uses `Type.GetProperties()` to enumerate all public instance properties
when compiling entity layouts at startup:

```csharp
// BareMetalWeb.Data/EntityLayoutCompiler.cs:51-58
var allProps = meta.Type
    .GetProperties(BindingFlags.Public | BindingFlags.Instance);
var propList = new List<PropertyInfo>(allProps.Length);
foreach (var p in allProps)
{
    if (p.CanRead && p.CanWrite)
        propList.Add(p);
}
```

## Why This Violates the Guidelines

1. **Reflection** — `GetProperties()` is a reflection call that enumerates CLR type metadata.
2. **AOT / trim safety** — Property metadata may be stripped by the trimmer unless preserved
   via `[DynamicallyAccessedMembers]` annotations on the `meta.Type` parameter.
3. **Startup-only** — This is called once per entity type during `GetOrCompile()`, so it is
   not a hot-path issue, but it still represents a reflection dependency.

## Proposed Fix

The entity metadata (`DataEntityMetadata`) already carries field definitions. The layout
compiler should build layouts from the metadata field list rather than re-discovering
properties via reflection. If the metadata is complete, `GetProperties()` is unnecessary.

## Affected Code Paths

- `EntityLayoutCompiler.Compile()` — called once per entity type at startup
