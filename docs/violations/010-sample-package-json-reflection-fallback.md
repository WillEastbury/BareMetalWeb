# [VIOLATION] SamplePackageJson uses GetProperties reflection fallback

**Severity:** 🟡 Medium  
**File:** `BareMetalWeb.Runtime/SamplePackageJson.cs`  
**Lines:** 80–87  
**Labels:** `violation`, `reflection`, `aot-unsafe`

## Description

`SamplePackageJson.DeserializeSample<T>()` has a fallback path that uses `typeof(T).GetProperties()`
when `DataScaffold` metadata is unavailable:

```csharp
// BareMetalWeb.Runtime/SamplePackageJson.cs:80-87
Dictionary<string, (System.Reflection.PropertyInfo Prop, Type ClrType)>? propCache = null;
if (meta == null)
{
    propCache = new(StringComparer.OrdinalIgnoreCase);
    foreach (var p in typeof(T).GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance))
        if (p.CanWrite) propCache[p.Name] = (p, p.PropertyType);
}
```

## Why This Violates the Guidelines

1. **Reflection** — `typeof(T).GetProperties()` is a reflection call that enumerates all public
   instance properties of the type at runtime.
2. **AOT / trim safety** — Property metadata may be trimmed in NativeAOT builds, causing the
   fallback path to silently return no properties.
3. **Metadata-driven** — The primary path already uses `DataScaffold` metadata. The fallback
   should not exist; all entity types should be registered with `DataScaffold` at startup.

## Proposed Fix

Remove the reflection fallback. Require that all entity types used with `SamplePackageJson`
are registered in `DataScaffold` before calling this method. If metadata is missing, throw
a descriptive error instead of silently falling back to reflection.

## Affected Code Paths

- `SamplePackageJson.DeserializeSample<T>()` — fallback path when metadata is not registered
