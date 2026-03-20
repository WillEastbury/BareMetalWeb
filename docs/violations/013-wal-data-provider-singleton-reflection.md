# [VIOLATION] WalDataProvider uses GetProperties + GetCustomAttribute for singleton flags

**Severity:** 🟡 Medium  
**File:** `BareMetalWeb.Data/WalDataProvider.cs`  
**Lines:** 2079–2093  
**Labels:** `violation`, `reflection`, `aot-unsafe`

## Description

`WalDataProvider` has a fallback path that uses `Type.GetProperties()` and
`PropertyInfo.GetCustomAttribute<SingletonFlagAttribute>()` to discover singleton flag
properties on entity types:

```csharp
// BareMetalWeb.Data/WalDataProvider.cs:2079-2093
// Fallback for entities not registered with DataScaffold: use live reflection on the CLR type.
var props = type.GetProperties(BindingFlags.Public | BindingFlags.Instance);
var singletonProps = new List<PropertyInfo>();
foreach (var p in props)
{
    if (p.PropertyType == typeof(bool)
        && p.GetCustomAttribute<SingletonFlagAttribute>() != null
        && p.CanRead && p.CanWrite
        && true.Equals(p.GetValue(obj)))
    {
        singletonProps.Add(p);
    }
}
```

## Why This Violates the Guidelines

1. **Reflection** — Uses `GetProperties()`, `GetCustomAttribute<T>()`, and `PropertyInfo.GetValue()`
   — a three-level reflection chain.
2. **Metadata-driven** — The comment explicitly acknowledges this is a "fallback for entities not
   registered with DataScaffold". All entities should be registered at startup; the reflection
   fallback should not exist.
3. **AOT / trim safety** — Custom attributes and property metadata may be stripped by the trimmer.

## Proposed Fix

Remove the reflection fallback. Singleton flag metadata should be part of `DataEntityMetadata`
(set during entity registration). If an entity is not registered, throw a descriptive error
instead of silently falling back to reflection.

## Affected Code Paths

- `WalDataProvider.ClearSingletonFlagsOnOtherRecords()` — called during save operations
  for entities with singleton flag properties

## Resolution

**Status:** ✅ RESOLVED

The entire reflection fallback block (lines 2081–2111) has been removed from `ClearSingletonFlagsOnOtherRecords<T>()`. The method now returns early when `DataScaffold.GetEntityByType()` returns null. All entity types used with singleton flags must now be registered in DataScaffold, which enforces the metadata-driven architecture.
