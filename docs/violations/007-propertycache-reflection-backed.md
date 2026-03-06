# [VIOLATION] PropertyCache uses ConcurrentDictionary<(Type,string), PropertyInfo?> (reflection-backed)

**Severity:** 🟡 Medium  
**File:** `BareMetalWeb.Data/DataScaffold.cs`  
**Line:** 151  
**Labels:** `violation`, `reflection`, `metadata-driven`

## Description

`DataScaffold` maintains a static reflection-backed property cache:

```csharp
// BareMetalWeb.Data/DataScaffold.cs:151
private static readonly ConcurrentDictionary<(Type, string), PropertyInfo?> PropertyCache = new();
```

This dictionary caches `PropertyInfo` objects keyed by `(Type, fieldName)`. While caching prevents
repeated reflection lookups, the underlying access mechanism is still `PropertyInfo.GetValue` /
`PropertyInfo.SetValue` — i.e., reflection on every use.

## Why This Violates the Guidelines

1. **"Avoid reflection"** — even cached, `PropertyInfo.GetValue` / `SetValue` are reflection calls.
   The compiled delegate approach (`Func<object, object?>` / `Action<object, object?>`) is faster
   (~1–2 ns) and has no reflection overhead.
2. **Metadata-driven architecture** — the `DataEntityMetadata` / `DataFieldMetadata` system already
   has compiled `GetValueFn` / `SetValueFn` delegates for every registered entity field. There is no
   reason for `DataScaffold` to maintain a second, weaker property-lookup mechanism.
3. **Inconsistency** — the rest of the codebase uses `FieldRuntime.Getter`/`Setter` (compiled, ordinal
   indexed). `PropertyCache` is an inconsistent pattern that undermines the metadata-first model.

## Proposed Fix

Remove `PropertyCache` and replace all usages with direct field-metadata lookups:

```csharp
// Before (reflection):
var pi = PropertyCache.GetOrAdd((entity.GetType(), fieldName),
    _ => entity.GetType().GetProperty(fieldName, BindingFlags.Public | BindingFlags.Instance));
var val = pi?.GetValue(entity);

// After (metadata-driven, no reflection):
if (DataScaffold.TryGetEntity(entitySlug, out var meta))
{
    var field = meta.FindField(fieldName);
    var val = field?.GetValueFn?.Invoke(entity);
}
```

## Affected Code Paths

Search for usages of `PropertyCache` in `DataScaffold.cs` to enumerate all call sites.
