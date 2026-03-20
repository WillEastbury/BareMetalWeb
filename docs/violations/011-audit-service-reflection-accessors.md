# [VIOLATION] AuditService uses GetProperties reflection in accessor cache

**Severity:** 🟡 Medium  
**File:** `BareMetalWeb.Data/AuditService.cs`  
**Lines:** 24–35  
**Labels:** `violation`, `reflection`, `aot-unsafe`

## Description

`AuditService.GetCachedAccessors()` uses `Type.GetProperties()` to enumerate all public instance
properties, then builds getter delegates via `PropertyAccessorFactory.BuildGetter()`:

```csharp
// BareMetalWeb.Data/AuditService.cs:24-35
private static (string Name, Func<object, object?> Getter)[] GetCachedAccessors(Type type)
{
    return _accessorCache.GetOrAdd(type, static t =>
    {
        var props = t.GetProperties(BindingFlags.Public | BindingFlags.Instance);
        var list = new List<(string, Func<object, object?>)>(props.Length);
        foreach (var p in props)
        {
            if (!p.CanRead || !p.CanWrite) continue;
            list.Add((p.Name, PropertyAccessorFactory.BuildGetter(p)));
        }
        return list.ToArray();
    });
}
```

## Why This Violates the Guidelines

1. **Reflection** — `GetProperties()` is a reflection call. While results are cached per type,
   the initial call is still reflection.
2. **Metadata-driven** — Entity types are registered in `DataScaffold` with pre-compiled field
   metadata including getter/setter delegates. `AuditService` should use the existing metadata
   rather than re-discovering properties via reflection.

## Proposed Fix

Replace `GetProperties()` + `PropertyAccessorFactory.BuildGetter()` with a lookup into
`DataScaffold` metadata. The `DataFieldMetadata.GetValueFn` delegate is already compiled
at registration time for each field.

## Affected Code Paths

- `AuditService.GetCachedAccessors()` — called on first audit operation per entity type
- `AuditService.BuildAuditDelta()` — uses the cached accessors to diff old vs new entity state
