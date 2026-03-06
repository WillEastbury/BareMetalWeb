# [VIOLATION] TryConvertJsonChildList / TryParseChildList use Activator.CreateInstance and reflection

**Severity:** 🟠 High  
**File:** `BareMetalWeb.Data/DataScaffold.cs`  
**Lines:** 3006–3050 (`TryParseChildList`), 3587–3636 (`TryConvertJsonChildList`)  
**Labels:** `violation`, `reflection`, `aot-unsafe`, `hot-path`

## Description

Two methods in `DataScaffold` use runtime reflection to deserialize JSON arrays into typed
child-entity lists. Both are annotated with `[RequiresUnreferencedCode]`, indicating they
are known AOT-unsafe:

### `TryConvertJsonChildList` (lines 3587–3636)
```csharp
[RequiresUnreferencedCode("JSON child list deserialization requires compiled entity types.")]
private static bool TryConvertJsonChildList(JsonElement element, Type childType, out object? list)
{
    var listType = typeof(List<>).MakeGenericType(childType);             // reflection
    var typedList = (IList)Activator.CreateInstance(listType)!;           // reflection
    var props = new Dictionary<string, PropertyInfo>(StringComparer.OrdinalIgnoreCase);

    foreach (var p in childType.GetProperties(BindingFlags.Public | BindingFlags.Instance)) // reflection
    {
        if (p.CanRead && p.CanWrite) props[p.Name] = p;
    }

    foreach (var row in element.EnumerateArray())
    {
        var instance = Activator.CreateInstance(childType);              // reflection
        foreach (var prop in row.EnumerateObject())
        {
            if (!props.TryGetValue(prop.Name, out var pi)) continue;
            if (TryConvertJson(prop.Value, pi.PropertyType, out var val))
                pi.SetValue(instance, val);                              // reflection
        }
        typedList.Add(instance);
    }
    list = typedList;
    return true;
}
```

### `TryParseChildList` (lines 3006–3050)
Similar pattern: `[RequiresUnreferencedCode]`, `[DynamicallyAccessedMembers]`, `GetProperties`,
`Activator.CreateInstance`, `PropertyInfo.SetValue`.

## Why This Violates the Guidelines

1. **AOT / trim safety** — `[RequiresUnreferencedCode]` is explicit. These methods cannot run in a
   NativeAOT-compiled deployment. Types will be stripped and runtime errors will occur silently.
2. **"Avoid reflection"** — `GetProperties`, `Activator.CreateInstance`, `SetValue` are all
   reflection APIs. The guideline forbids these in request-handling paths.
3. **Allocations** — `GetProperties` returns a new `PropertyInfo[]`; `new Dictionary<string, PropertyInfo>`
   is allocated per call. These are O(fields) allocations per child-list POST body.
4. **Metadata-driven violation** — the child entity type is already registered in `DataScaffold`
   (or should be). Its `EntityLayout` and `FieldRuntime.Setter` delegates are pre-compiled with
   zero allocation at call time.

## Proposed Fix

Replace reflection-based deserialization with metadata-driven ordinal setter access:

```csharp
// AOT-safe, allocation-minimal approach using pre-compiled metadata:
private static bool TryConvertJsonChildList(JsonElement element, string childSlug, out object? list)
{
    if (!DataScaffold.TryGetEntity(childSlug, out var childMeta))
    {
        list = null;
        return false;
    }

    var rows = new List<BaseDataObject>();
    foreach (var row in element.EnumerateArray())
    {
        if (row.ValueKind != JsonValueKind.Object) continue;
        var instance = childMeta.Handlers.Create();
        foreach (var prop in row.EnumerateObject())
        {
            var field = childMeta.FindField(prop.Name);
            if (field?.SetValueFn == null) continue;
            if (TryConvertJson(prop.Value, field.Property.PropertyType, out var val))
                field.SetValueFn(instance, val);
        }
        rows.Add(instance);
    }
    list = rows;
    return true;
}
```

For CLR-typed child lists (non-gallery entities like `OrderRow`), the child type should also be
registered in `DataScaffold` at startup, after which the same metadata path works.

## Affected Code Paths

- `DataScaffold.TryConvertJsonChildList` (line 3587) — called from `TryConvertJson` during API POST
- `DataScaffold.TryParseChildList` (line 3007) — called from `ApplyFormValues` during form POST
- Both called on every form/API POST request that contains a child list field
