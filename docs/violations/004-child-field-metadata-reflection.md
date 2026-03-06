# [VIOLATION] GetChildFieldMetadata uses runtime reflection in request-handling path

**Severity:** 🟠 High  
**File:** `BareMetalWeb.Data/DataScaffold.cs`  
**Lines:** 2561–2638 (key excerpts shown below)  
**Labels:** `violation`, `reflection`, `hot-path`, `metadata-driven`

## Description

`DataScaffold.GetChildFieldMetadata(Type childType)` is called from multiple request-handling paths
(form rendering, view rendering, export) and performs full runtime reflection on the child type:

```csharp
// BareMetalWeb.Data/DataScaffold.cs:2561-2638
private static IReadOnlyList<ChildFieldMeta> GetChildFieldMetadata(
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties)] Type childType)
{
    var fields = new List<ChildFieldMeta>();
    var properties = childType.GetProperties(BindingFlags.Public | BindingFlags.Instance); // reflection
    Array.Sort(properties, (a, b) => a.MetadataToken.CompareTo(b.MetadataToken));          // reflection

    foreach (var prop in properties)
    {
        var fieldAttribute = prop.GetCustomAttribute<DataFieldAttribute>();     // reflection
        var lookupAttribute = prop.GetCustomAttribute<DataLookupAttribute>();   // reflection
        var calculatedAttr = prop.GetCustomAttribute<CalculatedFieldAttribute>(); // reflection
        var copyFromParentAttr = prop.GetCustomAttribute<CopyFromParentAttribute>(); // reflection

        // ... builds ChildFieldMeta using compiled delegates from PropertyAccessorFactory
        fields.Add(new ChildFieldMeta(
            Getter: PropertyAccessorFactory.BuildGetter(prop),  // Expression.Lambda.Compile via reflection
            Setter: PropertyAccessorFactory.BuildSetter(prop),  // Expression.Lambda.Compile via reflection
            ...));
    }
    return fields;
}
```

This method is called from:
- `BuildChildListEditorHtml` → called from `BuildFormFields` → called on every form render (POST and GET)
- `BuildChildListViewHtml` → called from `BuildViewRowsHtml` → called on every detail view render
- `GetChildFieldMetadataSimple` → called from child list export (`BuildListPlainRows`)

## Why This Violates the Guidelines

1. **"Avoid reflection"** — `GetProperties`, `GetCustomAttribute`, `MetadataToken` all use the CLR
   reflection API. The guideline explicitly forbids reflection in hot paths.
2. **Metadata-driven architecture** — the platform already has a full metadata registry
   (`DataEntityMetadata`, `DataFieldMetadata`, `EntityLayout`, `FieldRuntime`) that contains all of
   this information pre-compiled at startup. Using CLR reflection to re-derive it on every request
   duplicates work the metadata system already did.
3. **Allocations** — `GetProperties` returns a new `PropertyInfo[]` allocation on every call.
   `GetCustomAttribute<T>` allocates attribute instances. These put pressure on the GC.
4. **AOT safety** — `[DynamicallyAccessedMembers]` annotation is required to prevent the linker from
   stripping these properties. This is only a workaround, not a solution.

## Proposed Fix

Cache the result of `GetChildFieldMetadata` per type at startup, or better, derive `ChildFieldMeta`
directly from the pre-compiled `EntityLayout` and `FieldRuntime` that the metadata system already
provides. The child type should be registered as an entity in `DataScaffold` and its `EntityLayout`
consulted at render time:

```csharp
// Instead of calling GetChildFieldMetadata(childType) on every request:
// 1. At startup: register child entity types (already done for top-level entities)
// 2. At render time: look up the already-compiled EntityLayout
if (DataScaffold.TryGetEntity(childEntitySlug, out var childMeta))
{
    // childMeta.Fields already has Name, Label, FieldType, Getter, Setter, LookupConfig
    // No reflection needed — metadata was compiled at registration time
}
```

At minimum, cache the `GetChildFieldMetadata` result in a `ConcurrentDictionary<Type, IReadOnlyList<ChildFieldMeta>>`
keyed by type so reflection only runs once per type per process lifetime, not per request.

## Affected Code Paths

- `DataScaffold.GetChildFieldMetadata(Type)` — reflection on every call
- `DataScaffold.BuildChildListEditorHtml` — calls above per form render
- `DataScaffold.BuildChildListViewHtml` — calls above per view render
- `DataScaffold.GetChildFieldMetadataSimple` — similar reflection for export path
