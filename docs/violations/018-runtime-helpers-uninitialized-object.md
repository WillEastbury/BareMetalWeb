# [VIOLATION] MetadataWireSerializer and CalculatedFieldService use RuntimeHelpers.GetUninitializedObject

**Severity:** 🟡 Medium  
**Files:** `BareMetalWeb.Data/MetadataWireSerializer.cs`, `BareMetalWeb.Data/ExpressionEngine/CalculatedFieldService.cs`  
**Lines:** MetadataWireSerializer.cs:547–556, CalculatedFieldService.cs:383–387  
**Labels:** `violation`, `reflection`, `aot-unsafe`

## Description

Two files use `RuntimeHelpers.GetUninitializedObject()` to create entity instances or default
values without calling constructors:

```csharp
// BareMetalWeb.Data/MetadataWireSerializer.cs:550-556
private static object CreateEntityInstance(Type entityType)
{
    if (entityType == typeof(DataRecord))
        return new DataRecord();

    return System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(entityType);
}

// BareMetalWeb.Data/ExpressionEngine/CalculatedFieldService.cs:383-387
// Fallback for unknown value types — still needed for user-defined structs.
return RuntimeHelpers.GetUninitializedObject(targetType);
```

## Why This Violates the Guidelines

1. **Runtime type construction** — `GetUninitializedObject()` creates an instance of a type
   known only at runtime, bypassing constructors.
2. **AOT / trim safety** — The trimmer may strip the target type if it is not referenced
   elsewhere. The type is known only as a `Type` parameter at runtime.
3. **Metadata-driven** — Entity instance creation should use pre-registered factory delegates
   (e.g., `DataEntityMetadata.Handlers.Create()`) rather than `RuntimeHelpers`.

## Proposed Fix

Replace `GetUninitializedObject()` with pre-registered factory delegates:

- **MetadataWireSerializer**: Use `DataEntityRegistry.GetFactory(entityType)()` which returns
  a pre-compiled `Func<BaseDataObject>` registered at startup.
- **CalculatedFieldService**: For known value types (int, double, DateTime, etc.), return
  `default` directly via a type-switch. For unknown value types, throw an error.

## Affected Code Paths

- `MetadataWireSerializer.CreateEntityInstance()` — called during wire deserialization
- `CalculatedFieldService.GetDefaultValue()` — called during calculated field evaluation

## Resolution

**Status:** ✅ RESOLVED

All `RuntimeHelpers.GetUninitializedObject()` calls have been replaced:
- `MetadataWireSerializer.CreateEntityInstance()`: Uses `DataScaffold.GetEntityByType()` → `meta.Handlers.Create()` factory delegate
- `TransactionCommitEngine.CloneEntity()`: Uses `meta.Handlers.Create()` factory delegate
- `DataScaffold.IsDefaultValue()`: Extended known value types list + enum support; returns `false` for unknown types
- `DataScaffold.HasDefaultValue()`: Uses `Activator.CreateInstance()` with `[DynamicallyAccessedMembers(PublicParameterlessConstructor)]` annotation
- `BinaryObjectSerializer.CreateInstance()`: Extended known value types list; uses `Activator.CreateInstance()` with annotation
- `BinaryObjectSerializer.GetDefaultValue()`: Extended known value types list + enum support; returns `null` for unknown types
- `CalculatedFieldService.ConvertToPropertyType()`: Extended known value types list + enum support; returns `null` for unknown types
