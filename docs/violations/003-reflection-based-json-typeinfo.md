# [VIOLATION] Reflection-based JSON type resolution via DefaultJsonTypeInfoResolver

**Severity:** 🟠 High  
**File:** `BareMetalWeb.Data/JsonTypeInfoRegistry.cs`  
**Lines:** 1–27  
**Labels:** `violation`, `reflection`, `aot-unsafe`, `serialization`

## Description

`JsonTypeInfoRegistry` is a singleton that resolves `JsonTypeInfo` instances using the
reflection-based `DefaultJsonTypeInfoResolver`:

```csharp
// BareMetalWeb.Data/JsonTypeInfoRegistry.cs
private static readonly JsonSerializerOptions ReflectionOptions = new()
{
    TypeInfoResolver = new DefaultJsonTypeInfoResolver()   // ← reflection-based
};

public static JsonTypeInfo<T> GetTypeInfo<T>() where T : BaseDataObject
{
    var info = TypeInfoByType.GetOrAdd(typeof(T), static type => ReflectionOptions.GetTypeInfo(type));
    return (JsonTypeInfo<T>)info;
}
```

`DefaultJsonTypeInfoResolver` uses runtime reflection to discover properties, constructors, and
attributes for JSON serialization. This is the default fallback resolver when no source-generated
context is provided.

## Why This Violates the Guidelines

1. **AOT / trim safety** — `DefaultJsonTypeInfoResolver` uses reflection and is explicitly excluded
   from NativeAOT scenarios. Microsoft's guidance for AOT/trimmed apps is to use
   `[JsonSerializable]`-attributed source-generated contexts instead.
2. **"Avoid reflection"** — reflection-based JSON type resolution is slower than source-generated
   type info, especially on first access. Source generators produce the type info at compile time.
3. **GC pressure** — `DefaultJsonTypeInfoResolver` dynamically allocates property converters,
   constructor delegates, and metadata objects on each new type encountered.

## Proposed Fix

Replace `JsonTypeInfoRegistry` with a source-generated `JsonSerializerContext` annotated with
`[JsonSerializable]` for all known `BaseDataObject` subtypes:

```csharp
// BareMetalWeb.Data/BareMetalWebJsonContext.cs
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(Customer))]
[JsonSerializable(typeof(Order))]
[JsonSerializable(typeof(Address))]
// ... all registered entity types
internal partial class BareMetalWebJsonContext : JsonSerializerContext { }
```

Consumers currently calling `JsonTypeInfoRegistry.GetTypeInfo<T>()` would call
`BareMetalWebJsonContext.Default.GetTypeInfo<T>()` instead.

For dynamic/gallery-defined types (where the CLR type is not known at compile time), serialize as
`DataRecord` / `Dictionary<string, object?>` using a registered context for those types.

## Affected Code Paths

- `JsonTypeInfoRegistry.GetTypeInfo<T>()` — called from serialization paths in `LocalFolderBinaryDataProvider`, `WalDataProvider`, etc.
- `JsonTypeInfoRegistry.GetTypeInfo(Type type)` — called from polymorphic serialization paths
