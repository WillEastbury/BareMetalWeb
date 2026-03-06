# [VIOLATION] Assembly scanning via AppDomain.GetAssemblies() in deserialization path

**Severity:** 🔴 Critical  
**File:** `BareMetalWeb.Data/BinaryObjectSerializer.cs`  
**Lines:** 1275–1295  
**Labels:** `violation`, `reflection`, `aot-unsafe`, `performance`

## Description

`BinaryObjectSerializer.ResolveType()` iterates over all loaded CLR assemblies at deserialization time
to find a type by its assembly-qualified name string:

```csharp
// BareMetalWeb.Data/BinaryObjectSerializer.cs:1275-1295
[RequiresUnreferencedCode("Assembly scanning for type resolution is not AOT-safe.")]
private static Type ResolveType(string typeName)
{
    var resolved = Type.GetType(typeName, throwOnError: false, ignoreCase: false);
    if (resolved != null) return resolved;

    resolved = typeof(BinaryObjectSerializer).Assembly.GetType(typeName, ...);
    if (resolved != null) return resolved;

    foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())  // ← scans ALL assemblies
    {
        resolved = assembly.GetType(typeName, throwOnError: false, ignoreCase: false);
        if (resolved != null) return resolved;
    }
    throw new InvalidOperationException($"Unable to resolve type '{typeName}'.");
}
```

The method is annotated `[RequiresUnreferencedCode]`, which is an explicit acknowledgement that it is
not AOT-safe and that linked types may be stripped.

## Why This Violates the Guidelines

1. **AOT / trim safety** — `AppDomain.CurrentDomain.GetAssemblies()` is not trim-safe. Types referenced
   only by string name will be stripped by the linker, causing silent runtime failures in published builds.
2. **Performance** — scanning all loaded assemblies is O(N·M) where N = assemblies, M = types per assembly.
   In a large deployment this can involve hundreds of assemblies and thousands of types per call.
3. **"Avoid reflection"** — the guideline requires metadata-based, ordinal-indexed type resolution.
   A pre-registered explicit type map achieves the same result with O(1) lookup and full AOT safety.

## Proposed Fix

Replace the assembly-scan fallback with a pre-registered type map. Any type that can appear in a
serialized binary object must be registered at startup:

```csharp
// Startup registration (once per type, AOT-safe):
BinaryObjectSerializer.RegisterKnownType<Customer>();
BinaryObjectSerializer.RegisterKnownType<Order>();
// ...

// Lookup at deserialization time (O(1), no reflection):
private static readonly Dictionary<string, Type> KnownTypes = new(StringComparer.Ordinal);

public static void RegisterKnownType<T>()
    => KnownTypes[typeof(T).AssemblyQualifiedName ?? typeof(T).FullName!] = typeof(T);

private static Type ResolveType(string typeName)
{
    if (KnownTypes.TryGetValue(typeName, out var t)) return t;
    throw new InvalidOperationException($"Unknown type '{typeName}'. Register it at startup.");
}
```

## Affected Code Paths

- `BinaryObjectSerializer.ResolveType` (lines 1275–1295) — called during deserialization
- Any code path that deserializes binary objects containing polymorphic type fields
