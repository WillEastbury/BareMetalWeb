# [VIOLATION] DataScaffold GetMethods for RemoteCommand discovery

**Severity:** 🟡 Medium  
**File:** `BareMetalWeb.Data/DataScaffold.cs`  
**Lines:** 2829–2838  
**Labels:** `violation`, `reflection`, `aot-unsafe`

## Description

`DataScaffold` uses `Type.GetMethods()` and `MethodInfo.GetCustomAttribute<RemoteCommandAttribute>()`
to discover remote command handler methods on entity types:

```csharp
// BareMetalWeb.Data/DataScaffold.cs:2829-2838
// Using Delegate.CreateDelegate at startup avoids per-request MethodInfo.Invoke overhead
// and is NativeAOT-safe because T is a concrete type with [DynamicallyAccessedMembers].
var commands = new List<RemoteCommandMetadata>();
var methods = type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly);
foreach (var method in methods)
{
    var cmdAttr = method.GetCustomAttribute<RemoteCommandAttribute>();
    if (cmdAttr == null) continue;
    // ...
}
```

## Why This Violates the Guidelines

1. **Reflection** — `GetMethods()` and `GetCustomAttribute<T>()` are reflection APIs that
   enumerate CLR type metadata.
2. **Startup-only** — This is called once per entity type during handler registration. The
   comment acknowledges that `Delegate.CreateDelegate` is used to avoid per-request reflection.
3. **Metadata-driven** — Remote commands could be defined in metadata rather than discovered
   via attribute scanning.

## Proposed Fix

Remote command definitions should be part of the entity metadata, either:
- Declared in the gallery JSON definition for gallery entities
- Registered explicitly at startup for compiled entity types

The current `[DynamicallyAccessedMembers]` annotation on `type` helps the trimmer preserve
the methods, but the reflection scan itself is the issue.

## Affected Code Paths

- `DataScaffold.RegisterRemoteCommands<T>()` — called once per entity type at startup
