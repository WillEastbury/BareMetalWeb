# [VIOLATION] Reflection.Emit used to generate dynamic CLR enum types at runtime

**Severity:** 🔴 Critical  
**File:** `BareMetalWeb.Runtime/RuntimeEntityCompiler.cs`  
**Lines:** 287–309  
**Labels:** `violation`, `reflection`, `aot-unsafe`, `runtime`

## Description

`RuntimeEntityCompiler.CreateRuntimeEnum()` uses `System.Reflection.Emit` to dynamically construct
a new CLR `enum` type at runtime from a list of metadata-defined string values. This is invoked
whenever the compiler encounters an `Enum` field type in a gallery/metadata-defined entity.

```csharp
// BareMetalWeb.Runtime/RuntimeEntityCompiler.cs:287-309
private static Type CreateRuntimeEnum(IReadOnlyList<string> values)
{
    var enumTypeName = $"RuntimeEnum_{Guid.NewGuid():N}";
    var assemblyName = new System.Reflection.AssemblyName(enumTypeName);
    var assemblyBuilder = System.Reflection.Emit.AssemblyBuilder.DefineDynamicAssembly(
        assemblyName, System.Reflection.Emit.AssemblyBuilderAccess.Run);
    var moduleBuilder = assemblyBuilder.DefineDynamicModule("Module");
    var enumBuilder = moduleBuilder.DefineEnum(enumTypeName,
        System.Reflection.TypeAttributes.Public, typeof(int));
    // ...
}
```

## Why This Violates the Guidelines

1. **"Avoid reflection"** — the guideline explicitly bans reflection for runtime behaviour. `Reflection.Emit`
   is the most invasive form of reflection: it generates new CLR types at runtime.
2. **AOT / trim safety** — `System.Reflection.Emit` is not available in NativeAOT environments and may
   be stripped in aggressive trimming scenarios. This prevents deploying the app as a native AOT binary.
3. **Metadata-driven architecture** — the platform should store enum labels in metadata as a string array
   paired with their integer ordinals, NOT as a dynamically emitted CLR enum type. The CLR type is never
   truly needed; only the label map (int → string) is used for rendering.
4. **Memory / GC** — each dynamic assembly allocates permanent, unreclaimable memory in the CLR loader heap.
   If `CreateRuntimeEnum` is called repeatedly (e.g. during hot metadata reload), it leaks loader-heap memory.

## Proposed Fix

Replace the dynamic enum type with a first-class metadata concept: a `RuntimeEnumDefinition` that holds
a `string[] Labels` array (ordinal = index). Downstream consumers (renderers, validators) access label
by ordinal index rather than via `Enum.GetName()` reflection.

```csharp
// Instead of a CLR enum type, store:
internal sealed record RuntimeEnumDefinition(string[] Labels)
{
    public string GetLabel(int ordinal)
        => (uint)ordinal < (uint)Labels.Length ? Labels[ordinal] : ordinal.ToString();
    public int? TryParse(string label)
    {
        for (int i = 0; i < Labels.Length; i++)
            if (string.Equals(Labels[i], label, StringComparison.OrdinalIgnoreCase))
                return i;
        return null;
    }
}
```

`RuntimeEntityModel.Fields` would carry a `RuntimeEnumDefinition?` for enum fields instead of a CLR `Type`.
All places that currently call `CreateRuntimeEnum` would be updated to construct a `RuntimeEnumDefinition`.

## Affected Code Paths

- `RuntimeEntityCompiler.CreateRuntimeEnum` (lines 287–309)
- `RuntimeEntityCompiler.GetOrCreateRuntimeEnum` (lines ~265–285, calls `CreateRuntimeEnum`)
- Any consumer that casts to an enum type to render labels (search for `EnumTypeCache`)
