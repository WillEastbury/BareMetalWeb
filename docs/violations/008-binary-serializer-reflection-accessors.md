# [VIOLATION] BinaryObjectSerializer uses PropertyInfo.GetValue at serialization time

## Resolution

> **Status: RESOLVED** — Both property and field accessors now use compiled `Expression.Lambda` delegates. Property accessors use `PropertyAccessorFactory.BuildGetter`/`BuildSetter`. Field accessors use compiled `Expression.Field` delegates. Zero `FieldInfo.GetValue`/`SetValue` or `PropertyInfo.GetValue`/`SetValue` in production code.

**Severity:** 🟡 Medium  
**File:** `BareMetalWeb.Data/BinaryObjectSerializer.cs`  
**Lines:** ~1181–1230  
**Labels:** `violation`, `reflection`, `performance`, `serialization`

## Description

`BinaryObjectSerializer.GetMemberMap()` and `CreateMemberAccessor()` build `MemberAccessor` objects
that wrap `PropertyInfo.GetValue` / `PropertyInfo.SetValue` as their getter/setter delegates:

```csharp
// BareMetalWeb.Data/BinaryObjectSerializer.cs:~1196-1226
private static MemberAccessor CreateMemberAccessor(PropertyInfo property)
{
    var getter = CreatePropertyGetter(property);
    var setter = CreatePropertySetter(property);
    return new MemberAccessor(property.Name, AssumePublicMembers(property.PropertyType), getter, setter);
}

private static Func<object, object?> CreatePropertyGetter(PropertyInfo property)
{
    // AOT-safe: use PropertyInfo.GetValue instead of Expression.Lambda.Compile.
    return instance => property.GetValue(instance);   // ← reflection per call
}

private static Action<object, object?> CreatePropertySetter(PropertyInfo property)
{
    // AOT-safe: use PropertyInfo.SetValue instead of Expression.Lambda.Compile.
    return (instance, value) => property.SetValue(instance, value);  // ← reflection per call
}
```

At serialization/deserialization time, these delegates call `PropertyInfo.GetValue` (reflection)
rather than compiled expression delegates.

## Why This Violates the Guidelines

1. **Performance** — `PropertyInfo.GetValue` boxes value types and has ~50–200 ns overhead per call
   vs ~1–2 ns for a compiled `Func<object, object?>` delegate. For a serialized object with 20 fields,
   this adds 1–4 µs per object on the serialization hot path.
2. **"Avoid reflection"** — delegates wrapping `PropertyInfo.GetValue` are still reflection at the
   point of invocation. They do not provide the performance benefit of compiled delegates.
3. **Inconsistency** — `FieldRuntime` (used in `EntityLayoutCompiler`) uses
   `Expression.Lambda<Func<object, object?>>(...).Compile()` for compiled getters/setters at ~1 ns.
   `BinaryObjectSerializer` should use the same compiled delegate pattern.

## Proposed Fix

Use `Expression.Lambda.Compile()` (already used in `PropertyAccessorFactory.BuildGetter`) to produce
compiled delegates, or better, use the `FieldRuntime.Getter`/`Setter` delegates that are already
compiled for all registered entity types:

```csharp
// Option A: compiled Expression delegates (same as PropertyAccessorFactory):
private static Func<object, object?> CreatePropertyGetter(PropertyInfo property)
{
    var param = Expression.Parameter(typeof(object));
    var cast = Expression.Convert(param, property.DeclaringType!);
    var access = Expression.Property(cast, property);
    var box = Expression.Convert(access, typeof(object));
    return Expression.Lambda<Func<object, object?>>(box, param).Compile();
}

// Option B (preferred): look up the already-compiled FieldRuntime getter:
// At build time: call EntityLayoutCompiler.Compile(entityMeta) to get EntityLayout
// At serialize time: layout.Fields[ordinal].Getter(obj) — ~1 ns, no reflection
```

## Affected Code Paths

- `BinaryObjectSerializer.CreatePropertyGetter` / `CreatePropertySetter` — every property access during serialize/deserialize
- `BinaryObjectSerializer.GetTypeShape` — builds the type shape once; if getters are reflection-based the shape is still slow per call
