# [VIOLATION] MetadataExtractor uses reflection chain for entity/field metadata

**Severity:** 🟡 Medium  
**File:** `BareMetalWeb.Runtime/MetadataExtractor.cs`  
**Lines:** 48, 118, 146–155, 167, 218, 250  
**Labels:** `violation`, `reflection`, `aot-unsafe`

## Description

`MetadataExtractor` uses a multi-level reflection chain to extract entity and field metadata
from compiled C# types:

```csharp
// BareMetalWeb.Runtime/MetadataExtractor.cs:48
var attr = targetType.GetCustomAttribute<DataEntityAttribute>();

// BareMetalWeb.Runtime/MetadataExtractor.cs:118
var entityAttr = type.GetCustomAttribute<DataEntityAttribute>();

// BareMetalWeb.Runtime/MetadataExtractor.cs:146-155
var properties = type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
    .Where(p => !IsCoreProperty(p))
    .Select(p => (Prop: p, Attr: p.GetCustomAttribute<DataFieldAttribute>()))
    .Where(x => x.Attr != null)
    .OrderBy(x => x.Attr!.Order);
// ...
var dataIndex = prop.GetCustomAttribute<DataIndexAttribute>();
var lookupAttr = prop.GetCustomAttribute<DataLookupAttribute>();

// BareMetalWeb.Runtime/MetadataExtractor.cs:167
enumValues = string.Join("|", Enum.GetNames(effectivePropType));
```

Also uses `Enum.GetNames()` (lines 167, 250) to extract enum value labels.

## Why This Violates the Guidelines

1. **Reflection** — `GetProperties()`, `GetCustomAttribute<T>()`, and `Enum.GetNames()` are
   all reflection APIs.
2. **Startup-only** — This is called during entity type registration at startup, not per-request.
   However, it is a systematic reflection scan of every registered entity type.
3. **Enum.GetNames** — Uses reflection to read enum labels. In NativeAOT, enum metadata may
   be stripped unless the enum type is explicitly preserved.

## Proposed Fix

This is a startup-only metadata extraction path that bridges compiled C# entity types to the
metadata system. While it cannot be fully eliminated without removing compiled entity support,
it should be annotated with `[DynamicallyAccessedMembers]` to guide the trimmer, and
`Enum.GetNames()` should be replaced with a pre-registered enum label map.

## Affected Code Paths

- `MetadataExtractor.ExtractFromType()` — called during entity registration at startup
- `MetadataExtractor.BuildFromMetadata()` — called to build entity definitions from metadata
- `MetadataExtractor.ResolveEntitySlug()` — called to resolve entity slug from type

## Resolution

**Status:** ⚠️ MITIGATED

Added `[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties)]` annotation to the `type` parameter of `ExtractFromType()`, eliminating IL2070 trimmer warnings. In `BuildFromMetadata()`, `Enum.GetNames()` now prefers pre-registered `DataFieldMetadata.EnumValues` when available, falling back to `Enum.GetNames()` only when enum values aren't pre-cached in metadata. Added `using System.Diagnostics.CodeAnalysis` import.
