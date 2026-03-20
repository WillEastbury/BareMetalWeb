# [VIOLATION] ValidationService uses GetCustomAttributes with RequiresUnreferencedCode

**Severity:** 🟡 Medium  
**File:** `BareMetalWeb.Data/ValidationService.cs`  
**Lines:** 40–51, 109–118  
**Labels:** `violation`, `reflection`, `aot-unsafe`

## Description

`ValidationService` uses `PropertyInfo.GetCustomAttributes()` and
`Type.GetCustomAttributes<T>()` to discover validation rules from CLR attributes. Both
methods are explicitly marked with `[RequiresUnreferencedCode]`:

```csharp
// BareMetalWeb.Data/ValidationService.cs:40-52
[RequiresUnreferencedCode("Attribute scanning requires property metadata to be preserved.")]
public static ValidationConfig? BuildValidationConfig(PropertyInfo property)
{
    var validators = new List<ValidationAttribute>();
    foreach (var attr in property.GetCustomAttributes())
    {
        if (attr is ValidationAttribute va)
            validators.Add(va);
    }
    var expressionRules = new List<ValidationRuleAttribute>();
    foreach (var rule in property.GetCustomAttributes<ValidationRuleAttribute>())
        expressionRules.Add(rule);
    // ...
}

// BareMetalWeb.Data/ValidationService.cs:109-118
[RequiresUnreferencedCode("Attribute scanning requires entity type metadata to be preserved.")]
public static IReadOnlyList<ValidationRuleAttribute> GetEntityRules(Type entityType)
{
    return _entityRulesCache.GetOrAdd(entityType, static t =>
    {
        var rules = new List<ValidationRuleAttribute>();
        foreach (var rule in t.GetCustomAttributes<ValidationRuleAttribute>())
            rules.Add(rule);
        return rules;
    });
}
```

## Why This Violates the Guidelines

1. **Reflection** — `GetCustomAttributes()` is a reflection call that scans CLR metadata.
2. **Self-documented violation** — The `[RequiresUnreferencedCode]` attributes explicitly
   acknowledge that these methods are not trim-safe.
3. **Metadata-driven** — Validation rules should be part of the entity metadata definition,
   not discovered at runtime via attribute scanning.

## Proposed Fix

Define validation rules in `DataFieldMetadata` and `DataEntityMetadata` at registration
time, rather than scanning CLR attributes at runtime. For compiled entity types, validation
rules can be extracted once at startup (tolerated) and stored in the metadata. For
gallery-defined entities, validation rules are already in the gallery JSON.

## Affected Code Paths

- `ValidationService.BuildValidationConfig()` — called during field registration
- `ValidationService.GetEntityRules()` — called during entity registration

## Resolution

**Status:** ⚠️ MITIGATED

Added `[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties)]` annotation to the `entityType` parameter of `GetEntityRules()`. The existing `[RequiresUnreferencedCode]` annotation remains. This is startup-only attribute scanning that runs during entity registration, not in request paths.
