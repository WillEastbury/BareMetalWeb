# [VIOLATION] Assembly.GetCustomAttributes used in MCP handler for version string

## Resolution

> **Status: RESOLVED** — `GetCustomAttributes` was replaced with `Assembly.GetName().Version`, which does not use reflection attribute scanning. The version is now read directly from the assembly metadata.

**Severity:** 🟢 Low  
**File:** `BareMetalWeb.Host/McpRouteHandler.cs`  
**Line:** 146  
**Labels:** `violation`, `reflection`, `low-priority`

## Description

`McpRouteHandler` reads the server version string via runtime reflection on the assembly:

```csharp
// BareMetalWeb.Host/McpRouteHandler.cs:146
.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
```

While this is only called once per MCP `initialize` handshake (not a hot path), it uses the
reflection API to query assembly metadata that could be resolved at compile time.

## Why This Violates the Guidelines

1. **"Avoid reflection"** — the guideline is broad: reflection should be avoided. Using
   `GetCustomAttributes` for something as static as an assembly version is unnecessary.
2. **AOT / trim safety** — `GetCustomAttributes` on assembly-level attributes may not work correctly
   in aggressively trimmed builds where attribute data has been stripped.

## Proposed Fix

Resolve the version at compile time using the `<InformationalVersion>` MSBuild property and the
`[assembly: AssemblyInformationalVersion(...)]` attribute, or use a pre-computed constant:

```csharp
// Option A: use Assembly.GetName().Version (no reflection on custom attributes):
private static readonly string ServerVersion =
    typeof(McpRouteHandler).Assembly.GetName().Version?.ToString() ?? "1.0.0";

// Option B: compile-time constant via T4 or source generator.
// Option C: read from appsettings / IConfiguration (already available in host).
```

The original reflection usage on `AssemblyInformationalVersionAttribute` looks like this:
```csharp
// BareMetalWeb.Host/McpRouteHandler.cs:145-153 (current code)
string? rawVersion = null;
foreach (var attr in typeof(McpRouteHandler).Assembly
    .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false))
{
    if (attr is System.Reflection.AssemblyInformationalVersionAttribute infoAttr)
    {
        rawVersion = infoAttr.InformationalVersion;
        break;
    }
}
```

## Affected Code Paths

- `McpRouteHandler.ServeInitializeAsync` or similar — single MCP handshake call
