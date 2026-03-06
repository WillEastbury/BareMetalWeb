# [VIOLATION] ReportExecutor uses reflection per-cell during report row projection

**Severity:** 🟡 Medium  
**File:** `BareMetalWeb.Data/ReportExecutor.cs`  
**Lines:** 344–371  
**Labels:** `violation`, `reflection`, `hot-path`, `performance`

## Description

`ReportExecutor.ProjectRow()` calls `FindAccessorOnObject()` for every cell (column × row) during
report execution. `FindAccessorOnObject` resolves a field by name using `Type.GetProperty()`:

```csharp
// BareMetalWeb.Data/ReportExecutor.cs:344-371
private static string?[] ProjectRow(Dictionary<string, BaseDataObject> row, IReadOnlyList<ReportColumn> columns)
{
    var cells = new string?[columns.Count];
    for (int i = 0; i < columns.Count; i++)
    {
        var col = columns[i];
        if (!row.TryGetValue(col.Entity, out var obj)) { cells[i] = null; continue; }

        var prop = FindAccessorOnObject(obj.GetType(), col.Field);   // ← reflection per cell
        if (prop == null) { cells[i] = null; continue; }

        var raw = prop.GetValue(obj);                                 // ← reflection per cell
        cells[i] = FormatValue(raw, col.Format);
    }
    return cells;
}

private static PropertyInfo? FindAccessorOnObject(
    [DynamicallyAccessedMembers(...)] Type type, string fieldName)
    => type.GetProperty(fieldName, BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);
                                                                      // ← reflection
```

## Why This Violates the Guidelines

1. **"Avoid reflection"** — `Type.GetProperty` and `PropertyInfo.GetValue` are reflection calls.
   For a 1000-row report with 10 columns this executes 10,000 reflection property lookups.
2. **Performance** — `GetProperty` with `BindingFlags.IgnoreCase` is O(N fields) on every call.
   `PropertyInfo.GetValue` boxes the return value, generating GC pressure.
3. **Metadata-driven architecture** — every entity is registered in `DataScaffold` with a compiled
   `DataFieldMetadata.GetValueFn` delegate. There is no reason to fall back to reflection.

## Proposed Fix

Replace `FindAccessorOnObject` with a metadata-aware field resolver that uses pre-compiled
`GetValueFn` delegates:

```csharp
private static string?[] ProjectRow(
    Dictionary<string, BaseDataObject> row,
    IReadOnlyList<ReportColumn> columns,
    IReadOnlyDictionary<string, DataEntityMetadata> metaByEntity)
{
    var cells = new string?[columns.Count];
    for (int i = 0; i < columns.Count; i++)
    {
        var col = columns[i];
        if (!row.TryGetValue(col.Entity, out var obj)) { cells[i] = null; continue; }
        if (!metaByEntity.TryGetValue(col.Entity, out var meta)) { cells[i] = null; continue; }

        var field = meta.FindField(col.Field);
        if (field?.GetValueFn == null) { cells[i] = null; continue; }

        var raw = field.GetValueFn(obj);   // ← compiled delegate, ~1ns, no reflection
        cells[i] = FormatValue(raw, col.Format);
    }
    return cells;
}
```

`DataEntityMetadata` should be pre-resolved once per report execution from the registered entity
slug, not per row.

## Affected Code Paths

- `ReportExecutor.ProjectRow` — called once per report row
- `ReportExecutor.FindAccessorOnObject` — called once per column per row
- `ReportExecutor.GetStringValue` / `GetNullableStringValue` — also use `PropertyInfo.GetValue`
