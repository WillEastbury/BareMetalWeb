# Auto Key Generation & Identifier System

## Overview

BareMetalWeb uses a two-part identity system for all data entities:

1. **`Key`** (`uint32`) — Auto-incrementing clustered primary key used for all internal storage, lookups, and references. Assigned automatically by the engine.
2. **`Identifier`** (`IdentifierValue`, 16 bytes) — A human-readable code encoded in base-37 (A-Z, 0-9, hyphen). Max 25 characters. Stored as two `ulong` values for compact binary representation.

The old GUID-based `Id` field has been removed entirely.

## Key Generation

Keys are sequential `uint32` values, starting from 1 and auto-incrementing per entity type. They are:
- Persisted in a 4-byte little-endian file (`_seqid.dat`) per entity type
- Thread-safe via `Interlocked` operations and file locking
- Unique per entity type (each type has its own counter)

### Automatic Assignment

Keys are automatically assigned when saving a new entity:

```csharp
var customer = new Customer { Identifier = IdentifierValue.Parse("ACME-CORP") };
await DataStoreProvider.Current.SaveAsync(customer);
// customer.Key is now 1 (or next available)
```

## Identifier System

The `IdentifierValue` struct provides compact storage for human-readable codes:

### Character Set (Base-37)
- `A-Z` (26 letters, uppercase only)
- `0-9` (10 digits)
- `-` (hyphen)

### Normalization
- Accented characters are stripped to ASCII (é→E, ñ→N, ü→U)
- All characters are uppercased
- Invalid characters are rejected

### Storage
- Encoded as two `ulong` values (16 bytes total)
- Max 25 characters per identifier
- Binary format: two little-endian uint64 values

### Usage

```csharp
// Parse from string
var id = IdentifierValue.Parse("ACME-CORP-2024");

// Accents are normalized
var id2 = IdentifierValue.Parse("Café-Résumé");  // → "CAFERESUME"

// Convert back to string
string display = id.ToString();  // "ACME-CORP-2024"

// Binary serialization (16 bytes)
Span<byte> buffer = stackalloc byte[16];
id.WriteTo(buffer);
var restored = IdentifierValue.ReadFrom(buffer);
```

## Entity Configuration

### Using DataEntity Attribute

```csharp
[DataEntity("Invoices", ShowOnNav = true, NavGroup = "Finance",
            IdGeneration = AutoIdStrategy.Sequential)]
public class Invoice : BaseDataObject
{
    [DataField(Label = "Invoice Code", Order = 1)]
    public IdentifierValue Identifier { get; set; }

    // Other properties...
}
```

### AutoIdStrategy Options
- `Sequential` (default) — Auto-increment uint32 key
- `None` — Key must be manually assigned before saving

## Thread Safety

- Key generation uses `Interlocked.Increment()` for atomic operations
- Each entity type has its own independent counter
- File-based persistence uses exclusive locking with retry

## Legacy Data Migration

**This is a breaking change.** The system detects old GUID-based data at startup and automatically wipes the data folder. There is no migration path — all data is re-created fresh. This is acceptable since there are no live consumers.

Detection checks:
- 8-byte `_seqid.dat` files (old int64 format vs new 4-byte uint32)
- 32-character hex-named `.bin` files (old GUID filenames)
