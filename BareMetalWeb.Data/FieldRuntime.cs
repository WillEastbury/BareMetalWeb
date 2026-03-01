using System.Buffers;
using System.Collections.Frozen;
using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>Compact field type enum for runtime hot paths. Stable IDs — never renumber.</summary>
public enum FieldType : byte
{
    Bool       = 1,
    Byte       = 2,
    SByte      = 3,
    Int16      = 4,
    UInt16     = 5,
    Int32      = 6,
    UInt32     = 7,
    Int64      = 8,
    UInt64     = 9,
    Float32    = 10,
    Float64    = 11,
    Decimal    = 12,
    Char       = 13,
    DateOnly   = 14,
    DateTime   = 15,
    DateTimeOffset = 16,
    TimeOnly   = 17,
    TimeSpan   = 18,
    Guid       = 19,
    StringUtf8 = 20,
    Bytes      = 21,
    EnumInt32  = 22,
    Identifier = 23,
}

/// <summary>Bitflags for field constraints. Hot-path null/required checks via bitwise AND.</summary>
[Flags]
public enum FieldFlags : ushort
{
    None     = 0,
    Nullable = 1 << 0,
    Required = 1 << 1,
    ReadOnly = 1 << 2,
    Unique   = 1 << 3,
    Indexed  = 1 << 4,
    Lookup   = 1 << 5,
    Computed = 1 << 6,
}

/// <summary>
/// Dense, ordinal-indexed field descriptor compiled once at startup.
/// No reflection, no strings, no dictionaries in hot loops.
/// </summary>
public sealed class FieldRuntime
{
    public required int Ordinal { get; init; }
    public required string Name { get; init; }
    public required uint NameHash { get; init; }
    public required FieldType Type { get; init; }
    public required FieldFlags Flags { get; init; }
    /// <summary>Byte width for fixed-size fields (0 for variable-length).</summary>
    public required ushort FixedSizeBytes { get; init; }
    /// <summary>Byte offset into the fixed region (-1 for variable-length fields).</summary>
    public required int FixedOffset { get; init; }
    /// <summary>Index into VarOffsets table (only meaningful for variable-length fields).</summary>
    public required ushort VarIndex { get; init; }
    /// <summary>Stable codec ID for the CodecTable array lookup.</summary>
    public required byte CodecId { get; init; }
    public required Type ClrType { get; init; }
    /// <summary>Compiled getter — no reflection at runtime.</summary>
    public required Func<object, object?> Getter { get; init; }
    /// <summary>Compiled setter — no reflection at runtime.</summary>
    public required Action<object, object?> Setter { get; init; }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool Is(FieldFlags flag) => (Flags & flag) != 0;
}

/// <summary>
/// Precomputed row layout for an entity type. All sizes are deterministic
/// given the same field set — suitable for caching and AOT.
/// </summary>
public sealed class EntityLayout
{
    public required string EntityName { get; init; }
    public required string Slug { get; init; }
    public required Type ClrType { get; init; }
    /// <summary>Dense ordinal-indexed array: Fields[ordinal] is the FieldRuntime.</summary>
    public required FieldRuntime[] Fields { get; init; }
    /// <summary>Bytes needed for the null bitmap (1 bit per field, rounded up).</summary>
    public required int NullBitmapBytes { get; init; }
    /// <summary>Total bytes for packed fixed-width values.</summary>
    public required int FixedRegionBytes { get; init; }
    /// <summary>Number of variable-length fields (determines VarOffsets table size).</summary>
    public required int VarFieldCount { get; init; }
    /// <summary>Minimum row size: NullBitmap + Fixed + VarOffsets (no payload).</summary>
    public int RowMinBytes => NullBitmapBytes + FixedRegionBytes + (VarFieldCount * 4);
    /// <summary>FNV-1a schema hash for migration detection.</summary>
    public required ulong SchemaHash { get; init; }
    /// <summary>Boundary-only: name → ordinal lookup. Never used in hot loops.</summary>
    public required FrozenDictionary<string, int> NameToOrdinal { get; init; }

    /// <summary>Resolve field by name (boundary path only).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public FieldRuntime? FieldByName(string name)
        => NameToOrdinal.TryGetValue(name, out var ord) ? Fields[ord] : null;

    // ── Null bitmap helpers ──

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool IsNull(ReadOnlySpan<byte> nullBitmap, int ordinal)
        => (nullBitmap[ordinal >> 3] & (1 << (ordinal & 7))) != 0;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void SetNull(Span<byte> nullBitmap, int ordinal)
        => nullBitmap[ordinal >> 3] |= (byte)(1 << (ordinal & 7));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ClearNull(Span<byte> nullBitmap, int ordinal)
        => nullBitmap[ordinal >> 3] &= (byte)~(1 << (ordinal & 7));

    // ── FNV-1a hash for field names ──

    public static uint Fnv1aHash(string s)
    {
        uint hash = 2166136261u;
        foreach (char c in s)
        {
            hash ^= (byte)c;
            hash *= 16777619u;
        }
        return hash;
    }

    // ── Row encoding: read/write fixed fields ──

    /// <summary>Read a fixed-size field from the fixed region of a row buffer.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ReadOnlySpan<byte> ReadFixed(ReadOnlySpan<byte> row, FieldRuntime field)
        => row.Slice(NullBitmapBytes + field.FixedOffset, field.FixedSizeBytes);

    /// <summary>Read a variable-length field from a row buffer.</summary>
    public ReadOnlySpan<byte> ReadVar(ReadOnlySpan<byte> row, FieldRuntime field)
    {
        int offsetTableStart = NullBitmapBytes + FixedRegionBytes;
        int entryPos = offsetTableStart + (field.VarIndex * 4);
        uint offset = BitConverter.ToUInt32(row.Slice(entryPos, 4));
        if (offset == 0xFFFFFFFF) return default;
        int payloadStart = offsetTableStart + (VarFieldCount * 4);
        int absPos = payloadStart + (int)offset;
        uint len = BitConverter.ToUInt32(row.Slice(absPos, 4));
        return row.Slice(absPos + 4, (int)len);
    }
}
