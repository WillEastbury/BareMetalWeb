using System;
using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>A name→ordinal slot in an entity's field lookup table. Sorted by Name for linear scan.</summary>
public readonly struct FieldSlot
{
    public readonly string Name;
    public readonly int Ordinal;
    public FieldSlot(string name, int ordinal) { Name = name; Ordinal = ordinal; }
}

public abstract class BaseDataObject : IBaseDataObject
{
    // ── Ordinal-indexed field storage ─────────────────────────────────────────
    // Base properties occupy ordinals 0-7. Entity-specific DataField properties
    // start at BaseFieldCount (8). Every property getter/setter reads/writes
    // _values[ordinal] — zero reflection, ~1-2 ns per access.

    protected internal const int Ord_Key          = 0;
    protected internal const int Ord_Identifier   = 1;
    protected internal const int Ord_CreatedOnUtc = 2;
    protected internal const int Ord_UpdatedOnUtc = 3;
    protected internal const int Ord_CreatedBy    = 4;
    protected internal const int Ord_UpdatedBy    = 5;
    protected internal const int Ord_ETag         = 6;
    protected internal const int Ord_Version      = 7;
    protected internal const int BaseFieldCount   = 8;

    protected internal object?[] _values;

    /// <summary>
    /// The schema describing this instance's field layout.
    /// Set during entity registration or DataRecord construction.
    /// Used for name→ordinal lookups at API boundaries.
    /// </summary>
    public EntitySchema? Schema { get; internal set; }

    // ── Base CLR properties backed by _values ────────────────────────────────

    public uint Key
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => (uint)(_values[Ord_Key] ?? 0u);
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        set => _values[Ord_Key] = value;
    }

    public IdentifierValue Identifier
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => _values[Ord_Identifier] is IdentifierValue iv ? iv : default;
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        set => _values[Ord_Identifier] = value;
    }

    public DateTime CreatedOnUtc
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => _values[Ord_CreatedOnUtc] is DateTime dt ? dt : default;
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        set => _values[Ord_CreatedOnUtc] = value;
    }

    public DateTime UpdatedOnUtc
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => _values[Ord_UpdatedOnUtc] is DateTime dt ? dt : default;
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        set => _values[Ord_UpdatedOnUtc] = value;
    }

    public string CreatedBy
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => (string?)_values[Ord_CreatedBy] ?? string.Empty;
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        set => _values[Ord_CreatedBy] = value;
    }

    public string UpdatedBy
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => (string?)_values[Ord_UpdatedBy] ?? string.Empty;
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        set => _values[Ord_UpdatedBy] = value;
    }

    public string ETag
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => (string?)_values[Ord_ETag] ?? string.Empty;
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        set => _values[Ord_ETag] = value;
    }

    /// <summary>Monotonic version counter for optimistic concurrency. Incremented on every save.</summary>
    public uint Version
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => (uint)(_values[Ord_Version] ?? 0u);
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        set => _values[Ord_Version] = value;
    }

    // ── IBaseDataObject ordinal access ────────────────────────────────────────

    /// <summary>Read a field value by storage ordinal. ~1-2 ns.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public object? GetFieldValue(int ordinal) => _values[ordinal];

    /// <summary>Write a field value by storage ordinal. ~1-2 ns.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetFieldValue(int ordinal, object? value) => _values[ordinal] = value;

    /// <summary>Read a field value by name via schema lookup. ~50 ns.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public object? GetFieldByName(string name)
    {
        if (Schema != null && Schema.TryGetOrdinal(name, out var ord))
            return _values[ord];
        return null;
    }

    /// <summary>Write a field value by name via schema lookup. ~50 ns.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetFieldByName(string name, object? value)
    {
        if (Schema != null && Schema.TryGetOrdinal(name, out var ord))
            _values[ord] = value;
    }

    /// <summary>Resolve a field name to its storage ordinal. Returns -1 if not found.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int GetOrdinal(string name)
        => Schema != null && Schema.TryGetOrdinal(name, out var ord) ? ord : -1;

    /// <summary>Total number of field slots in this instance.</summary>
    public int FieldCount => _values.Length;

    /// <summary>
    /// Grows the values array if needed to accommodate more fields.
    /// Existing values are preserved.
    /// </summary>
    public void EnsureCapacity(int requiredCount)
    {
        if (requiredCount <= _values.Length) return;
        var prev = _values;
        _values = new object?[requiredCount];
        Array.Copy(prev, _values, prev.Length);
    }

    // ── Field lookup table ───────────────────────────────────────────────────
    // Sorted by name for linear scan. Each entity overrides to include its own fields.
    // Base properties are included so DataScaffold can discover all ordinals.

    private static readonly FieldSlot[] _baseFieldMap = new[]
    {
        new FieldSlot("CreatedBy", Ord_CreatedBy),
        new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
        new FieldSlot("ETag", Ord_ETag),
        new FieldSlot("Identifier", Ord_Identifier),
        new FieldSlot("Key", Ord_Key),
        new FieldSlot("UpdatedBy", Ord_UpdatedBy),
        new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
        new FieldSlot("Version", Ord_Version),
    };

    /// <summary>
    /// Returns a sorted (by name) lookup table of all field name→ordinal mappings
    /// for this entity type, including base properties. Override in each entity
    /// to add entity-specific fields. Linear scan at startup; ordinals are cached.
    /// </summary>
    protected internal virtual ReadOnlySpan<FieldSlot> GetFieldMap() => _baseFieldMap;

    // ── Constructors ─────────────────────────────────────────────────────────

    protected BaseDataObject() : this(BaseFieldCount)
    {
    }

    protected BaseDataObject(int totalFieldCount)
    {
        _values = new object?[totalFieldCount];
        _values[Ord_CreatedOnUtc] = DateTime.UtcNow;
        _values[Ord_UpdatedOnUtc] = _values[Ord_CreatedOnUtc];
        _values[Ord_CreatedBy] = string.Empty;
        _values[Ord_UpdatedBy] = string.Empty;
        _values[Ord_ETag] = string.Empty;
    }

    public BaseDataObject(string createdBy) : this(BaseFieldCount, createdBy)
    {
    }

    protected BaseDataObject(int totalFieldCount, string createdBy) : this(totalFieldCount)
    {
        _values[Ord_CreatedBy] = createdBy;
        _values[Ord_ETag] = Guid.NewGuid().ToString("N");
    }

    public void Touch(string updatedBy)
    {
        _values[Ord_UpdatedBy] = updatedBy ?? string.Empty;
        _values[Ord_UpdatedOnUtc] = DateTime.UtcNow;
        _values[Ord_ETag] = Guid.NewGuid().ToString("N");
        Version++;
    }
}
