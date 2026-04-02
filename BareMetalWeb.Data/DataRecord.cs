using System;
using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// Base data record for all entities — both compiled (derived) and gallery-defined (virtual).
/// Uses an ordinal-indexed <c>_values</c> array for zero-reflection field access.
/// ~1–2 ns per ordinal access, ~50 ns for name-based lookups via schema.
/// Fully metadata-driven, AOT-safe.
/// </summary>
public class DataRecord : IBaseDataObject
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
    public const int BaseFieldCount   = 8;

    protected internal object?[] _values;

    private string _entityTypeName = string.Empty;

    /// <summary>
    /// The schema describing this instance's field layout.
    /// Set during entity registration or DataRecord construction.
    /// Used for name→ordinal lookups at API boundaries.
    /// </summary>
    public EntitySchema? Schema { get; internal set; }

    /// <summary>
    /// The entity type name for this instance (e.g. "Orders", "Customer").
    /// Checks _entityTypeName first, then falls back to Schema?.EntityName.
    /// </summary>
    public virtual string EntityTypeName
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => _entityTypeName.Length > 0 ? _entityTypeName : (Schema?.EntityName ?? string.Empty);
        set => _entityTypeName = value;
    }

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

    public DataRecord() : this(BaseFieldCount)
    {
    }

    public DataRecord(int totalFieldCount)
    {
        _values = new object?[Math.Max(totalFieldCount, BaseFieldCount)];
        _values[Ord_CreatedOnUtc] = DateTime.UtcNow;
        _values[Ord_UpdatedOnUtc] = _values[Ord_CreatedOnUtc];
        _values[Ord_CreatedBy] = string.Empty;
        _values[Ord_UpdatedBy] = string.Empty;
        _values[Ord_ETag] = string.Empty;
    }

    public DataRecord(string createdBy) : this(BaseFieldCount, createdBy)
    {
    }

    protected DataRecord(int totalFieldCount, string createdBy) : this(totalFieldCount)
    {
        _values[Ord_CreatedBy] = createdBy;
        _values[Ord_ETag] = Guid.NewGuid().ToString("N");
    }

    /// <summary>Creates a new record sized to match <paramref name="schema"/>.</summary>
    public DataRecord(EntitySchema schema) : this(BaseFieldCount + schema.FieldCount)
    {
        EntityTypeName = schema.EntityName;
        Schema = schema;
    }

    public void Touch(string updatedBy)
    {
        _values[Ord_UpdatedBy] = updatedBy ?? string.Empty;
        _values[Ord_UpdatedOnUtc] = DateTime.UtcNow;
        _values[Ord_ETag] = Guid.NewGuid().ToString("N");
        Version++;
    }

    // ── Hot-path accessors (ordinal) ───────────────────────────────────────

    /// <summary>Read a field value by ordinal. ~1–2 ns — one pointer dereference.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public object? GetValue(int ordinal) => _values[ordinal];

    /// <summary>Write a field value by ordinal. ~1–2 ns.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetValue(int ordinal, object? value) => _values[ordinal] = value;

    // ── Boundary accessors (name → ordinal via schema) ─────────────────────

    /// <summary>Read a field value by name. Uses schema dictionary lookup (~50 ns).</summary>
    public object? GetField(EntitySchema schema, string name)
        => schema.TryGetOrdinal(name, out var ord) ? _values[ord] : null;

    /// <summary>Write a field value by name. Uses schema dictionary lookup (~50 ns).</summary>
    public void SetField(EntitySchema schema, string name, object? value)
    {
        if (schema.TryGetOrdinal(name, out var ord))
            _values[ord] = value;
    }

    /// <summary>
    /// Grows the values array to accommodate a schema with more fields.
    /// Existing values at their ordinals are preserved.
    /// </summary>
    public void Resize(int newFieldCount)
    {
        EnsureCapacity(newFieldCount);
    }
}
