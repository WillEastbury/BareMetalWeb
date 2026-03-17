using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// A <see cref="BaseDataObject"/> for gallery-defined (virtual) entities.
/// Uses the inherited <c>_values</c> ordinal-indexed array from <see cref="BaseDataObject"/>.
/// Adds <see cref="EntityTypeName"/> for runtime entity routing and convenience
/// name-based accessors that delegate to the base schema lookup.
/// <para>
/// ~1–2 ns per ordinal access, ~50 ns for name-based lookups via
/// <see cref="BaseDataObject.GetFieldByName"/>. Fully metadata-driven, AOT-safe.
/// </para>
/// </summary>
public sealed class DataRecord : BaseDataObject
{
    /// <summary>
    /// The name of the entity type this instance belongs to (e.g. "Customer").
    /// Used to locate entity metadata and route to the correct storage.
    /// </summary>
    public string EntityTypeName { get; set; } = string.Empty;

    /// <summary>Creates a new record with space for <paramref name="fieldCount"/> fields.</summary>
    public DataRecord(int fieldCount) : base(Math.Max(fieldCount, BaseFieldCount))
    {
    }

    /// <summary>Creates an empty record. The schema and values array must be set before use.</summary>
    public DataRecord() : this(BaseFieldCount) { }

    /// <summary>Creates a new record sized to match <paramref name="schema"/>.</summary>
    public DataRecord(EntitySchema schema) : base(BaseFieldCount + schema.FieldCount)
    {
        EntityTypeName = schema.EntityName;
        Schema = schema;
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
