using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// A <see cref="BaseDataObject"/> that stores field values in an ordinal-indexed
/// <c>object?[]</c> array.  Designed for ~1–2 ns per field access (same as compiled
/// C# properties) while being fully metadata-driven and AOT-safe — no reflection,
/// no <c>Expression.Compile</c>, no dictionaries on the hot path.
/// <para>
/// Each instance is paired with an <see cref="EntitySchema"/> that describes the
/// field layout. The schema provides the ordinal for named lookups at API
/// boundaries; hot paths use raw ordinals captured in closures.
/// </para>
/// </summary>
public sealed class DataRecord : BaseDataObject
{
    /// <summary>
    /// The name of the entity type this instance belongs to (e.g. "Customer").
    /// Used to locate entity metadata and route to the correct storage.
    /// </summary>
    public string EntityTypeName { get; set; } = string.Empty;

    /// <summary>
    /// Ordinal-indexed field values. <c>_values[ord]</c> holds the native CLR
    /// value (string, int, decimal, DateTime, bool, …) for the field at that
    /// ordinal. <c>null</c> means the field is not set.
    /// </summary>
    internal object?[] _values;

    /// <summary>Creates a new record with space for <paramref name="fieldCount"/> fields.</summary>
    public DataRecord(int fieldCount)
    {
        _values = new object?[fieldCount];
    }

    /// <summary>Creates a new record sized to match <paramref name="schema"/>.</summary>
    public DataRecord(EntitySchema schema)
    {
        EntityTypeName = schema.EntityName;
        Schema = schema;
        _values = new object?[schema.FieldCount];
    }

    /// <summary>
    /// The schema this record was created from, if any. Used by downstream code
    /// (e.g. <see cref="DynamicPropertyInfo"/>) to resolve field names → ordinals
    /// without requiring the schema to be passed explicitly.
    /// </summary>
    public EntitySchema? Schema { get; }

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
    /// Returns the number of field slots in this record.
    /// </summary>
    public int FieldCount => _values.Length;

    /// <summary>
    /// Grows the values array to accommodate a schema with more fields.
    /// Existing values at their ordinals are preserved.
    /// </summary>
    public void Resize(int newFieldCount)
    {
        if (newFieldCount <= _values.Length) return;
        var prev = _values;
        _values = new object?[newFieldCount];
        Array.Copy(prev, _values, prev.Length);
    }
}
