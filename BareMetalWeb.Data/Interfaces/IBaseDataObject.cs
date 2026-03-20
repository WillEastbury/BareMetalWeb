namespace BareMetalWeb.Data;

public interface IBaseDataObject
{
    uint Key { get; set; }
    IdentifierValue Identifier { get; set; }
    DateTime CreatedOnUtc { get; set; }
    DateTime UpdatedOnUtc { get; set; }
    string CreatedBy { get; set; }
    string UpdatedBy { get; set; }
    string ETag { get; set; }

    void Touch(string updatedBy);

    // ── Ordinal-indexed field access ─────────────────────────────────────
    /// <summary>Read a field value by storage ordinal. ~1-2 ns.</summary>
    object? GetFieldValue(int ordinal);
    /// <summary>Write a field value by storage ordinal. ~1-2 ns.</summary>
    void SetFieldValue(int ordinal, object? value);
    /// <summary>Read a field value by name via schema lookup. ~50 ns.</summary>
    object? GetFieldByName(string name);
    /// <summary>Write a field value by name via schema lookup. ~50 ns.</summary>
    void SetFieldByName(string name, object? value);
    /// <summary>Resolve a field name to its storage ordinal. Returns -1 if not found.</summary>
    int GetOrdinal(string name);
    /// <summary>Total number of field slots in this instance.</summary>
    int FieldCount { get; }
    /// <summary>The schema describing this instance's field layout. May be null before registration.</summary>
    EntitySchema? Schema { get; }
}
