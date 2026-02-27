using System.Collections.Generic;

namespace BareMetalWeb.Data;

/// <summary>Whether a WAL operation is an upsert or a delete tombstone.</summary>
public enum ChangeType { Upsert, Delete }

/// <summary>
/// Opaque secondary-index key.  The caller encodes field values into a uint64 representation.
/// Fixed-width numeric fields are stored directly; variable-width fields use a stable hash.
/// </summary>
public readonly struct IndexKey : IEquatable<IndexKey>, IComparable<IndexKey>
{
    /// <summary>Raw 64-bit representation of this key.</summary>
    public ulong RawValue { get; init; }

    /// <summary>Creates an <see cref="IndexKey"/> directly from a <see cref="ulong"/>.</summary>
    public static IndexKey FromUInt64(ulong v) => new() { RawValue = v };

    /// <summary>Creates an <see cref="IndexKey"/> from a <see cref="uint"/>.</summary>
    public static IndexKey FromUInt32(uint v) => new() { RawValue = v };

    /// <summary>
    /// Creates an <see cref="IndexKey"/> from a string using a stable 64-bit hash.
    /// Not collision-free; suitable for equality lookups, not ordering.
    /// </summary>
    public static IndexKey FromString(string? s)
    {
        if (s is null) return default;
        // FNV-1a 64-bit over UTF-16 code units – deterministic, no heap alloc
        ulong h = 14695981039346656037ul;
        foreach (char c in s)
        {
            h ^= (byte)(c & 0xFF);       h *= 1099511628211ul;
            h ^= (byte)((c >> 8) & 0xFF); h *= 1099511628211ul;
        }
        return new IndexKey { RawValue = h };
    }

    public bool Equals(IndexKey other) => RawValue == other.RawValue;
    public int CompareTo(IndexKey other) => RawValue.CompareTo(other.RawValue);
    public override bool Equals(object? obj) => obj is IndexKey k && Equals(k);
    public override int GetHashCode() => RawValue.GetHashCode();
    public static bool operator ==(IndexKey a, IndexKey b) => a.RawValue == b.RawValue;
    public static bool operator !=(IndexKey a, IndexKey b) => a.RawValue != b.RawValue;
}

/// <summary>
/// A secondary in-memory index maintained atomically with WAL commits.
/// <para>
/// Implementations must be thread-safe: <see cref="ApplyChange"/> and
/// <see cref="Remove"/> are called under the store's write lock; query methods
/// may be called concurrently.
/// </para>
/// </summary>
public interface ISecondaryIndex
{
    /// <summary>The table whose rows this index covers.</summary>
    uint TableId { get; }

    /// <summary>Human-readable name, unique within a given <see cref="TableId"/>.</summary>
    string Name { get; }

    /// <summary>
    /// Applies a committed change to the index.
    /// <paramref name="oldRow"/> is empty when the key did not previously exist.
    /// <paramref name="newRow"/> is empty for <see cref="ChangeType.Delete"/> operations.
    /// </summary>
    void ApplyChange(ulong key, ReadOnlySpan<byte> oldRow, ReadOnlySpan<byte> newRow, ChangeType ct);

    /// <summary>Removes all index entries for a deleted row.</summary>
    void Remove(ulong key, ReadOnlySpan<byte> oldRow);

    /// <summary>Returns all record keys whose indexed field equals <paramref name="k"/>.</summary>
    IEnumerable<ulong> QueryEquals(IndexKey k);

    /// <summary>
    /// Returns all record keys whose indexed field value falls in [<paramref name="min"/>, <paramref name="max"/>].
    /// Implementations that do not support range queries may return <see cref="QueryEquals(IndexKey)"/>
    /// for <paramref name="min"/> == <paramref name="max"/> and throw for true range queries.
    /// </summary>
    IEnumerable<ulong> QueryRange(IndexKey min, IndexKey max);
}
