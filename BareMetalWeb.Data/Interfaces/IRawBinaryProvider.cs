namespace BareMetalWeb.Data;

/// <summary>
/// Optional interface for data providers that can return raw binary payloads
/// without deserialising to CLR objects. Enables binary → JSON transcoding
/// (via <see cref="BmwJsonWriter"/>) with zero object materialisation.
/// </summary>
public interface IRawBinaryProvider
{
    /// <summary>
    /// Loads the raw binary payload for a single entity by key and type name.
    /// Returns <see cref="ReadOnlyMemory{T}.Empty"/> if not found.
    /// The returned bytes are in BSO1 format (header + fields in ordinal order).
    /// </summary>
    ReadOnlyMemory<byte> LoadBinary(string typeName, uint key);

    /// <summary>
    /// Loads raw binary payloads for all entities matching the query.
    /// Each entry is a BSO1-encoded binary row.
    /// </summary>
    IReadOnlyList<ReadOnlyMemory<byte>> QueryBinary(string typeName, QueryDefinition? query = null);
}
