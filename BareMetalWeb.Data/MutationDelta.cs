using System.Buffers;
using System.Buffers.Binary;

namespace BareMetalWeb.Data;

/// <summary>
/// A single field change within a mutation delta.
/// Ordinal-based — no string field names in the wire format.
/// </summary>
public readonly struct FieldDelta
{
    /// <summary>Field ordinal (index into EntityLayout.Fields).</summary>
    public readonly ushort Ordinal;
    /// <summary>New value encoded by the field's codec. Empty = set to null.</summary>
    public readonly ReadOnlyMemory<byte> Value;

    public FieldDelta(ushort ordinal, ReadOnlyMemory<byte> value)
    {
        Ordinal = ordinal;
        Value = value;
    }

    public bool IsNull => Value.IsEmpty;
}

/// <summary>
/// Row-level atomic mutation delta. Sent by clients instead of full objects.
/// Wire format: [RowId(4)][ExpectedVersion(4)][SchemaHash(8)][Count(2)][per-field: Ordinal(2)+Len(4)+Value(N)]
/// </summary>
public sealed class MutationDelta
{
    /// <summary>Target row key (uint32).</summary>
    public uint RowId { get; init; }
    /// <summary>Expected version for optimistic concurrency. 0 = skip check (create).</summary>
    public uint ExpectedVersion { get; init; }
    /// <summary>Schema hash from EntityLayout — reject if mismatched.</summary>
    public ulong SchemaHash { get; init; }
    /// <summary>Field-level changes.</summary>
    public required FieldDelta[] Changes { get; init; }

    /// <summary>
    /// Serialize to binary wire format.
    /// [RowId(4)][ExpectedVersion(4)][SchemaHash(8)][Count(2)][per-field: Ordinal(2)+Len(4)+Value(N)]
    /// </summary>
    public int Serialize(IBufferWriter<byte> writer)
    {
        // Header: 4+4+8+2 = 18 bytes
        int headerSize = 18;
        var header = writer.GetSpan(headerSize);
        BinaryPrimitives.WriteUInt32LittleEndian(header, RowId);
        BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(4), ExpectedVersion);
        BinaryPrimitives.WriteUInt64LittleEndian(header.Slice(8), SchemaHash);
        BinaryPrimitives.WriteUInt16LittleEndian(header.Slice(16), (ushort)Changes.Length);
        writer.Advance(headerSize);

        int total = headerSize;
        foreach (ref readonly var change in Changes.AsSpan())
        {
            int fieldHeaderSize = 6; // Ordinal(2) + Len(4)
            var fh = writer.GetSpan(fieldHeaderSize + change.Value.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(fh, change.Ordinal);
            BinaryPrimitives.WriteInt32LittleEndian(fh.Slice(2), change.Value.Length);
            if (!change.Value.IsEmpty)
                change.Value.Span.CopyTo(fh.Slice(6));
            writer.Advance(fieldHeaderSize + change.Value.Length);
            total += fieldHeaderSize + change.Value.Length;
        }
        return total;
    }

    /// <summary>Deserialize from binary wire format.</summary>
    public static MutationDelta Deserialize(ReadOnlySpan<byte> data)
    {
        if (data.Length < 18)
            throw new ArgumentException("Delta payload too short.");

        uint rowId = BinaryPrimitives.ReadUInt32LittleEndian(data);
        uint expectedVersion = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4));
        ulong schemaHash = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(8));
        ushort count = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(16));

        var changes = new FieldDelta[count];
        int offset = 18;
        for (int i = 0; i < count; i++)
        {
            ushort ordinal = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset));
            int len = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset + 2));
            offset += 6;
            var value = len > 0 ? data.Slice(offset, len).ToArray() : ReadOnlyMemory<byte>.Empty;
            changes[i] = new FieldDelta(ordinal, value);
            offset += len;
        }

        return new MutationDelta
        {
            RowId = rowId,
            ExpectedVersion = expectedVersion,
            SchemaHash = schemaHash,
            Changes = changes,
        };
    }

    /// <summary>Compute the wire size without serializing.</summary>
    public int WireSize()
    {
        int size = 18;
        foreach (ref readonly var c in Changes.AsSpan())
            size += 6 + c.Value.Length;
        return size;
    }
}

/// <summary>Result of applying a mutation delta.</summary>
public enum MutationResult : byte
{
    Success = 0,
    VersionConflict = 1,
    SchemaHashMismatch = 2,
    EntityNotFound = 3,
    ValidationFailed = 4,
    InvalidOrdinal = 5,
}
