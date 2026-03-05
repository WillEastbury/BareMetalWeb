namespace BareMetalWeb.Data;

/// <summary>
/// Represents a single operation inside a WAL commit batch.
/// A struct so callers can build op lists without heap allocation pressure.
/// Callers own the <see cref="Payload"/> memory for the duration of the commit call.
/// </summary>
public readonly struct WalOp
{
    /// <summary>Packed key: (tableId &lt;&lt; 32) | recordId</summary>
    public ulong Key { get; init; }

    /// <summary>
    /// Previous head pointer for this key (0 = none).
    /// If left as 0, <see cref="WalStore"/> fills it automatically from the current head map.
    /// </summary>
    public ulong PrevPtr { get; init; }

    /// <summary>Schema/serializer signature carried through the record (use 0 if unused).</summary>
    public ulong SchemaSignature { get; init; }

    /// <summary>
    /// Op type. Use <see cref="WalConstants.OpTypeUpsertFullImage"/>,
    /// <see cref="WalConstants.OpTypeUpsertPatchRuns"/>, or
    /// <see cref="WalConstants.OpTypeDeleteTombstone"/>.
    /// </summary>
    public ushort OpType { get; init; }

    /// <summary>
    /// Codec for <see cref="Payload"/>. Use <see cref="WalConstants.CodecNone"/> or
    /// <see cref="WalConstants.CodecDeflate"/>.
    /// </summary>
    public ushort Codec { get; init; }

    /// <summary>Uncompressed payload length. Equal to <c>Payload.Length</c> for <see cref="WalConstants.CodecNone"/>.</summary>
    public uint UncompressedLen { get; init; }

    /// <summary>
    /// Op flags. Use <see cref="WalConstants.OpFlagIsBaseImage"/>,
    /// <see cref="WalConstants.OpFlagIsPatch"/>, or <see cref="WalConstants.OpFlagIsTombstone"/>.
    /// </summary>
    public uint Flags { get; init; }

    /// <summary>
    /// Payload bytes to store. Length is used as the on-disk CompressedLen.
    /// Must be empty for <see cref="WalConstants.OpTypeDeleteTombstone"/> ops.
    /// </summary>
    public ReadOnlyMemory<byte> Payload { get; init; }

    // ── Convenience factories ────────────────────────────────────────────────

    /// <summary>
    /// Creates a full-image upsert op, automatically applying Brotli compression when
    /// the payload meets the minimum size threshold and compression reduces the size.
    /// </summary>
    public static WalOp Upsert(ulong key, ReadOnlyMemory<byte> payload,
        ulong schemaSignature = 0, WalEnvelopeEncryption? encryption = null)
    {
        var compressed = WalPayloadCodec.TryCompress(payload, out ushort codec,
            out uint uncompressedLen, encryption);
        return new WalOp
        {
            Key             = key,
            OpType          = WalConstants.OpTypeUpsertFullImage,
            Codec           = codec,
            Flags           = WalConstants.OpFlagIsBaseImage,
            Payload         = compressed,
            UncompressedLen = uncompressedLen,
            SchemaSignature = schemaSignature,
        };
    }

    /// <summary>Creates a delete-tombstone op.</summary>
    public static WalOp Delete(ulong key) => new()
    {
        Key    = key,
        OpType = WalConstants.OpTypeDeleteTombstone,
        Codec  = WalConstants.CodecNone,
        Flags  = WalConstants.OpFlagIsTombstone,
    };
}
