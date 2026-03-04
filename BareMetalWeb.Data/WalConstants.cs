using System.Buffers.Binary;

namespace BareMetalWeb.Data;

/// <summary>
/// Constants, magic numbers, and key/pointer helpers for the WAL segment store.
/// All on-disk integers are little-endian.
/// </summary>
internal static class WalConstants
{
    // ── Segment header ──────────────────────────────────────────────────────
    public const uint   SegmentMagic          = 0x57414C31u; // "WAL1" LE
    public const ushort SegmentFormatVersion  = 1;
    public const ushort SegmentHeaderBytes    = 16;

    // ── Record header ────────────────────────────────────────────────────────
    public const uint   RecordMagic           = 0x52454331u; // "REC1" LE
    public const ushort RecordTypeCommitBatch = 1;
    /// <summary>Fixed record header size (32 bytes; includes 4-byte alignment pad).</summary>
    public const ushort RecordHeaderBytes     = 32;

    // ── Record trailer ───────────────────────────────────────────────────────
    public const uint TrailerMagic      = 0x54524C31u; // "TRL1" LE
    public const int  RecordTrailerBytes = 16;

    // ── Segment footer index ─────────────────────────────────────────────────
    public const uint   FooterMagic    = 0x494E4431u; // "IND1" LE
    public const ushort FooterVersion  = 1;
    public const uint   FooterEndMagic = 0x454E4431u; // "END1" LE
    /// <summary>Footer tail size: CRC32C(4) + FooterStartOffset(8) + EndMagic(4) = 16.</summary>
    public const int    FooterTailBytes = 16;

    // ── Commit batch flags ────────────────────────────────────────────────────
    public const uint PayloadFlagsCommittedOnly = 1u;

    // ── Op types ─────────────────────────────────────────────────────────────
    public const ushort OpTypeUpsertFullImage = 1;
    public const ushort OpTypeUpsertPatchRuns = 2;
    public const ushort OpTypeDeleteTombstone = 3;

    // ── Codecs ────────────────────────────────────────────────────────────────
    public const ushort CodecNone    = 1;
    public const ushort CodecDeflate = 2;
    public const ushort CodecBrotli  = 3;
    public const ushort CodecEncryptedNone   = 4; // AES-GCM envelope, inner payload uncompressed
    public const ushort CodecEncryptedBrotli = 5; // AES-GCM envelope, inner payload Brotli-compressed

    // ── Op flags ─────────────────────────────────────────────────────────────
    public const uint OpFlagIsBaseImage = 1u;
    public const uint OpFlagIsPatch     = 2u;
    public const uint OpFlagIsTombstone = 4u;

    // ── Null pointer ─────────────────────────────────────────────────────────
    public const ulong NullPtr = 0uL;

    // ── Segment naming ───────────────────────────────────────────────────────

    /// <summary>Returns the file name for the given segment ID (e.g. "wal_seg_0000000001.log").</summary>
    public static string SegmentFileName(uint segmentId) =>
        string.Create(22, segmentId, static (span, id) =>
        {
            "wal_seg_".AsSpan().CopyTo(span);
            id.TryFormat(span[8..], out _, "D10");
            ".log".AsSpan().CopyTo(span[18..]);
        });

    /// <summary>Tries to parse the segment ID from a "wal_seg_XXXXXXXXXX.log" filename.</summary>
    public static bool TryParseSegmentId(string fileName, out uint segmentId)
    {
        segmentId = 0;
        if (fileName.Length != 22) return false;
        if (!fileName.StartsWith("wal_seg_", StringComparison.Ordinal)) return false;
        if (!fileName.EndsWith(".log", StringComparison.Ordinal)) return false;
        return uint.TryParse(fileName.AsSpan(8, 10), out segmentId);
    }

    // ── Key / pointer packing ─────────────────────────────────────────────────

    /// <summary>Packs tableId and recordId into a 64-bit composite key.</summary>
    public static ulong PackKey(uint tableId, uint recordId) =>
        (ulong)tableId << 32 | recordId;

    /// <summary>Unpacks a 64-bit key into (tableId, recordId).</summary>
    public static (uint tableId, uint recordId) UnpackKey(ulong key) =>
        ((uint)(key >> 32), (uint)(key & 0xFFFF_FFFFu));

    /// <summary>Packs segmentId and byte offset into a 64-bit pointer.</summary>
    public static ulong PackPtr(uint segmentId, uint offset32) =>
        (ulong)segmentId << 32 | offset32;

    /// <summary>Unpacks a 64-bit pointer into (segmentId, offset32).</summary>
    public static (uint segmentId, uint offset32) UnpackPtr(ulong ptr) =>
        ((uint)(ptr >> 32), (uint)(ptr & 0xFFFF_FFFFu));
}
