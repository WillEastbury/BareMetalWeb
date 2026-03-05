using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;

namespace BareMetalWeb.Data;

/// <summary>
/// Reads WAL segment files during startup recovery.
/// Provides two strategies:
///   1. Footer index (fast) – used when the segment was closed cleanly.
///   2. Linear scan (fallback) – used when no valid footer exists (crash scenario).
/// All methods are static and allocation-light on the hot path.
/// </summary>
internal static class WalSegmentReader
{
    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>
    /// Tries to read the footer index of a segment file.
    /// Returns a dictionary mapping key → offset32 of the latest RecordHeader for that key
    /// within the segment, or <c>null</c> if no valid footer is found.
    /// </summary>
    public static Dictionary<ulong, uint>? TryReadFooterIndex(string filePath)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite, 4096, FileOptions.SequentialScan);
        return TryReadFooterIndex(fs);
    }

    /// <summary>
    /// Falls back to a sequential scan of the segment body when no footer exists.
    /// Returns a dictionary mapping key → offset32 of the latest RecordHeader for that key.
    /// Stops at the first corrupt/truncated record.
    /// </summary>
    public static Dictionary<ulong, uint> LinearScanIndex(string filePath)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite, 4096, FileOptions.SequentialScan);
        return LinearScanIndex(fs);
    }

    // ── Footer path ───────────────────────────────────────────────────────────

    private static Dictionary<ulong, uint>? TryReadFooterIndex(FileStream fs)
    {
        // Need at least: SegmentHeader + FooterTail
        if (fs.Length < WalConstants.SegmentHeaderBytes + WalConstants.FooterTailBytes)
            return null;

        // Read the last 16 bytes (footer tail): CRC32C(4) + FooterStartOffset(8) + EndMagic(4)
        fs.Seek(-WalConstants.FooterTailBytes, SeekOrigin.End);
        Span<byte> tail = stackalloc byte[WalConstants.FooterTailBytes];
        if (fs.Read(tail) != WalConstants.FooterTailBytes) return null;

        uint endMagic = BinaryPrimitives.ReadUInt32LittleEndian(tail[12..]);
        if (endMagic != WalConstants.FooterEndMagic) return null;

        ulong footerStartOffset = BinaryPrimitives.ReadUInt64LittleEndian(tail[4..]);
        uint  storedCrc         = BinaryPrimitives.ReadUInt32LittleEndian(tail[0..]);

        if (footerStartOffset >= (ulong)(fs.Length - WalConstants.FooterTailBytes)) return null;
        if (footerStartOffset < WalConstants.SegmentHeaderBytes) return null;

        // footer body = bytes from footerStartOffset up to (but not including) footer tail
        long bodyLen = fs.Length - WalConstants.FooterTailBytes - (long)footerStartOffset;
        if (bodyLen < 12 || bodyLen > int.MaxValue) return null; // minimum: magic+ver+res+count

        var body = new byte[(int)bodyLen];
        fs.Seek((long)footerStartOffset, SeekOrigin.Begin);
        if (fs.Read(body) != body.Length) return null;

        // Verify CRC32C over footer body
        if (WalCrc32C.Compute(body) != storedCrc) return null;

        var span = body.AsSpan();
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(span[0..]);
        if (magic != WalConstants.FooterMagic) return null;

        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(span[4..]);
        if (version != WalConstants.FooterVersion) return null;

        uint entryCount = BinaryPrimitives.ReadUInt32LittleEndian(span[8..]);
        int off = 12;

        if (off + (long)entryCount * 16 > body.Length) return null; // truncated

        var result = new Dictionary<ulong, uint>((int)entryCount);
        for (uint i = 0; i < entryCount; i++)
        {
            ulong key      = BinaryPrimitives.ReadUInt64LittleEndian(span[off..]);  off += 8;
            uint  offset32 = BinaryPrimitives.ReadUInt32LittleEndian(span[off..]);  off += 4;
            off += 4; // Reserved
            result[key] = offset32;
        }

        return result;
    }

    // ── Linear scan path ─────────────────────────────────────────────────────

    private static Dictionary<ulong, uint> LinearScanIndex(FileStream fs)
    {
        var result = new Dictionary<ulong, uint>();

        if (fs.Length < WalConstants.SegmentHeaderBytes)
            return result;

        // Validate and skip segment header
        Span<byte> segHeader = stackalloc byte[WalConstants.SegmentHeaderBytes];
        if (fs.Read(segHeader) != WalConstants.SegmentHeaderBytes) return result;
        if (BinaryPrimitives.ReadUInt32LittleEndian(segHeader) != WalConstants.SegmentMagic)
            return result;

        Span<byte> recHeader = stackalloc byte[WalConstants.RecordHeaderBytes];
        byte[]? pooledBuf = null;

        try
        {
            while (fs.Position < fs.Length)
            {
                long recordStart = fs.Position;
                if (fs.Read(recHeader) != WalConstants.RecordHeaderBytes) break;

                uint recMagic = BinaryPrimitives.ReadUInt32LittleEndian(recHeader[0..]);
                if (recMagic != WalConstants.RecordMagic) break; // corrupt / start of footer

                ushort recType    = BinaryPrimitives.ReadUInt16LittleEndian(recHeader[4..]);
                uint   totalBytes = BinaryPrimitives.ReadUInt32LittleEndian(recHeader[8..]);

                long minSize = WalConstants.RecordHeaderBytes + WalConstants.RecordTrailerBytes;
                if (totalBytes < minSize) break;
                if (recordStart + totalBytes > fs.Length) break; // truncated

                // Read the entire record for CRC verification, using pooled buffer
                fs.Seek(recordStart, SeekOrigin.Begin);
                if (pooledBuf == null || pooledBuf.Length < (int)totalBytes)
                {
                    if (pooledBuf != null) ArrayPool<byte>.Shared.Return(pooledBuf);
                    pooledBuf = ArrayPool<byte>.Shared.Rent((int)totalBytes);
                }
                if (fs.Read(pooledBuf, 0, (int)totalBytes) != (int)totalBytes) break;

                if (!VerifyRecordCrc(pooledBuf.AsSpan(0, (int)totalBytes))) break;

                if (recType == WalConstants.RecordTypeCommitBatch)
                {
                    var span = pooledBuf.AsSpan(0, (int)totalBytes);
                    int off = WalConstants.RecordHeaderBytes;
                    // Commit batch header: TxId(8) + OpCount(4) + PayloadFlags(4) = 16
                    if (off + 16 > span.Length) break;
                    uint opCount = BinaryPrimitives.ReadUInt32LittleEndian(span[(off + 8)..]);
                    off += 16;

                    bool corrupt = false;
                    for (uint k = 0; k < opCount; k++)
                    {
                        if (off + 44 > span.Length) { corrupt = true; break; }

                        ulong key           = BinaryPrimitives.ReadUInt64LittleEndian(span[off..]);
                        uint  compressedLen = BinaryPrimitives.ReadUInt32LittleEndian(span[(off + 32)..]);
                        off += 44;

                        result[key] = (uint)recordStart;

                        off += (int)compressedLen;
                        if (off > span.Length) { corrupt = true; break; }
                    }
                    if (corrupt) break;
                }

                // Advance to the next record
                fs.Seek(recordStart + totalBytes, SeekOrigin.Begin);
            }
        }
        finally
        {
            if (pooledBuf != null) ArrayPool<byte>.Shared.Return(pooledBuf);
        }

        return result;
    }

    /// <summary>
    /// Verifies the CRC-32C of a complete WAL record.
    /// The CRC is stored at header offset 24 and trailer offset +8; both must match
    /// the CRC computed with those fields zeroed.
    /// </summary>
    internal static bool VerifyRecordCrc(Span<byte> record)
    {
        if (record.Length < WalConstants.RecordHeaderBytes + WalConstants.RecordTrailerBytes)
            return false;

        const int headerCrcOffset = 24; // offset within record header
        int trailerStart = record.Length - WalConstants.RecordTrailerBytes;
        int trailerCrcOffset = trailerStart + 8; // offset within trailer

        uint storedHeaderCrc  = BinaryPrimitives.ReadUInt32LittleEndian(record[headerCrcOffset..]);
        uint storedTrailerCrc = BinaryPrimitives.ReadUInt32LittleEndian(record[trailerCrcOffset..]);

        // Both CRC fields must agree
        if (storedHeaderCrc != storedTrailerCrc) return false;

        // Zero both CRC fields, compute, then restore
        BinaryPrimitives.WriteUInt32LittleEndian(record[headerCrcOffset..],  0u);
        BinaryPrimitives.WriteUInt32LittleEndian(record[trailerCrcOffset..], 0u);
        uint computed = WalCrc32C.Compute(record);
        BinaryPrimitives.WriteUInt32LittleEndian(record[headerCrcOffset..],  storedHeaderCrc);
        BinaryPrimitives.WriteUInt32LittleEndian(record[trailerCrcOffset..], storedTrailerCrc);

        return computed == storedHeaderCrc;
    }
}
