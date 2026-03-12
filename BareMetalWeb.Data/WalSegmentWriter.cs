using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;

namespace BareMetalWeb.Data;

/// <summary>
/// Append-only writer for a single WAL segment file.
/// Not thread-safe; the caller (<see cref="WalStore"/>) must hold a write lock.
/// </summary>
internal sealed class WalSegmentWriter : IDisposable
{
    // Commit-batch payload header: TxId(8) + OpCount(4) + PayloadFlags(4)
    private const int CommitBatchHeaderSize = 16;
    // Op entry header: Key(8)+PrevPtr(8)+SchemaSignature(8)+OpType(2)+Codec(2)+UncompressedLen(4)+CompressedLen(4)+Flags(4)+Reserved(4)
    private const int OpHeaderSize = 44;

    private readonly FileStream _file;
    private bool _disposed;

    // Latest RecordHeader offset (within this segment) per key – used to build footer index.
    private readonly Dictionary<ulong, uint> _latestOpOffset = new();

    public uint SegmentId      { get; }
    public uint CurrentOffset  { get; private set; }
    public bool FooterWritten  { get; private set; }

    // ── Construction ────────────────────────────────────────────────────────

    public WalSegmentWriter(string filePath, uint segmentId)
    {
        SegmentId = segmentId;
        _file = new FileStream(filePath, FileMode.OpenOrCreate, FileAccess.ReadWrite,
            FileShare.Read, 65536, FileOptions.None);

        if (_file.Length == 0)
            WriteSegmentHeader();
        else
        {
            _file.Seek(0, SeekOrigin.End);
            CurrentOffset = checked((uint)_file.Position);
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>
    /// Appends a commit-batch record.
    /// Returns the Ptr for this record: (segmentId &lt;&lt; 32 | offset32).
    /// </summary>
    public ulong AppendCommitBatch(ulong txId, IReadOnlyList<WalOp> ops)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (FooterWritten)
            throw new InvalidOperationException("Cannot append after footer has been written.");

        uint recordOffset = CurrentOffset;
        ulong ptr = WalConstants.PackPtr(SegmentId, recordOffset);

        byte[] record = BuildCommitBatchRecord(txId, ops, ptr, out uint totalBytes);
        _file.Write(record);

        foreach (var op in ops)
            _latestOpOffset[op.Key] = recordOffset;

        CurrentOffset = checked(CurrentOffset + totalBytes);
        return ptr;
    }

    /// <summary>Flushes buffered data. Pass <c>flushToDisk=true</c> for an fsync equivalent.</summary>
    public void Flush(bool flushToDisk = true) => _file.Flush(flushToDisk);

    /// <summary>
    /// Writes the per-segment footer index, fsyncs, and closes the underlying file.
    /// After this call the writer is disposed.
    /// </summary>
    public void WriteFooterAndClose()
    {
        if (_disposed) return;
        if (!FooterWritten)
        {
            FooterWritten = true;
            WriteFooter();
            _file.Flush(flushToDisk: true);
        }
        Dispose();
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose()
    {
        if (!_disposed) { _disposed = true; _file.Dispose(); }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private void WriteSegmentHeader()
    {
        Span<byte> h = stackalloc byte[WalConstants.SegmentHeaderBytes];
        BinaryPrimitives.WriteUInt32LittleEndian(h[0..], WalConstants.SegmentMagic);
        BinaryPrimitives.WriteUInt16LittleEndian(h[4..], WalConstants.SegmentFormatVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(h[6..], WalConstants.SegmentHeaderBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(h[8..], SegmentId);
        BinaryPrimitives.WriteUInt32LittleEndian(h[12..], 0u); // Reserved
        _file.Write(h);
        CurrentOffset = WalConstants.SegmentHeaderBytes;
    }

    private void WriteFooter()
    {
        int entryCount = _latestOpOffset.Count;
        // Footer body: magic(4)+version(2)+reserved(2)+entryCount(4) = 12; entries: entryCount×16
        int bodySize = 12 + entryCount * 16;
        var body = new byte[bodySize];
        var s = body.AsSpan();
        int off = 0;

        BinaryPrimitives.WriteUInt32LittleEndian(s[off..], WalConstants.FooterMagic);   off += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(s[off..], WalConstants.FooterVersion); off += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(s[off..], (ushort)0);                  off += 2; // Reserved
        BinaryPrimitives.WriteUInt32LittleEndian(s[off..], (uint)entryCount);           off += 4;

        foreach (var (key, offset32) in _latestOpOffset)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(s[off..], key);                    off += 8;
            BinaryPrimitives.WriteUInt32LittleEndian(s[off..], offset32);               off += 4;
            BinaryPrimitives.WriteUInt32LittleEndian(s[off..], 0u);                     off += 4; // Reserved
        }

        uint footerCrc = WalCrc32C.Compute(body);
        ulong footerStartOffset = CurrentOffset;

        // Footer tail: CRC(4) + FooterStartOffset(8) + EndMagic(4)
        Span<byte> tail = stackalloc byte[WalConstants.FooterTailBytes];
        BinaryPrimitives.WriteUInt32LittleEndian(tail[0..],  footerCrc);
        BinaryPrimitives.WriteUInt64LittleEndian(tail[4..],  footerStartOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(tail[12..], WalConstants.FooterEndMagic);

        _file.Write(body);
        _file.Write(tail);
        CurrentOffset = checked(CurrentOffset + (uint)(bodySize + WalConstants.FooterTailBytes));
    }

    /// <summary>Builds the full commit-batch record (header + payload + trailer) in a byte[].</summary>
    private static byte[] BuildCommitBatchRecord(ulong txId, IReadOnlyList<WalOp> ops,
        ulong ptr, out uint totalBytes)
    {
        int payloadTotal = 0;
        foreach (var op in ops) payloadTotal += op.Payload.Length;

        int size = WalConstants.RecordHeaderBytes
                 + CommitBatchHeaderSize
                 + ops.Count * OpHeaderSize
                 + payloadTotal
                 + WalConstants.RecordTrailerBytes;
        totalBytes = checked((uint)size);

        var buf = new byte[size];
        var s   = buf.AsSpan();
        int o   = 0;

        // ── Record header (32 bytes) ──
        // Layout: Magic(4) | RecordType(2) | HeaderBytes(2) | TotalRecordBytes(4) |
        //         Reserved0(4)[alignment] | CommitPtrOrLSN(8) | CRC32C(4) | Reserved1(4)
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], WalConstants.RecordMagic);            o += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(s[o..], WalConstants.RecordTypeCommitBatch);  o += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(s[o..], WalConstants.RecordHeaderBytes);      o += 2;
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], totalBytes);                          o += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], 0u); // Reserved0
        o += 4;
        BinaryPrimitives.WriteUInt64LittleEndian(s[o..], ptr);                                 o += 8;
        int crcInHeader = o;
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], 0u); // CRC – zeroed for compute
        o += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], 0u); // Reserved1
        o += 4;

        // ── Commit batch payload header (16 bytes) ──
        BinaryPrimitives.WriteUInt64LittleEndian(s[o..], txId);                                o += 8;
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], (uint)ops.Count);                     o += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], WalConstants.PayloadFlagsCommittedOnly); o += 4;

        // ── Op entries ──
        foreach (var op in ops)
        {
            var payload = op.Payload.Span;
            BinaryPrimitives.WriteUInt64LittleEndian(s[o..], op.Key);               o += 8;
            BinaryPrimitives.WriteUInt64LittleEndian(s[o..], op.PrevPtr);           o += 8;
            BinaryPrimitives.WriteUInt64LittleEndian(s[o..], op.SchemaSignature);   o += 8;
            BinaryPrimitives.WriteUInt16LittleEndian(s[o..], op.OpType);            o += 2;
            BinaryPrimitives.WriteUInt16LittleEndian(s[o..], op.Codec);             o += 2;
            BinaryPrimitives.WriteUInt32LittleEndian(s[o..], op.UncompressedLen);   o += 4;
            BinaryPrimitives.WriteUInt32LittleEndian(s[o..], (uint)payload.Length); o += 4;
            BinaryPrimitives.WriteUInt32LittleEndian(s[o..], op.Flags);             o += 4;
            BinaryPrimitives.WriteUInt32LittleEndian(s[o..], 0u); // Reserved
            o += 4;
            payload.CopyTo(s[o..]);                                                 o += payload.Length;
        }

        // ── Record trailer (16 bytes) ──
        // Layout: TrailerMagic(4) | TotalRecordBytes(4) | CRC32C(4) | Reserved(4)
        int trailerCrcOff = o + 8; // CRC is at byte +8 within the trailer
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], WalConstants.TrailerMagic);  o += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], totalBytes);                  o += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], 0u); // CRC placeholder
        o += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], 0u); // Reserved
        o += 4;

        // Compute CRC over entire record (both CRC fields are still zero).
        uint crc = WalCrc32C.Compute(s[..size]);

        // Patch CRC into record header and trailer.
        BinaryPrimitives.WriteUInt32LittleEndian(s[crcInHeader..],  crc);
        BinaryPrimitives.WriteUInt32LittleEndian(s[trailerCrcOff..], crc);

        return buf;
    }
}
