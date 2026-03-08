using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Threading;

namespace BareMetalWeb.Data;

/// <summary>
/// Per-table monotonic <see cref="uint"/> record-ID sequence (V2 / PR-574 concept).
///
/// <para>
/// Generates auto-numbered primary keys for WAL records, replacing GUID-based string IDs.
/// Each call to <see cref="AllocateRecordId"/> increments the per-table counter atomically
/// and returns the new <c>recordId</c> — suitable for packing into a WAL key via
/// <see cref="WalConstants.PackKey"/>.
/// </para>
///
/// <para>
/// The current high-water mark for each table is persisted to
/// <c>wal_seqids.bin</c> in the WAL directory.  On startup, call
/// <see cref="TryLoad"/> to restore the previous state so IDs remain monotonic
/// across restarts.  On shutdown call <see cref="Flush"/> (or <see cref="Dispose"/>).
/// </para>
///
/// File format (little-endian, all integers):
/// <list type="bullet">
///   <item>u32 Magic = 0x53514944 ("SQID")</item>
///   <item>u16 Version = 1</item>
///   <item>u16 Reserved</item>
///   <item>u32 EntryCount</item>
///   <item>Repeated EntryCount × { u32 tableId, u32 lastId }</item>
///   <item>u32 CRC32C (over all bytes above, CRC field treated as zero)</item>
/// </list>
/// </summary>
public sealed class WalTableKeyAllocator : IDisposable
{
    private const uint   SeqMagic   = 0x53514944u; // "SQID"
    private const ushort SeqVersion = 1;

    /// <summary>File name within the WAL directory.</summary>
    public const string FileName = "wal_seqids.bin";

    private readonly object _lock = new();
    private readonly Dictionary<uint, uint> _sequences = new();
    private readonly string _directory;
    private bool _disposed;

    // ── Construction ────────────────────────────────────────────────────────

    private WalTableKeyAllocator(string directory) => _directory = directory;

    /// <summary>
    /// Creates a <see cref="WalTableKeyAllocator"/> for <paramref name="directory"/>,
    /// restoring any previously persisted sequences. If no file exists, starts from 0.
    /// </summary>
    public static WalTableKeyAllocator Load(string directory)
    {
        var allocator = new WalTableKeyAllocator(directory);
        string path = Path.Combine(directory, FileName);
        if (!File.Exists(path)) return allocator;

        try
        {
            byte[] buf = EncryptedFileIO.ReadDecrypted(path, "seqids");
            if (buf.Length < 12) return allocator; // header (8) + CRC (4)

            var s = buf.AsSpan();
            if (BinaryPrimitives.ReadUInt32LittleEndian(s)    != SeqMagic)   return allocator;
            if (BinaryPrimitives.ReadUInt16LittleEndian(s[4..]) != SeqVersion) return allocator;

            uint entryCount = BinaryPrimitives.ReadUInt32LittleEndian(s[8..]);
            int expectedLen = 12 + (int)entryCount * 8 + 4; // header + entries + CRC
            if (buf.Length != expectedLen) return allocator;

            // Verify CRC (CRC field = last 4 bytes, computed over [0..len-4))
            int  crcOff    = buf.Length - 4;
            uint storedCrc = BinaryPrimitives.ReadUInt32LittleEndian(s[crcOff..]);
            if (WalCrc32C.Compute(s[..crcOff]) != storedCrc) return allocator;

            int off = 12;
            for (uint i = 0; i < entryCount; i++)
            {
                uint tableId = BinaryPrimitives.ReadUInt32LittleEndian(s[off..]); off += 4;
                uint lastId  = BinaryPrimitives.ReadUInt32LittleEndian(s[off..]); off += 4;
                allocator._sequences[tableId] = lastId;
            }
        }
        catch (IOException) { /* treat as missing — start fresh */ }

        return allocator;
    }

    // ── Allocation ───────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the next monotonic <c>recordId</c> for <paramref name="tableId"/>.
    /// IDs start at 1 and increment by 1 per call.
    /// Thread-safe.
    /// </summary>
    public uint AllocateRecordId(uint tableId)
    {
        lock (_lock)
        {
            _sequences.TryGetValue(tableId, out uint current);
            uint next = current + 1;
            if (next == 0) throw new OverflowException($"Table {tableId} recordId uint32 exhausted.");
            _sequences[tableId] = next;
            return next;
        }
    }

    /// <summary>
    /// Returns the last allocated <c>recordId</c> for <paramref name="tableId"/>,
    /// or 0 if none have been allocated yet.
    /// </summary>
    public uint PeekLastId(uint tableId)
    {
        lock (_lock)
        {
            _sequences.TryGetValue(tableId, out uint last);
            return last;
        }
    }

    /// <summary>
    /// Seeds the sequence for <paramref name="tableId"/> to start at <paramref name="floor"/>
    /// (useful when importing existing data or after a snapshot restore).
    /// Only advances the counter; never decreases it.
    /// </summary>
    public void Seed(uint tableId, uint floor)
    {
        lock (_lock)
        {
            _sequences.TryGetValue(tableId, out uint current);
            if (floor > current) _sequences[tableId] = floor;
        }
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    /// <summary>
    /// Atomically writes the current sequences to disk (write-then-rename).
    /// Safe to call from any thread.
    /// </summary>
    public void Flush()
    {
        (uint tableId, uint lastId)[] snapshot;
        lock (_lock)
        {
            snapshot = new (uint, uint)[_sequences.Count];
            int i = 0;
            foreach (var kv in _sequences) { snapshot[i].tableId = kv.Key; snapshot[i].lastId = kv.Value; i++; }
        }

        int size = 12 + snapshot.Length * 8 + 4; // header + entries + CRC
        var buf = new byte[size];
        var s = buf.AsSpan();
        int o = 0;

        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], SeqMagic);                 o += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(s[o..], SeqVersion);               o += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(s[o..], (ushort)0);                o += 2; // Reserved
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], (uint)snapshot.Length);    o += 4;

        foreach (var (tableId, lastId) in snapshot)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(s[o..], tableId); o += 4;
            BinaryPrimitives.WriteUInt32LittleEndian(s[o..], lastId);  o += 4;
        }

        uint crc = WalCrc32C.Compute(s[..o]);
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], crc); o += 4;

        string path    = Path.Combine(_directory, FileName);
        string tmpPath = path + ".tmp";

        // Encrypt at rest when BMW_WAL_ENCRYPTION_KEY is configured
        var encrypted = EncryptedFileIO.Encrypt(buf, "seqids");
        File.WriteAllBytes(tmpPath, encrypted);
        File.Move(tmpPath, path, overwrite: true);
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose()
    {
        if (!_disposed) { _disposed = true; Flush(); }
    }
}
