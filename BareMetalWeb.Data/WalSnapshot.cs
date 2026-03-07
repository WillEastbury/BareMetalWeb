using System.Buffers.Binary;
using System.IO;

namespace BareMetalWeb.Data;

/// <summary>
/// Persisted checkpoint of the <see cref="WalHeadMap"/>.
///
/// <para>
/// Snapshot file format (little-endian):
/// <list type="bullet">
///   <item>SnapshotHeader (24 bytes): Magic(4) | Version(2) | Reserved(2) | SnapshotPtr(8) | KeyCount(8)</item>
///   <item>Keys array: ulong[KeyCount]</item>
///   <item>Heads array: ulong[KeyCount]</item>
///   <item>SnapshotFooter (16 bytes): CRC32C(4) | SnapshotPtr(8) | EndMagic(4)</item>
/// </list>
/// CRC32C covers all bytes from offset 0 up to (but not including) the footer CRC field.
/// </para>
/// </summary>
internal static class WalSnapshot
{
    private const uint   SnapMagic    = 0x534E4150u; // "SNAP" LE
    private const uint   SnapEndMagic = 0x534E5045u; // "SNPE" LE
    private const ushort SnapVersion  = 1;
    private const int    HeaderBytes  = 24;
    private const int    FooterBytes  = 16;

    /// <summary>Fixed snapshot file name within the WAL directory.</summary>
    public const string FileName = "wal_snapshot.bin";

    // ── Write ─────────────────────────────────────────────────────────────────

    /// <summary>
    /// Writes a snapshot of <paramref name="headMap"/> to disk, atomically replacing
    /// any previous snapshot in <paramref name="directory"/>.
    /// </summary>
    public static void Write(string directory, ulong snapshotPtr, WalHeadMap headMap)
    {
        // Snapshot the head map arrays under read lock via a temporary BulkLoad-compatible read.
        ulong[] keys;
        ulong[] heads;
        headMap.CopyArrays(out keys, out heads);

        long keyCount = keys.Length;
        int dataBytes = HeaderBytes + (int)(keyCount * 16) + FooterBytes;
        var buf = new byte[dataBytes];
        var s   = buf.AsSpan();
        int o   = 0;

        // ── Header ──
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], SnapMagic);   o += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(s[o..], SnapVersion); o += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(s[o..], (ushort)0);  o += 2; // Reserved
        BinaryPrimitives.WriteUInt64LittleEndian(s[o..], snapshotPtr); o += 8;
        BinaryPrimitives.WriteUInt64LittleEndian(s[o..], (ulong)keyCount); o += 8;

        // ── Keys + Heads arrays ──
        for (int i = 0; i < keyCount; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(s[o..], keys[i]);  o += 8;
        }
        for (int i = 0; i < keyCount; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(s[o..], heads[i]); o += 8;
        }

        // ── Footer – CRC over [0 .. o) ──
        int crcOffset = o;
        uint crc = WalCrc32C.Compute(s[..o]);
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], crc);          o += 4;
        BinaryPrimitives.WriteUInt64LittleEndian(s[o..], snapshotPtr);  o += 8;
        BinaryPrimitives.WriteUInt32LittleEndian(s[o..], SnapEndMagic); o += 4;

        // Write atomically: write to .tmp, fsync, rename, then fsync directory
        string path    = Path.Combine(directory, FileName);
        string tmpPath = path + ".tmp";
        File.WriteAllBytes(tmpPath, buf);

        // #1170: fsync the temp file so data is durable before the rename
        using (var fs = new FileStream(tmpPath, FileMode.Open, FileAccess.Read, FileShare.None))
            fs.Flush(flushToDisk: true);

        File.Move(tmpPath, path, overwrite: true);

        // #1170: fsync the directory so the rename (directory entry) is durable
        if (!OperatingSystem.IsWindows())
        {
            try
            {
                using var d = new FileStream(directory, FileMode.Open,
                    FileAccess.Read, FileShare.ReadWrite);
                d.Flush(flushToDisk: true);
            }
            catch (IOException)                { /* best-effort */ }
            catch (UnauthorizedAccessException) { /* best-effort */ }
        }
    }

    // ── Load ──────────────────────────────────────────────────────────────────

    /// <summary>
    /// Tries to load and validate a snapshot from <paramref name="directory"/>.
    /// Returns <c>false</c> if no valid snapshot is found.
    /// </summary>
    public static bool TryLoad(string directory, out ulong snapshotPtr, out ulong[] keys, out ulong[] heads)
    {
        snapshotPtr = 0;
        keys  = [];
        heads = [];

        string path = Path.Combine(directory, FileName);
        if (!File.Exists(path)) return false;

        byte[] buf;
        try { buf = File.ReadAllBytes(path); }
        catch (IOException) { return false; }

        if (buf.Length < HeaderBytes + FooterBytes) return false;

        var s = buf.AsSpan();
        int o = 0;

        // ── Header ──
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(s[o..]); o += 4;
        if (magic != SnapMagic) return false;

        ushort version = BinaryPrimitives.ReadUInt16LittleEndian(s[o..]); o += 2;
        if (version != SnapVersion) return false;

        o += 2; // Reserved
        ulong snapPtr  = BinaryPrimitives.ReadUInt64LittleEndian(s[o..]); o += 8;
        ulong keyCount = BinaryPrimitives.ReadUInt64LittleEndian(s[o..]); o += 8;

        long expectedDataBytes = HeaderBytes + (long)keyCount * 16 + FooterBytes;
        if (buf.Length != expectedDataBytes) return false;

        // ── Validate CRC (over header + arrays) ──
        int crcStart  = o;                     // start of key/head arrays
        int crcEnd    = (int)expectedDataBytes - FooterBytes; // exclusive end
        uint storedCrc = BinaryPrimitives.ReadUInt32LittleEndian(s[crcEnd..]);

        // Zero the CRC field before computing (it's over [0 .. crcEnd) )
        uint actualCrc = WalCrc32C.Compute(s[..crcEnd]);
        if (actualCrc != storedCrc) return false;

        // ── Validate footer ──
        ulong footerPtr  = BinaryPrimitives.ReadUInt64LittleEndian(s[(crcEnd + 4)..]);
        uint  endMagic   = BinaryPrimitives.ReadUInt32LittleEndian(s[(crcEnd + 12)..]);
        if (footerPtr != snapPtr || endMagic != SnapEndMagic) return false;

        // ── Decode arrays ──
        var loadedKeys  = new ulong[keyCount];
        var loadedHeads = new ulong[keyCount];
        for (ulong i = 0; i < keyCount; i++)
        {
            loadedKeys[i] = BinaryPrimitives.ReadUInt64LittleEndian(s[o..]); o += 8;
        }
        for (ulong i = 0; i < keyCount; i++)
        {
            loadedHeads[i] = BinaryPrimitives.ReadUInt64LittleEndian(s[o..]); o += 8;
        }

        snapshotPtr = snapPtr;
        keys  = loadedKeys;
        heads = loadedHeads;
        return true;
    }
}
