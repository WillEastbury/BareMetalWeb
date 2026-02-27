using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace BareMetalWeb.Data;

/// <summary>
/// Log-structured WAL-backed record store.
///
/// Design summary:
/// - Append-only segment files on disk form the authoritative committed history.
/// - Only committed batches are written to disk.
/// - Each <see cref="CommitAsync"/> writes exactly ONE atomic CommitBatch record,
///   fsyncs the segment, then updates the in-memory head map.
/// - Startup recovery reads per-segment footer indexes (newest → oldest); falls
///   back to a linear scan for any segment without a valid footer.
/// - <see cref="Dispose"/> writes a footer to the active segment for clean shutdown.
///
/// Thread-safety: all writes serialised under <see cref="_writeLock"/>;
/// reads from <see cref="HeadMap"/> are independently lock-protected.
/// </summary>
public sealed class WalStore : IDisposable
{
    /// <summary>Default maximum segment size before rotating to a new segment (64 MiB).</summary>
    public const uint DefaultMaxSegmentBytes = 64u * 1024u * 1024u;

    private readonly string _directory;
    private readonly uint   _maxSegmentBytes;
    private readonly object _writeLock = new();

    private WalSegmentWriter? _activeWriter;
    private uint _nextSegmentId;
    private ulong _nextTxId = 1;
    private bool _disposed;

    // ── Public surface ────────────────────────────────────────────────────────

    /// <summary>In-memory head map: key → Ptr of the latest committed record for that key.</summary>
    public WalHeadMap HeadMap { get; } = new();

    /// <summary>Convenience proxy for <see cref="WalHeadMap.TryGetHead"/>.</summary>
    public bool TryGetHead(ulong key, out ulong ptr) => HeadMap.TryGetHead(key, out ptr);

    // ── Construction / startup ────────────────────────────────────────────────

    /// <param name="directory">Directory that holds segment files.</param>
    /// <param name="maxSegmentBytes">
    ///   Rotate to a new segment when the active segment reaches this size.
    ///   Defaults to <see cref="DefaultMaxSegmentBytes"/> (64 MiB).
    /// </param>
    public WalStore(string directory, uint maxSegmentBytes = DefaultMaxSegmentBytes)
    {
        ArgumentNullException.ThrowIfNull(directory);
        _directory       = directory;
        _maxSegmentBytes = maxSegmentBytes;
        Directory.CreateDirectory(directory);
        Recover();
    }

    // ── Commit ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Commits a batch of operations atomically.
    ///
    /// Steps (all serialised under a lock):
    /// 1. Auto-fill <see cref="WalOp.PrevPtr"/> from the current head map if the caller left it as 0.
    /// 2. Append a CommitBatch record to the active segment.
    /// 3. Fsync the segment.
    /// 4. Update the head map for every op in the batch.
    ///
    /// Returns the Ptr assigned to the batch record: (segmentId &lt;&lt; 32 | offset32).
    /// </summary>
    public Task<ulong> CommitAsync(IReadOnlyList<WalOp> ops,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ops);
        if (ops.Count == 0)
            throw new ArgumentException("Batch must contain at least one op.", nameof(ops));

        cancellationToken.ThrowIfCancellationRequested();

        lock (_writeLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            EnsureActiveWriter();

            // Rotate segment if the active one is full
            if (_activeWriter!.CurrentOffset >= _maxSegmentBytes)
                RotateSegment();

            ulong txId = _nextTxId++;

            // Auto-fill PrevPtr from head map where caller left it as NullPtr
            var filledOps = new WalOp[ops.Count];
            for (int i = 0; i < ops.Count; i++)
            {
                var op = ops[i];
                if (op.PrevPtr == WalConstants.NullPtr)
                {
                    HeadMap.TryGetHead(op.Key, out ulong prev);
                    filledOps[i] = op with { PrevPtr = prev };
                }
                else
                {
                    filledOps[i] = op;
                }
            }

            // Write record, fsync
            ulong ptr = _activeWriter.AppendCommitBatch(txId, filledOps);
            _activeWriter.Flush(flushToDisk: true);

            // Update head map (completes the "TCS" notification in spec terms)
            foreach (var op in filledOps)
                HeadMap.SetHead(op.Key, ptr);

            return Task.FromResult(ptr);
        }
    }

    // ── Read-back helpers ─────────────────────────────────────────────────────

    /// <summary>
    /// Reads the payload of the op for <paramref name="key"/> from the record at
    /// <paramref name="ptr"/> on disk. Returns <c>false</c> if the op is not found or
    /// the ptr does not point to a CommitBatch containing that key.
    /// </summary>
    public bool TryReadOpPayload(ulong ptr, ulong key, out ReadOnlyMemory<byte> payload)
    {
        payload = default;
        if (ptr == WalConstants.NullPtr) return false;

        var (segId, offset32) = WalConstants.UnpackPtr(ptr);
        string path = Path.Combine(_directory, WalConstants.SegmentFileName(segId));
        if (!File.Exists(path)) return false;

        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite, 4096);
            return TryReadOpPayloadFromStream(fs, offset32, key, out payload);
        }
        catch (IOException) { return false; }
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose()
    {
        lock (_writeLock)
        {
            if (_disposed) return;
            _disposed = true;
            _activeWriter?.WriteFooterAndClose();
            _activeWriter = null;
        }
        HeadMap.Dispose();
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// <summary>
    /// Reads all existing segments (newest → oldest) to rebuild the head map,
    /// then sets <see cref="_nextSegmentId"/> for the next new segment.
    /// </summary>
    private void Recover()
    {
        var segments = DiscoverSegments();  // sorted descending

        // Build head map from newest segment to oldest.
        // We accumulate into a flat list then sort once for BulkLoad.
        var headEntries = new SortedDictionary<ulong, ulong>();

        foreach (var (segId, filePath) in segments)
        {
            Dictionary<ulong, uint>? index = WalSegmentReader.TryReadFooterIndex(filePath)
                                          ?? WalSegmentReader.LinearScanIndex(filePath);

            foreach (var (key, offset32) in index)
            {
                // Only set if this key is not yet known (we process newest → oldest)
                if (!headEntries.ContainsKey(key))
                    headEntries[key] = WalConstants.PackPtr(segId, offset32);
            }
        }

        if (headEntries.Count > 0)
        {
            var keys  = new ulong[headEntries.Count];
            var heads = new ulong[headEntries.Count];
            int i = 0;
            foreach (var kv in headEntries) { keys[i] = kv.Key; heads[i] = kv.Value; i++; }
            HeadMap.BulkLoad(keys, heads);
        }

        // Always start a new segment; don't resume the previous active segment.
        _nextSegmentId = segments.Count > 0 ? segments[0].segId + 1 : 0;
    }

    /// <summary>Returns segment (segId, filePath) pairs sorted descending by segId.</summary>
    private List<(uint segId, string filePath)> DiscoverSegments()
    {
        var list = new List<(uint segId, string filePath)>();
        foreach (string file in Directory.EnumerateFiles(_directory, "wal_seg_*.log"))
        {
            string name = Path.GetFileName(file);
            if (WalConstants.TryParseSegmentId(name, out uint segId))
                list.Add((segId, file));
        }
        list.Sort((a, b) => b.segId.CompareTo(a.segId)); // newest first
        return list;
    }

    private void EnsureActiveWriter()
    {
        if (_activeWriter is null)
            OpenNewSegment();
    }

    private void OpenNewSegment()
    {
        string path = Path.Combine(_directory, WalConstants.SegmentFileName(_nextSegmentId));
        _activeWriter = new WalSegmentWriter(path, _nextSegmentId);
        _nextSegmentId++;
    }

    private void RotateSegment()
    {
        _activeWriter?.WriteFooterAndClose();
        _activeWriter = null;
        OpenNewSegment();
    }

    // ── Read-back internals ───────────────────────────────────────────────────

    private static bool TryReadOpPayloadFromStream(FileStream fs, uint offset32,
        ulong targetKey, out ReadOnlyMemory<byte> payload)
    {
        payload = default;

        if (offset32 + WalConstants.RecordHeaderBytes > fs.Length) return false;
        fs.Seek(offset32, SeekOrigin.Begin);

        Span<byte> recHdr = stackalloc byte[WalConstants.RecordHeaderBytes];
        if (fs.Read(recHdr) != WalConstants.RecordHeaderBytes) return false;

        if (BinaryPrimitives.ReadUInt32LittleEndian(recHdr[0..]) != WalConstants.RecordMagic)
            return false;
        if (BinaryPrimitives.ReadUInt16LittleEndian(recHdr[4..]) != WalConstants.RecordTypeCommitBatch)
            return false;

        // Read commit batch header: TxId(8)+OpCount(4)+PayloadFlags(4) = 16
        Span<byte> batchHdr = stackalloc byte[16];
        if (fs.Read(batchHdr) != 16) return false;
        uint opCount = BinaryPrimitives.ReadUInt32LittleEndian(batchHdr[8..]);

        // Op header = 44 bytes; declared once outside the loop
        Span<byte> opHdr = stackalloc byte[44];
        for (uint i = 0; i < opCount; i++)
        {
            if (fs.Read(opHdr) != 44) return false;

            ulong key           = BinaryPrimitives.ReadUInt64LittleEndian(opHdr[0..]);
            uint  compressedLen = BinaryPrimitives.ReadUInt32LittleEndian(opHdr[32..]);

            if (key == targetKey)
            {
                if (compressedLen == 0) { payload = ReadOnlyMemory<byte>.Empty; return true; }
                var buf = new byte[compressedLen];
                if (fs.Read(buf) != (int)compressedLen) return false;
                payload = buf;
                return true;
            }

            // Skip this op's payload
            fs.Seek(compressedLen, SeekOrigin.Current);
        }

        return false;
    }
}
