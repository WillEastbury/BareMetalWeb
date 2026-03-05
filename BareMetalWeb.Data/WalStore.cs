using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace BareMetalWeb.Data;

/// <summary>
/// Log-structured WAL-backed record store (V2).
///
/// Design summary:
/// - Append-only segment files on disk form the authoritative committed history.
/// - Only committed batches are written to disk.
/// - Each <see cref="CommitAsync"/> writes exactly ONE atomic CommitBatch record,
///   fsyncs the segment, then updates the in-memory head map.
/// - Startup recovery loads a snapshot if present, then replays WAL tail.
/// - <see cref="Dispose"/> writes a snapshot and a segment footer for clean shutdown.
/// - <see cref="ProjectionManager"/> dispatches committed ops to secondary indexes.
/// - <see cref="VisibleCommitPtr"/> tracks the latest durable commit watermark.
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
    internal readonly WalEnvelopeEncryption Encryption;

    private WalSegmentWriter? _activeWriter;
    private uint _nextSegmentId;
    private ulong _nextTxId = 1;
    private ulong _visibleCommitPtr;
    private bool _disposed;

    // ── Public surface ────────────────────────────────────────────────────────

    /// <summary>In-memory head map: key → Ptr of the latest committed record for that key.</summary>
    public WalHeadMap HeadMap { get; } = new();

    /// <summary>
    /// Global monotonic commit watermark (V2 spec §3.1 VisibleCommitPtr).
    /// Queries and projections should only observe versions ≤ this value.
    /// Updated after every successful commit.
    /// </summary>
    public ulong VisibleCommitPtr => Volatile.Read(ref _visibleCommitPtr);

    /// <summary>
    /// Secondary-index coordinator (V2 spec §4.2).
    /// Register <see cref="ISecondaryIndex"/> instances here before the first commit.
    /// </summary>
    public WalProjectionManager ProjectionManager { get; } = new();

    /// <summary>
    /// Per-table monotonic <c>uint32</c> primary-key sequence (PR-574 concept).
    /// Use <see cref="AllocateKey"/> to generate a fully-packed WAL key with an auto-numbered recordId.
    /// </summary>
    public WalTableKeyAllocator KeyAllocator { get; private set; } = null!;

    /// <summary>Convenience proxy for <see cref="WalHeadMap.TryGetHead"/>.</summary>
    public bool TryGetHead(ulong key, out ulong ptr) => HeadMap.TryGetHead(key, out ptr);

    /// <summary>
    /// Allocates the next monotonic <c>recordId</c> for <paramref name="tableId"/> and
    /// returns the packed WAL key <c>(tableId &lt;&lt; 32 | newRecordId)</c>.
    /// Use this to obtain a primary key before staging a <see cref="WalOp.Upsert"/> op.
    /// </summary>
    public ulong AllocateKey(uint tableId)
        => WalConstants.PackKey(tableId, KeyAllocator.AllocateRecordId(tableId));

    // ── Construction / startup ────────────────────────────────────────────────

    /// <param name="directory">Directory that holds segment files.</param>
    /// <param name="maxSegmentBytes">
    ///   Rotate to a new segment when the active segment reaches this size.
    ///   Defaults to <see cref="DefaultMaxSegmentBytes"/> (64 MiB).
    /// </param>
    public WalStore(string directory, uint maxSegmentBytes = DefaultMaxSegmentBytes,
        WalEnvelopeEncryption? encryption = null)
    {
        ArgumentNullException.ThrowIfNull(directory);
        _directory       = directory;
        _maxSegmentBytes = maxSegmentBytes;
        Encryption       = encryption ?? WalPayloadCodec.GetDefaultEncryption();
        Directory.CreateDirectory(directory);
        KeyAllocator = WalTableKeyAllocator.Load(directory);
        Recover();
    }

    // ── Transaction ───────────────────────────────────────────────────────────

    /// <summary>
    /// Creates a new staging transaction (V2 spec §3).
    /// Stage operations on the returned <see cref="WalTransaction"/>, then call
    /// <see cref="WalTransaction.CommitAsync"/> to persist atomically.
    /// If the transaction is disposed without committing, staged ops are discarded.
    /// </summary>
    public WalTransaction BeginTransaction() => new(this);

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

        WalOp[] filledOps;
        ulong ptr;

        lock (_writeLock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            EnsureActiveWriter();

            // Rotate segment if the active one is full
            if (_activeWriter!.CurrentOffset >= _maxSegmentBytes)
                RotateSegment();

            ulong txId = _nextTxId++;

            // Auto-fill PrevPtr from head map where caller left it as NullPtr
            filledOps = new WalOp[ops.Count];
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
            ptr = _activeWriter.AppendCommitBatch(txId, filledOps);
            _activeWriter.Flush(flushToDisk: true);

            // Batch head map update — single write-lock instead of N
            Span<ulong> opKeys = stackalloc ulong[filledOps.Length];
            for (int i = 0; i < filledOps.Length; i++)
                opKeys[i] = filledOps[i].Key;
            HeadMap.BatchSetHeads(opKeys, ptr);

            Volatile.Write(ref _visibleCommitPtr, ptr);
        }

        // Dispatch to secondary projections outside the write lock
        ProjectionManager.ApplyCommit(filledOps);

        return Task.FromResult(ptr);
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
            return TryReadOpPayloadFromStream(fs, offset32, key, out payload, Encryption);
        }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    // ── IDisposable ───────────────────────────────────────────────────────────

    public void Dispose()
    {
        lock (_writeLock)
        {
            if (_disposed) return;
            _disposed = true;

            // Persist a snapshot on clean shutdown (V2 spec §5.3)
            if (_visibleCommitPtr != WalConstants.NullPtr)
            {
                try { WalSnapshot.Write(_directory, _visibleCommitPtr, HeadMap); }
                catch (Exception ex) when (ex is not OutOfMemoryException and not StackOverflowException)
                {
                    System.Diagnostics.Debug.WriteLine($"WalStore: snapshot on shutdown failed: {ex.GetType().Name}: {ex.Message}");
                }
            }

            _activeWriter?.WriteFooterAndClose();
            _activeWriter = null;
        }
        ProjectionManager.Dispose();
        KeyAllocator.Dispose();
        HeadMap.Dispose();
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// <summary>
    /// Reads all existing segments (newest → oldest) to rebuild the head map,
    /// optionally bootstrapping from a persisted snapshot to bound replay cost.
    /// Sets <see cref="_nextSegmentId"/> for the next new segment.
    /// </summary>
    private void Recover()
    {
        ulong snapshotPtr = WalConstants.NullPtr;

        // V2 spec §9: load latest snapshot first, then replay WAL tail only
        if (WalSnapshot.TryLoad(_directory, out snapshotPtr, out var snapKeys, out var snapHeads))
        {
            HeadMap.BulkLoad(snapKeys, snapHeads);
            Volatile.Write(ref _visibleCommitPtr, snapshotPtr);
        }

        var segments = DiscoverSegments();  // sorted descending

        // Build head map from newest segment to oldest.
        // Use Dictionary (O(1) inserts) instead of SortedDictionary (O(log n) inserts)
        // and sort once at the end for BulkLoad.
        var headEntries = new Dictionary<ulong, ulong>();

        foreach (var (segId, filePath) in segments)
        {
            Dictionary<ulong, uint>? index = WalSegmentReader.TryReadFooterIndex(filePath)
                                          ?? WalSegmentReader.LinearScanIndex(filePath);

            foreach (var (key, offset32) in index)
            {
                ulong ptr = WalConstants.PackPtr(segId, offset32);

                // Prefer WAL-derived ptr over snapshot ptr (WAL is authoritative for the tail)
                if (!headEntries.ContainsKey(key))
                    headEntries[key] = ptr;
            }
        }

        if (headEntries.Count > 0)
        {
            // Build sorted arrays from WAL-derived heads
            var keys  = new ulong[headEntries.Count];
            var heads = new ulong[headEntries.Count];
            int i = 0;
            foreach (var kv in headEntries) { keys[i] = kv.Key; heads[i] = kv.Value; i++; }

            // Sort by key for BulkLoad/BatchSetHeads (single sort vs O(n log n) SortedDictionary inserts)
            Array.Sort(keys, heads);

            if (_visibleCommitPtr == WalConstants.NullPtr)
            {
                // No snapshot — just bulk-load the WAL-derived heads directly
                HeadMap.BulkLoad(keys, heads);
            }
            else
            {
                // Snapshot was loaded — merge WAL heads on top (single write-lock)
                HeadMap.BatchSetHeads(keys.AsSpan(), heads);
            }
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
        ulong targetKey, out ReadOnlyMemory<byte> payload, WalEnvelopeEncryption? encryption = null)
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

        uint totalBytes = BinaryPrimitives.ReadUInt32LittleEndian(recHdr[8..]);
        long minSize = WalConstants.RecordHeaderBytes + WalConstants.RecordTrailerBytes;
        if (totalBytes < minSize || offset32 + totalBytes > fs.Length) return false;

        // Read entire record for CRC verification
        fs.Seek(offset32, SeekOrigin.Begin);
        var recordBuf = new byte[totalBytes];
        if (fs.Read(recordBuf) != (int)totalBytes) return false;

        if (!WalSegmentReader.VerifyRecordCrc(recordBuf)) return false;

        // Parse commit batch from the verified buffer
        var span = recordBuf.AsSpan();
        int off = WalConstants.RecordHeaderBytes;

        // Commit batch header: TxId(8)+OpCount(4)+PayloadFlags(4) = 16
        if (off + 16 > span.Length) return false;
        uint opCount = BinaryPrimitives.ReadUInt32LittleEndian(span[(off + 8)..]);
        off += 16;

        for (uint i = 0; i < opCount; i++)
        {
            if (off + 44 > span.Length) return false;

            ulong key           = BinaryPrimitives.ReadUInt64LittleEndian(span[off..]);
            uint  compressedLen = BinaryPrimitives.ReadUInt32LittleEndian(span[(off + 32)..]);

            if (key == targetKey)
            {
                ushort codec           = BinaryPrimitives.ReadUInt16LittleEndian(span[(off + 26)..]);
                uint   uncompressedLen = BinaryPrimitives.ReadUInt32LittleEndian(span[(off + 28)..]);
                off += 44;

                if (codec != WalConstants.CodecNone && codec != WalConstants.CodecBrotli
                    && codec != WalConstants.CodecEncryptedNone && codec != WalConstants.CodecEncryptedBrotli)
                    throw new System.IO.InvalidDataException(
                        $"Unknown WAL op codec 0x{codec:X4} for key 0x{key:X16}.");

                if (compressedLen == 0) { payload = ReadOnlyMemory<byte>.Empty; return true; }
                if (off + compressedLen > span.Length) return false;

                var raw = span.Slice(off, (int)compressedLen).ToArray();
                payload = WalPayloadCodec.Decompress(raw, codec, uncompressedLen, encryption);
                return true;
            }

            off += 44 + (int)compressedLen;
            if (off > span.Length) return false;
        }

        return false;
    }
}
