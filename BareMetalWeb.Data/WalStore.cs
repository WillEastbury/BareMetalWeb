using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

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

    /// <summary>Maximum allowed compressed payload size (100 MB) to prevent OOM from corrupt data.</summary>
    private const int MaxPayloadSize = 100_000_000;

    private readonly string _directory;
    private readonly uint   _maxSegmentBytes;
    private readonly object _writeLock = new();
    internal readonly WalEnvelopeEncryption Encryption;

    /// <summary>
    /// When true, each commit performs an fsync to guarantee on-disk durability.
    /// When false (default), data is flushed to OS page cache only — safe against
    /// process crash but not power loss. Set to true for full durability on
    /// unreliable storage.
    /// </summary>
    public bool ForceDiskSync { get; set; }

    private WalSegmentWriter? _activeWriter;
    private uint _nextSegmentId;
    private ulong _nextTxId = 1;
    private ulong _visibleCommitPtr;
    private bool _disposed;

    // #1240: Cached read handles per segment — RandomAccess.Read is thread-safe
    private readonly ConcurrentDictionary<uint, SafeFileHandle> _readerHandles = new();

    // Memory-mapped segment cache for zero-overhead reads via OS page cache
    private readonly MappedSegmentCache _mappedSegments;

    // ── Public surface ────────────────────────────────────────────────────────

    /// <summary>In-memory head map: key → Ptr of the latest committed record for that key.</summary>
    public WalHeadMap HeadMap { get; } = new();

    /// <summary>In-memory segment index: segmentId → set of WAL keys in that segment.</summary>
    public WalSegmentIndex SegmentIndex { get; } = new();

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

    /// <summary>The directory containing segment files (internal for compaction).</summary>
    internal string SegmentDirectory => _directory;

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
        _mappedSegments  = new MappedSegmentCache(directory);
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

        // #1248: Disk space check before writing
        CheckDiskSpace();

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

            // Write record; fsync only when ForceDiskSync is enabled (#1245)
            ptr = _activeWriter.AppendCommitBatch(txId, filledOps);
            _activeWriter.Flush(flushToDisk: ForceDiskSync);

            // Batch head map update — single write-lock instead of N
            Span<ulong> opKeys = stackalloc ulong[filledOps.Length];
            for (int i = 0; i < filledOps.Length; i++)
                opKeys[i] = filledOps[i].Key;
            HeadMap.BatchSetHeads(opKeys, ptr);

            // Maintain segment index
            var (newSegId, _) = WalConstants.UnpackPtr(ptr);
            for (int i = 0; i < filledOps.Length; i++)
            {
                if (filledOps[i].PrevPtr != WalConstants.NullPtr)
                {
                    var (oldSegId, _) = WalConstants.UnpackPtr(filledOps[i].PrevPtr);
                    SegmentIndex.Move(filledOps[i].Key, oldSegId, newSegId);
                }
                else
                {
                    SegmentIndex.Add(filledOps[i].Key, newSegId);
                }
            }

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

        try
        {
            // Try memory-mapped path first (zero open overhead)
            var mapped = _mappedSegments.GetOrCreate(segId);
            if (mapped != null)
            {
                try
                {
                    var buffer = mapped.ReadRecord(offset32, out int totalBytes);
                    if (buffer != null)
                    {
                        try
                        {
                            return TryExtractPayloadFromRecord(
                                buffer.AsSpan(0, totalBytes), key, out payload, Encryption);
                        }
                        finally
                        {
                            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
                        }
                    }
                }
                catch (ObjectDisposedException) { /* segment evicted during read — fall through */ }
            }

            // Fallback to SafeFileHandle path
            var handle = GetOrOpenReaderHandle(segId);
            if (handle == null) return false;
            return TryReadOpPayloadFromHandle(handle, offset32, key, out payload, Encryption);
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

        // #1240: Close all cached reader handles
        foreach (var kvp in _readerHandles)
        {
            try { kvp.Value.Dispose(); } catch { /* best-effort */ }
        }
        _readerHandles.Clear();

        _mappedSegments.Dispose();

        ProjectionManager.Dispose();
        KeyAllocator.Dispose();
        HeadMap.Dispose();
        SegmentIndex.Dispose();
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

        // Rebuild segment index from head map
        HeadMap.CopyArrays(out var skeys, out var sheads);
        for (int i = 0; i < skeys.Length; i++)
        {
            var (segId, _) = WalConstants.UnpackPtr(sheads[i]);
            SegmentIndex.Add(skeys[i], segId);
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

    /// <summary>#1248: Ensure at least 50 MB of free disk space before writes.</summary>
    private const long MinFreeDiskBytes = 50L * 1024 * 1024;
    private void CheckDiskSpace()
    {
        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(_directory));
            if (root == null) return;
            var drive = new DriveInfo(root);
            if (drive.IsReady && drive.AvailableFreeSpace < MinFreeDiskBytes)
            {
                throw new IOException(
                    $"Insufficient disk space for WAL write. Available: {drive.AvailableFreeSpace / (1024 * 1024)} MB, required: {MinFreeDiskBytes / (1024 * 1024)} MB");
            }
        }
        catch (IOException) { throw; }
        catch { /* DriveInfo may fail on some platforms — allow write to proceed */ }
    }

    /// <summary>
    /// #1240: Returns a cached SafeFileHandle for the given segment, opening it on first access.
    /// RandomAccess.Read with SafeFileHandle is thread-safe — no locking needed per read.
    /// </summary>
    private SafeFileHandle? GetOrOpenReaderHandle(uint segId)
    {
        if (_readerHandles.TryGetValue(segId, out var cached))
            return cached;

        string path = Path.Combine(_directory, WalConstants.SegmentFileName(segId));
        if (!File.Exists(path)) return null;

        var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        if (_readerHandles.TryAdd(segId, handle))
            return handle;

        // Another thread won the race — dispose our handle and use theirs
        handle.Dispose();
        return _readerHandles[segId];
    }

    /// <summary>
    /// #1240: Evict and close a cached reader handle for a segment about to be deleted.
    /// Called during compaction before File.Delete.
    /// </summary>
    internal void EvictReaderHandle(uint segId)
    {
        if (_readerHandles.TryRemove(segId, out var handle))
            handle.Dispose();
    }

    /// <summary>
    /// Forces a segment rotation (closes the active writer, starts a new segment).
    /// Exposed as <c>internal</c> so unit tests can ensure a segment is no longer
    /// active before calling <see cref="CompactSegmentFromMaterialisedView"/>.
    /// </summary>
    internal void RotateSegmentForTest()
    {
        lock (_writeLock)
        {
            EnsureActiveWriter();
            RotateSegment();
        }
    }

    // ── Compaction ─────────────────────────────────────────────────────────────

    /// <summary>
    /// Compacts a single WAL segment by rewriting it with only the latest version of each
    /// key whose head pointer still references this segment (the materialised-view approach).
    /// Tombstones are dropped.  Must not be called on the active segment.
    /// </summary>
    public void CompactSegment(uint segmentId)
    {
        string originalPath = Path.Combine(_directory, WalConstants.SegmentFileName(segmentId));
        if (!File.Exists(originalPath)) return;

        long startTicks = EngineMetrics.StartTiming();
        long originalSize = new FileInfo(originalPath).Length;

        // ── 1. Get keys from segment index ────────────────────────────────
        SegmentIndex.GetKeys(segmentId, out ulong[] matchKeys);

        if (matchKeys.Length == 0)
        {
            // No live keys reference this segment — it can be deleted
            EvictReaderHandle(segmentId);
            _mappedSegments.Evict(segmentId);
            try { File.Delete(originalPath); } catch { /* best effort */ }
            EngineMetrics.RecordCompaction(EngineMetrics.ElapsedUs(startTicks), originalSize);
            return;
        }

        // ── 2. Look up head pointers for each key ──────────────────────────
        var matchHeads = new ulong[matchKeys.Length];
        for (int i = 0; i < matchKeys.Length; i++)
        {
            HeadMap.TryGetHead(matchKeys[i], out matchHeads[i]);
        }

        // ── 3. Read payloads from disk, skipping tombstones ─────────────────
        var ops    = new WalOp[matchKeys.Length];
        var opKeys = new ulong[matchKeys.Length]; // keys for head map update
        int opCount = 0;
        var deadKeys = new ulong[matchKeys.Length]; // keys to remove from segment index
        int deadCount = 0;

        for (int i = 0; i < matchKeys.Length; i++)
        {
            if (!TryReadFullOp(matchHeads[i], matchKeys[i], out WalOp op))
            {
                deadKeys[deadCount++] = matchKeys[i];
                continue;
            }
            if (op.OpType == WalConstants.OpTypeDeleteTombstone)
            {
                deadKeys[deadCount++] = matchKeys[i];
                continue;
            }

            ops[opCount]    = op;
            opKeys[opCount] = matchKeys[i];
            opCount++;
        }

        // Remove dead keys from segment index
        for (int i = 0; i < deadCount; i++)
            SegmentIndex.Remove(deadKeys[i], segmentId);

        if (opCount == 0)
        {
            // All entries were tombstones — delete the segment
            EvictReaderHandle(segmentId);
            _mappedSegments.Evict(segmentId);
            try { File.Delete(originalPath); } catch { /* best effort */ }
            EngineMetrics.RecordCompaction(EngineMetrics.ElapsedUs(startTicks), originalSize);
            return;
        }

        // ── 4. Write compacted segment to a temp file ───────────────────────
        string tmpPath = originalPath + ".compact";
        var newPtrs = new ulong[opCount];

        try
        {
            using (var writer = new WalSegmentWriter(tmpPath, segmentId))
            {
                // Write all surviving ops as a single commit batch
                var batch = new WalOp[opCount];
                Array.Copy(ops, batch, opCount);

                ulong ptr = writer.AppendCommitBatch(0, batch);

                // All ops in the batch share the same record offset (same commit batch)
                for (int i = 0; i < opCount; i++)
                    newPtrs[i] = ptr;

                writer.WriteFooterAndClose();
            }

            // ── 5. Fsync temp file, then atomic rename ──────────────────────
            // Fsync is handled by WriteFooterAndClose above.
            // Atomic rename over the original segment.
            EvictReaderHandle(segmentId);
            _mappedSegments.Evict(segmentId);
            File.Move(tmpPath, originalPath, overwrite: true);
        }
        catch
        {
            // Clean up temp file on failure
            try { File.Delete(tmpPath); } catch { /* best effort */ }
            throw;
        }

        // ── 6. Update head map under write lock ─────────────────────────────
        lock (_writeLock)
        {
            // Re-check: only update pointers that still reference this segment.
            // A concurrent commit may have moved some keys to a newer segment.
            for (int i = 0; i < opCount; i++)
            {
                if (HeadMap.TryGetHead(opKeys[i], out ulong currentPtr))
                {
                    var (curSeg, _) = WalConstants.UnpackPtr(currentPtr);
                    if (curSeg == segmentId)
                        HeadMap.SetHead(opKeys[i], newPtrs[i]);
                }
            }
        }

        // ── 7. Record metrics ───────────────────────────────────────────────
        long newSize = File.Exists(originalPath) ? new FileInfo(originalPath).Length : 0;
        long reclaimed = originalSize - newSize;
        if (reclaimed < 0) reclaimed = 0;
        EngineMetrics.RecordCompaction(EngineMetrics.ElapsedUs(startTicks), reclaimed);
    }

    /// <summary>
    /// Compacts the given segment by rebuilding it from the in-memory materialised view
    /// (HeadMap + targeted disk reads).  No full sequential read of the original segment
    /// is performed; only the latest version of each live key is written.
    ///
    /// Algorithm:
    /// <list type="number">
    ///   <item>Snapshot the HeadMap to find all walKeys whose latest pointer is in
    ///         <paramref name="segmentId"/>.</item>
    ///   <item>For each such key, read the raw op bytes via a targeted seek (no full
    ///         segment scan, no decompression/recompression).</item>
    ///   <item>Write each op as a single-op commit batch to a <c>.compact</c> temp file,
    ///         tracking each key's new file offset.</item>
    ///   <item>Under the write lock: atomically rename <c>.compact</c> → <c>.log</c>,
    ///         then update the HeadMap with the new offsets for keys that have not
    ///         been superseded by a newer commit since the snapshot was taken.</item>
    ///   <item>Fsync the WAL directory for durability of the rename.</item>
    /// </list>
    ///
    /// Thread-safety: concurrent readers continue reading the old segment file via
    /// file-name-based open until the atomic rename completes.  The HeadMap is updated
    /// in the same write-lock window as the rename, so the window of inconsistency is
    /// bounded to microseconds.  Keys committed to a newer segment after the HeadMap
    /// snapshot was taken are skipped, preserving correctness.
    ///
    /// Precondition: <paramref name="segmentId"/> must not be the currently active
    /// (still-being-written) segment.
    /// </summary>
    public void CompactSegmentFromMaterialisedView(uint segmentId)
    {
        // Guard: never compact the active segment (quick optimistic check outside lock)
        lock (_writeLock)
        {
            if (_disposed) return;
            if (_activeWriter != null && _activeWriter.SegmentId == segmentId) return;
        }

        string segPath = Path.Combine(_directory, WalConstants.SegmentFileName(segmentId));
        string tmpPath = segPath + ".compact";

        // Step 1: Snapshot HeadMap — find all walKeys whose HEAD is in targetSegment.
        // #1166: CopyArrays is intentionally called outside the write lock for
        // throughput.  Safety is guaranteed by the segment-ID guard in Step 4:
        // SetHead (BatchSetHeads) only updates entries whose current head still
        // points to this segment.  If a concurrent write moved the head to a
        // newer segment between the snapshot and the lock acquisition, the stale
        // entry is simply skipped, so no data is lost.
        HeadMap.CopyArrays(out ulong[] allKeys, out ulong[] allHeads);

        int matchCount = 0;
        for (int i = 0; i < allKeys.Length; i++)
        {
            if ((uint)(allHeads[i] >> 32) == segmentId) matchCount++;
        }

        if (matchCount == 0) return;

        var targetWalKeys = new ulong[matchCount];
        var targetOffsets = new uint[matchCount];
        int fill = 0;
        for (int i = 0; i < allKeys.Length; i++)
        {
            if ((uint)(allHeads[i] >> 32) == segmentId)
            {
                targetWalKeys[fill] = allKeys[i];
                targetOffsets[fill] = (uint)(allHeads[i] & 0xFFFF_FFFFu);
                fill++;
            }
        }

        // Step 2: Read raw ops for each target key via targeted seeks (outside lock).
        var rawOps  = new WalOp[matchCount];
        var rawKeys = new ulong[matchCount];
        int rawCount = 0;

        if (!File.Exists(segPath)) return;

        try
        {
            using var srcFile = new FileStream(segPath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite, 65536, FileOptions.RandomAccess);

            for (int i = 0; i < matchCount; i++)
            {
                // #1168: Delete tombstones are excluded here so compacted segments
                // contain only live upserts.  The HeadMap segment-ID guard in
                // Step 4 ensures a tombstone from an older segment can never
                // override a newer upsert whose head already moved to a different
                // segment — the HeadMap is authoritative.
                if (TryReadRawOpFromStream(srcFile, targetOffsets[i], targetWalKeys[i], out WalOp rawOp)
                    && rawOp.OpType != WalConstants.OpTypeDeleteTombstone)
                {
                    rawOps[rawCount]  = rawOp;
                    rawKeys[rawCount] = targetWalKeys[i];
                    rawCount++;
                }
            }
        }
        catch (FileNotFoundException) { return; }
        catch (IOException)           { return; }

        if (rawCount == 0) return;

        // Step 3: Write compacted segment to tmpPath (outside the write lock).
        if (File.Exists(tmpPath)) File.Delete(tmpPath);

        var newPtrs = new ulong[rawCount];
        var singleOpBatch = new WalOp[1];
        using (var tmpWriter = new WalSegmentWriter(tmpPath, segmentId))
        {
            for (int i = 0; i < rawCount; i++)
            {
                singleOpBatch[0] = rawOps[i];
                newPtrs[i]       = tmpWriter.AppendCommitBatch(0UL, singleOpBatch);
            }
            tmpWriter.Flush(flushToDisk: true);
            tmpWriter.WriteFooterAndClose();
        }

        // Step 4: Under the write lock — atomic rename then HeadMap update.
        lock (_writeLock)
        {
            if (_disposed)           { TryDeleteFile(tmpPath); return; }
            if (_activeWriter != null && _activeWriter.SegmentId == segmentId)
            {
                TryDeleteFile(tmpPath);
                return;
            }

            // Evict cached handles/mappings before atomic rename
            EvictReaderHandle(segmentId);
            _mappedSegments.Evict(segmentId);
            File.Move(tmpPath, segPath, overwrite: true);

            int updateCount = 0;
            var updateKeys = new ulong[rawCount];
            var updatePtrs = new ulong[rawCount];

            for (int i = 0; i < rawCount; i++)
            {
                ulong walKey = rawKeys[i];
                if (HeadMap.TryGetHead(walKey, out ulong currentPtr)
                    && (uint)(currentPtr >> 32) == segmentId)
                {
                    updateKeys[updateCount] = walKey;
                    updatePtrs[updateCount] = newPtrs[i];
                    updateCount++;
                }
            }

            if (updateCount > 0)
            {
                Array.Sort(updateKeys, updatePtrs, 0, updateCount);
                HeadMap.BatchSetHeads(
                    new ReadOnlySpan<ulong>(updateKeys, 0, updateCount),
                    new ReadOnlySpan<ulong>(updatePtrs, 0, updateCount));
            }
        }

        // Step 5: Fsync the directory so the rename is durable
        FsyncDirectory(_directory);
    }

    /// <summary>
    /// Returns the segment ID of the currently active (being-written-to) segment,
    /// or <c>null</c> if no segment is active.
    /// </summary>
    internal uint? ActiveSegmentId
    {
        get
        {
            lock (_writeLock)
            {
                return _activeWriter?.SegmentId;
            }
        }
    }

    /// <summary>
    /// Returns all segment IDs discovered on disk, sorted ascending.
    /// </summary>
    internal List<uint> GetSegmentIds()
    {
        var list = new List<uint>();
        foreach (string file in Directory.EnumerateFiles(_directory, "wal_seg_*.log"))
        {
            string name = Path.GetFileName(file);
            if (WalConstants.TryParseSegmentId(name, out uint segId))
                list.Add(segId);
        }
        list.Sort();
        return list;
    }

    /// <summary>
    /// Reads the full <see cref="WalOp"/> (including OpType, Codec, SchemaSignature, Flags)
    /// for a given key at the specified pointer. Used by compaction to preserve op metadata.
    /// </summary>
    private bool TryReadFullOp(ulong ptr, ulong key, out WalOp op)
    {
        op = default;
        if (ptr == WalConstants.NullPtr) return false;

        var (segId, offset32) = WalConstants.UnpackPtr(ptr);

        try
        {
            // Try memory-mapped path first
            var mapped = _mappedSegments.GetOrCreate(segId);
            if (mapped != null)
            {
                try
                {
                    var buffer = mapped.ReadRecord(offset32, out int totalBytes);
                    if (buffer != null)
                    {
                        try
                        {
                            return TryExtractFullOpFromRecord(
                                buffer.AsSpan(0, totalBytes), key, out op, Encryption);
                        }
                        finally
                        {
                            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
                        }
                    }
                }
                catch (ObjectDisposedException) { /* segment evicted — fall through */ }
            }

            // Fallback to SafeFileHandle path
            var handle = GetOrOpenReaderHandle(segId);
            if (handle == null) return false;
            return TryReadFullOpFromHandle(handle, offset32, key, out op, Encryption);
        }
        catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }

    private static bool TryReadFullOpFromHandle(SafeFileHandle handle, uint offset32,
        ulong targetKey, out WalOp op, WalEnvelopeEncryption? encryption = null)
    {
        op = default;

        long fileLength = RandomAccess.GetLength(handle);
        if (offset32 + WalConstants.RecordHeaderBytes > fileLength) return false;

        Span<byte> recHdr = stackalloc byte[WalConstants.RecordHeaderBytes];
        if (RandomAccess.Read(handle, recHdr, offset32) != WalConstants.RecordHeaderBytes) return false;

        if (BinaryPrimitives.ReadUInt32LittleEndian(recHdr[0..]) != WalConstants.RecordMagic)
            return false;
        if (BinaryPrimitives.ReadUInt16LittleEndian(recHdr[4..]) != WalConstants.RecordTypeCommitBatch)
            return false;

        uint totalBytes = BinaryPrimitives.ReadUInt32LittleEndian(recHdr[8..]);
        long minSize = WalConstants.RecordHeaderBytes + WalConstants.RecordTrailerBytes;
        if (totalBytes < minSize || offset32 + totalBytes > fileLength) return false;

        var recordBuf = new byte[totalBytes];
        if (RandomAccess.Read(handle, recordBuf, offset32) != (int)totalBytes) return false;

        if (!WalSegmentReader.VerifyRecordCrc(recordBuf)) return false;

        var span = recordBuf.AsSpan();
        int off = WalConstants.RecordHeaderBytes;

        if (off + 16 > span.Length) return false;
        uint opCount = BinaryPrimitives.ReadUInt32LittleEndian(span[(off + 8)..]);
        off += 16;

        for (uint i = 0; i < opCount; i++)
        {
            if (off + 44 > span.Length) return false;

            ulong key             = BinaryPrimitives.ReadUInt64LittleEndian(span[off..]);
            ulong prevPtr         = BinaryPrimitives.ReadUInt64LittleEndian(span[(off + 8)..]);
            ulong schemaSig       = BinaryPrimitives.ReadUInt64LittleEndian(span[(off + 16)..]);
            ushort opType         = BinaryPrimitives.ReadUInt16LittleEndian(span[(off + 24)..]);
            ushort codec          = BinaryPrimitives.ReadUInt16LittleEndian(span[(off + 26)..]);
            uint   uncompressedLen = BinaryPrimitives.ReadUInt32LittleEndian(span[(off + 28)..]);
            uint   compressedLen  = BinaryPrimitives.ReadUInt32LittleEndian(span[(off + 32)..]);
            uint   flags          = BinaryPrimitives.ReadUInt32LittleEndian(span[(off + 36)..]);

            if (key == targetKey)
            {
                off += 44;

                ReadOnlyMemory<byte> payload;
                if (compressedLen == 0)
                {
                    payload = ReadOnlyMemory<byte>.Empty;
                }
                else
                {
                    if (compressedLen > MaxPayloadSize) return false;
                    if (off + compressedLen > span.Length) return false;
                    // Keep raw compressed payload — avoids decompress/recompress round-trip
                    payload = span.Slice(off, (int)compressedLen).ToArray();
                }

                op = new WalOp
                {
                    Key             = key,
                    PrevPtr         = WalConstants.NullPtr, // compacted; no chain
                    SchemaSignature = schemaSig,
                    OpType          = opType,
                    Codec           = codec,
                    UncompressedLen = uncompressedLen,
                    Flags           = flags,
                    Payload         = payload,
                };
                return true;
            }

            off += 44 + (int)compressedLen;
            if (off > span.Length) return false;
        }

        return false;
    }

    /// <summary>
    /// Reads the raw (potentially compressed) op entry for <paramref name="targetKey"/>
    /// from the commit-batch record at <paramref name="offset32"/> without decompression.
    /// Uses pooled buffers to avoid per-call heap allocations.
    /// </summary>
    private static bool TryReadRawOpFromStream(FileStream fs, uint offset32,
        ulong targetKey, out WalOp op)
    {
        op = default;
        if (offset32 + WalConstants.RecordHeaderBytes > fs.Length) return false;

        fs.Seek(offset32, SeekOrigin.Begin);
        Span<byte> recHdr = stackalloc byte[WalConstants.RecordHeaderBytes];
        if (fs.Read(recHdr) != WalConstants.RecordHeaderBytes) return false;

        if (BinaryPrimitives.ReadUInt32LittleEndian(recHdr[0..]) != WalConstants.RecordMagic)
            return false;
        if (BinaryPrimitives.ReadUInt16LittleEndian(recHdr[4..]) != WalConstants.RecordTypeCommitBatch)
            return false;

        uint totalBytes = BinaryPrimitives.ReadUInt32LittleEndian(recHdr[8..]);
        long minSize    = (long)WalConstants.RecordHeaderBytes + WalConstants.RecordTrailerBytes;
        if (totalBytes < minSize || offset32 + totalBytes > fs.Length) return false;

        fs.Seek(offset32, SeekOrigin.Begin);
        byte[] pooled = ArrayPool<byte>.Shared.Rent((int)totalBytes);
        try
        {
            if (fs.Read(pooled, 0, (int)totalBytes) != (int)totalBytes) return false;
            if (!WalSegmentReader.VerifyRecordCrc(pooled.AsSpan(0, (int)totalBytes))) return false;

            var span = pooled.AsSpan(0, (int)totalBytes);
            int off  = WalConstants.RecordHeaderBytes;

            if (off + 16 > span.Length) return false;
            uint opCount = BinaryPrimitives.ReadUInt32LittleEndian(span[(off + 8)..]);
            off += 16;

            for (uint i = 0; i < opCount; i++)
            {
                if (off + 44 > span.Length) return false;

                ulong  key            = BinaryPrimitives.ReadUInt64LittleEndian(span[off..]);
                ulong  schemaSig      = BinaryPrimitives.ReadUInt64LittleEndian(span[(off + 16)..]);
                ushort opType         = BinaryPrimitives.ReadUInt16LittleEndian(span[(off + 24)..]);
                ushort codec          = BinaryPrimitives.ReadUInt16LittleEndian(span[(off + 26)..]);
                uint   uncompressedLen = BinaryPrimitives.ReadUInt32LittleEndian(span[(off + 28)..]);
                uint   compressedLen  = BinaryPrimitives.ReadUInt32LittleEndian(span[(off + 32)..]);
                uint   flags          = BinaryPrimitives.ReadUInt32LittleEndian(span[(off + 36)..]);
                if (compressedLen > int.MaxValue - 44) return false;
                off += 44;

                if (key == targetKey)
                {
                    if (compressedLen > MaxPayloadSize) return false;
                    if (off + compressedLen > span.Length) return false;

                    byte[] rawPayload = compressedLen > 0
                        ? span.Slice(off, (int)compressedLen).ToArray()
                        : [];

                    op = new WalOp
                    {
                        Key             = key,
                        PrevPtr         = WalConstants.NullPtr,
                        SchemaSignature = schemaSig,
                        OpType          = opType,
                        Codec           = codec,
                        UncompressedLen = uncompressedLen,
                        Flags           = flags,
                        Payload         = rawPayload,
                    };
                    return true;
                }

                off = checked(off + (int)compressedLen);
                if (off > span.Length) return false;
            }

            return false;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(pooled, clearArray: true);
        }
    }

    /// <summary>
    /// Fsyncs the WAL directory to ensure the directory entry (rename) is durable.
    /// No-op on Windows where NTFS commits renames atomically to its own log.
    /// </summary>
    private static void FsyncDirectory(string directory)
    {
        if (OperatingSystem.IsWindows()) return;
        try
        {
            using var d = new FileStream(directory, FileMode.Open,
                FileAccess.Read, FileShare.ReadWrite);
            d.Flush(flushToDisk: true);
        }
        catch (IOException)              { /* best-effort */ }
        catch (UnauthorizedAccessException) { /* best-effort */ }
    }

    private static void TryDeleteFile(string path)
    {
        try { File.Delete(path); }
        catch (IOException) { /* best-effort */ }
    }

    // ── Read-back internals ───────────────────────────────────────────────────

    private static bool TryReadOpPayloadFromHandle(SafeFileHandle handle, uint offset32,
        ulong targetKey, out ReadOnlyMemory<byte> payload, WalEnvelopeEncryption? encryption = null)
    {
        payload = default;

        long fileLength = RandomAccess.GetLength(handle);
        if (offset32 + WalConstants.RecordHeaderBytes > fileLength) return false;

        Span<byte> recHdr = stackalloc byte[WalConstants.RecordHeaderBytes];
        if (RandomAccess.Read(handle, recHdr, offset32) != WalConstants.RecordHeaderBytes) return false;

        if (BinaryPrimitives.ReadUInt32LittleEndian(recHdr[0..]) != WalConstants.RecordMagic)
            return false;
        if (BinaryPrimitives.ReadUInt16LittleEndian(recHdr[4..]) != WalConstants.RecordTypeCommitBatch)
            return false;

        uint totalBytes = BinaryPrimitives.ReadUInt32LittleEndian(recHdr[8..]);
        long minSize = WalConstants.RecordHeaderBytes + WalConstants.RecordTrailerBytes;
        if (totalBytes < minSize || offset32 + totalBytes > fileLength) return false;

        // Read entire record for CRC verification
        var recordBuf = new byte[totalBytes];
        if (RandomAccess.Read(handle, recordBuf, offset32) != (int)totalBytes) return false;

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
                if (compressedLen > MaxPayloadSize) return false;
                if (off + compressedLen > span.Length) return false;

                var raw = span.Slice(off, (int)compressedLen).ToArray();
                payload = WalPayloadCodec.Decompress(raw, codec, uncompressedLen, encryption);
                return true;
            }

            if (compressedLen > int.MaxValue - 44) return false;
            off = checked(off + 44 + (int)compressedLen);
            if (off > span.Length) return false;
        }

        return false;
    }

    /// <summary>
    /// Extracts a key's payload from a pre-read, CRC-verified record buffer.
    /// Shared by both the mmap and SafeFileHandle read paths.
    /// </summary>
    private static bool TryExtractPayloadFromRecord(ReadOnlySpan<byte> record, ulong targetKey,
        out ReadOnlyMemory<byte> payload, WalEnvelopeEncryption? encryption = null)
    {
        payload = default;
        if (!WalSegmentReader.VerifyRecordCrc(record.ToArray())) return false;

        int off = WalConstants.RecordHeaderBytes;
        if (off + 16 > record.Length) return false;
        uint opCount = BinaryPrimitives.ReadUInt32LittleEndian(record[(off + 8)..]);
        off += 16;

        for (uint i = 0; i < opCount; i++)
        {
            if (off + 44 > record.Length) return false;
            ulong key           = BinaryPrimitives.ReadUInt64LittleEndian(record[off..]);
            uint  compressedLen = BinaryPrimitives.ReadUInt32LittleEndian(record[(off + 32)..]);

            if (key == targetKey)
            {
                ushort codec           = BinaryPrimitives.ReadUInt16LittleEndian(record[(off + 26)..]);
                uint   uncompressedLen = BinaryPrimitives.ReadUInt32LittleEndian(record[(off + 28)..]);
                off += 44;

                if (codec != WalConstants.CodecNone && codec != WalConstants.CodecBrotli
                    && codec != WalConstants.CodecEncryptedNone && codec != WalConstants.CodecEncryptedBrotli)
                    throw new InvalidDataException(
                        $"Unknown WAL op codec 0x{codec:X4} for key 0x{key:X16}.");

                if (compressedLen == 0) { payload = ReadOnlyMemory<byte>.Empty; return true; }
                if (compressedLen > MaxPayloadSize) return false;
                if (off + compressedLen > record.Length) return false;

                var raw = record.Slice(off, (int)compressedLen).ToArray();
                payload = WalPayloadCodec.Decompress(raw, codec, uncompressedLen, encryption);
                return true;
            }

            if (compressedLen > int.MaxValue - 44) return false;
            off = checked(off + 44 + (int)compressedLen);
            if (off > record.Length) return false;
        }
        return false;
    }

    /// <summary>
    /// Extracts a full <see cref="WalOp"/> from a pre-read, CRC-verified record buffer.
    /// Shared by both the mmap and SafeFileHandle read paths.
    /// </summary>
    private static bool TryExtractFullOpFromRecord(ReadOnlySpan<byte> record, ulong targetKey,
        out WalOp op, WalEnvelopeEncryption? encryption = null)
    {
        op = default;
        if (!WalSegmentReader.VerifyRecordCrc(record.ToArray())) return false;

        int off = WalConstants.RecordHeaderBytes;
        if (off + 16 > record.Length) return false;
        uint opCount = BinaryPrimitives.ReadUInt32LittleEndian(record[(off + 8)..]);
        off += 16;

        for (uint i = 0; i < opCount; i++)
        {
            if (off + 44 > record.Length) return false;

            ulong  key            = BinaryPrimitives.ReadUInt64LittleEndian(record[off..]);
            ulong  prevPtr        = BinaryPrimitives.ReadUInt64LittleEndian(record[(off + 8)..]);
            ulong  schemaSig      = BinaryPrimitives.ReadUInt64LittleEndian(record[(off + 16)..]);
            ushort opType         = BinaryPrimitives.ReadUInt16LittleEndian(record[(off + 24)..]);
            ushort codec          = BinaryPrimitives.ReadUInt16LittleEndian(record[(off + 26)..]);
            uint   uncompressedLen = BinaryPrimitives.ReadUInt32LittleEndian(record[(off + 28)..]);
            uint   compressedLen  = BinaryPrimitives.ReadUInt32LittleEndian(record[(off + 32)..]);
            uint   flags          = BinaryPrimitives.ReadUInt32LittleEndian(record[(off + 36)..]);
            if (compressedLen > int.MaxValue - 44) return false;
            off += 44;

            if (key == targetKey)
            {
                if (compressedLen > MaxPayloadSize) return false;
                if (off + compressedLen > record.Length) return false;

                byte[] rawPayload = compressedLen > 0
                    ? record.Slice(off, (int)compressedLen).ToArray()
                    : [];

                bool encrypted = codec == WalConstants.CodecEncryptedNone
                    || codec == WalConstants.CodecEncryptedBrotli;

                op = new WalOp
                {
                    Key             = key,
                    PrevPtr         = prevPtr,
                    SchemaSignature = schemaSig,
                    OpType          = opType,
                    Codec           = codec,
                    UncompressedLen = uncompressedLen,
                    Flags           = flags,
                    Payload         = rawPayload,
                };
                return true;
            }

            off = checked(off + (int)compressedLen);
            if (off > record.Length) return false;
        }
        return false;
    }
}
