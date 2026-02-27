using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Unit tests for the WAL-backed log-structured record store.
/// Covers: key/ptr packing, CRC32C, head map, segment write/read, commit, recovery.
/// </summary>
public sealed class WalStoreTests : IDisposable
{
    private readonly string _dir;

    public WalStoreTests()
    {
        _dir = Path.Combine(Path.GetTempPath(), "BmwWalTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_dir);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true); }
        catch { /* best-effort */ }
    }

    // ── Key / Pointer packing ────────────────────────────────────────────────

    [Fact]
    public void PackKey_RoundTrip()
    {
        uint tableId = 0xDEAD_BEEFu;
        uint recordId = 0x0000_1234u;
        ulong key = WalConstants.PackKey(tableId, recordId);
        var (t2, r2) = WalConstants.UnpackKey(key);
        Assert.Equal(tableId,  t2);
        Assert.Equal(recordId, r2);
    }

    [Fact]
    public void PackPtr_RoundTrip()
    {
        uint segId   = 42u;
        uint offset  = 0x0001_0000u;
        ulong ptr = WalConstants.PackPtr(segId, offset);
        var (s2, o2) = WalConstants.UnpackPtr(ptr);
        Assert.Equal(segId,  s2);
        Assert.Equal(offset, o2);
    }

    [Fact]
    public void PackKey_ZeroValues()
    {
        ulong key = WalConstants.PackKey(0, 0);
        Assert.Equal(0uL, key);
        var (t, r) = WalConstants.UnpackKey(key);
        Assert.Equal(0u, t);
        Assert.Equal(0u, r);
    }

    [Fact]
    public void PackKey_MaxValues()
    {
        ulong key = WalConstants.PackKey(uint.MaxValue, uint.MaxValue);
        Assert.Equal(ulong.MaxValue, key);
        var (t, r) = WalConstants.UnpackKey(key);
        Assert.Equal(uint.MaxValue, t);
        Assert.Equal(uint.MaxValue, r);
    }

    [Fact]
    public void SegmentFileName_Format()
    {
        Assert.Equal("wal_seg_0000000000.log", WalConstants.SegmentFileName(0));
        Assert.Equal("wal_seg_0000000001.log", WalConstants.SegmentFileName(1));
        Assert.Equal("wal_seg_4294967295.log", WalConstants.SegmentFileName(uint.MaxValue));
    }

    [Fact]
    public void TryParseSegmentId_Valid()
    {
        Assert.True(WalConstants.TryParseSegmentId("wal_seg_0000000007.log", out uint id));
        Assert.Equal(7u, id);
    }

    [Fact]
    public void TryParseSegmentId_Invalid()
    {
        Assert.False(WalConstants.TryParseSegmentId("not_a_segment.log",  out _));
        Assert.False(WalConstants.TryParseSegmentId("wal_seg_ABCDEFGHIJ.log", out _));
        Assert.False(WalConstants.TryParseSegmentId("wal_seg_12.log",     out _));
    }

    // ── CRC32C ───────────────────────────────────────────────────────────────

    [Fact]
    public void Crc32C_EmptySpan_IsZero()
    {
        uint crc = WalCrc32C.Compute(ReadOnlySpan<byte>.Empty);
        Assert.Equal(0u, crc);
    }

    [Fact]
    public void Crc32C_KnownVector_123456789()
    {
        // CRC-32C of ASCII "123456789" = 0xE3069283
        byte[] data = Encoding.ASCII.GetBytes("123456789");
        uint crc = WalCrc32C.Compute(data);
        Assert.Equal(0xE306_9283u, crc);
    }

    [Fact]
    public void Crc32C_Deterministic()
    {
        byte[] data = Encoding.UTF8.GetBytes("Hello, WAL!");
        uint c1 = WalCrc32C.Compute(data);
        uint c2 = WalCrc32C.Compute(data);
        Assert.Equal(c1, c2);
    }

    [Fact]
    public void Crc32C_DifferentData_DifferentCrc()
    {
        uint c1 = WalCrc32C.Compute(new byte[] { 0x01 });
        uint c2 = WalCrc32C.Compute(new byte[] { 0x02 });
        Assert.NotEqual(c1, c2);
    }

    // ── WalHeadMap ───────────────────────────────────────────────────────────

    [Fact]
    public void HeadMap_SetAndGet_SingleKey()
    {
        using var map = new WalHeadMap();
        ulong key = WalConstants.PackKey(1, 100);
        ulong ptr = WalConstants.PackPtr(0, 16);
        map.SetHead(key, ptr);
        Assert.True(map.TryGetHead(key, out ulong got));
        Assert.Equal(ptr, got);
    }

    [Fact]
    public void HeadMap_MissingKey_ReturnsFalse()
    {
        using var map = new WalHeadMap();
        Assert.False(map.TryGetHead(0xDEAD_BEEFul, out ulong ptr));
        Assert.Equal(WalConstants.NullPtr, ptr);
    }

    [Fact]
    public void HeadMap_Update_OverwritesExisting()
    {
        using var map = new WalHeadMap();
        ulong key  = WalConstants.PackKey(2, 200);
        ulong ptr1 = WalConstants.PackPtr(0, 16);
        ulong ptr2 = WalConstants.PackPtr(1, 32);
        map.SetHead(key, ptr1);
        map.SetHead(key, ptr2);
        Assert.True(map.TryGetHead(key, out ulong got));
        Assert.Equal(ptr2, got);
    }

    [Fact]
    public void HeadMap_MultipleKeys_SortedBinarySearch()
    {
        using var map = new WalHeadMap();
        // Insert out-of-order
        for (uint r = 10; r >= 1; r--)
        {
            ulong key = WalConstants.PackKey(0, r);
            ulong ptr = WalConstants.PackPtr(0, r * 100);
            map.SetHead(key, ptr);
        }
        Assert.Equal(10, map.Count);
        for (uint r = 1; r <= 10; r++)
        {
            Assert.True(map.TryGetHead(WalConstants.PackKey(0, r), out ulong ptr));
            Assert.Equal(WalConstants.PackPtr(0, r * 100), ptr);
        }
    }

    [Fact]
    public void HeadMap_BulkLoad_Roundtrip()
    {
        using var map = new WalHeadMap();
        var keys  = new ulong[] { 1, 5, 10, 100 };
        var heads = new ulong[] { 10, 50, 100, 1000 };
        map.BulkLoad(keys, heads);
        Assert.Equal(4, map.Count);
        Assert.True(map.TryGetHead(5, out ulong v));
        Assert.Equal(50uL, v);
    }

    // ── WalStore: basic commit ────────────────────────────────────────────────

    [Fact]
    public async Task CommitAsync_SingleOp_HeadMapUpdated()
    {
        using var store = new WalStore(_dir);
        ulong key     = WalConstants.PackKey(1, 42);
        var   payload = new byte[] { 0xAA, 0xBB, 0xCC };

        ulong ptr = await store.CommitAsync(new[] { WalOp.Upsert(key, payload) });

        Assert.NotEqual(WalConstants.NullPtr, ptr);
        Assert.True(store.TryGetHead(key, out ulong gotPtr));
        Assert.Equal(ptr, gotPtr);
    }

    [Fact]
    public async Task CommitAsync_MultipleOpsInOneBatch_AllKeysInHeadMap()
    {
        using var store = new WalStore(_dir);
        var ops = new[]
        {
            WalOp.Upsert(WalConstants.PackKey(1, 1), new byte[] { 1 }),
            WalOp.Upsert(WalConstants.PackKey(1, 2), new byte[] { 2 }),
            WalOp.Upsert(WalConstants.PackKey(1, 3), new byte[] { 3 }),
        };

        ulong ptr = await store.CommitAsync(ops);

        for (uint r = 1; r <= 3; r++)
        {
            Assert.True(store.TryGetHead(WalConstants.PackKey(1, r), out ulong p));
            Assert.Equal(ptr, p);
        }
    }

    [Fact]
    public async Task CommitAsync_SuccessiveCommits_LatestPtrWins()
    {
        using var store = new WalStore(_dir);
        ulong key = WalConstants.PackKey(3, 99);

        ulong ptr1 = await store.CommitAsync(new[] { WalOp.Upsert(key, new byte[] { 0x01 }) });
        ulong ptr2 = await store.CommitAsync(new[] { WalOp.Upsert(key, new byte[] { 0x02 }) });

        Assert.NotEqual(ptr1, ptr2);
        Assert.True(store.TryGetHead(key, out ulong head));
        Assert.Equal(ptr2, head);
    }

    [Fact]
    public async Task CommitAsync_DeleteOp_HeadMapPointsToTombstone()
    {
        using var store = new WalStore(_dir);
        ulong key = WalConstants.PackKey(5, 7);

        await store.CommitAsync(new[] { WalOp.Upsert(key, new byte[] { 0xFF }) });
        ulong deletePtr = await store.CommitAsync(new[] { WalOp.Delete(key) });

        Assert.True(store.TryGetHead(key, out ulong head));
        Assert.Equal(deletePtr, head);
    }

    [Fact]
    public async Task CommitAsync_EmptyBatch_Throws()
    {
        using var store = new WalStore(_dir);
        await Assert.ThrowsAsync<ArgumentException>(() => store.CommitAsync(Array.Empty<WalOp>()));
    }

    // ── WalStore: payload read-back ──────────────────────────────────────────

    [Fact]
    public async Task TryReadOpPayload_ReturnsCorrectBytes()
    {
        ulong key     = WalConstants.PackKey(7, 77);
        byte[] payload = Encoding.UTF8.GetBytes("Hello, WAL payload!");
        ulong ptr;

        {
            using var store = new WalStore(_dir);
            ptr = await store.CommitAsync(new[] { WalOp.Upsert(key, payload) });
        } // Dispose writes footer

        // Re-open a fresh store (forces recovery)
        using var store2 = new WalStore(_dir);
        Assert.True(store2.TryGetHead(key, out ulong recoveredPtr),
            "Head map should contain the key after recovery");
        Assert.Equal(ptr, recoveredPtr);
        Assert.True(store2.TryReadOpPayload(recoveredPtr, key, out var got),
            $"TryReadOpPayload failed for ptr={recoveredPtr} key={key}");
        Assert.Equal(payload, got.ToArray());
    }

    // ── WalStore: recovery from footer index ─────────────────────────────────

    [Fact]
    public async Task Recovery_FooterIndex_HeadMapRebuilt()
    {
        ulong key1 = WalConstants.PackKey(10, 1);
        ulong key2 = WalConstants.PackKey(10, 2);

        // First store lifetime: commit, close (writes footer)
        ulong ptrA, ptrB;
        {
            using var s = new WalStore(_dir);
            ptrA = await s.CommitAsync(new[] { WalOp.Upsert(key1, new byte[] { 0x01 }) });
            ptrB = await s.CommitAsync(new[] { WalOp.Upsert(key2, new byte[] { 0x02 }) });
        } // Dispose writes footer

        // Second store lifetime: must recover both heads from footer
        using var s2 = new WalStore(_dir);
        Assert.True(s2.TryGetHead(key1, out ulong r1));
        Assert.True(s2.TryGetHead(key2, out ulong r2));
        Assert.Equal(ptrA, r1);
        Assert.Equal(ptrB, r2);
    }

    [Fact]
    public async Task Recovery_LinearScan_HeadMapRebuilt_WhenNoFooter()
    {
        ulong key = WalConstants.PackKey(11, 5);
        ulong ptr;

        {
            using var s = new WalStore(_dir);
            ptr = await s.CommitAsync(new[] { WalOp.Upsert(key, new byte[] { 0xAB }) });
        } // Dispose writes footer

        // Remove the footer by truncating the file to just after the last commit record.
        // Read FooterStartOffset from footer tail to know where to truncate.
        string[] files = Directory.GetFiles(_dir, "wal_seg_*.log");
        Assert.Single(files);
        using (var fs = new FileStream(files[0], FileMode.Open, FileAccess.ReadWrite))
        {
            // Footer tail layout (last 16 bytes): CRC(4) | FooterStartOffset(8) | EndMagic(4)
            fs.Seek(-WalConstants.FooterTailBytes, SeekOrigin.End);
            Span<byte> tail = stackalloc byte[WalConstants.FooterTailBytes];
            int bytesRead = fs.Read(tail);
            Assert.Equal(WalConstants.FooterTailBytes, bytesRead);
            ulong footerStart = BinaryPrimitives.ReadUInt64LittleEndian(tail[4..]);
            fs.SetLength((long)footerStart); // truncate: removes footer entirely
        }

        // Directly verify LinearScanIndex can find the key in the footer-less file
        var scanResult = WalSegmentReader.LinearScanIndex(files[0]);
        Assert.True(scanResult.ContainsKey(key),
            $"LinearScanIndex should find key=0x{key:X16}. Actual keys: {string.Join(", ", scanResult.Keys.Select(k => $"0x{k:X16}"))}");

        // Recover via linear scan (no footer present)
        using var s2 = new WalStore(_dir);
        Assert.True(s2.TryGetHead(key, out ulong recovered),
            "Head map should be rebuilt from linear scan");
        // The segId encoded in recovered must match the segId encoded in the original ptr
        var (segId, _)     = WalConstants.UnpackPtr(recovered);
        var (origSegId, _) = WalConstants.UnpackPtr(ptr);
        Assert.Equal(origSegId, segId);
    }

    // ── WalStore: segment rotation ───────────────────────────────────────────

    [Fact]
    public async Task SegmentRotation_NewSegmentCreated_WhenSizeExceeded()
    {
        // Use a very small max segment size to force rotation after one commit.
        // A single-op, 1-byte-payload commit record is 109 bytes.
        // Segment header is 16 bytes. CurrentOffset after first commit = 125.
        // With smallMax=100: second commit finds 125 >= 100 and rotates.
        uint smallMax = 100;
        using var store = new WalStore(_dir, smallMax);

        ulong key1 = WalConstants.PackKey(20, 1);
        ulong key2 = WalConstants.PackKey(20, 2);

        await store.CommitAsync(new[] { WalOp.Upsert(key1, new byte[] { 0x01 }) });
        await store.CommitAsync(new[] { WalOp.Upsert(key2, new byte[] { 0x02 }) });

        // Should have created at least two segment files
        var files = Directory.GetFiles(_dir, "wal_seg_*.log");
        Assert.True(files.Length >= 2, $"Expected >=2 segments, got {files.Length}");

        // Both keys must be in head map
        Assert.True(store.TryGetHead(key1, out _));
        Assert.True(store.TryGetHead(key2, out _));
    }

    // ── WalStore: concurrent commits ─────────────────────────────────────────

    [Fact]
    public async Task ConcurrentCommits_AllSucceed_AllHeadsPresent()
    {
        using var store = new WalStore(_dir);
        const int threadCount = 20;
        var ptrs = new ulong[threadCount];
        var tasks = new Task[threadCount];

        for (int i = 0; i < threadCount; i++)
        {
            int idx = i;
            tasks[idx] = Task.Run(async () =>
            {
                ulong key = WalConstants.PackKey(99, (uint)idx);
                ptrs[idx] = await store.CommitAsync(new[]
                {
                    WalOp.Upsert(key, new byte[] { (byte)idx })
                });
            });
        }

        await Task.WhenAll(tasks);

        for (int i = 0; i < threadCount; i++)
        {
            ulong key = WalConstants.PackKey(99, (uint)i);
            Assert.True(store.TryGetHead(key, out ulong head), $"key {i} missing");
            Assert.Equal(ptrs[i], head);
        }
    }

    // ── V2: VisibleCommitPtr ─────────────────────────────────────────────────

    [Fact]
    public async Task VisibleCommitPtr_UpdatedAfterEachCommit()
    {
        using var store = new WalStore(_dir);
        Assert.Equal(WalConstants.NullPtr, store.VisibleCommitPtr);

        ulong ptr1 = await store.CommitAsync(new[] { WalOp.Upsert(WalConstants.PackKey(1, 1), new byte[] { 1 }) });
        Assert.Equal(ptr1, store.VisibleCommitPtr);

        ulong ptr2 = await store.CommitAsync(new[] { WalOp.Upsert(WalConstants.PackKey(1, 2), new byte[] { 2 }) });
        Assert.Equal(ptr2, store.VisibleCommitPtr);
        Assert.NotEqual(ptr1, ptr2);
    }

    // ── V2: WalTransaction ───────────────────────────────────────────────────

    [Fact]
    public async Task Transaction_Commit_WritesOpsToStore()
    {
        using var store = new WalStore(_dir);
        ulong key = WalConstants.PackKey(30, 1);

        using var tx = store.BeginTransaction();
        tx.Stage(WalOp.Upsert(key, new byte[] { 0xAB }));
        Assert.Equal(1, tx.StagedCount);

        ulong ptr = await tx.CommitAsync();

        Assert.NotEqual(WalConstants.NullPtr, ptr);
        Assert.True(store.TryGetHead(key, out ulong head));
        Assert.Equal(ptr, head);
    }

    [Fact]
    public async Task Transaction_Rollback_LeavesStoreUnchanged()
    {
        using var store = new WalStore(_dir);
        ulong key = WalConstants.PackKey(31, 1);

        {
            using var tx = store.BeginTransaction();
            tx.Stage(WalOp.Upsert(key, new byte[] { 0xFF }));
        } // Dispose without commit → rollback

        Assert.False(store.TryGetHead(key, out _));
    }

    [Fact]
    public void Transaction_CannotCommitTwice()
    {
        using var store = new WalStore(_dir);
        var tx = store.BeginTransaction();
        tx.Stage(WalOp.Upsert(WalConstants.PackKey(32, 1), new byte[] { 1 }));
        tx.CommitAsync().GetAwaiter().GetResult();
        Assert.Throws<InvalidOperationException>(() => tx.CommitAsync().GetAwaiter().GetResult());
        tx.Dispose();
    }

    [Fact]
    public void Transaction_EmptyBatch_Throws()
    {
        using var store = new WalStore(_dir);
        using var tx = store.BeginTransaction();
        Assert.Throws<InvalidOperationException>(() => tx.CommitAsync().GetAwaiter().GetResult());
    }

    // ── V2: WalSnapshot ──────────────────────────────────────────────────────

    [Fact]
    public async Task Snapshot_WriteAndLoad_RoundTrip()
    {
        ulong key1 = WalConstants.PackKey(40, 1);
        ulong key2 = WalConstants.PackKey(40, 2);

        ulong ptr1, ptr2;
        {
            using var store = new WalStore(_dir);
            ptr1 = await store.CommitAsync(new[] { WalOp.Upsert(key1, new byte[] { 1 }) });
            ptr2 = await store.CommitAsync(new[] { WalOp.Upsert(key2, new byte[] { 2 }) });
        } // Dispose writes snapshot + segment footer

        // Verify snapshot file exists
        Assert.True(File.Exists(Path.Combine(_dir, WalSnapshot.FileName)));

        // Load snapshot directly
        Assert.True(WalSnapshot.TryLoad(_dir, out ulong loadedPtr, out var keys, out var heads));
        Assert.Equal(ptr2, loadedPtr); // last committed ptr
        Assert.Equal(2, keys.Length);

        // Verify head map on fresh store reopen
        using var store2 = new WalStore(_dir);
        Assert.True(store2.TryGetHead(key1, out ulong r1));
        Assert.True(store2.TryGetHead(key2, out ulong r2));
        Assert.Equal(ptr1, r1);
        Assert.Equal(ptr2, r2);
    }

    [Fact]
    public void Snapshot_MissingFile_ReturnsFalse()
    {
        Assert.False(WalSnapshot.TryLoad(_dir, out _, out _, out _));
    }

    [Fact]
    public void Snapshot_CorruptFile_ReturnsFalse()
    {
        // Write a garbage file
        File.WriteAllBytes(Path.Combine(_dir, WalSnapshot.FileName), new byte[] { 0xFF, 0x00, 0xAA });
        Assert.False(WalSnapshot.TryLoad(_dir, out _, out _, out _));
    }

    // ── V2: ISecondaryIndex / WalProjectionManager ───────────────────────────

    [Fact]
    public async Task ProjectionManager_ApplyCommit_DispatchedAfterCommit()
    {
        using var store = new WalStore(_dir);
        var tracker = new TestSecondaryIndex(tableId: 50);
        store.ProjectionManager.Register(tracker);

        ulong key = WalConstants.PackKey(50, 7);
        await store.CommitAsync(new[] { WalOp.Upsert(key, Encoding.UTF8.GetBytes("hello")) });

        Assert.Equal(1, tracker.UpsertCount);
        Assert.Equal(0, tracker.DeleteCount);
    }

    [Fact]
    public async Task ProjectionManager_DeleteOp_CallsRemove()
    {
        using var store = new WalStore(_dir);
        var tracker = new TestSecondaryIndex(tableId: 51);
        store.ProjectionManager.Register(tracker);

        ulong key = WalConstants.PackKey(51, 3);
        await store.CommitAsync(new[] { WalOp.Upsert(key, new byte[] { 0x01 }) });
        await store.CommitAsync(new[] { WalOp.Delete(key) });

        Assert.Equal(1, tracker.UpsertCount);
        Assert.Equal(1, tracker.DeleteCount);
    }

    [Fact]
    public async Task ProjectionManager_DifferentTable_NotDispatched()
    {
        using var store = new WalStore(_dir);
        var tracker = new TestSecondaryIndex(tableId: 60);
        store.ProjectionManager.Register(tracker);

        // Commit to table 61 – tracker registered for 60 should not receive it
        ulong key = WalConstants.PackKey(61, 1);
        await store.CommitAsync(new[] { WalOp.Upsert(key, new byte[] { 0x01 }) });

        Assert.Equal(0, tracker.UpsertCount);
    }

    // ── IndexKey helpers ─────────────────────────────────────────────────────

    [Fact]
    public void IndexKey_FromUInt64_RoundTrip()
    {
        var k = IndexKey.FromUInt64(12345678uL);
        Assert.Equal(12345678uL, k.RawValue);
    }

    [Fact]
    public void IndexKey_FromString_Deterministic()
    {
        var k1 = IndexKey.FromString("hello");
        var k2 = IndexKey.FromString("hello");
        Assert.Equal(k1, k2);
    }

    [Fact]
    public void IndexKey_FromString_DifferentStrings_DifferentKeys()
    {
        var k1 = IndexKey.FromString("hello");
        var k2 = IndexKey.FromString("world");
        Assert.NotEqual(k1, k2);
    }

    // ── Helper: simple test secondary index ──────────────────────────────────

    private sealed class TestSecondaryIndex(uint tableId) : ISecondaryIndex
    {
        public uint   TableId     => tableId;
        public string Name        => "test";
        public int    UpsertCount { get; private set; }
        public int    DeleteCount { get; private set; }

        public void ApplyChange(ulong key, ReadOnlySpan<byte> oldRow, ReadOnlySpan<byte> newRow, ChangeType ct)
        {
            if (ct == ChangeType.Upsert) UpsertCount++;
        }
        public void Remove(ulong key, ReadOnlySpan<byte> oldRow) => DeleteCount++;
        public IEnumerable<ulong> QueryEquals(IndexKey k)            => [];
        public IEnumerable<ulong> QueryRange(IndexKey min, IndexKey max) => [];
    }
}
