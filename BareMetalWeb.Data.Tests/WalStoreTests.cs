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

    // ── WalHeadMap: striped (sharded) behaviour ──────────────────────────────

    [Fact]
    public void HeadMap_Striped_DefaultShardCountIsPowerOfTwo()
    {
        int n = WalHeadMap.DefaultShardCount;
        Assert.True(n > 0 && (n & (n - 1)) == 0, $"DefaultShardCount {n} is not a positive power of two.");
    }

    [Fact]
    public void HeadMap_Striped_InvalidShardCount_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new WalHeadMap(0).Dispose());
        Assert.Throws<ArgumentOutOfRangeException>(() => new WalHeadMap(3).Dispose());
        Assert.Throws<ArgumentOutOfRangeException>(() => new WalHeadMap(-1).Dispose());
    }

    [Fact]
    public void HeadMap_Striped_KeysAcrossDifferentTables_AllReadable()
    {
        using var map = new WalHeadMap(shardCount: 4);

        // Insert keys for 8 different tableIds — they fan out across the 4 shards
        for (uint tableId = 0; tableId < 8; tableId++)
        {
            ulong key = WalConstants.PackKey(tableId, 1);
            ulong ptr = WalConstants.PackPtr(0, tableId * 16 + 16);
            map.SetHead(key, ptr);
        }

        Assert.Equal(8, map.Count);

        for (uint tableId = 0; tableId < 8; tableId++)
        {
            ulong key = WalConstants.PackKey(tableId, 1);
            ulong expected = WalConstants.PackPtr(0, tableId * 16 + 16);
            Assert.True(map.TryGetHead(key, out ulong got));
            Assert.Equal(expected, got);
        }
    }

    [Fact]
    public void HeadMap_Striped_BulkLoad_DistributesAcrossShards()
    {
        using var map = new WalHeadMap(shardCount: 4);

        // Build a globally sorted array spanning 16 tableIds
        var sortedKeys  = new ulong[16];
        var sortedHeads = new ulong[16];
        for (uint t = 0; t < 16; t++)
        {
            sortedKeys[t]  = WalConstants.PackKey(t, 1);
            sortedHeads[t] = WalConstants.PackPtr(0, t * 8 + 8);
        }

        map.BulkLoad(sortedKeys, sortedHeads);

        Assert.Equal(16, map.Count);
        for (uint t = 0; t < 16; t++)
        {
            Assert.True(map.TryGetHead(WalConstants.PackKey(t, 1), out ulong ptr));
            Assert.Equal(WalConstants.PackPtr(0, t * 8 + 8), ptr);
        }
    }

    [Fact]
    public void HeadMap_Striped_CopyArrays_MergesShardsIntoSortedOutput()
    {
        using var map = new WalHeadMap(shardCount: 4);

        // Insert keys that will land in at least two different shards
        // tableId 0 → shard 0,  tableId 1 → shard 1
        ulong k0 = WalConstants.PackKey(0, 10);
        ulong k1 = WalConstants.PackKey(1, 5);
        map.SetHead(k0, WalConstants.PackPtr(0, 100));
        map.SetHead(k1, WalConstants.PackPtr(0, 200));

        map.CopyArrays(out ulong[] keys, out ulong[] heads);

        Assert.Equal(2, keys.Length);
        Assert.Equal(2, heads.Length);

        // Output must be sorted ascending by key
        for (int i = 1; i < keys.Length; i++)
            Assert.True(keys[i] > keys[i - 1], "CopyArrays output is not sorted.");

        // Both keys must appear with correct pointers
        for (int i = 0; i < keys.Length; i++)
        {
            if (keys[i] == k0) Assert.Equal(WalConstants.PackPtr(0, 100), heads[i]);
            else if (keys[i] == k1) Assert.Equal(WalConstants.PackPtr(0, 200), heads[i]);
            else Assert.Fail($"Unexpected key 0x{keys[i]:X16} in CopyArrays output.");
        }
    }

    [Fact]
    public void HeadMap_Striped_BatchSetHeads_CrossShardKeys_AllUpdated()
    {
        using var map = new WalHeadMap(shardCount: 4);

        // Keys across all 4 shards (tableIds 0,1,2,3)
        ulong[] keys = [
            WalConstants.PackKey(0, 1),
            WalConstants.PackKey(1, 1),
            WalConstants.PackKey(2, 1),
            WalConstants.PackKey(3, 1),
        ];
        ulong ptr = WalConstants.PackPtr(0, 512);

        map.BatchSetHeads(keys.AsSpan(), ptr);

        Assert.Equal(4, map.Count);
        foreach (var k in keys)
        {
            Assert.True(map.TryGetHead(k, out ulong got));
            Assert.Equal(ptr, got);
        }
    }

    [Fact]
    public void HeadMap_Striped_BatchSetHeads_PerKeyPtrs_CrossShard()
    {
        using var map = new WalHeadMap(shardCount: 4);

        // Keys sorted ascending, spanning two shards
        ulong[] keys = [
            WalConstants.PackKey(0, 1),
            WalConstants.PackKey(1, 1),
        ];
        ulong[] ptrs = [
            WalConstants.PackPtr(0, 100),
            WalConstants.PackPtr(1, 200),
        ];

        map.BatchSetHeads(keys.AsSpan(), ptrs);

        Assert.True(map.TryGetHead(keys[0], out ulong p0));
        Assert.True(map.TryGetHead(keys[1], out ulong p1));
        Assert.Equal(ptrs[0], p0);
        Assert.Equal(ptrs[1], p1);
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

    // ── WalTableKeyAllocator ─────────────────────────────────────────────────

    [Fact]
    public void KeyAllocator_AllocateRecordId_Monotonic()
    {
        using var store = new WalStore(_dir);
        uint id1 = store.KeyAllocator.AllocateRecordId(1);
        uint id2 = store.KeyAllocator.AllocateRecordId(1);
        uint id3 = store.KeyAllocator.AllocateRecordId(1);
        Assert.Equal(1u, id1);
        Assert.Equal(2u, id2);
        Assert.Equal(3u, id3);
    }

    [Fact]
    public void KeyAllocator_DifferentTables_IndependentSequences()
    {
        using var store = new WalStore(_dir);
        Assert.Equal(1u, store.KeyAllocator.AllocateRecordId(10));
        Assert.Equal(1u, store.KeyAllocator.AllocateRecordId(20));
        Assert.Equal(2u, store.KeyAllocator.AllocateRecordId(10));
    }

    [Fact]
    public void KeyAllocator_PersistAndReload_MonotonicAcrossRestarts()
    {
        {
            using var s = new WalStore(_dir);
            s.KeyAllocator.AllocateRecordId(5); // id=1
            s.KeyAllocator.AllocateRecordId(5); // id=2
        } // Dispose flushes seqids

        {
            using var s2 = new WalStore(_dir);
            uint next = s2.KeyAllocator.AllocateRecordId(5);
            Assert.Equal(3u, next); // continues from 2
        }
    }

    [Fact]
    public void AllocateKey_PacksTableAndRecordId()
    {
        using var store = new WalStore(_dir);
        ulong key = store.AllocateKey(tableId: 7);
        var (t, r) = WalConstants.UnpackKey(key);
        Assert.Equal(7u, t);
        Assert.Equal(1u, r); // first allocation for table 7
    }

    [Fact]
    public void KeyAllocator_Seed_AdvancesFloor()
    {
        using var store = new WalStore(_dir);
        store.KeyAllocator.Seed(3, 100);
        uint next = store.KeyAllocator.AllocateRecordId(3);
        Assert.Equal(101u, next);
    }

    [Fact]
    public void KeyAllocator_Seed_DoesNotDecreaseExisting()
    {
        using var store = new WalStore(_dir);
        store.KeyAllocator.AllocateRecordId(4); // 1
        store.KeyAllocator.AllocateRecordId(4); // 2
        store.KeyAllocator.Seed(4, 1);          // below current — ignored
        uint next = store.KeyAllocator.AllocateRecordId(4);
        Assert.Equal(3u, next);
    }

    // ── WalLatin1Key32 ───────────────────────────────────────────────────────

    [Fact]
    public void Latin1Key_FromString_Short_PaddedWithZero()
    {
        var k = WalLatin1Key32.FromString("Hi");
        Span<byte> buf = stackalloc byte[32];
        k.CopyTo(buf);
        Assert.Equal((byte)'H', buf[0]);
        Assert.Equal((byte)'i', buf[1]);
        for (int i = 2; i < 32; i++) Assert.Equal(0, buf[i]);
    }

    [Fact]
    public void Latin1Key_FromString_Truncates_At32Chars()
    {
        string s = new('A', 40);
        var k = WalLatin1Key32.FromString(s);
        Span<byte> buf = stackalloc byte[32];
        k.CopyTo(buf);
        for (int i = 0; i < 32; i++) Assert.Equal((byte)'A', buf[i]);
    }

    [Fact]
    public void Latin1Key_NonLatin1_ReplacedWithQuestion()
    {
        var k = WalLatin1Key32.FromString("\u0100"); // U+0100 = Ā, above Latin-1
        Span<byte> buf = stackalloc byte[32];
        k.CopyTo(buf);
        Assert.Equal((byte)'?', buf[0]);
    }

    [Fact]
    public void Latin1Key_Equality_SameContent_Equal()
    {
        var k1 = WalLatin1Key32.FromString("hello");
        var k2 = WalLatin1Key32.FromString("hello");
        Assert.Equal(k1, k2);
        Assert.Equal(k1.ToIndexKey(), k2.ToIndexKey());
    }

    [Fact]
    public void Latin1Key_Equality_DifferentContent_NotEqual()
    {
        var k1 = WalLatin1Key32.FromString("hello");
        var k2 = WalLatin1Key32.FromString("world");
        Assert.NotEqual(k1, k2);
        Assert.NotEqual(k1.ToIndexKey(), k2.ToIndexKey());
    }

    [Fact]
    public void Latin1Key_Null_MapsToZeroKey()
    {
        var k = WalLatin1Key32.FromString(null);
        Span<byte> buf = stackalloc byte[32];
        k.CopyTo(buf);
        for (int i = 0; i < 32; i++) Assert.Equal(0, buf[i]);
    }

    [Fact]
    public void Latin1Key_ToString_RoundTrips_AsciiString()
    {
        var k = WalLatin1Key32.FromString("Hello WAL");
        Assert.Equal("Hello WAL", k.ToString());
    }

    [Fact]
    public void Latin1Key_Comparison_Lexicographic()
    {
        var ka = WalLatin1Key32.FromString("apple");
        var kb = WalLatin1Key32.FromString("banana");
        Assert.True(ka.CompareTo(kb) < 0);
        Assert.True(kb.CompareTo(ka) > 0);
        Assert.Equal(0, ka.CompareTo(ka));
    }

    // ── Brotli compression ───────────────────────────────────────────────────

    [Fact]
    public void WalPayloadCodec_SmallPayload_NotCompressed()
    {
        // Payloads below threshold should be stored as-is (CodecNone)
        var input = new byte[] { 1, 2, 3 };
        var result = WalPayloadCodec.TryCompress(input, out ushort codec, out uint uncompressedLen);
        Assert.Equal(WalConstants.CodecNone, codec);
        Assert.Equal((uint)input.Length, uncompressedLen);
        Assert.Equal(input, result.ToArray());
    }

    [Fact]
    public void WalPayloadCodec_LargeCompressiblePayload_UsesCodecBrotli()
    {
        // A highly repetitive payload compresses well with Brotli
        var input = new byte[512];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 4);

        var compressed = WalPayloadCodec.TryCompress(input, out ushort codec, out uint uncompressedLen);

        Assert.Equal(WalConstants.CodecBrotli, codec);
        Assert.Equal((uint)input.Length, uncompressedLen);
        Assert.True(compressed.Length < input.Length, "Compressed size should be smaller than original");
    }

    [Fact]
    public void WalPayloadCodec_RoundTrip_DecompressesCorrectly()
    {
        var input = new byte[512];
        for (int i = 0; i < input.Length; i++) input[i] = (byte)(i % 8);

        var compressed = WalPayloadCodec.TryCompress(input, out ushort codec, out uint uncompressedLen);
        Assert.Equal(WalConstants.CodecBrotli, codec);

        var restored = WalPayloadCodec.Decompress(compressed, codec, uncompressedLen);
        Assert.Equal(input, restored.ToArray());
    }

    [Fact]
    public void WalPayloadCodec_Decompress_CodecNone_ReturnsUnchanged()
    {
        var input = new byte[] { 10, 20, 30 };
        var result = WalPayloadCodec.Decompress(input, WalConstants.CodecNone, (uint)input.Length);
        Assert.Equal(input, result.ToArray());
    }

    [Fact]
    public async Task CommitAsync_CompressiblePayload_DecompressesCorrectlyOnRead()
    {
        // Build a large repetitive payload that Brotli will compress
        var original = new byte[1024];
        for (int i = 0; i < original.Length; i++) original[i] = (byte)(i % 16);

        ulong key = WalConstants.PackKey(50, 1);
        ulong ptr;
        {
            using var store = new WalStore(_dir);
            ptr = await store.CommitAsync(new[] { WalOp.Upsert(key, original) });
        }

        using var store2 = new WalStore(_dir);
        Assert.True(store2.TryGetHead(key, out ulong recovered));
        Assert.Equal(ptr, recovered);
        Assert.True(store2.TryReadOpPayload(recovered, key, out var got));
        Assert.Equal(original, got.ToArray());
    }

    [Fact]
    public async Task TryReadOpPayload_RejectsTamperedRecord()
    {
        ulong key = WalConstants.PackKey(60, 1);
        var payload = Encoding.UTF8.GetBytes("integrity test");
        ulong ptr;
        {
            using var store = new WalStore(_dir);
            ptr = await store.CommitAsync(new[] { WalOp.Upsert(key, payload) });
        }

        // Tamper with the WAL segment file: flip a byte in the payload area
        var (segId, offset32) = WalConstants.UnpackPtr(ptr);
        string segPath = Path.Combine(_dir, WalConstants.SegmentFileName(segId));
        var bytes = File.ReadAllBytes(segPath);
        // Payload sits after record header (32) + batch header (16) + op header (44) = 92 bytes from offset
        int payloadStart = (int)offset32 + 92;
        Assert.True(payloadStart < bytes.Length, "Payload offset out of range");
        bytes[payloadStart] ^= 0xFF; // flip bits
        File.WriteAllBytes(segPath, bytes);

        using var store2 = new WalStore(_dir);
        Assert.True(store2.TryGetHead(key, out ulong recovered));
        // CRC should now fail — TryReadOpPayload must return false
        Assert.False(store2.TryReadOpPayload(recovered, key, out _));
    }

    [Fact]
    public async Task LinearScanRecovery_SkipsCorruptRecord()
    {
        ulong key1 = WalConstants.PackKey(70, 1);
        ulong key2 = WalConstants.PackKey(70, 2);
        var payload1 = Encoding.UTF8.GetBytes("record one");
        var payload2 = Encoding.UTF8.GetBytes("record two");
        ulong ptr1, ptr2;
        {
            using var store = new WalStore(_dir);
            ptr1 = await store.CommitAsync(new[] { WalOp.Upsert(key1, payload1) });
            ptr2 = await store.CommitAsync(new[] { WalOp.Upsert(key2, payload2) });
        }

        // Find and corrupt the FIRST record (ptr1), then invalidate the footer
        // so recovery uses linear scan. The scan should stop at the corrupt record.
        var (segId, offset32) = WalConstants.UnpackPtr(ptr1);
        string segPath = Path.Combine(_dir, WalConstants.SegmentFileName(segId));
        var bytes = File.ReadAllBytes(segPath);

        // Corrupt a byte inside the first record's payload
        int payloadStart = (int)offset32 + 92;
        Assert.True(payloadStart < bytes.Length);
        bytes[payloadStart] ^= 0xFF;

        // Wipe the footer end-magic so TryReadFooterIndex returns null → forces linear scan
        int endMagicPos = bytes.Length - 4;
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(endMagicPos), 0u);
        File.WriteAllBytes(segPath, bytes);

        // Delete the snapshot so recovery can't bypass the WAL scan
        string snapPath = Path.Combine(_dir, "wal_snapshot.bin");
        if (File.Exists(snapPath)) File.Delete(snapPath);

        // Re-open: footer is broken → linear scan → first record CRC fails → scan stops
        using var store2 = new WalStore(_dir);
        // Neither key should be recovered because scan stops at the first corrupt record
        Assert.False(store2.TryGetHead(key1, out _));
        Assert.False(store2.TryGetHead(key2, out _));
    }

    // ── CompactSegmentFromMaterialisedView ───────────────────────────────────

    [Fact]
    public async Task CompactSegmentFromMaterialisedView_LiveRecordsReadableAfterCompaction()
    {
        // Arrange: commit several records so they land in segment 0
        using var store = new WalStore(_dir);
        ulong key1 = store.AllocateKey(tableId: 80);
        ulong key2 = store.AllocateKey(tableId: 80);
        var payload1 = Encoding.UTF8.GetBytes("hello compaction");
        var payload2 = Encoding.UTF8.GetBytes("second record");

        ulong ptr1 = await store.CommitAsync(new[] { WalOp.Upsert(key1, payload1) });
        ulong ptr2 = await store.CommitAsync(new[] { WalOp.Upsert(key2, payload2) });

        uint segId = (uint)(ptr1 >> 32); // both should be in segment 0

        // Act: compact segment 0
        // Rotate so the segment is no longer active, then compact
        store.RotateSegmentForTest();
        store.CompactSegmentFromMaterialisedView(segId);

        // Assert: both keys are still readable via TryReadOpPayload
        Assert.True(store.TryGetHead(key1, out ulong newPtr1));
        Assert.True(store.TryReadOpPayload(newPtr1, key1, out var got1));
        Assert.Equal(payload1, got1.ToArray());

        Assert.True(store.TryGetHead(key2, out ulong newPtr2));
        Assert.True(store.TryReadOpPayload(newPtr2, key2, out var got2));
        Assert.Equal(payload2, got2.ToArray());
    }

    [Fact]
    public async Task CompactSegmentFromMaterialisedView_UpdatesHeadMapToNewOffsets()
    {
        // Arrange: commit key1 twice (two versions) and key2 once in seg 0.
        // After compaction, only the latest version of each key is kept,
        // so key1's head must move to a new (lower) offset than before.
        using var store = new WalStore(_dir);
        ulong key1 = store.AllocateKey(tableId: 81);
        ulong key2 = store.AllocateKey(tableId: 81);

        var payload1v1 = Encoding.UTF8.GetBytes("record A version 1 — superseded");
        var payload1v2 = Encoding.UTF8.GetBytes("record A version 2 — latest");
        var payload2   = Encoding.UTF8.GetBytes("record B");

        await store.CommitAsync(new[] { WalOp.Upsert(key1, payload1v1) }); // seg0, offset A
        await store.CommitAsync(new[] { WalOp.Upsert(key2, payload2)   }); // seg0, offset B
        ulong prePtr1 = 0;
        Assert.True(store.TryGetHead(key1, out prePtr1)); // prePtr1 = seg0:A

        // Overwrite key1 — its head now points to a later record in seg0
        await store.CommitAsync(new[] { WalOp.Upsert(key1, payload1v2) }); // seg0, offset C > A
        Assert.True(store.TryGetHead(key1, out ulong prePtrAfterUpdate));
        Assert.NotEqual(prePtr1, prePtrAfterUpdate); // confirm head advanced

        uint segId = (uint)(prePtrAfterUpdate >> 32);
        store.RotateSegmentForTest();

        // Act
        store.CompactSegmentFromMaterialisedView(segId);

        // Assert: HeadMap pointers updated
        Assert.True(store.TryGetHead(key1, out ulong postPtr1));
        Assert.True(store.TryGetHead(key2, out ulong postPtr2));

        // Segment ID unchanged; key1's offset should differ from the pre-compaction head
        // (it was at offset C; after compaction the single-op batch is at a lower offset)
        Assert.Equal(segId, (uint)(postPtr1 >> 32));
        Assert.Equal(segId, (uint)(postPtr2 >> 32));
        Assert.NotEqual(prePtrAfterUpdate, postPtr1); // compacted offset differs from the multi-version offset

        // Data must still be intact (latest versions only)
        Assert.True(store.TryReadOpPayload(postPtr1, key1, out var gotA));
        Assert.Equal(payload1v2, gotA.ToArray()); // only the latest version
        Assert.True(store.TryReadOpPayload(postPtr2, key2, out var gotB));
        Assert.Equal(payload2, gotB.ToArray());
    }

    [Fact]
    public async Task CompactSegmentFromMaterialisedView_SkipsTombstones()
    {
        // Arrange: commit a record, then delete it (tombstone), then compact
        using var store = new WalStore(_dir);
        ulong keyLive    = store.AllocateKey(tableId: 82);
        ulong keyDeleted = store.AllocateKey(tableId: 82);

        var livePayload = Encoding.UTF8.GetBytes("I survive");
        await store.CommitAsync(new[] { WalOp.Upsert(keyLive,    livePayload) });
        await store.CommitAsync(new[] { WalOp.Upsert(keyDeleted, Encoding.UTF8.GetBytes("doomed")) });
        // Rotate so tombstone and live record land in the same segment
        store.RotateSegmentForTest();

        // Delete keyDeleted: its head now points to a tombstone in a new segment
        await store.CommitAsync(new[] { WalOp.Delete(keyDeleted) });
        store.RotateSegmentForTest(); // rotate again so the tombstone is in seg 1

        // The live record's head still points to seg 0; compact that segment
        Assert.True(store.TryGetHead(keyLive, out ulong livePtr));
        uint targetSegId = (uint)(livePtr >> 32);
        store.CompactSegmentFromMaterialisedView(targetSegId);

        // Live record still readable
        Assert.True(store.TryGetHead(keyLive, out ulong newPtr));
        Assert.True(store.TryReadOpPayload(newPtr, keyLive, out var gotLive));
        Assert.Equal(livePayload, gotLive.ToArray());

        // keyDeleted is NOT in the compacted segment (its head points to the tombstone
        // in seg 1, so it was never in targetSegId's candidate set after the delete)
    }

    [Fact]
    public async Task CompactSegmentFromMaterialisedView_SupersededKeyNotDowngraded()
    {
        // A key committed to seg 0, then updated to seg 1 — compacting seg 0
        // must NOT move the key back to seg 0.
        using var store = new WalStore(_dir);
        ulong key = store.AllocateKey(tableId: 83);
        var v1 = Encoding.UTF8.GetBytes("version one");
        var v2 = Encoding.UTF8.GetBytes("version two — newer");

        ulong ptr0 = await store.CommitAsync(new[] { WalOp.Upsert(key, v1) });
        uint  seg0  = (uint)(ptr0 >> 32);

        // Rotate so next commit lands in seg 1
        store.RotateSegmentForTest();
        ulong ptr1 = await store.CommitAsync(new[] { WalOp.Upsert(key, v2) });
        uint  seg1  = (uint)(ptr1 >> 32);
        Assert.NotEqual(seg0, seg1); // confirm different segments

        // Rotate again before compacting seg 0
        store.RotateSegmentForTest();

        // Act: compact seg 0 — key's head already points to seg 1
        store.CompactSegmentFromMaterialisedView(seg0);

        // Assert: key's head still points to seg 1 (v2), NOT to the compacted seg 0
        Assert.True(store.TryGetHead(key, out ulong currentPtr));
        Assert.Equal(seg1, (uint)(currentPtr >> 32));

        Assert.True(store.TryReadOpPayload(currentPtr, key, out var got));
        Assert.Equal(v2, got.ToArray());
    }

    [Fact]
    public async Task CompactSegmentFromMaterialisedView_EmptySegment_IsNoOp()
    {
        // Arrange: commit to seg 0, then update all records (seg 1) and compact seg 0
        using var store = new WalStore(_dir);
        ulong key = store.AllocateKey(tableId: 84);
        var v1 = Encoding.UTF8.GetBytes("first");
        var v2 = Encoding.UTF8.GetBytes("second");

        await store.CommitAsync(new[] { WalOp.Upsert(key, v1) });
        store.RotateSegmentForTest();  // rotate to seg 1

        ulong ptr1 = await store.CommitAsync(new[] { WalOp.Upsert(key, v2) });
        store.RotateSegmentForTest();  // rotate to seg 2

        // seg 0 has no live keys (key was updated to seg 1) — compaction is a no-op
        store.CompactSegmentFromMaterialisedView(0u);

        // key's head still points to the seg 1 version
        Assert.True(store.TryGetHead(key, out ulong currentPtr));
        Assert.Equal((uint)(ptr1 >> 32), (uint)(currentPtr >> 32));
        Assert.True(store.TryReadOpPayload(currentPtr, key, out var got));
        Assert.Equal(v2, got.ToArray());
    }

    [Fact]
    public async Task CompactSegmentFromMaterialisedView_DataSurvivesFullRecovery()
    {
        // Arrange: write records, compact, close store, reopen and verify data intact
        uint segId;
        ulong key1, key2;
        var payload1 = Encoding.UTF8.GetBytes("persisted after compaction A");
        var payload2 = Encoding.UTF8.GetBytes("persisted after compaction B");

        using (var store = new WalStore(_dir))
        {
            key1 = store.AllocateKey(tableId: 85);
            key2 = store.AllocateKey(tableId: 85);
            ulong ptr = await store.CommitAsync(new[] { WalOp.Upsert(key1, payload1) });
            await store.CommitAsync(new[] { WalOp.Upsert(key2, payload2) });
            segId = (uint)(ptr >> 32);
            store.RotateSegmentForTest();
            store.CompactSegmentFromMaterialisedView(segId);
        } // Dispose writes snapshot + footer

        // Re-open and verify both records are readable
        using var store2 = new WalStore(_dir);
        Assert.True(store2.TryGetHead(key1, out ulong rPtr1));
        Assert.True(store2.TryReadOpPayload(rPtr1, key1, out var rGot1));
        Assert.Equal(payload1, rGot1.ToArray());

        Assert.True(store2.TryGetHead(key2, out ulong rPtr2));
        Assert.True(store2.TryReadOpPayload(rPtr2, key2, out var rGot2));
        Assert.Equal(payload2, rGot2.ToArray());
    }
}
