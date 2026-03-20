using System;
using System.Collections.Generic;
using System.Numerics;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for the columnstore ordinal indirection subsystem:
///   <see cref="FreeOrdinalStack"/>, <see cref="OrdinalMap"/>,
///   and the incremental <c>UpsertRow</c> / <c>RemoveRow</c> methods on
///   <see cref="ColumnarStore"/>.
///
/// <para>
/// Correctness is verified at three levels:
///   1. <c>FreeOrdinalStack</c> — push/pop LIFO semantics, growth, clear.
///   2. <c>OrdinalMap</c> — upsert, remove, free-slot reuse, HighWater behaviour.
///   3. <c>ColumnarStore</c> incremental ops — single-row add/update/delete,
///      validity bitmap masking, ordinal reuse after delete + insert.
/// </para>
/// </summary>
[Collection("SharedState")]
public sealed class OrdinalIndirectionTests : IDisposable
{
    // ── Minimal entity used throughout ────────────────────────────────────────

    [DataEntity("OrdinalItems")]
    private sealed class OrdinalItem : BaseDataObject
    {
        private const int Ord_BigVal = BaseFieldCount + 0;
        private const int Ord_Label = BaseFieldCount + 1;
        private const int Ord_Score = BaseFieldCount + 2;
        private const int Ord_Value = BaseFieldCount + 3;
        internal new const int TotalFieldCount = BaseFieldCount + 4;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("BigVal", Ord_BigVal),
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("Label", Ord_Label),
            new FieldSlot("Score", Ord_Score),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Value", Ord_Value),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public OrdinalItem() : base(TotalFieldCount) { }
        public OrdinalItem(string createdBy) : base(TotalFieldCount, createdBy) { }

        [DataField]
        public string Label
        {
            get => (string?)_values[Ord_Label] ?? string.Empty;
            set => _values[Ord_Label] = value;
        }

        [DataField]
        public int Value
        {
            get => (int)(_values[Ord_Value] ?? 0);
            set => _values[Ord_Value] = value;
        }

        [DataField]
        public long BigVal
        {
            get => (long)(_values[Ord_BigVal] ?? 0L);
            set => _values[Ord_BigVal] = value;
        }

        [DataField]
        public double Score
        {
            get => (double)(_values[Ord_Score] ?? 0.0);
            set => _values[Ord_Score] = value;
        }
    }

    public OrdinalIndirectionTests()
    {
        DataScaffold.RegisterEntity<OrdinalItem>();
    }

    public void Dispose() { }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static List<OrdinalItem> MakeItems(int count)
    {
        var list = new List<OrdinalItem>(count);
        for (int i = 0; i < count; i++)
            list.Add(new OrdinalItem { Key = (uint)(i + 1), Label = $"L{i}", Value = i * 10, BigVal = i * 1000L, Score = i * 0.5 });
        return list;
    }

    private static int CountBits(ulong[] mask)
    {
        int n = 0;
        foreach (var w in mask) n += BitOperations.PopCount(w);
        return n;
    }

    // ════════════════════════════════════════════════════════════════════════
    // 1. FreeOrdinalStack
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void FreeOrdinalStack_PushPop_LIFOOrder()
    {
        var stack = new FreeOrdinalStack();
        stack.Push(1u);
        stack.Push(2u);
        stack.Push(3u);

        Assert.True(stack.TryPop(out var a)); Assert.Equal(3u, a);
        Assert.True(stack.TryPop(out var b)); Assert.Equal(2u, b);
        Assert.True(stack.TryPop(out var c)); Assert.Equal(1u, c);
        Assert.False(stack.TryPop(out _));
    }

    [Fact]
    public void FreeOrdinalStack_TryPop_EmptyReturnsFalse()
    {
        var stack = new FreeOrdinalStack();
        Assert.False(stack.TryPop(out var v));
        Assert.Equal(0u, v);
    }

    [Fact]
    public void FreeOrdinalStack_Count_TracksCorrectly()
    {
        var stack = new FreeOrdinalStack();
        Assert.Equal(0, stack.Count);
        stack.Push(10u);
        Assert.Equal(1, stack.Count);
        stack.Push(20u);
        Assert.Equal(2, stack.Count);
        stack.TryPop(out _);
        Assert.Equal(1, stack.Count);
        stack.Clear();
        Assert.Equal(0, stack.Count);
    }

    [Fact]
    public void FreeOrdinalStack_GrowsBeyondInitialCapacity()
    {
        var stack = new FreeOrdinalStack(4); // small initial capacity
        for (uint i = 0; i < 100; i++)
            stack.Push(i);

        Assert.Equal(100, stack.Count);

        for (uint i = 100; i > 0; i--)
        {
            Assert.True(stack.TryPop(out var v));
            Assert.Equal(i - 1, v);
        }
    }

    [Fact]
    public void FreeOrdinalStack_AsSpan_ReflectsContents()
    {
        var stack = new FreeOrdinalStack();
        stack.Push(5u);
        stack.Push(10u);
        stack.Push(15u);

        var span = stack.AsSpan();
        Assert.Equal(3, span.Length);
        Assert.Equal(5u,  span[0]);
        Assert.Equal(10u, span[1]);
        Assert.Equal(15u, span[2]);
    }

    // ════════════════════════════════════════════════════════════════════════
    // 2. OrdinalMap
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void OrdinalMap_Upsert_NewIdAssignsIncreasingOrdinals()
    {
        var map = new OrdinalMap();
        var (o0, new0) = map.Upsert(1u);
        var (o1, new1) = map.Upsert(2u);
        var (o2, new2) = map.Upsert(3u);

        Assert.True(new0); Assert.True(new1); Assert.True(new2);
        Assert.Equal(0u, o0);
        Assert.Equal(1u, o1);
        Assert.Equal(2u, o2);
        Assert.Equal(3u, map.HighWater);
    }

    [Fact]
    public void OrdinalMap_Upsert_ExistingIdReturnsIsNewFalse()
    {
        var map = new OrdinalMap();
        map.Upsert(7u);
        var (ordinal, isNew) = map.Upsert(7u);
        Assert.False(isNew);
        Assert.Equal(1, map.Count);
    }

    [Fact]
    public void OrdinalMap_Remove_ReturnsTrueAndPushesOrdinal()
    {
        var map = new OrdinalMap();
        map.Upsert(1u);
        map.Upsert(2u);

        bool removed = map.Remove(1u, out var ordinal);

        Assert.True(removed);
        Assert.Equal(0u, ordinal);
        Assert.Equal(1, map.Count);
        Assert.Equal(1, map.FreeCount);
        Assert.Equal(2u, map.HighWater); // high water unchanged
    }

    [Fact]
    public void OrdinalMap_Remove_MissingIdReturnsFalse()
    {
        var map = new OrdinalMap();
        Assert.False(map.Remove(99u, out _));
    }

    [Fact]
    public void OrdinalMap_GetId_ReturnsTombstoneZeroForFreedSlot()
    {
        var map = new OrdinalMap();
        var (ord, _) = map.Upsert(42u);
        map.Remove(42u, out _);
        Assert.Equal(0u, map.GetId(ord));
    }

    [Fact]
    public void OrdinalMap_Upsert_ReusesFreedOrdinal()
    {
        var map = new OrdinalMap();
        map.Upsert(1u);  // ordinal 0
        map.Upsert(2u);  // ordinal 1
        map.Remove(1u, out _); // frees ordinal 0

        // Inserting id=3 should reuse ordinal 0
        var (reused, isNew) = map.Upsert(3u);
        Assert.True(isNew);
        Assert.Equal(0u, reused);
        Assert.Equal(2u, map.HighWater); // no growth
        Assert.Equal(0, map.FreeCount);  // free stack drained
    }

    [Fact]
    public void OrdinalMap_HighWater_GrowsOnlyWhenFreeStackIsEmpty()
    {
        var map = new OrdinalMap();
        map.Upsert(1u); map.Upsert(2u); map.Upsert(3u);
        Assert.Equal(3u, map.HighWater);

        map.Remove(2u, out _); // frees ordinal 1; HighWater stays at 3
        Assert.Equal(3u, map.HighWater);

        map.Upsert(10u); // reuses ordinal 1; HighWater stays at 3
        Assert.Equal(3u, map.HighWater);

        map.Upsert(20u); // no free ordinals; HighWater grows to 4
        Assert.Equal(4u, map.HighWater);
    }

    [Fact]
    public void OrdinalMap_TryGetOrdinal_FindsLiveRows()
    {
        var map = new OrdinalMap();
        map.Upsert(5u);
        Assert.True(map.TryGetOrdinal(5u, out var ord));
        Assert.Equal(0u, ord);
        Assert.False(map.TryGetOrdinal(99u, out _));
    }

    [Fact]
    public void OrdinalMap_Clear_ResetsAllState()
    {
        var map = new OrdinalMap();
        map.Upsert(1u); map.Upsert(2u); map.Remove(1u, out _);

        map.Clear();

        Assert.Equal(0, map.Count);
        Assert.Equal(0u, map.HighWater);
        Assert.Equal(0, map.FreeCount);
    }

    // ════════════════════════════════════════════════════════════════════════
    // 3. ColumnarStore incremental operations
    // ════════════════════════════════════════════════════════════════════════

    [Fact]
    public void ColumnarStore_UpsertRow_BeforeBuild_ReturnsFalse()
    {
        var store = new ColumnarStore(64);
        var meta  = DataScaffold.GetEntityByType(typeof(OrdinalItem))!;
        var item  = new OrdinalItem { Key = 1u, Value = 42 };

        // Store has no column schema yet; UpsertRow should report not-built
        bool ok = store.UpsertRow(item, meta);
        Assert.False(ok);
    }

    [Fact]
    public void ColumnarStore_UpsertRow_AfterBuild_UpdatesColumnValue()
    {
        var rows = MakeItems(300);
        var meta = DataScaffold.GetEntityByType(typeof(OrdinalItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        // Update key=1's Value from 0 to 9999
        var updated = new OrdinalItem { Key = 1u, Label = "Updated", Value = 9999 };
        Assert.True(store.UpsertRow(updated, meta));

        // Scan: Value == 9999 should hit exactly 1 row
        int wordCount = store.ScanWordCount;
        var mask = store.ScanClause("Value", QueryOperator.Equals, 9999, wordCount);
        Assert.NotNull(mask);
        Assert.Equal(1, CountBits(mask!));
    }

    [Fact]
    public void ColumnarStore_UpsertRow_Insert_AddsRow()
    {
        var rows = MakeItems(300);
        var meta = DataScaffold.GetEntityByType(typeof(OrdinalItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        // Insert a brand-new key
        var newItem = new OrdinalItem { Key = 9999u, Value = 1234 };
        Assert.True(store.UpsertRow(newItem, meta));

        Assert.Equal(301, store.RowCount);

        // Scan for Value == 1234 should return exactly 1 hit
        int wordCount = store.ScanWordCount;
        var mask = store.ScanClause("Value", QueryOperator.Equals, 1234, wordCount);
        Assert.Equal(1, CountBits(mask!));
    }

    [Fact]
    public void ColumnarStore_RemoveRow_DecreasesRowCount()
    {
        var rows = MakeItems(300);
        var meta = DataScaffold.GetEntityByType(typeof(OrdinalItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        bool removed = store.RemoveRow(rows[0].Key);
        Assert.True(removed);
        Assert.Equal(299, store.RowCount);
    }

    [Fact]
    public void ColumnarStore_RemoveRow_MissingKeyReturnsFalse()
    {
        var rows = MakeItems(300);
        var meta = DataScaffold.GetEntityByType(typeof(OrdinalItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        Assert.False(store.RemoveRow(99999u));
    }

    [Fact]
    public void ColumnarStore_RemoveRow_FreedOrdinalNotReturnedByScan()
    {
        // Build with 300 rows all having Value = 0, 10, 20, …
        var rows = MakeItems(300);
        var meta = DataScaffold.GetEntityByType(typeof(OrdinalItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        // Row at ordinal 0 has Value = 0 (key = 1)
        int beforeHits = CountBits(store.ScanClause("Value", QueryOperator.Equals, 0, store.ScanWordCount)!);

        store.RemoveRow(1u); // remove key=1 (ordinal 0, Value=0)

        int afterHits = CountBits(store.ScanClause("Value", QueryOperator.Equals, 0, store.ScanWordCount)!);

        // The validity mask must have masked the freed slot out
        Assert.Equal(beforeHits - 1, afterHits);
    }

    [Fact]
    public void ColumnarStore_OrdinalReuse_NoArrayGrowth()
    {
        var rows = MakeItems(300);
        var meta = DataScaffold.GetEntityByType(typeof(OrdinalItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        int capacityBefore = store.Capacity;

        // Delete a row and insert a new one — ordinal should be reused
        store.RemoveRow(1u);
        var newItem = new OrdinalItem { Key = 9001u, Value = 7777 };
        store.UpsertRow(newItem, meta);

        // Capacity (HighWater) must not have grown
        Assert.Equal(capacityBefore, store.Capacity);
        Assert.Equal(300, store.RowCount); // same live count
    }

    [Fact]
    public void ColumnarStore_OrdinalReuse_ReusedSlotIsCorrectlyScanned()
    {
        // Use enough rows to trigger the vectorised path
        var rows = MakeItems(300);
        var meta = DataScaffold.GetEntityByType(typeof(OrdinalItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        // Remove key=1 (ordinal 0, Value=0); insert key=9001 with Value=5555
        store.RemoveRow(1u);
        var newItem = new OrdinalItem { Key = 9001u, Value = 5555 };
        store.UpsertRow(newItem, meta);

        // Scan for Value == 5555: should find exactly 1 row (reused ordinal 0)
        var mask = store.ScanClause("Value", QueryOperator.Equals, 5555, store.ScanWordCount);
        Assert.Equal(1, CountBits(mask!));

        // Scan for Value == 0: should NOT find the freed slot
        var maskZero = store.ScanClause("Value", QueryOperator.Equals, 0, store.ScanWordCount);
        Assert.Equal(0, CountBits(maskZero!));

        // GetKeyAtRow at the reused ordinal should return the new key
        Assert.Equal(9001u, store.GetKeyAtRow(0));
    }

    [Fact]
    public void ColumnarStore_Invalidate_DoesNotAffectUpsertState()
    {
        var rows = MakeItems(300);
        var meta = DataScaffold.GetEntityByType(typeof(OrdinalItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        long vBefore = store.Version;
        store.UpsertRow(new OrdinalItem { Key = 1u, Value = 42 }, meta);
        long vAfterUpsert = store.Version;

        // Upsert must NOT change the rebuild-signal version
        Assert.Equal(vBefore, vAfterUpsert);

        store.Invalidate();
        Assert.True(store.Version > vBefore);
    }

    [Fact]
    public void ColumnarStore_RemoveRow_DoesNotChangeVersion()
    {
        var rows = MakeItems(300);
        var meta = DataScaffold.GetEntityByType(typeof(OrdinalItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        long vBefore = store.Version;
        store.RemoveRow(1u);

        Assert.Equal(vBefore, store.Version);
    }

    [Fact]
    public void ColumnarStore_ScanWordCount_EqualsRowCountWordCountAfterBuild()
    {
        // After a clean build (no holes), ScanWordCount == (RowCount + 63) >> 6
        var rows = MakeItems(300);
        var meta = DataScaffold.GetEntityByType(typeof(OrdinalItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta);

        Assert.Equal((store.RowCount + 63) >> 6, store.ScanWordCount);
    }

    [Fact]
    public void ColumnarStore_Capacity_GrowsOnlyOnNewInsertBeyondFreeStack()
    {
        var rows = MakeItems(4);
        var meta = DataScaffold.GetEntityByType(typeof(OrdinalItem))!;
        var store = new ColumnarStore(rows.Count);
        store.Build(rows, meta); // ordinals 0-3, HighWater=4

        store.RemoveRow(1u); // frees ordinal 0; HighWater stays 4
        Assert.Equal(4, store.Capacity);

        store.UpsertRow(new OrdinalItem { Key = 100u, Value = 1 }, meta); // reuses ordinal 0
        Assert.Equal(4, store.Capacity); // still 4

        store.UpsertRow(new OrdinalItem { Key = 101u, Value = 2 }, meta); // needs new slot
        Assert.Equal(5, store.Capacity); // grew to 5
    }
}
