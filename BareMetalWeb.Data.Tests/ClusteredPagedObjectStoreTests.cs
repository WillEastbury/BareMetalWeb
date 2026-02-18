using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class ClusteredPagedObjectStoreTests : IDisposable
{
    private readonly string _testRoot;
    private readonly LocalFolderBinaryDataProvider _provider;

    public ClusteredPagedObjectStoreTests()
    {
        _testRoot = Path.Combine(Path.GetTempPath(), "BareMetalWeb_Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testRoot);
        _provider = new LocalFolderBinaryDataProvider(_testRoot);
    }

    public void Dispose()
    {
        if (Directory.Exists(_testRoot))
        {
            try
            {
                Directory.Delete(_testRoot, recursive: true);
            }
            catch
            {
                // Best effort cleanup
            }
        }
    }

    private ClusteredPagedObjectStore CreateStore(int pageSize = 16384)
    {
        return new ClusteredPagedObjectStore(_provider, "TestEntity", pageSize);
    }

    private ClusteredPagedObjectStore CreateStore(string entityName, int pageSize = 16384)
    {
        return new ClusteredPagedObjectStore(_provider, entityName, pageSize);
    }

    // --- Constructor validation ---

    [Fact]
    public void Constructor_NullProvider_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new ClusteredPagedObjectStore(null!, "entity"));
    }

    [Fact]
    public void Constructor_NullEntityName_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new ClusteredPagedObjectStore(_provider, null!));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Constructor_InvalidPageSize_ThrowsArgumentOutOfRangeException(int pageSize)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ClusteredPagedObjectStore(_provider, "entity", pageSize));
    }

    [Fact]
    public void Constructor_ValidParameters_DoesNotThrow()
    {
        // Act & Assert — no exception
        var store = new ClusteredPagedObjectStore(_provider, "valid-entity", 1024);
        Assert.NotNull(store);
    }

    // --- Write / Read (basic CRUD) ---

    [Fact]
    public void Write_And_Read_SmallPayload_RoundTrips()
    {
        // Arrange
        var store = CreateStore();
        var payload = Encoding.UTF8.GetBytes("hello world");

        // Act
        var location = store.Write("id1", payload);
        var result = store.Read(location);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(payload, result);
    }

    [Fact]
    public void Write_EmptyPayload_RoundTrips()
    {
        // Arrange
        var store = CreateStore();

        // Act
        var location = store.Write("empty", ReadOnlySpan<byte>.Empty);
        var result = store.Read(location);

        // Assert
        Assert.NotNull(result);
        Assert.Empty(result);
    }

    [Fact]
    public void Write_EmptyId_ThrowsArgumentException()
    {
        // Arrange
        var store = CreateStore();

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            store.Write("", Encoding.UTF8.GetBytes("data")));
    }

    [Fact]
    public void Write_WhitespaceId_ThrowsArgumentException()
    {
        // Arrange
        var store = CreateStore();

        // Act & Assert
        Assert.Throws<ArgumentException>(() =>
            store.Write("   ", Encoding.UTF8.GetBytes("data")));
    }

    [Fact]
    public void Write_ReturnsNonEmptyLocation()
    {
        // Arrange
        var store = CreateStore();

        // Act
        var location = store.Write("loc-test", Encoding.UTF8.GetBytes("data"));

        // Assert
        Assert.False(string.IsNullOrWhiteSpace(location));
    }

    [Fact]
    public void Write_SingleBytePayload_RoundTrips()
    {
        // Arrange
        var store = CreateStore();

        // Act
        var location = store.Write("single", new byte[] { 0xAB });
        var result = store.Read(location);

        // Assert
        Assert.NotNull(result);
        Assert.Single(result);
        Assert.Equal(0xAB, result[0]);
    }

    [Fact]
    public void Write_UnicodeId_RoundTrips()
    {
        // Arrange
        var store = CreateStore();
        var payload = Encoding.UTF8.GetBytes("unicode payload");

        // Act
        var location = store.Write("id-ñoño-日本語", payload);
        var result = store.Read(location);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(payload, result);
    }

    // --- Read edge cases ---

    [Fact]
    public void Read_InvalidLocation_ReturnsNull()
    {
        // Arrange
        var store = CreateStore();

        // Act & Assert
        Assert.Null(store.Read(""));
        Assert.Null(store.Read("invalid"));
        Assert.Null(store.Read("abc:def"));
    }

    [Fact]
    public void Read_NonExistentPage_ReturnsNull()
    {
        // Arrange
        var store = CreateStore();
        store.Write("seed", Encoding.UTF8.GetBytes("seed"));

        // Act
        var result = store.Read("999:0");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void Read_NullLocation_ReturnsNull()
    {
        // Arrange
        var store = CreateStore();

        // Act & Assert
        Assert.Null(store.Read(null!));
    }

    [Fact]
    public void Read_ZeroPageIndex_ReturnsNull()
    {
        // Arrange
        var store = CreateStore();
        store.Write("seed", Encoding.UTF8.GetBytes("seed"));

        // Act — page 0 is the header, not valid for data reads
        var result = store.Read("0:0");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void Read_InvalidOverflowLocation_ReturnsNull()
    {
        // Arrange
        var store = CreateStore();
        store.Write("seed", Encoding.UTF8.GetBytes("seed"));

        // Act & Assert
        Assert.Null(store.Read("o:999:1"));
        Assert.Null(store.Read("o:0:1"));
        Assert.Null(store.Read("o:1:0"));
    }

    // --- Delete ---

    [Fact]
    public void Delete_ExistingRecord_ReturnsTrue_AndReadReturnsNull()
    {
        // Arrange
        var store = CreateStore();
        var location = store.Write("del1", Encoding.UTF8.GetBytes("to delete"));

        // Act
        var deleted = store.Delete(location);
        var result = store.Read(location);

        // Assert
        Assert.True(deleted);
        Assert.Null(result);
    }

    [Fact]
    public void Delete_AlreadyDeleted_ReturnsFalse()
    {
        // Arrange
        var store = CreateStore();
        var location = store.Write("del2", Encoding.UTF8.GetBytes("data"));
        store.Delete(location);

        // Act
        var secondDelete = store.Delete(location);

        // Assert
        Assert.False(secondDelete);
    }

    [Fact]
    public void Delete_InvalidLocation_ReturnsFalse()
    {
        // Arrange
        var store = CreateStore();

        // Act & Assert
        Assert.False(store.Delete(""));
        Assert.False(store.Delete("invalid"));
        Assert.False(store.Delete("999:0"));
    }

    [Fact]
    public void Delete_NullLocation_ReturnsFalse()
    {
        // Arrange
        var store = CreateStore();

        // Act & Assert
        Assert.False(store.Delete(null!));
    }

    [Fact]
    public void Delete_NonExistentPage_ReturnsFalse()
    {
        // Arrange
        var store = CreateStore();
        store.Write("seed", Encoding.UTF8.GetBytes("seed"));

        // Act
        var result = store.Delete("999:0");

        // Assert
        Assert.False(result);
    }

    // --- Multiple objects ---

    [Fact]
    public void Write_MultipleObjects_AllRetrievable()
    {
        // Arrange
        var store = CreateStore();
        var locations = new Dictionary<string, string>();

        // Act
        for (int i = 0; i < 10; i++)
        {
            var id = $"obj-{i}";
            var payload = Encoding.UTF8.GetBytes($"payload-{i}");
            locations[id] = store.Write(id, payload);
        }

        // Assert
        for (int i = 0; i < 10; i++)
        {
            var result = store.Read(locations[$"obj-{i}"]);
            Assert.NotNull(result);
            Assert.Equal($"payload-{i}", Encoding.UTF8.GetString(result));
        }
    }

    [Fact]
    public void Write_MultipleObjects_DeleteOne_OthersStillAccessible()
    {
        // Arrange
        var store = CreateStore();
        var loc1 = store.Write("a", Encoding.UTF8.GetBytes("aaa"));
        var loc2 = store.Write("b", Encoding.UTF8.GetBytes("bbb"));
        var loc3 = store.Write("c", Encoding.UTF8.GetBytes("ccc"));

        // Act
        store.Delete(loc2);

        // Assert
        Assert.NotNull(store.Read(loc1));
        Assert.Null(store.Read(loc2));
        Assert.NotNull(store.Read(loc3));
        Assert.Equal("aaa", Encoding.UTF8.GetString(store.Read(loc1)!));
        Assert.Equal("ccc", Encoding.UTF8.GetString(store.Read(loc3)!));
    }

    [Fact]
    public void Write_MultipleObjects_DeleteAll_AllReturnNull()
    {
        // Arrange
        var store = CreateStore();
        var locations = new List<string>();
        for (int i = 0; i < 5; i++)
            locations.Add(store.Write($"d{i}", Encoding.UTF8.GetBytes($"data{i}")));

        // Act
        foreach (var loc in locations)
            store.Delete(loc);

        // Assert
        foreach (var loc in locations)
            Assert.Null(store.Read(loc));
    }

    // --- Large object / overflow handling ---

    [Fact]
    public void Write_LargeObject_RoundTrips()
    {
        // Arrange — use a small page size to force overflow
        var store = CreateStore(pageSize: 512);
        var payload = new byte[4096];
        new Random(42).NextBytes(payload);

        // Act
        var location = store.Write("large", payload);
        var result = store.Read(location);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(payload, result);
    }

    [Fact]
    public void Write_LargeObject_LocationIsOverflowFormat()
    {
        // Arrange — small page forces overflow path
        var store = CreateStore(pageSize: 512);
        var payload = new byte[2048];
        new Random(42).NextBytes(payload);

        // Act
        var location = store.Write("overflow-id", payload);

        // Assert — overflow locations start with "o:"
        Assert.StartsWith("o:", location);
    }

    [Fact]
    public void Delete_LargeObject_ReturnsTrue_AndReadReturnsNull()
    {
        // Arrange
        var store = CreateStore(pageSize: 512);
        var payload = new byte[4096];
        new Random(42).NextBytes(payload);
        var location = store.Write("large-del", payload);

        // Act
        var deleted = store.Delete(location);
        var result = store.Read(location);

        // Assert
        Assert.True(deleted);
        Assert.Null(result);
    }

    [Fact]
    public void Write_VeryLargeObject_MultipleOverflowPages_RoundTrips()
    {
        // Arrange — 64KB payload with 512-byte pages = many overflow pages
        var store = CreateStore(pageSize: 512);
        var payload = new byte[65536];
        new Random(123).NextBytes(payload);

        // Act
        var location = store.Write("huge", payload);
        var result = store.Read(location);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(payload, result);
    }

    [Fact]
    public void Write_LargeObject_ExactlyOnePageCapacity_RoundTrips()
    {
        // Arrange — payload that fills exactly one overflow page
        var store = CreateStore(pageSize: 512);
        var overflowHeaderSize = 16;
        var payload = new byte[512 - overflowHeaderSize - 10]; // just under one page
        new Random(77).NextBytes(payload);

        // Act
        var location = store.Write("exact", payload);
        var result = store.Read(location);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(payload, result);
    }

    [Fact]
    public void Delete_LargeObject_AlreadyDeleted_StillSucceeds()
    {
        // Arrange — overflow delete marks pages as 'X' but does not track prior state,
        // so deleting again still returns true as long as the pages exist.
        var store = CreateStore(pageSize: 512);
        var payload = new byte[2048];
        new Random(42).NextBytes(payload);
        var location = store.Write("large-del2", payload);
        store.Delete(location);

        // Act
        var secondDelete = store.Delete(location);

        // Assert — overflow pages are always re-markable
        Assert.True(secondDelete);
    }

    [Fact]
    public void Write_MultipleLargeObjects_EachRoundTrips()
    {
        // Arrange
        var store = CreateStore(pageSize: 512);
        var rng = new Random(99);
        var entries = new Dictionary<string, byte[]>();
        var locations = new Dictionary<string, string>();

        for (int i = 0; i < 3; i++)
        {
            var payload = new byte[2048 + i * 512];
            rng.NextBytes(payload);
            entries[$"big{i}"] = payload;
            locations[$"big{i}"] = store.Write($"big{i}", payload);
        }

        // Act & Assert
        foreach (var kvp in entries)
        {
            var result = store.Read(locations[kvp.Key]);
            Assert.NotNull(result);
            Assert.Equal(kvp.Value, result);
        }
    }

    // --- Page allocation ---

    [Fact]
    public void Write_FillsPage_AllRecordsOnSinglePageRetrievable()
    {
        // Arrange — use a page size that fits all records on a single page
        var store = CreateStore(pageSize: 4096);
        var locations = new Dictionary<string, string>();

        // Act — write records that all fit within one 4096-byte page
        for (int i = 0; i < 20; i++)
        {
            var id = $"r{i}";
            var payload = Encoding.UTF8.GetBytes($"v{i}");
            locations[id] = store.Write(id, payload);
        }

        // Assert — all should be readable
        for (int i = 0; i < 20; i++)
        {
            var result = store.Read(locations[$"r{i}"]);
            Assert.NotNull(result);
            Assert.Equal($"v{i}", Encoding.UTF8.GetString(result));
        }
    }

    [Fact]
    public void Write_ManySmallRecords_FitOnSinglePage_AllRetrievable()
    {
        // Arrange — 512-byte page fits approximately 17 small records
        var store = CreateStore(pageSize: 512);
        var locations = new Dictionary<string, string>();

        // Act — write 15 records (well within single page capacity)
        for (int i = 0; i < 15; i++)
        {
            var id = $"r{i}";
            var payload = Encoding.UTF8.GetBytes($"v{i}");
            locations[id] = store.Write(id, payload);
        }

        // Assert — all should be readable
        foreach (var kvp in locations)
        {
            var result = store.Read(kvp.Value);
            Assert.NotNull(result);
        }
    }

    [Fact]
    public void Write_RecordsProduceUniqueLocationsOnSamePage()
    {
        // Arrange
        var store = CreateStore();
        var locations = new List<string>();

        // Act
        for (int i = 0; i < 5; i++)
            locations.Add(store.Write($"u{i}", Encoding.UTF8.GetBytes($"val{i}")));

        // Assert — each location should be unique
        Assert.Equal(locations.Count, locations.Distinct().Count());
    }

    [Fact]
    public void Write_LocationFormat_ContainsPageAndSlot()
    {
        // Arrange
        var store = CreateStore();

        // Act
        var location = store.Write("fmt", Encoding.UTF8.GetBytes("data"));

        // Assert — non-overflow location is "page:slot"
        Assert.DoesNotContain("o:", location);
        var parsed = ClusteredPagedObjectStore.TryParseLocation(location, out var page, out var slot);
        Assert.True(parsed);
        Assert.True(page > 0);
    }

    // --- Exists ---

    [Fact]
    public void Exists_BeforeAnyWrite_ReturnsFalse()
    {
        // Arrange
        var store = new ClusteredPagedObjectStore(_provider, "NonExistent");

        // Act & Assert
        Assert.False(store.Exists());
    }

    [Fact]
    public void Exists_AfterWrite_ReturnsTrue()
    {
        // Arrange
        var store = CreateStore();
        store.Write("x", Encoding.UTF8.GetBytes("data"));

        // Act & Assert
        Assert.True(store.Exists());
    }

    [Fact]
    public void Exists_DifferentEntities_Independent()
    {
        // Arrange
        var storeA = CreateStore("EntityA");
        var storeB = CreateStore("EntityB");

        // Act
        storeA.Write("x", Encoding.UTF8.GetBytes("data"));

        // Assert
        Assert.True(storeA.Exists());
        Assert.False(storeB.Exists());
    }

    // --- TryParseLocation (static) ---

    [Fact]
    public void TryParseLocation_ValidLocation_ReturnsTrue()
    {
        // Act
        var result = ClusteredPagedObjectStore.TryParseLocation("5:3", out var pageIndex, out var slotIndex);

        // Assert
        Assert.True(result);
        Assert.Equal(5, pageIndex);
        Assert.Equal(3, slotIndex);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("invalid")]
    [InlineData("a:b")]
    [InlineData("0:0")]
    [InlineData("o:1:2")]
    public void TryParseLocation_InvalidInputs_ReturnsFalse(string input)
    {
        // Act
        var result = ClusteredPagedObjectStore.TryParseLocation(input, out _, out _);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void TryParseLocation_NullInput_ReturnsFalse()
    {
        // Act
        var result = ClusteredPagedObjectStore.TryParseLocation(null!, out _, out _);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void TryParseLocation_LargeIndices_ReturnsTrue()
    {
        // Act
        var result = ClusteredPagedObjectStore.TryParseLocation("100000:65535", out var page, out var slot);

        // Assert
        Assert.True(result);
        Assert.Equal(100000, page);
        Assert.Equal(65535, slot);
    }

    [Fact]
    public void TryParseLocation_ThreeParts_ReturnsFalse()
    {
        // Act — three colon-separated parts (not overflow format) should fail
        var result = ClusteredPagedObjectStore.TryParseLocation("1:2:3", out _, out _);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void TryParseLocation_NegativePage_ReturnsFalse()
    {
        // Act
        var result = ClusteredPagedObjectStore.TryParseLocation("-1:0", out _, out _);

        // Assert
        Assert.False(result);
    }

    // --- Compact ---

    [Fact]
    public void Compact_RewritesLiveRecords_WithNewLocations()
    {
        // Arrange
        var store = CreateStore();
        var loc1 = store.Write("a", Encoding.UTF8.GetBytes("alpha"));
        var loc2 = store.Write("b", Encoding.UTF8.GetBytes("beta"));
        var loc3 = store.Write("c", Encoding.UTF8.GetBytes("gamma"));

        // Delete one so that compaction has something to skip
        store.Delete(loc2);

        var liveLocations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["a"] = loc1,
            ["c"] = loc3
        };

        // Act
        var newMap = store.Compact(liveLocations);

        // Assert
        Assert.Equal(2, newMap.Count);
        Assert.True(newMap.ContainsKey("a"));
        Assert.True(newMap.ContainsKey("c"));

        var resultA = store.Read(newMap["a"]);
        var resultC = store.Read(newMap["c"]);
        Assert.NotNull(resultA);
        Assert.NotNull(resultC);
        Assert.Equal("alpha", Encoding.UTF8.GetString(resultA));
        Assert.Equal("gamma", Encoding.UTF8.GetString(resultC));
    }

    [Fact]
    public void Compact_EmptyLiveLocations_ReturnsEmptyMap()
    {
        // Arrange
        var store = CreateStore();
        store.Write("x", Encoding.UTF8.GetBytes("data"));

        // Act
        var result = store.Compact(new Dictionary<string, string>());

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void Compact_NullLiveLocations_ReturnsEmptyMap()
    {
        // Arrange
        var store = CreateStore();

        // Act
        var result = store.Compact(null!);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public void Compact_AllLive_PreservesAllData()
    {
        // Arrange
        var store = CreateStore();
        var loc1 = store.Write("x", Encoding.UTF8.GetBytes("xdata"));
        var loc2 = store.Write("y", Encoding.UTF8.GetBytes("ydata"));

        var liveLocations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["x"] = loc1,
            ["y"] = loc2
        };

        // Act
        var newMap = store.Compact(liveLocations);

        // Assert
        Assert.Equal(2, newMap.Count);
        Assert.Equal("xdata", Encoding.UTF8.GetString(store.Read(newMap["x"])!));
        Assert.Equal("ydata", Encoding.UTF8.GetString(store.Read(newMap["y"])!));
    }

    [Fact]
    public void Compact_WithOverflowRecords_PreservesData()
    {
        // Arrange
        var store = CreateStore(pageSize: 512);
        var payload = new byte[2048];
        new Random(42).NextBytes(payload);
        var loc = store.Write("overflow-compact", payload);

        var liveLocations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["overflow-compact"] = loc
        };

        // Act
        var newMap = store.Compact(liveLocations);

        // Assert
        Assert.Single(newMap);
        var result = store.Read(newMap["overflow-compact"]);
        Assert.NotNull(result);
        Assert.Equal(payload, result);
    }

    // --- Concurrent access ---

    [Fact]
    public async Task ConcurrentReads_AfterSequentialWrites_AllRetrievable()
    {
        // Arrange — write sequentially to avoid write contention
        var store = CreateStore();
        var locations = new Dictionary<string, string>();
        for (int i = 0; i < 40; i++)
        {
            var id = $"item-{i}";
            locations[id] = store.Write(id, Encoding.UTF8.GetBytes($"data-{id}"));
        }

        // Act — read concurrently from multiple threads
        var errors = new System.Collections.Concurrent.ConcurrentBag<string>();
        var tasks = new Task[8];
        for (int t = 0; t < tasks.Length; t++)
        {
            var threadId = t;
            tasks[t] = Task.Run(() =>
            {
                for (int i = 0; i < 40; i++)
                {
                    var id = $"item-{i}";
                    var result = store.Read(locations[id]);
                    if (result == null || Encoding.UTF8.GetString(result) != $"data-{id}")
                        errors.Add($"Thread {threadId}: mismatch for {id}");
                }
            });
        }
        await Task.WhenAll(tasks);

        // Assert
        Assert.Empty(errors);
    }

    [Fact]
    public async Task ConcurrentWrites_SeparateEntities_AllRetrievable()
    {
        // Arrange — each thread writes to its own entity to avoid file contention
        var locations = new System.Collections.Concurrent.ConcurrentDictionary<string, (string Location, string EntityName)>();

        // Act
        var tasks = new Task[4];
        for (int t = 0; t < tasks.Length; t++)
        {
            var threadId = t;
            tasks[t] = Task.Run(() =>
            {
                var entityName = $"ConcurrentEntity{threadId}";
                var threadStore = CreateStore(entityName);
                for (int i = 0; i < 5; i++)
                {
                    var id = $"t{threadId}-{i}";
                    var payload = Encoding.UTF8.GetBytes($"data-{id}");
                    var loc = threadStore.Write(id, payload);
                    locations[id] = (loc, entityName);
                }
            });
        }
        await Task.WhenAll(tasks);

        // Assert — every record should be readable from its entity store
        foreach (var kvp in locations)
        {
            var threadStore = CreateStore(kvp.Value.EntityName);
            var result = threadStore.Read(kvp.Value.Location);
            Assert.NotNull(result);
            Assert.Equal($"data-{kvp.Key}", Encoding.UTF8.GetString(result));
        }
    }

    // --- Binary payload integrity ---

    [Fact]
    public void Write_BinaryPayload_PreservesExactBytes()
    {
        // Arrange
        var store = CreateStore();
        var payload = new byte[256];
        for (int i = 0; i < 256; i++)
            payload[i] = (byte)i;

        // Act
        var location = store.Write("binary", payload);
        var result = store.Read(location);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(payload, result);
    }

    [Fact]
    public void Write_PayloadWithAllZeros_RoundTrips()
    {
        // Arrange
        var store = CreateStore();
        var payload = new byte[1024];

        // Act
        var location = store.Write("zeros", payload);
        var result = store.Read(location);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(payload, result);
    }

    [Fact]
    public void Write_PayloadWithAllOnes_RoundTrips()
    {
        // Arrange
        var store = CreateStore();
        var payload = new byte[512];
        Array.Fill(payload, (byte)0xFF);

        // Act
        var location = store.Write("ones", payload);
        var result = store.Read(location);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(payload, result);
    }

    [Fact]
    public void Write_RepetitiveData_CompressesAndRoundTrips()
    {
        // Arrange — highly repetitive data should compress well with Brotli
        var store = CreateStore();
        var payload = new byte[4096];
        for (int i = 0; i < payload.Length; i++)
            payload[i] = (byte)(i % 4);

        // Act
        var location = store.Write("compressible", payload);
        var result = store.Read(location);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(payload, result);
    }

    // --- Error recovery ---

    [Fact]
    public void Read_AfterDeletedRecord_StillReturnsNull()
    {
        // Arrange
        var store = CreateStore();
        var location = store.Write("recover", Encoding.UTF8.GetBytes("data"));
        store.Delete(location);

        // Act — read the deleted record multiple times
        var result1 = store.Read(location);
        var result2 = store.Read(location);

        // Assert
        Assert.Null(result1);
        Assert.Null(result2);
    }

    [Fact]
    public void Write_AfterDelete_NewRecordIsIndependent()
    {
        // Arrange
        var store = CreateStore();
        var loc1 = store.Write("first", Encoding.UTF8.GetBytes("original"));
        store.Delete(loc1);

        // Act — write a new record after deletion
        var loc2 = store.Write("second", Encoding.UTF8.GetBytes("replacement"));
        var result = store.Read(loc2);

        // Assert
        Assert.Null(store.Read(loc1));
        Assert.NotNull(result);
        Assert.Equal("replacement", Encoding.UTF8.GetString(result));
    }

    [Fact]
    public void Read_WithMalformedOverflowLocation_ReturnsNull()
    {
        // Arrange
        var store = CreateStore();
        store.Write("seed", Encoding.UTF8.GetBytes("seed"));

        // Act & Assert — malformed overflow locations
        Assert.Null(store.Read("o:"));
        Assert.Null(store.Read("o:abc:1"));
        Assert.Null(store.Read("o:1:abc"));
        Assert.Null(store.Read("o:-1:1"));
    }

    [Fact]
    public void Delete_WithMalformedOverflowLocation_ReturnsFalse()
    {
        // Arrange
        var store = CreateStore();

        // Act & Assert
        Assert.False(store.Delete("o:"));
        Assert.False(store.Delete("o:abc:1"));
        Assert.False(store.Delete("o:1:abc"));
    }

    // --- Separate entity isolation ---

    [Fact]
    public void Write_DifferentEntities_DoNotInterfere()
    {
        // Arrange
        var storeA = CreateStore("EntityA");
        var storeB = CreateStore("EntityB");

        // Act
        var locA = storeA.Write("id1", Encoding.UTF8.GetBytes("dataA"));
        var locB = storeB.Write("id1", Encoding.UTF8.GetBytes("dataB"));

        // Assert — each store reads its own data
        Assert.Equal("dataA", Encoding.UTF8.GetString(storeA.Read(locA)!));
        Assert.Equal("dataB", Encoding.UTF8.GetString(storeB.Read(locB)!));
    }

    // --- Compact with deleted overflow ---

    [Fact]
    public void Compact_AfterDeletingSomeRecords_PreservesRemainingData()
    {
        // Arrange — use only regular (non-overflow) records to avoid page conflicts
        var store = CreateStore();

        var locA = store.Write("rec-a", Encoding.UTF8.GetBytes("alpha"));
        var locB = store.Write("rec-b", Encoding.UTF8.GetBytes("beta"));
        var locC = store.Write("rec-c", Encoding.UTF8.GetBytes("gamma"));

        store.Delete(locB);

        var liveLocations = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["rec-a"] = locA,
            ["rec-c"] = locC
        };

        // Act
        var newMap = store.Compact(liveLocations);

        // Assert
        Assert.Equal(2, newMap.Count);
        Assert.Equal("alpha", Encoding.UTF8.GetString(store.Read(newMap["rec-a"])!));
        Assert.Equal("gamma", Encoding.UTF8.GetString(store.Read(newMap["rec-c"])!));
    }

    // --- Write/read with varying payload sizes ---

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(100)]
    [InlineData(1000)]
    [InlineData(8000)]
    public void Write_VariousPayloadSizes_RoundTrips(int size)
    {
        // Arrange
        var store = CreateStore();
        var payload = new byte[size];
        if (size > 0)
            new Random(size).NextBytes(payload);

        // Act
        var location = store.Write($"size-{size}", payload);
        var result = store.Read(location);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(payload, result);
    }

    // --- Overflow with varying sizes ---

    [Theory]
    [InlineData(600)]
    [InlineData(1024)]
    [InlineData(5000)]
    [InlineData(32768)]
    public void Write_OverflowVariousSizes_RoundTrips(int size)
    {
        // Arrange — 512-byte page forces overflow for larger payloads
        var store = CreateStore(pageSize: 512);
        var payload = new byte[size];
        new Random(size).NextBytes(payload);

        // Act
        var location = store.Write($"ovf-{size}", payload);
        var result = store.Read(location);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(payload, result);
    }
}
