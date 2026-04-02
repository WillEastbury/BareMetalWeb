using System;
using System.IO;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests that sequential IDs are persisted across simulated application restarts
/// so that duplicate IDs are never generated.
/// </summary>
public class SequentialIdPersistenceTests : IDisposable
{
    private readonly string _tempRoot;

    public SequentialIdPersistenceTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), "bmw_seq_id_tests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_tempRoot);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempRoot))
            Directory.Delete(_tempRoot, recursive: true);
    }

    [Fact]
    public void NextSequentialKey_IncrementsFromOne()
    {
        // Arrange
        var provider = new WalDataProvider(_tempRoot);

        // Act
        var id1 = provider.NextSequentialKey("Widget");
        var id2 = provider.NextSequentialKey("Widget");
        var id3 = provider.NextSequentialKey("Widget");

        // Assert
        Assert.Equal(1u, id1);
        Assert.Equal(2u, id2);
        Assert.Equal(3u, id3);
    }

    [Fact]
    public void NextSequentialKey_SurvivesProviderReplacement_NoDuplicates()
    {
        // Arrange – first "run" generates some IDs
        var provider1 = new WalDataProvider(_tempRoot);
        var id1 = provider1.NextSequentialKey("Invoice");
        var id2 = provider1.NextSequentialKey("Invoice");
        Assert.True(id2 > id1);

        // Act – create a brand-new provider instance pointing at the same root
        // (simulates an application restart — batch-allocated IDs may leave gaps).
        var provider2 = new WalDataProvider(_tempRoot);
        var id3 = provider2.NextSequentialKey("Invoice");
        var id4 = provider2.NextSequentialKey("Invoice");

        // Assert – counter must be strictly greater than previous run, no duplicates.
        Assert.True(id3 > id2, $"Expected id3 ({id3}) > id2 ({id2}) across simulated restart.");
        Assert.True(id4 > id3);
        Assert.NotEqual(id1, id3);
        Assert.NotEqual(id2, id3);
        Assert.NotEqual(id1, id4);
        Assert.NotEqual(id2, id4);
    }

    [Fact]
    public void SeedSequentialKey_SetsFloorWhenCurrentIsLower()
    {
        // Arrange
        var provider = new WalDataProvider(_tempRoot);

        // Act – seed to 100 (simulates migration from existing data with max ID = 100)
        provider.SeedSequentialKey("Order", 100);
        var next = provider.NextSequentialKey("Order");

        // Assert – first generated ID must be > 100
        Assert.True(next > 100);
    }

    [Fact]
    public void SeedSequentialKey_DoesNotLowerExistingCounter()
    {
        // Arrange – advance counter to 50
        var provider = new WalDataProvider(_tempRoot);
        uint lastId = 0;
        for (int i = 0; i < 50; i++)
            lastId = provider.NextSequentialKey("Product");

        // Act – try to seed with a lower value
        provider.SeedSequentialKey("Product", 10);
        var next = provider.NextSequentialKey("Product");

        // Assert – counter must NOT go backwards (batch allocation may skip ahead)
        Assert.True(next > lastId, $"Expected next ({next}) > lastId ({lastId}) after low seed.");
    }

    [Fact]
    public void NextSequentialKey_IsolatedPerEntityName()
    {
        // Arrange
        var provider = new WalDataProvider(_tempRoot);

        // Act
        var inv1 = provider.NextSequentialKey("Invoice");
        var ord1 = provider.NextSequentialKey("Order");
        var inv2 = provider.NextSequentialKey("Invoice");

        // Assert – each entity has an independent counter
        Assert.Equal(1u, inv1);
        Assert.Equal(1u, ord1);
        Assert.Equal(2u, inv2);
    }

    [Fact]
    public void DefaultIdGenerator_WithProvider_UsesPersistentCounter()
    {
        // Arrange – register a persistent provider
        var originalProvider = DataStoreProvider.PrimaryProvider;
        try
        {
            var provider = new WalDataProvider(_tempRoot);
            DataStoreProvider.PrimaryProvider = provider;

            var generator = new DefaultIdGenerator();

            // Act – "first run"
            var id1 = generator.GenerateKey(typeof(FakeEntity));
            var id2 = generator.GenerateKey(typeof(FakeEntity));

            // Swap in a fresh provider instance (simulates restart with same data root)
            DataStoreProvider.PrimaryProvider = new WalDataProvider(_tempRoot);
            var generator2 = new DefaultIdGenerator();

            // Act – "second run"
            var id3 = generator2.GenerateKey(typeof(FakeEntity));

            // Assert – no duplicates across "restarts"
            Assert.True(id2 > id1);
            Assert.True(id3 > id2, $"Expected id3 ({id3}) > id2 ({id2}) across simulated restart.");
        }
        finally
        {
            DataStoreProvider.PrimaryProvider = originalProvider;
        }
    }

    private class FakeEntity : DataRecord
    {
        internal new const int TotalFieldCount = BaseFieldCount;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public FakeEntity() : base(TotalFieldCount) { }
        public FakeEntity(string createdBy) : base(TotalFieldCount, createdBy) { }
    }
}
