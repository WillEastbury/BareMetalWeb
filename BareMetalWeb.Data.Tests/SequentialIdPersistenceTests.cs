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
    public void NextSequentialId_IncrementsFromOne()
    {
        // Arrange
        var provider = new LocalFolderBinaryDataProvider(_tempRoot);

        // Act
        var id1 = provider.NextSequentialId("Widget");
        var id2 = provider.NextSequentialId("Widget");
        var id3 = provider.NextSequentialId("Widget");

        // Assert
        Assert.Equal("1", id1);
        Assert.Equal("2", id2);
        Assert.Equal("3", id3);
    }

    [Fact]
    public void NextSequentialId_SurvivesProviderReplacement_NoDuplicates()
    {
        // Arrange – first "run" generates some IDs
        var provider1 = new LocalFolderBinaryDataProvider(_tempRoot);
        var id1 = provider1.NextSequentialId("Invoice");
        var id2 = provider1.NextSequentialId("Invoice");
        Assert.Equal("1", id1);
        Assert.Equal("2", id2);

        // Act – create a brand-new provider instance pointing at the same root
        // (simulates an application restart).
        var provider2 = new LocalFolderBinaryDataProvider(_tempRoot);
        var id3 = provider2.NextSequentialId("Invoice");
        var id4 = provider2.NextSequentialId("Invoice");

        // Assert – counter must continue from where it left off, no duplicates.
        Assert.Equal("3", id3);
        Assert.Equal("4", id4);
        Assert.NotEqual(id1, id3);
        Assert.NotEqual(id2, id3);
        Assert.NotEqual(id1, id4);
        Assert.NotEqual(id2, id4);
    }

    [Fact]
    public void SeedSequentialId_SetsFloorWhenCurrentIsLower()
    {
        // Arrange
        var provider = new LocalFolderBinaryDataProvider(_tempRoot);

        // Act – seed to 100 (simulates migration from existing data with max ID = 100)
        provider.SeedSequentialId("Order", 100);
        var next = provider.NextSequentialId("Order");

        // Assert – first generated ID must be > 100
        Assert.True(long.TryParse(next, out var num));
        Assert.True(num > 100);
    }

    [Fact]
    public void SeedSequentialId_DoesNotLowerExistingCounter()
    {
        // Arrange – advance counter to 50
        var provider = new LocalFolderBinaryDataProvider(_tempRoot);
        for (int i = 0; i < 50; i++)
            provider.NextSequentialId("Product");

        // Act – try to seed with a lower value
        provider.SeedSequentialId("Product", 10);
        var next = provider.NextSequentialId("Product");

        // Assert – counter must NOT go backwards
        Assert.True(long.TryParse(next, out var num));
        Assert.Equal(51, num);
    }

    [Fact]
    public void NextSequentialId_IsolatedPerEntityName()
    {
        // Arrange
        var provider = new LocalFolderBinaryDataProvider(_tempRoot);

        // Act
        var inv1 = provider.NextSequentialId("Invoice");
        var ord1 = provider.NextSequentialId("Order");
        var inv2 = provider.NextSequentialId("Invoice");

        // Assert – each entity has an independent counter
        Assert.Equal("1", inv1);
        Assert.Equal("1", ord1);
        Assert.Equal("2", inv2);
    }

    [Fact]
    public void DefaultIdGenerator_WithProvider_UsesPersistentCounter()
    {
        // Arrange – register a persistent provider
        var originalProvider = DataStoreProvider.PrimaryProvider;
        try
        {
            var provider = new LocalFolderBinaryDataProvider(_tempRoot);
            DataStoreProvider.PrimaryProvider = provider;

            var generator = new DefaultIdGenerator();

            // Act – "first run"
            var id1 = generator.GenerateId(typeof(FakeEntity), IdGenerationStrategy.SequentialLong);
            var id2 = generator.GenerateId(typeof(FakeEntity), IdGenerationStrategy.SequentialLong);

            // Swap in a fresh provider instance (simulates restart with same data root)
            DataStoreProvider.PrimaryProvider = new LocalFolderBinaryDataProvider(_tempRoot);
            var generator2 = new DefaultIdGenerator();

            // Act – "second run"
            var id3 = generator2.GenerateId(typeof(FakeEntity), IdGenerationStrategy.SequentialLong);

            // Assert – no duplicates across "restarts"
            Assert.True(long.TryParse(id1, out var n1));
            Assert.True(long.TryParse(id2, out var n2));
            Assert.True(long.TryParse(id3, out var n3));
            Assert.True(n2 > n1);
            Assert.True(n3 > n2, $"Expected id3 ({n3}) > id2 ({n2}) across simulated restart.");
        }
        finally
        {
            DataStoreProvider.PrimaryProvider = originalProvider;
        }
    }

    private class FakeEntity : BaseDataObject { }
}
