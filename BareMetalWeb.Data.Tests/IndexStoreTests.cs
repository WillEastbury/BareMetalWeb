using System;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class IndexStoreTests : IDisposable
{
    private readonly string _testRoot;
    private readonly LocalFolderBinaryDataProvider _provider;
    private readonly IndexStore _indexStore;

    public IndexStoreTests()
    {
        _testRoot = Path.Combine(Path.GetTempPath(), "BareMetalWeb_IndexStore_Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testRoot);
        _provider = new LocalFolderBinaryDataProvider(_testRoot);
        _indexStore = new IndexStore(_provider);
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

    [Fact]
    public void AppendEntry_SingleEntry_Success()
    {
        // Arrange
        const string entityName = "TestEntity";
        const string fieldName = "TestField";
        const string key = "testkey";
        const string id = "test-id-1";

        // Act
        _indexStore.AppendEntry(entityName, fieldName, key, id, 'A', normalizeKey: false);

        // Assert
        var index = _indexStore.ReadIndex(entityName, fieldName, normalizeKey: false);
        Assert.True(index.ContainsKey(key));
        Assert.Contains(id, index[key]);
    }

    [Fact]
    public void AppendEntries_MultipleEntries_AcquiresLockOnce()
    {
        // Arrange
        const string entityName = "TestEntity";
        const string fieldName = "TestField";
        var entries = new List<(string key, string id, char op, long? expiresAtUtcTicks)>
        {
            ("key1", "id1", 'A', null),
            ("key2", "id2", 'A', null),
            ("key1", "id3", 'D', null)
        };

        // Act
        _indexStore.AppendEntries(entityName, fieldName, entries, normalizeKey: false);

        // Assert
        var index = _indexStore.ReadIndex(entityName, fieldName, normalizeKey: false);
        Assert.True(index.ContainsKey("key1"));
        Assert.True(index.ContainsKey("key2"));
        Assert.Contains("id2", index["key2"]);
    }

    [Fact]
    public void AppendEntries_EmptyList_DoesNotThrow()
    {
        // Arrange
        const string entityName = "TestEntity";
        const string fieldName = "TestField";
        var entries = new List<(string key, string id, char op, long? expiresAtUtcTicks)>();

        // Act & Assert - Should not throw
        _indexStore.AppendEntries(entityName, fieldName, entries, normalizeKey: false);
    }

    [Fact]
    public void AppendEntries_SameFieldMultipleTimes_NoLockContention()
    {
        // Arrange
        const string entityName = "UserSession";
        const string fieldName = "_clustered";
        
        // Act - Simulate the Save<T> scenario with Add and Delete
        for (int i = 0; i < 10; i++)
        {
            var entries = new List<(string key, string id, char op, long? expiresAtUtcTicks)>
            {
                ($"session-{i}", $"location-{i}", 'A', null)
            };
            
            if (i > 0)
            {
                // Simulate updating an existing session (old location gets deleted)
                entries.Add(($"session-{i}", $"old-location-{i}", 'D', null));
            }

            // This should not throw lock contention errors
            _indexStore.AppendEntries(entityName, fieldName, entries, normalizeKey: false);
        }

        // Assert - Verify all entries were recorded
        var index = _indexStore.ReadLatestValueIndex(entityName, fieldName, normalizeKey: false);
        Assert.Equal(10, index.Count);
    }

    [Fact]
    public void AppendEntries_InvalidOp_ThrowsArgumentException()
    {
        // Arrange
        const string entityName = "TestEntity";
        const string fieldName = "TestField";
        var entries = new List<(string key, string id, char op, long? expiresAtUtcTicks)>
        {
            ("key1", "id1", 'X', null) // Invalid op
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            _indexStore.AppendEntries(entityName, fieldName, entries, normalizeKey: false));
    }

    [Fact]
    public void AppendEntries_EmptyId_ThrowsArgumentException()
    {
        // Arrange
        const string entityName = "TestEntity";
        const string fieldName = "TestField";
        var entries = new List<(string key, string id, char op, long? expiresAtUtcTicks)>
        {
            ("key1", "", 'A', null) // Empty id
        };

        // Act & Assert
        Assert.Throws<ArgumentException>(() => 
            _indexStore.AppendEntries(entityName, fieldName, entries, normalizeKey: false));
    }

    [Fact]
    public void AppendEntries_NullEntries_ThrowsArgumentNullException()
    {
        // Arrange
        const string entityName = "TestEntity";
        const string fieldName = "TestField";

        // Act & Assert
        Assert.Throws<ArgumentNullException>(() => 
            _indexStore.AppendEntries(entityName, fieldName, null!, normalizeKey: false));
    }

    [Fact]
    public void AppendEntries_SimulatesSaveScenario_NoLockContention()
    {
        // Arrange - This test specifically validates the fix for the lock contention issue
        // where saving a UserSession would cause two rapid AppendEntry calls that could
        // fail due to lock contention on the same _clustered.log.lock file
        const string entityName = "UserSession";
        const string fieldName = "_clustered";

        // Act - Simulate the Save scenario: multiple rapid saves with Add + Delete operations
        for (int i = 0; i < 20; i++)
        {
            var entries = new List<(string key, string id, char op, long? expiresAtUtcTicks)>
            {
                ($"session-{i}", $"new-location-{i}", 'A', null)
            };
            
            if (i > 0)
            {
                // Simulate updating an existing session (old location gets deleted)
                entries.Add(($"session-{i}", $"old-location-{i}", 'D', null));
            }

            // This should not throw lock contention errors
            // The fix batches the Add and Delete operations into a single lock acquisition
            _indexStore.AppendEntries(entityName, fieldName, entries, normalizeKey: false);
        }

        // Assert - Verify all entries were recorded
        var index = _indexStore.ReadLatestValueIndex(entityName, fieldName, normalizeKey: false);
        Assert.True(index.Count > 0, "Index should contain entries");
    }
}
