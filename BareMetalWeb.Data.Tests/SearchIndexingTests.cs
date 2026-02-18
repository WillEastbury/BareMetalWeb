using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

// Test data object for indexing tests
public class TestSearchableItem : BaseDataObject
{
    [DataIndex(IndexKind.Inverted)]
    public string? Name { get; set; }
    
    [DataIndex(IndexKind.BTree)]
    public string? Category { get; set; }
    
    [DataIndex(IndexKind.Treap)]
    public string? Tags { get; set; }
    
    [DataIndex(IndexKind.Bloom)]
    public string? Description { get; set; }
}

public class SearchIndexingTests : IDisposable
{
    private readonly string _testRoot;
    private readonly TestBufferedLogger _logger;

    public SearchIndexingTests()
    {
        _testRoot = Path.Combine(Path.GetTempPath(), $"SearchIndexTests_{Guid.NewGuid()}");
        Directory.CreateDirectory(_testRoot);
        _logger = new TestBufferedLogger();
    }

    public void Dispose()
    {
        if (Directory.Exists(_testRoot))
        {
            Directory.Delete(_testRoot, recursive: true);
        }
    }

    [Fact]
    public void HasIndexedFields_WithIndexedProperties_ReturnsTrue()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        
        // Act
        var hasFields = manager.HasIndexedFields(typeof(TestSearchableItem), out var fields);
        
        // Assert
        Assert.True(hasFields);
        Assert.Equal(4, fields.Count);
    }

    [Fact]
    public void HasIndexedFields_WithoutIndexedProperties_ReturnsFalse()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        
        // Act
        var hasFields = manager.HasIndexedFields(typeof(User), out var fields);
        
        // Assert - User class doesn't have DataIndex attributes
        Assert.False(hasFields);
        Assert.Empty(fields);
    }

    [Fact]
    public void IndexObject_InvertedIndex_CanSearchByName()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var item = new TestSearchableItem
        {
            Id = "1",
            Name = "Test Product",
            Category = "Electronics",
            Tags = "gadget device",
            Description = "A great electronic device"
        };

        // Act
        manager.IndexObject(item);
        var results = manager.Search(typeof(TestSearchableItem), "Product", () => new[] { item });

        // Assert
        Assert.Contains(item.Id, results);
    }

    [Fact]
    public void IndexObject_BTreeIndex_CanSearchByCategory()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var items = new[]
        {
            new TestSearchableItem { Id = "1", Name = "Item1", Category = "Electronics" },
            new TestSearchableItem { Id = "2", Name = "Item2", Category = "Books" },
            new TestSearchableItem { Id = "3", Name = "Item3", Category = "Electronics" }
        };

        // Act
        foreach (var item in items)
            manager.IndexObject(item);
        
        var results = manager.Search(typeof(TestSearchableItem), "Electronics", () => items, IndexKind.BTree);

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains("1", results);
        Assert.Contains("3", results);
    }

    [Fact]
    public void IndexObject_TreapIndex_CanSearchByTags()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var items = new[]
        {
            new TestSearchableItem { Id = "1", Name = "Item1", Tags = "gadget device" },
            new TestSearchableItem { Id = "2", Name = "Item2", Tags = "book reading" },
            new TestSearchableItem { Id = "3", Name = "Item3", Tags = "gadget tech" }
        };

        // Act
        foreach (var item in items)
            manager.IndexObject(item);
        
        var results = manager.Search(typeof(TestSearchableItem), "gadget", () => items, IndexKind.Treap);

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains("1", results);
        Assert.Contains("3", results);
    }

    [Fact]
    public void IndexObject_BloomFilter_CanSearchByDescription()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var items = new[]
        {
            new TestSearchableItem { Id = "1", Name = "Item1", Description = "great product" },
            new TestSearchableItem { Id = "2", Name = "Item2", Description = "amazing deal" },
            new TestSearchableItem { Id = "3", Name = "Item3", Description = "great value" }
        };

        // Act
        foreach (var item in items)
            manager.IndexObject(item);
        
        var results = manager.Search(typeof(TestSearchableItem), "great", () => items, IndexKind.Bloom);

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains("1", results);
        Assert.Contains("3", results);
    }

    [Fact]
    public void RemoveObject_RemovesFromAllIndexTypes()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var item = new TestSearchableItem
        {
            Id = "1",
            Name = "Test Product",
            Category = "Electronics",
            Tags = "gadget",
            Description = "great product"
        };

        // Act
        manager.IndexObject(item);
        manager.RemoveObject(item);
        
        // Assert - search should not find the removed item
        var invertedResults = manager.Search(typeof(TestSearchableItem), "Product", () => Array.Empty<TestSearchableItem>());
        var btreeResults = manager.Search(typeof(TestSearchableItem), "Electronics", () => Array.Empty<TestSearchableItem>(), IndexKind.BTree);
        var treapResults = manager.Search(typeof(TestSearchableItem), "gadget", () => Array.Empty<TestSearchableItem>(), IndexKind.Treap);
        var bloomResults = manager.Search(typeof(TestSearchableItem), "great", () => Array.Empty<TestSearchableItem>(), IndexKind.Bloom);
        
        Assert.Empty(invertedResults);
        Assert.Empty(btreeResults);
        Assert.Empty(treapResults);
        Assert.Empty(bloomResults);
    }

    [Fact]
    public void IndexObject_UpdateExisting_UpdatesAllIndexes()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var item = new TestSearchableItem
        {
            Id = "1",
            Name = "Old Name",
            Category = "Old Category"
        };

        // Act
        manager.IndexObject(item);
        item.Name = "New Name";
        item.Category = "New Category";
        manager.IndexObject(item);
        
        var oldNameResults = manager.Search(typeof(TestSearchableItem), "Old", () => new[] { item });
        var newNameResults = manager.Search(typeof(TestSearchableItem), "New", () => new[] { item });

        // Assert
        Assert.Empty(oldNameResults); // Old name should be removed
        Assert.Contains("1", newNameResults); // New name should be found
    }

    [Fact]
    public void Search_WithMultipleTokens_ReturnsUnionOfResults()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var items = new[]
        {
            new TestSearchableItem { Id = "1", Name = "Apple Phone" },
            new TestSearchableItem { Id = "2", Name = "Orange Juice" },
            new TestSearchableItem { Id = "3", Name = "Apple Juice" }
        };

        // Act
        foreach (var item in items)
            manager.IndexObject(item);
        
        var results = manager.Search(typeof(TestSearchableItem), "Apple Orange", () => items);

        // Assert
        Assert.Equal(3, results.Count); // All items match either Apple or Orange
    }

    [Fact]
    public void BTreeIndex_PrefixSearch_FindsMatches()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var items = new[]
        {
            new TestSearchableItem { Id = "1", Category = "Electronics" },
            new TestSearchableItem { Id = "2", Category = "Electrical" },
            new TestSearchableItem { Id = "3", Category = "Books" }
        };

        // Act
        foreach (var item in items)
            manager.IndexObject(item);
        
        var results = manager.Search(typeof(TestSearchableItem), "Elect", () => items, IndexKind.BTree);

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains("1", results);
        Assert.Contains("2", results);
    }

    [Fact]
    public void EnsureBuilt_BuildsIndexFromExistingObjects()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var items = new[]
        {
            new TestSearchableItem { Id = "1", Name = "Item One" },
            new TestSearchableItem { Id = "2", Name = "Item Two" },
            new TestSearchableItem { Id = "3", Name = "Item Three" }
        };

        // Act - EnsureBuilt should be called internally by Search
        var results = manager.Search(typeof(TestSearchableItem), "Item", () => items);

        // Assert
        Assert.Equal(3, results.Count);
    }

    [Fact]
    public void Search_EmptyQuery_ReturnsEmpty()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var items = new[]
        {
            new TestSearchableItem { Id = "1", Name = "Item One" }
        };

        // Act
        var results = manager.Search(typeof(TestSearchableItem), "", () => items);

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public void Search_WhitespaceQuery_ReturnsEmpty()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var items = new[]
        {
            new TestSearchableItem { Id = "1", Name = "Item One" }
        };

        // Act
        var results = manager.Search(typeof(TestSearchableItem), "   ", () => items);

        // Assert
        Assert.Empty(results);
    }

    // Helper class for testing
    private class TestBufferedLogger : IBufferedLogger
    {
        private readonly List<string> _logs = new();

        public void LogInfo(string message) => _logs.Add($"INFO: {message}");
        public void LogError(string message, Exception ex) => _logs.Add($"ERROR: {message} - {ex?.Message}");
        public Task RunAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public void OnApplicationStopping(CancellationTokenSource cts, Task loggerTask) { }
        
        public List<string> GetLogs() => _logs;
    }
}
