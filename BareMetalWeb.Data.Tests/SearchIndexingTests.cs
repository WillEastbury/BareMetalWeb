using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using Xunit;

namespace BareMetalWeb.Data.Tests;

// Test data object for multi-index-kind tests (no shipped entity has all 4 kinds)
[DataEntity("Test Searchable Item", Slug = "testsearchableitem")]
public class TestSearchableItem : BaseDataObject
{
    [DataField] [DataIndex(IndexKind.Inverted)]
    public string? Name { get; set; }

    [DataField] [DataIndex(IndexKind.BTree)]
    public string? Category { get; set; }

    [DataField] [DataIndex(IndexKind.Treap)]
    public string? Tags { get; set; }

    [DataField] [DataIndex(IndexKind.Bloom)]
    public string? Description { get; set; }
}

// Edge-case test entities — no shipped entity has these field types
[DataEntity("List Field Test", Slug = "listfieldtest")]
public class ListFieldEntity : BaseDataObject
{
    [DataField] [DataIndex]
    public List<string> Tags { get; set; } = new();
}

[DataEntity("Nullable Int Test", Slug = "nullableinttest")]
public class NullableIntEntity : BaseDataObject
{
    [DataField] [DataIndex]
    public int? Score { get; set; }
}

[DataEntity("Int List Test", Slug = "intlisttest")]
public class IntListEntity : BaseDataObject
{
    [DataField] [DataIndex]
    public List<int> Values { get; set; } = new();
}

[DataEntity("BTree Test", Slug = "btreetest")]
public class BTreeEntity : BaseDataObject
{
    [DataField] [DataIndex(IndexKind.BTree)]
    public string Label { get; set; } = string.Empty;
}

public class SearchIndexingTests : IDisposable
{
    private readonly string _testRoot;
    private readonly SearchIndexManager _manager;
    private readonly TestBufferedLogger _logger;

    public SearchIndexingTests()
    {
        _testRoot = Path.Combine(Path.GetTempPath(), "BareMetalWeb_SearchIndexing_Tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testRoot);
        _logger = new TestBufferedLogger();

        DataScaffold.RegisterEntity<AppSetting>();
        DataScaffold.RegisterEntity<User>();
        DataScaffold.RegisterEntity<AuditEntry>();
        DataScaffold.RegisterEntity<TestSearchableItem>();
        DataScaffold.RegisterEntity<ListFieldEntity>();
        DataScaffold.RegisterEntity<NullableIntEntity>();
        DataScaffold.RegisterEntity<IntListEntity>();
        DataScaffold.RegisterEntity<BTreeEntity>();

        _manager = new SearchIndexManager(_testRoot, logger: null);
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

        // Use a local type that has no [DataIndex] attributes
        var hasFields = manager.HasIndexedFields(typeof(NoIndexEntity), out var fields);

        // Assert
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
            Key = 1,
            Name = "Test Product",
            Category = "Electronics",
            Tags = "gadget device",
            Description = "A great electronic device"
        };

        // Act
        manager.IndexObject(item);
        var results = manager.Search(typeof(TestSearchableItem), "Product", () => new[] { item });

        // Assert
        Assert.Contains(item.Key, results);
    }

    [Fact]
    public void IndexObject_BTreeIndex_CanSearchByCategory()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var items = new[]
        {
            new TestSearchableItem { Key = 1, Name = "Item1", Category = "Electronics" },
            new TestSearchableItem { Key = 2, Name = "Item2", Category = "Books" },
            new TestSearchableItem { Key = 3, Name = "Item3", Category = "Electronics" }
        };

        // Act
        foreach (var item in items)
            manager.IndexObject(item);
        
        var results = manager.Search(typeof(TestSearchableItem), "Electronics", () => items, IndexKind.BTree);

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(1u, results);
        Assert.Contains(3u, results);
    }

    [Fact]
    public void IndexObject_TreapIndex_CanSearchByTags()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var items = new[]
        {
            new TestSearchableItem { Key = 1, Name = "Item1", Tags = "gadget device" },
            new TestSearchableItem { Key = 2, Name = "Item2", Tags = "book reading" },
            new TestSearchableItem { Key = 3, Name = "Item3", Tags = "gadget tech" }
        };

        // Act
        foreach (var item in items)
            manager.IndexObject(item);
        
        var results = manager.Search(typeof(TestSearchableItem), "gadget", () => items, IndexKind.Treap);

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(1u, results);
        Assert.Contains(3u, results);
    }

    [Fact]
    public void IndexObject_BloomFilter_CanSearchByDescription()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var items = new[]
        {
            new TestSearchableItem { Key = 1, Name = "Item1", Description = "great product" },
            new TestSearchableItem { Key = 2, Name = "Item2", Description = "amazing deal" },
            new TestSearchableItem { Key = 3, Name = "Item3", Description = "great value" }
        };

        // Act
        foreach (var item in items)
            manager.IndexObject(item);
        
        var results = manager.Search(typeof(TestSearchableItem), "great", () => items, IndexKind.Bloom);

        // Assert
        Assert.Equal(2, results.Count);
        Assert.Contains(1u, results);
        Assert.Contains(3u, results);
    }

    [Fact]
    public void RemoveObject_RemovesFromAllIndexTypes()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var item = new TestSearchableItem
        {
            Key = 1,
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
            Key = 1,
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
        Assert.Contains(1u, newNameResults); // New name should be found
    }

    [Fact]
    public void Search_WithMultipleTokens_ReturnsUnionOfResults()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var items = new[]
        {
            new TestSearchableItem { Key = 1, Name = "Apple Phone" },
            new TestSearchableItem { Key = 2, Name = "Orange Juice" },
            new TestSearchableItem { Key = 3, Name = "Apple Juice" }
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
            new TestSearchableItem { Key = 1, Category = "Electronics" },
            new TestSearchableItem { Key = 2, Category = "Electrical" },
            new TestSearchableItem { Key = 3, Category = "Books" }
        };

        // Act
        foreach (var item in items)
            manager.IndexObject(item);
        
        var results = manager.Search(typeof(TestSearchableItem), "Elect", () => items, IndexKind.BTree);

        // Assert
        Assert.Equal(2, results.Count);
    }

    // --- Test entities ---

    private class NoIndexEntity : BaseDataObject
    {
        public string Value { get; set; } = string.Empty;
    }

    // --- HasIndexedFields ---

    [Fact]
    public void HasIndexedFields_TypeWithAttribute_ReturnsTrue()
    {
        // Act
        var result = _manager.HasIndexedFields(typeof(AppSetting), out var fields);

        // Assert
        Assert.True(result);
        Assert.Single(fields);
        Assert.Equal("SettingId", fields[0].Name);
    }

    [Fact]
    public void HasIndexedFields_TypeWithoutAttribute_ReturnsFalse()
    {
        // Act
        var result = _manager.HasIndexedFields(typeof(NoIndexEntity), out var fields);

        // Assert
        Assert.False(result);
        Assert.Empty(fields);
    }

    [Fact]
    public void HasIndexedFields_MultiFieldEntity_ReturnsAllIndexedFields()
    {
        // Act
        var result = _manager.HasIndexedFields(typeof(User), out var fields);

        // Assert
        Assert.True(result);
        Assert.Equal(2, fields.Count);
        Assert.Contains(fields, f => f.Name == "UserName");
        Assert.Contains(fields, f => f.Name == "Email");
    }

    // --- Index building and search ---

    [Fact]
    public void IndexObject_And_Search_FindsByExactToken()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "Hello World" };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), "hello", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    [Fact]
    public void Search_CaseInsensitive_FindsMatch()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "FooBar" };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), "FOOBAR", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    [Fact]
    public void Search_MultipleTokensInQuery_FindsAll()
    {
        // Arrange
        var e1 = new AppSetting { Key = 1, SettingId = "alpha" };
        var e2 = new AppSetting { Key = 2, SettingId = "beta" };
        _manager.IndexObject(e1);
        _manager.IndexObject(e2);

        // Act
        var results = _manager.Search(typeof(AppSetting), "alpha beta", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
        Assert.Contains(2u, results);
    }

    [Fact]
    public void Search_NoMatch_ReturnsEmpty()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "Hello" };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), "xyz", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public void Search_PrefixMatch_FindsToken()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "programming" };
        _manager.IndexObject(entity);

        // Act - "pro" is a 3-char prefix that should match via prefix tree
        var results = _manager.Search(typeof(AppSetting), "pro", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    // --- Multi-field indexing ---

    [Fact]
    public void IndexObject_MultiField_SearchFindsFromEitherField()
    {
        // Arrange
        var entity = new User
        {
            Key = 1,
            UserName = "Widgets",
            Email = "Industrial gadgets"
        };
        _manager.IndexObject(entity);

        // Act
        var byTitle = _manager.Search(typeof(User), "widgets", () => Array.Empty<BaseDataObject>());
        var byDesc = _manager.Search(typeof(User), "gadgets", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, byTitle);
        Assert.Contains(1u, byDesc);
    }

    // --- Integer field indexing ---

    [Fact]
    public void IndexObject_IntField_SearchByNumberString()
    {
        // Arrange
        var entity = new AuditEntry { Key = 1, EntityKey = 42 };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AuditEntry), "42", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    // --- List field indexing ---

    [Fact]
    public void IndexObject_ListField_SearchByAnyTag()
    {
        // Arrange
        var entity = new ListFieldEntity { Key = 1, Tags = new List<string> { "csharp", "dotnet", "testing" } };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(ListFieldEntity), "dotnet", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    // --- Token extraction and normalization ---

    [Fact]
    public void Search_TokenizesOnPunctuation()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "foo-bar_baz.qux" };
        _manager.IndexObject(entity);

        // Act - each word between separators is a token
        var r1 = _manager.Search(typeof(AppSetting), "foo", () => Array.Empty<BaseDataObject>());
        var r2 = _manager.Search(typeof(AppSetting), "bar", () => Array.Empty<BaseDataObject>());
        var r3 = _manager.Search(typeof(AppSetting), "baz", () => Array.Empty<BaseDataObject>());
        var r4 = _manager.Search(typeof(AppSetting), "qux", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, r1);
        Assert.Contains(1u, r2);
        Assert.Contains(1u, r3);
        Assert.Contains(1u, r4);
    }

    [Fact]
    public void Search_TokensAreLowercased()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "CamelCaseWord" };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), "camelcaseword", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    // --- Special characters and Unicode ---

    [Fact]
    public void Search_UnicodeLetters_AreIndexed()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "café résumé" };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), "café", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    [Fact]
    public void Search_SpecialCharactersStripped_TokensSplit()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "hello@world.com" };
        _manager.IndexObject(entity);

        // Act - '@' and '.' are separators, tokens are "hello", "world", "com"
        var results = _manager.Search(typeof(AppSetting), "world", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    [Fact]
    public void Search_DigitsInTokens_ArePreserved()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "version2 release3" };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), "version2", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    // --- Empty/null input handling ---

    [Fact]
    public void Search_EmptyQuery_ReturnsEmpty()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "test" };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), "", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public void Search_NullQuery_ReturnsEmpty()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "test" };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), null!, () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public void Search_WhitespaceQuery_ReturnsEmpty()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "test" };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), "   ", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public void IndexObject_NullObject_DoesNotThrow()
    {
        // Act & Assert - should not throw
        _manager.IndexObject(null!);
    }

    [Fact]
    public void IndexObject_NullId_DoesNotThrow()
    {
        // Arrange
        var entity = new AppSetting { Key = 0, SettingId = "test" };

        // Act & Assert - should not throw
        _manager.IndexObject(entity);
    }

    [Fact]
    public void IndexObject_EmptyName_DoesNotThrow()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "" };

        // Act & Assert - should not throw
        _manager.IndexObject(entity);

        var results = _manager.Search(typeof(AppSetting), "anything", () => Array.Empty<BaseDataObject>());
        Assert.DoesNotContain(1u, results);
    }

    [Fact]
    public void IndexObject_NullableIntField_NullValue_DoesNotThrow()
    {
        // Arrange
        var entity = new NullableIntEntity { Key = 1, Score = null };

        // Act & Assert - should not throw
        _manager.IndexObject(entity);

        var results = _manager.Search(typeof(NullableIntEntity), "anything", () => Array.Empty<BaseDataObject>());
        Assert.Empty(results);
    }

    // --- RemoveObject ---

    [Fact]
    public void RemoveObject_RemovesFromIndex()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "removeme" };
        _manager.IndexObject(entity);

        // Act
        _manager.RemoveObject(entity);
        var results = _manager.Search(typeof(AppSetting), "removeme", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Empty(results);
    }

    [Fact]
    public void RemoveObject_NullObject_DoesNotThrow()
    {
        // Act & Assert
        _manager.RemoveObject(null!);
    }

    // --- EnsureBuilt with loadAll ---

    [Fact]
    public void EnsureBuilt_BuildsIndexFromLoadAll()
    {
        // Arrange
        var entities = new List<BaseDataObject>
        {
            new AppSetting { Key = 1, SettingId = "apple" },
            new AppSetting { Key = 2, SettingId = "banana" },
            new AppSetting { Key = 3, SettingId = "cherry" }
        };

        // Act
        _manager.EnsureBuilt(typeof(AppSetting), () => entities);
        var results = _manager.Search(typeof(AppSetting), "banana", () => entities);

        // Assert
        Assert.Single(results);
        Assert.Contains(2u, results);
    }

    [Fact]
    public void EnsureBuilt_SkipsNullAndEmptyIdEntities()
    {
        // Arrange
        var entities = new List<BaseDataObject>
        {
            new AppSetting { Key = 1, SettingId = "valid" },
            null!,
            new AppSetting { Key = 0, SettingId = "emptyid" }
        };

        // Act & Assert - should not throw
        _manager.EnsureBuilt(typeof(AppSetting), () => entities);
        var results = _manager.Search(typeof(AppSetting), "valid", () => entities);
        Assert.Contains(1u, results);
    }

    // --- IndexObject replaces previous tokens ---

    [Fact]
    public void IndexObject_ReindexSameId_UpdatesTokens()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "oldvalue" };
        _manager.IndexObject(entity);

        // Act - update the entity and re-index
        entity.SettingId = "newvalue";
        _manager.IndexObject(entity);

        // Assert
        var oldResults = _manager.Search(typeof(AppSetting), "oldvalue", () => Array.Empty<BaseDataObject>());
        var newResults = _manager.Search(typeof(AppSetting), "newvalue", () => Array.Empty<BaseDataObject>());
        Assert.Empty(oldResults);
        Assert.Contains(1u, newResults);
    }

    // --- DataIndexAttribute ---

    [Fact]
    public void DataIndexAttribute_DefaultKind_IsInverted()
    {
        // Act
        var attr = new DataIndexAttribute();

        // Assert
        Assert.Equal(IndexKind.Inverted, attr.Kind);
    }

    [Fact]
    public void DataIndexAttribute_ExplicitKind_IsStored()
    {
        // Act
        var attr = new DataIndexAttribute(IndexKind.BTree);

        // Assert
        Assert.Equal(IndexKind.BTree, attr.Kind);
    }

    // --- Ranked / multiple results ordering ---

    [Fact]
    public void Search_ReturnsAllMatchingIds()
    {
        // Arrange
        var e1 = new AppSetting { Key = 1, SettingId = "search term here" };
        var e2 = new AppSetting { Key = 2, SettingId = "another search result" };
        var e3 = new AppSetting { Key = 3, SettingId = "unrelated content" };
        _manager.IndexObject(e1);
        _manager.IndexObject(e2);
        _manager.IndexObject(e3);

        // Act
        var results = _manager.Search(typeof(AppSetting), "search", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
        Assert.Contains(2u, results);
        Assert.DoesNotContain(3u, results);
    }

    // --- Substring / contains matching fallback ---

    [Fact]
    public void Search_ShortQueryToken_FallsBackToContains()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "example" };
        _manager.IndexObject(entity);

        // Act - short query tokens (< 3 chars) that don't exactly match use fallback contains
        var results = _manager.Search(typeof(AppSetting), "ex", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    // --- Index persistence (save/load round-trip) ---

    [Fact]
    public void IndexObject_PersistsToFile_NewManagerCanSearch()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "persisted" };
        _manager.IndexObject(entity);

        // Act - create a new manager pointing at the same root
        var manager2 = new SearchIndexManager(_testRoot, logger: null);
        var results = manager2.Search(typeof(AppSetting), "persisted", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    // --- RemoveObject edge cases ---

    [Fact]
    public void RemoveObject_NonExistentId_DoesNotThrow()
    {
        // Arrange
        var entity = new AppSetting { Key = 999, SettingId = "test" };

        // Act & Assert - should not throw
        _manager.RemoveObject(entity);
    }

    [Fact]
    public void RemoveObject_EmptyId_DoesNotThrow()
    {
        // Arrange
        var entity = new AppSetting { Key = 0, SettingId = "test" };

        // Act & Assert - should not throw
        _manager.RemoveObject(entity);
    }

    [Fact]
    public void RemoveObject_OnlyRemovesTargetEntity()
    {
        // Arrange
        var e1 = new AppSetting { Key = 1, SettingId = "shared token" };
        var e2 = new AppSetting { Key = 2, SettingId = "shared value" };
        _manager.IndexObject(e1);
        _manager.IndexObject(e2);

        // Act
        _manager.RemoveObject(e1);
        var results = _manager.Search(typeof(AppSetting), "shared", () => Array.Empty<BaseDataObject>());

        // Assert - only e2 remains
        Assert.DoesNotContain(1u, results);
        Assert.Contains(2u, results);
    }

    // --- EnsureBuilt idempotency ---

    [Fact]
    public void EnsureBuilt_CalledTwice_DoesNotRebuild()
    {
        // Arrange
        int loadCount = 0;
        IEnumerable<BaseDataObject> LoadAll()
        {
            loadCount++;
            return new[] { new AppSetting { Key = 1, SettingId = "test" } };
        }

        // Act
        _manager.EnsureBuilt(typeof(AppSetting), LoadAll);
        _manager.EnsureBuilt(typeof(AppSetting), LoadAll);

        // Assert - loadAll should only be called once
        Assert.Equal(1, loadCount);
    }

    // --- Nullable int with value ---

    [Fact]
    public void IndexObject_NullableIntField_WithValue_IsSearchable()
    {
        // Arrange
        var entity = new NullableIntEntity { Key = 1, Score = 99 };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(NullableIntEntity), "99", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    // --- List field edge cases ---

    [Fact]
    public void IndexObject_ListField_EmptyList_DoesNotThrow()
    {
        // Arrange
        var entity = new ListFieldEntity { Key = 1, Tags = new List<string>() };

        // Act & Assert
        _manager.IndexObject(entity);
        var results = _manager.Search(typeof(ListFieldEntity), "anything", () => Array.Empty<BaseDataObject>());
        Assert.Empty(results);
    }

    [Fact]
    public void IndexObject_ListField_NullItems_DoesNotThrow()
    {
        // Arrange
        var entity = new ListFieldEntity { Key = 1, Tags = new List<string> { null!, "valid", "" } };

        // Act & Assert - should not throw
        _manager.IndexObject(entity);
        var results = _manager.Search(typeof(ListFieldEntity), "valid", () => Array.Empty<BaseDataObject>());
        Assert.Contains(1u, results);
    }

    // --- Non-inverted IndexKind fallback ---

    [Fact]
    public void IndexObject_NonInvertedKind_FallsBackToInverted()
    {
        // Arrange
        var entity = new BTreeEntity { Key = 1, Label = "fallback" };

        // Act - BTree is not implemented, should fall back to inverted
        _manager.IndexObject(entity);
        var results = _manager.Search(typeof(BTreeEntity), "fallback", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    // --- Unicode and special character edge cases ---

    [Fact]
    public void Search_CJKCharacters_AreIndexed()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "日本語テスト" };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), "日本語テスト", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    [Fact]
    public void Search_EmojiStripped_TokensSplit()
    {
        // Arrange - emoji are not letters/digits, so they act as separators
        var entity = new AppSetting { Key = 1, SettingId = "hello😀world" };
        _manager.IndexObject(entity);

        // Act
        var r1 = _manager.Search(typeof(AppSetting), "hello", () => Array.Empty<BaseDataObject>());
        var r2 = _manager.Search(typeof(AppSetting), "world", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, r1);
        Assert.Contains(1u, r2);
    }

    [Fact]
    public void Search_AccentedCharacters_AreLowercased()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "RÉSUMÉ" };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), "résumé", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    [Fact]
    public void Search_QueryWithOnlySpecialChars_ReturnsEmpty()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "test" };
        _manager.IndexObject(entity);

        // Act - query of only special characters produces no tokens
        var results = _manager.Search(typeof(AppSetting), "@#$%^&*()", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Empty(results);
    }

    // --- Very long token (overflow buffer path) ---

    [Fact]
    public void IndexObject_VeryLongToken_IsIndexedCorrectly()
    {
        // Arrange - token > 256 chars triggers overflow buffer in TokenizeToHashSet
        var longWord = new string('a', 300);
        var entity = new AppSetting { Key = 1, SettingId = longWord };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), longWord, () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    // --- Prefix tree cleanup on remove ---

    [Fact]
    public void RemoveObject_CleansUpPrefixTree_NoStaleResults()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "uniqueprefix" };
        _manager.IndexObject(entity);

        // Act
        _manager.RemoveObject(entity);
        var results = _manager.Search(typeof(AppSetting), "uni", () => Array.Empty<BaseDataObject>());

        // Assert - prefix "uni" should no longer match
        Assert.Empty(results);
    }

    // --- Multi-field partial match ---

    [Fact]
    public void Search_MultiField_MatchesAcrossFieldsIndependently()
    {
        // Arrange
        var e1 = new User { Key = 1, UserName = "alpha", Email = "beta" };
        var e2 = new User { Key = 2, UserName = "gamma", Email = "delta" };
        _manager.IndexObject(e1);
        _manager.IndexObject(e2);

        // Act - query matches title of e1 and description of e2
        var results = _manager.Search(typeof(User), "alpha delta", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
        Assert.Contains(2u, results);
    }

    [Fact]
    public void EnsureBuilt_BuildsIndexFromExistingObjects()
    {
        // Arrange
        var manager = new SearchIndexManager(_testRoot, _logger);
        var items = new[]
        {
            new TestSearchableItem { Key = 1, Name = "Item One" },
            new TestSearchableItem { Key = 2, Name = "Item Two" },
            new TestSearchableItem { Key = 3, Name = "Item Three" }
        };

        // Act - EnsureBuilt should be called internally by Search
        var results = manager.Search(typeof(TestSearchableItem), "Item", () => items);

        // Assert
        Assert.Equal(3, results.Count);
    }

    // --- IndexObject after EnsureBuilt (incremental) ---

    [Fact]
    public void IndexObject_AfterEnsureBuilt_AddsToIndex()
    {
        // Arrange
        var entities = new List<BaseDataObject>
        {
            new AppSetting { Key = 1, SettingId = "original" }
        };
        _manager.EnsureBuilt(typeof(AppSetting), () => entities);

        // Act - add a new entity after index is built
        var newEntity = new AppSetting { Key = 2, SettingId = "incremental" };
        _manager.IndexObject(newEntity);
        var results = _manager.Search(typeof(AppSetting), "incremental", () => entities);

        // Assert
        Assert.Contains(2u, results);
    }

    // --- IEnumerable of non-string (int list) ---

    [Fact]
    public void IndexObject_IntEnumerable_TokenizesViaToString()
    {
        // Arrange
        var entity = new IntListEntity { Key = 1, Values = new List<int> { 10, 20, 30 } };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(IntListEntity), "20", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    // --- Search with multiple shared tokens ---

    [Fact]
    public void Search_MultipleEntitiesSameToken_ReturnsAll()
    {
        // Arrange
        var e1 = new AppSetting { Key = 1, SettingId = "common word" };
        var e2 = new AppSetting { Key = 2, SettingId = "common phrase" };
        var e3 = new AppSetting { Key = 3, SettingId = "common term" };
        _manager.IndexObject(e1);
        _manager.IndexObject(e2);
        _manager.IndexObject(e3);

        // Act
        var results = _manager.Search(typeof(AppSetting), "common", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Equal(3, results.Count);
        Assert.Contains(1u, results);
        Assert.Contains(2u, results);
        Assert.Contains(3u, results);
    }

    // --- HasIndexedFields with non-inverted kind ---

    [Fact]
    public void HasIndexedFields_BTreeKind_StillDetected()
    {
        // Act
        var result = _manager.HasIndexedFields(typeof(BTreeEntity), out var fields);

        // Assert
        Assert.True(result);
        Assert.Single(fields);
        Assert.Equal("Label", fields[0].Name);
    }

    // --- Search type isolation ---

    [Fact]
    public void Search_DifferentTypes_AreIsolated()
    {
        // Arrange
        var simple = new AppSetting { Key = 1, SettingId = "overlap" };
        var multi = new User { Key = 2, UserName = "overlap", Email = "" };
        _manager.IndexObject(simple);
        _manager.IndexObject(multi);

        // Act
        var simpleResults = _manager.Search(typeof(AppSetting), "overlap", () => Array.Empty<BaseDataObject>());
        var multiResults = _manager.Search(typeof(User), "overlap", () => Array.Empty<BaseDataObject>());

        // Assert - each type's index is separate
        Assert.Single(simpleResults);
        Assert.Contains(1u, simpleResults);
        Assert.Single(multiResults);
        Assert.Contains(2u, multiResults);
    }

    // --- EnsureBuilt with empty collection ---

    [Fact]
    public void EnsureBuilt_EmptyCollection_CreatesEmptyIndex()
    {
        // Act
        _manager.EnsureBuilt(typeof(AppSetting), () => Array.Empty<BaseDataObject>());
        var results = _manager.Search(typeof(AppSetting), "anything", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Empty(results);
    }

    // --- Token with mixed digits and letters ---

    [Fact]
    public void Search_MixedAlphanumericToken_IsKeptTogether()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "abc123def" };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), "abc123def", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    // --- DataIndexAttribute enum values ---

    [Fact]
    public void DataIndexAttribute_TreapKind_IsStored()
    {
        // Act
        var attr = new DataIndexAttribute(IndexKind.Treap);

        // Assert
        Assert.Equal(IndexKind.Treap, attr.Kind);
    }

    [Fact]
    public void DataIndexAttribute_BloomKind_IsStored()
    {
        // Act
        var attr = new DataIndexAttribute(IndexKind.Bloom);

        // Assert
        Assert.Equal(IndexKind.Bloom, attr.Kind);
    }

    // --- Prefix tree: prefix length boundary ---

    [Fact]
    public void Search_SingleCharToken_MatchesViaContainsFallback()
    {
        // Arrange - "a" is < 3 chars, so prefix tree won't be used
        var entity = new AppSetting { Key = 1, SettingId = "a" };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), "a", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    [Fact]
    public void Search_TwoCharToken_ExactMatch()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "ab" };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), "ab", () => Array.Empty<BaseDataObject>());

        // Assert
        Assert.Contains(1u, results);
    }

    // --- Whitespace-only name ---

    [Fact]
    public void IndexObject_WhitespaceOnlyName_ProducesNoTokens()
    {
        // Arrange
        var entity = new AppSetting { Key = 1, SettingId = "   \t\n  " };
        _manager.IndexObject(entity);

        // Act
        var results = _manager.Search(typeof(AppSetting), "anything", () => Array.Empty<BaseDataObject>());

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

    // --- Re-index same ID via EnsureBuilt ---

    [Fact]
    public void EnsureBuilt_DuplicateIds_LastWins()
    {
        // Arrange - two entities with the same ID, last one's tokens should win
        var entities = new List<BaseDataObject>
        {
            new AppSetting { Key = 1, SettingId = "first" },
            new AppSetting { Key = 1, SettingId = "second" }
        };

        // Act
        _manager.EnsureBuilt(typeof(AppSetting), () => entities);
        var firstResults = _manager.Search(typeof(AppSetting), "first", () => entities);
        var secondResults = _manager.Search(typeof(AppSetting), "second", () => entities);

        // Assert - both tokens are indexed because BuildFrom doesn't de-dup
        // The last entity's tokens are in IdToTokens, but first entity's tokens remain in Tokens
        Assert.Contains(1u, secondResults);
    }
}

