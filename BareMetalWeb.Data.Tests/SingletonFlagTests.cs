using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

// Test entity with a singleton flag property
[DataEntity("Singleton Test Items", Slug = "singleton-test-items")]
public class SingletonTestItem : BaseDataObject
{
    [DataField(Label = "Name")]
    public string Name { get; set; } = string.Empty;

    [DataField(Label = "Is Default")]
    [SingletonFlag]
    public bool IsDefault { get; set; }
}

// Test entity with multiple singleton flag properties
[DataEntity("Multi Singleton Test Items", Slug = "multi-singleton-test-items")]
public class MultiSingletonTestItem : BaseDataObject
{
    [DataField(Label = "Name")]
    public string Name { get; set; } = string.Empty;

    [DataField(Label = "Is Primary")]
    [SingletonFlag]
    public bool IsPrimary { get; set; }

    [DataField(Label = "Is Secondary")]
    [SingletonFlag]
    public bool IsSecondary { get; set; }
}

public class SingletonFlagTests : IDisposable
{
    private readonly string _testRoot;
    private readonly WalDataProvider _provider;

    public SingletonFlagTests()
    {
        _testRoot = Path.Combine(Path.GetTempPath(), "BareMetalWeb_SingletonTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testRoot);
        _provider = new WalDataProvider(_testRoot);
    }

    public void Dispose()
    {
        _provider.Dispose();
        if (Directory.Exists(_testRoot))
        {
            try { Directory.Delete(_testRoot, recursive: true); }
            catch { /* best effort cleanup */ }
        }
    }

    [Fact]
    public void Save_SingletonFlagTrue_ClearsOtherRecordsFlag()
    {
        // Arrange - save first record with the flag set
        var first = new SingletonTestItem { Key = 1, Name = "First", IsDefault = true };
        _provider.Save(first);

        // Act - save second record with the flag also set to true
        var second = new SingletonTestItem { Key = 2, Name = "Second", IsDefault = true };
        _provider.Save(second);

        // Assert - first record's flag should have been cleared
        var reloadedFirst = _provider.Load<SingletonTestItem>(1);
        Assert.NotNull(reloadedFirst);
        Assert.False(reloadedFirst!.IsDefault);

        // And second record should still have the flag set
        var reloadedSecond = _provider.Load<SingletonTestItem>(2);
        Assert.NotNull(reloadedSecond);
        Assert.True(reloadedSecond!.IsDefault);
    }

    [Fact]
    public async Task SaveAsync_SingletonFlagTrue_ClearsOtherRecordsFlag()
    {
        // Arrange
        var first = new SingletonTestItem { Key = 1, Name = "First", IsDefault = true };
        await _provider.SaveAsync(first);

        // Act
        var second = new SingletonTestItem { Key = 2, Name = "Second", IsDefault = true };
        await _provider.SaveAsync(second);

        // Assert
        var reloadedFirst = _provider.Load<SingletonTestItem>(1);
        Assert.NotNull(reloadedFirst);
        Assert.False(reloadedFirst!.IsDefault);

        var reloadedSecond = _provider.Load<SingletonTestItem>(2);
        Assert.NotNull(reloadedSecond);
        Assert.True(reloadedSecond!.IsDefault);
    }

    [Fact]
    public void Save_SingletonFlagFalse_DoesNotAffectOtherRecords()
    {
        // Arrange - save a record with the flag set
        var first = new SingletonTestItem { Key = 1, Name = "First", IsDefault = true };
        _provider.Save(first);

        // Act - save second record with flag NOT set
        var second = new SingletonTestItem { Key = 2, Name = "Second", IsDefault = false };
        _provider.Save(second);

        // Assert - first record's flag should be unchanged
        var reloadedFirst = _provider.Load<SingletonTestItem>(1);
        Assert.NotNull(reloadedFirst);
        Assert.True(reloadedFirst!.IsDefault);
    }

    [Fact]
    public void Save_SingletonFlagTrue_OnlyOneActiveAtATime_MultipleRecords()
    {
        // Arrange - save multiple records, each one setting the flag to true
        for (int i = 1; i <= 5; i++)
        {
            var item = new SingletonTestItem { Key = (uint)i, Name = $"Item {i}", IsDefault = true };
            _provider.Save(item);
        }

        // Assert - only the last saved record should have the flag set
        var allItems = _provider.Query<SingletonTestItem>().ToList();
        Assert.Equal(5, allItems.Count);
        var flaggedItems = allItems.Where(x => x.IsDefault).ToList();
        Assert.Single(flaggedItems);
        Assert.Equal(5u, flaggedItems[0].Key);
    }

    [Fact]
    public void Save_UpdateSameRecord_RetainsSingletonFlag()
    {
        // Arrange - save a record with the flag set
        var item = new SingletonTestItem { Key = 1, Name = "Original", IsDefault = true };
        _provider.Save(item);

        // Act - update the same record (keeping the flag)
        item.Name = "Updated";
        _provider.Save(item);

        // Assert - the record still has the flag
        var reloaded = _provider.Load<SingletonTestItem>(1);
        Assert.NotNull(reloaded);
        Assert.True(reloaded!.IsDefault);
        Assert.Equal("Updated", reloaded.Name);
    }

    [Fact]
    public void Save_MultipleSingletonFlags_EachEnforcedIndependently()
    {
        // Arrange - save two records each with different singleton flags
        var first = new MultiSingletonTestItem { Key = 1, Name = "First", IsPrimary = true, IsSecondary = false };
        _provider.Save(first);

        var second = new MultiSingletonTestItem { Key = 2, Name = "Second", IsPrimary = false, IsSecondary = true };
        _provider.Save(second);

        // Act - save third record with both flags set
        var third = new MultiSingletonTestItem { Key = 3, Name = "Third", IsPrimary = true, IsSecondary = true };
        _provider.Save(third);

        // Assert - first record's IsPrimary should be cleared
        var reloadedFirst = _provider.Load<MultiSingletonTestItem>(1);
        Assert.NotNull(reloadedFirst);
        Assert.False(reloadedFirst!.IsPrimary);

        // Assert - second record's IsSecondary should be cleared
        var reloadedSecond = _provider.Load<MultiSingletonTestItem>(2);
        Assert.NotNull(reloadedSecond);
        Assert.False(reloadedSecond!.IsSecondary);

        // Assert - third record has both flags set
        var reloadedThird = _provider.Load<MultiSingletonTestItem>(3);
        Assert.NotNull(reloadedThird);
        Assert.True(reloadedThird!.IsPrimary);
        Assert.True(reloadedThird!.IsSecondary);
    }

    [Fact]
    public void SingletonFlagAttribute_IsApplied_ToTestItemIsDefault()
    {
        // Verify that the SingletonTestItem.IsDefault property has the [SingletonFlag] attribute applied
        var prop = typeof(SingletonTestItem).GetProperty(nameof(SingletonTestItem.IsDefault));
        Assert.NotNull(prop);
        var attr = prop!.GetCustomAttributes(typeof(SingletonFlagAttribute), inherit: true);
        Assert.NotEmpty(attr);
    }
}
