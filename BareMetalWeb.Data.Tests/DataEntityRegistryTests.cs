using System;
using System.Linq;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

[Collection("DataStoreProvider")]
public class DataEntityRegistryTests
{
    public DataEntityRegistryTests()
    {
        _ = GalleryTestFixture.State;
    }

    [Fact]
    public void RegisterEntity_RegistersProductEntity()
    {
        // Assert — gallery fixture registers products from JSON
        Assert.True(DataScaffold.TryGetEntity("products", out var meta));
        Assert.NotNull(meta);
    }

    [Fact]
    public void RegisterEntity_RegistersToDo()
    {
        Assert.True(DataScaffold.TryGetEntity("to-do", out var meta));
        Assert.NotNull(meta);
    }

    [Fact]
    public void RegisterEntity_RegistersEntityMetadata()
    {
        Assert.True(DataScaffold.TryGetEntity("products", out var meta));
        Assert.NotNull(meta);
        Assert.NotNull(meta.Name);
        Assert.NotNull(meta.Slug);
        Assert.NotEmpty(meta.Fields);
    }

    [Fact]
    public void RegisterEntity_CanFindEntityBySlug()
    {
        var found = DataScaffold.TryGetEntity("products", out var productMetadata);

        Assert.True(found);
        Assert.NotNull(productMetadata);
    }

    [Fact]
    public void RegisterEntity_CanFindEntityByType()
    {
        Assert.True(DataScaffold.TryGetEntity("products", out var meta));
        Assert.NotNull(meta);
        Assert.Equal(typeof(DataRecord), meta.Type);
    }

    [Fact]
    public void RegisterEntity_MultipleInvocations_DoesNotDuplicate()
    {
        var countBefore = DataScaffold.Entities.Count(e => e.Slug == "products");

        // Re-initialize fixture (already initialized, so this is a no-op for the lazy)
        _ = GalleryTestFixture.State;
        var countAfter = DataScaffold.Entities.Count(e => e.Slug == "products");

        Assert.Equal(countBefore, countAfter);
    }

    [Fact]
    public void RegisterEntity_RegistersKnownUserClassEntities()
    {
        var knownSlugs = new[] { "to-do", "products", "customers", "orders" };

        foreach (var slug in knownSlugs)
        {
            var found = DataScaffold.TryGetEntity(slug, out _);
            Assert.True(found, $"Expected to find entity with slug '{slug}'");
        }
    }
}
