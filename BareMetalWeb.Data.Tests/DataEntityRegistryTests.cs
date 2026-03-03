using System;
using System.Linq;
using BareMetalWeb.Core;
using BareMetalWeb.Data.DataObjects;
using BareMetalWeb.Rendering;
using Xunit;

namespace BareMetalWeb.Data.Tests;

public class DataEntityRegistryTests
{
    public DataEntityRegistryTests()
    {
        // Force UserClasses assembly to load so [DataEntity] types like ToDo and Product are available
        _ = typeof(Product).Assembly;
    }

    [Fact]
    public void RegisterEntity_RegistersProductEntity()
    {
        // Arrange & Act
        DataScaffold.RegisterEntity<Product>();

        // Assert
        var entities = DataScaffold.Entities;
        Assert.NotEmpty(entities);

        var productEntity = entities.FirstOrDefault(e => e.Type == typeof(Product));
        Assert.NotNull(productEntity);
    }

    [Fact]
    public void RegisterEntity_RegistersToDo()
    {
        // Arrange & Act
        DataScaffold.RegisterEntity<ToDo>();

        // Assert
        var entities = DataScaffold.Entities;
        var todoEntity = entities.FirstOrDefault(e => e.Type == typeof(ToDo));
        Assert.NotNull(todoEntity);
    }

    [Fact]
    public void RegisterEntity_RegistersRenderableDataObjectTypes()
    {
        // Arrange & Act
        DataScaffold.RegisterEntity<Product>();

        // Assert - RenderableDataObject subclasses should be registered
        var entities = DataScaffold.Entities;
        Assert.Contains(entities, e => typeof(RenderableDataObject).IsAssignableFrom(e.Type));
    }

    [Fact]
    public void RegisterEntity_RegistersEntityMetadata()
    {
        // Arrange & Act
        DataScaffold.RegisterEntity<Product>();

        // Assert - Entities should have metadata populated
        var productEntity = DataScaffold.GetEntityByType(typeof(Product));
        Assert.NotNull(productEntity);
        Assert.NotNull(productEntity.Name);
        Assert.NotNull(productEntity.Slug);
    }

    [Fact]
    public void RegisterEntity_CanFindEntityBySlug()
    {
        // Arrange
        DataScaffold.RegisterEntity<Product>();

        // Act
        var found = DataScaffold.TryGetEntity("products", out var productMetadata);

        // Assert
        Assert.True(found);
        Assert.NotNull(productMetadata);
    }

    [Fact]
    public void RegisterEntity_CanFindEntityByType()
    {
        // Arrange
        DataScaffold.RegisterEntity<Product>();

        // Act
        var metadata = DataScaffold.GetEntityByType(typeof(Product));

        // Assert
        Assert.NotNull(metadata);
        Assert.Equal(typeof(Product), metadata.Type);
    }

    [Fact]
    public void RegisterEntity_MultipleInvocations_DoesNotDuplicate()
    {
        // Arrange
        DataScaffold.RegisterEntity<Product>();
        var countAfterFirst = DataScaffold.Entities.Count(e => e.Type == typeof(Product));

        // Act
        DataScaffold.RegisterEntity<Product>();
        var countAfterSecond = DataScaffold.Entities.Count(e => e.Type == typeof(Product));

        // Assert - Should not duplicate registrations
        Assert.Equal(countAfterFirst, countAfterSecond);
    }

    [Fact]
    public void RegisterEntity_RegistersKnownUserClassEntities()
    {
        // Arrange & Act
        DataScaffold.RegisterEntity<ToDo>();
        DataScaffold.RegisterEntity<Product>();
        DataScaffold.RegisterEntity<Customer>();
        DataScaffold.RegisterEntity<Order>();

        // Assert - Verify known entities from UserClasses are registered
        var entities = DataScaffold.Entities;

        var knownEntityNames = new[] { "ToDo", "Product", "Customer", "Order" };

        foreach (var name in knownEntityNames)
        {
            var found = entities.Any(e => e.Type.Name.Contains(name));
            Assert.True(found, $"Expected to find entity with name containing '{name}'");
        }
    }
}
