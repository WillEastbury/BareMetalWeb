using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data.Tests;

public class BinaryObjectSerializerTests
{
    [Fact]
    public void Serialize_SimpleObject_ReturnsNonEmptyByteArray()
    {
        // Arrange
        var serializer = new BinaryObjectSerializer();
        var original = new Address
        {
            Label = "Test Address",
            Line1 = "123 Main St",
            Line2 = "Apt 4",
            City = "Springfield",
            Region = "IL",
            PostalCode = "62701",
            Country = "US"
        };

        // Act
        var serialized = serializer.Serialize(original);

        // Assert
        Assert.NotNull(serialized);
        Assert.NotEmpty(serialized);
        Assert.True(serialized.Length > 0);
    }

    [Fact]
    public void Serialize_ObjectWithId_ProducesConsistentOutput()
    {
        // Arrange
        var serializer = new BinaryObjectSerializer();
        var original = new Customer
        {
            Name = "John Doe",
            Email = "john@example.com",
            Phone = "555-1234",
            Company = "Test Co",
            IsActive = true
        };

        // Act
        var serialized1 = serializer.Serialize(original);
        var serialized2 = serializer.Serialize(original);

        // Assert
        Assert.NotNull(serialized1);
        Assert.NotNull(serialized2);
        Assert.Equal(serialized1.Length, serialized2.Length);
    }

    [Fact]
    public void Serialize_ObjectWithEmptyList_Succeeds()
    {
        // Arrange
        var serializer = new BinaryObjectSerializer();
        var original = new Product
        {
            Name = "Widget",
            Sku = "W001",
            Tags = new List<string>()
        };

        // Act
        var serialized = serializer.Serialize(original);

        // Assert
        Assert.NotNull(serialized);
        Assert.True(serialized.Length > 0);
    }

    [Fact]
    public void Serialize_ObjectWithListItems_ProducesLargerOutput()
    {
        // Arrange
        var serializer = new BinaryObjectSerializer();
        var emptyList = new Product
        {
            Name = "Widget",
            Sku = "W001",
            Tags = new List<string>()
        };
        var withList = new Product
        {
            Name = "Widget",
            Sku = "W001",
            Tags = new List<string> { "hardware", "tools", "bestseller" }
        };

        // Act
        var serializedEmpty = serializer.Serialize(emptyList);
        var serializedWithList = serializer.Serialize(withList);

        // Assert
        Assert.NotNull(serializedEmpty);
        Assert.NotNull(serializedWithList);
        Assert.True(serializedWithList.Length > serializedEmpty.Length,
            "Object with list items should produce larger serialized output");
    }

    [Fact]
    public void Serialize_MultipleObjects_ProducesUniqueOutputs()
    {
        // Arrange
        var serializer = new BinaryObjectSerializer();
        var address1 = new Address { Label = "Address 1", Line1 = "123 Main St", City = "City1", Country = "US" };
        var address2 = new Address { Label = "Address 2", Line1 = "456 Oak Ave", City = "City2", Country = "US" };

        // Act
        var serialized1 = serializer.Serialize(address1);
        var serialized2 = serializer.Serialize(address2);

        // Assert
        Assert.NotNull(serialized1);
        Assert.NotNull(serialized2);
        Assert.NotEqual(serialized1, serialized2);
    }
}
