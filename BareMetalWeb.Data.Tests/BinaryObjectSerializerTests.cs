using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;
using BareMetalWeb.Core;

namespace BareMetalWeb.Data.Tests;

public class BinaryObjectSerializerTests
{
    [Fact]
    public void SerializeDeserialize_SimpleObject_ReturnsEqualObject()
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
        var deserialized = serializer.Deserialize<Address>(serialized);

        // Assert
        Assert.NotNull(deserialized);
        Assert.Equal(original.Label, deserialized.Label);
        Assert.Equal(original.Line1, deserialized.Line1);
        Assert.Equal(original.Line2, deserialized.Line2);
        Assert.Equal(original.City, deserialized.City);
        Assert.Equal(original.Region, deserialized.Region);
        Assert.Equal(original.PostalCode, deserialized.PostalCode);
        Assert.Equal(original.Country, deserialized.Country);
    }

    [Fact]
    public void SerializeDeserialize_ObjectWithId_PreservesId()
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
        var originalId = original.Id;

        // Act
        var serialized = serializer.Serialize(original);
        var deserialized = serializer.Deserialize<Customer>(serialized);

        // Assert
        Assert.NotNull(deserialized);
        Assert.Equal(originalId, deserialized.Id);
        Assert.Equal(original.Name, deserialized.Name);
        Assert.Equal(original.Email, deserialized.Email);
    }

    [Fact]
    public void SerializeDeserialize_EmptyList_ReturnsEmptyList()
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
        var deserialized = serializer.Deserialize<Product>(serialized);

        // Assert
        Assert.NotNull(deserialized);
        Assert.NotNull(deserialized.Tags);
        Assert.Empty(deserialized.Tags);
    }

    [Fact]
    public void SerializeDeserialize_ListWithItems_PreservesItems()
    {
        // Arrange
        var serializer = new BinaryObjectSerializer();
        var original = new Product
        {
            Name = "Widget",
            Sku = "W001",
            Tags = new List<string> { "hardware", "tools", "bestseller" }
        };

        // Act
        var serialized = serializer.Serialize(original);
        var deserialized = serializer.Deserialize<Product>(serialized);

        // Assert
        Assert.NotNull(deserialized);
        Assert.NotNull(deserialized.Tags);
        Assert.Equal(3, deserialized.Tags.Count);
        Assert.Equal("hardware", deserialized.Tags[0]);
        Assert.Equal("tools", deserialized.Tags[1]);
        Assert.Equal("bestseller", deserialized.Tags[2]);
    }
}
