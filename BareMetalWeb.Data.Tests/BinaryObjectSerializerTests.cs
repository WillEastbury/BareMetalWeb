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

    [Fact]
    public void Deserialize_WithSchemaHashMismatch_StrictMode_Throws()
    {
        // Arrange - simulates what happens when an entity class changes (new field added)
        // and old records are read with a schema whose hash no longer matches the current type.
        var serializer = new BinaryObjectSerializer();
        var original = new Customer { Key = 1, Name = "Acme Corp", Email = "acme@test.com" };
        var bytes = serializer.Serialize(original, 1);

        var currentSchema = serializer.BuildSchema(typeof(Customer));
        // Construct a stale schema with a deliberately wrong hash (simulating old schema after entity change)
        var staleSchema = new SchemaDefinition(1, currentSchema.Hash + 1, currentSchema.Members);

        // Act & Assert - Strict mode should throw on hash mismatch
        Assert.Throws<InvalidOperationException>(() => serializer.Deserialize<Customer>(bytes, staleSchema));
    }

    [Fact]
    public void Deserialize_WithSchemaHashMismatch_BestEffortMode_ReturnsObject()
    {
        // Arrange - simulates schema evolution: entity was modified after records were saved.
        // The stored schema's hash differs from the current type's hash, but the data is still readable.
        var serializer = new BinaryObjectSerializer();
        var original = new Customer { Key = 1, Name = "Acme Corp", Email = "acme@test.com" };
        var bytes = serializer.Serialize(original, 1);

        var currentSchema = serializer.BuildSchema(typeof(Customer));
        // Construct a stale schema with a wrong hash (old hash before entity evolution)
        var staleSchema = new SchemaDefinition(1, currentSchema.Hash + 1, currentSchema.Members);

        // Act - BestEffort mode should succeed and return the object with its available data
        var result = serializer.Deserialize<Customer>(bytes, staleSchema, SchemaReadMode.BestEffort);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(1u, result.Key);
        Assert.Equal("Acme Corp", result.Name);
        Assert.Equal("acme@test.com", result.Email);
    }
}
