using System;
using System.Collections.Generic;
using System.Linq;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace BareMetalWeb.Host.Tests;

public class ExportTests
{
    [Fact]
    public void ExportOptions_FromQuery_ParsesFormat()
    {
        // Arrange
        var query = new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            { "format", "HierarchicalJSON" }
        });

        // Act
        var options = ExportOptions.FromQuery(query);

        // Assert
        Assert.Equal(ExportFormat.HierarchicalJSON, options.Format);
    }

    [Fact]
    public void ExportOptions_FromQuery_ParsesDepth()
    {
        // Arrange
        var query = new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            { "depth", "2" }
        });

        // Act
        var options = ExportOptions.FromQuery(query);

        // Assert
        Assert.Equal(2, options.MaxDepth);
    }

    [Fact]
    public void ExportOptions_FromQuery_LimitsDepthTo10()
    {
        // Arrange
        var query = new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            { "depth", "100" }
        });

        // Act
        var options = ExportOptions.FromQuery(query);

        // Assert - should be capped at default 1 since 100 > 10
        Assert.Equal(1, options.MaxDepth);
    }

    [Fact]
    public void ExportOptions_FromQuery_ParsesIncludeNested()
    {
        // Arrange
        var query = new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            { "includeNested", "false" }
        });

        // Act
        var options = ExportOptions.FromQuery(query);

        // Assert
        Assert.False(options.IncludeNested);
    }

    [Fact]
    public void ExportOptions_FromQuery_ParsesComponents()
    {
        // Arrange
        var query = new QueryCollection(new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>
        {
            { "components", "OrderRows,LineItems" }
        });

        // Act
        var options = ExportOptions.FromQuery(query);

        // Assert
        Assert.NotNull(options.IncludeNestedComponents);
        Assert.Contains("OrderRows", options.IncludeNestedComponents!);
        Assert.Contains("LineItems", options.IncludeNestedComponents!);
    }

    [Fact]
    public void ExportOptions_Defaults_AreCorrect()
    {
        // Act
        var options = new ExportOptions();

        // Assert
        Assert.Equal(ExportFormat.SimpleCSV, options.Format);
        Assert.Equal(1, options.MaxDepth);
        Assert.True(options.IncludeNested);
        Assert.Null(options.IncludeNestedComponents);
    }

    [Fact]
    public void DataScaffold_GetNestedComponents_ReturnsChildLists()
    {
        // Arrange - ensure Order entity is registered
        DataScaffold.RegisterEntity<Order>();
        var metadata = DataScaffold.TryGetEntity("orders", out var meta) ? meta : null;
        Assert.NotNull(metadata);

        // Act
        var nested = DataScaffold.GetNestedComponents(metadata!);

        // Assert
        Assert.NotEmpty(nested);
        var orderRowsField = nested.First(n => n.Field.Name == "OrderRows");
        Assert.Equal(typeof(OrderRow), orderRowsField.ChildType);
    }

    [Fact]
    public void DataScaffold_ExtractNestedData_ExtractsOrderRows()
    {
        // Arrange
        DataScaffold.RegisterEntity<Order>();
        var metadata = DataScaffold.TryGetEntity("orders", out var meta) ? meta : null;
        Assert.NotNull(metadata);

        var order = new Order
        {
            Id = "ORD-001",
            OrderNumber = "12345",
            CustomerId = "CUST-001",
            OrderDate = DateOnly.FromDateTime(DateTime.UtcNow),
            Status = "Open",
            CurrencyId = "USD",
            OrderRows = new List<OrderRow>
            {
                new OrderRow
                {
                    ProductId = "PROD-001",
                    Quantity = 2,
                    UnitPrice = 10.50m,
                    LineTotal = 21.00m,
                    Notes = "Test item 1"
                },
                new OrderRow
                {
                    ProductId = "PROD-002",
                    Quantity = 1,
                    UnitPrice = 5.00m,
                    LineTotal = 5.00m,
                    Notes = "Test item 2"
                }
            }
        };

        // Act
        var nested = DataScaffold.ExtractNestedData(metadata!, order);

        // Assert
        Assert.NotEmpty(nested);
        var orderRowsData = nested.First(n => n.FieldName == "OrderRows");
        Assert.Equal(2, orderRowsData.Rows.Length);
        
        // Check headers
        Assert.Contains("Product", orderRowsData.Headers);
        Assert.Contains("Quantity", orderRowsData.Headers);
        Assert.Contains("Unit Price", orderRowsData.Headers);
        
        // Check first row data
        var firstRow = orderRowsData.Rows[0];
        Assert.Contains("PROD-001", firstRow);
        Assert.Contains("2", firstRow);
    }

    [Fact]
    public void DataScaffold_ExtractNestedData_HandlesEmptyList()
    {
        // Arrange
        DataScaffold.RegisterEntity<Order>();
        var metadata = DataScaffold.TryGetEntity("orders", out var meta) ? meta : null;
        Assert.NotNull(metadata);

        var order = new Order
        {
            Id = "ORD-002",
            OrderNumber = "67890",
            CustomerId = "CUST-002",
            OrderDate = DateOnly.FromDateTime(DateTime.UtcNow),
            Status = "Open",
            CurrencyId = "USD",
            OrderRows = new List<OrderRow>() // Empty list
        };

        // Act
        var nested = DataScaffold.ExtractNestedData(metadata!, order);

        // Assert
        Assert.NotEmpty(nested);
        var orderRowsData = nested.First(n => n.FieldName == "OrderRows");
        Assert.Empty(orderRowsData.Rows);
    }

    [Fact]
    public void BuildSubFieldSchemas_ForOrderRowsField_ReturnsSubFieldMetadata()
    {
        // Arrange - ensure Order entity is registered
        DataScaffold.RegisterEntity<Order>();
        var metadata = DataScaffold.TryGetEntity("orders", out var meta) ? meta : null;
        Assert.NotNull(metadata);

        var orderRowsField = metadata!.Fields.FirstOrDefault(f => f.Name == "OrderRows");
        Assert.NotNull(orderRowsField);

        // Act - BuildSubFieldSchemas reads only attribute metadata, no data store needed
        var subFields = DataScaffold.BuildSubFieldSchemas(orderRowsField!);

        // Assert - should return sub-field schemas for OrderRow
        Assert.NotNull(subFields);
        Assert.NotEmpty(subFields!);

        // ProductId should be a LookupList field
        var productField = subFields.FirstOrDefault(f => (string?)f["name"] == "ProductId");
        Assert.NotNull(productField);
        Assert.Equal("LookupList", productField!["type"]);
        Assert.NotNull(productField["lookup"]);

        // Quantity should be present
        var quantityField = subFields.FirstOrDefault(f => (string?)f["name"] == "Quantity");
        Assert.NotNull(quantityField);
        Assert.Equal("Integer", quantityField!["type"]);

        // LineTotal should be a calculated field
        var lineTotalField = subFields.FirstOrDefault(f => (string?)f["name"] == "LineTotal");
        Assert.NotNull(lineTotalField);
        Assert.NotNull(lineTotalField!["calculated"]);
        Assert.True((bool?)lineTotalField["readOnly"]);
    }

    [Fact]
    public void BuildSubFieldSchemas_ForNonListField_ReturnsNull()
    {
        // Arrange
        DataScaffold.RegisterEntity<Order>();
        var metadata = DataScaffold.TryGetEntity("orders", out var meta) ? meta : null;
        Assert.NotNull(metadata);

        // Pick a non-list field (OrderNumber is a plain string field)
        var orderNumberField = metadata!.Fields.FirstOrDefault(f => f.Name == "OrderNumber");
        Assert.NotNull(orderNumberField);

        // Act
        var subFields = DataScaffold.BuildSubFieldSchemas(orderNumberField!);

        // Assert - non-list fields return null
        Assert.Null(subFields);
    }
}
