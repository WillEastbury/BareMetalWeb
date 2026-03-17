using System;
using System.Collections.Generic;
using System.Linq;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace BareMetalWeb.Host.Tests;

[Collection("SharedState")]
public class ExportTests
{
    [DataEntity("Test Order Rows", Slug = "test-export-order-rows")]
    private class TestOrderRow : BaseDataObject
    {
        private const int Ord_LineTotal = BaseFieldCount + 0;
        private const int Ord_Notes = BaseFieldCount + 1;
        private const int Ord_ProductId = BaseFieldCount + 2;
        private const int Ord_Quantity = BaseFieldCount + 3;
        private const int Ord_UnitPrice = BaseFieldCount + 4;
        internal new const int TotalFieldCount = BaseFieldCount + 5;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("LineTotal", Ord_LineTotal),
            new FieldSlot("Notes", Ord_Notes),
            new FieldSlot("ProductId", Ord_ProductId),
            new FieldSlot("Quantity", Ord_Quantity),
            new FieldSlot("UnitPrice", Ord_UnitPrice),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public TestOrderRow() : base(TotalFieldCount) { }
        public TestOrderRow(string createdBy) : base(TotalFieldCount, createdBy) { }


        [DataField(Label = "Product", Order = 1)]
        [DataLookup(typeof(BaseDataObject))]
        public string ProductId
        {
            get => (string?)_values[Ord_ProductId] ?? string.Empty;
            set => _values[Ord_ProductId] = value;
        }

        public int Quantity
        {
            get => (int)(_values[Ord_Quantity] ?? 0);
            set => _values[Ord_Quantity] = value;
        }

        public decimal UnitPrice
        {
            get => (decimal)(_values[Ord_UnitPrice] ?? 0m);
            set => _values[Ord_UnitPrice] = value;
        }

        public string Notes
        {
            get => (string?)_values[Ord_Notes] ?? string.Empty;
            set => _values[Ord_Notes] = value;
        }


        [DataField(Label = "Line Total", Order = 5, FieldType = Rendering.Models.FormFieldType.Decimal)]
        [CalculatedField(Expression = "Quantity * UnitPrice")]
        public decimal LineTotal
        {
            get => (decimal)(_values[Ord_LineTotal] ?? 0m);
            set => _values[Ord_LineTotal] = value;
        }
    }

    [DataEntity("Test Orders", Slug = "test-export-orders")]
    private class TestOrder : BaseDataObject
    {
        private const int Ord_CurrencyId = BaseFieldCount + 0;
        private const int Ord_CustomerId = BaseFieldCount + 1;
        private const int Ord_OrderDate = BaseFieldCount + 2;
        private const int Ord_OrderNumber = BaseFieldCount + 3;
        private const int Ord_OrderRows = BaseFieldCount + 4;
        private const int Ord_Status = BaseFieldCount + 5;
        internal new const int TotalFieldCount = BaseFieldCount + 6;

        private static readonly FieldSlot[] _fieldMap = new[]
        {
            new FieldSlot("CreatedBy", Ord_CreatedBy),
            new FieldSlot("CreatedOnUtc", Ord_CreatedOnUtc),
            new FieldSlot("CurrencyId", Ord_CurrencyId),
            new FieldSlot("CustomerId", Ord_CustomerId),
            new FieldSlot("ETag", Ord_ETag),
            new FieldSlot("Identifier", Ord_Identifier),
            new FieldSlot("Key", Ord_Key),
            new FieldSlot("OrderDate", Ord_OrderDate),
            new FieldSlot("OrderNumber", Ord_OrderNumber),
            new FieldSlot("OrderRows", Ord_OrderRows),
            new FieldSlot("Status", Ord_Status),
            new FieldSlot("UpdatedBy", Ord_UpdatedBy),
            new FieldSlot("UpdatedOnUtc", Ord_UpdatedOnUtc),
            new FieldSlot("Version", Ord_Version),
        };
        protected internal override ReadOnlySpan<FieldSlot> GetFieldMap() => _fieldMap;

        public TestOrder() : base(TotalFieldCount) { }
        public TestOrder(string createdBy) : base(TotalFieldCount, createdBy) { }

        public string OrderNumber
        {
            get => (string?)_values[Ord_OrderNumber] ?? string.Empty;
            set => _values[Ord_OrderNumber] = value;
        }

        public string CustomerId
        {
            get => (string?)_values[Ord_CustomerId] ?? string.Empty;
            set => _values[Ord_CustomerId] = value;
        }

        public DateOnly OrderDate
        {
            get => _values[Ord_OrderDate] is DateOnly d ? d : default;
            set => _values[Ord_OrderDate] = value;
        }

        public string Status
        {
            get => (string?)_values[Ord_Status] ?? string.Empty;
            set => _values[Ord_Status] = value;
        }

        public string CurrencyId
        {
            get => (string?)_values[Ord_CurrencyId] ?? string.Empty;
            set => _values[Ord_CurrencyId] = value;
        }


        [DataField(Label = "Order Rows", Order = 6, FieldType = Rendering.Models.FormFieldType.ChildList)]
        public List<TestOrderRow> OrderRows
        {
            get => (List<TestOrderRow>?)_values[Ord_OrderRows] ?? new();
            set => _values[Ord_OrderRows] = value;
        }
    }

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
        DataScaffold.RegisterEntity<TestOrder>();
        var metadata = DataScaffold.TryGetEntity("test-export-orders", out var meta) ? meta : null;
        Assert.NotNull(metadata);

        // Act
        var nested = DataScaffold.GetNestedComponents(metadata!);

        // Assert
        Assert.NotEmpty(nested);
        var orderRowsField = nested.First(n => n.Field.Name == "OrderRows");
        Assert.Equal(typeof(TestOrderRow), orderRowsField.ChildType);
    }

    [Fact]
    public void DataScaffold_ExtractNestedData_ExtractsOrderRows()
    {
        // Arrange
        DataScaffold.RegisterEntity<TestOrder>();
        var metadata = DataScaffold.TryGetEntity("test-export-orders", out var meta) ? meta : null;
        Assert.NotNull(metadata);

        var order = new TestOrder
        {
            Key = 1,
            OrderNumber = "12345",
            CustomerId = "CUST-001",
            OrderDate = DateOnly.FromDateTime(DateTime.UtcNow),
            Status = "Open",
            CurrencyId = "USD",
            OrderRows = new List<TestOrderRow>
            {
                new TestOrderRow
                {
                    ProductId = "PROD-001",
                    Quantity = 2,
                    UnitPrice = 10.50m,
                    LineTotal = 21.00m,
                    Notes = "Test item 1"
                },
                new TestOrderRow
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
        DataScaffold.RegisterEntity<TestOrder>();
        var metadata = DataScaffold.TryGetEntity("test-export-orders", out var meta) ? meta : null;
        Assert.NotNull(metadata);

        var order = new TestOrder
        {
            Key = 2,
            OrderNumber = "67890",
            CustomerId = "CUST-002",
            OrderDate = DateOnly.FromDateTime(DateTime.UtcNow),
            Status = "Open",
            CurrencyId = "USD",
            OrderRows = new List<TestOrderRow>() // Empty list
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
        DataScaffold.RegisterEntity<TestOrder>();
        var metadata = DataScaffold.TryGetEntity("test-export-orders", out var meta) ? meta : null;
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
        DataScaffold.RegisterEntity<TestOrder>();
        var metadata = DataScaffold.TryGetEntity("test-export-orders", out var meta) ? meta : null;
        Assert.NotNull(metadata);

        // Pick a non-list field (OrderNumber is a plain string field)
        var orderNumberField = metadata!.Fields.FirstOrDefault(f => f.Name == "OrderNumber");
        Assert.NotNull(orderNumberField);

        // Act
        var subFields = DataScaffold.BuildSubFieldSchemas(orderNumberField!);

        // Assert - non-list fields return null
        Assert.Null(subFields);
    }

    [Fact]
    public void BuildSubFieldSchemas_ForVirtualEntityChildList_ReturnsSubFieldsFromChildMeta()
    {
        // Arrange — "orders" is a metadata-driven gallery entity with a ChildList "OrderRows"
        // whose ChildEntitySlug = "order-rows".  No CLR List<T> type exists; CLR type is string.
        _ = HostGalleryTestFixture.State;
        Assert.True(DataScaffold.TryGetEntity("orders", out var meta));
        var orderRowsField = meta!.Fields.FirstOrDefault(f => f.Name == "OrderRows");
        Assert.NotNull(orderRowsField);
        Assert.Equal(Rendering.Models.FormFieldType.ChildList, orderRowsField!.FieldType);
        Assert.Equal(typeof(string), orderRowsField.ClrType); // virtual entity — stored as JSON string

        // Act
        var subFields = DataScaffold.BuildSubFieldSchemas(orderRowsField);

        // Assert — sub-fields must be populated from the registered "order-rows" entity metadata
        Assert.NotNull(subFields);
        Assert.NotEmpty(subFields!);

        // ProductId must be present (it's the first field in the order-rows entity)
        var productField = subFields.FirstOrDefault(f => (string?)f["name"] == "ProductId");
        Assert.NotNull(productField);
        Assert.Equal("LookupList", (string?)productField!["type"]);

        // Quantity must be present
        var qtyField = subFields.FirstOrDefault(f => (string?)f["name"] == "Quantity");
        Assert.NotNull(qtyField);
    }
}
