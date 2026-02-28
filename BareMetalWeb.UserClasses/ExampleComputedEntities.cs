using System.Collections.Generic;
using BareMetalWeb.Data;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.UserClasses;

/// <summary>
/// Example entity demonstrating computed field functionality.
/// Represents a product with base pricing and stock information.
/// </summary>
[DataEntity("Example Products", Slug = "example-products", ShowOnNav = false, NavGroup = "Examples", NavOrder = 100)]
public class ExampleProduct : BaseDataObject
{
    [DataField(Label = "Product Name", Order = 1, Required = true)]
    public string Name { get; set; } = string.Empty;

    [DataField(Label = "SKU", Order = 2)]
    public string SKU { get; set; } = string.Empty;

    [DataField(Label = "Base Price", FieldType = FormFieldType.Money, Order = 3)]
    public decimal BasePrice { get; set; }

    [DataField(Label = "Stock Quantity", Order = 4)]
    public int StockQuantity { get; set; }

    [DataField(Label = "Category", Order = 5)]
    public string Category { get; set; } = string.Empty;

    [DataField(Label = "Description", FieldType = FormFieldType.TextArea, Order = 6)]
    public string Description { get; set; } = string.Empty;
}

/// <summary>
/// Example entity demonstrating all three computed field strategies.
/// Represents an order with various computed price fields.
/// </summary>
[DataEntity("Example Orders", Slug = "example-orders", ShowOnNav = false, NavGroup = "Examples", NavOrder = 101)]
public class ExampleOrder : BaseDataObject
{
    [DataField(Label = "Order Number", Order = 1, Required = true)]
    public string OrderNumber { get; set; } = string.Empty;

    [DataField(Label = "Customer Name", Order = 2)]
    public string CustomerName { get; set; } = string.Empty;

    [DataField(Label = "Product", Order = 3)]
    [DataLookup(typeof(ExampleProduct), DisplayField = nameof(ExampleProduct.Name), ValueField = nameof(ExampleProduct.Key))]
    public string ProductId { get; set; } = string.Empty;

    [DataField(Label = "Quantity", Order = 4)]
    public int Quantity { get; set; }

    /// <summary>
    /// SNAPSHOT STRATEGY: Price frozen at order creation.
    /// This value is copied from the product's BasePrice when the order is created.
    /// It will NOT change if the product price changes later.
    /// Use case: Maintain accurate historical pricing for audit/accounting.
    /// </summary>
    [ComputedField(
        SourceEntity = typeof(ExampleProduct),
        SourceField = nameof(ExampleProduct.BasePrice),
        ForeignKeyField = nameof(ProductId),
        Strategy = ComputedStrategy.Snapshot,
        Trigger = ComputedTrigger.OnCreate)]
    [DataField(Label = "Unit Price at Order (Snapshot)", FieldType = FormFieldType.Money, Order = 5, List = true, View = true)]
    public decimal UnitPriceSnapshot { get; set; }

    /// <summary>
    /// CACHED LIVE STRATEGY: Shows current product price with 60-second caching.
    /// This value is fetched from the product but cached for performance.
    /// Use case: Display current pricing without hitting the database on every access.
    /// </summary>
    [ComputedField(
        SourceEntity = typeof(ExampleProduct),
        SourceField = nameof(ExampleProduct.BasePrice),
        ForeignKeyField = nameof(ProductId),
        Strategy = ComputedStrategy.CachedLive,
        CacheSeconds = 60)]
    [DataField(Label = "Current Price (Cached 60s)", FieldType = FormFieldType.Money, Order = 6, List = false, View = true)]
    public decimal CurrentPriceCached { get; set; }

    /// <summary>
    /// ALWAYS LIVE STRATEGY: Always shows current product price in real-time.
    /// This value is fetched from the product on every access with no caching.
    /// Use case: Critical real-time pricing where staleness is not acceptable.
    /// </summary>
    [ComputedField(
        SourceEntity = typeof(ExampleProduct),
        SourceField = nameof(ExampleProduct.BasePrice),
        ForeignKeyField = nameof(ProductId),
        Strategy = ComputedStrategy.AlwaysLive)]
    [DataField(Label = "Current Price (Always Live)", FieldType = FormFieldType.Money, Order = 7, List = false, View = true)]
    public decimal CurrentPriceLive { get; set; }

    /// <summary>
    /// COMPUTED TOTAL: Calculated from snapshot price × quantity.
    /// This shows the total order value based on the frozen historical price.
    /// </summary>
    [DataField(Label = "Total Amount", FieldType = FormFieldType.Money, Order = 8, List = true, View = true)]
    public decimal TotalAmount => UnitPriceSnapshot * Quantity;

    [DataField(Label = "Order Date", FieldType = FormFieldType.DateOnly, Order = 9)]
    public DateOnly OrderDate { get; set; } = DateOnly.FromDateTime(DateTime.UtcNow);

    [DataField(Label = "Status", Order = 10)]
    public string Status { get; set; } = "Pending";

    [DataField(Label = "Notes", FieldType = FormFieldType.TextArea, Order = 11, Required = false)]
    public string Notes { get; set; } = string.Empty;
}
