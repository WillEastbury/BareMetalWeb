using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

[DataEntity("Order Lines", Slug = "order-lines", ShowOnNav = true, NavGroup = "Sales", NavOrder = 50)]
public class OrderRow : RenderableDataObject
{
    [DataField(Label = "Product", Order = 1, Required = true)]
    [DataLookup(typeof(Product), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc, CacheSeconds = 120, CopyFields = "Price->UnitPrice")]
    [DataIndex]
    public string ProductId { get; set; } = string.Empty;

    [DataField(Label = "Quantity", Order = 2, Required = true)]
    public int Quantity { get; set; } = 1;

    [DataField(Label = "Unit Price", Order = 3, Required = true, FieldType = Rendering.Models.FormFieldType.Decimal)]
    public decimal UnitPrice { get; set; }

    [DataField(Label = "Discount %", Order = 4, FieldType = Rendering.Models.FormFieldType.Decimal)]
    [CopyFromParent("CustomerId", "customers", "DiscountPercent")]
    public decimal DiscountPercent { get; set; }

    [CalculatedField(Expression = "Quantity * UnitPrice")]
    [DataField(Label = "Subtotal", Order = 5, FieldType = Rendering.Models.FormFieldType.Decimal)]
    public decimal Subtotal { get; set; }

    [CalculatedField(Expression = "Subtotal * (1 - DiscountPercent / 100)")]
    [DataField(Label = "Line Total", Order = 6, FieldType = Rendering.Models.FormFieldType.Decimal)]
    public decimal LineTotal { get; set; }

    [DataField(Label = "Notes", Order = 7)]
    public string Notes { get; set; } = string.Empty;
}
