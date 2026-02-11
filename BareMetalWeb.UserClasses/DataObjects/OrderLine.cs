using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

public class OrderRow
{
    [DataField(Label = "Product", Order = 1, Required = true)]
    [DataLookup(typeof(Product), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc, CacheSeconds = 120)]
    public string ProductId { get; set; } = string.Empty;

    [DataField(Label = "Quantity", Order = 2, Required = true)]
    public int Quantity { get; set; } = 1;

    [DataField(Label = "Unit Price", Order = 3, Required = true, FieldType = Rendering.Models.FormFieldType.Decimal)]
    public decimal UnitPrice { get; set; }

    [DataField(Label = "Line Total", Order = 4, Required = true, FieldType = Rendering.Models.FormFieldType.Decimal)]
    public decimal LineTotal { get; set; }

    [DataField(Label = "Notes", Order = 5)]
    public string Notes { get; set; } = string.Empty;
}
