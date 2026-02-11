using System;
using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

[DataEntity("Orders", ShowOnNav = true, NavGroup = "Sales", NavOrder = 40)]
public class Order : RenderableDataObject
{
    [DataField(Label = "Order Number", Order = 1, Required = true)]
    public string OrderNumber { get; set; } = string.Empty;

    [DataField(Label = "Customer", Order = 2, Required = true)]
    [DataLookup(typeof(Customer), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc, CacheSeconds = 120)]
    public string CustomerId { get; set; } = string.Empty;

    [DataField(Label = "Order Date", Order = 3, Required = true)]
    public DateOnly OrderDate { get; set; } = DateOnly.FromDateTime(DateTime.UtcNow);

    [DataField(Label = "Status", Order = 4, Required = true)]
    public string Status { get; set; } = "Open";

    [DataField(Label = "Currency", Order = 5, Required = true)]
    [DataLookup(typeof(Currency), DisplayField = "IsoCode", SortField = "IsoCode", SortDirection = SortDirection.Asc, CacheSeconds = 120)]
    public string CurrencyId { get; set; } = string.Empty;

    [DataField(Label = "Notes", Order = 6)]
    public string Notes { get; set; } = string.Empty;

    [DataField(Label = "Is Open", Order = 7)]
    public bool IsOpen { get; set; } = true;

    [DataField(Label = "Order Rows", Order = 8)]
    public List<OrderRow> OrderRows { get; set; } = new();
}
