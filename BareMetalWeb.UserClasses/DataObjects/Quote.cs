using System;
using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

/// <summary>
/// A sales quote that can be converted into an Order.
/// Demonstrates the document-chain relationship: Quote → Order.
/// </summary>
[DataEntity("Quotes", ShowOnNav = true, NavGroup = "Sales", NavOrder = 35)]
public class Quote : RenderableDataObject
{
    [DataField(Label = "Quote Number", Order = 1, Required = true)]
    [DataIndex]
    public string QuoteNumber { get; set; } = string.Empty;

    [DataField(Label = "Customer", Order = 2, Required = true)]
    [DataLookup(typeof(Customer), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc, CacheSeconds = 120)]
    [DataIndex]
    public string CustomerId { get; set; } = string.Empty;

    [DataField(Label = "Quote Date", Order = 3, Required = true)]
    public DateOnly QuoteDate { get; set; } = DateOnly.FromDateTime(DateTime.UtcNow);

    [DataField(Label = "Expiry Date", Order = 4)]
    public DateOnly? ExpiryDate { get; set; }

    [DataField(Label = "Status", Order = 5, Required = true)]
    [DataIndex]
    public string Status { get; set; } = "Draft";

    [DataField(Label = "Notes", Order = 6)]
    public string Notes { get; set; } = string.Empty;

    public override string ToString() => QuoteNumber;
}
