using System;
using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

/// <summary>
/// Example entity demonstrating auto-generated sequential integer IDs.
/// Each instance will receive an auto-incrementing ID (1, 2, 3, etc.)
/// </summary>
[DataEntity("Invoices", ShowOnNav = true, NavGroup = "Finance", NavOrder = 50)]
public class Invoice : RenderableDataObject
{
    // Override the base Id property to apply auto-generation with sequential long strategy
    [IdGeneration(IdGenerationStrategy.SequentialLong)]
    [DataField(Label = "Invoice #", Order = 0, ReadOnly = true, List = true, View = true, Edit = false, Create = false)]
    public new string Id
    {
        get => base.Id;
        set => base.Id = value;
    }

    [DataField(Label = "Customer", Order = 1, Required = true)]
    [DataLookup(typeof(Customer), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc, CacheSeconds = 120)]
    [DataIndex]
    public string CustomerId { get; set; } = string.Empty;

    [DataField(Label = "Invoice Date", Order = 2, Required = true, FieldType = Rendering.Models.FormFieldType.DateOnly)]
    public DateOnly InvoiceDate { get; set; } = DateOnly.FromDateTime(DateTime.Today);

    [DataField(Label = "Due Date", Order = 3, Required = true, FieldType = Rendering.Models.FormFieldType.DateOnly)]
    public DateOnly DueDate { get; set; } = DateOnly.FromDateTime(DateTime.Today.AddDays(30));

    [DataField(Label = "Amount", Order = 4, Required = true, FieldType = Rendering.Models.FormFieldType.Decimal)]
    public decimal Amount { get; set; } = 0m;

    [DataField(Label = "Currency", Order = 5, Required = true)]
    [DataLookup(typeof(Currency), DisplayField = "Name", SortField = "Name", SortDirection = SortDirection.Asc, CacheSeconds = 300)]
    public string CurrencyId { get; set; } = string.Empty;

    [DataField(Label = "Status", Order = 6, Required = true)]
    public InvoiceStatus Status { get; set; } = InvoiceStatus.Draft;

    [DataField(Label = "Notes", Order = 7, FieldType = Rendering.Models.FormFieldType.TextArea)]
    public string Notes { get; set; } = string.Empty;
}

/// <summary>
/// Invoice status enumeration.
/// </summary>
public enum InvoiceStatus
{
    Draft = 0,
    Sent = 1,
    Paid = 2,
    Cancelled = 3
}
