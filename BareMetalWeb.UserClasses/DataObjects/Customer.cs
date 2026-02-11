using System;
using System.Collections.Generic;
using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

[DataEntity("Customers", ShowOnNav = true, NavGroup = "Sales", NavOrder = 10)]
public class Customer : RenderableDataObject
{
    [DataField(Label = "Name", Order = 1, Required = true)]
    public string Name { get; set; } = string.Empty;

    [DataField(Label = "Email", Order = 2, Required = true, FieldType = Rendering.Models.FormFieldType.Email)]
    public string Email { get; set; } = string.Empty;

    [DataField(Label = "Phone", Order = 3)]
    public string Phone { get; set; } = string.Empty;

    [DataField(Label = "Company", Order = 4)]
    public string Company { get; set; } = string.Empty;

    [DataField(Label = "Address", Order = 5)]
    [DataLookup(typeof(Address), DisplayField = "Label", SortField = "Label", SortDirection = SortDirection.Asc, CacheSeconds = 120)]
    public string AddressId { get; set; } = string.Empty;

    [DataField(Label = "Active", Order = 6)]
    public bool IsActive { get; set; } = true;

    [DataField(Label = "Notes", Order = 7)]
    public string Notes { get; set; } = string.Empty;

    [DataField(Label = "Tags", Order = 8)]
    public List<string> Tags { get; set; } = new();
}
