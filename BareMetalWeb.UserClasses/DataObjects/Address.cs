using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

[DataEntity("Addresses", ShowOnNav = true, NavGroup = "Sales", NavOrder = 15)]
public class Address : RenderableDataObject
{
    [DataField(Label = "Label", Order = 1, Required = true)]
    public string Label { get; set; } = string.Empty;

    [DataField(Label = "Address Line 1", Order = 2, Required = true)]
    public string Line1 { get; set; } = string.Empty;

    [DataField(Label = "Address Line 2", Order = 3)]
    public string Line2 { get; set; } = string.Empty;

    [DataField(Label = "City", Order = 4, Required = true)]
    public string City { get; set; } = string.Empty;

    [DataField(Label = "Region", Order = 5)]
    public string Region { get; set; } = string.Empty;

    [DataField(Label = "Postal Code", Order = 6)]
    public string PostalCode { get; set; } = string.Empty;

    [DataField(Label = "Country", Order = 7, Required = true, FieldType = Rendering.Models.FormFieldType.Country)]
    public string Country { get; set; } = string.Empty;
}
