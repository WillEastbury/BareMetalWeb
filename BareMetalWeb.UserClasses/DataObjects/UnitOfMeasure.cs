using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

[DataEntity("Units Of Measure", ShowOnNav = true, NavGroup = "Sales", NavOrder = 25)]
public class UnitOfMeasure : RenderableDataObject
{
    [DataField(Label = "Name", Order = 1, Required = true)]
    public string Name { get; set; } = string.Empty;

    [DataField(Label = "Abbreviation", Order = 2, Required = true)]
    public string Abbreviation { get; set; } = string.Empty;

    [DataField(Label = "Description", Order = 3)]
    public string Description { get; set; } = string.Empty;

    [DataField(Label = "Active", Order = 4)]
    public bool IsActive { get; set; } = true;
}
