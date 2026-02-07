using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

[DataEntity("Currencies", ShowOnNav = true, NavGroup = "Sales", NavOrder = 30)]
public class Currency : RenderableDataObject
{
    [DataField(Label = "ISO Code", Order = 1, Required = true)]
    public string IsoCode { get; set; } = string.Empty;

    [DataField(Label = "Description", Order = 2, Required = true)]
    public string Description { get; set; } = string.Empty;

    [DataField(Label = "Symbol", Order = 3)]
    public string Symbol { get; set; } = string.Empty;

    [DataField(Label = "Decimal Places", Order = 4)]
    public int DecimalPlaces { get; set; } = 2;

    [DataField(Label = "Enabled", Order = 5)]
    public bool IsEnabled { get; set; } = true;

    [DataField(Label = "Base Currency", Order = 6)]
    public bool IsBase { get; set; }
}
