namespace BareMetalWeb.Data;

[DataEntity("Settings", ShowOnNav = true, NavGroup = "Administration", NavOrder = 1)]
public class AppSetting : RenderableDataObject
{
    [DataField(Label = "Setting ID", Order = 1, Required = true)]
    [DataIndex]
    public string SettingId { get; set; } = string.Empty;

    [DataField(Label = "Value", Order = 2)]
    public string Value { get; set; } = string.Empty;

    [DataField(Label = "Description", Order = 3)]
    public string Description { get; set; } = string.Empty;
}
