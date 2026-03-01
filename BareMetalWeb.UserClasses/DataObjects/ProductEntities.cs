using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

/// <summary>Product category for browsing hierarchy.</summary>
[DataEntity("Product Categories", ShowOnNav = true, NavGroup = "Commerce", NavOrder = 5)]
public class ProductCategory : RenderableDataObject
{
    [DataField(Label = "Name", Order = 1, Required = true)]
    [DataIndex]
    public string Name { get; set; } = string.Empty;

    [DataField(Label = "Slug", Order = 2, Required = true)]
    [DataIndex]
    public string Slug { get; set; } = string.Empty;

    [DataField(Label = "Description", Order = 3)]
    public string Description { get; set; } = string.Empty;

    [DataField(Label = "Icon", Order = 4)]
    public string Icon { get; set; } = string.Empty;

    [DataField(Label = "Display Order", Order = 5)]
    public int DisplayOrder { get; set; } = 100;

    public override string ToString() => Name;
}
