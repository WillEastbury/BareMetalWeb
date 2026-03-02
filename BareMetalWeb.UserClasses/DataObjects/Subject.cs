using System;
using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

[DataEntity("Subjects", ShowOnNav = true, NavGroup = "School", NavOrder = 10)]
public class Subject : RenderableDataObject
{
    [DataField(Label = "Name", Order = 1, Required = true)]
    [DataIndex]
    public string Name { get; set; } = string.Empty;
}
