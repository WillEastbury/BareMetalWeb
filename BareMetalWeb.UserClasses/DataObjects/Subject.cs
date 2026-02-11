using System;
using BareMetalWeb.Data;

namespace BareMetalWeb.Data.DataObjects;

[DataEntity("Subjects", ShowOnNav = false, NavGroup = "Admin", NavOrder = 10)]
public class Subject : RenderableDataObject
{
    [DataField(Label = "Name", Order = 1, Required = true)]
    public string Name { get; set; } = string.Empty;
}
