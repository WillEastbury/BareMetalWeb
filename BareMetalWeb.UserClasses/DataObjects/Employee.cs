using BareMetalWeb.Data;

namespace BareMetalWeb.UserClasses.DataObjects;

[DataEntity("Employees", ShowOnNav = true, NavGroup = "Organization", NavOrder = 10, IdGeneration = AutoIdStrategy.Guid)]
[DataViewType(ViewType.TreeView)]
public class Employee : RenderableDataObject
{
    [DataField(Order = 2, Label = "Name", List = true, View = true, Edit = true, Create = true, Required = true)]
    [DataIndex]
    public string Name { get; set; } = string.Empty;

    [DataField(Order = 3, Label = "Title", List = true, View = true, Edit = true, Create = true)]
    public string? Title { get; set; }

    [DataField(Order = 4, Label = "Email", List = true, View = true, Edit = true, Create = true)]
    public string? Email { get; set; }

    [DataField(Order = 5, Label = "Manager", List = true, View = true, Edit = true, Create = true)]
    [DataLookup(typeof(Employee), DisplayField = nameof(Name), QueryField = nameof(Id), QueryOperator = QueryOperator.NotEquals)]
    public string? ManagerId { get; set; }

    [DataField(Order = 6, Label = "Department", List = true, View = true, Edit = true, Create = true)]
    [DataIndex]
    public string? Department { get; set; }

    [DataField(Order = 7, Label = "Hire Date", List = false, View = true, Edit = true, Create = true)]
    public DateOnly? HireDate { get; set; }

    public Employee() { }
}
