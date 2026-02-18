namespace BareMetalWeb.Data;

public enum ViewType
{
    Table = 0,
    TreeView = 1,
    OrgChart = 2
}

[AttributeUsage(AttributeTargets.Class, Inherited = true, AllowMultiple = false)]
public sealed class DataViewTypeAttribute : Attribute
{
    public ViewType ViewType { get; }

    public DataViewTypeAttribute(ViewType viewType)
    {
        ViewType = viewType;
    }
}
