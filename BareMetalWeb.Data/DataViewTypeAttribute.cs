namespace BareMetalWeb.Data;

public enum ViewType
{
    Table = 0,
    TreeView = 1,
    OrgChart = 2,
    Timeline = 3
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
