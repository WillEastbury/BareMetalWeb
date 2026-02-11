namespace BareMetalWeb.Data;

[AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
public sealed class DataEntityAttribute : Attribute
{
    public string Name { get; }
    public string? Slug { get; set; }
    public string Permissions { get; set; } = string.Empty;
    public bool ShowOnNav { get; set; } = false;
    public string? NavGroup { get; set; }
    public int NavOrder { get; set; } = 0;

    public DataEntityAttribute(string name)
    {
        Name = name;
    }
}


