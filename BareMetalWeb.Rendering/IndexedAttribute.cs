namespace BareMetalWeb.Rendering;

[AttributeUsage(AttributeTargets.Class, Inherited = false, AllowMultiple = false)]
public sealed class IndexedAttribute : Attribute
{
    public string[] Fields { get; }

    public IndexedAttribute(params string[] fields)
    {
        Fields = fields ?? Array.Empty<string>();
    }
}


