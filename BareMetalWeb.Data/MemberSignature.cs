namespace BareMetalWeb.Data;

public sealed class MemberSignature
{
    public MemberSignature(string name, string typeName, Type type)
        : this(name, typeName, type, null)
    {
    }

    public MemberSignature(string name, string typeName, Type type, int? blittableSize)
    {
        Name = name;
        TypeName = typeName;
        Type = type;
        BlittableSize = blittableSize;
    }

    public string Name { get; }
    public string TypeName { get; }
    public Type Type { get; }
    public int? BlittableSize { get; }
}
