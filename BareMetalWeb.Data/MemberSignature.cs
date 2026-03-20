namespace BareMetalWeb.Data;

public sealed class MemberSignature
{
    public MemberSignature(string name, string typeName, Type type)
    {
        Name = name;
        TypeName = typeName;
        Type = type;
    }

    public string Name { get; }
    public string TypeName { get; }
    public Type Type { get; }
}
