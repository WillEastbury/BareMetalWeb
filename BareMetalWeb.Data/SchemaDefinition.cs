namespace BareMetalWeb.Data;

public sealed class SchemaDefinition
{
    public SchemaDefinition(int version, uint hash, MemberSignature[] members)
        : this(version, hash, members, BinaryArchitectureMapper.Current)
    {
    }

    public SchemaDefinition(int version, uint hash, MemberSignature[] members, BinaryArchitecture architecture)
    {
        Version = version;
        Hash = hash;
        Members = members;
        Architecture = architecture;
    }

    public int Version { get; }
    public uint Hash { get; }
    public MemberSignature[] Members { get; }
    public BinaryArchitecture Architecture { get; }
}
