using System.Collections.Generic;

namespace BareMetalWeb.Data;

internal sealed class SchemaRegistryFile
{
    public int CurrentVersion { get; set; }
    public List<SchemaDefinitionFile> Versions { get; set; } = new();
}

internal sealed class SchemaDefinitionFile
{
    public int Version { get; set; }
    public uint Hash { get; set; }
    public string? Architecture { get; set; }
    public List<MemberSignatureFile> Members { get; set; } = new();
}

internal sealed class MemberSignatureFile
{
    public string Name { get; set; } = string.Empty;
    public string TypeName { get; set; } = string.Empty;
    public int? BlittableSize { get; set; }
}
