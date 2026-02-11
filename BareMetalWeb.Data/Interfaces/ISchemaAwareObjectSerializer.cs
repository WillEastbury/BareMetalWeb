using System.Buffers;
namespace BareMetalWeb.Data.Interfaces;

public interface ISchemaAwareObjectSerializer
{
    SchemaDefinition BuildSchema(Type type);
    SchemaDefinition CreateSchema(int version, IEnumerable<MemberSignature> members, uint? expectedHash = null);
    SchemaDefinition CreateSchema(int version, IEnumerable<MemberSignature> members, BinaryArchitecture architecture, uint? expectedHash = null);
    T? Deserialize<T>(byte[] data);
    T? Deserialize<T>(byte[] data, SchemaDefinition schema);
    T? Deserialize<T>(ReadOnlySpan<byte> data);
    T? Deserialize<T>(ReadOnlySpan<byte> data, SchemaDefinition schema);
    int ReadSchemaVersion(byte[] data);
    int ReadSchemaVersion(ReadOnlySpan<byte> data);
    Type ResolveTypeName(string typeName);
    byte[] Serialize<T>(T obj);
    byte[] Serialize<T>(T obj, int schemaVersion);
    int Serialize<T>(T obj, Span<byte> destination);
    int Serialize<T>(T obj, int schemaVersion, Span<byte> destination);
    int Serialize<T>(T obj, IBufferWriter<byte> destination);
    int Serialize<T>(T obj, int schemaVersion, IBufferWriter<byte> destination);
}


