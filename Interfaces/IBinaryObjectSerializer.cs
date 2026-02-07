using System;
using System.Buffers;
using System.Collections.Generic;
using BareMetalWeb.Data;

namespace BareMetalWeb.Interfaces;

public interface ISchemaAwareObjectSerializer
{
    BinaryObjectSerializer.SchemaDefinition BuildSchema(Type type);
    BinaryObjectSerializer.SchemaDefinition CreateSchema(int version, IEnumerable<BinaryObjectSerializer.MemberSignature> members, uint? expectedHash = null);
    BinaryObjectSerializer.SchemaDefinition CreateSchema(int version, IEnumerable<BinaryObjectSerializer.MemberSignature> members, BinaryObjectSerializer.BinaryArchitecture architecture, uint? expectedHash = null);
    T? Deserialize<T>(byte[] data);
    T? Deserialize<T>(byte[] data, BinaryObjectSerializer.SchemaDefinition schema);
    T? Deserialize<T>(ReadOnlySpan<byte> data);
    T? Deserialize<T>(ReadOnlySpan<byte> data, BinaryObjectSerializer.SchemaDefinition schema);
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


