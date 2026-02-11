using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using BareMetalWeb.Data.Interfaces;
namespace BareMetalWeb.Data;

// • Schema must be supplied on read
// • Schema version is authoritative
// • No polymorphism
// • No reference tracking
// • Members are name-sorted
// • Public fields + properties only
// • Binary is little-endian
// • Hash is FNV-1a over member signatures

public sealed class BinaryObjectSerializer : ISchemaAwareObjectSerializer
{
    private static readonly ConcurrentDictionary<Type, TypeShape> TypeCache = new();
    private static readonly ConcurrentDictionary<SchemaCacheKey, byte> SchemaValidationCache = new();
    private static readonly Encoding Utf8 = Encoding.UTF8;
    private const int Magic = 0x314F5342; // "BSO1" in little-endian
    private const int CurrentVersion = 3;
    private const int MaxDepth = 64;
    private const int MaxStringBytes = 4 * 1024 * 1024; // 4 MiB
    private const int MaxCollectionLength = 1_000_000;
    private const int MaxDictionaryEntries = 1_000_000;
    private const int MaxBlittableSize = 4 * 1024 * 1024; // 4 MiB
    private const int SignatureSize = 32;
    private const int HeaderFieldsSizeV2 = 4 + 4 + 4 + 1;
    private const int HeaderFieldsSizeV3 = 4 + 4 + 4 + 1;
    private const int HeaderSizeV3 = HeaderFieldsSizeV3 + SignatureSize;
    private static readonly byte[] SignaturePlaceholder = new byte[SignatureSize];
    private static readonly string DefaultSigningKeyPath = Path.Combine(AppContext.BaseDirectory, ".keys", "binary-serializer.key");
    private static readonly MethodInfo BlittableSizeMethod = typeof(BinaryObjectSerializer)
        .GetMethod(nameof(GetBlittableSizeCore), BindingFlags.NonPublic | BindingFlags.Static)!;
    private static readonly MethodInfo BlittableWriteMethod = typeof(BinaryObjectSerializer)
        .GetMethod(nameof(BlittableWriteCore), BindingFlags.NonPublic | BindingFlags.Static)!;
    private static readonly MethodInfo BlittableReadMethod = typeof(BinaryObjectSerializer)
        .GetMethod(nameof(BlittableReadCore), BindingFlags.NonPublic | BindingFlags.Static)!;

    private readonly byte[] _signingKey;

    public BinaryObjectSerializer()
        : this(LoadOrCreateSigningKey(DefaultSigningKeyPath))
    {
    }

    public BinaryObjectSerializer(byte[] signingKey)
    {
        if (signingKey is null) throw new ArgumentNullException(nameof(signingKey));
        if (signingKey.Length != SignatureSize)
            throw new InvalidOperationException($"Signing key must be {SignatureSize} bytes.");
        _signingKey = signingKey;
    }

    public static BinaryObjectSerializer CreateDefault(string rootFolder)
    {
        if (string.IsNullOrWhiteSpace(rootFolder))
            throw new ArgumentException("Root folder cannot be null or whitespace.", nameof(rootFolder));

        var keyPath = Path.Combine(rootFolder, ".keys", "binary-serializer.key");
        return new BinaryObjectSerializer(LoadOrCreateSigningKey(keyPath));
    }

    public byte[] Serialize<T>(T obj)
    {
        return Serialize(obj, 1);
    }

    public int Serialize<T>(T obj, Span<byte> destination)
    {
        return Serialize(obj, 1, destination);
    }

    public int Serialize<T>(T obj, IBufferWriter<byte> destination)
    {
        return Serialize(obj, 1, destination);
    }

    public byte[] Serialize<T>(T obj, int schemaVersion)
    {
        return SerializeSigned(obj, schemaVersion);
    }

    public int Serialize<T>(T obj, int schemaVersion, Span<byte> destination)
    {
        var data = SerializeSigned(obj, schemaVersion);
        if (data.Length > destination.Length)
            throw new ArgumentException("Destination span is too small.", nameof(destination));

        data.CopyTo(destination);
        return data.Length;
    }

    public int Serialize<T>(T obj, int schemaVersion, IBufferWriter<byte> destination)
    {
        if (destination is null) throw new ArgumentNullException(nameof(destination));
        var data = SerializeSigned(obj, schemaVersion);
        var span = destination.GetSpan(data.Length);
        data.CopyTo(span);
        destination.Advance(data.Length);
        return data.Length;
    }

    public T? Deserialize<T>(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        ValidateSignature(data);
        using var stream = new MemoryStream(data);
        using var reader = new BinaryReader(stream, Utf8, leaveOpen: true);
        var schemaVersion = ReadHeader(reader, out _);
        throw new InvalidOperationException($"Schema version {schemaVersion} requires a schema definition for type {typeof(T).Name}.");
    }

    public T? Deserialize<T>(ReadOnlySpan<byte> data)
    {
        ValidateSignature(data);
        var reader = new SpanReader(data);
        var schemaVersion = ReadHeader(ref reader, out _);
        throw new InvalidOperationException($"Schema version {schemaVersion} requires a schema definition for type {typeof(T).Name}.");
    }

    public T? Deserialize<T>(byte[] data, SchemaDefinition schema)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (schema is null) throw new ArgumentNullException(nameof(schema));
        ValidateSignature(data);
        using var stream = new MemoryStream(data);
        using var reader = new BinaryReader(stream, Utf8, leaveOpen: true);
        var schemaVersion = ReadHeader(reader, out var architecture);
        if (schemaVersion != schema.Version)
            throw new InvalidOperationException($"Schema version mismatch for {typeof(T).Name}. Expected {schema.Version}, payload is {schemaVersion}.");
        ValidateArchitecture(schema, architecture);
        ValidateSchema(typeof(T), schema, SchemaReadMode.Strict);
        var value = ReadValue(reader, typeof(T), schema, 0);
        return (T?)value;
    }

    public T? Deserialize<T>(ReadOnlySpan<byte> data, SchemaDefinition schema)
    {
        return Deserialize<T>(data, schema, SchemaReadMode.Strict);
    }

    public T? Deserialize<T>(byte[] data, SchemaDefinition schema, SchemaReadMode mode)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (schema is null) throw new ArgumentNullException(nameof(schema));
        ValidateSignature(data);
        using var stream = new MemoryStream(data);
        using var reader = new BinaryReader(stream, Utf8, leaveOpen: true);
        var schemaVersion = ReadHeader(reader, out var architecture);
        if (schemaVersion != schema.Version)
            throw new InvalidOperationException($"Schema version mismatch for {typeof(T).Name}. Expected {schema.Version}, payload is {schemaVersion}.");
        ValidateArchitecture(schema, architecture);
        ValidateSchema(typeof(T), schema, mode);
        var value = ReadValue(reader, typeof(T), schema, 0);
        return (T?)value;
    }

    public T? Deserialize<T>(ReadOnlySpan<byte> data, SchemaDefinition schema, SchemaReadMode mode)
    {
        if (schema is null) throw new ArgumentNullException(nameof(schema));
        ValidateSignature(data);
        var reader = new SpanReader(data);
        var schemaVersion = ReadHeader(ref reader, out var architecture);
        if (schemaVersion != schema.Version)
            throw new InvalidOperationException($"Schema version mismatch for {typeof(T).Name}. Expected {schema.Version}, payload is {schemaVersion}.");
        ValidateArchitecture(schema, architecture);
        ValidateSchema(typeof(T), schema, mode);
        var value = ReadValue(ref reader, typeof(T), schema, 0);
        return (T?)value;
    }

    public int ReadSchemaVersion(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        using var stream = new MemoryStream(data);
        using var reader = new BinaryReader(stream, Utf8, leaveOpen: true);
        return ReadHeader(reader, out _);
    }

    public int ReadSchemaVersion(ReadOnlySpan<byte> data)
    {
        var reader = new SpanReader(data);
        return ReadHeader(ref reader, out _);
    }

    public SchemaDefinition BuildSchema(Type type)
    {
        var shape = GetTypeShape(type);
        return new SchemaDefinition(0, shape.SignatureHash, shape.MemberSignatures, BinaryArchitectureMapper.Current);
    }

    public SchemaDefinition CreateSchema(int version, IEnumerable<MemberSignature> members, uint? expectedHash = null)
    {
        return CreateSchema(version, members, BinaryArchitectureMapper.Current, expectedHash);
    }

    public SchemaDefinition CreateSchema(int version, IEnumerable<MemberSignature> members, BinaryArchitecture architecture, uint? expectedHash = null)
    {
        if (members is null) throw new ArgumentNullException(nameof(members));
        var materialized = members.ToArray();
        var hash = GetSignatureHash(materialized);
        if (expectedHash.HasValue && expectedHash.Value != hash)
            throw new InvalidOperationException("Schema hash does not match member signatures.");
        return new SchemaDefinition(version, hash, materialized, architecture);
    }

    public Type ResolveTypeName(string typeName) => ResolveType(typeName);

    private static void WriteHeader(BinaryWriter writer, int schemaVersion)
    {
        writer.Write(Magic);
        writer.Write(CurrentVersion);
        writer.Write(schemaVersion);
        writer.Write((byte)BinaryArchitectureMapper.Current);
        writer.Write(SignaturePlaceholder);
    }

    private static void WriteHeader(ref SpanWriter writer, int schemaVersion)
    {
        writer.WriteInt32(Magic);
        writer.WriteInt32(CurrentVersion);
        writer.WriteInt32(schemaVersion);
        writer.WriteByte((byte)BinaryArchitectureMapper.Current);
        writer.WriteBytes(SignaturePlaceholder);
    }

    private static int ReadHeader(BinaryReader reader, out BinaryArchitecture architecture)
    {
        var magic = reader.ReadInt32();
        if (magic != Magic)
            throw new InvalidOperationException("Invalid binary payload magic.");

        var version = reader.ReadInt32();
        if (version > CurrentVersion)
            throw new InvalidOperationException($"Unsupported binary payload version {version}.");

        var schemaVersion = reader.ReadInt32();
        if (version >= 2)
        {
            architecture = (BinaryArchitecture)reader.ReadByte();
        }
        else
        {
            architecture = BinaryArchitecture.Unknown;
        }

        if (version >= 3)
        {
            Span<byte> signature = stackalloc byte[SignatureSize];
            reader.Read(signature);
        }

        return schemaVersion;
    }

    private static int ReadHeader(ref SpanReader reader, out BinaryArchitecture architecture)
    {
        var magic = reader.ReadInt32();
        if (magic != Magic)
            throw new InvalidOperationException("Invalid binary payload magic.");

        var version = reader.ReadInt32();
        if (version > CurrentVersion)
            throw new InvalidOperationException($"Unsupported binary payload version {version}.");

        var schemaVersion = reader.ReadInt32();
        if (version >= 2)
        {
            architecture = (BinaryArchitecture)reader.ReadByte();
        }
        else
        {
            architecture = BinaryArchitecture.Unknown;
        }

        if (version >= 3)
        {
            Span<byte> signature = stackalloc byte[SignatureSize];
            reader.ReadBytes(signature);
        }

        return schemaVersion;
    }

    private static void WriteValue(BinaryWriter writer, Type type, object? value, int depth)
    {
        if (depth > MaxDepth)
            throw new InvalidOperationException($"Max serialization depth {MaxDepth} exceeded.");

        var shape = GetTypeShape(type);
        if (shape.IsNullable)
        {
            if (value is null)
            {
                writer.Write((byte)0);
                return;
            }

            writer.Write((byte)1);
            WriteValue(writer, shape.NullableUnderlying!, value, depth + 1);
            return;
        }
        switch (shape.Kind)
        {
            case TypeKind.Enum:
            {
                var enumUnderlying = shape.EnumUnderlying!;
                var rawValue = value == null
                    ? Convert.ChangeType(0, enumUnderlying)
                    : Convert.ChangeType(value, enumUnderlying);
                WriteValue(writer, enumUnderlying, rawValue, depth + 1);
                return;
            }
            case TypeKind.String:
                WriteString(writer, (string?)value);
                return;
            case TypeKind.Primitive:
                WritePrimitive(writer, shape.TypeCode, value);
                return;
            case TypeKind.Guid:
            {
                var guid = (Guid)(value ?? Guid.Empty);
                Span<byte> buffer = stackalloc byte[16];
                guid.TryWriteBytes(buffer);
                writer.Write(buffer);
                return;
            }
            case TypeKind.Blittable:
            {
                var size = shape.BlittableSize;
                var rented = ArrayPool<byte>.Shared.Rent(size);
                try
                {
                    shape.BlittableWrite!(value, rented);
                    writer.Write(rented, 0, size);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
                return;
            }
            case TypeKind.DateTime:
            {
                var dt = (DateTime)(value ?? default(DateTime));
                writer.Write(dt.Ticks);
                writer.Write((byte)dt.Kind);
                return;
            }
            case TypeKind.DateOnly:
            {
                var d = (DateOnly)(value ?? default(DateOnly));
                writer.Write(d.DayNumber);
                return;
            }
            case TypeKind.TimeOnly:
            {
                var t = (TimeOnly)(value ?? default(TimeOnly));
                writer.Write(t.Ticks);
                return;
            }
            case TypeKind.DateTimeOffset:
            {
                var dto = (DateTimeOffset)(value ?? default(DateTimeOffset));
                writer.Write(dto.Ticks);
                writer.Write((short)dto.Offset.TotalMinutes);
                return;
            }
            case TypeKind.TimeSpan:
            {
                var ts = (TimeSpan)(value ?? default(TimeSpan));
                writer.Write(ts.Ticks);
                return;
            }
            case TypeKind.Half:
            {
                var half = (Half)(value ?? default(Half));
                writer.Write(BitConverter.HalfToUInt16Bits(half));
                return;
            }
            case TypeKind.IntPtr:
            {
                var ptr = (IntPtr)(value ?? IntPtr.Zero);
                writer.Write(ptr.ToInt64());
                return;
            }
            case TypeKind.UIntPtr:
            {
                var ptr = (UIntPtr)(value ?? UIntPtr.Zero);
                writer.Write(ptr.ToUInt64());
                return;
            }
            case TypeKind.Array:
            {
                var elementType = shape.ElementType!;

                if (value is null)
                {
                    writer.Write(-1);
                    return;
                }

                var array = (Array)value;
                writer.Write(array.Length);
                for (int i = 0; i < array.Length; i++)
                    WriteValue(writer, elementType, array.GetValue(i), depth + 1);
                return;
            }
            case TypeKind.List:
            {
                if (value is null)
                {
                    writer.Write(-1);
                    return;
                }

                var list = (System.Collections.IList)value;
                writer.Write(list.Count);
                var listElementType = shape.ElementType!;
                for (int i = 0; i < list.Count; i++)
                    WriteValue(writer, listElementType, list[i], depth + 1);
                return;
            }
            case TypeKind.Dictionary:
            {
                if (value is null)
                {
                    writer.Write(-1);
                    return;
                }

                var dict = (System.Collections.IDictionary)value;
                writer.Write(dict.Count);
                var keyType = shape.KeyType!;
                var valueType = shape.ValueType!;
                foreach (System.Collections.DictionaryEntry entry in dict)
                {
                    WriteValue(writer, keyType, entry.Key, depth + 1);
                    WriteValue(writer, valueType, entry.Value, depth + 1);
                }
                return;
            }
            case TypeKind.Object:
            default:
            {
                if (!type.IsValueType)
                {
                    if (value is null)
                    {
                        writer.Write((byte)0);
                        return;
                    }
                    writer.Write((byte)1);
                }

                var members = GetMembers(type);
                foreach (var member in members)
                {
                    var memberValue = member.Getter(value!);
                    WriteValue(writer, AssumePublicMembers(member.MemberType), memberValue, depth + 1);
                }
                return;
            }
        }
    }

    private static void WriteValue(ref SpanWriter writer, Type type, object? value, int depth)
    {
        if (depth > MaxDepth)
            throw new InvalidOperationException($"Max serialization depth {MaxDepth} exceeded.");

        var shape = GetTypeShape(type);
        if (shape.IsNullable)
        {
            if (value is null)
            {
                writer.WriteByte(0);
                return;
            }

            writer.WriteByte(1);
            WriteValue(ref writer, shape.NullableUnderlying!, value, depth + 1);
            return;
        }

        switch (shape.Kind)
        {
            case TypeKind.Enum:
            {
                var enumUnderlying = shape.EnumUnderlying!;
                var rawValue = value == null
                    ? Convert.ChangeType(0, enumUnderlying)
                    : Convert.ChangeType(value, enumUnderlying);
                WriteValue(ref writer, enumUnderlying, rawValue, depth + 1);
                return;
            }
            case TypeKind.String:
                WriteString(ref writer, (string?)value);
                return;
            case TypeKind.Primitive:
                WritePrimitive(ref writer, shape.TypeCode, value);
                return;
            case TypeKind.Guid:
            {
                var guid = (Guid)(value ?? Guid.Empty);
                Span<byte> buffer = stackalloc byte[16];
                guid.TryWriteBytes(buffer);
                writer.WriteBytes(buffer);
                return;
            }
            case TypeKind.Blittable:
            {
                var size = shape.BlittableSize;
                var rented = ArrayPool<byte>.Shared.Rent(size);
                try
                {
                    shape.BlittableWrite!(value, rented);
                    writer.WriteBytes(rented.AsSpan(0, size));
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
                return;
            }
            case TypeKind.DateTime:
            {
                var dt = (DateTime)(value ?? default(DateTime));
                writer.WriteInt64(dt.Ticks);
                writer.WriteByte((byte)dt.Kind);
                return;
            }
            case TypeKind.DateOnly:
            {
                var d = (DateOnly)(value ?? default(DateOnly));
                writer.WriteInt32(d.DayNumber);
                return;
            }
            case TypeKind.TimeOnly:
            {
                var t = (TimeOnly)(value ?? default(TimeOnly));
                writer.WriteInt64(t.Ticks);
                return;
            }
            case TypeKind.DateTimeOffset:
            {
                var dto = (DateTimeOffset)(value ?? default(DateTimeOffset));
                writer.WriteInt64(dto.Ticks);
                writer.WriteInt16((short)dto.Offset.TotalMinutes);
                return;
            }
            case TypeKind.TimeSpan:
            {
                var ts = (TimeSpan)(value ?? default(TimeSpan));
                writer.WriteInt64(ts.Ticks);
                return;
            }
            case TypeKind.Half:
            {
                var half = (Half)(value ?? default(Half));
                writer.WriteUInt16(BitConverter.HalfToUInt16Bits(half));
                return;
            }
            case TypeKind.IntPtr:
            {
                var ptr = (IntPtr)(value ?? IntPtr.Zero);
                writer.WriteInt64(ptr.ToInt64());
                return;
            }
            case TypeKind.UIntPtr:
            {
                var ptr = (UIntPtr)(value ?? UIntPtr.Zero);
                writer.WriteUInt64(ptr.ToUInt64());
                return;
            }
            case TypeKind.Array:
            {
                var elementType = shape.ElementType!;

                if (value is null)
                {
                    writer.WriteInt32(-1);
                    return;
                }

                var array = (Array)value;
                writer.WriteInt32(array.Length);
                for (int i = 0; i < array.Length; i++)
                    WriteValue(ref writer, elementType, array.GetValue(i), depth + 1);
                return;
            }
            case TypeKind.List:
            {
                if (value is null)
                {
                    writer.WriteInt32(-1);
                    return;
                }

                var list = (System.Collections.IList)value;
                writer.WriteInt32(list.Count);
                var listElementType = shape.ElementType!;
                for (int i = 0; i < list.Count; i++)
                    WriteValue(ref writer, listElementType, list[i], depth + 1);
                return;
            }
            case TypeKind.Dictionary:
            {
                if (value is null)
                {
                    writer.WriteInt32(-1);
                    return;
                }

                var dict = (System.Collections.IDictionary)value;
                writer.WriteInt32(dict.Count);
                var keyType = shape.KeyType!;
                var valueType = shape.ValueType!;
                foreach (System.Collections.DictionaryEntry entry in dict)
                {
                    WriteValue(ref writer, keyType, entry.Key, depth + 1);
                    WriteValue(ref writer, valueType, entry.Value, depth + 1);
                }
                return;
            }
            case TypeKind.Object:
            default:
            {
                if (!type.IsValueType)
                {
                    if (value is null)
                    {
                        writer.WriteByte(0);
                        return;
                    }
                    writer.WriteByte(1);
                }

                var members = GetMembers(type);
                foreach (var member in members)
                {
                    var memberValue = member.Getter(value!);
                    WriteValue(ref writer, AssumePublicMembers(member.MemberType), memberValue, depth + 1);
                }
                return;
            }
        }
    }

    private static object? ReadValue(BinaryReader reader, Type type)
        => ReadValue(reader, type, null, 0);

    private static object? ReadValue(BinaryReader reader, Type type, SchemaDefinition? schema, int depth)
    {
        if (depth > MaxDepth)
            throw new InvalidOperationException($"Max deserialization depth {MaxDepth} exceeded.");

        var shape = GetTypeShape(type);
        if (shape.IsNullable)
        {
            var hasValue = reader.ReadByte();
            if (hasValue == 0)
                return null;
            return ReadValue(reader, shape.NullableUnderlying!, null, depth + 1);
        }
        switch (shape.Kind)
        {
            case TypeKind.Enum:
            {
                var enumUnderlying = shape.EnumUnderlying!;
                var rawValue = ReadValue(reader, enumUnderlying, null, depth + 1);
                return rawValue == null ? Enum.ToObject(type, 0) : Enum.ToObject(type, rawValue);
            }
            case TypeKind.String:
                return ReadString(reader);
            case TypeKind.Primitive:
                return ReadPrimitive(reader, shape.TypeCode);
            case TypeKind.Guid:
            {
                Span<byte> buffer = stackalloc byte[16];
                ReadExact(reader, buffer);
                return new Guid(buffer);
            }
            case TypeKind.Blittable:
            {
                var size = shape.BlittableSize;
                var rented = ArrayPool<byte>.Shared.Rent(size);
                try
                {
                    ReadExact(reader, rented.AsSpan(0, size));
                    return shape.BlittableRead!(rented);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }
            case TypeKind.DateTime:
            {
                var ticks = reader.ReadInt64();
                var kind = (DateTimeKind)reader.ReadByte();
                return new DateTime(ticks, kind);
            }
            case TypeKind.DateOnly:
            {
                var dayNumber = reader.ReadInt32();
                return DateOnly.FromDayNumber(dayNumber);
            }
            case TypeKind.TimeOnly:
            {
                var ticks = reader.ReadInt64();
                return new TimeOnly(ticks);
            }
            case TypeKind.DateTimeOffset:
            {
                var ticks = reader.ReadInt64();
                var offsetMinutes = reader.ReadInt16();
                return new DateTimeOffset(ticks, TimeSpan.FromMinutes(offsetMinutes));
            }
            case TypeKind.TimeSpan:
            {
                var ticks = reader.ReadInt64();
                return new TimeSpan(ticks);
            }
            case TypeKind.Half:
            {
                var bits = reader.ReadUInt16();
                return BitConverter.UInt16BitsToHalf(bits);
            }
            case TypeKind.IntPtr:
            {
                var value = reader.ReadInt64();
                return new IntPtr(value);
            }
            case TypeKind.UIntPtr:
            {
                var value = reader.ReadUInt64();
                return new UIntPtr(value);
            }
            case TypeKind.Array:
            {
                var elementType = shape.ElementType!;

                var length = reader.ReadInt32();
                if (length < 0) return null;
                if (length > MaxCollectionLength)
                    throw new InvalidOperationException($"Array length {length} exceeds MaxCollectionLength {MaxCollectionLength}.");
                var array = shape.ArrayFactory!(length);
                for (int i = 0; i < length; i++)
                    array.SetValue(ReadValue(reader, elementType, null, depth + 1), i);
                return array;
            }
            case TypeKind.List:
            {
                var count = reader.ReadInt32();
                if (count < 0) return null;
                if (count > MaxCollectionLength)
                    throw new InvalidOperationException($"List length {count} exceeds MaxCollectionLength {MaxCollectionLength}.");

                var list = shape.ListFactory!(count);
                for (int i = 0; i < count; i++)
                    list.Add(ReadValue(reader, shape.ElementType!, null, depth + 1));
                return list;
            }
            case TypeKind.Dictionary:
            {
                var count = reader.ReadInt32();
                if (count < 0) return null;
                if (count > MaxDictionaryEntries)
                    throw new InvalidOperationException($"Dictionary entries {count} exceeds MaxDictionaryEntries {MaxDictionaryEntries}.");

                var dict = shape.DictionaryFactory!(count);
                for (int i = 0; i < count; i++)
                {
                    var key = ReadValue(reader, shape.KeyType!, null, depth + 1);
                    var val = ReadValue(reader, shape.ValueType!, null, depth + 1);
                    dict.Add(key!, val);
                }
                return dict;
            }
            case TypeKind.Object:
            default:
            {
                if (!type.IsValueType)
                {
                    var hasValue = reader.ReadByte();
                    if (hasValue == 0) return null;
                }

                var instance = CreateInstance(type);
                var memberMap = GetMemberMap(type);

                if (schema != null)
                {
                    foreach (var signature in schema.Members)
                    {
                        var signatureType = AssumePublicMembers(signature.Type);
                        if (!TryReadValue(reader, signatureType, depth + 1, out var memberValue))
                            break;

                        if (memberMap.TryGetValue(signature.Name, out var member))
                            TryAssignValue(instance, member, memberValue);
                    }
                }
                else
                {
                    var members = GetMembers(type);
                    foreach (var member in members)
                    {
                        if (!TryReadValue(reader, AssumePublicMembers(member.MemberType), depth + 1, out var memberValue))
                            break;

                        member.Setter(instance, memberValue);
                    }
                }

                return instance;
            }
        }
    }

    private static object? ReadValue(ref SpanReader reader, Type type, SchemaDefinition? schema, int depth)
    {
        if (depth > MaxDepth)
            throw new InvalidOperationException($"Max deserialization depth {MaxDepth} exceeded.");

        var shape = GetTypeShape(type);
        if (shape.IsNullable)
        {
            var hasValue = reader.ReadByte();
            if (hasValue == 0)
                return null;
            return ReadValue(ref reader, shape.NullableUnderlying!, null, depth + 1);
        }

        switch (shape.Kind)
        {
            case TypeKind.Enum:
            {
                var enumUnderlying = shape.EnumUnderlying!;
                var rawValue = ReadValue(ref reader, enumUnderlying, null, depth + 1);
                return rawValue == null ? Enum.ToObject(type, 0) : Enum.ToObject(type, rawValue);
            }
            case TypeKind.String:
                return ReadString(ref reader);
            case TypeKind.Primitive:
                return ReadPrimitive(ref reader, shape.TypeCode);
            case TypeKind.Guid:
            {
                Span<byte> buffer = stackalloc byte[16];
                reader.ReadBytes(buffer);
                return new Guid(buffer);
            }
            case TypeKind.Blittable:
            {
                var size = shape.BlittableSize;
                var rented = ArrayPool<byte>.Shared.Rent(size);
                try
                {
                    reader.ReadBytes(rented.AsSpan(0, size));
                    return shape.BlittableRead!(rented);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }
            case TypeKind.DateTime:
            {
                var ticks = reader.ReadInt64();
                var kind = (DateTimeKind)reader.ReadByte();
                return new DateTime(ticks, kind);
            }
            case TypeKind.DateOnly:
            {
                var dayNumber = reader.ReadInt32();
                return DateOnly.FromDayNumber(dayNumber);
            }
            case TypeKind.TimeOnly:
            {
                var ticks = reader.ReadInt64();
                return new TimeOnly(ticks);
            }
            case TypeKind.DateTimeOffset:
            {
                var ticks = reader.ReadInt64();
                var offsetMinutes = reader.ReadInt16();
                return new DateTimeOffset(ticks, TimeSpan.FromMinutes(offsetMinutes));
            }
            case TypeKind.TimeSpan:
            {
                var ticks = reader.ReadInt64();
                return new TimeSpan(ticks);
            }
            case TypeKind.Half:
            {
                var bits = reader.ReadUInt16();
                return BitConverter.UInt16BitsToHalf(bits);
            }
            case TypeKind.IntPtr:
            {
                var value = reader.ReadInt64();
                return new IntPtr(value);
            }
            case TypeKind.UIntPtr:
            {
                var value = reader.ReadUInt64();
                return new UIntPtr(value);
            }
            case TypeKind.Array:
            {
                var elementType = shape.ElementType!;
                var length = reader.ReadInt32();
                if (length < 0) return null;
                if (length > MaxCollectionLength)
                    throw new InvalidOperationException($"Array length {length} exceeds MaxCollectionLength {MaxCollectionLength}.");
                var array = shape.ArrayFactory!(length);
                for (int i = 0; i < length; i++)
                    array.SetValue(ReadValue(ref reader, elementType, null, depth + 1), i);
                return array;
            }
            case TypeKind.List:
            {
                var count = reader.ReadInt32();
                if (count < 0) return null;
                if (count > MaxCollectionLength)
                    throw new InvalidOperationException($"List length {count} exceeds MaxCollectionLength {MaxCollectionLength}.");

                var list = shape.ListFactory!(count);
                for (int i = 0; i < count; i++)
                    list.Add(ReadValue(ref reader, shape.ElementType!, null, depth + 1));
                return list;
            }
            case TypeKind.Dictionary:
            {
                var count = reader.ReadInt32();
                if (count < 0) return null;
                if (count > MaxDictionaryEntries)
                    throw new InvalidOperationException($"Dictionary entries {count} exceeds MaxDictionaryEntries {MaxDictionaryEntries}.");

                var dict = shape.DictionaryFactory!(count);
                for (int i = 0; i < count; i++)
                {
                    var key = ReadValue(ref reader, shape.KeyType!, null, depth + 1);
                    var val = ReadValue(ref reader, shape.ValueType!, null, depth + 1);
                    dict.Add(key!, val);
                }
                return dict;
            }
            case TypeKind.Object:
            default:
            {
                if (!type.IsValueType)
                {
                    var hasValue = reader.ReadByte();
                    if (hasValue == 0) return null;
                }

                var instance = CreateInstance(type);
                var memberMap = GetMemberMap(type);

                if (schema != null)
                {
                    foreach (var signature in schema.Members)
                    {
                        var signatureType = AssumePublicMembers(signature.Type);
                        if (!TryReadValue(ref reader, signatureType, depth + 1, out var memberValue))
                            break;

                        if (memberMap.TryGetValue(signature.Name, out var member))
                            TryAssignValue(instance, member, memberValue);
                    }
                }
                else
                {
                    var members = GetMembers(type);
                    foreach (var member in members)
                    {
                        if (!TryReadValue(ref reader, AssumePublicMembers(member.MemberType), depth + 1, out var memberValue))
                            break;

                        member.Setter(instance, memberValue);
                    }
                }

                return instance;
            }
        }
    }

    private static void WriteString(BinaryWriter writer, string? value)
    {
        if (value is null)
        {
            writer.Write(-1);
            return;
        }

        var byteCount = Utf8.GetByteCount(value);
        writer.Write(byteCount);
        if (byteCount == 0)
            return;

        const int StackLimit = 512;
        if (byteCount <= StackLimit)
        {
            Span<byte> buffer = stackalloc byte[byteCount];
            Utf8.GetBytes(value, buffer);
            writer.Write(buffer);
            return;
        }

        var rented = ArrayPool<byte>.Shared.Rent(byteCount);
        try
        {
            var span = rented.AsSpan(0, byteCount);
            Utf8.GetBytes(value, span);
            writer.Write(span);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static void WriteString(ref SpanWriter writer, string? value)
    {
        if (value is null)
        {
            writer.WriteInt32(-1);
            return;
        }

        var byteCount = Utf8.GetByteCount(value);
        writer.WriteInt32(byteCount);
        if (byteCount == 0)
            return;

        const int StackLimit = 512;
        if (byteCount <= StackLimit)
        {
            Span<byte> buffer = stackalloc byte[byteCount];
            Utf8.GetBytes(value, buffer);
            writer.WriteBytes(buffer);
            return;
        }

        var rented = ArrayPool<byte>.Shared.Rent(byteCount);
        try
        {
            var span = rented.AsSpan(0, byteCount);
            Utf8.GetBytes(value, span);
            writer.WriteBytes(span);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static string? ReadString(BinaryReader reader)
    {
        var length = reader.ReadInt32();
        if (length < 0) return null;
        if (length > MaxStringBytes)
            throw new InvalidOperationException($"String byte length {length} exceeds MaxStringBytes {MaxStringBytes}.");
        if (length == 0) return string.Empty;

        const int StackLimit = 512;
        if (length <= StackLimit)
        {
            Span<byte> buffer = stackalloc byte[length];
            ReadExact(reader, buffer);
            return Utf8.GetString(buffer);
        }

        var rented = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            var span = rented.AsSpan(0, length);
            ReadExact(reader, span);
            return Utf8.GetString(span);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static string? ReadString(ref SpanReader reader)
    {
        var length = reader.ReadInt32();
        if (length < 0) return null;
        if (length > MaxStringBytes)
            throw new InvalidOperationException($"String byte length {length} exceeds MaxStringBytes {MaxStringBytes}.");
        if (length == 0) return string.Empty;

        const int StackLimit = 512;
        if (length <= StackLimit)
        {
            Span<byte> buffer = stackalloc byte[length];
            reader.ReadBytes(buffer);
            return Utf8.GetString(buffer);
        }

        var rented = ArrayPool<byte>.Shared.Rent(length);
        try
        {
            var span = rented.AsSpan(0, length);
            reader.ReadBytes(span);
            return Utf8.GetString(span);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static bool IsNullable(Type type, out Type? underlying)
    {
        underlying = Nullable.GetUnderlyingType(type);
        return underlying != null;
    }

    private static bool IsList(Type type, out Type elementType)
    {
        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(List<>))
        {
            elementType = type.GetGenericArguments()[0];
            return true;
        }
        elementType = null!;
        return false;
    }

    private static bool IsDictionary(Type type, out Type keyType, out Type valueType)
    {
        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(Dictionary<,>))
        {
            var args = type.GetGenericArguments();
            keyType = args[0];
            valueType = args[1];
            return true;
        }
        keyType = null!;
        valueType = null!;
        return false;
    }

    private static MemberAccessor[] GetMembers(Type type)
    {
        return GetTypeShape(type).Members;
    }

    private static Dictionary<string, MemberAccessor> GetMemberMap(Type type)
    {
        return GetTypeShape(type).MemberMap;
    }

    private static MemberAccessor CreateMemberAccessor(PropertyInfo property)
    {
        var declaringType = property.DeclaringType ?? throw new InvalidOperationException("Property declaring type missing.");
        var getter = CreatePropertyGetter(property);
        var setter = CreatePropertySetter(property);
        return new MemberAccessor(property.Name, AssumePublicMembers(property.PropertyType), getter, setter);
    }

    private static MemberAccessor CreateMemberAccessor(FieldInfo field)
    {
        var getter = CreateFieldGetter(field);
        var setter = CreateFieldSetter(field);
        return new MemberAccessor(field.Name, AssumePublicMembers(field.FieldType), getter, setter);
    }

    private static Func<object, object?> CreatePropertyGetter(PropertyInfo property)
    {
        return instance => property.GetValue(instance);
    }

    private static Action<object, object?> CreatePropertySetter(PropertyInfo property)
    {
        return (instance, value) => property.SetValue(instance, value);
    }

    private static Func<object, object?> CreateFieldGetter(FieldInfo field)
    {
        return instance => field.GetValue(instance);
    }

    private static Action<object, object?> CreateFieldSetter(FieldInfo field)
    {
        return (instance, value) => field.SetValue(instance, value);
    }

    private static uint GetSignatureHash(MemberSignature[] members)
    {
        uint hash = 2166136261;

        foreach (var member in members)
        {
            hash = Fnv1a(hash, member.Name);
            hash = Fnv1a(hash, ":");
            hash = Fnv1a(hash, member.TypeName);
            if (member.BlittableSize.HasValue)
            {
                hash = Fnv1a(hash, ":blittable-size=");
                hash = Fnv1a(hash, member.BlittableSize.Value.ToString());
            }
            hash = Fnv1a(hash, ";");
        }

        return hash;
    }

    private static string GetTypeIdentifier(Type type)
        => type.AssemblyQualifiedName ?? type.FullName ?? type.Name;

    private static Type ResolveType(string typeName)
    {
        var resolved = Type.GetType(typeName, throwOnError: false, ignoreCase: false);
        if (resolved != null)
            return resolved;

        resolved = typeof(BinaryObjectSerializer).Assembly.GetType(typeName, throwOnError: false, ignoreCase: false);
        if (resolved != null)
            return resolved;

        foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
        {
            resolved = assembly.GetType(typeName, throwOnError: false, ignoreCase: false);
            if (resolved != null)
                return resolved;
        }

        throw new InvalidOperationException($"Unable to resolve type '{typeName}'.");
    }

    private static Type AssumePublicMembers(Type type)
        => type;

    private static object CreateInstance(Type type)
    {
        if (type.IsEnum)
            return Enum.ToObject(type, 0);

        if (type.IsValueType)
            return Activator.CreateInstance(type) ?? throw new InvalidOperationException($"Unable to create default value for '{type.FullName}'.");

        return Activator.CreateInstance(type)
            ?? throw new InvalidOperationException($"Unable to create instance for '{type.FullName}'.");
    }

    private static void TryAssignValue(object instance, MemberAccessor member, object? value)
    {
        if (value is null)
        {
            if (!member.MemberType.IsValueType)
                member.Setter(instance, null);
            return;
        }

        var valueType = value.GetType();
        if (member.MemberType.IsAssignableFrom(valueType))
        {
            member.Setter(instance, value);
            return;
        }

        if (value is IConvertible)
        {
            try
            {
                var converted = Convert.ChangeType(value, member.MemberType);
                member.Setter(instance, converted);
                return;
            }
            catch
            {
            }
        }
    }

    private static bool TryReadValue(BinaryReader reader, Type type, int depth, out object? value)
    {
        try
        {
            value = ReadValue(reader, type, null, depth);
            return true;
        }
        catch (EndOfStreamException)
        {
            value = GetDefaultValue(type);
            return false;
        }
    }

    private static object? GetDefaultValue(Type type)
    {
        if (!type.IsValueType)
            return null;
        return Activator.CreateInstance(type);
    }

    private static TypeShape GetTypeShape(Type type)
    {
        return TypeCache.GetOrAdd(type, CreateTypeShape);
    }

    private static TypeShape CreateTypeShape(Type type)
    {
        var shape = new TypeShape(type);
        var nullable = Nullable.GetUnderlyingType(type);
        if (nullable != null)
        {
            shape.IsNullable = true;
            shape.NullableUnderlying = nullable;
            return shape;
        }

        if (type == typeof(string))
        {
            shape.Kind = TypeKind.String;
            return shape;
        }

        if (type.IsEnum)
        {
            shape.Kind = TypeKind.Enum;
            shape.EnumUnderlying = AssumePublicMembers(Enum.GetUnderlyingType(type));
            return shape;
        }

        if (type == typeof(Guid))
        {
            shape.Kind = TypeKind.Guid;
            return shape;
        }

        if (IsBlittable(type))
        {
            shape.Kind = TypeKind.Blittable;
            shape.BlittableSize = GetBlittableSize(type);
            if (shape.BlittableSize > MaxBlittableSize)
                throw new InvalidOperationException($"Blittable size {shape.BlittableSize} exceeds MaxBlittableSize {MaxBlittableSize}.");
            shape.BlittableWrite = CreateBlittableWrite(type);
            shape.BlittableRead = CreateBlittableRead(type);
            shape.MemberSignatures = Array.Empty<MemberSignature>();
            shape.MemberMap = EmptyMemberMap;
            shape.Members = Array.Empty<MemberAccessor>();
            shape.SignatureHash = GetBlittableSignatureHash(shape.BlittableSize);
            return shape;
        }

        if (type == typeof(DateTime))
        {
            shape.Kind = TypeKind.DateTime;
            return shape;
        }

        if (type == typeof(DateOnly))
        {
            shape.Kind = TypeKind.DateOnly;
            return shape;
        }

        if (type == typeof(TimeOnly))
        {
            shape.Kind = TypeKind.TimeOnly;
            return shape;
        }

        if (type == typeof(DateTimeOffset))
        {
            shape.Kind = TypeKind.DateTimeOffset;
            return shape;
        }

        if (type == typeof(TimeSpan))
        {
            shape.Kind = TypeKind.TimeSpan;
            return shape;
        }

        if (type == typeof(Half))
        {
            shape.Kind = TypeKind.Half;
            return shape;
        }

        if (type == typeof(IntPtr))
        {
            shape.Kind = TypeKind.IntPtr;
            return shape;
        }

        if (type == typeof(UIntPtr))
        {
            shape.Kind = TypeKind.UIntPtr;
            return shape;
        }

        if (type.IsArray)
        {
            shape.Kind = TypeKind.Array;
            shape.ElementType = AssumePublicMembers(type.GetElementType() ?? throw new NotSupportedException("Array element type missing."));
            shape.ArrayFactory = length => Array.CreateInstance(shape.ElementType, length);
            return shape;
        }

        if (IsList(type, out var listElementType))
        {
            shape.Kind = TypeKind.List;
            shape.ElementType = AssumePublicMembers(listElementType);
            shape.ListFactory = capacity => (System.Collections.IList)Activator.CreateInstance(type, capacity)!;
            return shape;
        }

        if (IsDictionary(type, out var keyType, out var valueType))
        {
            shape.Kind = TypeKind.Dictionary;
            shape.KeyType = AssumePublicMembers(keyType);
            shape.ValueType = AssumePublicMembers(valueType);
            shape.DictionaryFactory = capacity => (System.Collections.IDictionary)Activator.CreateInstance(type, capacity)!;
            return shape;
        }

        var typeCode = Type.GetTypeCode(type);
        if (typeCode != TypeCode.Object)
        {
            shape.Kind = TypeKind.Primitive;
            shape.TypeCode = typeCode;
            shape.Members = Array.Empty<MemberAccessor>();
            shape.MemberMap = EmptyMemberMap;
            shape.MemberSignatures = Array.Empty<MemberSignature>();
            shape.SignatureHash = 2166136261;
            return shape;
        }

        shape.Kind = TypeKind.Object;
        InitializeMemberMetadata(shape, type);
        return shape;
    }

    private static void WritePrimitive(BinaryWriter writer, TypeCode typeCode, object? value)
    {
        switch (typeCode)
        {
            case TypeCode.Int32:
                writer.Write((int)(value ?? 0));
                return;
            case TypeCode.UInt32:
                writer.Write((uint)(value ?? 0u));
                return;
            case TypeCode.Int64:
                writer.Write((long)(value ?? 0L));
                return;
            case TypeCode.UInt64:
                writer.Write((ulong)(value ?? 0UL));
                return;
            case TypeCode.Int16:
                writer.Write((short)(value ?? (short)0));
                return;
            case TypeCode.UInt16:
                writer.Write((ushort)(value ?? (ushort)0));
                return;
            case TypeCode.Single:
                writer.Write((float)(value ?? 0f));
                return;
            case TypeCode.Double:
                writer.Write((double)(value ?? 0d));
                return;
            case TypeCode.Decimal:
                writer.Write((decimal)(value ?? 0m));
                return;
            case TypeCode.Boolean:
                writer.Write((bool)(value ?? false));
                return;
            case TypeCode.Byte:
                writer.Write((byte)(value ?? (byte)0));
                return;
            case TypeCode.Char:
                writer.Write((char)(value ?? '\0'));
                return;
            case TypeCode.SByte:
                writer.Write((sbyte)(value ?? (sbyte)0));
                return;
            default:
                throw new NotSupportedException($"Unsupported primitive type code {typeCode}.");
        }
    }

    private static void WritePrimitive(ref SpanWriter writer, TypeCode typeCode, object? value)
    {
        switch (typeCode)
        {
            case TypeCode.Int32:
                writer.WriteInt32((int)(value ?? 0));
                return;
            case TypeCode.UInt32:
                writer.WriteUInt32((uint)(value ?? 0u));
                return;
            case TypeCode.Int64:
                writer.WriteInt64((long)(value ?? 0L));
                return;
            case TypeCode.UInt64:
                writer.WriteUInt64((ulong)(value ?? 0UL));
                return;
            case TypeCode.Int16:
                writer.WriteInt16((short)(value ?? (short)0));
                return;
            case TypeCode.UInt16:
                writer.WriteUInt16((ushort)(value ?? (ushort)0));
                return;
            case TypeCode.Single:
                writer.WriteSingle((float)(value ?? 0f));
                return;
            case TypeCode.Double:
                writer.WriteDouble((double)(value ?? 0d));
                return;
            case TypeCode.Decimal:
                writer.WriteDecimal((decimal)(value ?? 0m));
                return;
            case TypeCode.Boolean:
                writer.WriteBoolean((bool)(value ?? false));
                return;
            case TypeCode.Byte:
                writer.WriteByte((byte)(value ?? (byte)0));
                return;
            case TypeCode.Char:
                writer.WriteChar((char)(value ?? '\0'));
                return;
            case TypeCode.SByte:
                writer.WriteSByte((sbyte)(value ?? (sbyte)0));
                return;
            default:
                throw new NotSupportedException($"Unsupported primitive type code {typeCode}.");
        }
    }

    private static object ReadPrimitive(BinaryReader reader, TypeCode typeCode)
    {
        return typeCode switch
        {
            TypeCode.Int32 => reader.ReadInt32(),
            TypeCode.UInt32 => reader.ReadUInt32(),
            TypeCode.Int64 => reader.ReadInt64(),
            TypeCode.UInt64 => reader.ReadUInt64(),
            TypeCode.Int16 => reader.ReadInt16(),
            TypeCode.UInt16 => reader.ReadUInt16(),
            TypeCode.Single => reader.ReadSingle(),
            TypeCode.Double => reader.ReadDouble(),
            TypeCode.Decimal => reader.ReadDecimal(),
            TypeCode.Boolean => reader.ReadBoolean(),
            TypeCode.Byte => reader.ReadByte(),
            TypeCode.Char => reader.ReadChar(),
            TypeCode.SByte => reader.ReadSByte(),
            _ => throw new NotSupportedException($"Unsupported primitive type code {typeCode}.")
        };
    }

    private static object ReadPrimitive(ref SpanReader reader, TypeCode typeCode)
    {
        return typeCode switch
        {
            TypeCode.Int32 => reader.ReadInt32(),
            TypeCode.UInt32 => reader.ReadUInt32(),
            TypeCode.Int64 => reader.ReadInt64(),
            TypeCode.UInt64 => reader.ReadUInt64(),
            TypeCode.Int16 => reader.ReadInt16(),
            TypeCode.UInt16 => reader.ReadUInt16(),
            TypeCode.Single => reader.ReadSingle(),
            TypeCode.Double => reader.ReadDouble(),
            TypeCode.Decimal => reader.ReadDecimal(),
            TypeCode.Boolean => reader.ReadBoolean(),
            TypeCode.Byte => reader.ReadByte(),
            TypeCode.Char => reader.ReadChar(),
            TypeCode.SByte => reader.ReadSByte(),
            _ => throw new NotSupportedException($"Unsupported primitive type code {typeCode}.")
        };
    }

    private static void ReadExact(BinaryReader reader, Span<byte> buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = reader.Read(buffer.Slice(total));
            if (read == 0)
                throw new EndOfStreamException();
            total += read;
        }
    }

    private static bool TryReadValue(ref SpanReader reader, Type type, int depth, out object? value)
    {
        try
        {
            value = ReadValue(ref reader, type, null, depth);
            return true;
        }
        catch (EndOfStreamException)
        {
            value = GetDefaultValue(type);
            return false;
        }
    }

    private static uint Fnv1a(uint hash, string value)
    {
        for (int i = 0; i < value.Length; i++)
        {
            hash ^= value[i];
            hash *= 16777619;
        }

        return hash;
    }

    private static void ValidateSchema(Type type, SchemaDefinition schema, SchemaReadMode mode)
    {
        var cacheKey = new SchemaCacheKey(type, schema.Version, schema.Hash, mode);
        if (SchemaValidationCache.ContainsKey(cacheKey))
            return;

        var shape = GetTypeShape(type);
        var expectedHash = shape.SignatureHash;
        if (schema.Hash != expectedHash)
        {
            if (mode == SchemaReadMode.Strict)
                throw new InvalidOperationException($"Schema hash mismatch for {type.Name}. Expected {expectedHash}, schema has {schema.Hash}.");
        }

        var memberMap = shape.MemberMap;
        foreach (var signature in schema.Members)
        {
            if (!memberMap.TryGetValue(signature.Name, out var member))
            {
                if (mode == SchemaReadMode.Strict)
                    throw new InvalidOperationException($"Schema member '{signature.Name}' not found on {type.Name}.");
                continue;
            }

            if (member.MemberType != signature.Type)
            {
                if (mode == SchemaReadMode.Strict)
                    throw new InvalidOperationException($"Schema member '{signature.Name}' type mismatch. Expected {member.MemberType.Name}, schema has {signature.Type.Name}.");
            }

            // Blittable validation disabled.
        }

        SchemaValidationCache.TryAdd(cacheKey, 0);
    }

    private static readonly Dictionary<string, MemberAccessor> EmptyMemberMap =
        new Dictionary<string, MemberAccessor>(0, StringComparer.Ordinal);

    private static void InitializeMemberMetadata(TypeShape shape, Type type)
    {
        var members = BuildMemberAccessors(type);
        shape.Members = members;
        if (members.Length == 0)
        {
            shape.MemberMap = EmptyMemberMap;
            shape.MemberSignatures = Array.Empty<MemberSignature>();
            shape.SignatureHash = 2166136261;
            return;
        }

        var map = new Dictionary<string, MemberAccessor>(members.Length, StringComparer.Ordinal);
        var signatures = new MemberSignature[members.Length];
        for (int i = 0; i < members.Length; i++)
        {
            var member = members[i];
            map[member.Name] = member;
            signatures[i] = new MemberSignature(member.Name, GetTypeIdentifier(member.MemberType), AssumePublicMembers(member.MemberType), null);
        }

        shape.MemberMap = map;
        shape.MemberSignatures = signatures;
        shape.SignatureHash = GetSignatureHash(signatures);
    }

    private static bool IsBlittable(Type type)
    {
        if (!type.IsValueType || type.IsEnum)
            return false;

        if (Type.GetTypeCode(type) != TypeCode.Object)
            return false;

        if (IsKnownSpecialType(type))
            return false;

        if (!type.IsLayoutSequential && !type.IsExplicitLayout)
            return false;

        return IsBlittableStruct(type, new HashSet<Type>());
    }

    private static bool IsBlittableStruct(Type type, HashSet<Type> visited)
    {
        if (visited.Contains(type))
            return true;

        visited.Add(type);

        if (type.IsPrimitive || type.IsEnum)
            return true;

        if (!type.IsValueType)
            return false;

        if (!type.IsLayoutSequential && !type.IsExplicitLayout)
            return false;

        var fields = type.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
        for (int i = 0; i < fields.Length; i++)
        {
            var fieldType = fields[i].FieldType;
            if (fieldType.IsPointer || fieldType == typeof(IntPtr) || fieldType == typeof(UIntPtr))
                return false;

            if (!fieldType.IsValueType)
                return false;

            if (Type.GetTypeCode(fieldType) != TypeCode.Object)
                continue;

            if (IsKnownSpecialType(fieldType))
                return false;

            if (!IsBlittableStruct(fieldType, visited))
                return false;
        }

        return true;
    }

    private static bool IsKnownSpecialType(Type type)
    {
        return type == typeof(DateTime)
            || type == typeof(DateOnly)
            || type == typeof(TimeOnly)
            || type == typeof(DateTimeOffset)
            || type == typeof(TimeSpan)
            || type == typeof(Half)
            || type == typeof(IntPtr)
            || type == typeof(UIntPtr);
    }

    private static uint GetBlittableSignatureHash(int size)
    {
        var hash = 2166136261u;
        hash = Fnv1a(hash, "blittable:");
        hash = Fnv1a(hash, size.ToString());
        return hash;
    }

    private static void ValidateArchitecture(SchemaDefinition schema, BinaryArchitecture payloadArchitecture)
    {
        if (schema.Architecture == BinaryArchitecture.Unknown || payloadArchitecture == BinaryArchitecture.Unknown)
            return;

        if (schema.Architecture != payloadArchitecture)
            throw new InvalidOperationException($"Schema architecture {schema.Architecture} does not match payload architecture {payloadArchitecture}.");

        var current = BinaryArchitectureMapper.Current;
        if (current != BinaryArchitecture.Unknown && payloadArchitecture != current)
            throw new InvalidOperationException($"Payload architecture {payloadArchitecture} does not match current architecture {current}.");
    }

    private static int GetBlittableSize(Type type)
    {
        if (!IsBlittable(type))
            throw new NotSupportedException($"Type '{type.FullName}' is not blittable.");

        var sizeMethod = BlittableSizeMethod.MakeGenericMethod(type);
        return (int)sizeMethod.Invoke(null, null)!;
    }

    private static Action<object?, byte[]> CreateBlittableWrite(Type type)
    {
        if (!IsBlittable(type))
            throw new NotSupportedException($"Type '{type.FullName}' is not blittable.");

        var method = BlittableWriteMethod.MakeGenericMethod(type);
        return (Action<object?, byte[]>)method.CreateDelegate(typeof(Action<object?, byte[]>));
    }

    private static Func<byte[], object> CreateBlittableRead(Type type)
    {
        if (!IsBlittable(type))
            throw new NotSupportedException($"Type '{type.FullName}' is not blittable.");

        var method = BlittableReadMethod.MakeGenericMethod(type);
        return (Func<byte[], object>)method.CreateDelegate(typeof(Func<byte[], object>));
    }

    private static int GetBlittableSizeCore<T>() where T : unmanaged
    {
        return Unsafe.SizeOf<T>();
    }

    private static void BlittableWriteCore<T>(object? value, byte[] buffer) where T : unmanaged
    {
        if (buffer is null) throw new ArgumentNullException(nameof(buffer));
        var size = Unsafe.SizeOf<T>();
        if (buffer.Length < size)
            throw new ArgumentException("Blittable buffer is too small.", nameof(buffer));

        var span = buffer.AsSpan(0, size);
        if (value is null)
        {
            span.Clear();
            return;
        }

        var typed = (T)value;
        MemoryMarshal.Write(span, in typed);
    }

    private static object BlittableReadCore<T>(byte[] buffer) where T : unmanaged
    {
        if (buffer is null) throw new ArgumentNullException(nameof(buffer));
        var size = Unsafe.SizeOf<T>();
        if (buffer.Length < size)
            throw new ArgumentException("Blittable buffer is too small.", nameof(buffer));

        return MemoryMarshal.Read<T>(buffer.AsSpan(0, size));
    }

    private static byte[] LoadOrCreateSigningKey(string keyFilePath)
    {
        if (string.IsNullOrWhiteSpace(keyFilePath))
            throw new ArgumentException("Key file path cannot be null or whitespace.", nameof(keyFilePath));

        var directory = Path.GetDirectoryName(keyFilePath);
        if (!string.IsNullOrWhiteSpace(directory))
            Directory.CreateDirectory(directory);

        if (File.Exists(keyFilePath))
            return LoadSigningKey(keyFilePath);

        var key = RandomNumberGenerator.GetBytes(SignatureSize);
        File.WriteAllText(keyFilePath, Convert.ToBase64String(key));
        return key;
    }

    private static byte[] LoadSigningKey(string keyFilePath)
    {
        var base64 = File.ReadAllText(keyFilePath).Trim();
        var key = Convert.FromBase64String(base64);
        if (key.Length != SignatureSize)
            throw new InvalidOperationException($"Signing key must be {SignatureSize} bytes.");
        return key;
    }

    private byte[] SerializeSigned<T>(T obj, int schemaVersion)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Utf8, leaveOpen: true);
        WriteHeader(writer, schemaVersion);
        WriteValue(writer, typeof(T), obj, 0);
        writer.Flush();

        var length = (int)stream.Length;
        var buffer = stream.GetBuffer();
        if (length < HeaderSizeV3)
            throw new InvalidOperationException("Signed payload is too short.");

        var signature = ComputeSignature(buffer.AsSpan(0, length));
        signature.CopyTo(buffer.AsSpan(HeaderFieldsSizeV3, SignatureSize));

        var result = new byte[length];
        Buffer.BlockCopy(buffer, 0, result, 0, length);
        return result;
    }

    private void ValidateSignature(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < HeaderFieldsSizeV2)
            throw new InvalidOperationException("Payload is too short.");

        var magic = BinaryPrimitives.ReadInt32LittleEndian(payload.Slice(0, 4));
        if (magic != Magic)
            throw new InvalidOperationException("Invalid binary payload magic.");

        var version = BinaryPrimitives.ReadInt32LittleEndian(payload.Slice(4, 4));
        if (version > CurrentVersion)
            throw new InvalidOperationException($"Unsupported binary payload version {version}.");

        if (version < 3)
            throw new InvalidOperationException("Unsigned payloads are not supported.");

        if (payload.Length < HeaderSizeV3)
            throw new InvalidOperationException("Payload is too short for signed header.");

        var expected = ComputeSignature(payload);
        var actual = payload.Slice(HeaderFieldsSizeV3, SignatureSize);
        if (!CryptographicOperations.FixedTimeEquals(expected, actual))
            throw new InvalidOperationException("Payload signature mismatch.");
    }

    private byte[] ComputeSignature(ReadOnlySpan<byte> payload)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _signingKey);
        hmac.AppendData(payload.Slice(0, HeaderFieldsSizeV3));
        hmac.AppendData(payload.Slice(HeaderFieldsSizeV3 + SignatureSize));
        return hmac.GetHashAndReset();
    }

    private static MemberAccessor[] BuildMemberAccessors(Type type)
    {
        var properties = type.GetProperties(BindingFlags.Instance | BindingFlags.Public);
        var fields = type.GetFields(BindingFlags.Instance | BindingFlags.Public);
        var list = new List<MemberAccessor>(properties.Length + fields.Length);

        for (int i = 0; i < properties.Length; i++)
        {
            var property = properties[i];
            if (property.GetIndexParameters().Length != 0 || !property.CanRead || !property.CanWrite)
                continue;
            list.Add(CreateMemberAccessor(property));
        }

        for (int i = 0; i < fields.Length; i++)
            list.Add(CreateMemberAccessor(fields[i]));

        list.Sort(static (a, b) => StringComparer.Ordinal.Compare(a.Name, b.Name));
        return list.ToArray();
    }
}


