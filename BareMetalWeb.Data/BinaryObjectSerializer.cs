using System.Buffers;
using System.Buffers.Binary;
using System.Collections;
using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.IO.Hashing;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using BareMetalWeb.Core;
using BareMetalWeb.Data.Interfaces;
namespace BareMetalWeb.Data;

// • Schema must be supplied on read
// • Schema version is authoritative
// • No polymorphism
// • No reference tracking
// • Members are name-sorted
// • Public fields + properties only
// • Binary is little-endian
// • Hash is XxHash64 over member signatures (hardware-accelerated on x86 SSE/AES and ARM NEON)

public sealed class BinaryObjectSerializer : ISchemaAwareObjectSerializer
{
    private static readonly ConcurrentDictionary<Type, TypeShape> TypeCache = new();
    private static readonly ConcurrentDictionary<SchemaCacheKey, byte> SchemaValidationCache = new();
    // Maps (Type, schema-hash) → pre-built ordinal array so schema-based deserialization
    // uses array indexing instead of a per-field dictionary lookup.
    private static readonly ConcurrentDictionary<(Type Type, uint SchemaHash), MemberAccessor?[]> SchemaOrdinalCache = new();
    private static readonly ConcurrentDictionary<Type, Func<object>> InstanceFactory = new();
    // Explicit member accessors for non-entity types (registered at startup, zero reflection).
    private static readonly ConcurrentDictionary<Type, MemberAccessor[]> ExplicitMemberCache = new();
    private static readonly Encoding Utf8 = Encoding.UTF8;

    static BinaryObjectSerializer()
    {
        // Register IdentifierValue (readonly struct) as a known type.
        // Serialization/deserialization is handled inline as two ulongs.
        InstanceFactory.TryAdd(typeof(IdentifierValue), () => default(IdentifierValue));
    }

    // Base property accessors for BaseDataObject — ordinal-indexed, zero reflection.
    private static readonly MemberAccessor[] BasePropertyAccessors = new[]
    {
        new MemberAccessor("CreatedBy",    typeof(string),          obj => ((BaseDataObject)obj).GetFieldValue(BaseDataObject.Ord_CreatedBy),    (obj, val) => ((BaseDataObject)obj).SetFieldValue(BaseDataObject.Ord_CreatedBy, val)),
        new MemberAccessor("CreatedOnUtc", typeof(DateTime),        obj => ((BaseDataObject)obj).GetFieldValue(BaseDataObject.Ord_CreatedOnUtc), (obj, val) => ((BaseDataObject)obj).SetFieldValue(BaseDataObject.Ord_CreatedOnUtc, val)),
        new MemberAccessor("ETag",         typeof(string),          obj => ((BaseDataObject)obj).GetFieldValue(BaseDataObject.Ord_ETag),         (obj, val) => ((BaseDataObject)obj).SetFieldValue(BaseDataObject.Ord_ETag, val)),
        new MemberAccessor("Identifier",   typeof(IdentifierValue), obj => ((BaseDataObject)obj).GetFieldValue(BaseDataObject.Ord_Identifier),  (obj, val) => ((BaseDataObject)obj).SetFieldValue(BaseDataObject.Ord_Identifier, val)),
        new MemberAccessor("Key",          typeof(uint),            obj => ((BaseDataObject)obj).GetFieldValue(BaseDataObject.Ord_Key),          (obj, val) => ((BaseDataObject)obj).SetFieldValue(BaseDataObject.Ord_Key, val)),
        new MemberAccessor("UpdatedBy",    typeof(string),          obj => ((BaseDataObject)obj).GetFieldValue(BaseDataObject.Ord_UpdatedBy),    (obj, val) => ((BaseDataObject)obj).SetFieldValue(BaseDataObject.Ord_UpdatedBy, val)),
        new MemberAccessor("UpdatedOnUtc", typeof(DateTime),        obj => ((BaseDataObject)obj).GetFieldValue(BaseDataObject.Ord_UpdatedOnUtc), (obj, val) => ((BaseDataObject)obj).SetFieldValue(BaseDataObject.Ord_UpdatedOnUtc, val)),
        new MemberAccessor("Version",      typeof(uint),            obj => ((BaseDataObject)obj).GetFieldValue(BaseDataObject.Ord_Version),      (obj, val) => ((BaseDataObject)obj).SetFieldValue(BaseDataObject.Ord_Version, val)),
    };
    private const int Magic = 0x314F5342; // "BSO1" in little-endian
    private const int CurrentVersion = 3;
    private const int MaxDepth = 32;
    private const int MaxStringBytes = 4 * 1024 * 1024; // 4 MiB
    private const int MaxCollectionLength = 100_000;
    private const int MaxDictionaryEntries = 1_000_000;

    private const int SignatureSize = 32;
    private const int HeaderFieldsSizeV2 = 4 + 4 + 4 + 1;
    private const int HeaderFieldsSizeV3 = 4 + 4 + 4 + 1;
    private const int HeaderSizeV3 = HeaderFieldsSizeV3 + SignatureSize;
    private static readonly byte[] SignaturePlaceholder = new byte[SignatureSize];
    private static readonly string DefaultSigningKeyPath = Path.Combine(AppContext.BaseDirectory, ".keys", "binary-serializer.key");
    // XxHash64 of an empty byte sequence, folded to 32 bits.  Used as the canonical
    // schema hash for types that expose no serialisable members (primitives, empty objects).
    private static readonly uint EmptySchemaHash = GetSignatureHash(Array.Empty<MemberSignature>());

    private readonly byte[] _signingKey;

    /// <summary>Returns a copy of the signing key.</summary>
    public byte[] GetSigningKeyCopy() => (byte[])_signingKey.Clone();

    // Cached field plans per CLR type — built once, reused forever (FieldPlan-based serialization)
    private static readonly ConcurrentDictionary<Type, FieldPlan[]> PlanCache = new();

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
        return Deserialize<T>(data.AsSpan());
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
        return Deserialize<T>(data.AsSpan(), schema);
    }

    public T? Deserialize<T>(ReadOnlySpan<byte> data, SchemaDefinition schema)
    {
        return Deserialize<T>(data, schema, SchemaReadMode.Strict);
    }

    public T? Deserialize<T>(byte[] data, SchemaDefinition schema, SchemaReadMode mode)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return Deserialize<T>(data.AsSpan(), schema, mode);
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
        return ReadSchemaVersion(data.AsSpan());
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
        var materializedList = new List<MemberSignature>();
        foreach (var m in members)
            materializedList.Add(m);
        var materialized = materializedList.ToArray();
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
                    ? EnumHelper.GetZeroUnderlying(shape.EnumUnderlyingTypeCode)
                    : EnumHelper.ToUnderlyingValue(value, shape.EnumUnderlyingTypeCode);
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
                throw new NotSupportedException($"Blittable struct serialization has been removed. Type: {type.Name}");
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
            case TypeKind.IdentifierValue:
            {
                var id = (IdentifierValue)(value ?? default(IdentifierValue));
                writer.Write(id.Hi);
                writer.Write(id.Lo);
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
                    ? EnumHelper.GetZeroUnderlying(shape.EnumUnderlyingTypeCode)
                    : EnumHelper.ToUnderlyingValue(value, shape.EnumUnderlyingTypeCode);
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
                throw new NotSupportedException($"Blittable struct serialization has been removed. Type: {type.Name}");
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
            case TypeKind.IdentifierValue:
            {
                var id = (IdentifierValue)(value ?? default(IdentifierValue));
                writer.WriteUInt64(id.Hi);
                writer.WriteUInt64(id.Lo);
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
                return rawValue == null
                    ? EnumHelper.FromLong(type, 0L)
                    : EnumHelper.FromLong(type, ((IConvertible)rawValue).ToInt64(null));
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
                throw new NotSupportedException($"Blittable struct serialization has been removed. Type: {type.Name}");
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
            case TypeKind.IdentifierValue:
            {
                var hi = reader.ReadUInt64();
                var lo = reader.ReadUInt64();
                return new IdentifierValue(hi, lo);
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
                    var ordinals = GetOrBuildSchemaOrdinals(type, schema);
                    for (int i = 0; i < schema.Members.Length; i++)
                    {
                        var signatureType = AssumePublicMembers(schema.Members[i].Type);
                        if (!TryReadValue(reader, signatureType, depth + 1, out var memberValue))
                            break;

                        var member = ordinals[i];
                        if (member != null)
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
                return rawValue == null
                    ? EnumHelper.FromLong(type, 0L)
                    : EnumHelper.FromLong(type, ((IConvertible)rawValue).ToInt64(null));
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
                throw new NotSupportedException($"Blittable struct serialization has been removed. Type: {type.Name}");
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
            case TypeKind.IdentifierValue:
            {
                var hi = reader.ReadUInt64();
                var lo = reader.ReadUInt64();
                return new IdentifierValue(hi, lo);
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
                    var ordinals = GetOrBuildSchemaOrdinals(type, schema);
                    for (int i = 0; i < schema.Members.Length; i++)
                    {
                        var signatureType = AssumePublicMembers(schema.Members[i].Type);
                        if (!TryReadValue(ref reader, signatureType, depth + 1, out var memberValue))
                            break;
                        if (reader.Remaining < 0)
                            throw new System.IO.InvalidDataException("Field read overran buffer boundary");

                        var member = ordinals[i];
                        if (member != null)
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
                        if (reader.Remaining < 0)
                            throw new System.IO.InvalidDataException("Field read overran buffer boundary");

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

        // Guard against corrupted length that exceeds remaining stream data
        var remaining = reader.BaseStream.Length - reader.BaseStream.Position;
        if (length > remaining)
            throw new InvalidOperationException($"String byte length {length} exceeds remaining payload ({remaining} bytes). Data may be corrupt.");

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

        if (length > reader.Remaining)
            throw new InvalidOperationException($"String byte length {length} exceeds remaining payload ({reader.Remaining} bytes). Data may be corrupt.");

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

    private static uint GetSignatureHash(MemberSignature[] members)
    {
        // XxHash64 is hardware-accelerated on x86 (via AESNI/SSE4) and ARM (via NEON),
        // giving ~10× throughput over the old character-at-a-time FNV-1a path.
        // We fold the 64-bit digest to 32 bits by XOR-folding the two halves, preserving
        // the full avalanche quality of XxHash for structural-change detection.
        var hasher = new XxHash64();
        foreach (var member in members)
        {
            AppendUtf8(ref hasher, member.Name);
            hasher.Append(":"u8);
            AppendUtf8(ref hasher, member.TypeName);
            hasher.Append(";"u8);
        }
        ulong h64 = hasher.GetCurrentHashAsUInt64();
        return (uint)(h64 ^ (h64 >> 32));
    }

    /// <summary>
    /// Encodes <paramref name="value"/> as UTF-8 and appends it to <paramref name="hasher"/>
    /// without a heap allocation for strings that fit in a 768-byte stack buffer
    /// (≤ 256 UTF-16 code units, which covers virtually all member and type names).
    /// Long strings fall back to a single heap allocation.
    /// </summary>
    [System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.AggressiveInlining)]
    private static void AppendUtf8(ref XxHash64 hasher, string value)
    {
        if (value.Length <= 256)
        {
            Span<byte> buf = stackalloc byte[value.Length * 3]; // worst-case UTF-8 expansion
            int written = Utf8.GetBytes(value, buf);
            hasher.Append(buf[..written]);
        }
        else
        {
            hasher.Append(Utf8.GetBytes(value)); // heap fallback for pathologically long names
        }
    }

    private static string GetTypeIdentifier(Type type)
        => type.AssemblyQualifiedName ?? type.FullName ?? type.Name;

    // Pre-registered known types for AOT-safe type resolution (no assembly scanning).
    private static readonly ConcurrentDictionary<string, Type> KnownTypes = InitKnownTypes();

    private static ConcurrentDictionary<string, Type> InitKnownTypes()
    {
        var dict = new ConcurrentDictionary<string, Type>(StringComparer.Ordinal);
        // Pre-register BCL primitive/common types so schema deserialization can resolve
        // type names from stored schema files without Type.GetType() reflection.
        ReadOnlySpan<Type> builtins = new[]
        {
            typeof(string), typeof(int), typeof(uint), typeof(long), typeof(ulong),
            typeof(short), typeof(ushort), typeof(byte), typeof(sbyte),
            typeof(bool), typeof(float), typeof(double), typeof(decimal),
            typeof(DateTime), typeof(Guid), typeof(char),
            typeof(List<string>), typeof(List<int>), typeof(List<decimal>),
            typeof(Dictionary<string, string>), typeof(Dictionary<string, object>),
            typeof(IdentifierValue), typeof(DataRecord),
        };
        foreach (var t in builtins)
        {
            dict[t.AssemblyQualifiedName ?? t.FullName ?? t.Name] = t;
            if (t.FullName != null) dict[t.FullName] = t;
            dict[t.Name] = t;
        }
        return dict;
    }

    /// <summary>
    /// Registers a type so it can be resolved by name during deserialization without assembly scanning.
    /// Call at startup for every type that may appear in serialized binary data.
    /// Throws if a short name is already registered with a different type to prevent type confusion (see #1222).
    /// </summary>
    public static void RegisterKnownType<[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] T>() where T : new()
    {
        var t = typeof(T);
        RegisterKnownTypeCore(t);
        InstanceFactory.TryAdd(t, static () => new T());
    }

    /// <summary>
    /// Registers a type by runtime <see cref="Type"/> reference.
    /// Throws if a short name is already registered with a different type to prevent type confusion (see #1222).
    /// </summary>
    public static void RegisterKnownType([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] Type t)
    {
        RegisterKnownTypeCore(t);
    }

    /// <summary>Registers a type with an explicit factory (AOT-safe, no Activator.CreateInstance).</summary>
    public static void RegisterKnownType(Type t, Func<object> factory)
    {
        RegisterKnownTypeCore(t);
        InstanceFactory.TryAdd(t, factory);
    }

    /// <summary>Registers a non-entity type with explicit member accessors and factory. Fully AOT-safe, zero reflection.</summary>
    public static void RegisterKnownType(Type t, Func<object> factory, MemberAccessor[] members)
    {
        RegisterKnownTypeCore(t);
        InstanceFactory.TryAdd(t, factory);
        Array.Sort(members, static (a, b) => StringComparer.Ordinal.Compare(a.Name, b.Name));
        ExplicitMemberCache.TryAdd(t, members);
    }

    private static void RegisterKnownTypeCore(Type t)
    {
        KnownTypes[t.AssemblyQualifiedName ?? t.FullName ?? t.Name] = t;
        if (t.FullName != null) KnownTypes[t.FullName] = t;

        // SECURITY: Detect short-name collisions to prevent type confusion attacks (see #1222)
        if (KnownTypes.TryGetValue(t.Name, out var existing) && existing != t)
            throw new InvalidOperationException(
                $"KnownType short-name collision: '{t.Name}' is already registered as '{existing.FullName}', cannot register '{t.FullName}'.");
        KnownTypes[t.Name] = t;
    }

    // Type resolution uses pre-registered KnownTypes map only (O(1), AOT-safe, zero reflection).
    private static Type ResolveType(string typeName)
    {
        if (KnownTypes.TryGetValue(typeName, out var known))
            return known;

        throw new InvalidOperationException($"Unable to resolve type '{typeName}'. Register it with BinaryObjectSerializer.RegisterKnownType<T>() at startup.");
    }

    private static Type AssumePublicMembers(Type type)
        => type;

    private static object CreateInstance(Type type)
    {
        if (type.IsEnum)
            return EnumHelper.FromLong(type, 0L);

        if (type == typeof(DataRecord))
            return new DataRecord();

        if (InstanceFactory.TryGetValue(type, out var factory))
            return factory();

        if (type.IsValueType)
        {
            if (type == typeof(int)) return 0;
            if (type == typeof(uint)) return 0u;
            if (type == typeof(long)) return 0L;
            if (type == typeof(decimal)) return 0m;
            if (type == typeof(double)) return 0.0;
            if (type == typeof(float)) return 0f;
            if (type == typeof(bool)) return false;
            if (type == typeof(DateTime)) return default(DateTime);
            if (type == typeof(Guid)) return Guid.Empty;
            if (type == typeof(IdentifierValue)) return default(IdentifierValue);

            throw new InvalidOperationException(
                $"No default factory for value type '{type.FullName}'. Add it to the known-type list or register it at startup.");
        }

        // Entity types must be registered — metadata system knows all persistable types
        var meta = DataScaffold.GetEntityByType(type);
        if (meta != null)
            return meta.Handlers.Create();

        throw new InvalidOperationException(
            $"No factory registered for type '{type.FullName}'. Register it with BinaryObjectSerializer.RegisterKnownType<T>() at startup.");
    }

    private static void TryAssignValue(object instance, MemberAccessor member, object? value)
    {
        if (value is null)
        {
            if (!member.MemberType.IsValueType)
                member.Setter(instance, null);
            return;
        }

        if (member.MemberType.IsInstanceOfType(value))
        {
            member.Setter(instance, value);
            return;
        }

        if (value is IConvertible ic)
        {
            try
            {
                var memberType = Nullable.GetUnderlyingType(member.MemberType) ?? member.MemberType;
                object converted = memberType.IsEnum
                    ? EnumHelper.FromLong(memberType, ic.ToInt64(null))
                    : ConvertPrimitive(ic, Type.GetTypeCode(memberType));
                member.Setter(instance, converted);
                return;
            }
            catch
            {
            }
        }
    }

    private static object ConvertPrimitive(IConvertible ic, TypeCode code) => code switch
    {
        TypeCode.Int32   => ic.ToInt32(null),
        TypeCode.Int64   => ic.ToInt64(null),
        TypeCode.Double  => ic.ToDouble(null),
        TypeCode.Single  => ic.ToSingle(null),
        TypeCode.Decimal => ic.ToDecimal(null),
        TypeCode.Boolean => ic.ToBoolean(null),
        TypeCode.String  => ic.ToString(null),
        TypeCode.Byte    => ic.ToByte(null),
        TypeCode.SByte   => ic.ToSByte(null),
        TypeCode.Int16   => ic.ToInt16(null),
        TypeCode.UInt16  => ic.ToUInt16(null),
        TypeCode.UInt32  => ic.ToUInt32(null),
        TypeCode.UInt64  => ic.ToUInt64(null),
        TypeCode.DateTime => ic.ToDateTime(null),
        TypeCode.Char    => ic.ToChar(null),
        _                => ic.ToInt32(null),
    };

    /// <summary>
    /// Returns a pre-built ordinal array that maps each index in <paramref name="schema"/>.Members
    /// to the corresponding <see cref="MemberAccessor"/> for <paramref name="type"/>, or
    /// <c>null</c> when the member is absent from the current type shape (schema evolution).
    /// The array is cached so subsequent deserializations skip the dictionary lookup.
    /// </summary>
    private static MemberAccessor?[] GetOrBuildSchemaOrdinals(Type type, SchemaDefinition schema)
    {
        return SchemaOrdinalCache.GetOrAdd((type, schema.Hash), key =>
        {
            var memberMap = GetTypeShape(key.Type).MemberMap;
            var ordinals = new MemberAccessor?[schema.Members.Length];
            for (int i = 0; i < schema.Members.Length; i++)
                memberMap.TryGetValue(schema.Members[i].Name, out ordinals[i]);
            return ordinals;
        });
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

        // AOT-safe default values for known value types.
        if (type == typeof(int)) return 0;
        if (type == typeof(uint)) return 0u;
        if (type == typeof(long)) return 0L;
        if (type == typeof(ulong)) return 0UL;
        if (type == typeof(short)) return (short)0;
        if (type == typeof(ushort)) return (ushort)0;
        if (type == typeof(byte)) return (byte)0;
        if (type == typeof(sbyte)) return (sbyte)0;
        if (type == typeof(decimal)) return 0m;
        if (type == typeof(double)) return 0.0;
        if (type == typeof(float)) return 0f;
        if (type == typeof(bool)) return false;
        if (type == typeof(char)) return '\0';
        if (type == typeof(DateTime)) return default(DateTime);
        if (type == typeof(DateTimeOffset)) return default(DateTimeOffset);
        if (type == typeof(DateOnly)) return default(DateOnly);
        if (type == typeof(TimeOnly)) return default(TimeOnly);
        if (type == typeof(TimeSpan)) return TimeSpan.Zero;
        if (type == typeof(Guid)) return Guid.Empty;
        if (type == typeof(Half)) return default(Half);
        if (type == typeof(IntPtr)) return IntPtr.Zero;
        if (type == typeof(UIntPtr)) return UIntPtr.Zero;

        throw new InvalidOperationException(
            $"No default value known for type '{type.FullName}'. Add it to the known-type list in CreateDefaultInstance.");
    }

    private static TypeShape GetTypeShape(Type type)
    {
        return TypeCache.GetOrAdd(type, CreateTypeShape);
    }

    private static TypeShape CreateTypeShape([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)] Type type)
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
            var underlying = AssumePublicMembers(Enum.GetUnderlyingType(type));
            shape.EnumUnderlying = underlying;
            shape.EnumUnderlyingTypeCode = Type.GetTypeCode(underlying);
            return shape;
        }

        if (type == typeof(Guid))
        {
            shape.Kind = TypeKind.Guid;
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

        if (type == typeof(IdentifierValue))
        {
            shape.Kind = TypeKind.IdentifierValue;
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
            var listType = type;
            // Capture the annotated 'listType' local so the trimmer tracks the
            // [DynamicallyAccessedMembers(PublicParameterlessConstructor)] annotation.
            var listFactory = InstanceFactory.GetOrAdd(listType, _ => { var t = listType; return () => Activator.CreateInstance(t)!; });
            shape.ListFactory = _ => (System.Collections.IList)listFactory();
            return shape;
        }

        if (IsDictionary(type, out var keyType, out var valueType))
        {
            shape.Kind = TypeKind.Dictionary;
            shape.KeyType = AssumePublicMembers(keyType);
            shape.ValueType = AssumePublicMembers(valueType);
            var dictType = type;
            // Capture the annotated 'dictType' local so the trimmer tracks the
            // [DynamicallyAccessedMembers(PublicParameterlessConstructor)] annotation.
            var dictFactory = InstanceFactory.GetOrAdd(dictType, _ => { var t = dictType; return () => Activator.CreateInstance(t)!; });
            shape.DictionaryFactory = _ => (System.Collections.IDictionary)dictFactory();
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
            shape.SignatureHash = EmptySchemaHash;
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
            shape.SignatureHash = EmptySchemaHash;
            return;
        }

        var map = new Dictionary<string, MemberAccessor>(members.Length, StringComparer.Ordinal);
        var signatures = new MemberSignature[members.Length];
        for (int i = 0; i < members.Length; i++)
        {
            var member = members[i];
            map[member.Name] = member;
            signatures[i] = new MemberSignature(member.Name, GetTypeIdentifier(member.MemberType), AssumePublicMembers(member.MemberType));
        }

        shape.MemberMap = map;
        shape.MemberSignatures = signatures;
        shape.SignatureHash = GetSignatureHash(signatures);
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
        // Entity types: use ordinal-indexed DataScaffold metadata (zero reflection)
        var meta = DataScaffold.GetEntityByType(type);
        if (meta != null)
        {
            // Build accessors from metadata fields + base properties — no PropertyInfo, no reflection.
            var list = new List<MemberAccessor>(meta.Fields.Count + BasePropertyAccessors.Length);

            // Base properties (Key, Identifier, CreatedOnUtc, etc.) — static ordinal accessors
            for (int i = 0; i < BasePropertyAccessors.Length; i++)
                list.Add(BasePropertyAccessors[i]);

            // Entity-specific DataField properties — ordinal-indexed via metadata
            foreach (var fieldMeta in meta.Fields)
            {
                if (fieldMeta.StorageOrdinal < 0)
                    continue;
                list.Add(new MemberAccessor(fieldMeta.Name, fieldMeta.ClrType,
                    fieldMeta.GetValueFn, fieldMeta.SetValueFn));
            }

            list.Sort(static (a, b) => StringComparer.Ordinal.Compare(a.Name, b.Name));
            return list.ToArray();
        }

        // Non-entity types with explicit member registration (zero reflection)
        if (ExplicitMemberCache.TryGetValue(type, out var explicitMembers))
            return explicitMembers;

        throw new InvalidOperationException(
            $"Type '{type.FullName}' is not a registered entity. Register it with DataScaffold or BinaryObjectSerializer.RegisterKnownType with explicit members.");
    }

    // ════════════════════════════════════════════════════════════════════════
    //  FieldPlan-based metadata-driven serialization (additive mode)
    //  Moved from MetadataWireSerializer — shares BSO1 envelope, signing key,
    //  and string encoding with the generic T-based mode above.
    // ════════════════════════════════════════════════════════════════════════

    private const int FieldPlanMaxDepth = 64;
    private const int FieldPlanMaxCollectionLength = 1_000_000;

    /// <summary>
    /// Precompiled per-field serialization plan. Built once from metadata,
    /// stored in ordinal-sorted array. No reflection at runtime.
    /// </summary>
    public sealed class FieldPlan
    {
        public required string Name { get; init; }
        public required int Ordinal { get; init; }
        public required WireFieldType WireType { get; init; }
        public required bool IsNullable { get; init; }
        public required Func<object, object?> Getter { get; init; }
        public required Action<object, object?> Setter { get; init; }
        // For enum fields: the underlying wire type (Int32, Byte, etc.)
        public WireFieldType EnumUnderlying { get; init; }
        // For collection fields: element wire type
        public WireFieldType ElementWireType { get; init; }
        // CLR type for object creation during deserialization
        public required Type ClrType { get; init; }
    }

    /// <summary>
    /// Compact field type enum for wire format. Avoids System.TypeCode dependency
    /// and maps directly to binary read/write operations.
    /// </summary>
    public enum WireFieldType : byte
    {
        Bool = 1,
        Byte = 2,
        SByte = 3,
        Int16 = 4,
        UInt16 = 5,
        Int32 = 6,
        UInt32 = 7,
        Int64 = 8,
        UInt64 = 9,
        Float32 = 10,
        Float64 = 11,
        Decimal = 12,
        Char = 13,
        String = 20,
        Guid = 21,
        DateTime = 22,
        DateOnly = 23,
        TimeOnly = 24,
        DateTimeOffset = 25,
        TimeSpan = 26,
        Enum = 30,
        Identifier = 40, // IdentifierValue — 16 bytes (hi LE, lo LE)
        Object = 50,
    }

    /// <summary>
    /// Descriptor passed in from the metadata layer to build a FieldPlan.
    /// The metadata layer resolves CLR PropertyInfo → WireFieldType once.
    /// </summary>
    public sealed class FieldPlanDescriptor
    {
        public required string Name { get; init; }
        public required WireFieldType WireType { get; init; }
        public required bool IsNullable { get; init; }
        public required Func<object, object?> Getter { get; init; }
        public required Action<object, object?> Setter { get; init; }
        public required Type ClrType { get; init; }
        public WireFieldType EnumUnderlying { get; init; }
        public WireFieldType ElementWireType { get; init; }
    }

    public sealed class WireSchemaDescriptor
    {
        public required string Slug { get; init; }
        public required int Version { get; init; }
        public required WireMemberDescriptor[] Members { get; init; }
    }

    public sealed class WireMemberDescriptor
    {
        public required string Name { get; init; }
        public required int Ordinal { get; init; }
        public required string WireType { get; init; }
        public required bool IsNullable { get; init; }
        public string? EnumUnderlying { get; init; }
    }

    // ────────────── Plan building ──────────────

    /// <summary>
    /// Builds a FieldPlan[] from entity metadata. Call once at startup per type.
    /// Plans are sorted by field name (ordinal) to match BinaryObjectSerializer member order.
    /// </summary>
    public static FieldPlan[] BuildPlan(Type entityType, IReadOnlyList<FieldPlanDescriptor> fields)
    {
        return PlanCache.GetOrAdd(entityType, _ => BuildPlanCore(fields));
    }

    /// <summary>
    /// Builds a FieldPlan[] without caching. Used when the cache key (Type) is shared
    /// across multiple schemas (e.g. all DataRecord entities share typeof(DataRecord)).
    /// </summary>
    public static FieldPlan[] BuildPlanUncached(IReadOnlyList<FieldPlanDescriptor> fields)
        => BuildPlanCore(fields);

    private static FieldPlan[] BuildPlanCore(IReadOnlyList<FieldPlanDescriptor> fields)
    {
        var plans = new FieldPlan[fields.Count];
        for (int i = 0; i < fields.Count; i++)
        {
            var f = fields[i];
            plans[i] = new FieldPlan
            {
                Name = f.Name,
                Ordinal = i,
                WireType = f.WireType,
                IsNullable = f.IsNullable,
                Getter = f.Getter,
                Setter = f.Setter,
                EnumUnderlying = f.EnumUnderlying,
                ElementWireType = f.ElementWireType,
                ClrType = f.ClrType,
            };
        }
        return plans;
    }

    /// <summary>
    /// Resolves a CLR property type to a WireFieldType. Called once per field at plan-build time.
    /// </summary>
    public static (WireFieldType wireType, bool isNullable, WireFieldType enumUnderlying) ResolveWireType(Type propertyType)
    {
        var nullable = Nullable.GetUnderlyingType(propertyType);
        var isNullable = nullable != null || !propertyType.IsValueType;
        var effective = nullable ?? propertyType;

        if (effective.IsEnum)
        {
            var underlying = Enum.GetUnderlyingType(effective);
            return (WireFieldType.Enum, isNullable, MapPrimitiveWireType(underlying));
        }

        if (effective == typeof(string)) return (WireFieldType.String, true, default);
        if (effective == typeof(bool)) return (WireFieldType.Bool, isNullable, default);
        if (effective == typeof(byte)) return (WireFieldType.Byte, isNullable, default);
        if (effective == typeof(sbyte)) return (WireFieldType.SByte, isNullable, default);
        if (effective == typeof(short)) return (WireFieldType.Int16, isNullable, default);
        if (effective == typeof(ushort)) return (WireFieldType.UInt16, isNullable, default);
        if (effective == typeof(int)) return (WireFieldType.Int32, isNullable, default);
        if (effective == typeof(uint)) return (WireFieldType.UInt32, isNullable, default);
        if (effective == typeof(long)) return (WireFieldType.Int64, isNullable, default);
        if (effective == typeof(ulong)) return (WireFieldType.UInt64, isNullable, default);
        if (effective == typeof(float)) return (WireFieldType.Float32, isNullable, default);
        if (effective == typeof(double)) return (WireFieldType.Float64, isNullable, default);
        if (effective == typeof(decimal)) return (WireFieldType.Decimal, isNullable, default);
        if (effective == typeof(char)) return (WireFieldType.Char, isNullable, default);
        if (effective == typeof(Guid)) return (WireFieldType.Guid, isNullable, default);
        if (effective == typeof(DateTime)) return (WireFieldType.DateTime, isNullable, default);
        if (effective == typeof(System.DateOnly)) return (WireFieldType.DateOnly, isNullable, default);
        if (effective == typeof(System.TimeOnly)) return (WireFieldType.TimeOnly, isNullable, default);
        if (effective == typeof(DateTimeOffset)) return (WireFieldType.DateTimeOffset, isNullable, default);
        if (effective == typeof(TimeSpan)) return (WireFieldType.TimeSpan, isNullable, default);
        if (effective == typeof(IdentifierValue)) return (WireFieldType.Identifier, isNullable, default);

        return (WireFieldType.Object, isNullable, default);
    }

    private static WireFieldType MapPrimitiveWireType(Type t)
    {
        if (t == typeof(int)) return WireFieldType.Int32;
        if (t == typeof(byte)) return WireFieldType.Byte;
        if (t == typeof(short)) return WireFieldType.Int16;
        if (t == typeof(long)) return WireFieldType.Int64;
        if (t == typeof(uint)) return WireFieldType.UInt32;
        if (t == typeof(ushort)) return WireFieldType.UInt16;
        if (t == typeof(ulong)) return WireFieldType.UInt64;
        if (t == typeof(sbyte)) return WireFieldType.SByte;
        return WireFieldType.Int32;
    }

    // ────────────── FieldPlan serialization (write) ──────────────

    /// <summary>
    /// Serializes an entity to a signed binary payload using the precompiled field plan.
    /// Writes directly to an IBufferWriter — zero intermediate copies.
    /// </summary>
    public int Serialize(object entity, FieldPlan[] plan, int schemaVersion, IBufferWriter<byte> output)
    {
        var data = Serialize(entity, plan, schemaVersion);
        var dest = output.GetSpan(data.Length);
        data.CopyTo(dest);
        output.Advance(data.Length);
        return data.Length;
    }

    /// <summary>
    /// Serializes an entity to a new byte[]. Writes to owned buffer and signs in-place.
    /// </summary>
    public byte[] Serialize(object entity, FieldPlan[] plan, int schemaVersion)
    {
        var buffer = new ArrayBufferWriter<byte>(256);
        var writer = new SpanWriter(buffer);
        WriteHeader(ref writer, schemaVersion);
        WriteFieldPlanFields(ref writer, entity, plan);
        writer.Commit();

        var result = buffer.WrittenSpan.ToArray();
        SignFieldPlanPayload(result);
        return result;
    }

    /// <summary>
    /// Serializes a list of entities for wire transport.
    /// Format: [BSO1 header][Int32 count][per item: Int32 len + payload bytes]
    /// </summary>
    public byte[] SerializeList(IEnumerable items, FieldPlan[] plan, int schemaVersion, int count)
    {
        var buffer = new ArrayBufferWriter<byte>(256 + count * 64);
        var writer = new SpanWriter(buffer);

        WriteHeader(ref writer, schemaVersion);
        writer.WriteInt32(count);
        writer.Commit();

        foreach (var item in items)
        {
            if (item is null) continue;
            var itemBuf = new ArrayBufferWriter<byte>(128);
            var itemWriter = new SpanWriter(itemBuf);
            WriteFieldPlanFields(ref itemWriter, item, plan);
            int itemLen = itemWriter.Commit();

            var lenWriter = new SpanWriter(buffer);
            lenWriter.WriteInt32(itemLen);
            lenWriter.Commit();
            var payload = itemBuf.WrittenSpan;
            var dest = buffer.GetSpan(payload.Length);
            payload.CopyTo(dest);
            buffer.Advance(payload.Length);
        }

        var result = buffer.WrittenSpan.ToArray();
        SignFieldPlanPayload(result);
        return result;
    }

    private static void WriteFieldPlanFields(ref SpanWriter writer, object entity, FieldPlan[] plan)
    {
        writer.WriteByte(1); // entity is never null here

        for (int i = 0; i < plan.Length; i++)
        {
            var fp = plan[i];
            var value = fp.Getter(entity);
            WriteFieldPlanValue(ref writer, fp, value, 0);
        }
    }

    private static void WriteFieldPlanValue(ref SpanWriter writer, FieldPlan fp, object? value, int depth)
    {
        if (depth > FieldPlanMaxDepth)
            throw new InvalidOperationException("Max serialization depth exceeded.");

        if (fp.IsNullable)
        {
            if (value is null)
            {
                writer.WriteByte(0);
                return;
            }
            writer.WriteByte(1);
        }

        switch (fp.WireType)
        {
            case WireFieldType.Enum:
                WriteFieldPlanEnumValue(ref writer, fp.EnumUnderlying, value);
                break;
            case WireFieldType.String:
                WriteString(ref writer, value as string);
                break;
            case WireFieldType.Bool:
                writer.WriteBoolean((bool)(value ?? false));
                break;
            case WireFieldType.Byte:
                writer.WriteByte((byte)(value ?? (byte)0));
                break;
            case WireFieldType.SByte:
                writer.WriteSByte((sbyte)(value ?? (sbyte)0));
                break;
            case WireFieldType.Int16:
                writer.WriteInt16((short)(value ?? (short)0));
                break;
            case WireFieldType.UInt16:
                writer.WriteUInt16((ushort)(value ?? (ushort)0));
                break;
            case WireFieldType.Int32:
                writer.WriteInt32((int)(value ?? 0));
                break;
            case WireFieldType.UInt32:
                writer.WriteUInt32((uint)(value ?? 0u));
                break;
            case WireFieldType.Int64:
                writer.WriteInt64((long)(value ?? 0L));
                break;
            case WireFieldType.UInt64:
                writer.WriteUInt64((ulong)(value ?? 0UL));
                break;
            case WireFieldType.Float32:
                writer.WriteSingle((float)(value ?? 0f));
                break;
            case WireFieldType.Float64:
                writer.WriteDouble((double)(value ?? 0d));
                break;
            case WireFieldType.Decimal:
                writer.WriteDecimal((decimal)(value ?? 0m));
                break;
            case WireFieldType.Char:
                writer.WriteChar((char)(value ?? '\0'));
                break;
            case WireFieldType.Guid:
            {
                var guid = (Guid)(value ?? Guid.Empty);
                Span<byte> buf = stackalloc byte[16];
                guid.TryWriteBytes(buf);
                writer.WriteBytes(buf);
                break;
            }
            case WireFieldType.DateTime:
            {
                var dt = (DateTime)(value ?? default(DateTime));
                writer.WriteInt64(dt.Ticks);
                writer.WriteByte((byte)dt.Kind);
                break;
            }
            case WireFieldType.DateOnly:
            {
                var d = (System.DateOnly)(value ?? default(System.DateOnly));
                writer.WriteInt32(d.DayNumber);
                break;
            }
            case WireFieldType.TimeOnly:
            {
                var t = (System.TimeOnly)(value ?? default(System.TimeOnly));
                writer.WriteInt64(t.Ticks);
                break;
            }
            case WireFieldType.DateTimeOffset:
            {
                var dto = (DateTimeOffset)(value ?? default(DateTimeOffset));
                writer.WriteInt64(dto.Ticks);
                writer.WriteInt16((short)dto.Offset.TotalMinutes);
                break;
            }
            case WireFieldType.TimeSpan:
            {
                var ts = (TimeSpan)(value ?? default(TimeSpan));
                writer.WriteInt64(ts.Ticks);
                break;
            }
            case WireFieldType.Identifier:
            {
                var id = (IdentifierValue)(value ?? IdentifierValue.Empty);
                Span<byte> buf = stackalloc byte[16];
                id.WriteTo(buf);
                writer.WriteBytes(buf);
                break;
            }
            default:
                WriteString(ref writer, value?.ToString());
                break;
        }
    }

    private static void WriteFieldPlanEnumValue(ref SpanWriter writer, WireFieldType underlying, object? value)
    {
        if (value is null) { writer.WriteInt32(0); return; }
        switch (underlying)
        {
            case WireFieldType.Byte: writer.WriteByte(Convert.ToByte(value)); break;
            case WireFieldType.SByte: writer.WriteSByte(Convert.ToSByte(value)); break;
            case WireFieldType.Int16: writer.WriteInt16(Convert.ToInt16(value)); break;
            case WireFieldType.UInt16: writer.WriteUInt16(Convert.ToUInt16(value)); break;
            case WireFieldType.Int32: writer.WriteInt32(Convert.ToInt32(value)); break;
            case WireFieldType.UInt32: writer.WriteUInt32(Convert.ToUInt32(value)); break;
            case WireFieldType.Int64: writer.WriteInt64(Convert.ToInt64(value)); break;
            case WireFieldType.UInt64: writer.WriteUInt64(Convert.ToUInt64(value)); break;
            default: writer.WriteInt32(Convert.ToInt32(value)); break;
        }
    }

    // ────────────── FieldPlan deserialization (read) ──────────────

    /// <summary>
    /// Deserializes a signed binary payload into an entity using the precompiled field plan.
    /// </summary>
    public object Deserialize(ReadOnlySpan<byte> data, FieldPlan[] plan, Type entityType)
    {
        ValidateSignature(data);
        var reader = new SpanReader(data);

        reader.ReadInt32(); // magic
        reader.ReadInt32(); // version
        reader.ReadInt32(); // schema version
        reader.ReadByte();  // architecture
        Span<byte> sigBuf = stackalloc byte[SignatureSize];
        reader.ReadBytes(sigBuf); // signature

        return ReadFieldPlanEntity(ref reader, plan, entityType);
    }

    /// <summary>
    /// Deserializes a signed binary payload into a pre-created instance.
    /// Avoids Activator.CreateInstance — fully AOT-safe.
    /// </summary>
    public void DeserializeInto(ReadOnlySpan<byte> data, FieldPlan[] plan, object instance)
    {
        ValidateSignature(data);
        var reader = new SpanReader(data);

        reader.ReadInt32(); // magic
        reader.ReadInt32(); // version
        reader.ReadInt32(); // schema version
        reader.ReadByte();  // architecture
        Span<byte> sigBuf = stackalloc byte[SignatureSize];
        reader.ReadBytes(sigBuf); // signature

        var hasValue = reader.ReadByte();
        if (hasValue == 0)
            throw new InvalidOperationException("Null entity in binary payload.");

        for (int i = 0; i < plan.Length; i++)
        {
            var fp = plan[i];
            var value = ReadFieldPlanValue(ref reader, fp, 0);
            if (value is not null || !fp.ClrType.IsValueType)
                fp.Setter(instance, value);
        }
    }

    /// <summary>
    /// Reads the schema version from a binary payload header without full validation.
    /// </summary>
    public int ReadSchemaVersionFromPayload(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderSizeV3)
            throw new InvalidOperationException("Payload too short for BSO1 header.");
        return BinaryPrimitives.ReadInt32LittleEndian(data.Slice(8, 4));
    }

    private static object ReadFieldPlanEntity(ref SpanReader reader, FieldPlan[] plan, Type entityType)
    {
        var hasValue = reader.ReadByte();
        if (hasValue == 0)
            throw new InvalidOperationException("Null entity in binary payload.");

        var instance = CreateFieldPlanEntityInstance(entityType);

        for (int i = 0; i < plan.Length; i++)
        {
            var fp = plan[i];
            var value = ReadFieldPlanValue(ref reader, fp, 0);
            if (value is not null || !fp.ClrType.IsValueType)
                fp.Setter(instance, value);
        }

        return instance;
    }

    /// <summary>
    /// AOT-safe entity instance creation for FieldPlan deserialization.
    /// </summary>
    private static object CreateFieldPlanEntityInstance(Type entityType)
    {
        if (entityType == typeof(DataRecord))
            return new DataRecord();

        var meta = DataScaffold.GetEntityByType(entityType);
        if (meta != null)
            return meta.Handlers.Create();

        throw new InvalidOperationException(
            $"Entity type '{entityType.FullName}' is not registered with DataScaffold. " +
            "Register it with DataScaffold.RegisterEntity<T>() at startup.");
    }

    private static object? ReadFieldPlanValue(ref SpanReader reader, FieldPlan fp, int depth)
    {
        if (depth > FieldPlanMaxDepth)
            throw new InvalidOperationException("Max deserialization depth exceeded.");

        if (fp.IsNullable)
        {
            var hasValue = reader.ReadByte();
            if (hasValue == 0) return null;
        }

        switch (fp.WireType)
        {
            case WireFieldType.Enum:
                return ReadFieldPlanEnumValue(ref reader, fp);
            case WireFieldType.String:
                return ReadString(ref reader);
            case WireFieldType.Bool:
                return reader.ReadBoolean();
            case WireFieldType.Byte:
                return reader.ReadByte();
            case WireFieldType.SByte:
                return reader.ReadSByte();
            case WireFieldType.Int16:
                return reader.ReadInt16();
            case WireFieldType.UInt16:
                return reader.ReadUInt16();
            case WireFieldType.Int32:
                return reader.ReadInt32();
            case WireFieldType.UInt32:
                return reader.ReadUInt32();
            case WireFieldType.Int64:
                return reader.ReadInt64();
            case WireFieldType.UInt64:
                return reader.ReadUInt64();
            case WireFieldType.Float32:
                return reader.ReadSingle();
            case WireFieldType.Float64:
                return reader.ReadDouble();
            case WireFieldType.Decimal:
                return reader.ReadDecimal();
            case WireFieldType.Char:
                return reader.ReadChar();
            case WireFieldType.Guid:
            {
                Span<byte> buf = stackalloc byte[16];
                reader.ReadBytes(buf);
                return new Guid(buf);
            }
            case WireFieldType.DateTime:
            {
                var ticks = reader.ReadInt64();
                var kind = (DateTimeKind)reader.ReadByte();
                return new DateTime(ticks, kind);
            }
            case WireFieldType.DateOnly:
                return System.DateOnly.FromDayNumber(reader.ReadInt32());
            case WireFieldType.TimeOnly:
                return new System.TimeOnly(reader.ReadInt64());
            case WireFieldType.DateTimeOffset:
            {
                var ticks = reader.ReadInt64();
                var offsetMin = reader.ReadInt16();
                return new DateTimeOffset(ticks, TimeSpan.FromMinutes(offsetMin));
            }
            case WireFieldType.TimeSpan:
                return new TimeSpan(reader.ReadInt64());
            case WireFieldType.Identifier:
            {
                Span<byte> buf = stackalloc byte[16];
                reader.ReadBytes(buf);
                return IdentifierValue.ReadFrom(buf);
            }
            default:
                return ReadString(ref reader);
        }
    }

    private static object ReadFieldPlanEnumValue(ref SpanReader reader, FieldPlan fp)
    {
        object raw = fp.EnumUnderlying switch
        {
            WireFieldType.Byte => reader.ReadByte(),
            WireFieldType.SByte => reader.ReadSByte(),
            WireFieldType.Int16 => reader.ReadInt16(),
            WireFieldType.UInt16 => reader.ReadUInt16(),
            WireFieldType.Int32 => reader.ReadInt32(),
            WireFieldType.UInt32 => reader.ReadUInt32(),
            WireFieldType.Int64 => reader.ReadInt64(),
            WireFieldType.UInt64 => reader.ReadUInt64(),
            _ => reader.ReadInt32(),
        };
        return EnumHelper.FromLong(fp.ClrType, ((IConvertible)raw).ToInt64(null));
    }

    // ────────────── FieldPlan HMAC signing ──────────────

    private void SignFieldPlanPayload(Span<byte> payload)
    {
        if (payload.Length < HeaderSizeV3) return;
        Span<byte> sig = stackalloc byte[SignatureSize];
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _signingKey);
        hmac.AppendData(payload.Slice(0, HeaderFieldsSizeV3));
        hmac.AppendData(payload.Slice(HeaderFieldsSizeV3 + SignatureSize));
        hmac.GetHashAndReset(sig);
        sig.CopyTo(payload.Slice(HeaderFieldsSizeV3, SignatureSize));
    }

    // ────────────── Schema descriptor for client ──────────────

    /// <summary>
    /// Builds a JSON-serializable schema descriptor for the JS client.
    /// </summary>
    public static WireSchemaDescriptor BuildSchemaDescriptor(string slug, int schemaVersion, FieldPlan[] plan)
    {
        var members = new WireMemberDescriptor[plan.Length];
        for (int i = 0; i < plan.Length; i++)
        {
            var fp = plan[i];
            members[i] = new WireMemberDescriptor
            {
                Name = fp.Name,
                Ordinal = fp.Ordinal,
                WireType = fp.WireType.ToString(),
                IsNullable = fp.IsNullable,
                EnumUnderlying = fp.WireType == WireFieldType.Enum ? fp.EnumUnderlying.ToString() : null,
            };
        }
        return new WireSchemaDescriptor
        {
            Slug = slug,
            Version = schemaVersion,
            Members = members,
        };
    }

    // ────────────── JSON serialization (metadata-driven) ──────────────

    /// <summary>
    /// Writes a single entity as a JSON object to a Utf8JsonWriter using the field plan.
    /// </summary>
    public static void WriteEntityJson(System.Text.Json.Utf8JsonWriter writer, object entity, FieldPlan[] plan)
    {
        writer.WriteStartObject();
        for (int i = 0; i < plan.Length; i++)
        {
            var fp = plan[i];
            var value = fp.Getter(entity);
            writer.WritePropertyName(fp.Name);
            WriteFieldPlanJsonValue(writer, fp, value);
        }
        writer.WriteEndObject();
    }

    /// <summary>
    /// Writes a list of entities as a JSON object { data: [...], count: N }.
    /// </summary>
    public static void WriteEntityListJson(System.Text.Json.Utf8JsonWriter writer, IEnumerable items, FieldPlan[] plan, int count)
    {
        writer.WriteStartObject();
        writer.WritePropertyName("data");
        writer.WriteStartArray();
        foreach (var item in items)
        {
            if (item is null) { writer.WriteNullValue(); continue; }
            WriteEntityJson(writer, item, plan);
        }
        writer.WriteEndArray();
        writer.WriteNumber("count", count);
        writer.WriteEndObject();
    }

    private static void WriteFieldPlanJsonValue(System.Text.Json.Utf8JsonWriter writer, FieldPlan fp, object? value)
    {
        if (value is null)
        {
            writer.WriteNullValue();
            return;
        }

        switch (fp.WireType)
        {
            case WireFieldType.Bool:
                writer.WriteBooleanValue((bool)value);
                break;
            case WireFieldType.Byte:
                writer.WriteNumberValue((byte)value);
                break;
            case WireFieldType.SByte:
                writer.WriteNumberValue((sbyte)value);
                break;
            case WireFieldType.Int16:
                writer.WriteNumberValue((short)value);
                break;
            case WireFieldType.UInt16:
                writer.WriteNumberValue((ushort)value);
                break;
            case WireFieldType.Int32:
                writer.WriteNumberValue((int)value);
                break;
            case WireFieldType.UInt32:
                writer.WriteNumberValue((uint)value);
                break;
            case WireFieldType.Int64:
                writer.WriteNumberValue((long)value);
                break;
            case WireFieldType.UInt64:
                writer.WriteNumberValue((ulong)value);
                break;
            case WireFieldType.Float32:
                writer.WriteNumberValue((float)value);
                break;
            case WireFieldType.Float64:
                writer.WriteNumberValue((double)value);
                break;
            case WireFieldType.Decimal:
                writer.WriteNumberValue((decimal)value);
                break;
            case WireFieldType.Char:
                writer.WriteStringValue(((char)value).ToString());
                break;
            case WireFieldType.String:
                writer.WriteStringValue((string)value);
                break;
            case WireFieldType.Guid:
                writer.WriteStringValue(((Guid)value).ToString("D"));
                break;
            case WireFieldType.DateTime:
                writer.WriteStringValue(((DateTime)value).ToString("O"));
                break;
            case WireFieldType.DateOnly:
                writer.WriteStringValue(((System.DateOnly)value).ToString("yyyy-MM-dd"));
                break;
            case WireFieldType.TimeOnly:
                writer.WriteStringValue(((System.TimeOnly)value).ToString("HH:mm:ss"));
                break;
            case WireFieldType.DateTimeOffset:
                writer.WriteStringValue(((DateTimeOffset)value).ToString("O"));
                break;
            case WireFieldType.TimeSpan:
                writer.WriteStringValue(((TimeSpan)value).ToString("c"));
                break;
            case WireFieldType.Identifier:
                writer.WriteStringValue(((IdentifierValue)value).ToString());
                break;
            case WireFieldType.Enum:
                writer.WriteNumberValue(Convert.ToInt32(value));
                break;
            default:
                writer.WriteStringValue(value.ToString());
                break;
        }
    }

    // ────────────── JSON deserialization (metadata-driven) ──────────────

    /// <summary>
    /// Deserializes a JSON object into an entity using the field plan.
    /// </summary>
    public static object DeserializeFromJson(System.Text.Json.JsonElement root, FieldPlan[] plan, Type entityType)
    {
        var instance = CreateFieldPlanEntityInstance(entityType);

        foreach (var prop in root.EnumerateObject())
        {
            FieldPlan? fp = null;
            for (int i = 0; i < plan.Length; i++)
            {
                if (string.Equals(plan[i].Name, prop.Name, StringComparison.OrdinalIgnoreCase))
                {
                    fp = plan[i];
                    break;
                }
            }
            if (fp == null) continue;

            var value = ParseFieldPlanJsonValue(prop.Value, fp);
            if (value is not null || !fp.ClrType.IsValueType || fp.IsNullable)
                fp.Setter(instance, value);
        }

        return instance;
    }

    private static object? ParseFieldPlanJsonValue(System.Text.Json.JsonElement element, FieldPlan fp)
    {
        if (element.ValueKind == System.Text.Json.JsonValueKind.Null ||
            element.ValueKind == System.Text.Json.JsonValueKind.Undefined)
            return null;

        switch (fp.WireType)
        {
            case WireFieldType.Bool:
                return element.ValueKind == System.Text.Json.JsonValueKind.True ||
                       (element.ValueKind == System.Text.Json.JsonValueKind.String && bool.TryParse(element.GetString(), out var b) && b);
            case WireFieldType.Byte:
                return element.TryGetByte(out var byteVal) ? byteVal : (byte)0;
            case WireFieldType.SByte:
                return element.TryGetSByte(out var sbyteVal) ? sbyteVal : (sbyte)0;
            case WireFieldType.Int16:
                return element.TryGetInt16(out var i16) ? i16 : (short)0;
            case WireFieldType.UInt16:
                return element.TryGetUInt16(out var u16) ? u16 : (ushort)0;
            case WireFieldType.Int32:
                return element.TryGetInt32(out var i32) ? i32 : 0;
            case WireFieldType.UInt32:
                return element.TryGetUInt32(out var u32) ? u32 : 0u;
            case WireFieldType.Int64:
                return element.TryGetInt64(out var i64) ? i64 : 0L;
            case WireFieldType.UInt64:
                return element.TryGetUInt64(out var u64) ? u64 : 0UL;
            case WireFieldType.Float32:
                return element.TryGetSingle(out var f32) ? f32 : 0f;
            case WireFieldType.Float64:
                return element.TryGetDouble(out var f64) ? f64 : 0d;
            case WireFieldType.Decimal:
                return element.TryGetDecimal(out var dec) ? dec : 0m;
            case WireFieldType.Char:
            {
                var s = element.GetString();
                return s?.Length > 0 ? s[0] : '\0';
            }
            case WireFieldType.String:
                return element.GetString();
            case WireFieldType.Guid:
            {
                var s = element.GetString();
                return s != null && Guid.TryParse(s, out var g) ? g : Guid.Empty;
            }
            case WireFieldType.DateTime:
            {
                if (element.TryGetDateTime(out var dt)) return dt;
                var s = element.GetString();
                return s != null && DateTime.TryParse(s, out var parsed) ? parsed : default;
            }
            case WireFieldType.DateOnly:
            {
                var s = element.GetString();
                return s != null && System.DateOnly.TryParse(s, out var d) ? d : default;
            }
            case WireFieldType.TimeOnly:
            {
                var s = element.GetString();
                return s != null && System.TimeOnly.TryParse(s, out var t) ? t : default;
            }
            case WireFieldType.DateTimeOffset:
            {
                if (element.TryGetDateTimeOffset(out var dto)) return dto;
                var s = element.GetString();
                return s != null && DateTimeOffset.TryParse(s, out var parsed) ? parsed : default;
            }
            case WireFieldType.TimeSpan:
            {
                var s = element.GetString();
                return s != null && TimeSpan.TryParse(s, out var ts) ? ts : default;
            }
            case WireFieldType.Identifier:
            {
                var s = element.GetString();
                return IdentifierValue.TryParse(s, out var id) ? id : IdentifierValue.Empty;
            }
            case WireFieldType.Enum:
            {
                if (element.ValueKind == System.Text.Json.JsonValueKind.Number && element.TryGetInt32(out var enumInt))
                    return EnumHelper.FromInt32(fp.ClrType, enumInt);
                if (element.ValueKind == System.Text.Json.JsonValueKind.String)
                {
                    var s = element.GetString();
                    if (s != null && DataScaffold.GetEnumLookup(fp.ClrType).TryGetValue(s, out var enumVal))
                        return enumVal;
                }
                return EnumHelper.FromLong(fp.ClrType, 0L);
            }
            default:
                return element.GetString();
        }
    }

}


