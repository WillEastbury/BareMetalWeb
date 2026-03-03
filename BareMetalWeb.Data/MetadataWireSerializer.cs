using System.Buffers;
using System.Buffers.Binary;
using System.Collections;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace BareMetalWeb.Data;

/// <summary>
/// Metadata-driven binary serializer for wire transport.
/// Uses precompiled <see cref="FieldPlan"/> arrays built once at startup from
/// entity metadata — zero reflection at serialize/deserialize time.
///
/// Wire format: BSO1 header (45 bytes) + fields in ordinal order.
/// Compatible with <see cref="BinaryObjectSerializer"/> binary layout.
/// </summary>
public sealed class MetadataWireSerializer
{
    private const int Magic = 0x314F5342; // "BSO1"
    private const int CurrentVersion = 3;
    private const int SignatureSize = 32;
    private const int HeaderFieldsSize = 4 + 4 + 4 + 1; // magic + version + schema + arch
    private const int HeaderSize = HeaderFieldsSize + SignatureSize;
    private const int MaxDepth = 64;
    private const int MaxStringBytes = 4 * 1024 * 1024;
    private const int MaxCollectionLength = 1_000_000;
    private static readonly byte[] SignaturePlaceholder = new byte[SignatureSize];
    private static readonly Encoding Utf8 = Encoding.UTF8;

    private readonly byte[] _signingKey;

    // Cached field plans per CLR type — built once, reused forever
    private static readonly ConcurrentDictionary<Type, FieldPlan[]> PlanCache = new();

    public MetadataWireSerializer(byte[] signingKey)
    {
        if (signingKey is null || signingKey.Length != SignatureSize)
            throw new ArgumentException($"Signing key must be {SignatureSize} bytes.");
        _signingKey = signingKey;
    }

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
            return (WireFieldType.Enum, isNullable, MapPrimitiveType(underlying));
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

    private static WireFieldType MapPrimitiveType(Type t)
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

    // ────────────── Serialization (write) ──────────────

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
        WriteFields(ref writer, entity, plan);
        writer.Commit();

        // Copy to owned array and sign in-place
        var result = buffer.WrittenSpan.ToArray();
        SignPayload(result);
        return result;
    }

    /// <summary>
    /// Serializes a list of entities for wire transport.
    /// Format: [BSO1 header][Int32 count][per item: Int32 len + payload bytes]
    /// Returns a signed byte[] that can be written to the response body.
    /// </summary>
    public byte[] SerializeList(IEnumerable items, FieldPlan[] plan, int schemaVersion, int count)
    {
        var buffer = new ArrayBufferWriter<byte>(256 + count * 64);
        var writer = new SpanWriter(buffer);

        // List envelope header
        WriteHeader(ref writer, schemaVersion);
        writer.WriteInt32(count);
        writer.Commit();

        foreach (var item in items)
        {
            if (item is null) continue;
            // Serialize item fields to a temp buffer to get the length
            var itemBuf = new ArrayBufferWriter<byte>(128);
            var itemWriter = new SpanWriter(itemBuf);
            WriteFields(ref itemWriter, item, plan);
            int itemLen = itemWriter.Commit();

            // Write length-prefix + payload into main buffer
            var lenWriter = new SpanWriter(buffer);
            lenWriter.WriteInt32(itemLen);
            lenWriter.Commit();
            var payload = itemBuf.WrittenSpan;
            var dest = buffer.GetSpan(payload.Length);
            payload.CopyTo(dest);
            buffer.Advance(payload.Length);
        }

        // Copy to owned array and sign in-place
        var result = buffer.WrittenSpan.ToArray();
        SignPayload(result);
        return result;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteHeader(ref SpanWriter writer, int schemaVersion)
    {
        writer.WriteInt32(Magic);
        writer.WriteInt32(CurrentVersion);
        writer.WriteInt32(schemaVersion);
        writer.WriteByte((byte)BinaryArchitectureMapper.Current);
        writer.WriteBytes(SignaturePlaceholder);
    }

    private static void WriteFields(ref SpanWriter writer, object entity, FieldPlan[] plan)
    {
        // Reference type null indicator
        writer.WriteByte(1); // entity is never null here

        for (int i = 0; i < plan.Length; i++)
        {
            var fp = plan[i];
            var value = fp.Getter(entity);
            WriteFieldValue(ref writer, fp, value, 0);
        }
    }

    private static void WriteFieldValue(ref SpanWriter writer, FieldPlan fp, object? value, int depth)
    {
        if (depth > MaxDepth)
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
                WriteEnumValue(ref writer, fp.EnumUnderlying, value);
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
                // Fallback: write as UTF-8 string via ToString()
                WriteString(ref writer, value?.ToString());
                break;
        }
    }

    private static void WriteEnumValue(ref SpanWriter writer, WireFieldType underlying, object? value)
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

    private static void WriteString(ref SpanWriter writer, string? value)
    {
        if (value is null) { writer.WriteInt32(-1); return; }
        var byteCount = Utf8.GetByteCount(value);
        writer.WriteInt32(byteCount);
        if (byteCount == 0) return;

        if (byteCount <= 512)
        {
            Span<byte> buf = stackalloc byte[byteCount];
            Utf8.GetBytes(value, buf);
            writer.WriteBytes(buf);
        }
        else
        {
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
    }

    // ────────────── Deserialization (read) ──────────────

    /// <summary>
    /// Deserializes a signed binary payload into an entity using the precompiled field plan.
    /// </summary>
    public object Deserialize(ReadOnlySpan<byte> data, FieldPlan[] plan, Type entityType)
    {
        ValidateSignature(data);
        var reader = new SpanReader(data);

        // Skip header
        reader.ReadInt32(); // magic
        reader.ReadInt32(); // version
        reader.ReadInt32(); // schema version
        reader.ReadByte();  // architecture
        Span<byte> sigBuf = stackalloc byte[SignatureSize];
        reader.ReadBytes(sigBuf); // signature

        return ReadEntity(ref reader, plan, entityType);
    }

    /// <summary>
    /// Deserializes a signed binary payload into a pre-created instance.
    /// Avoids <c>Activator.CreateInstance</c> — fully AOT-safe.
    /// The caller creates the instance (e.g. <see cref="DataRecord"/>)
    /// and this method populates it via the field plan setters.
    /// </summary>
    public void DeserializeInto(ReadOnlySpan<byte> data, FieldPlan[] plan, object instance)
    {
        ValidateSignature(data);
        var reader = new SpanReader(data);

        // Skip header
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
            var value = ReadFieldValue(ref reader, fp, 0);
            if (value is not null || !fp.ClrType.IsValueType)
                fp.Setter(instance, value);
        }
    }

    /// <summary>
    /// Reads the schema version from a binary payload header without full validation.
    /// </summary>
    public int ReadSchemaVersionFromPayload(ReadOnlySpan<byte> data)
    {
        if (data.Length < HeaderSize)
            throw new InvalidOperationException("Payload too short for BSO1 header.");
        return BinaryPrimitives.ReadInt32LittleEndian(data.Slice(8, 4));
    }

    private static object ReadEntity(ref SpanReader reader, FieldPlan[] plan, Type entityType)
    {
        var hasValue = reader.ReadByte();
        if (hasValue == 0)
            throw new InvalidOperationException("Null entity in binary payload.");

        var instance = CreateEntityInstance(entityType);

        for (int i = 0; i < plan.Length; i++)
        {
            var fp = plan[i];
            var value = ReadFieldValue(ref reader, fp, 0);
            if (value is not null || !fp.ClrType.IsValueType)
                fp.Setter(instance, value);
        }

        return instance;
    }

    /// <summary>
    /// AOT-safe entity instance creation. Returns a <see cref="DataRecord"/> when the
    /// target type is DataRecord; falls back to <see cref="RuntimeHelpers.GetUninitializedObject"/>
    /// for compiled entity types.
    /// </summary>
    private static object CreateEntityInstance(Type entityType)
    {
        if (entityType == typeof(DataRecord))
            return new DataRecord();

        return System.Runtime.CompilerServices.RuntimeHelpers.GetUninitializedObject(entityType);
    }

    private static object? ReadFieldValue(ref SpanReader reader, FieldPlan fp, int depth)
    {
        if (depth > MaxDepth)
            throw new InvalidOperationException("Max deserialization depth exceeded.");

        if (fp.IsNullable)
        {
            var hasValue = reader.ReadByte();
            if (hasValue == 0) return null;
        }

        switch (fp.WireType)
        {
            case WireFieldType.Enum:
                return ReadEnumValue(ref reader, fp);
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
                // Fallback: read as string
                return ReadString(ref reader);
        }
    }

    private static object ReadEnumValue(ref SpanReader reader, FieldPlan fp)
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
        return Enum.ToObject(fp.ClrType, raw);
    }

    private static string? ReadString(ref SpanReader reader)
    {
        var byteCount = reader.ReadInt32();
        if (byteCount < 0) return null;
        if (byteCount == 0) return string.Empty;
        if (byteCount > MaxStringBytes)
            throw new InvalidOperationException($"String length {byteCount} exceeds max {MaxStringBytes}.");

        if (byteCount <= 512)
        {
            Span<byte> buf = stackalloc byte[byteCount];
            reader.ReadBytes(buf);
            return Utf8.GetString(buf);
        }

        var rented = ArrayPool<byte>.Shared.Rent(byteCount);
        try
        {
            var span = rented.AsSpan(0, byteCount);
            reader.ReadBytes(span);
            return Utf8.GetString(span);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    // ────────────── HMAC signing ──────────────

    private void SignPayload(Span<byte> payload)
    {
        if (payload.Length < HeaderSize) return;
        Span<byte> sig = stackalloc byte[SignatureSize];
        ComputeSignature(payload, sig);
        sig.CopyTo(payload.Slice(HeaderFieldsSize, SignatureSize));
    }

    private void ComputeSignature(ReadOnlySpan<byte> payload, Span<byte> destination)
    {
        using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, _signingKey);
        hmac.AppendData(payload.Slice(0, HeaderFieldsSize));
        hmac.AppendData(payload.Slice(HeaderFieldsSize + SignatureSize));
        hmac.GetHashAndReset(destination);
    }

    private void ValidateSignature(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < HeaderSize)
            throw new InvalidOperationException("Payload too short for signed header.");

        var magic = BinaryPrimitives.ReadInt32LittleEndian(payload.Slice(0, 4));
        if (magic != Magic)
            throw new InvalidOperationException("Invalid binary payload magic.");

        Span<byte> expected = stackalloc byte[SignatureSize];
        ComputeSignature(payload, expected);
        var actual = payload.Slice(HeaderFieldsSize, SignatureSize);
        if (!CryptographicOperations.FixedTimeEquals(expected, actual))
            throw new InvalidOperationException("Payload signature mismatch.");
    }

    // ────────────── Schema descriptor for client ──────────────

    /// <summary>
    /// Builds a JSON-serializable schema descriptor for the JS client.
    /// The client uses this to build its own field plan for deserialization.
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

    // ────────────── JSON serialization (metadata-driven) ──────────────

    /// <summary>
    /// Writes a single entity as a JSON object to a Utf8JsonWriter using the field plan.
    /// No reflection — uses compiled getter delegates.
    /// </summary>
    public static void WriteEntityJson(System.Text.Json.Utf8JsonWriter writer, object entity, FieldPlan[] plan)
    {
        writer.WriteStartObject();
        for (int i = 0; i < plan.Length; i++)
        {
            var fp = plan[i];
            var value = fp.Getter(entity);
            writer.WritePropertyName(fp.Name);
            WriteJsonValue(writer, fp, value);
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

    private static void WriteJsonValue(System.Text.Json.Utf8JsonWriter writer, FieldPlan fp, object? value)
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
    /// No reflection — uses compiled setter delegates.
    /// </summary>
    public static object DeserializeFromJson(System.Text.Json.JsonElement root, FieldPlan[] plan, Type entityType)
    {
        var instance = CreateEntityInstance(entityType);

        // Build a name→plan lookup for JSON property matching (case-insensitive)
        // This is O(N) at call time but avoids dictionary allocation for small entities.
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

            var value = ParseJsonValue(prop.Value, fp);
            if (value is not null || !fp.ClrType.IsValueType || fp.IsNullable)
                fp.Setter(instance, value);
        }

        return instance;
    }

    private static object? ParseJsonValue(System.Text.Json.JsonElement element, FieldPlan fp)
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
                    return Enum.ToObject(fp.ClrType, enumInt);
                if (element.ValueKind == System.Text.Json.JsonValueKind.String)
                {
                    var s = element.GetString();
                    if (s != null && Enum.TryParse(fp.ClrType, s, true, out var enumVal))
                        return enumVal;
                }
                return Enum.ToObject(fp.ClrType, 0);
            }
            default:
                return element.GetString();
        }
    }
}
