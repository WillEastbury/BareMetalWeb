using System.Buffers;
using System.Buffers.Binary;
using System.Buffers.Text;
using System.Runtime.CompilerServices;
using System.Text;
using WireFieldType = BareMetalWeb.Data.MetadataWireSerializer.WireFieldType;
using FieldPlan = BareMetalWeb.Data.MetadataWireSerializer.FieldPlan;

namespace BareMetalWeb.Data;

/// <summary>
/// Single-pass streaming JSON ingest engine that parses a UTF-8 JSON object
/// and produces a BSO1 binary row — no CLR object materialisation, no
/// System.Text.Json dependency, no reflection, full AOT/trim safety.
///
/// Property names are matched via a precomputed ordinal lookup table of
/// UTF-8 name bytes built once at startup from <see cref="FieldPlan"/>.
/// </summary>
public static class BmwJsonReader
{
    private const int HeaderSize = 45;
    private const int Magic = 0x314F5342; // "BSO1"
    private const int CurrentVersion = 3;
    private const int MaxStringBytes = 4 * 1024 * 1024;
    private const int MaxFieldCount = 256;
    private const int MaxJsonSize = 16 * 1024 * 1024; // 16 MiB safety limit

    // ────────────── Lookup table ──────────────

    /// <summary>
    /// Precomputed lookup entry mapping a UTF-8 property name to its field ordinal.
    /// </summary>
    public sealed class JsonPropertyLookup
    {
        public required byte[] NameUtf8 { get; init; }
        public required int Ordinal { get; init; }
    }

    /// <summary>
    /// Builds a property-name → ordinal lookup table from a <see cref="FieldPlan"/> array.
    /// Call once per entity type at startup.
    /// </summary>
    public static JsonPropertyLookup[] BuildLookup(FieldPlan[] plan)
    {
        var lookup = new JsonPropertyLookup[plan.Length];
        for (int i = 0; i < plan.Length; i++)
        {
            lookup[i] = new JsonPropertyLookup
            {
                NameUtf8 = Encoding.UTF8.GetBytes(plan[i].Name),
                Ordinal = i,
            };
        }
        return lookup;
    }

    // ────────────── Read entity (create) ──────────────

    /// <summary>
    /// Reads a JSON object from <paramref name="jsonUtf8"/> and produces a
    /// BSO1 binary row payload. Unknown JSON properties are ignored;
    /// malformed tokens are rejected.
    /// </summary>
    /// <returns>BSO1 binary payload (unsigned — caller signs via MetadataWireSerializer).</returns>
    public static byte[] ReadEntity(
        ReadOnlySpan<byte> jsonUtf8,
        FieldPlan[] plan,
        JsonPropertyLookup[] lookup,
        int schemaVersion = 1)
    {
        // Phase 1: Parse JSON into per-field value slots
        var fieldCount = plan.Length;
        if (fieldCount > MaxFieldCount)
            throw new InvalidOperationException($"Field count {fieldCount} exceeds max {MaxFieldCount}.");

        // Per-field parsed binary values — null means field not present in JSON
        var slots = new byte[fieldCount][];
        var slotSet = new bool[fieldCount];

        ParseJsonObject(jsonUtf8, plan, lookup, slots, slotSet);

        // Phase 2: Assemble BSO1 binary row
        return AssembleBinaryRow(plan, slots, slotSet, schemaVersion);
    }

    /// <summary>
    /// Reads a JSON object from a <see cref="Stream"/> and produces a BSO1 binary row.
    /// Buffers the stream content then delegates to the span-based overload.
    /// </summary>
    public static byte[] ReadEntity(
        Stream input,
        FieldPlan[] plan,
        JsonPropertyLookup[] lookup,
        int schemaVersion = 1)
    {
        var jsonBytes = ReadStreamToBytes(input);
        return ReadEntity(jsonBytes.AsSpan(), plan, lookup, schemaVersion);
    }

    // ────────────── Merge entity (PUT/PATCH) ──────────────

    /// <summary>
    /// Merges a JSON object into an existing BSO1 binary row.
    /// Fields present in the JSON overwrite the binary; fields absent in
    /// the JSON retain their existing binary value.
    /// </summary>
    public static byte[] MergeEntity(
        ReadOnlySpan<byte> jsonUtf8,
        ReadOnlySpan<byte> existingBinary,
        FieldPlan[] plan,
        JsonPropertyLookup[] lookup,
        int schemaVersion = 1)
    {
        var fieldCount = plan.Length;

        // Parse existing binary row into per-field value slots
        var slots = new byte[fieldCount][];
        var slotSet = new bool[fieldCount];
        ExtractFieldsFromBinary(existingBinary, plan, slots, slotSet);

        // Overlay JSON values onto existing slots
        ParseJsonObject(jsonUtf8, plan, lookup, slots, slotSet);

        return AssembleBinaryRow(plan, slots, slotSet, schemaVersion);
    }

    /// <summary>Stream overload for MergeEntity.</summary>
    public static byte[] MergeEntity(
        Stream input,
        ReadOnlySpan<byte> existingBinary,
        FieldPlan[] plan,
        JsonPropertyLookup[] lookup,
        int schemaVersion = 1)
    {
        var jsonBytes = ReadStreamToBytes(input);
        return MergeEntity(jsonBytes.AsSpan(), existingBinary, plan, lookup, schemaVersion);
    }

    // ────────────── JSON parser ──────────────

    private static void ParseJsonObject(
        ReadOnlySpan<byte> json,
        FieldPlan[] plan,
        JsonPropertyLookup[] lookup,
        byte[][] slots,
        bool[] slotSet)
    {
        int pos = SkipWhitespace(json, 0);
        if (pos >= json.Length || json[pos] != (byte)'{')
            throw new InvalidOperationException("Expected JSON object '{'.");
        pos++; // skip '{'

        bool expectComma = false;
        while (pos < json.Length)
        {
            pos = SkipWhitespace(json, pos);
            if (pos >= json.Length) break;
            if (json[pos] == (byte)'}') break; // end of object

            if (expectComma)
            {
                if (json[pos] != (byte)',')
                    throw new InvalidOperationException("Expected ',' between JSON properties.");
                pos++;
                pos = SkipWhitespace(json, pos);
            }

            // Read property name
            if (pos >= json.Length || json[pos] != (byte)'"')
                throw new InvalidOperationException("Expected '\"' for property name.");
            var propName = ReadJsonString(json, pos, out var propEnd);
            pos = propEnd;

            // Colon
            pos = SkipWhitespace(json, pos);
            if (pos >= json.Length || json[pos] != (byte)':')
                throw new InvalidOperationException("Expected ':' after property name.");
            pos++;

            // Find field ordinal
            int ordinal = FindOrdinal(propName, lookup);

            // Read value
            pos = SkipWhitespace(json, pos);
            if (ordinal >= 0)
            {
                // Known field: parse value into binary slot
                var (value, valueEnd) = ParseFieldValue(json, pos, plan[ordinal]);
                slots[ordinal] = value;
                slotSet[ordinal] = true;
                pos = valueEnd;
            }
            else
            {
                // Unknown field: skip value
                pos = SkipJsonValue(json, pos);
            }

            expectComma = true;
        }
    }

    // ────────────── Field value parsing ──────────────

    /// <summary>
    /// Parses a JSON value at <paramref name="pos"/> and returns the binary-encoded
    /// field value bytes and the position after the value.
    /// </summary>
    private static (byte[] value, int endPos) ParseFieldValue(ReadOnlySpan<byte> json, int pos, FieldPlan fp)
    {
        // Handle null
        if (pos + 4 <= json.Length && json[pos] == (byte)'n' &&
            json[pos + 1] == (byte)'u' && json[pos + 2] == (byte)'l' && json[pos + 3] == (byte)'l')
        {
            // Null value — encode null indicator if nullable, else default
            if (fp.IsNullable)
                return ([0], pos + 4);
            return (EncodeDefault(fp), pos + 4);
        }

        switch (fp.WireType)
        {
            case WireFieldType.Bool:
                return ParseBoolValue(json, pos, fp.IsNullable);

            case WireFieldType.Byte:
            case WireFieldType.SByte:
            case WireFieldType.Int16:
            case WireFieldType.UInt16:
            case WireFieldType.Int32:
            case WireFieldType.UInt32:
            case WireFieldType.Int64:
            case WireFieldType.UInt64:
            case WireFieldType.Float32:
            case WireFieldType.Float64:
            case WireFieldType.Decimal:
                return ParseNumericValue(json, pos, fp);

            case WireFieldType.Char:
                return ParseCharValue(json, pos, fp.IsNullable);

            case WireFieldType.String:
                return ParseStringValue(json, pos, fp.IsNullable);

            case WireFieldType.Guid:
                return ParseGuidValue(json, pos, fp.IsNullable);

            case WireFieldType.DateTime:
                return ParseDateTimeValue(json, pos, fp.IsNullable);

            case WireFieldType.DateOnly:
                return ParseDateOnlyValue(json, pos, fp.IsNullable);

            case WireFieldType.TimeOnly:
                return ParseTimeOnlyValue(json, pos, fp.IsNullable);

            case WireFieldType.DateTimeOffset:
                return ParseDateTimeOffsetValue(json, pos, fp.IsNullable);

            case WireFieldType.TimeSpan:
                return ParseTimeSpanValue(json, pos, fp.IsNullable);

            case WireFieldType.Identifier:
                return ParseIdentifierValue(json, pos, fp.IsNullable);

            case WireFieldType.Enum:
                return ParseEnumValue(json, pos, fp);

            default:
                // Fallback: treat as string
                return ParseStringValue(json, pos, fp.IsNullable);
        }
    }

    private static (byte[] value, int endPos) ParseBoolValue(ReadOnlySpan<byte> json, int pos, bool isNullable)
    {
        bool val;
        int endPos;

        if (pos + 4 <= json.Length && json[pos] == (byte)'t' &&
            json[pos + 1] == (byte)'r' && json[pos + 2] == (byte)'u' && json[pos + 3] == (byte)'e')
        {
            val = true;
            endPos = pos + 4;
        }
        else if (pos + 5 <= json.Length && json[pos] == (byte)'f' &&
                 json[pos + 1] == (byte)'a' && json[pos + 2] == (byte)'l' &&
                 json[pos + 3] == (byte)'s' && json[pos + 4] == (byte)'e')
        {
            val = false;
            endPos = pos + 5;
        }
        else if (json[pos] == (byte)'"')
        {
            // String "true"/"false"
            var str = ReadJsonString(json, pos, out var strEnd);
            val = str.SequenceEqual("true"u8);
            endPos = strEnd;
        }
        else
        {
            throw new InvalidOperationException("Invalid boolean value.");
        }

        if (isNullable)
            return ([1, val ? (byte)1 : (byte)0], endPos);
        return ([val ? (byte)1 : (byte)0], endPos);
    }

    private static (byte[] value, int endPos) ParseNumericValue(ReadOnlySpan<byte> json, int pos, FieldPlan fp)
    {
        // Number could be a JSON number or quoted string
        ReadOnlySpan<byte> numSpan;
        int endPos;

        if (json[pos] == (byte)'"')
        {
            // Quoted number
            var str = ReadJsonString(json, pos, out var strEnd);
            numSpan = str;
            endPos = strEnd;
        }
        else
        {
            // Raw JSON number
            var numEnd = pos;
            while (numEnd < json.Length && IsNumberChar(json[numEnd]))
                numEnd++;
            numSpan = json[pos..numEnd];
            endPos = numEnd;
        }

        var encoded = EncodeNumeric(numSpan, fp);
        return (encoded, endPos);
    }

    private static byte[] EncodeNumeric(ReadOnlySpan<byte> utf8Num, FieldPlan fp)
    {
        var buf = new ArrayBufferWriter<byte>(fp.IsNullable ? 17 : 16);
        var writer = new SpanWriter(buf);

        if (fp.IsNullable) writer.WriteByte(1); // has value

        switch (fp.WireType)
        {
            case WireFieldType.Byte:
                Utf8Parser.TryParse(utf8Num, out byte byteVal, out _);
                writer.WriteByte(byteVal);
                break;
            case WireFieldType.SByte:
                Utf8Parser.TryParse(utf8Num, out sbyte sbyteVal, out _);
                writer.WriteSByte(sbyteVal);
                break;
            case WireFieldType.Int16:
                Utf8Parser.TryParse(utf8Num, out short i16, out _);
                writer.WriteInt16(i16);
                break;
            case WireFieldType.UInt16:
                Utf8Parser.TryParse(utf8Num, out ushort u16, out _);
                writer.WriteUInt16(u16);
                break;
            case WireFieldType.Int32:
                Utf8Parser.TryParse(utf8Num, out int i32, out _);
                writer.WriteInt32(i32);
                break;
            case WireFieldType.UInt32:
                Utf8Parser.TryParse(utf8Num, out uint u32, out _);
                writer.WriteUInt32(u32);
                break;
            case WireFieldType.Int64:
                Utf8Parser.TryParse(utf8Num, out long i64, out _);
                writer.WriteInt64(i64);
                break;
            case WireFieldType.UInt64:
                Utf8Parser.TryParse(utf8Num, out ulong u64, out _);
                writer.WriteUInt64(u64);
                break;
            case WireFieldType.Float32:
                Utf8Parser.TryParse(utf8Num, out float f32, out _);
                writer.WriteSingle(f32);
                break;
            case WireFieldType.Float64:
                Utf8Parser.TryParse(utf8Num, out double f64, out _);
                writer.WriteDouble(f64);
                break;
            case WireFieldType.Decimal:
                Utf8Parser.TryParse(utf8Num, out decimal dec, out _);
                writer.WriteDecimal(dec);
                break;
        }

        writer.Commit();
        return buf.WrittenSpan.ToArray();
    }

    private static (byte[] value, int endPos) ParseCharValue(ReadOnlySpan<byte> json, int pos, bool isNullable)
    {
        var str = ReadJsonString(json, pos, out var strEnd);
        char ch = '\0';
        if (str.Length > 0)
        {
            Span<char> chars = stackalloc char[2];
            int decoded = Encoding.UTF8.GetChars(str[..Math.Min(str.Length, 4)], chars);
            if (decoded > 0) ch = chars[0];
        }

        var buf = new byte[isNullable ? 3 : 2];
        int off = 0;
        if (isNullable) buf[off++] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(buf.AsSpan(off), ch);
        return (buf, strEnd);
    }

    private static (byte[] value, int endPos) ParseStringValue(ReadOnlySpan<byte> json, int pos, bool isNullable)
    {
        if (json[pos] == (byte)'"')
        {
            var str = ReadJsonString(json, pos, out var strEnd);
            var byteCount = str.Length;

            // Encode: [nullable indicator?] + [int32 length] + [utf8 bytes]
            var resultLen = (isNullable ? 1 : 0) + 4 + byteCount;
            var result = new byte[resultLen];
            int off = 0;
            if (isNullable) result[off++] = 1;
            BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(off), byteCount);
            off += 4;
            str.CopyTo(result.AsSpan(off));
            return (result, strEnd);
        }

        // Non-string JSON value for a string field — convert to string representation
        var valEnd = SkipJsonValue(json, pos);
        var raw = json[pos..valEnd];
        var rawLen = raw.Length;
        var res = new byte[(isNullable ? 1 : 0) + 4 + rawLen];
        int o = 0;
        if (isNullable) res[o++] = 1;
        BinaryPrimitives.WriteInt32LittleEndian(res.AsSpan(o), rawLen);
        o += 4;
        raw.CopyTo(res.AsSpan(o));
        return (res, valEnd);
    }

    private static (byte[] value, int endPos) ParseGuidValue(ReadOnlySpan<byte> json, int pos, bool isNullable)
    {
        var str = ReadJsonString(json, pos, out var strEnd);
        Guid guid = Guid.Empty;
        if (str.Length > 0)
        {
            Span<char> chars = stackalloc char[str.Length];
            Encoding.UTF8.GetChars(str, chars);
            Guid.TryParse(chars, out guid);
        }

        var result = new byte[(isNullable ? 1 : 0) + 16];
        int off = 0;
        if (isNullable) result[off++] = 1;
        guid.TryWriteBytes(result.AsSpan(off));
        return (result, strEnd);
    }

    private static (byte[] value, int endPos) ParseDateTimeValue(ReadOnlySpan<byte> json, int pos, bool isNullable)
    {
        var str = ReadJsonString(json, pos, out var strEnd);
        DateTime dt = default;
        if (str.Length > 0)
        {
            Span<char> chars = stackalloc char[str.Length];
            Encoding.UTF8.GetChars(str, chars);
            DateTime.TryParse(chars, out dt);
        }

        // DateTime: int64 ticks + byte kind = 9 bytes
        var result = new byte[(isNullable ? 1 : 0) + 9];
        int off = 0;
        if (isNullable) result[off++] = 1;
        BinaryPrimitives.WriteInt64LittleEndian(result.AsSpan(off), dt.Ticks);
        off += 8;
        result[off] = (byte)dt.Kind;
        return (result, strEnd);
    }

    private static (byte[] value, int endPos) ParseDateOnlyValue(ReadOnlySpan<byte> json, int pos, bool isNullable)
    {
        var str = ReadJsonString(json, pos, out var strEnd);
        DateOnly d = default;
        if (str.Length > 0)
        {
            Span<char> chars = stackalloc char[str.Length];
            Encoding.UTF8.GetChars(str, chars);
            DateOnly.TryParse(chars, out d);
        }

        var result = new byte[(isNullable ? 1 : 0) + 4];
        int off = 0;
        if (isNullable) result[off++] = 1;
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(off), d.DayNumber);
        return (result, strEnd);
    }

    private static (byte[] value, int endPos) ParseTimeOnlyValue(ReadOnlySpan<byte> json, int pos, bool isNullable)
    {
        var str = ReadJsonString(json, pos, out var strEnd);
        TimeOnly t = default;
        if (str.Length > 0)
        {
            Span<char> chars = stackalloc char[str.Length];
            Encoding.UTF8.GetChars(str, chars);
            TimeOnly.TryParse(chars, out t);
        }

        var result = new byte[(isNullable ? 1 : 0) + 8];
        int off = 0;
        if (isNullable) result[off++] = 1;
        BinaryPrimitives.WriteInt64LittleEndian(result.AsSpan(off), t.Ticks);
        return (result, strEnd);
    }

    private static (byte[] value, int endPos) ParseDateTimeOffsetValue(ReadOnlySpan<byte> json, int pos, bool isNullable)
    {
        var str = ReadJsonString(json, pos, out var strEnd);
        DateTimeOffset dto = default;
        if (str.Length > 0)
        {
            Span<char> chars = stackalloc char[str.Length];
            Encoding.UTF8.GetChars(str, chars);
            DateTimeOffset.TryParse(chars, out dto);
        }

        // DateTimeOffset: int64 ticks + int16 offset minutes = 10 bytes
        var result = new byte[(isNullable ? 1 : 0) + 10];
        int off = 0;
        if (isNullable) result[off++] = 1;
        BinaryPrimitives.WriteInt64LittleEndian(result.AsSpan(off), dto.Ticks);
        off += 8;
        BinaryPrimitives.WriteInt16LittleEndian(result.AsSpan(off), (short)dto.Offset.TotalMinutes);
        return (result, strEnd);
    }

    private static (byte[] value, int endPos) ParseTimeSpanValue(ReadOnlySpan<byte> json, int pos, bool isNullable)
    {
        var str = ReadJsonString(json, pos, out var strEnd);
        TimeSpan ts = default;
        if (str.Length > 0)
        {
            Span<char> chars = stackalloc char[str.Length];
            Encoding.UTF8.GetChars(str, chars);
            TimeSpan.TryParse(chars, out ts);
        }

        var result = new byte[(isNullable ? 1 : 0) + 8];
        int off = 0;
        if (isNullable) result[off++] = 1;
        BinaryPrimitives.WriteInt64LittleEndian(result.AsSpan(off), ts.Ticks);
        return (result, strEnd);
    }

    private static (byte[] value, int endPos) ParseIdentifierValue(ReadOnlySpan<byte> json, int pos, bool isNullable)
    {
        var str = ReadJsonString(json, pos, out var strEnd);
        IdentifierValue id = IdentifierValue.Empty;
        if (str.Length > 0)
        {
            var s = Encoding.UTF8.GetString(str);
            IdentifierValue.TryParse(s, out id);
        }

        var result = new byte[(isNullable ? 1 : 0) + 16];
        int off = 0;
        if (isNullable) result[off++] = 1;
        id.WriteTo(result.AsSpan(off));
        return (result, strEnd);
    }

    private static (byte[] value, int endPos) ParseEnumValue(ReadOnlySpan<byte> json, int pos, FieldPlan fp)
    {
        // Enum can be a number or a string name
        int enumInt = 0;
        int endPos;

        if (json[pos] == (byte)'"')
        {
            // String enum name — we can't resolve by name without the CLR type,
            // so we try parsing as an integer string
            var str = ReadJsonString(json, pos, out var strEnd);
            Utf8Parser.TryParse(str, out enumInt, out _);
            endPos = strEnd;
        }
        else
        {
            // Numeric enum
            var numEnd = pos;
            while (numEnd < json.Length && IsNumberChar(json[numEnd]))
                numEnd++;
            Utf8Parser.TryParse(json[pos..numEnd], out enumInt, out _);
            endPos = numEnd;
        }

        // Encode as the underlying type
        var underlying = fp.EnumUnderlying == default ? WireFieldType.Int32 : fp.EnumUnderlying;
        var buf = new ArrayBufferWriter<byte>(fp.IsNullable ? 9 : 8);
        var writer = new SpanWriter(buf);
        if (fp.IsNullable) writer.WriteByte(1);

        switch (underlying)
        {
            case WireFieldType.Byte: writer.WriteByte((byte)enumInt); break;
            case WireFieldType.SByte: writer.WriteSByte((sbyte)enumInt); break;
            case WireFieldType.Int16: writer.WriteInt16((short)enumInt); break;
            case WireFieldType.UInt16: writer.WriteUInt16((ushort)enumInt); break;
            case WireFieldType.Int32: writer.WriteInt32(enumInt); break;
            case WireFieldType.UInt32: writer.WriteUInt32((uint)enumInt); break;
            case WireFieldType.Int64: writer.WriteInt64(enumInt); break;
            case WireFieldType.UInt64: writer.WriteUInt64((ulong)enumInt); break;
            default: writer.WriteInt32(enumInt); break;
        }
        writer.Commit();
        return (buf.WrittenSpan.ToArray(), endPos);
    }

    // ────────────── Binary assembly ──────────────

    private static byte[] AssembleBinaryRow(FieldPlan[] plan, byte[][] slots, bool[] slotSet, int schemaVersion)
    {
        // Calculate total size
        int totalSize = HeaderSize + 1; // header + entity null indicator
        for (int i = 0; i < plan.Length; i++)
        {
            if (slotSet[i] && slots[i] != null)
            {
                totalSize += slots[i].Length;
            }
            else
            {
                totalSize += GetDefaultFieldSize(plan[i]);
            }
        }

        var result = new byte[totalSize];
        int off = 0;

        // Write BSO1 header
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(off), Magic);
        off += 4;
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(off), CurrentVersion);
        off += 4;
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(off), schemaVersion);
        off += 4;
        result[off++] = (byte)BinaryArchitectureMapper.Current;
        // Signature placeholder (32 bytes of zeros — caller signs)
        off += 32;

        // Entity null indicator
        result[off++] = 1; // entity is not null

        // Write fields in ordinal order
        for (int i = 0; i < plan.Length; i++)
        {
            if (slotSet[i] && slots[i] != null)
            {
                slots[i].CopyTo(result.AsSpan(off));
                off += slots[i].Length;
            }
            else
            {
                off += WriteDefaultField(result.AsSpan(off), plan[i]);
            }
        }

        return result;
    }

    // ────────────── Extract fields from existing binary ──────────────

    private static void ExtractFieldsFromBinary(ReadOnlySpan<byte> binary, FieldPlan[] plan, byte[][] slots, bool[] slotSet)
    {
        if (binary.Length < HeaderSize + 1) return;

        var reader = new SpanReader(binary[HeaderSize..]);
        var hasValue = reader.ReadByte();
        if (hasValue == 0) return;

        for (int i = 0; i < plan.Length; i++)
        {
            int startPos = binary.Length - reader.Remaining;
            var fp = plan[i];

            if (fp.IsNullable)
            {
                var hasFieldValue = reader.ReadByte();
                if (hasFieldValue == 0)
                {
                    // Null — store just the null indicator
                    slots[i] = [0];
                    slotSet[i] = true;
                    continue;
                }
            }

            // Read the field value from binary (advance reader)
            int beforeRemaining = reader.Remaining;
            SkipBinaryFieldValue(ref reader, fp.WireType, fp.EnumUnderlying);
            int valueSize = beforeRemaining - reader.Remaining;

            // Capture the entire field bytes (including nullable indicator)
            int totalFieldBytes = binary.Length - reader.Remaining - startPos;
            var fieldBytes = new byte[totalFieldBytes];
            binary.Slice(startPos, totalFieldBytes).CopyTo(fieldBytes);
            slots[i] = fieldBytes;
            slotSet[i] = true;
        }
    }

    private static void SkipBinaryFieldValue(ref SpanReader reader, WireFieldType wireType, WireFieldType enumUnderlying)
    {
        switch (wireType)
        {
            case WireFieldType.Bool: reader.ReadByte(); break;
            case WireFieldType.Byte: reader.ReadByte(); break;
            case WireFieldType.SByte: reader.ReadByte(); break;
            case WireFieldType.Int16: reader.ReadInt16(); break;
            case WireFieldType.UInt16: reader.ReadUInt16(); break;
            case WireFieldType.Int32: reader.ReadInt32(); break;
            case WireFieldType.UInt32: reader.ReadUInt32(); break;
            case WireFieldType.Int64: reader.ReadInt64(); break;
            case WireFieldType.UInt64: reader.ReadUInt64(); break;
            case WireFieldType.Float32: reader.ReadSingle(); break;
            case WireFieldType.Float64: reader.ReadDouble(); break;
            case WireFieldType.Decimal: reader.ReadDecimal(); break;
            case WireFieldType.Char: reader.ReadChar(); break;
            case WireFieldType.Guid:
            {
                Span<byte> skip = stackalloc byte[16];
                reader.ReadBytes(skip);
                break;
            }
            case WireFieldType.DateTime:
                reader.ReadInt64(); // ticks
                reader.ReadByte();  // kind
                break;
            case WireFieldType.DateOnly: reader.ReadInt32(); break;
            case WireFieldType.TimeOnly: reader.ReadInt64(); break;
            case WireFieldType.DateTimeOffset:
                reader.ReadInt64(); // ticks
                reader.ReadInt16(); // offset
                break;
            case WireFieldType.TimeSpan: reader.ReadInt64(); break;
            case WireFieldType.Identifier:
            {
                Span<byte> skip = stackalloc byte[16];
                reader.ReadBytes(skip);
                break;
            }
            case WireFieldType.String:
            {
                var len = reader.ReadInt32();
                if (len > 0)
                {
                    // Skip string bytes
                    if (len <= 512)
                    {
                        Span<byte> skip = stackalloc byte[len];
                        reader.ReadBytes(skip);
                    }
                    else
                    {
                        var rented = ArrayPool<byte>.Shared.Rent(len);
                        try { reader.ReadBytes(rented.AsSpan(0, len)); }
                        finally { ArrayPool<byte>.Shared.Return(rented); }
                    }
                }
                break;
            }
            case WireFieldType.Enum:
                SkipBinaryFieldValue(ref reader, enumUnderlying == default ? WireFieldType.Int32 : enumUnderlying, default);
                break;
        }
    }

    // ────────────── Default field encoding ──────────────

    private static int GetDefaultFieldSize(FieldPlan fp)
    {
        if (fp.IsNullable) return 1; // just the null indicator (0)

        return fp.WireType switch
        {
            WireFieldType.Bool => 1,
            WireFieldType.Byte => 1,
            WireFieldType.SByte => 1,
            WireFieldType.Int16 => 2,
            WireFieldType.UInt16 => 2,
            WireFieldType.Int32 => 4,
            WireFieldType.UInt32 => 4,
            WireFieldType.Int64 => 8,
            WireFieldType.UInt64 => 8,
            WireFieldType.Float32 => 4,
            WireFieldType.Float64 => 8,
            WireFieldType.Decimal => 16,
            WireFieldType.Char => 2,
            WireFieldType.Guid => 16,
            WireFieldType.DateTime => 9,    // ticks(8) + kind(1)
            WireFieldType.DateOnly => 4,
            WireFieldType.TimeOnly => 8,
            WireFieldType.DateTimeOffset => 10, // ticks(8) + offset(2)
            WireFieldType.TimeSpan => 8,
            WireFieldType.Identifier => 16,
            WireFieldType.String => 4,      // length prefix = -1 (null) or 0
            WireFieldType.Enum => GetEnumSize(fp.EnumUnderlying),
            _ => 4,                         // fallback: string null
        };
    }

    private static int GetEnumSize(WireFieldType underlying) => underlying switch
    {
        WireFieldType.Byte or WireFieldType.SByte => 1,
        WireFieldType.Int16 or WireFieldType.UInt16 => 2,
        WireFieldType.Int64 or WireFieldType.UInt64 => 8,
        _ => 4,
    };

    private static int WriteDefaultField(Span<byte> dest, FieldPlan fp)
    {
        if (fp.IsNullable)
        {
            dest[0] = 0; // null
            return 1;
        }

        int size = GetDefaultFieldSize(fp);
        dest[..size].Clear(); // zero-fill = default value for all types

        // String default is null (-1 length)
        if (fp.WireType == WireFieldType.String)
            BinaryPrimitives.WriteInt32LittleEndian(dest, -1);

        return size;
    }

    // ────────────── JSON tokenizer helpers ──────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int SkipWhitespace(ReadOnlySpan<byte> json, int pos)
    {
        while (pos < json.Length && (json[pos] == (byte)' ' || json[pos] == (byte)'\t' ||
               json[pos] == (byte)'\r' || json[pos] == (byte)'\n'))
            pos++;
        return pos;
    }

    /// <summary>
    /// Reads a JSON string starting at the opening quote, returns the unescaped
    /// UTF-8 content and sets <paramref name="endPos"/> to the position after the closing quote.
    /// </summary>
    private static ReadOnlySpan<byte> ReadJsonString(ReadOnlySpan<byte> json, int pos, out int endPos)
    {
        if (json[pos] != (byte)'"')
            throw new InvalidOperationException("Expected '\"'.");
        pos++; // skip opening quote

        // Fast path: scan for closing quote without escapes
        int start = pos;
        bool hasEscapes = false;
        while (pos < json.Length)
        {
            byte b = json[pos];
            if (b == (byte)'"')
            {
                if (!hasEscapes)
                {
                    endPos = pos + 1;
                    return json[start..pos];
                }
                break;
            }
            if (b == (byte)'\\')
            {
                hasEscapes = true;
                pos += 2; // skip escape sequence
                continue;
            }
            pos++;
        }

        if (!hasEscapes)
            throw new InvalidOperationException("Unterminated JSON string.");

        // Slow path: unescape into a rented buffer
        int maxLen = pos - start;
        var rented = ArrayPool<byte>.Shared.Rent(maxLen);
        int writeIdx = 0;
        int readIdx = start;
        while (readIdx < pos)
        {
            byte b = json[readIdx];
            if (b == (byte)'\\' && readIdx + 1 < pos)
            {
                readIdx++;
                byte esc = json[readIdx];
                rented[writeIdx++] = esc switch
                {
                    (byte)'"' => (byte)'"',
                    (byte)'\\' => (byte)'\\',
                    (byte)'/' => (byte)'/',
                    (byte)'n' => (byte)'\n',
                    (byte)'r' => (byte)'\r',
                    (byte)'t' => (byte)'\t',
                    (byte)'b' => (byte)'\b',
                    (byte)'f' => 0x0C,
                    (byte)'u' => HandleUnicodeEscape(json, ref readIdx, rented, ref writeIdx),
                    _ => esc,
                };
                readIdx++;
            }
            else
            {
                rented[writeIdx++] = b;
                readIdx++;
            }
        }

        // Copy to right-sized result and return rental
        var result = new byte[writeIdx];
        rented.AsSpan(0, writeIdx).CopyTo(result);
        ArrayPool<byte>.Shared.Return(rented);

        endPos = pos + 1;
        return result;
    }

    private static byte HandleUnicodeEscape(ReadOnlySpan<byte> json, ref int readIdx, byte[] dest, ref int writeIdx)
    {
        // \uXXXX — parse 4 hex digits
        if (readIdx + 4 >= json.Length) return (byte)'?';
        Span<char> hexChars = stackalloc char[4];
        for (int h = 0; h < 4; h++)
            hexChars[h] = (char)json[readIdx + 1 + h];
        readIdx += 4;

        if (ushort.TryParse(hexChars, System.Globalization.NumberStyles.HexNumber, null, out ushort codePoint))
        {
            if (codePoint < 0x80)
                return (byte)codePoint;

            // Multi-byte UTF-8
            Span<char> chars = stackalloc char[1] { (char)codePoint };
            Span<byte> utf8 = stackalloc byte[4];
            int len = Encoding.UTF8.GetBytes(chars, utf8);
            // Write extra bytes (first byte returned directly)
            for (int i = 1; i < len; i++)
                dest[writeIdx++] = utf8[i];
            return utf8[0];
        }
        return (byte)'?';
    }

    /// <summary>
    /// Skips over a JSON value (string, number, object, array, true, false, null)
    /// and returns the position after the value.
    /// </summary>
    private static int SkipJsonValue(ReadOnlySpan<byte> json, int pos)
    {
        if (pos >= json.Length)
            throw new InvalidOperationException("Unexpected end of JSON.");

        byte b = json[pos];

        // String
        if (b == (byte)'"')
        {
            ReadJsonString(json, pos, out var endPos);
            return endPos;
        }

        // Object
        if (b == (byte)'{')
        {
            pos++;
            int depth = 1;
            while (pos < json.Length && depth > 0)
            {
                if (json[pos] == (byte)'{') depth++;
                else if (json[pos] == (byte)'}') depth--;
                else if (json[pos] == (byte)'"') { ReadJsonString(json, pos, out var ep); pos = ep; continue; }
                pos++;
            }
            return pos;
        }

        // Array
        if (b == (byte)'[')
        {
            pos++;
            int depth = 1;
            while (pos < json.Length && depth > 0)
            {
                if (json[pos] == (byte)'[') depth++;
                else if (json[pos] == (byte)']') depth--;
                else if (json[pos] == (byte)'"') { ReadJsonString(json, pos, out var ep); pos = ep; continue; }
                pos++;
            }
            return pos;
        }

        // true/false/null/number
        while (pos < json.Length && json[pos] != (byte)',' && json[pos] != (byte)'}' &&
               json[pos] != (byte)']' && json[pos] != (byte)' ' &&
               json[pos] != (byte)'\t' && json[pos] != (byte)'\r' && json[pos] != (byte)'\n')
            pos++;
        return pos;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsNumberChar(byte b) =>
        (b >= (byte)'0' && b <= (byte)'9') || b == (byte)'-' || b == (byte)'+' ||
        b == (byte)'.' || b == (byte)'e' || b == (byte)'E';

    // ────────────── Ordinal lookup ──────────────

    private static int FindOrdinal(ReadOnlySpan<byte> propertyName, JsonPropertyLookup[] lookup)
    {
        for (int i = 0; i < lookup.Length; i++)
        {
            if (propertyName.SequenceEqual(lookup[i].NameUtf8))
                return lookup[i].Ordinal;
        }
        // Case-insensitive fallback
        for (int i = 0; i < lookup.Length; i++)
        {
            if (propertyName.Length == lookup[i].NameUtf8.Length &&
                Ascii.EqualsIgnoreCase(propertyName, lookup[i].NameUtf8))
                return lookup[i].Ordinal;
        }
        return -1; // unknown field
    }

    private static byte[] EncodeDefault(FieldPlan fp)
    {
        var size = GetDefaultFieldSize(fp);
        var buf = new byte[size];
        if (fp.WireType == WireFieldType.String)
            BinaryPrimitives.WriteInt32LittleEndian(buf, -1);
        return buf;
    }

    // ────────────── Stream helpers ──────────────

    private static byte[] ReadStreamToBytes(Stream input)
    {
        if (input is MemoryStream ms && ms.TryGetBuffer(out var msBuffer))
            return msBuffer.Array!.AsSpan(msBuffer.Offset, msBuffer.Count).ToArray();

        if (input.CanSeek)
        {
            int length = (int)(input.Length - input.Position);
            var rented = ArrayPool<byte>.Shared.Rent(length);
            try
            {
                input.ReadExactly(rented, 0, length);
                var result = new byte[length];
                rented.AsSpan(0, length).CopyTo(result);
                return result;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }

        using var buffer = new MemoryStream();
        input.CopyTo(buffer);
        return buffer.ToArray();
    }
}
