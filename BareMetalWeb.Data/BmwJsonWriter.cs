using System.Buffers;
using System.Buffers.Text;
using System.Collections;
using System.Runtime.CompilerServices;
using System.Text;
using WireFieldType = BareMetalWeb.Data.MetadataWireSerializer.WireFieldType;
using FieldPlan = BareMetalWeb.Data.MetadataWireSerializer.FieldPlan;

namespace BareMetalWeb.Data;

/// <summary>
/// Single-pass streaming JSON serializer that reads BSO1 binary row spans
/// and emits UTF-8 JSON directly to a <see cref="Stream"/> — no CLR object
/// materialisation, no System.Text.Json dependency.
///
/// At startup, call <see cref="BuildFragments"/> once per entity type to
/// cache UTF-8 property-name fragments. At request time, call
/// <see cref="WriteEntity"/> or <see cref="WriteEntityList"/> with the
/// binary payload from WAL/wire and the cached fragments.
/// </summary>
public static class BmwJsonWriter
{
    private const int HeaderSize = 45; // magic(4) + version(4) + schema(4) + arch(1) + sig(32)
    private const int MaxStringBytes = 4 * 1024 * 1024;

    // Precomputed JSON literal fragments (UTF-8) — ReadOnlySpan properties
    // JIT inlines these; they point directly at the assembly's static data section (zero allocation).
    private static ReadOnlySpan<byte> JsonObjectStart => "{"u8;
    private static ReadOnlySpan<byte> JsonObjectEnd => "}"u8;
    private static ReadOnlySpan<byte> JsonArrayStart => "["u8;
    private static ReadOnlySpan<byte> JsonArrayEnd => "]"u8;
    private static ReadOnlySpan<byte> JsonNull => "null"u8;
    private static ReadOnlySpan<byte> JsonTrue => "true"u8;
    private static ReadOnlySpan<byte> JsonFalse => "false"u8;
    private static ReadOnlySpan<byte> JsonQuote => "\""u8;
    private static ReadOnlySpan<byte> JsonComma => ","u8;
    private static ReadOnlySpan<byte> DataPrefix => "\"data\":"u8;
    private static ReadOnlySpan<byte> CountPrefix => ",\"count\":"u8;

    // ────────────── Fragment plan ──────────────

    /// <summary>
    /// Precomputed UTF-8 fragment for a single field: <c>,"propertyName":</c>
    /// (first field omits leading comma). Built once at startup.
    /// </summary>
    public sealed class JsonFieldFragment
    {
        /// <summary>UTF-8 bytes for the property prefix (e.g. <c>,"name":</c>).</summary>
        public required byte[] Prefix { get; init; }
        public required WireFieldType WireType { get; init; }
        public required bool IsNullable { get; init; }
        public required WireFieldType EnumUnderlying { get; init; }
    }

    /// <summary>
    /// Builds an ordinal-indexed array of <see cref="JsonFieldFragment"/> from
    /// a <see cref="FieldPlan"/> array. Call once per entity type at startup.
    /// </summary>
    public static JsonFieldFragment[] BuildFragments(FieldPlan[] plan)
    {
        var frags = new JsonFieldFragment[plan.Length];
        for (int i = 0; i < plan.Length; i++)
        {
            var fp = plan[i];
            // Build UTF-8 prefix: ,"propertyName":  (first field has no comma)
            var prefix = i == 0
                ? $"\"{fp.Name}\":"
                : $",\"{fp.Name}\":";
            frags[i] = new JsonFieldFragment
            {
                Prefix = Encoding.UTF8.GetBytes(prefix),
                WireType = fp.WireType,
                IsNullable = fp.IsNullable,
                EnumUnderlying = fp.EnumUnderlying,
            };
        }
        return frags;
    }

    // ────────────── Single entity ──────────────

    /// <summary>
    /// Transcodes a single BSO1 binary row directly to a JSON object on <paramref name="output"/>.
    /// No CLR object is created — values are read from the binary span and
    /// formatted as UTF-8 JSON inline.
    /// </summary>
    public static void WriteEntity(Stream output, ReadOnlySpan<byte> rowBinary, JsonFieldFragment[] fragments)
    {
        if (rowBinary.Length < HeaderSize + 1)
            throw new InvalidOperationException("Binary payload too short for BSO1 header.");

        // Skip BSO1 header (45 bytes)
        var reader = new SpanReader(rowBinary[HeaderSize..]);

        // Entity null indicator
        var hasValue = reader.ReadByte();
        if (hasValue == 0)
        {
            output.Write(JsonNull);
            return;
        }

        output.Write(JsonObjectStart);
        WriteFieldsFromBinary(output, ref reader, fragments);
        output.Write(JsonObjectEnd);
    }

    /// <summary>
    /// Transcodes a list of BSO1 binary rows to <c>{"data":[...],"count":N}</c>.
    /// Each row is independently transcoded — no intermediate object allocation.
    /// </summary>
    public static void WriteEntityList(Stream output, IReadOnlyList<ReadOnlyMemory<byte>> rows, JsonFieldFragment[] fragments, int count)
    {
        output.Write(JsonObjectStart);
        output.Write(DataPrefix);
        output.Write(JsonArrayStart);

        for (int r = 0; r < rows.Count; r++)
        {
            if (r > 0) output.Write(JsonComma);
            WriteEntity(output, rows[r].Span, fragments);
        }

        output.Write(JsonArrayEnd);

        // ,"count":N
        output.Write(CountPrefix);
        Span<byte> numBuf = stackalloc byte[20];
        if (Utf8Formatter.TryFormat(count, numBuf, out int written))
            output.Write(numBuf[..written]);
        else
            output.Write("0"u8);

        output.Write(JsonObjectEnd);
    }

    /// <summary>
    /// Overload accepting materialized objects — serializes each entity to BSO1
    /// binary via <paramref name="serializer"/> then transcodes to JSON.
    /// Useful as transitional path before raw-binary data handlers are available.
    /// </summary>
    public static void WriteEntityListFromObjects(
        Stream output,
        IEnumerable items,
        FieldPlan[] plan,
        JsonFieldFragment[] fragments,
        MetadataWireSerializer serializer,
        int count)
    {
        output.Write(JsonObjectStart);
        output.Write(DataPrefix);
        output.Write(JsonArrayStart);

        bool first = true;
        foreach (var item in items)
        {
            if (item is null) continue;
            if (!first) output.Write(JsonComma);
            first = false;
            var binary = serializer.Serialize(item, plan, 1);
            WriteEntity(output, binary, fragments);
        }

        output.Write(JsonArrayEnd);
        output.Write(CountPrefix);
        Span<byte> numBuf = stackalloc byte[20];
        if (Utf8Formatter.TryFormat(count, numBuf, out int written))
            output.Write(numBuf[..written]);
        else
            output.Write("0"u8);
        output.Write(JsonObjectEnd);
    }

    // ────────────── Field iteration ──────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteFieldsFromBinary(Stream output, ref SpanReader reader, JsonFieldFragment[] fragments)
    {
        for (int i = 0; i < fragments.Length; i++)
        {
            var frag = fragments[i];
            output.Write(frag.Prefix);

            if (frag.IsNullable)
            {
                var hasValue = reader.ReadByte();
                if (hasValue == 0)
                {
                    output.Write(JsonNull);
                    continue;
                }
            }

            WriteFieldValueAsJson(output, ref reader, frag.WireType, frag.EnumUnderlying);
        }
    }

    // ────────────── Value transcoding ──────────────

    private static void WriteFieldValueAsJson(Stream output, ref SpanReader reader, WireFieldType wireType, WireFieldType enumUnderlying)
    {
        // Stack buffer shared by numeric formatters
        Span<byte> fmtBuf = stackalloc byte[64];

        switch (wireType)
        {
            case WireFieldType.Bool:
                if (reader.ReadBoolean()) output.Write(JsonTrue); else output.Write(JsonFalse);
                break;

            case WireFieldType.Byte:
                FormatAndWrite(output, (uint)reader.ReadByte(), fmtBuf);
                break;

            case WireFieldType.SByte:
                FormatAndWrite(output, (int)reader.ReadSByte(), fmtBuf);
                break;

            case WireFieldType.Int16:
                FormatAndWrite(output, (int)reader.ReadInt16(), fmtBuf);
                break;

            case WireFieldType.UInt16:
                FormatAndWrite(output, (uint)reader.ReadUInt16(), fmtBuf);
                break;

            case WireFieldType.Int32:
                FormatAndWrite(output, reader.ReadInt32(), fmtBuf);
                break;

            case WireFieldType.UInt32:
                FormatAndWrite(output, reader.ReadUInt32(), fmtBuf);
                break;

            case WireFieldType.Int64:
                FormatAndWriteInt64(output, reader.ReadInt64(), fmtBuf);
                break;

            case WireFieldType.UInt64:
                FormatAndWriteUInt64(output, reader.ReadUInt64(), fmtBuf);
                break;

            case WireFieldType.Float32:
                FormatAndWriteFloat(output, reader.ReadSingle(), fmtBuf);
                break;

            case WireFieldType.Float64:
                FormatAndWriteDouble(output, reader.ReadDouble(), fmtBuf);
                break;

            case WireFieldType.Decimal:
                FormatAndWriteDecimal(output, reader.ReadDecimal(), fmtBuf);
                break;

            case WireFieldType.Char:
            {
                var ch = reader.ReadChar();
                output.Write(JsonQuote);
                WriteEscapedChar(output, ch, fmtBuf);
                output.Write(JsonQuote);
                break;
            }

            case WireFieldType.String:
                WriteStringField(output, ref reader);
                break;

            case WireFieldType.Guid:
            {
                Span<byte> guidBytes = stackalloc byte[16];
                reader.ReadBytes(guidBytes);
                var guid = new Guid(guidBytes);
                output.Write(JsonQuote);
                // Guid "D" format: 36 chars
                Span<byte> guidBuf = stackalloc byte[36];
                if (Utf8Formatter.TryFormat(guid, guidBuf, out int gw, new StandardFormat('D')))
                    output.Write(guidBuf[..gw]);
                output.Write(JsonQuote);
                break;
            }

            case WireFieldType.DateTime:
            {
                var ticks = reader.ReadInt64();
                var kind = (DateTimeKind)reader.ReadByte();
                var dt = new DateTime(ticks, kind);
                output.Write(JsonQuote);
                // ISO 8601 "O" format: max ~33 chars
                Span<byte> dtBuf = stackalloc byte[40];
                if (Utf8Formatter.TryFormat(dt, dtBuf, out int dw, new StandardFormat('O')))
                    output.Write(dtBuf[..dw]);
                output.Write(JsonQuote);
                break;
            }

            case WireFieldType.DateOnly:
            {
                var dayNumber = reader.ReadInt32();
                var d = System.DateOnly.FromDayNumber(dayNumber);
                output.Write(JsonQuote);
                // "yyyy-MM-dd" = 10 chars
                Span<char> dateFmt = stackalloc char[10];
                if (d.TryFormat(dateFmt, out int dc, "yyyy-MM-dd"))
                {
                    Span<byte> dateUtf8 = stackalloc byte[10];
                    Encoding.UTF8.GetBytes(dateFmt[..dc], dateUtf8);
                    output.Write(dateUtf8[..dc]);
                }
                output.Write(JsonQuote);
                break;
            }

            case WireFieldType.TimeOnly:
            {
                var timeTicks = reader.ReadInt64();
                var t = new System.TimeOnly(timeTicks);
                output.Write(JsonQuote);
                // "HH:mm:ss" = 8 chars
                Span<char> timeFmt = stackalloc char[16];
                if (t.TryFormat(timeFmt, out int tc, "HH:mm:ss"))
                {
                    Span<byte> timeUtf8 = stackalloc byte[16];
                    Encoding.UTF8.GetBytes(timeFmt[..tc], timeUtf8);
                    output.Write(timeUtf8[..tc]);
                }
                output.Write(JsonQuote);
                break;
            }

            case WireFieldType.DateTimeOffset:
            {
                var dtoTicks = reader.ReadInt64();
                var offsetMin = reader.ReadInt16();
                var dto = new DateTimeOffset(dtoTicks, TimeSpan.FromMinutes(offsetMin));
                output.Write(JsonQuote);
                Span<byte> dtoBuf = stackalloc byte[40];
                if (Utf8Formatter.TryFormat(dto, dtoBuf, out int dtow, new StandardFormat('O')))
                    output.Write(dtoBuf[..dtow]);
                output.Write(JsonQuote);
                break;
            }

            case WireFieldType.TimeSpan:
            {
                var tsTicks = reader.ReadInt64();
                var ts = new TimeSpan(tsTicks);
                output.Write(JsonQuote);
                // "c" format: e.g. "1.02:03:04.0050000" — max ~26 chars
                Span<char> tsFmt = stackalloc char[32];
                if (ts.TryFormat(tsFmt, out int tsc, "c"))
                {
                    Span<byte> tsUtf8 = stackalloc byte[32];
                    int tsBytes = Encoding.UTF8.GetBytes(tsFmt[..tsc], tsUtf8);
                    output.Write(tsUtf8[..tsBytes]);
                }
                output.Write(JsonQuote);
                break;
            }

            case WireFieldType.Identifier:
            {
                Span<byte> idBytes = stackalloc byte[16];
                reader.ReadBytes(idBytes);
                var id = IdentifierValue.ReadFrom(idBytes);
                var idStr = id.ToString();
                output.Write(JsonQuote);
                if (idStr.Length > 0)
                {
                    Span<byte> idUtf8 = stackalloc byte[32]; // max 25 chars
                    int idLen = Encoding.UTF8.GetBytes(idStr, idUtf8);
                    output.Write(idUtf8[..idLen]);
                }
                output.Write(JsonQuote);
                break;
            }

            case WireFieldType.Enum:
                WriteEnumAsJson(output, ref reader, enumUnderlying);
                break;

            default:
                // Unknown type: read as string fallback
                WriteStringField(output, ref reader);
                break;
        }
    }

    // ────────────── Number formatting helpers ──────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void FormatAndWrite(Stream output, int value, Span<byte> buf)
    {
        if (Utf8Formatter.TryFormat(value, buf, out int written))
            output.Write(buf[..written]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void FormatAndWrite(Stream output, uint value, Span<byte> buf)
    {
        if (Utf8Formatter.TryFormat(value, buf, out int written))
            output.Write(buf[..written]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void FormatAndWriteInt64(Stream output, long value, Span<byte> buf)
    {
        if (Utf8Formatter.TryFormat(value, buf, out int written))
            output.Write(buf[..written]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void FormatAndWriteUInt64(Stream output, ulong value, Span<byte> buf)
    {
        if (Utf8Formatter.TryFormat(value, buf, out int written))
            output.Write(buf[..written]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void FormatAndWriteFloat(Stream output, float value, Span<byte> buf)
    {
        if (Utf8Formatter.TryFormat(value, buf, out int written))
            output.Write(buf[..written]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void FormatAndWriteDouble(Stream output, double value, Span<byte> buf)
    {
        if (Utf8Formatter.TryFormat(value, buf, out int written))
            output.Write(buf[..written]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void FormatAndWriteDecimal(Stream output, decimal value, Span<byte> buf)
    {
        if (Utf8Formatter.TryFormat(value, buf, out int written))
            output.Write(buf[..written]);
    }

    // ────────────── Enum ──────────────

    private static void WriteEnumAsJson(Stream output, ref SpanReader reader, WireFieldType underlying)
    {
        long raw = underlying switch
        {
            WireFieldType.Byte => reader.ReadByte(),
            WireFieldType.SByte => reader.ReadSByte(),
            WireFieldType.Int16 => reader.ReadInt16(),
            WireFieldType.UInt16 => reader.ReadUInt16(),
            WireFieldType.Int32 => reader.ReadInt32(),
            WireFieldType.UInt32 => reader.ReadUInt32(),
            WireFieldType.Int64 => reader.ReadInt64(),
            WireFieldType.UInt64 => (long)reader.ReadUInt64(),
            _ => reader.ReadInt32(),
        };
        Span<byte> buf = stackalloc byte[64];
        FormatAndWriteInt64(output, raw, buf);
    }

    // ────────────── String field ──────────────

    private static void WriteStringField(Stream output, ref SpanReader reader)
    {
        var byteCount = reader.ReadInt32();
        if (byteCount < 0)
        {
            output.Write(JsonNull);
            return;
        }
        if (byteCount == 0)
        {
            output.Write(JsonQuote);
            output.Write(JsonQuote);
            return;
        }
        if (byteCount > MaxStringBytes)
            throw new InvalidOperationException($"String length {byteCount} exceeds max {MaxStringBytes}.");

        output.Write(JsonQuote);

        // Read raw UTF-8 bytes from the binary span
        if (byteCount <= 512)
        {
            Span<byte> strBuf = stackalloc byte[byteCount];
            reader.ReadBytes(strBuf);
            WriteEscapedUtf8(output, strBuf);
        }
        else
        {
            var rented = ArrayPool<byte>.Shared.Rent(byteCount);
            try
            {
                var span = rented.AsSpan(0, byteCount);
                reader.ReadBytes(span);
                WriteEscapedUtf8(output, span);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented);
            }
        }

        output.Write(JsonQuote);
    }

    // ────────────── JSON string escaping ──────────────

    /// <summary>
    /// Writes UTF-8 bytes to the output, escaping characters that are
    /// special in JSON: \ " and control chars (U+0000–U+001F).
    /// Fast-paths the common case where no escaping is needed.
    /// </summary>
    private static void WriteEscapedUtf8(Stream output, ReadOnlySpan<byte> utf8)
    {
        // Fast scan: find the first byte that needs escaping
        int start = 0;
        for (int i = 0; i < utf8.Length; i++)
        {
            byte b = utf8[i];
            if (b == (byte)'\\' || b == (byte)'"' || b < 0x20)
            {
                // Write everything before this character
                if (i > start)
                    output.Write(utf8[start..i]);

                // Write escape sequence
                WriteEscapeSequence(output, b);
                start = i + 1;
            }
        }

        // Write remaining unescaped tail
        if (start < utf8.Length)
            output.Write(utf8[start..]);
    }

    private static void WriteEscapeSequence(Stream output, byte b)
    {
        ReadOnlySpan<byte> seq = b switch
        {
            (byte)'\\' => "\\\\"u8,
            (byte)'"'  => "\\\""u8,
            (byte)'\n' => "\\n"u8,
            (byte)'\r' => "\\r"u8,
            (byte)'\t' => "\\t"u8,
            (byte)'\b' => "\\b"u8,
            0x0C       => "\\f"u8,  // form feed
            _          => ReadOnlySpan<byte>.Empty,
        };

        if (seq.Length > 0)
        {
            output.Write(seq);
        }
        else
        {
            // \u00XX for other control chars
            Span<byte> esc = stackalloc byte[6];
            esc[0] = (byte)'\\';
            esc[1] = (byte)'u';
            esc[2] = (byte)'0';
            esc[3] = (byte)'0';
            esc[4] = HexChar(b >> 4);
            esc[5] = HexChar(b & 0x0F);
            output.Write(esc);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte HexChar(int nibble) =>
        (byte)(nibble < 10 ? '0' + nibble : 'a' + nibble - 10);

    /// <summary>
    /// Writes a single char with JSON escaping (for WireFieldType.Char).
    /// </summary>
    private static void WriteEscapedChar(Stream output, char ch, Span<byte> buf)
    {
        if (ch == '\\' || ch == '"' || ch < 0x20)
        {
            WriteEscapeSequence(output, (byte)ch);
        }
        else if (ch < 0x80)
        {
            buf[0] = (byte)ch;
            output.Write(buf[..1]);
        }
        else
        {
            // Multi-byte UTF-8
            Span<char> chars = stackalloc char[1] { ch };
            int len = Encoding.UTF8.GetBytes(chars, buf);
            output.Write(buf[..len]);
        }
    }
}
