using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Text;

namespace BareMetalWeb.Data;

/// <summary>
/// Codec interface for reading/writing field values in the canonical row encoding.
/// Hot-path implementations must not allocate, reflect, or use dictionaries.
/// </summary>
public interface IFieldCodec
{
    /// <summary>Read a value from a fixed-width span.</summary>
    object? ReadFixed(ReadOnlySpan<byte> data);
    /// <summary>Write a value into a fixed-width span. Returns bytes written.</summary>
    int WriteFixed(object? value, Span<byte> dest);
    /// <summary>Read a value from a variable-length span (length-prefixed already stripped).</summary>
    object? ReadVar(ReadOnlySpan<byte> data);
    /// <summary>Write a value to an IBufferWriter (variable-length fields). Returns bytes written.</summary>
    int WriteVar(object? value, IBufferWriter<byte> writer);
    /// <summary>Try to parse a string representation (boundary path: forms, query strings).</summary>
    bool TryParse(ReadOnlySpan<char> input, out object? result);
    /// <summary>Format a value to string (boundary path: UI, logging).</summary>
    string Format(object? value);
    /// <summary>Fixed size in bytes (0 for variable-length codecs).</summary>
    int FixedSize { get; }
}

// ── Boxed Singleton Cache ──
// Pre-boxed values eliminate boxing allocations for the most common field values.
internal static class BoxedValues
{
    public static readonly object True = true;
    public static readonly object False = false;
    public static readonly object[] Bytes = new object[256];
    public static readonly object[] SBytes = new object[256]; // -128..127 stored at index + 128
    public static readonly object ZeroInt16 = (short)0;
    public static readonly object ZeroUInt16 = (ushort)0;
    public static readonly object ZeroInt32 = 0;
    public static readonly object ZeroUInt32 = 0U;
    public static readonly object ZeroInt64 = 0L;
    public static readonly object ZeroUInt64 = 0UL;
    public static readonly object ZeroFloat32 = 0f;
    public static readonly object ZeroFloat64 = 0d;
    public static readonly object ZeroDecimal = 0m;
    public static readonly object ZeroChar = '\0';

    static BoxedValues()
    {
        for (int i = 0; i < 256; i++)
        {
            Bytes[i] = (byte)i;
            SBytes[i] = (sbyte)(i - 128);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static object BoxByte(byte v) => Bytes[v];

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static object BoxSByte(sbyte v) => SBytes[v + 128];
}

// ── Concrete Codecs ──

/// <summary>Codec for <see cref="bool"/> values.</summary>
public sealed class BoolCodec : IFieldCodec
{
    public int FixedSize => 1;
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public object? ReadFixed(ReadOnlySpan<byte> data) => data[0] != 0 ? BoxedValues.True : BoxedValues.False;
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int WriteFixed(object? value, Span<byte> dest) { dest[0] = (byte)((bool)value! ? 1 : 0); return 1; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(1); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (bool.TryParse(input, out var v)) { result = v ? BoxedValues.True : BoxedValues.False; return true; } result = null; return false; }
    public string Format(object? value) => value?.ToString() ?? "";
}

/// <summary>Codec for <see cref="byte"/> values.</summary>
public sealed class ByteCodec : IFieldCodec
{
    public int FixedSize => 1;
    public object? ReadFixed(ReadOnlySpan<byte> data) => BoxedValues.BoxByte(data[0]);
    public int WriteFixed(object? value, Span<byte> dest) { dest[0] = (byte)value!; return 1; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(1); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (byte.TryParse(input, out var v)) { result = BoxedValues.BoxByte(v); return true; } result = null; return false; }
    public string Format(object? value) => value?.ToString() ?? "";
}

/// <summary>Codec for <see cref="sbyte"/> values.</summary>
public sealed class SByteCodec : IFieldCodec
{
    public int FixedSize => 1;
    public object? ReadFixed(ReadOnlySpan<byte> data) => BoxedValues.BoxSByte((sbyte)data[0]);
    public int WriteFixed(object? value, Span<byte> dest) { dest[0] = (byte)(sbyte)value!; return 1; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(1); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (sbyte.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value?.ToString() ?? "";
}

/// <summary>Codec for <see cref="short"/> values.</summary>
public sealed class Int16Codec : IFieldCodec
{
    public int FixedSize => 2;
    public object? ReadFixed(ReadOnlySpan<byte> data) { var v = BinaryPrimitives.ReadInt16LittleEndian(data); return v == 0 ? BoxedValues.ZeroInt16 : (object)v; }
    public int WriteFixed(object? value, Span<byte> dest) { BinaryPrimitives.WriteInt16LittleEndian(dest, (short)value!); return 2; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(2); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (short.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value?.ToString() ?? "";
}

/// <summary>Codec for <see cref="ushort"/> values.</summary>
public sealed class UInt16Codec : IFieldCodec
{
    public int FixedSize => 2;
    public object? ReadFixed(ReadOnlySpan<byte> data) { var v = BinaryPrimitives.ReadUInt16LittleEndian(data); return v == 0 ? BoxedValues.ZeroUInt16 : (object)v; }
    public int WriteFixed(object? value, Span<byte> dest) { BinaryPrimitives.WriteUInt16LittleEndian(dest, (ushort)value!); return 2; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(2); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (ushort.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value?.ToString() ?? "";
}

/// <summary>Codec for <see cref="int"/> values.</summary>
public sealed class Int32Codec : IFieldCodec
{
    public int FixedSize => 4;
    public object? ReadFixed(ReadOnlySpan<byte> data) { var v = BinaryPrimitives.ReadInt32LittleEndian(data); return v == 0 ? BoxedValues.ZeroInt32 : (object)v; }
    public int WriteFixed(object? value, Span<byte> dest) { BinaryPrimitives.WriteInt32LittleEndian(dest, (int)value!); return 4; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(4); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (int.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value?.ToString() ?? "";
}

/// <summary>Codec for <see cref="uint"/> values.</summary>
public sealed class UInt32Codec : IFieldCodec
{
    public int FixedSize => 4;
    public object? ReadFixed(ReadOnlySpan<byte> data) { var v = BinaryPrimitives.ReadUInt32LittleEndian(data); return v == 0 ? BoxedValues.ZeroUInt32 : (object)v; }
    public int WriteFixed(object? value, Span<byte> dest) { BinaryPrimitives.WriteUInt32LittleEndian(dest, (uint)value!); return 4; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(4); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (uint.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value?.ToString() ?? "";
}

/// <summary>Codec for <see cref="long"/> values.</summary>
public sealed class Int64Codec : IFieldCodec
{
    public int FixedSize => 8;
    public object? ReadFixed(ReadOnlySpan<byte> data) { var v = BinaryPrimitives.ReadInt64LittleEndian(data); return v == 0 ? BoxedValues.ZeroInt64 : (object)v; }
    public int WriteFixed(object? value, Span<byte> dest) { BinaryPrimitives.WriteInt64LittleEndian(dest, (long)value!); return 8; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(8); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (long.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value?.ToString() ?? "";
}

/// <summary>Codec for <see cref="ulong"/> values.</summary>
public sealed class UInt64Codec : IFieldCodec
{
    public int FixedSize => 8;
    public object? ReadFixed(ReadOnlySpan<byte> data) { var v = BinaryPrimitives.ReadUInt64LittleEndian(data); return v == 0 ? BoxedValues.ZeroUInt64 : (object)v; }
    public int WriteFixed(object? value, Span<byte> dest) { BinaryPrimitives.WriteUInt64LittleEndian(dest, (ulong)value!); return 8; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(8); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (ulong.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value?.ToString() ?? "";
}

/// <summary>Codec for <see cref="float"/> values.</summary>
public sealed class Float32Codec : IFieldCodec
{
    public int FixedSize => 4;
    public object? ReadFixed(ReadOnlySpan<byte> data) => BinaryPrimitives.ReadSingleLittleEndian(data);
    public int WriteFixed(object? value, Span<byte> dest) { BinaryPrimitives.WriteSingleLittleEndian(dest, (float)value!); return 4; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(4); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (float.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value?.ToString() ?? "";
}

/// <summary>Codec for <see cref="double"/> values.</summary>
public sealed class Float64Codec : IFieldCodec
{
    public int FixedSize => 8;
    public object? ReadFixed(ReadOnlySpan<byte> data) => BinaryPrimitives.ReadDoubleLittleEndian(data);
    public int WriteFixed(object? value, Span<byte> dest) { BinaryPrimitives.WriteDoubleLittleEndian(dest, (double)value!); return 8; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(8); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (double.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value?.ToString() ?? "";
}

/// <summary>Codec for <see cref="decimal"/> values.</summary>
public sealed class DecimalCodec : IFieldCodec
{
    public int FixedSize => 16;
    public object? ReadFixed(ReadOnlySpan<byte> data)
    {
        int lo = BinaryPrimitives.ReadInt32LittleEndian(data);
        int mid = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(4));
        int hi = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(8));
        int flags = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(12));
        return new decimal(lo, mid, hi, (flags & unchecked((int)0x80000000)) != 0, (byte)((flags >> 16) & 0xFF));
    }
    public int WriteFixed(object? value, Span<byte> dest)
    {
        var bits = decimal.GetBits((decimal)value!);
        BinaryPrimitives.WriteInt32LittleEndian(dest, bits[0]);
        BinaryPrimitives.WriteInt32LittleEndian(dest.Slice(4), bits[1]);
        BinaryPrimitives.WriteInt32LittleEndian(dest.Slice(8), bits[2]);
        BinaryPrimitives.WriteInt32LittleEndian(dest.Slice(12), bits[3]);
        return 16;
    }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(16); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (decimal.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value?.ToString() ?? "";
}

/// <summary>Codec for <see cref="char"/> values.</summary>
public sealed class CharCodec : IFieldCodec
{
    public int FixedSize => 2;
    public object? ReadFixed(ReadOnlySpan<byte> data) => (char)BinaryPrimitives.ReadUInt16LittleEndian(data);
    public int WriteFixed(object? value, Span<byte> dest) { BinaryPrimitives.WriteUInt16LittleEndian(dest, (char)value!); return 2; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(2); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (input.Length == 1) { result = input[0]; return true; } result = null; return false; }
    public string Format(object? value) => value?.ToString() ?? "";
}

/// <summary>Codec for <see cref="DateOnly"/> values.</summary>
public sealed class DateOnlyCodec : IFieldCodec
{
    public int FixedSize => 4;
    public object? ReadFixed(ReadOnlySpan<byte> data) => DateOnly.FromDayNumber(BinaryPrimitives.ReadInt32LittleEndian(data));
    public int WriteFixed(object? value, Span<byte> dest) { BinaryPrimitives.WriteInt32LittleEndian(dest, ((DateOnly)value!).DayNumber); return 4; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(4); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (DateOnly.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value is DateOnly d ? d.ToString("O") : "";
}

/// <summary>Codec for <see cref="DateTime"/> values.</summary>
public sealed class DateTimeCodec : IFieldCodec
{
    public int FixedSize => 8;
    public object? ReadFixed(ReadOnlySpan<byte> data) => new DateTime(BinaryPrimitives.ReadInt64LittleEndian(data), DateTimeKind.Utc);
    public int WriteFixed(object? value, Span<byte> dest) { BinaryPrimitives.WriteInt64LittleEndian(dest, ((DateTime)value!).Ticks); return 8; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(8); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (DateTime.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value is DateTime dt ? dt.ToString("O") : "";
}

/// <summary>Codec for <see cref="DateTimeOffset"/> values.</summary>
public sealed class DateTimeOffsetCodec : IFieldCodec
{
    public int FixedSize => 10; // 8 ticks + 2 offset minutes
    public object? ReadFixed(ReadOnlySpan<byte> data)
    {
        long ticks = BinaryPrimitives.ReadInt64LittleEndian(data);
        short offsetMinutes = BinaryPrimitives.ReadInt16LittleEndian(data.Slice(8));
        return new DateTimeOffset(ticks, TimeSpan.FromMinutes(offsetMinutes));
    }
    public int WriteFixed(object? value, Span<byte> dest)
    {
        var dto = (DateTimeOffset)value!;
        BinaryPrimitives.WriteInt64LittleEndian(dest, dto.Ticks);
        BinaryPrimitives.WriteInt16LittleEndian(dest.Slice(8), (short)dto.Offset.TotalMinutes);
        return 10;
    }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(10); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (DateTimeOffset.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value is DateTimeOffset dto ? dto.ToString("O") : "";
}

/// <summary>Codec for <see cref="TimeOnly"/> values.</summary>
public sealed class TimeOnlyCodec : IFieldCodec
{
    public int FixedSize => 8;
    public object? ReadFixed(ReadOnlySpan<byte> data) => new TimeOnly(BinaryPrimitives.ReadInt64LittleEndian(data));
    public int WriteFixed(object? value, Span<byte> dest) { BinaryPrimitives.WriteInt64LittleEndian(dest, ((TimeOnly)value!).Ticks); return 8; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(8); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (TimeOnly.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value is TimeOnly t ? t.ToString("O") : "";
}

/// <summary>Codec for <see cref="TimeSpan"/> values.</summary>
public sealed class TimeSpanCodec : IFieldCodec
{
    public int FixedSize => 8;
    public object? ReadFixed(ReadOnlySpan<byte> data) => new TimeSpan(BinaryPrimitives.ReadInt64LittleEndian(data));
    public int WriteFixed(object? value, Span<byte> dest) { BinaryPrimitives.WriteInt64LittleEndian(dest, ((TimeSpan)value!).Ticks); return 8; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(8); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (TimeSpan.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value is TimeSpan ts ? ts.ToString() : "";
}

/// <summary>Codec for <see cref="Guid"/> values.</summary>
public sealed class GuidCodec : IFieldCodec
{
    public int FixedSize => 16;
    public object? ReadFixed(ReadOnlySpan<byte> data) => new Guid(data.Slice(0, 16));
    public int WriteFixed(object? value, Span<byte> dest) { ((Guid)value!).TryWriteBytes(dest); return 16; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(16); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (Guid.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value is Guid g ? g.ToString("D") : "";
}

/// <summary>Codec for <see cref="IdentifierValue"/> values.</summary>
public sealed class IdentifierCodec : IFieldCodec
{
    public int FixedSize => 16;
    public object? ReadFixed(ReadOnlySpan<byte> data)
    {
        ulong lo = BinaryPrimitives.ReadUInt64LittleEndian(data);
        ulong hi = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(8));
        return new IdentifierValue(hi, lo);
    }
    public int WriteFixed(object? value, Span<byte> dest)
    {
        var id = (IdentifierValue)value!;
        BinaryPrimitives.WriteUInt64LittleEndian(dest, id.Lo);
        BinaryPrimitives.WriteUInt64LittleEndian(dest.Slice(8), id.Hi);
        return 16;
    }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(16); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { result = IdentifierValue.Parse(input.ToString()); return true; }
    public string Format(object? value) => value is IdentifierValue id ? id.ToString() : "";
}

/// <summary>Codec for <see cref="string"/> values (UTF-8 encoded).</summary>
public sealed class StringCodec : IFieldCodec
{
    public int FixedSize => 0; // variable-length
    public object? ReadFixed(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);
    public object? ReadVar(ReadOnlySpan<byte> data) => Encoding.UTF8.GetString(data);
    public int WriteFixed(object? value, Span<byte> dest) => Encoding.UTF8.GetBytes((string)value!, dest);
    public int WriteVar(object? value, IBufferWriter<byte> writer)
    {
        var s = (string)value!;
        int byteCount = Encoding.UTF8.GetByteCount(s);
        var span = writer.GetSpan(4 + byteCount);
        BinaryPrimitives.WriteInt32LittleEndian(span, byteCount);
        Encoding.UTF8.GetBytes(s, span.Slice(4));
        writer.Advance(4 + byteCount);
        return 4 + byteCount;
    }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { result = input.ToString(); return true; }
    public string Format(object? value) => value?.ToString() ?? "";
}

/// <summary>Codec for <see cref="T:byte[]"/> values.</summary>
public sealed class BytesCodec : IFieldCodec
{
    public int FixedSize => 0; // variable-length
    public object? ReadFixed(ReadOnlySpan<byte> data) => data.ToArray();
    public object? ReadVar(ReadOnlySpan<byte> data) => data.ToArray();
    public int WriteFixed(object? value, Span<byte> dest) { var b = (byte[])value!; b.CopyTo(dest); return b.Length; }
    public int WriteVar(object? value, IBufferWriter<byte> writer)
    {
        var b = (byte[])value!;
        var span = writer.GetSpan(4 + b.Length);
        BinaryPrimitives.WriteInt32LittleEndian(span, b.Length);
        b.CopyTo(span.Slice(4));
        writer.Advance(4 + b.Length);
        return 4 + b.Length;
    }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { result = Convert.FromBase64String(input.ToString()); return true; }
    public string Format(object? value) => value is byte[] b ? Convert.ToBase64String(b) : "";
}

/// <summary>Codec for enum values stored as <see cref="int"/>.</summary>
public sealed class EnumInt32Codec : IFieldCodec
{
    public int FixedSize => 4;
    public object? ReadFixed(ReadOnlySpan<byte> data) => BinaryPrimitives.ReadInt32LittleEndian(data);
    public int WriteFixed(object? value, Span<byte> dest) { BinaryPrimitives.WriteInt32LittleEndian(dest, Convert.ToInt32(value)); return 4; }
    public object? ReadVar(ReadOnlySpan<byte> data) => ReadFixed(data);
    public int WriteVar(object? value, IBufferWriter<byte> writer) { var s = writer.GetSpan(4); return WriteFixed(value, s); }
    public bool TryParse(ReadOnlySpan<char> input, out object? result) { if (int.TryParse(input, out var v)) { result = v; return true; } result = null; return false; }
    public string Format(object? value) => value?.ToString() ?? "";
}

/// <summary>
/// Static codec table. Codecs are assigned stable IDs at startup and looked up
/// by array index — no dictionary in hot paths. codecs[codecId] is O(1).
/// </summary>
public static class CodecTable
{
    // Stable codec IDs — never renumber
    public const byte Bool_Id           = 1;
    public const byte Byte_Id           = 2;
    public const byte SByte_Id          = 3;
    public const byte Int16_Id          = 4;
    public const byte UInt16_Id         = 5;
    public const byte Int32_Id          = 6;
    public const byte UInt32_Id         = 7;
    public const byte Int64_Id          = 8;
    public const byte UInt64_Id         = 9;
    public const byte Float32_Id        = 10;
    public const byte Float64_Id        = 11;
    public const byte Decimal_Id        = 12;
    public const byte Char_Id           = 13;
    public const byte DateOnly_Id       = 14;
    public const byte DateTime_Id       = 15;
    public const byte DateTimeOffset_Id = 16;
    public const byte TimeOnly_Id       = 17;
    public const byte TimeSpan_Id       = 18;
    public const byte Guid_Id           = 19;
    public const byte StringUtf8_Id     = 20;
    public const byte Bytes_Id          = 21;
    public const byte EnumInt32_Id      = 22;
    public const byte Identifier_Id     = 23;

    private static readonly IFieldCodec[] _codecs = new IFieldCodec[32];

    static CodecTable()
    {
        _codecs[Bool_Id]           = new BoolCodec();
        _codecs[Byte_Id]           = new ByteCodec();
        _codecs[SByte_Id]          = new SByteCodec();
        _codecs[Int16_Id]          = new Int16Codec();
        _codecs[UInt16_Id]         = new UInt16Codec();
        _codecs[Int32_Id]          = new Int32Codec();
        _codecs[UInt32_Id]         = new UInt32Codec();
        _codecs[Int64_Id]          = new Int64Codec();
        _codecs[UInt64_Id]         = new UInt64Codec();
        _codecs[Float32_Id]        = new Float32Codec();
        _codecs[Float64_Id]        = new Float64Codec();
        _codecs[Decimal_Id]        = new DecimalCodec();
        _codecs[Char_Id]           = new CharCodec();
        _codecs[DateOnly_Id]       = new DateOnlyCodec();
        _codecs[DateTime_Id]       = new DateTimeCodec();
        _codecs[DateTimeOffset_Id] = new DateTimeOffsetCodec();
        _codecs[TimeOnly_Id]       = new TimeOnlyCodec();
        _codecs[TimeSpan_Id]       = new TimeSpanCodec();
        _codecs[Guid_Id]           = new GuidCodec();
        _codecs[StringUtf8_Id]     = new StringCodec();
        _codecs[Bytes_Id]          = new BytesCodec();
        _codecs[EnumInt32_Id]      = new EnumInt32Codec();
        _codecs[Identifier_Id]     = new IdentifierCodec();
    }

    /// <summary>O(1) array lookup. No dictionary.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static IFieldCodec Get(byte codecId) => _codecs[codecId];

    /// <summary>Map FieldType enum to codec ID. Called once at compile time, never in hot loops.</summary>
    public static byte CodecIdFor(FieldType type) => type switch
    {
        FieldType.Bool           => Bool_Id,
        FieldType.Byte           => Byte_Id,
        FieldType.SByte          => SByte_Id,
        FieldType.Int16          => Int16_Id,
        FieldType.UInt16         => UInt16_Id,
        FieldType.Int32          => Int32_Id,
        FieldType.UInt32         => UInt32_Id,
        FieldType.Int64          => Int64_Id,
        FieldType.UInt64         => UInt64_Id,
        FieldType.Float32        => Float32_Id,
        FieldType.Float64        => Float64_Id,
        FieldType.Decimal        => Decimal_Id,
        FieldType.Char           => Char_Id,
        FieldType.DateOnly       => DateOnly_Id,
        FieldType.DateTime       => DateTime_Id,
        FieldType.DateTimeOffset => DateTimeOffset_Id,
        FieldType.TimeOnly       => TimeOnly_Id,
        FieldType.TimeSpan       => TimeSpan_Id,
        FieldType.Guid           => Guid_Id,
        FieldType.StringUtf8     => StringUtf8_Id,
        FieldType.Bytes          => Bytes_Id,
        FieldType.EnumInt32      => EnumInt32_Id,
        FieldType.Identifier     => Identifier_Id,
        _ => throw new ArgumentOutOfRangeException(nameof(type), type, "Unknown field type")
    };
}
