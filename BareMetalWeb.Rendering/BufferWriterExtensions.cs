using System.Buffers;

namespace BareMetalWeb.Rendering.Extensions;

public static class BufferWriterExtensions
{
    public static void Write(this IBufferWriter<char> writer, string value)
    {
        if (string.IsNullOrEmpty(value)) return;
        var span = writer.GetSpan(value.Length);
        value.AsSpan().CopyTo(span);
        writer.Advance(value.Length);
    }

    public static void Write(this IBufferWriter<char> writer, ReadOnlySpan<char> span)
    {
        var buffer = writer.GetSpan(span.Length);
        span.CopyTo(buffer);
        writer.Advance(span.Length);
    }

    public static void Write(this IBufferWriter<char> writer, char c)
    {
        var span = writer.GetSpan(1);
        span[0] = c;
        writer.Advance(1);
    }
    private static void Write(this IBufferWriter<byte> writer, byte[] data)
    {
        var span = writer.GetSpan(data.Length);
        data.CopyTo(span);
        writer.Advance(data.Length);
    }
}