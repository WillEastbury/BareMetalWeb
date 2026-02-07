using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Rendering;

// Fragment store to manage static HTML fragments loaded from disk at application startup
public sealed class HtmlFragmentStore : IHtmlFragmentStore
{
    private readonly string[] _fragmentKeys;
    private readonly string[] _fragmentValues;

    public HtmlFragmentStore()
    {
        List<string> keys = new();
        List<string> values = new();

        foreach (var filePath in Directory.GetFiles("wwwroot/templates/fragments", "*.html"))
        {
            keys.Add(Path.GetFileNameWithoutExtension(filePath));
            values.Add(File.ReadAllText(filePath));
        }

        _fragmentKeys = keys.ToArray();
        _fragmentValues = values.ToArray();
    }

    public string ReturnTemplateFragment(string templateKey)
    {
        int index = Array.IndexOf(_fragmentKeys, templateKey);
        return index >= 0 ? _fragmentValues[index] : throw new KeyNotFoundException($"Template fragment '{templateKey}' not found.");
    }

    public string ZeroAllocationReplaceCopy(string template, string[] keys, string[] values)
{
    if (keys.Length != values.Length)
        throw new ArgumentException("Keys and values must be of equal length.");

    // Estimate: template.Length * 2 = worst case after substitution
    ReadOnlySpan<char> input = template.AsSpan();
    var buffer = new ArrayBufferWriter<char>();

    int i = 0;
    while (i < input.Length)
    {
        if (input[i] == '{' && i + 1 < input.Length && input[i + 1] == '{')
        {
            int start = i + 2;
            int end = input.Slice(start).IndexOf("}}");

            if (end >= 0)
            {
                var token = input.Slice(start, end);

                bool matched = false;
                for (int k = 0; k < keys.Length; k++)
                {
                    if (token.SequenceEqual(keys[k].AsSpan().Slice(2, keys[k].Length - 4))) // remove {{ }}
                    {
                        buffer.Write(values[k]);
                        matched = true;
                        break;
                    }
                }

                if (!matched)
                {
                    buffer.Write("{{");
                    buffer.Write(token);
                    buffer.Write("}}");
                }

                i = start + end + 2; // past the }}
                continue;
            }
        }

        buffer.Write(input[i]);
        i++;
    }

    return new string(buffer.WrittenSpan);
}

    public byte[] ZeroAllocationReplaceCopyAndEncode(string template, string[] keys, string[] values)
    {
        return Encoding.UTF8.GetBytes(ZeroAllocationReplaceCopy(template, keys, values));
    }

    public void ZeroAllocationReplaceCopyAndWrite(string template, IBufferWriter<byte> writer, string[] keys, string[] values)
    {
    if (keys.Length != values.Length)
        throw new ArgumentException("Keys and values must be of equal length.");

    ReadOnlySpan<char> input = template.AsSpan();

    int i = 0;
    while (i < input.Length)
    {
        if (input[i] == '{' && i + 1 < input.Length && input[i + 1] == '{')
        {
            int start = i + 2;
            int end = input.Slice(start).IndexOf("}}");

            if (end >= 0)
            {
                var token = input.Slice(start, end);

                bool matched = false;
                for (int k = 0; k < keys.Length; k++)
                {
                    if (token.SequenceEqual(keys[k].AsSpan().Slice(2, keys[k].Length - 4))) // remove {{ }}
                    {
                        WriteUtf8(writer, values[k].AsSpan());
                        matched = true;
                        break;
                    }
                }

                if (!matched)
                {
                    WriteUtf8(writer, "{{".AsSpan());
                    WriteUtf8(writer, token);
                    WriteUtf8(writer, "}}".AsSpan());
                }

                i = start + end + 2; // past the }}
                continue;
            }
        }

        WriteUtf8(writer, input.Slice(i, 1));
        i++;
    }
}

    private static void WriteUtf8(IBufferWriter<byte> writer, ReadOnlySpan<char> span)
    {
        int maxBytes = Encoding.UTF8.GetMaxByteCount(span.Length);
        Span<byte> buffer = writer.GetSpan(maxBytes);
        int bytesWritten = Encoding.UTF8.GetBytes(span, buffer);
        writer.Advance(bytesWritten);
    }
}
