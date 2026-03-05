using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;

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

        var fragmentsPath = Path.Combine(AppContext.BaseDirectory, "wwwroot", "templates", "fragments");
        if (!Directory.Exists(fragmentsPath))
        {
            var repoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", ".."));
            var repoFragmentsPath = Path.Combine(repoRoot, "BareMetalWeb.Core", "wwwroot", "templates", "fragments");
            if (Directory.Exists(repoFragmentsPath))
            {
                fragmentsPath = repoFragmentsPath;
            }
        }

        foreach (var filePath in Directory.GetFiles(fragmentsPath, "*.html"))
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

    ReadOnlySpan<char> input = template.AsSpan();
    var buffer = new ArrayBufferWriter<char>();

    int pos = 0;
    while (pos < input.Length)
    {
        // SIMD-accelerated scan: IndexOf uses SSE2/NEON vector search internally.
        int openIdx = input.Slice(pos).IndexOf("{{".AsSpan());

        if (openIdx < 0)
        {
            // No more tokens — write the remainder as one contiguous slice.
            buffer.Write(input.Slice(pos));
            break;
        }

        // Write all literal characters before '{{'.
        if (openIdx > 0)
            buffer.Write(input.Slice(pos, openIdx));

        int start = pos + openIdx + 2;
        int end   = input.Slice(start).IndexOf("}}".AsSpan());

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

            pos = start + end + 2; // past the }}
        }
        else
        {
            // Unmatched '{{' with no closing '}}' — emit as literal and advance.
            // `start` already equals `pos + openIdx + 2`, so assigning `pos = start`
            // is the same as `pos += openIdx + 2`, which moves past the '{{'.
            buffer.Write(input.Slice(pos + openIdx, 2));
            pos = start; // identical to: pos = pos + openIdx + 2
        }
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

    int pos = 0;
    while (pos < input.Length)
    {
        // SIMD-accelerated scan: IndexOf uses SSE2/NEON vector search internally.
        int openIdx = input.Slice(pos).IndexOf("{{".AsSpan());

        if (openIdx < 0)
        {
            // No more tokens — write the remainder as one contiguous UTF-8 slice.
            WriteUtf8(writer, input.Slice(pos));
            return;
        }

        // Write all literal characters before '{{'.
        if (openIdx > 0)
            WriteUtf8(writer, input.Slice(pos, openIdx));

        int start = pos + openIdx + 2;
        int end   = input.Slice(start).IndexOf("}}".AsSpan());

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

            pos = start + end + 2; // past the }}
        }
        else
        {
            // Unmatched '{{' with no closing '}}' — emit as literal and advance.
            // `start` already equals `pos + openIdx + 2`, so assigning `pos = start`
            // is the same as `pos += openIdx + 2`, which moves past the '{{'.
            WriteUtf8(writer, input.Slice(pos + openIdx, 2));
            pos = start; // identical to: pos = pos + openIdx + 2
        }
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
