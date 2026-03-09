using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;

namespace BareMetalWeb.Rendering;

/// <summary>
/// A single segment in a compiled render plan.
/// Either a static UTF-8 fragment (Fragment != null) or a dynamic token hole (TokenKey != null).
/// </summary>
public readonly struct RenderSegment
{
    /// <summary>Pre-encoded UTF-8 bytes for static content. Null for dynamic tokens.</summary>
    public readonly byte[]? Fragment;

    /// <summary>Token key name (without {{ }}). Null for static fragments.</summary>
    public readonly string? TokenKey;

    /// <summary>True if this token carries pre-rendered HTML (html_ prefix).</summary>
    public readonly bool IsRawHtml;

    private RenderSegment(byte[]? fragment, string? tokenKey, bool isRawHtml)
    {
        Fragment = fragment;
        TokenKey = tokenKey;
        IsRawHtml = isRawHtml;
    }

    public static RenderSegment Static(byte[] fragment) => new(fragment, null, false);
    public static RenderSegment Token(string key) => new(null, key, key.StartsWith("html_", StringComparison.Ordinal));
}

/// <summary>
/// Pre-compiled render plan for a template section. Parses {{ tokens }} at compile time
/// so runtime rendering is a simple segment iteration with no string scanning.
/// </summary>
public sealed class RenderPlan
{
    private static readonly Encoding Utf8 = Encoding.UTF8;

    public RenderSegment[] Segments { get; }

    private RenderPlan(RenderSegment[] segments)
    {
        Segments = segments;
    }

    /// <summary>
    /// Compile a template string into a render plan. Tokens like {{key}} become
    /// Token segments; everything else becomes pre-encoded UTF-8 Static segments.
    /// Note: loop constructs (Loop%%, For%%) are not supported in compiled plans
    /// and will be emitted as regular tokens.
    /// </summary>
    public static RenderPlan Compile(string template)
    {
        if (string.IsNullOrEmpty(template))
            return new RenderPlan(Array.Empty<RenderSegment>());

        var segments = new List<RenderSegment>();
        var span = template.AsSpan();
        int pos = 0;

        while (pos < span.Length)
        {
            int openIdx = span.Slice(pos).IndexOf("{{".AsSpan());

            if (openIdx < 0)
            {
                // Remainder is all static
                segments.Add(RenderSegment.Static(Utf8.GetBytes(span.Slice(pos).ToString())));
                break;
            }

            // Static fragment before {{
            if (openIdx > 0)
                segments.Add(RenderSegment.Static(Utf8.GetBytes(span.Slice(pos, openIdx).ToString())));

            int bodyStart = pos + openIdx + 2;
            int closeRelIdx = span.Slice(bodyStart).IndexOf("}}".AsSpan());

            if (closeRelIdx < 0)
            {
                // Malformed — emit literal {{ and rest
                segments.Add(RenderSegment.Static(Utf8.GetBytes(span.Slice(pos + openIdx).ToString())));
                break;
            }

            var key = span.Slice(bodyStart, closeRelIdx).ToString();
            segments.Add(RenderSegment.Token(key));

            pos = bodyStart + closeRelIdx + 2;
        }

        return new RenderPlan(segments.ToArray());
    }

    /// <summary>
    /// Execute this plan, writing output to an IBufferWriter. Token values are looked up
    /// from the provided key/value arrays. Pre-rendered byte tokens use byteKeys/byteValues.
    /// </summary>
    public void Execute(
        IBufferWriter<byte> writer,
        string[] keys, string[] values,
        string[] appkeys, string[] appvalues,
        string[]? byteKeys = null, byte[][]? byteValues = null)
    {
        ref var stats = ref HtmlRenderer.GetStats();

        for (int s = 0; s < Segments.Length; s++)
        {
            ref readonly var seg = ref Segments[s];

            if (seg.Fragment != null)
            {
                var buffer = writer.GetSpan(seg.Fragment.Length);
                seg.Fragment.CopyTo(buffer);
                writer.Advance(seg.Fragment.Length);
                stats.WriteCount++;
                stats.BytesWritten += seg.Fragment.Length;
                stats.FragmentCount++;
                continue;
            }

            // Dynamic token — find value
            var tokenKey = seg.TokenKey!;
            string? value = null;

            for (int k = 0; k < keys.Length; k++)
            {
                if (string.Equals(tokenKey, keys[k], StringComparison.Ordinal))
                {
                    value = values[k];
                    break;
                }
            }

            if (value == null)
            {
                for (int k = 0; k < appkeys.Length; k++)
                {
                    if (string.Equals(tokenKey, appkeys[k], StringComparison.Ordinal))
                    {
                        value = appvalues[k];
                        break;
                    }
                }
            }

            // Check byte-rendered tokens (table, form, links)
            if (value == null && byteKeys != null && byteValues != null)
            {
                for (int k = 0; k < byteKeys.Length; k++)
                {
                    if (string.Equals(tokenKey, byteKeys[k], StringComparison.Ordinal))
                    {
                        var bv = byteValues[k];
                        var buffer = writer.GetSpan(bv.Length);
                        bv.CopyTo(buffer);
                        writer.Advance(bv.Length);
                        stats.WriteCount++;
                        stats.BytesWritten += bv.Length;
                        stats.FragmentCount++;
                        value = string.Empty; // mark as handled
                        break;
                    }
                }
                if (value == string.Empty)
                {
                    stats.TokenCount++;
                    continue;
                }
            }

            stats.TokenCount++;
            if (value == null) continue; // unknown token — drop

            if (seg.IsRawHtml)
            {
                if (value.Length > 0)
                {
                    int byteCount = Utf8.GetByteCount(value);
                    var buffer = writer.GetSpan(byteCount);
                    Utf8.GetBytes(value, buffer);
                    writer.Advance(byteCount);
                    stats.WriteCount++;
                    stats.BytesWritten += byteCount;
                }
            }
            else
            {
                WriteHtmlEncoded(writer, value, ref stats);
            }
        }
    }

    private static void WriteHtmlEncoded(IBufferWriter<byte> writer, string text, ref RenderStats stats)
    {
        var span = text.AsSpan();
        int i = 0, segStart = 0;

        while (i < span.Length)
        {
            char c = span[i];
            ReadOnlySpan<char> entity;
            switch (c)
            {
                case '&':  entity = "&amp;".AsSpan();  break;
                case '<':  entity = "&lt;".AsSpan();   break;
                case '>':  entity = "&gt;".AsSpan();   break;
                case '"':  entity = "&quot;".AsSpan(); break;
                case '\'': entity = "&#39;".AsSpan();  break;
                default:   i++;                        continue;
            }

            if (i > segStart)
                WriteSpan(writer, span.Slice(segStart, i - segStart), ref stats);

            WriteSpan(writer, entity, ref stats);
            i++;
            segStart = i;
        }

        if (segStart < span.Length)
            WriteSpan(writer, span.Slice(segStart), ref stats);
    }

    private static void WriteSpan(IBufferWriter<byte> writer, ReadOnlySpan<char> span, ref RenderStats stats)
    {
        int maxBytes = Utf8.GetMaxByteCount(span.Length);
        var buffer = writer.GetSpan(maxBytes);
        int bytesWritten = Utf8.GetBytes(span, buffer);
        writer.Advance(bytesWritten);
        stats.WriteCount++;
        stats.BytesWritten += bytesWritten;
    }
}
