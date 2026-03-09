using System.Buffers;
using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Text;

namespace BareMetalWeb.Rendering;

/// <summary>
/// A single segment of a compiled render plan — either a static UTF-8 byte
/// fragment or a dynamic field placeholder ("hole").
/// </summary>
public readonly struct RenderSegment
{
    /// <summary>Pre-encoded UTF-8 bytes for static content. Empty for dynamic holes.</summary>
    public readonly ReadOnlyMemory<byte> Fragment;

    /// <summary>
    /// Index into the values array for dynamic content, or -1 for static fragments.
    /// Indices 0..N map to page keys; negative values other than -1 are reserved.
    /// </summary>
    public readonly int FieldIndex;

    /// <summary>If true, the value should be written raw (html_ prefix). Otherwise HTML-encoded.</summary>
    public readonly bool IsRawHtml;

    private RenderSegment(ReadOnlyMemory<byte> fragment, int fieldIndex, bool isRawHtml)
    {
        Fragment = fragment;
        FieldIndex = fieldIndex;
        IsRawHtml = isRawHtml;
    }

    public static RenderSegment Static(ReadOnlyMemory<byte> fragment) =>
        new(fragment, -1, false);

    public static RenderSegment Dynamic(int fieldIndex, bool isRawHtml) =>
        new(ReadOnlyMemory<byte>.Empty, fieldIndex, isRawHtml);

    public bool IsStatic => FieldIndex < 0;
}

/// <summary>
/// A precompiled render plan: a flat array of segments that can be executed
/// in linear order to produce the HTML output.
/// </summary>
public sealed class TemplateRenderPlan
{
    public readonly RenderSegment[] Segments;
    public readonly string[] FieldKeys;

    /// <summary>Total bytes of all static fragments (for size estimation).</summary>
    public readonly int StaticByteCount;

    public TemplateRenderPlan(RenderSegment[] segments, string[] fieldKeys)
    {
        Segments = segments;
        FieldKeys = fieldKeys;
        int total = 0;
        for (int i = 0; i < segments.Length; i++)
        {
            if (segments[i].IsStatic)
                total += segments[i].Fragment.Length;
        }
        StaticByteCount = total;
    }
}

/// <summary>
/// Compiles a template string with <c>{{key}}</c> placeholders into a
/// <see cref="TemplateRenderPlan"/> at startup time.
/// </summary>
public static class TemplatePlanCompiler
{
    private static readonly Encoding Utf8 = Encoding.UTF8;

    /// <summary>
    /// Parses <paramref name="template"/> and produces a <see cref="TemplateRenderPlan"/>.
    /// Static text between tokens is pre-encoded to UTF-8 bytes.
    /// Dynamic tokens become field indices into the returned key array.
    /// </summary>
    public static TemplateRenderPlan Compile(string template)
    {
        if (string.IsNullOrEmpty(template))
            return new TemplateRenderPlan(Array.Empty<RenderSegment>(), Array.Empty<string>());

        var segments = new List<RenderSegment>();
        var fieldKeys = new List<string>();
        var fieldMap = new Dictionary<string, int>(StringComparer.Ordinal);

        var span = template.AsSpan();
        int pos = 0;

        while (pos < span.Length)
        {
            int openIdx = span.Slice(pos).IndexOf("{{".AsSpan());
            if (openIdx < 0)
            {
                // Remaining static text
                segments.Add(RenderSegment.Static(Utf8.GetBytes(span.Slice(pos).ToString())));
                break;
            }

            // Static text before the token
            if (openIdx > 0)
                segments.Add(RenderSegment.Static(Utf8.GetBytes(span.Slice(pos, openIdx).ToString())));

            int bodyStart = pos + openIdx + 2;
            int closeIdx = span.Slice(bodyStart).IndexOf("}}".AsSpan());

            if (closeIdx < 0)
            {
                // Malformed — emit literal {{ and rest
                segments.Add(RenderSegment.Static(Utf8.GetBytes(span.Slice(pos + openIdx).ToString())));
                break;
            }

            var key = span.Slice(bodyStart, closeIdx).ToString();
            bool isRaw = key.StartsWith("html_", StringComparison.Ordinal);

            if (!fieldMap.TryGetValue(key, out int idx))
            {
                idx = fieldKeys.Count;
                fieldMap[key] = idx;
                fieldKeys.Add(key);
            }

            segments.Add(RenderSegment.Dynamic(idx, isRaw));
            pos = bodyStart + closeIdx + 2;
        }

        return new TemplateRenderPlan(segments.ToArray(), fieldKeys.ToArray());
    }
}

/// <summary>
/// Executes a compiled <see cref="TemplateRenderPlan"/> against a set of key-value pairs,
/// writing output directly to a <see cref="PipeWriter"/>.
/// </summary>
public static class TemplatePlanExecutor
{
    private static readonly Encoding Utf8 = Encoding.UTF8;

    /// <summary>
    /// Executes <paramref name="plan"/> by resolving field values from the provided
    /// key/value arrays (page keys take precedence over app keys).
    /// </summary>
    public static void Execute(
        PipeWriter writer,
        TemplateRenderPlan plan,
        string[] pageKeys,
        string[] pageValues,
        string[] appKeys,
        string[] appValues)
    {
        // Build a lookup: plan field index → resolved value
        var resolved = new string?[plan.FieldKeys.Length];
        for (int f = 0; f < plan.FieldKeys.Length; f++)
        {
            var key = plan.FieldKeys[f];
            string? val = null;

            // Page keys (highest priority)
            for (int k = 0; k < pageKeys.Length; k++)
            {
                if (string.Equals(key, pageKeys[k], StringComparison.Ordinal))
                {
                    val = pageValues[k];
                    break;
                }
            }

            // App keys (lower priority)
            if (val == null)
            {
                for (int k = 0; k < appKeys.Length; k++)
                {
                    if (string.Equals(key, appKeys[k], StringComparison.Ordinal))
                    {
                        val = appValues[k];
                        break;
                    }
                }
            }

            resolved[f] = val;
        }

        ExecuteWithResolvedValues(writer, plan, resolved);
    }

    /// <summary>
    /// Executes with pre-resolved values (one per field index).
    /// </summary>
    public static void ExecuteWithResolvedValues(
        PipeWriter writer,
        TemplateRenderPlan plan,
        string?[] resolvedValues)
    {
        var segments = plan.Segments;

        for (int i = 0; i < segments.Length; i++)
        {
            ref readonly var seg = ref segments[i];

            if (seg.IsStatic)
            {
                WriteFragment(writer, seg.Fragment.Span);
            }
            else
            {
                var val = seg.FieldIndex < resolvedValues.Length
                    ? resolvedValues[seg.FieldIndex]
                    : null;

                if (val != null)
                {
                    if (seg.IsRawHtml)
                        WriteUtf8(writer, val);
                    else
                        WriteHtmlEncoded(writer, val);
                }
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void WriteFragment(PipeWriter writer, ReadOnlySpan<byte> source)
    {
        var dest = writer.GetSpan(source.Length);
        SimdCopy.CopyFragment(source, dest);
        writer.Advance(source.Length);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteUtf8(PipeWriter writer, string text)
    {
        int byteCount = Utf8.GetByteCount(text);
        var buffer = writer.GetSpan(byteCount);
        Utf8.GetBytes(text, buffer);
        writer.Advance(byteCount);
    }

    private static void WriteHtmlEncoded(PipeWriter writer, string text)
    {
        ReadOnlySpan<char> span = text.AsSpan();
        int segStart = 0;

        for (int i = 0; i < span.Length; i++)
        {
            ReadOnlySpan<byte> entity;
            switch (span[i])
            {
                case '&':  entity = "&amp;"u8;  break;
                case '<':  entity = "&lt;"u8;   break;
                case '>':  entity = "&gt;"u8;   break;
                case '"':  entity = "&quot;"u8; break;
                case '\'': entity = "&#39;"u8;  break;
                default: continue;
            }

            if (i > segStart)
                WriteUtf8Span(writer, span.Slice(segStart, i - segStart));

            WriteFragment(writer, entity);
            segStart = i + 1;
        }

        if (segStart < span.Length)
            WriteUtf8Span(writer, span.Slice(segStart));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteUtf8Span(PipeWriter writer, ReadOnlySpan<char> chars)
    {
        int maxBytes = Utf8.GetMaxByteCount(chars.Length);
        var buffer = writer.GetSpan(maxBytes);
        int written = Utf8.GetBytes(chars, buffer);
        writer.Advance(written);
    }
}
