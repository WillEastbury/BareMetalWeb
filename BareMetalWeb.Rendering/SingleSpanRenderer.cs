using System.IO.Pipelines;
using System.Runtime.CompilerServices;
using System.Text;

namespace BareMetalWeb.Rendering;

/// <summary>
/// Renders a compiled <see cref="RenderPlan"/> into a single contiguous buffer,
/// eliminating repeated <c>PipeWriter.GetSpan</c>/<c>Advance</c> calls.
/// One <c>GetSpan</c> → one <c>Advance</c> → one <c>FlushAsync</c>.
/// </summary>
public static class SingleSpanRenderer
{
    private static readonly Encoding Utf8 = Encoding.UTF8;

    // Conservative estimate: average dynamic value is ≤ 128 bytes UTF-8
    private const int DefaultDynamicEstimate = 128;

    /// <summary>
    /// Estimates the total byte size needed for the rendered output.
    /// </summary>
    public static int EstimateTotalSize(RenderPlan plan, string?[] resolvedValues)
    {
        int total = plan.StaticByteCount;

        for (int i = 0; i < plan.FieldKeys.Length; i++)
        {
            var val = i < resolvedValues.Length ? resolvedValues[i] : null;
            if (val != null)
            {
                // Worst case for HTML encoding: every char becomes an entity (6 chars → 6 bytes max)
                // but Utf8.GetMaxByteCount already handles multi-byte chars
                total += Utf8.GetMaxByteCount(val.Length) + (val.Length * 5); // entity expansion headroom
            }
            else
            {
                total += DefaultDynamicEstimate;
            }
        }

        return total;
    }

    /// <summary>
    /// Renders <paramref name="plan"/> with resolved values into a single
    /// PipeWriter span. Returns the number of bytes written.
    /// </summary>
    public static int RenderToSpan(
        RenderPlan plan,
        string?[] resolvedValues,
        Span<byte> buffer)
    {
        int offset = 0;
        var segments = plan.Segments;

        for (int i = 0; i < segments.Length; i++)
        {
            ref readonly var seg = ref segments[i];

            if (seg.IsStatic)
            {
                var frag = seg.Fragment.Span;
                SimdCopy.CopyFragment(frag, buffer.Slice(offset));
                offset += frag.Length;
            }
            else
            {
                var val = seg.FieldIndex < resolvedValues.Length
                    ? resolvedValues[seg.FieldIndex]
                    : null;

                if (val != null)
                {
                    if (seg.IsRawHtml)
                    {
                        int written = Utf8.GetBytes(val, buffer.Slice(offset));
                        offset += written;
                    }
                    else
                    {
                        offset += WriteHtmlEncodedToBuffer(val, buffer.Slice(offset));
                    }
                }
            }
        }

        return offset;
    }

    /// <summary>
    /// Full pipeline: estimate size → GetSpan once → render → Advance → FlushAsync.
    /// </summary>
    public static async ValueTask RenderAsync(
        PipeWriter writer,
        RenderPlan plan,
        string[] pageKeys,
        string[] pageValues,
        string[] appKeys,
        string[] appValues)
    {
        var resolved = ResolveValues(plan, pageKeys, pageValues, appKeys, appValues);
        int estimatedSize = EstimateTotalSize(plan, resolved);

        var buffer = writer.GetSpan(estimatedSize);
        int bytesWritten = RenderToSpan(plan, resolved, buffer);
        writer.Advance(bytesWritten);
        await writer.FlushAsync();
    }

    /// <summary>
    /// Full pipeline using pre-resolved values.
    /// </summary>
    public static async ValueTask RenderAsync(
        PipeWriter writer,
        RenderPlan plan,
        string?[] resolvedValues)
    {
        int estimatedSize = EstimateTotalSize(plan, resolvedValues);

        var buffer = writer.GetSpan(estimatedSize);
        int bytesWritten = RenderToSpan(plan, resolvedValues, buffer);
        writer.Advance(bytesWritten);
        await writer.FlushAsync();
    }

    private static string?[] ResolveValues(
        RenderPlan plan,
        string[] pageKeys, string[] pageValues,
        string[] appKeys, string[] appValues)
    {
        var resolved = new string?[plan.FieldKeys.Length];

        for (int f = 0; f < plan.FieldKeys.Length; f++)
        {
            var key = plan.FieldKeys[f];
            string? val = null;

            for (int k = 0; k < pageKeys.Length; k++)
            {
                if (string.Equals(key, pageKeys[k], StringComparison.Ordinal))
                {
                    val = pageValues[k];
                    break;
                }
            }

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

        return resolved;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int WriteHtmlEncodedToBuffer(string text, Span<byte> buffer)
    {
        ReadOnlySpan<char> span = text.AsSpan();
        int offset = 0;
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
            {
                int written = Utf8.GetBytes(span.Slice(segStart, i - segStart), buffer.Slice(offset));
                offset += written;
            }

            entity.CopyTo(buffer.Slice(offset));
            offset += entity.Length;
            segStart = i + 1;
        }

        if (segStart < span.Length)
        {
            int written = Utf8.GetBytes(span.Slice(segStart), buffer.Slice(offset));
            offset += written;
        }

        return offset;
    }
}
