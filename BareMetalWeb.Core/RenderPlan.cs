using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Core;

/// <summary>
/// Pre-compiled render plan using struct-of-arrays layout.
/// Templates are parsed once at startup into parallel arrays of static fragments
/// and token names. At first render, token names are bound to ordinal indices
/// against the actual key arrays — all subsequent renders use O(1) index lookups
/// with zero string comparisons on the hot path.
///
/// Lives in Core so BmwContext and RouteHandlerData can reference RenderPlan /
/// RouteRenderPlans with full strong typing — no object? casts required.
/// </summary>
public sealed class RenderPlan
{
    private static readonly Encoding Utf8 = Encoding.UTF8;

    // ── Struct of arrays (populated at compile time) ───────────────────

    /// <summary>Number of segments in this plan.</summary>
    public int Count { get; }

    /// <summary>Per-segment operation. 0 = static fragment.</summary>
    private readonly byte[] _ops;

    /// <summary>Static UTF-8 fragments indexed by segment ordinal. null for token segments.</summary>
    private readonly byte[]?[] _fragments;

    /// <summary>Token key names from the template. null for static segments. Used only during Bind().</summary>
    private readonly string?[] _tokenKeys;

    /// <summary>True if the token is html_ prefixed (raw write, no encoding).</summary>
    private readonly bool[] _isRawHtml;

    // ── Bound ordinals (populated at bind time) ────────────────────────
    // Op codes: 0=fragment, 1=page_value, 2=app_value, 3=byte_value, 4=raw_page, 5=raw_app, 6=unresolved(drop)

    /// <summary>Resolved ordinal index into the source array for each token segment.</summary>
    private readonly int[] _ordinals;

    private volatile bool _bound;

    /// <summary>Pre-computed total size of all static fragments (known at compile time).</summary>
    private readonly int _staticByteCount;

    private RenderPlan(int count, byte[] ops, byte[]?[] fragments, string?[] tokenKeys, bool[] isRawHtml, int[] ordinals)
    {
        Count = count;
        _ops = ops;
        _fragments = fragments;
        _tokenKeys = tokenKeys;
        _isRawHtml = isRawHtml;
        _ordinals = ordinals;

        // Pre-compute static fragment total for single-span size estimation
        int total = 0;
        for (int i = 0; i < count; i++)
        {
            if (ops[i] == 0 && fragments[i] != null)
                total += fragments[i]!.Length;
        }
        _staticByteCount = total;
    }

    /// <summary>
    /// Compile a template string into a render plan. Tokens like {{key}} become
    /// token segments; everything else becomes pre-encoded UTF-8 static fragments.
    /// Loop constructs (Loop%%, For%%) are not supported and will be emitted as tokens.
    /// </summary>
    public static RenderPlan Compile(string template)
    {
        if (string.IsNullOrEmpty(template))
            return new RenderPlan(0, Array.Empty<byte>(), Array.Empty<byte[]?>(), Array.Empty<string?>(), Array.Empty<bool>(), Array.Empty<int>());

        var segOps = new List<byte>();
        var segFragments = new List<byte[]?>();
        var segTokenKeys = new List<string?>();
        var segIsRaw = new List<bool>();

        var span = template.AsSpan();
        int pos = 0;

        while (pos < span.Length)
        {
            int openIdx = span.Slice(pos).IndexOf("{{".AsSpan());

            if (openIdx < 0)
            {
                segOps.Add(0);
                segFragments.Add(Utf8.GetBytes(span.Slice(pos).ToString()));
                segTokenKeys.Add(null);
                segIsRaw.Add(false);
                break;
            }

            if (openIdx > 0)
            {
                segOps.Add(0);
                segFragments.Add(Utf8.GetBytes(span.Slice(pos, openIdx).ToString()));
                segTokenKeys.Add(null);
                segIsRaw.Add(false);
            }

            int bodyStart = pos + openIdx + 2;
            int closeRelIdx = span.Slice(bodyStart).IndexOf("}}".AsSpan());

            if (closeRelIdx < 0)
            {
                segOps.Add(0);
                segFragments.Add(Utf8.GetBytes(span.Slice(pos + openIdx).ToString()));
                segTokenKeys.Add(null);
                segIsRaw.Add(false);
                break;
            }

            var key = span.Slice(bodyStart, closeRelIdx).ToString();
            bool isRaw = key.StartsWith("html_", StringComparison.Ordinal);
            segOps.Add(6); // unresolved until Bind()
            segFragments.Add(null);
            segTokenKeys.Add(key);
            segIsRaw.Add(isRaw);

            pos = bodyStart + closeRelIdx + 2;
        }

        int count = segOps.Count;
        return new RenderPlan(
            count,
            segOps.ToArray(),
            segFragments.ToArray(),
            segTokenKeys.ToArray(),
            segIsRaw.ToArray(),
            new int[count]);
    }

    /// <summary>
    /// Bind token names to ordinal indices against the provided key arrays.
    /// Called once on first Execute — all subsequent calls use the resolved ordinals.
    /// Thread-safe: worst case two threads both bind (idempotent, same result).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void Bind(string[] keys, string[] appkeys, string[]? byteKeys)
    {
        for (int i = 0; i < Count; i++)
        {
            if (_ops[i] == 0) continue; // static fragment — skip

            var tokenKey = _tokenKeys[i]!;
            bool resolved = false;

            for (int k = 0; k < keys.Length; k++)
            {
                if (string.Equals(tokenKey, keys[k], StringComparison.Ordinal))
                {
                    _ops[i] = _isRawHtml[i] ? (byte)4 : (byte)1;
                    _ordinals[i] = k;
                    resolved = true;
                    break;
                }
            }

            if (resolved) continue;

            for (int k = 0; k < appkeys.Length; k++)
            {
                if (string.Equals(tokenKey, appkeys[k], StringComparison.Ordinal))
                {
                    _ops[i] = _isRawHtml[i] ? (byte)5 : (byte)2;
                    _ordinals[i] = k;
                    resolved = true;
                    break;
                }
            }

            if (resolved) continue;

            if (byteKeys != null)
            {
                for (int k = 0; k < byteKeys.Length; k++)
                {
                    if (string.Equals(tokenKey, byteKeys[k], StringComparison.Ordinal))
                    {
                        _ops[i] = 3;
                        _ordinals[i] = k;
                        resolved = true;
                        break;
                    }
                }
            }

            if (!resolved)
                _ops[i] = 6; // unresolved — will be dropped at render time
        }

        _bound = true;
    }

    /// <summary>
    /// Execute the plan, writing directly to an IBufferWriter (PipeWriter or ArrayBufferWriter).
    /// First call binds token ordinals; subsequent calls are pure array-indexed writes.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Execute(
        IBufferWriter<byte> writer,
        string[] keys, string[] values,
        string[] appkeys, string[] appvalues,
        string[]? byteKeys = null, byte[][]? byteValues = null)
    {
        if (!_bound)
            Bind(keys, appkeys, byteKeys);

        ref var stats = ref RenderStatsProvider.GetStats();

        for (int i = 0; i < Count; i++)
        {
            switch (_ops[i])
            {
                case 0: // Static fragment
                {
                    var frag = _fragments[i]!;
                    var buf = writer.GetSpan(frag.Length);
                    frag.CopyTo(buf);
                    writer.Advance(frag.Length);
                    stats.WriteCount++;
                    stats.BytesWritten += frag.Length;
                    stats.FragmentCount++;
                    break;
                }

                case 1: // Page value (HTML-encoded)
                {
                    stats.TokenCount++;
                    var val = values[_ordinals[i]];
                    WriteHtmlEncoded(writer, val, ref stats);
                    break;
                }

                case 2: // App value (HTML-encoded)
                {
                    stats.TokenCount++;
                    var val = appvalues[_ordinals[i]];
                    WriteHtmlEncoded(writer, val, ref stats);
                    break;
                }

                case 3: // Byte-rendered value (table/form/links — already UTF-8)
                {
                    stats.TokenCount++;
                    var bv = byteValues![_ordinals[i]];
                    var buf = writer.GetSpan(bv.Length);
                    bv.CopyTo(buf);
                    writer.Advance(bv.Length);
                    stats.WriteCount++;
                    stats.BytesWritten += bv.Length;
                    stats.FragmentCount++;
                    break;
                }

                case 4: // Raw page value (no encoding — html_ prefix)
                {
                    stats.TokenCount++;
                    var val = values[_ordinals[i]];
                    if (val.Length > 0)
                    {
                        int bc = Utf8.GetByteCount(val);
                        var buf = writer.GetSpan(bc);
                        Utf8.GetBytes(val, buf);
                        writer.Advance(bc);
                        stats.WriteCount++;
                        stats.BytesWritten += bc;
                    }
                    break;
                }

                case 5: // Raw app value (no encoding)
                {
                    stats.TokenCount++;
                    var val = appvalues[_ordinals[i]];
                    if (val.Length > 0)
                    {
                        int bc = Utf8.GetByteCount(val);
                        var buf = writer.GetSpan(bc);
                        Utf8.GetBytes(val, buf);
                        writer.Advance(bc);
                        stats.WriteCount++;
                        stats.BytesWritten += bc;
                    }
                    break;
                }

                // case 6: unresolved — drop silently
            }
        }
    }

    // ── Single-span execution (#1309) ──────────────────────────────────

    /// <summary>
    /// Estimate the total output size for this plan given current values.
    /// Used by the single-span path to allocate one contiguous buffer.
    /// Static fragment sizes are exact; dynamic values use GetByteCount for precision.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int EstimateSize(
        string[] values, string[] appvalues,
        byte[][]? byteValues = null)
    {
        if (!_bound) return -1; // not yet bound — caller should fall back

        int total = _staticByteCount;

        for (int i = 0; i < Count; i++)
        {
            switch (_ops[i])
            {
                case 1: // page value (HTML-encoded — worst case 6× for entities)
                    total += Utf8.GetMaxByteCount(values[_ordinals[i]].Length);
                    break;
                case 2: // app value (HTML-encoded)
                    total += Utf8.GetMaxByteCount(appvalues[_ordinals[i]].Length);
                    break;
                case 3: // byte value (exact)
                    total += byteValues![_ordinals[i]].Length;
                    break;
                case 4: // raw page value
                    total += Utf8.GetByteCount(values[_ordinals[i]]);
                    break;
                case 5: // raw app value
                    total += Utf8.GetByteCount(appvalues[_ordinals[i]]);
                    break;
            }
        }

        return total;
    }

    /// <summary>
    /// Execute the plan into a single contiguous span. The caller must provide a span
    /// of at least <see cref="EstimateSize"/> bytes. Returns the actual number of bytes
    /// written. This eliminates all GetSpan/Advance overhead — one write, one advance.
    /// </summary>
    /// <returns>Number of bytes written into the output span.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int ExecuteSingleSpan(
        Span<byte> output,
        string[] keys, string[] values,
        string[] appkeys, string[] appvalues,
        string[]? byteKeys = null, byte[][]? byteValues = null)
    {
        if (!_bound)
            Bind(keys, appkeys, byteKeys);

        ref var stats = ref RenderStatsProvider.GetStats();
        int offset = 0;

        for (int i = 0; i < Count; i++)
        {
            switch (_ops[i])
            {
                case 0: // Static fragment — direct copy
                {
                    var frag = _fragments[i]!;
                    frag.CopyTo(output.Slice(offset));
                    offset += frag.Length;
                    stats.FragmentCount++;
                    break;
                }

                case 1: // Page value (HTML-encoded)
                {
                    stats.TokenCount++;
                    offset += WriteHtmlEncodedToSpan(output.Slice(offset), values[_ordinals[i]]);
                    break;
                }

                case 2: // App value (HTML-encoded)
                {
                    stats.TokenCount++;
                    offset += WriteHtmlEncodedToSpan(output.Slice(offset), appvalues[_ordinals[i]]);
                    break;
                }

                case 3: // Byte value (already UTF-8)
                {
                    stats.TokenCount++;
                    var bv = byteValues![_ordinals[i]];
                    bv.CopyTo(output.Slice(offset));
                    offset += bv.Length;
                    break;
                }

                case 4: // Raw page value
                {
                    stats.TokenCount++;
                    var val = values[_ordinals[i]];
                    if (val.Length > 0)
                    {
                        int bc = Utf8.GetBytes(val, output.Slice(offset));
                        offset += bc;
                    }
                    break;
                }

                case 5: // Raw app value
                {
                    stats.TokenCount++;
                    var val = appvalues[_ordinals[i]];
                    if (val.Length > 0)
                    {
                        int bc = Utf8.GetBytes(val, output.Slice(offset));
                        offset += bc;
                    }
                    break;
                }
            }
        }

        // Single write/advance stats update
        stats.WriteCount++;
        stats.BytesWritten += offset;

        return offset;
    }

    // ── HTML encoding helpers ──────────────────────────────────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteHtmlEncoded(IBufferWriter<byte> writer, string text, ref RenderStats stats)
    {
        if (string.IsNullOrEmpty(text)) return;

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

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteSpan(IBufferWriter<byte> writer, ReadOnlySpan<char> span, ref RenderStats stats)
    {
        int maxBytes = Utf8.GetMaxByteCount(span.Length);
        var buffer = writer.GetSpan(maxBytes);
        int bytesWritten = Utf8.GetBytes(span, buffer);
        writer.Advance(bytesWritten);
        stats.WriteCount++;
        stats.BytesWritten += bytesWritten;
    }

    /// <summary>
    /// HTML-encode text directly into a span at the given offset.
    /// Returns the number of bytes written. Zero GetSpan/Advance calls.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int WriteHtmlEncodedToSpan(Span<byte> output, string text)
    {
        if (string.IsNullOrEmpty(text)) return 0;

        var src = text.AsSpan();
        int offset = 0;
        int i = 0, segStart = 0;

        while (i < src.Length)
        {
            char c = src[i];
            ReadOnlySpan<byte> entity;
            switch (c)
            {
                case '&':  entity = "&amp;"u8;  break;
                case '<':  entity = "&lt;"u8;   break;
                case '>':  entity = "&gt;"u8;   break;
                case '"':  entity = "&quot;"u8; break;
                case '\'': entity = "&#39;"u8;  break;
                default:   i++;                 continue;
            }

            if (i > segStart)
                offset += Utf8.GetBytes(src.Slice(segStart, i - segStart), output.Slice(offset));

            entity.CopyTo(output.Slice(offset));
            offset += entity.Length;
            i++;
            segStart = i;
        }

        if (segStart < src.Length)
            offset += Utf8.GetBytes(src.Slice(segStart), output.Slice(offset));

        return offset;
    }
}

/// <summary>
/// Pre-compiled render plans for a route's four template sections.
/// Built once at startup from the jump table, plans use SoA ordinal-indexed
/// lookups with zero string comparisons on the hot render path.
/// Strongly typed — no object? casts needed on BmwContext or RouteHandlerData.
/// </summary>
public sealed class RouteRenderPlans
{
    public RenderPlan Head { get; }
    public RenderPlan Body { get; }
    public RenderPlan Footer { get; }
    public RenderPlan Script { get; }

    public RouteRenderPlans(RenderPlan head, RenderPlan body, RenderPlan footer, RenderPlan script)
    {
        Head = head;
        Body = body;
        Footer = footer;
        Script = script;
    }

    /// <summary>Compile plans from a template's four sections.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static RouteRenderPlans FromTemplate(IHtmlTemplate template)
    {
        return new RouteRenderPlans(
            RenderPlan.Compile(template.Head),
            RenderPlan.Compile(template.Body),
            RenderPlan.Compile(template.Footer),
            RenderPlan.Compile(template.Script));
    }

    /// <summary>
    /// Estimate total output size across all four sections for single-span rendering.
    /// Returns -1 if any plan is not yet bound.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int EstimateTotalSize(string[] values, string[] appvalues, byte[][]? byteValues = null)
    {
        int total = 0;
        int h = Head.EstimateSize(values, appvalues, byteValues);
        if (h < 0) return -1;
        total += h;
        int b = Body.EstimateSize(values, appvalues, byteValues);
        if (b < 0) return -1;
        total += b;
        int f = Footer.EstimateSize(values, appvalues, byteValues);
        if (f < 0) return -1;
        total += f;
        int s = Script.EstimateSize(values, appvalues, byteValues);
        if (s < 0) return -1;
        total += s;
        return total;
    }
}
