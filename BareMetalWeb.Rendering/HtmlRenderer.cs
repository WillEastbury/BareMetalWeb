using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO.Pipelines;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Host;
using Microsoft.AspNetCore.Http;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Rendering.Interfaces;
using BareMetalWeb.Rendering.Models;
namespace BareMetalWeb.Rendering;

public class HtmlRenderer : IHtmlRenderer
{
    public static Action<TimeSpan>? OnRenderComplete;
    public static Action<TimeSpan, RenderStats>? OnRenderCompleteWithStats;

    private static readonly Encoding Utf8 = Encoding.UTF8;
    private readonly IHtmlFragmentRenderer _fragments;

    /// <summary>When true, uses the arena renderer (single contiguous buffer) instead of PipeWriter streaming.</summary>
    public static bool UseArenaRenderer { get; set; }

    public HtmlRenderer(IHtmlFragmentRenderer fragments)
    {
        _fragments = fragments;
    }

    public async ValueTask<ReadOnlyMemory<byte>> RenderToBytesAsync(IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null)
    {
        var ms = new MemoryStream();
        var pipeWriter = PipeWriter.Create(ms);
        await RenderToStreamAsync(pipeWriter, template, keys, values, appkeys, appvalues, app, tableColumnTitles, tableRows, formDefinition, templateLoops);
        await pipeWriter.CompleteAsync();
        return ms.TryGetBuffer(out var buffer) ? buffer : ms.ToArray();
    }

    /// <summary>
    /// Arena-based renderer: writes all output into a single contiguous ArrayBufferWriter,
    /// then copies to the PipeWriter in one GetSpan/Advance/Flush cycle.
    /// Reduces PipeWriter overhead by eliminating per-fragment GetSpan calls.
    /// </summary>
    public async ValueTask<ReadOnlyMemory<byte>> RenderToBytesArenaAsync(IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null)
    {
        var arena = new ArrayBufferWriter<byte>(16384);

        WriteToBuffer(arena, _fragments.DocTypeAndHeadStart);
        WriteToBuffer(arena, template.Encoding.WebName);
        WriteToBuffer(arena, "'>");

        RenderSectionToBuffer(arena, template.Head, keys, values, appkeys, appvalues, null, null, templateLoops);

        WriteToBuffer(arena, _fragments.HeadEndAndBodyStart);

        int byteCount = 2
            + (tableColumnTitles is not null && tableRows is not null ? 1 : 0)
            + (formDefinition is not null ? 1 : 0);
        var byteKeysArr = new string[byteCount];
        var byteValuesArr = new byte[byteCount][];
        byteKeysArr[0] = "links_left";
        byteValuesArr[0] = _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: false);
        byteKeysArr[1] = "links_right";
        byteValuesArr[1] = _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: true);
        int idx = 2;
        if (tableColumnTitles != null && tableRows != null)
        {
            byteKeysArr[idx] = "table";
            byteValuesArr[idx++] = _fragments.RenderTable(tableColumnTitles, tableRows);
        }
        if (formDefinition is not null)
        {
            byteKeysArr[idx] = "form";
            byteValuesArr[idx] = _fragments.RenderForm(formDefinition);
        }

        RenderSectionToBuffer(arena, template.Body, keys, values, appkeys, appvalues, byteKeysArr, byteValuesArr, templateLoops);
        RenderSectionToBuffer(arena, template.Footer, keys, values, appkeys, appvalues, null, null, templateLoops);

        if (!string.IsNullOrEmpty(template.Script))
        {
            WriteToBuffer(arena, _fragments.ScriptTagStart);
            RenderSectionToBuffer(arena, template.Script, keys, values, appkeys, appvalues, null, null, templateLoops);
            WriteToBuffer(arena, _fragments.ScriptTagEnd);
        }

        WriteToBuffer(arena, _fragments.BodyEndAndHtmlEnd);

        return arena.WrittenMemory;
    }

    public async ValueTask RenderToStreamAsync(PipeWriter writer, IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null)
    {
        Write(writer, _fragments.DocTypeAndHeadStart);
        Write(writer, template.Encoding.WebName);
        Write(writer, "'>");

        RenderSection(writer, template.Head, keys, values, appkeys, appvalues, null, null, templateLoops);

        Write(writer, _fragments.HeadEndAndBodyStart);

        // Build the byte-rendered key/value pairs for the body section (at most 4 entries).
        // Using fixed-size arrays avoids List<T> allocation and the subsequent ToArray() copies.
        int byteCount = 2
            + (tableColumnTitles is not null && tableRows is not null ? 1 : 0)
            + (formDefinition is not null ? 1 : 0);
        var byteKeysArr = new string[byteCount];
        var byteValuesArr = new byte[byteCount][];
        byteKeysArr[0] = "links_left";
        byteValuesArr[0] = _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: false);
        byteKeysArr[1] = "links_right";
        byteValuesArr[1] = _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: true);
        int idx = 2;
        if (tableColumnTitles != null && tableRows != null)
        {
            byteKeysArr[idx] = "table";
            byteValuesArr[idx++] = _fragments.RenderTable(tableColumnTitles, tableRows);
        }
        if (formDefinition is not null)
        {
            byteKeysArr[idx] = "form";
            byteValuesArr[idx] = _fragments.RenderForm(formDefinition);
        }

        RenderSection(writer, template.Body, keys, values, appkeys, appvalues, byteKeysArr, byteValuesArr, templateLoops);
        RenderSection(writer, template.Footer, keys, values, appkeys, appvalues, null, null, templateLoops);

        if (!string.IsNullOrEmpty(template.Script))
        {
            Write(writer, _fragments.ScriptTagStart);
            RenderSection(writer, template.Script, keys, values, appkeys, appvalues, null, null, templateLoops);
            Write(writer, _fragments.ScriptTagEnd);
        }

        Write(writer, _fragments.BodyEndAndHtmlEnd);
        await writer.FlushAsync();
        RenderStatsProvider.GetStats().FlushCount++;
    }

    // ── Compiled plan cache ────────────────────────────────────────────────────
    // Plans are compiled once per template and cached. Template content is immutable
    // after startup so the cache never needs invalidation during normal operation.

    private static readonly Dictionary<string, CompiledTemplatePlans> _planCache = new();
    private static readonly object _planLock = new();

    private readonly record struct CompiledTemplatePlans(
        RenderPlan Head, RenderPlan Body, RenderPlan Footer, RenderPlan Script);

    private static CompiledTemplatePlans GetOrCompilePlans(IHtmlTemplate template)
    {
        // Use Head+Body hash as cache key (templates are reference-stable after startup)
        var key = string.Concat(template.Head.GetHashCode().ToString("x8"), template.Body.GetHashCode().ToString("x8"));
        lock (_planLock)
        {
            if (_planCache.TryGetValue(key, out var cached))
                return cached;

            var plans = new CompiledTemplatePlans(
                RenderPlan.Compile(template.Head),
                RenderPlan.Compile(template.Body),
                RenderPlan.Compile(template.Footer),
                RenderPlan.Compile(template.Script));
            _planCache[key] = plans;
            return plans;
        }
    }

    /// <summary>Clears compiled template plan cache (call after template reload).</summary>
    public static void InvalidatePlanCache()
    {
        lock (_planLock) { _planCache.Clear(); }
    }

    // ── Route-level pre-bound plan execution ───────────────────────────────────
    // These methods use RouteRenderPlans compiled at jump-table build time.
    // No template lookup, no lazy compilation — plans are already bound.

    /// <summary>
    /// Fastest path: uses pre-bound route plans, writes directly to PipeWriter.
    /// Plans were compiled and ordinal-bound at jump-table build time.
    /// </summary>
    private async ValueTask RenderWithPlansAsync(
        PipeWriter writer, RouteRenderPlans plans,
        IHtmlTemplate template,
        string[] keys, string[] values,
        IBareWebHost app,
        string[]? tableColumnTitles, string[][]? tableRows,
        FormDefinition? formDefinition)
    {
        Write(writer, _fragments.DocTypeAndHeadStart);
        Write(writer, template.Encoding.WebName);
        Write(writer, "'>");

        plans.Head.Execute(writer, keys, values, app.AppMetaDataKeys, app.AppMetaDataValues);

        Write(writer, _fragments.HeadEndAndBodyStart);

        int byteCount = 2
            + (tableColumnTitles is not null && tableRows is not null ? 1 : 0)
            + (formDefinition is not null ? 1 : 0);
        var byteKeysArr = new string[byteCount];
        var byteValuesArr = new byte[byteCount][];
        byteKeysArr[0] = "links_left";
        byteValuesArr[0] = _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: false);
        byteKeysArr[1] = "links_right";
        byteValuesArr[1] = _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: true);
        int idx = 2;
        if (tableColumnTitles != null && tableRows != null)
        {
            byteKeysArr[idx] = "table";
            byteValuesArr[idx++] = _fragments.RenderTable(tableColumnTitles, tableRows);
        }
        if (formDefinition is not null)
        {
            byteKeysArr[idx] = "form";
            byteValuesArr[idx] = _fragments.RenderForm(formDefinition);
        }

        plans.Body.Execute(writer, keys, values, app.AppMetaDataKeys, app.AppMetaDataValues, byteKeysArr, byteValuesArr);
        plans.Footer.Execute(writer, keys, values, app.AppMetaDataKeys, app.AppMetaDataValues);

        if (!string.IsNullOrEmpty(template.Script))
        {
            Write(writer, _fragments.ScriptTagStart);
            plans.Script.Execute(writer, keys, values, app.AppMetaDataKeys, app.AppMetaDataValues);
            Write(writer, _fragments.ScriptTagEnd);
        }

        Write(writer, _fragments.BodyEndAndHtmlEnd);
        await writer.FlushAsync();
        RenderStatsProvider.GetStats().FlushCount++;
    }

    /// <summary>
    /// Single-span render path (#1309). Precomputes total output size, acquires one
    /// contiguous PipeWriter span, renders everything with a moving pointer, then
    /// calls Advance once and flushes once. Maximum cache locality, minimum PipeWriter overhead.
    /// Falls back to RenderWithPlansAsync if size estimation fails (plans not yet bound).
    /// </summary>
    private async ValueTask RenderWithPlansSingleSpanAsync(
        PipeWriter writer, RouteRenderPlans plans,
        IHtmlTemplate template,
        string[] keys, string[] values,
        IBareWebHost app,
        string[]? tableColumnTitles, string[][]? tableRows,
        FormDefinition? formDefinition)
    {
        // Build byte-key arrays (same as multi-write path)
        int byteCount = 2
            + (tableColumnTitles is not null && tableRows is not null ? 1 : 0)
            + (formDefinition is not null ? 1 : 0);
        var byteKeysArr = new string[byteCount];
        var byteValuesArr = new byte[byteCount][];
        byteKeysArr[0] = "links_left";
        byteValuesArr[0] = _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: false);
        byteKeysArr[1] = "links_right";
        byteValuesArr[1] = _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: true);
        int bIdx = 2;
        if (tableColumnTitles != null && tableRows != null)
        {
            byteKeysArr[bIdx] = "table";
            byteValuesArr[bIdx++] = _fragments.RenderTable(tableColumnTitles, tableRows);
        }
        if (formDefinition is not null)
        {
            byteKeysArr[bIdx] = "form";
            byteValuesArr[bIdx] = _fragments.RenderForm(formDefinition);
        }

        // Estimate total output size
        int planSize = plans.EstimateTotalSize(values, app.AppMetaDataValues, byteValuesArr);
        if (planSize < 0)
        {
            // Plans not yet bound — fall back to multi-write path (binds on first Execute)
            await RenderWithPlansAsync(writer, plans, template, keys, values, app, tableColumnTitles, tableRows, formDefinition);
            return;
        }

        // Add structural fragment sizes
        int structuralSize = _fragments.DocTypeAndHeadStart.Length
            + Utf8.GetByteCount(template.Encoding.WebName)
            + 2 // "'>"
            + _fragments.HeadEndAndBodyStart.Length
            + _fragments.BodyEndAndHtmlEnd.Length;

        if (!string.IsNullOrEmpty(template.Script))
            structuralSize += _fragments.ScriptTagStart.Length + _fragments.ScriptTagEnd.Length;

        int totalSize = planSize + structuralSize;

        // Single GetSpan call for the entire response
        var span = writer.GetSpan(totalSize);
        int offset = 0;

        // DocType + encoding
        _fragments.DocTypeAndHeadStart.CopyTo(span.Slice(offset));
        offset += _fragments.DocTypeAndHeadStart.Length;
        offset += Utf8.GetBytes(template.Encoding.WebName, span.Slice(offset));
        span[offset] = (byte)'\'';
        span[offset + 1] = (byte)'>';
        offset += 2;

        // Head
        offset += plans.Head.ExecuteSingleSpan(span.Slice(offset), keys, values, app.AppMetaDataKeys, app.AppMetaDataValues);

        // Head→Body transition
        _fragments.HeadEndAndBodyStart.CopyTo(span.Slice(offset));
        offset += _fragments.HeadEndAndBodyStart.Length;

        // Body
        offset += plans.Body.ExecuteSingleSpan(span.Slice(offset), keys, values, app.AppMetaDataKeys, app.AppMetaDataValues, byteKeysArr, byteValuesArr);

        // Footer
        offset += plans.Footer.ExecuteSingleSpan(span.Slice(offset), keys, values, app.AppMetaDataKeys, app.AppMetaDataValues);

        // Script
        if (!string.IsNullOrEmpty(template.Script))
        {
            _fragments.ScriptTagStart.CopyTo(span.Slice(offset));
            offset += _fragments.ScriptTagStart.Length;
            offset += plans.Script.ExecuteSingleSpan(span.Slice(offset), keys, values, app.AppMetaDataKeys, app.AppMetaDataValues);
            _fragments.ScriptTagEnd.CopyTo(span.Slice(offset));
            offset += _fragments.ScriptTagEnd.Length;
        }

        // Body end
        _fragments.BodyEndAndHtmlEnd.CopyTo(span.Slice(offset));
        offset += _fragments.BodyEndAndHtmlEnd.Length;

        // Single Advance + Flush — one GetSpan, one Advance, one Flush
        writer.Advance(offset);
        await writer.FlushAsync();

        ref var stats = ref RenderStatsProvider.GetStats();
        stats.WriteCount = 1;
        stats.BytesWritten = offset;
        stats.FlushCount = 1;
    }

    /// <summary>
    /// Pre-bound route plans rendering to ArrayBufferWriter for compression path.
    /// </summary>
    private ReadOnlyMemory<byte> RenderToBytesWithPlans(
        RouteRenderPlans plans, IHtmlTemplate template,
        string[] keys, string[] values,
        IBareWebHost app,
        string[]? tableColumnTitles, string[][]? tableRows,
        FormDefinition? formDefinition)
    {
        var arena = new ArrayBufferWriter<byte>(16384);

        WriteToBuffer(arena, _fragments.DocTypeAndHeadStart);
        WriteToBuffer(arena, template.Encoding.WebName);
        WriteToBuffer(arena, "'>");

        plans.Head.Execute(arena, keys, values, app.AppMetaDataKeys, app.AppMetaDataValues);

        WriteToBuffer(arena, _fragments.HeadEndAndBodyStart);

        int byteCount = 2
            + (tableColumnTitles is not null && tableRows is not null ? 1 : 0)
            + (formDefinition is not null ? 1 : 0);
        var byteKeysArr = new string[byteCount];
        var byteValuesArr = new byte[byteCount][];
        byteKeysArr[0] = "links_left";
        byteValuesArr[0] = _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: false);
        byteKeysArr[1] = "links_right";
        byteValuesArr[1] = _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: true);
        int idx = 2;
        if (tableColumnTitles != null && tableRows != null)
        {
            byteKeysArr[idx] = "table";
            byteValuesArr[idx++] = _fragments.RenderTable(tableColumnTitles, tableRows);
        }
        if (formDefinition is not null)
        {
            byteKeysArr[idx] = "form";
            byteValuesArr[idx] = _fragments.RenderForm(formDefinition);
        }

        plans.Body.Execute(arena, keys, values, app.AppMetaDataKeys, app.AppMetaDataValues, byteKeysArr, byteValuesArr);
        plans.Footer.Execute(arena, keys, values, app.AppMetaDataKeys, app.AppMetaDataValues);

        if (!string.IsNullOrEmpty(template.Script))
        {
            WriteToBuffer(arena, _fragments.ScriptTagStart);
            plans.Script.Execute(arena, keys, values, app.AppMetaDataKeys, app.AppMetaDataValues);
            WriteToBuffer(arena, _fragments.ScriptTagEnd);
        }

        WriteToBuffer(arena, _fragments.BodyEndAndHtmlEnd);
        return arena.WrittenMemory;
    }

    /// <summary>
    /// Zero-copy compiled streaming renderer. Pre-compiled RenderPlans write directly
    /// to the PipeWriter with no intermediate buffer. Single flush at the end.
    /// </summary>
    public async ValueTask RenderToStreamCompiledAsync(PipeWriter writer, IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null)
    {
        var plans = GetOrCompilePlans(template);

        // Structural fragments: doctype + encoding
        Write(writer, _fragments.DocTypeAndHeadStart);
        Write(writer, template.Encoding.WebName);
        Write(writer, "'>");

        // Head section via compiled plan
        plans.Head.Execute(writer, keys, values, appkeys, appvalues);

        Write(writer, _fragments.HeadEndAndBodyStart);

        // Build byte-rendered tokens for body
        int byteCount = 2
            + (tableColumnTitles is not null && tableRows is not null ? 1 : 0)
            + (formDefinition is not null ? 1 : 0);
        var byteKeysArr = new string[byteCount];
        var byteValuesArr = new byte[byteCount][];
        byteKeysArr[0] = "links_left";
        byteValuesArr[0] = _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: false);
        byteKeysArr[1] = "links_right";
        byteValuesArr[1] = _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: true);
        int idx = 2;
        if (tableColumnTitles != null && tableRows != null)
        {
            byteKeysArr[idx] = "table";
            byteValuesArr[idx++] = _fragments.RenderTable(tableColumnTitles, tableRows);
        }
        if (formDefinition is not null)
        {
            byteKeysArr[idx] = "form";
            byteValuesArr[idx] = _fragments.RenderForm(formDefinition);
        }

        // Body + footer via compiled plan (PipeWriter is IBufferWriter<byte> — zero copy)
        plans.Body.Execute(writer, keys, values, appkeys, appvalues, byteKeysArr, byteValuesArr);
        plans.Footer.Execute(writer, keys, values, appkeys, appvalues);

        if (!string.IsNullOrEmpty(template.Script))
        {
            Write(writer, _fragments.ScriptTagStart);
            plans.Script.Execute(writer, keys, values, appkeys, appvalues);
            Write(writer, _fragments.ScriptTagEnd);
        }

        Write(writer, _fragments.BodyEndAndHtmlEnd);
        await writer.FlushAsync();
        RenderStatsProvider.GetStats().FlushCount++;
    }

    /// <summary>
    /// Compiled + buffered path: uses compiled plans writing to ArrayBufferWriter,
    /// returns the bytes for compression. Falls back to this when response needs
    /// post-processing (compression, banner injection).
    /// </summary>
    public ValueTask<ReadOnlyMemory<byte>> RenderToBytesCompiledAsync(IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null)
    {
        var plans = GetOrCompilePlans(template);
        var arena = new ArrayBufferWriter<byte>(16384);

        WriteToBuffer(arena, _fragments.DocTypeAndHeadStart);
        WriteToBuffer(arena, template.Encoding.WebName);
        WriteToBuffer(arena, "'>");

        plans.Head.Execute(arena, keys, values, appkeys, appvalues);

        WriteToBuffer(arena, _fragments.HeadEndAndBodyStart);

        int byteCount = 2
            + (tableColumnTitles is not null && tableRows is not null ? 1 : 0)
            + (formDefinition is not null ? 1 : 0);
        var byteKeysArr = new string[byteCount];
        var byteValuesArr = new byte[byteCount][];
        byteKeysArr[0] = "links_left";
        byteValuesArr[0] = _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: false);
        byteKeysArr[1] = "links_right";
        byteValuesArr[1] = _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: true);
        int idx = 2;
        if (tableColumnTitles != null && tableRows != null)
        {
            byteKeysArr[idx] = "table";
            byteValuesArr[idx++] = _fragments.RenderTable(tableColumnTitles, tableRows);
        }
        if (formDefinition is not null)
        {
            byteKeysArr[idx] = "form";
            byteValuesArr[idx] = _fragments.RenderForm(formDefinition);
        }

        plans.Body.Execute(arena, keys, values, appkeys, appvalues, byteKeysArr, byteValuesArr);
        plans.Footer.Execute(arena, keys, values, appkeys, appvalues);

        if (!string.IsNullOrEmpty(template.Script))
        {
            WriteToBuffer(arena, _fragments.ScriptTagStart);
            plans.Script.Execute(arena, keys, values, appkeys, appvalues);
            WriteToBuffer(arena, _fragments.ScriptTagEnd);
        }

        WriteToBuffer(arena, _fragments.BodyEndAndHtmlEnd);

        return ValueTask.FromResult<ReadOnlyMemory<byte>>(arena.WrittenMemory);
    }
    private static void RenderSection(
        PipeWriter writer,
        string template,
        string[] keys,
        string[] values,
        string[] appkeys,
        string[] appvalues,
        string[]? keysforbytesrendered,
        byte[][]? bytesrendered,
        TemplateLoop[]? templateLoops,
        string[]? scopedKeys = null,
        string[]? scopedValues = null
        )
    {
        RenderSection(writer, template.AsSpan(), keys, values, appkeys, appvalues, keysforbytesrendered, bytesrendered, templateLoops, scopedKeys, scopedValues);
    }

    private static void RenderSection(
        PipeWriter writer,
        ReadOnlySpan<char> span,
        string[] keys,
        string[] values,
        string[] appkeys,
        string[] appvalues,
        string[]? keysforbytesrendered,
        byte[][]? bytesrendered,
        TemplateLoop[]? templateLoops,
        string[]? scopedKeys,
        string[]? scopedValues
        )
    {
        int pos = 0;
        while (pos < span.Length)
        {
            // SIMD-accelerated scan: .NET's IndexOf uses SSE2/NEON vectorised search.
            int openIdx = span.Slice(pos).IndexOf("{{".AsSpan());

            if (openIdx < 0)
            {
                // No more tokens — write the remainder as one contiguous slice.
                Write(writer, span.Slice(pos));
                return;
            }

            // Write all literal characters before '{{'.
            if (openIdx > 0)
                Write(writer, span.Slice(pos, openIdx));

            int bodyStart = pos + openIdx + 2; // first char of token key

            // SIMD-accelerated scan for the closing '}}' delimiter.
            int closeRelIdx = span.Slice(bodyStart).IndexOf("}}".AsSpan());

            if (closeRelIdx < 0)
            {
                // Malformed template — no matching '}}'. Emit literal '{{' and advance.
                Write(writer, span.Slice(pos + openIdx, 2));
                pos = pos + openIdx + 1;
                continue;
            }

            var keySpan  = span.Slice(bodyStart, closeRelIdx);
            int tokenEnd = bodyStart + closeRelIdx + 2; // first char after '}}'

            if (TryParseLoopToken(keySpan, out var loopKey) &&
                TryFindClosingTag(span, tokenEnd, LoopTagKind.Loop, loopKey, out var endTagStart, out var endTagEnd))
            {
                if (TryGetLoop(loopKey, templateLoops, out var loop))
                {
                    var loopBody = span.Slice(tokenEnd, endTagStart - tokenEnd);
                    foreach (var item in loop.Items)
                    {
                        var (itemKeys, itemValues) = BuildScopedKeyValues(item, scopedKeys, scopedValues);
                        RenderSection(writer, loopBody, keys, values, appkeys, appvalues, keysforbytesrendered, bytesrendered, templateLoops, itemKeys, itemValues);
                    }
                }

                pos = endTagEnd + 1;
                continue;
            }

            if (TryParseForToken(keySpan, out var forSpec) &&
                TryFindClosingTag(span, tokenEnd, LoopTagKind.For, forSpec.Variable, out endTagStart, out endTagEnd))
            {
                var loopBody = span.Slice(tokenEnd, endTagStart - tokenEnd);
                foreach (var iterationValue in EnumerateForLoopValues(forSpec))
                {
                    var (itemKeys, itemValues) = BuildScopedKeyValues(
                        new Dictionary<string, string>(StringComparer.Ordinal)
                        {
                            [forSpec.Variable] = iterationValue
                        },
                        scopedKeys,
                        scopedValues);

                    RenderSection(writer, loopBody, keys, values, appkeys, appvalues, keysforbytesrendered, bytesrendered, templateLoops, itemKeys, itemValues);
                }

                pos = endTagEnd + 1;
                continue;
            }

            bool matched = false;

            if (!matched && scopedKeys != null && scopedValues != null)
            {
                for (int k = 0; k < scopedKeys.Length; k++)
                {
                    if (keySpan.SequenceEqual(scopedKeys[k]))
                    {
                        WriteTokenValue(writer, keySpan, scopedValues[k]);
                        matched = true;
                        break;
                    }
                }
            }

            // First set: page metadata
            if (!matched)
            {
                for (int k = 0; k < keys.Length; k++)
                {
                    if (keySpan.SequenceEqual(keys[k]))
                    {
                        WriteTokenValue(writer, keySpan, values[k]);
                        matched = true;
                        break;
                    }
                }
            }

            // Second set: app metadata (only if not matched)
            if (!matched)
            {
                for (int k = 0; k < appkeys.Length; k++)
                {
                    if (keySpan.SequenceEqual(appkeys[k]))
                    {
                        WriteTokenValue(writer, keySpan, appvalues[k]);
                        matched = true;
                        break;
                    }
                }
            }
            // Third set - pre-rendered/encoded bytes to insert to replace a token
            if (!matched && keysforbytesrendered != null && bytesrendered != null)
            {
                for (int k = 0; k < keysforbytesrendered.Length; k++)
                {
                    if (keySpan.SequenceEqual(keysforbytesrendered[k]))
                    {
                        Write(writer, bytesrendered[k]);
                        matched = true;
                        break;
                    }
                }
            }
            // Lastly drop it if we have a {{unknown}} token

            // no replace needed make it vanish from output

            pos = tokenEnd;
        }
    }

    private enum LoopTagKind
    {
        Loop,
        For
    }

    private readonly record struct ForLoopSpec(string Variable, int From, int To, int Increment);

    private static bool TryParseLoopToken(ReadOnlySpan<char> token, out string loopKey)
    {
        if (!token.StartsWith("Loop%%".AsSpan(), StringComparison.Ordinal))
        {
            loopKey = string.Empty;
            return false;
        }

        loopKey = token.Slice(6).ToString().Trim();
        return !string.IsNullOrWhiteSpace(loopKey);
    }

    private static bool TryParseForToken(ReadOnlySpan<char> token, out ForLoopSpec spec)
    {
        spec = default;
        if (!token.StartsWith("For%%".AsSpan(), StringComparison.Ordinal))
            return false;

        var content = token.Slice(5).ToString();

        // Span-based '|' splitting to avoid string[] allocation
        var contentSpan = content.AsSpan();
        // Count '|' separators
        int pipeCount = 0;
        foreach (var c in contentSpan) { if (c == '|') pipeCount++; }

        if (pipeCount == 4)
        {
            // Skip first segment (5 parts -> drop first to get 4)
            int firstPipe = contentSpan.IndexOf('|');
            contentSpan = contentSpan[(firstPipe + 1)..];
        }
        else if (pipeCount != 3)
            return false;

        int s1 = contentSpan.IndexOf('|');
        if (s1 < 0) return false;
        int s2 = contentSpan[(s1 + 1)..].IndexOf('|'); if (s2 < 0) return false; s2 += s1 + 1;
        int s3 = contentSpan[(s2 + 1)..].IndexOf('|'); if (s3 < 0) return false; s3 += s2 + 1;

        var variable = contentSpan[..s1].Trim();
        if (variable.IsEmpty) return false;

        if (!int.TryParse(contentSpan[(s1 + 1)..s2].Trim(), out var from))
            return false;
        if (!int.TryParse(contentSpan[(s2 + 1)..s3].Trim(), out var to))
            return false;
        if (!int.TryParse(contentSpan[(s3 + 1)..].Trim(), out var increment) || increment == 0)
            return false;

        spec = new ForLoopSpec(variable.ToString(), from, to, increment);
        return !string.IsNullOrWhiteSpace(spec.Variable);
    }

    private static IEnumerable<string> EnumerateForLoopValues(ForLoopSpec spec)
    {
        if (spec.Increment > 0)
        {
            for (int value = spec.From; value <= spec.To; value += spec.Increment)
            {
                yield return value.ToString();
            }
        }
        else
        {
            for (int value = spec.From; value >= spec.To; value += spec.Increment)
            {
                yield return value.ToString();
            }
        }
    }

    private static bool TryFindClosingTag(ReadOnlySpan<char> span, int searchStart, LoopTagKind kind, string? expectedKey, out int endTagStart, out int endTagEnd)
    {
        endTagStart = -1;
        endTagEnd = -1;
        int depth = 0;

        for (int i = searchStart; i < span.Length - 1; i++)
        {
            if (span[i] == '{' && span[i + 1] == '{')
            {
                int tokenStart = i + 2;
                int j = tokenStart;

                while (j + 1 < span.Length && !(span[j] == '}' && span[j + 1] == '}'))
                {
                    j++;
                }

                if (j + 1 >= span.Length)
                    break;

                var token = span.Slice(tokenStart, j - tokenStart);

                if (IsStartTag(token, kind))
                {
                    depth++;
                }
                else if (IsEndTag(token, kind, expectedKey))
                {
                    if (depth == 0)
                    {
                        endTagStart = i;
                        endTagEnd = j + 1;
                        return true;
                    }

                    depth--;
                }

                i = j + 1;
            }
        }

        return false;
    }

    private static bool IsStartTag(ReadOnlySpan<char> token, LoopTagKind kind)
        => kind switch
        {
            LoopTagKind.Loop => token.StartsWith("Loop%%".AsSpan(), StringComparison.Ordinal),
            LoopTagKind.For => token.StartsWith("For%%".AsSpan(), StringComparison.Ordinal),
            _ => false
        };

    private static bool IsEndTag(ReadOnlySpan<char> token, LoopTagKind kind, string? expectedKey)
    {
        return kind switch
        {
            LoopTagKind.Loop => token.StartsWith("EndLoop".AsSpan(), StringComparison.Ordinal) && MatchesLoopEndKey(token, expectedKey),
            LoopTagKind.For => token.StartsWith("EndFor".AsSpan(), StringComparison.Ordinal) && MatchesLoopEndKey(token, expectedKey),
            _ => false
        };
    }

    private static bool MatchesLoopEndKey(ReadOnlySpan<char> token, string? expectedKey)
    {
        if (string.IsNullOrEmpty(expectedKey))
            return true;

        var delimiterIndex = token.IndexOf("%%".AsSpan());
        if (delimiterIndex < 0)
            return true;

        var key = token.Slice(delimiterIndex + 2).ToString().Trim();
        return string.IsNullOrEmpty(key) || string.Equals(key, expectedKey, StringComparison.Ordinal);
    }

    private static bool TryGetLoop(string loopKey, TemplateLoop[]? templateLoops, out TemplateLoop loop)
    {
        if (templateLoops != null)
        {
            for (int i = 0; i < templateLoops.Length; i++)
            {
                if (string.Equals(templateLoops[i].Key, loopKey, StringComparison.Ordinal))
                {
                    loop = templateLoops[i];
                    return true;
                }
            }
        }

        loop = default!;
        return false;
    }

    private static (string[] Keys, string[] Values) BuildScopedKeyValues(
        IReadOnlyDictionary<string, string> newValues,
        string[]? existingKeys,
        string[]? existingValues)
    {
        var keys = new List<string>(newValues.Count + (existingKeys?.Length ?? 0));
        var values = new List<string>(newValues.Count + (existingValues?.Length ?? 0));

        foreach (var kvp in newValues)
        {
            keys.Add(kvp.Key);
            values.Add(kvp.Value);
        }

        if (existingKeys != null && existingValues != null)
        {
            for (int i = 0; i < existingKeys.Length; i++)
            {
                keys.Add(existingKeys[i]);
                values.Add(existingValues[i]);
            }
        }

        return (keys.ToArray(), values.ToArray());
    }

    private static void Write(PipeWriter writer, string text)
    {
        int byteCount = Utf8.GetByteCount(text);
        Span<byte> buffer = writer.GetSpan(byteCount);
        Utf8.GetBytes(text, buffer);
        writer.Advance(byteCount);
        RenderStatsProvider.GetStats().WriteCount++;
        RenderStatsProvider.GetStats().BytesWritten += byteCount;
    }

    private static void Write(PipeWriter writer, byte[] encodedtext)
    {
        int byteCount = encodedtext.Length;
        Span<byte> buffer = writer.GetSpan(byteCount);
        encodedtext.CopyTo(buffer);
        writer.Advance(byteCount);
        RenderStatsProvider.GetStats().WriteCount++;
        RenderStatsProvider.GetStats().BytesWritten += byteCount;
        RenderStatsProvider.GetStats().FragmentCount++;
    }

    private static void Write(PipeWriter writer, ReadOnlySpan<char> span)
    {
        int maxBytes = Utf8.GetMaxByteCount(span.Length);
        Span<byte> buffer = writer.GetSpan(maxBytes);
        int bytesWritten = Utf8.GetBytes(span, buffer);
        writer.Advance(bytesWritten);
        RenderStatsProvider.GetStats().WriteCount++;
        RenderStatsProvider.GetStats().BytesWritten += bytesWritten;
    }

    private static void Write(PipeWriter writer, char c)
    {
        Span<byte> buffer = writer.GetSpan(4);
        int bytesWritten = Utf8.GetBytes(
            new ReadOnlySpan<char>(ref c),
            buffer);
        writer.Advance(bytesWritten);
        RenderStatsProvider.GetStats().WriteCount++;
        RenderStatsProvider.GetStats().BytesWritten += bytesWritten;
    }

    // ── Arena (IBufferWriter<byte>) write methods ──────────────────────────────

    private static void WriteToBuffer(IBufferWriter<byte> writer, string text)
    {
        int byteCount = Utf8.GetByteCount(text);
        Span<byte> buffer = writer.GetSpan(byteCount);
        Utf8.GetBytes(text, buffer);
        writer.Advance(byteCount);
        RenderStatsProvider.GetStats().WriteCount++;
        RenderStatsProvider.GetStats().BytesWritten += byteCount;
    }

    private static void WriteToBuffer(IBufferWriter<byte> writer, byte[] encodedtext)
    {
        Span<byte> buffer = writer.GetSpan(encodedtext.Length);
        encodedtext.CopyTo(buffer);
        writer.Advance(encodedtext.Length);
        RenderStatsProvider.GetStats().WriteCount++;
        RenderStatsProvider.GetStats().BytesWritten += encodedtext.Length;
        RenderStatsProvider.GetStats().FragmentCount++;
    }

    private static void WriteToBuffer(IBufferWriter<byte> writer, ReadOnlySpan<char> span)
    {
        int maxBytes = Utf8.GetMaxByteCount(span.Length);
        Span<byte> buffer = writer.GetSpan(maxBytes);
        int bytesWritten = Utf8.GetBytes(span, buffer);
        writer.Advance(bytesWritten);
        RenderStatsProvider.GetStats().WriteCount++;
        RenderStatsProvider.GetStats().BytesWritten += bytesWritten;
    }

    private static void WriteTokenValueToBuffer(IBufferWriter<byte> writer, ReadOnlySpan<char> keySpan, string value)
    {
        RenderStatsProvider.GetStats().TokenCount++;
        if (keySpan.StartsWith("html_".AsSpan(), StringComparison.Ordinal))
        {
            if (!string.IsNullOrEmpty(value))
                WriteToBuffer(writer, value);
        }
        else
            WriteHtmlEncodedToBuffer(writer, value);
    }

    private static void WriteHtmlEncodedToBuffer(IBufferWriter<byte> writer, string? text)
    {
        if (string.IsNullOrEmpty(text))
            return;

        ReadOnlySpan<char> span = text.AsSpan();
        int i = 0;
        int segStart = 0;

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
                WriteToBuffer(writer, span.Slice(segStart, i - segStart));

            WriteToBuffer(writer, entity);
            i++;
            segStart = i;
        }

        if (segStart < span.Length)
            WriteToBuffer(writer, span.Slice(segStart));
    }

    private static void RenderSectionToBuffer(
        IBufferWriter<byte> writer,
        string template,
        string[] keys,
        string[] values,
        string[] appkeys,
        string[] appvalues,
        string[]? keysforbytesrendered,
        byte[][]? bytesrendered,
        TemplateLoop[]? templateLoops,
        string[]? scopedKeys = null,
        string[]? scopedValues = null)
    {
        RenderSectionToBuffer(writer, template.AsSpan(), keys, values, appkeys, appvalues, keysforbytesrendered, bytesrendered, templateLoops, scopedKeys, scopedValues);
    }

    private static void RenderSectionToBuffer(
        IBufferWriter<byte> writer,
        ReadOnlySpan<char> span,
        string[] keys,
        string[] values,
        string[] appkeys,
        string[] appvalues,
        string[]? keysforbytesrendered,
        byte[][]? bytesrendered,
        TemplateLoop[]? templateLoops,
        string[]? scopedKeys,
        string[]? scopedValues)
    {
        int pos = 0;
        while (pos < span.Length)
        {
            int openIdx = span.Slice(pos).IndexOf("{{".AsSpan());

            if (openIdx < 0)
            {
                WriteToBuffer(writer, span.Slice(pos));
                return;
            }

            if (openIdx > 0)
                WriteToBuffer(writer, span.Slice(pos, openIdx));

            int bodyStart = pos + openIdx + 2;
            int closeRelIdx = span.Slice(bodyStart).IndexOf("}}".AsSpan());

            if (closeRelIdx < 0)
            {
                WriteToBuffer(writer, span.Slice(pos + openIdx, 2));
                pos = pos + openIdx + 1;
                continue;
            }

            var keySpan = span.Slice(bodyStart, closeRelIdx);
            int tokenEnd = bodyStart + closeRelIdx + 2;

            if (TryParseLoopToken(keySpan, out var loopKey) &&
                TryFindClosingTag(span, tokenEnd, LoopTagKind.Loop, loopKey, out var endTagStart, out var endTagEnd))
            {
                if (TryGetLoop(loopKey, templateLoops, out var loop))
                {
                    var loopBody = span.Slice(tokenEnd, endTagStart - tokenEnd);
                    foreach (var item in loop.Items)
                    {
                        var (itemKeys, itemValues) = BuildScopedKeyValues(item, scopedKeys, scopedValues);
                        RenderSectionToBuffer(writer, loopBody, keys, values, appkeys, appvalues, keysforbytesrendered, bytesrendered, templateLoops, itemKeys, itemValues);
                    }
                }
                pos = endTagEnd + 1;
                continue;
            }

            if (TryParseForToken(keySpan, out var forSpec) &&
                TryFindClosingTag(span, tokenEnd, LoopTagKind.For, forSpec.Variable, out endTagStart, out endTagEnd))
            {
                var loopBody = span.Slice(tokenEnd, endTagStart - tokenEnd);
                foreach (var iterationValue in EnumerateForLoopValues(forSpec))
                {
                    var (itemKeys, itemValues) = BuildScopedKeyValues(
                        new Dictionary<string, string>(StringComparer.Ordinal) { [forSpec.Variable] = iterationValue },
                        scopedKeys, scopedValues);
                    RenderSectionToBuffer(writer, loopBody, keys, values, appkeys, appvalues, keysforbytesrendered, bytesrendered, templateLoops, itemKeys, itemValues);
                }
                pos = endTagEnd + 1;
                continue;
            }

            bool matched = false;

            if (!matched && scopedKeys != null && scopedValues != null)
            {
                for (int k = 0; k < scopedKeys.Length; k++)
                {
                    if (keySpan.SequenceEqual(scopedKeys[k]))
                    {
                        WriteTokenValueToBuffer(writer, keySpan, scopedValues[k]);
                        matched = true;
                        break;
                    }
                }
            }

            if (!matched)
            {
                for (int k = 0; k < keys.Length; k++)
                {
                    if (keySpan.SequenceEqual(keys[k]))
                    {
                        WriteTokenValueToBuffer(writer, keySpan, values[k]);
                        matched = true;
                        break;
                    }
                }
            }

            if (!matched)
            {
                for (int k = 0; k < appkeys.Length; k++)
                {
                    if (keySpan.SequenceEqual(appkeys[k]))
                    {
                        WriteTokenValueToBuffer(writer, keySpan, appvalues[k]);
                        matched = true;
                        break;
                    }
                }
            }

            if (!matched && keysforbytesrendered != null && bytesrendered != null)
            {
                for (int k = 0; k < keysforbytesrendered.Length; k++)
                {
                    if (keySpan.SequenceEqual(keysforbytesrendered[k]))
                    {
                        WriteToBuffer(writer, bytesrendered[k]);
                        matched = true;
                        break;
                    }
                }
            }

            pos = tokenEnd;
        }
    }

    private static void WriteTokenValue(PipeWriter writer, ReadOnlySpan<char> keySpan, string value)
    {
        RenderStatsProvider.GetStats().TokenCount++;
        // Keys prefixed with "html_" carry pre-rendered HTML and must be written raw.
        // All other tokens are HTML-encoded for defense-in-depth XSS protection.
        if (keySpan.StartsWith("html_".AsSpan(), StringComparison.Ordinal))
        {
            if (!string.IsNullOrEmpty(value))
                Write(writer, value);
        }
        else
            WriteHtmlEncoded(writer, value);
    }

    private static void WriteHtmlEncoded(PipeWriter writer, string? text)
    {
        // Write HTML-encoded text directly to the PipeWriter without allocating an intermediate string.
        if (string.IsNullOrEmpty(text))
            return;

        ReadOnlySpan<char> span = text.AsSpan();
        int i = 0;
        int segStart = 0;

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

            // Flush literal segment before the special char
            if (i > segStart)
                Write(writer, span.Slice(segStart, i - segStart));

            Write(writer, entity);
            i++;
            segStart = i;
        }

        // Flush any remaining literal tail
        if (segStart < span.Length)
            Write(writer, span.Slice(segStart));
    }

    public async ValueTask RenderPage(BmwContext context)
    {
        var app = context.App;
        var page = context.PageInfo;

        if (app == null || page == null)
        {
            context.StatusCode = StatusCodes.Status500InternalServerError;
            return;
        }

        await RenderPage(context, page, app);
    }

    public async ValueTask RenderPage(BmwContext context, PageInfo page, IBareWebHost app)
    {
        RenderStatsProvider.Reset(); // reset per-render counters
        var renderSw = Stopwatch.StartNew();
        // Ensure CSP nonce is in page context — search without List allocation
        var pageContext = page.PageContext;
        var existingKeys = pageContext.PageMetaDataKeys;
        int nonceIndex = -1;
        for (int i = 0; i < existingKeys.Length; i++)
        {
            if (string.Equals(existingKeys[i], "csp_nonce", StringComparison.Ordinal))
            {
                nonceIndex = i;
                break;
            }
        }

        if (nonceIndex < 0)
        {
            var nonce = context.GetCspNonce();
            var existingValues = pageContext.PageMetaDataValues;
            var newKeys = new string[existingKeys.Length + 1];
            var newValues = new string[existingValues.Length + 1];
            Array.Copy(existingKeys, newKeys, existingKeys.Length);
            Array.Copy(existingValues, newValues, existingValues.Length);
            newKeys[existingKeys.Length] = "csp_nonce";
            newValues[existingValues.Length] = nonce;
            pageContext = pageContext with
            {
                PageMetaDataKeys = newKeys,
                PageMetaDataValues = newValues
            };
            page = page with { PageContext = pageContext };
        }

        // Inject theme_css_url — resolved server-side from the bm-selected-theme cookie
        // so the browser fetches exactly one theme stylesheet with no client-side swap.
        pageContext = page.PageContext;
        var currentKeys = pageContext.PageMetaDataKeys;
        bool hasThemeUrl = false;
        for (int i = 0; i < currentKeys.Length; i++)
        {
            if (string.Equals(currentKeys[i], "theme_css_url", StringComparison.Ordinal))
            {
                hasThemeUrl = true;
                break;
            }
        }

        if (!hasThemeUrl)
        {
            var themeUrl = GetThemeCssUrl(context);
            var existingValuesForTheme = pageContext.PageMetaDataValues;
            var keysWithTheme   = new string[currentKeys.Length + 1];
            var valuesWithTheme = new string[existingValuesForTheme.Length + 1];
            Array.Copy(currentKeys, keysWithTheme, currentKeys.Length);
            Array.Copy(existingValuesForTheme, valuesWithTheme, existingValuesForTheme.Length);
            keysWithTheme[currentKeys.Length]                   = "theme_css_url";
            valuesWithTheme[existingValuesForTheme.Length]      = themeUrl;
            pageContext = pageContext with
            {
                PageMetaDataKeys   = keysWithTheme,
                PageMetaDataValues = valuesWithTheme
            };
            page = page with { PageContext = pageContext };
        }

        context.StatusCode = page.PageMetaData.StatusCode;
        context.ContentType = page.PageMetaData.Template.ContentTypeHeader;

        var encoding = CompressionHelper.SelectEncoding(context);
        bool needsCompression = encoding is "br" or "gzip";
        bool needsBanner = ShouldShowDiagnosticBanner(context, app);
        bool hasLoops = page.PageContext.TemplateLoops is { Length: > 0 };

        // Route-level pre-bound plans from jump table (fastest path)
        var routePlans = context.CompiledPlans;

        // Zero-copy path: compiled plan writes directly to the response PipeWriter.
        // Only possible when we don't need post-processing (compression, banner, loops).
        if (!needsCompression && !needsBanner && !hasLoops)
        {
            CompressionHelper.ApplyHeaders(context, encoding);
            if (routePlans != null)
            {
                // Single-span path: one GetSpan, one Advance, one Flush (fastest possible)
                await RenderWithPlansSingleSpanAsync(
                    context.ResponseBody, routePlans,
                    page.PageMetaData.Template,
                    page.PageContext.PageMetaDataKeys,
                    page.PageContext.PageMetaDataValues,
                    app, page.PageContext.TableColumnTitles,
                    page.PageContext.TableData,
                    page.PageContext.FormDefinition);
            }
            else
            {
                await RenderToStreamCompiledAsync(
                    context.ResponseBody,
                    page.PageMetaData.Template,
                    page.PageContext.PageMetaDataKeys,
                    page.PageContext.PageMetaDataValues,
                    app.AppMetaDataKeys,
                    app.AppMetaDataValues,
                    app,
                    page.PageContext.TableColumnTitles,
                    page.PageContext.TableData,
                    page.PageContext.FormDefinition,
                    page.PageContext.TemplateLoops);
            }
        }
        else
        {
            // Buffered path: render to bytes, then compress/inject banner.
            ReadOnlyMemory<byte> output;
            if (hasLoops)
            {
                output = await RenderToBytesAsync(
                    page.PageMetaData.Template,
                    page.PageContext.PageMetaDataKeys,
                    page.PageContext.PageMetaDataValues,
                    app.AppMetaDataKeys,
                    app.AppMetaDataValues,
                    app,
                    page.PageContext.TableColumnTitles,
                    page.PageContext.TableData,
                    page.PageContext.FormDefinition,
                    page.PageContext.TemplateLoops);
            }
            else if (routePlans != null)
            {
                output = RenderToBytesWithPlans(
                    routePlans, page.PageMetaData.Template,
                    page.PageContext.PageMetaDataKeys,
                    page.PageContext.PageMetaDataValues,
                    app, page.PageContext.TableColumnTitles,
                    page.PageContext.TableData,
                    page.PageContext.FormDefinition);
            }
            else
            {
                output = await RenderToBytesCompiledAsync(
                    page.PageMetaData.Template,
                    page.PageContext.PageMetaDataKeys,
                    page.PageContext.PageMetaDataValues,
                    app.AppMetaDataKeys,
                    app.AppMetaDataValues,
                    app,
                    page.PageContext.TableColumnTitles,
                    page.PageContext.TableData,
                    page.PageContext.FormDefinition,
                    page.PageContext.TemplateLoops);
            }

            if (needsBanner)
            {
                var bannerHtml = BuildDiagnosticBannerHtml(context, app, output.Length);
                output = InjectBeforeBodyEnd(output.Span, Utf8.GetBytes(bannerHtml));
            }

            ReadOnlyMemory<byte> responseBytes = encoding switch
            {
                "br"   => CompressionHelper.CompressBrotli(output.Span),
                "gzip" => CompressionHelper.CompressGzip(output.Span),
                _      => output
            };
            CompressionHelper.ApplyHeaders(context, encoding);
            context.ContentLength = responseBytes.Length;
            await context.ResponseBody.WriteAsync(responseBytes);
        }

        renderSw.Stop();
        OnRenderComplete?.Invoke(renderSw.Elapsed);
        OnRenderCompleteWithStats?.Invoke(renderSw.Elapsed, RenderStatsProvider.GetStats());

    }

    // ── Diagnostic banner helpers ──────────────────────────────────────────────

    public static bool ShouldShowDiagnosticBanner(BmwContext context, IBareWebHost app)
    {
        if (!app.ShowHostDiagnostics)
            return false;
        // Read query string from request headers (avoids HttpContext allocation)
        var qs = context.Request.QueryString;
        bool showHst = qs.Contains("showhst=true", StringComparison.OrdinalIgnoreCase);
        return showHst;
    }

    public static string BuildDiagnosticBannerHtml(BmwContext context, IBareWebHost app, int payloadBytes)
    {
        var initialHost = context.RequestHeaders.TryGetValue("X-Forwarded-Host", out var fwdHost) && !string.IsNullOrEmpty(fwdHost)
            ? fwdHost.ToString()
            : context.RequestHeaders.Host.ToString();
        var serverHost = System.Net.Dns.GetHostName();
        var rttMs = app.Metrics.GetSnapshot().RecentAverageResponseTime.TotalMilliseconds;
        return $"<div id=\"bm-diag-banner\" style=\"position:fixed;bottom:40px;right:0;background:rgba(0,0,0,0.85);color:#0f0;font-family:monospace;font-size:11px;padding:4px 8px;z-index:99999;border-radius:4px 0 0 4px\">" +
               $"&#9670; init:{WebUtility.HtmlEncode(initialHost)} | svr:{WebUtility.HtmlEncode(serverHost)} | rtt:{rttMs:F2}ms | payload:{payloadBytes:N0}B" +
               "</div>";
    }

    /// <summary>Inserts <paramref name="insertBytes"/> immediately before the final <c>&lt;/body&gt;</c> tag in <paramref name="source"/>.</summary>
    public static byte[] InjectBeforeBodyEnd(ReadOnlySpan<byte> source, ReadOnlySpan<byte> insertBytes)
    {
        // </body> in UTF-8 is the 7-byte ASCII sequence 3C 2F 62 6F 64 79 3E
        ReadOnlySpan<byte> bodyEndTag = [(byte)'<', (byte)'/', (byte)'b', (byte)'o', (byte)'d', (byte)'y', (byte)'>'];

        if (source.Length < bodyEndTag.Length)
        {
            var tiny = new byte[source.Length + insertBytes.Length];
            source.CopyTo(tiny);
            insertBytes.CopyTo(tiny.AsSpan(source.Length));
            return tiny;
        }

        // Search backwards for </body>
        int insertPos = source.LastIndexOf(bodyEndTag);

        if (insertPos < 0)
        {
            var fallback = new byte[source.Length + insertBytes.Length];
            source.CopyTo(fallback);
            insertBytes.CopyTo(fallback.AsSpan(source.Length));
            return fallback;
        }

        var result = new byte[source.Length + insertBytes.Length];
        source[..insertPos].CopyTo(result);
        insertBytes.CopyTo(result.AsSpan(insertPos));
        source[insertPos..].CopyTo(result.AsSpan(insertPos + insertBytes.Length));
        return result;
    }

    // ── Theme helpers ──────────────────────────────────────────────────────────

    private static readonly HashSet<string> _validThemes = new(StringComparer.OrdinalIgnoreCase)
    {
        "cerulean", "cosmo",    "cyborg",   "darkly",  "flatly",
        "journal",  "litera",   "lumen",    "lux",     "materia",
        "minty",    "morph",    "pulse",    "quartz",  "sandstone",
        "simplex",  "sketchy",  "slate",    "solar",   "spacelab",
        "superhero","united",   "vapor",    "yeti",    "zephyr"
    };

    private const string DefaultTheme   = "vapor";
    private const string ThemeCookieKey = "bm-selected-theme";

    private static string GetThemeCssUrl(BmwContext context)
    {
        // Cookie access requires lazy HttpContext bridge — acceptable for HTML renders
        var cookie = context.GetCookie(ThemeCookieKey);
        var theme  = (!string.IsNullOrEmpty(cookie) && _validThemes.Contains(cookie))
                     ? cookie
                     : DefaultTheme;
        return $"/static/css/themes/{theme}.min.css";
    }
}