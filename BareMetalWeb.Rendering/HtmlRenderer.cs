using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.IO.Pipelines;
using System.Net;
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
    private static readonly Encoding Utf8 = Encoding.UTF8;
    private readonly IHtmlFragmentRenderer _fragments;

    public HtmlRenderer(IHtmlFragmentRenderer fragments)
    {
        _fragments = fragments;
    }

    public async ValueTask<byte[]> RenderToBytesAsync(IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null)
    {
        using var ms = new MemoryStream();
        var pipeWriter = PipeWriter.Create(ms);
        await RenderToStreamAsync(pipeWriter, template, keys, values, appkeys, appvalues, app, tableColumnTitles, tableRows, formDefinition, templateLoops);
        await pipeWriter.CompleteAsync();
        return ms.ToArray();
    }

    public async ValueTask RenderToStreamAsync(PipeWriter writer, IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null)
    {
        Write(writer, _fragments.DocTypeAndHeadStart);
        Write(writer, template.Encoding.WebName);
        Write(writer, "'>");

        RenderSection(writer, template.Head, keys, values, appkeys, appvalues, null, null, templateLoops);

        Write(writer, _fragments.HeadEndAndBodyStart);

        // The menu is part of the app metadata and should be injected here if present from the apps property app.MenuOptionsList so lets pre-render that with the helper
        // Add the pre-rendered menu options to the output value and key for substitution as 'links'
        var byteKeysList = new List<string> { "links_left", "links_right" };
        var byteValuesList = new List<byte[]>
        {
            _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: false),
            _fragments.RenderMenuOptions(app.MenuOptionsList, rightAligned: true)
        };

        if (tableColumnTitles != null && tableRows != null)
        {
            byteKeysList.Add("table");
            byteValuesList.Add(_fragments.RenderTable(tableColumnTitles, tableRows));
        }
        if (formDefinition is not null)
        {
            byteKeysList.Add("form");
            byteValuesList.Add(_fragments.RenderForm(formDefinition));
        }
       
        RenderSection(writer, template.Body, keys, values, appkeys, appvalues, byteKeysList.ToArray(), byteValuesList.ToArray(), templateLoops);
        RenderSection(writer, template.Footer, keys, values, appkeys, appvalues, null, null, templateLoops);

        if (!string.IsNullOrEmpty(template.Script))
        {
            Write(writer, _fragments.ScriptTagStart);
            RenderSection(writer, template.Script, keys, values, appkeys, appvalues, null, null, templateLoops);
            Write(writer, _fragments.ScriptTagEnd);
        }

        Write(writer, _fragments.BodyEndAndHtmlEnd);
        await writer.FlushAsync();
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
        for (int i = 0; i < span.Length; i++)
        {
            if (span[i] == '{' &&
                i + 1 < span.Length &&
                span[i + 1] == '{')
            {
                int start = i + 2;
                int j = start;

                while (j + 1 < span.Length &&
                       !(span[j] == '}' && span[j + 1] == '}'))
                {
                    j++;
                }

                if (j + 1 < span.Length)
                {
                    var keySpan = span.Slice(start, j - start);

                    if (TryParseLoopToken(keySpan, out var loopKey) &&
                        TryFindClosingTag(span, j + 2, LoopTagKind.Loop, loopKey, out var endTagStart, out var endTagEnd))
                    {
                        if (TryGetLoop(loopKey, templateLoops, out var loop))
                        {
                            var loopBody = span.Slice(j + 2, endTagStart - (j + 2));
                            foreach (var item in loop.Items)
                            {
                                var (itemKeys, itemValues) = BuildScopedKeyValues(item, scopedKeys, scopedValues);
                                RenderSection(writer, loopBody, keys, values, appkeys, appvalues, keysforbytesrendered, bytesrendered, templateLoops, itemKeys, itemValues);
                            }
                        }

                        i = endTagEnd;
                        continue;
                    }

                    if (TryParseForToken(keySpan, out var forSpec) &&
                        TryFindClosingTag(span, j + 2, LoopTagKind.For, forSpec.Variable, out endTagStart, out endTagEnd))
                    {
                        var loopBody = span.Slice(j + 2, endTagStart - (j + 2));
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

                        i = endTagEnd;
                        continue;
                    }

                    bool matched = false;

                    if (!matched && scopedKeys != null && scopedValues != null)
                    {
                        for (int k = 0; k < scopedKeys.Length; k++)
                        {
                            if (keySpan.SequenceEqual(scopedKeys[k]))
                            {
                                WriteHtmlEncoded(writer, scopedValues[k]);
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
                                WriteHtmlEncoded(writer, values[k]);
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
                                WriteHtmlEncoded(writer, appvalues[k]);
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
                    if (!matched)
                    {
                        // Do nothing, effectively removing the unknown token
                    }

                    i = j + 1;
                    continue;
                }
            }

            Write(writer, span[i]);
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
        var parts = content.Split('|', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length == 5)
        {
            parts = parts.Skip(1).ToArray();
        }

        if (parts.Length != 4)
            return false;

        if (!int.TryParse(parts[1], out var from))
            return false;
        if (!int.TryParse(parts[2], out var to))
            return false;
        if (!int.TryParse(parts[3], out var increment) || increment == 0)
            return false;

        spec = new ForLoopSpec(parts[0], from, to, increment);
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
    }

    private static void Write(PipeWriter writer, byte[] encodedtext)
    {
        int byteCount = encodedtext.Length;
        Span<byte> buffer = writer.GetSpan(byteCount);
        encodedtext.CopyTo(buffer);
        writer.Advance(byteCount);
    }

    private static void Write(PipeWriter writer, ReadOnlySpan<char> span)
    {
        // Worst case: 4 bytes per char in UTF-8
        int maxBytes = Utf8.GetMaxByteCount(span.Length);
        Span<byte> buffer = writer.GetSpan(maxBytes);

        int bytesWritten = Utf8.GetBytes(span, buffer);
        writer.Advance(bytesWritten);
    }

    private static void Write(PipeWriter writer, char c)
    {
        // Intentionally using span-over-char to avoid allocation
        Span<byte> buffer = writer.GetSpan(4);
        int bytesWritten = Utf8.GetBytes(
            new ReadOnlySpan<char>(ref c),
            buffer);
        writer.Advance(bytesWritten);
    }

    private static void WriteHtmlEncoded(PipeWriter writer, string text)
    {
        // HTML encode the text to prevent XSS injection through template tokens
        // Handle null by treating as empty string
        var encoded = WebUtility.HtmlEncode(text ?? string.Empty);
        Write(writer, encoded);
    }

    public async ValueTask RenderPage(HttpContext context)
    {
        var app = context.GetApp();
        var page = context.GetPageInfo();

        if (app == null || page == null)
        {
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            return;
        }

        await RenderPage(context, page, app);
    }

    public async ValueTask RenderPage(HttpContext context, PageInfo page, IBareWebHost app)
    {
        // Ensure CSP nonce is in page context
        var pageContext = page.PageContext;
        var keys = pageContext.PageMetaDataKeys.ToList();
        var values = pageContext.PageMetaDataValues.ToList();
        
        var nonceIndex = keys.FindIndex(k => string.Equals(k, "csp_nonce", StringComparison.Ordinal));
        if (nonceIndex < 0)
        {
            var nonce = context.GetCspNonce();
            keys.Add("csp_nonce");
            values.Add(nonce);
            pageContext = pageContext with
            {
                PageMetaDataKeys = keys.ToArray(),
                PageMetaDataValues = values.ToArray()
            };
            page = page with { PageContext = pageContext };
        }
        
        byte[] output = await RenderToBytesAsync(
            page.PageMetaData.Template,
            page.PageContext.PageMetaDataKeys,
            page.PageContext.PageMetaDataValues,
            app.AppMetaDataKeys,
            app.AppMetaDataValues,
            app,
            page.PageContext.TableColumnTitles,
            page.PageContext.TableData,
            page.PageContext.FormDefinition,
            page.PageContext.TemplateLoops
        );
        context.Response.StatusCode = page.PageMetaData.StatusCode;
        context.Response.ContentType = page.PageMetaData.Template.ContentTypeHeader;
        await context.Response.BodyWriter.WriteAsync(output);

    }
}