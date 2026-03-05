using System.Buffers;
using System.Collections.Generic;

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

    private static void WriteTokenValue(PipeWriter writer, ReadOnlySpan<char> keySpan, string value)
    {
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

        if (ShouldShowDiagnosticBanner(context, app))
        {
            var bannerHtml = BuildDiagnosticBannerHtml(context, app, output.Length);
            output = InjectBeforeBodyEnd(output, Utf8.GetBytes(bannerHtml));
        }

        context.Response.StatusCode = page.PageMetaData.StatusCode;
        context.Response.ContentType = page.PageMetaData.Template.ContentTypeHeader;

        var encoding = CompressionHelper.SelectEncoding(context);
        var responseBytes = CompressionHelper.Compress(output, encoding);
        CompressionHelper.ApplyHeaders(context.Response, encoding);
        context.Response.ContentLength = responseBytes.Length;
        await context.Response.BodyWriter.WriteAsync(responseBytes);

    }

    // ── Diagnostic banner helpers ──────────────────────────────────────────────

    public static bool ShouldShowDiagnosticBanner(HttpContext context, IBareWebHost app)
    {
        if (!app.ShowHostDiagnostics)
            return false;
        string? qsVal = string.Empty; var showhstValues = context.Request.Query["showhst"]; if (showhstValues.Count > 0) qsVal = showhstValues[0] ?? string.Empty; else qsVal = string.Empty;
        return string.Equals(qsVal, "true", StringComparison.OrdinalIgnoreCase);
    }

    public static string BuildDiagnosticBannerHtml(HttpContext context, IBareWebHost app, int payloadBytes)
    {
        var initialHost = context.Request.Headers.TryGetValue("X-Forwarded-Host", out var fwdHost) && !string.IsNullOrEmpty(fwdHost)
            ? fwdHost.ToString()
            : context.Request.Host.Value;
        var serverHost = System.Net.Dns.GetHostName();
        var rttMs = app.Metrics.GetSnapshot().RecentAverageResponseTime.TotalMilliseconds;
        return $"<div id=\"bm-diag-banner\" style=\"position:fixed;bottom:40px;right:0;background:rgba(0,0,0,0.85);color:#0f0;font-family:monospace;font-size:11px;padding:4px 8px;z-index:99999;border-radius:4px 0 0 4px\">" +
               $"&#9670; init:{WebUtility.HtmlEncode(initialHost)} | svr:{WebUtility.HtmlEncode(serverHost)} | rtt:{rttMs:F2}ms | payload:{payloadBytes:N0}B" +
               "</div>";
    }

    /// <summary>Inserts <paramref name="insertBytes"/> immediately before the final <c>&lt;/body&gt;</c> tag in <paramref name="source"/>.</summary>
    public static byte[] InjectBeforeBodyEnd(byte[] source, byte[] insertBytes)
    {
        // </body> in UTF-8 is the 7-byte ASCII sequence 3C 2F 62 6F 64 79 3E
        const int bodyEndTagLen = 7; // </body>
        if (source.Length < bodyEndTagLen)
        {
            // Source too short to contain </body> — append at end
            var tiny = new byte[source.Length + insertBytes.Length];
            Array.Copy(source, 0, tiny, 0, source.Length);
            Array.Copy(insertBytes, 0, tiny, source.Length, insertBytes.Length);
            return tiny;
        }

        // Search backwards from the last possible position for </body>
        int insertPos = source.Length - bodyEndTagLen;
        while (insertPos >= 0)
        {
            if (source[insertPos]     == 0x3C && // '<'
                source[insertPos + 1] == 0x2F && // '/'
                source[insertPos + 2] == 0x62 && // 'b'
                source[insertPos + 3] == 0x6F && // 'o'
                source[insertPos + 4] == 0x64 && // 'd'
                source[insertPos + 5] == 0x79 && // 'y'
                source[insertPos + 6] == 0x3E)   // '>'
            {
                break;
            }
            insertPos--;
        }

        if (insertPos < 0)
        {
            // </body> not found — append the banner at the end as a fallback
            var fallback = new byte[source.Length + insertBytes.Length];
            Array.Copy(source, 0, fallback, 0, source.Length);
            Array.Copy(insertBytes, 0, fallback, source.Length, insertBytes.Length);
            return fallback;
        }

        var result = new byte[source.Length + insertBytes.Length];
        Array.Copy(source, 0, result, 0, insertPos);
        Array.Copy(insertBytes, 0, result, insertPos, insertBytes.Length);
        Array.Copy(source, insertPos, result, insertPos + insertBytes.Length, source.Length - insertPos);
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

    private static string GetThemeCssUrl(HttpContext context)
    {
        var cookie = context.GetCookie(ThemeCookieKey);
        var theme  = (!string.IsNullOrEmpty(cookie) && _validThemes.Contains(cookie))
                     ? cookie
                     : DefaultTheme;
        return $"/static/css/themes/{theme}.min.css";
    }
}