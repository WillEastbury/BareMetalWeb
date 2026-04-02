using System.Text;
using System.Text.RegularExpressions;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Renders Page entities (Markdown or HTML) inside the platform chrome shell.
/// Handles GET /page/{slug} route.
/// </summary>
public static partial class PageRenderer
{
    [GeneratedRegex(@"\*\*(.+?)\*\*")]
    private static partial Regex BoldRegex();
    [GeneratedRegex(@"\*(.+?)\*")]
    private static partial Regex ItalicRegex();
    [GeneratedRegex(@"`(.+?)`")]
    private static partial Regex CodeRegex();
    [GeneratedRegex(@"\[(.+?)\]\((.+?)\)")]
    private static partial Regex LinkRegex();
    [GeneratedRegex(@"(?i)(href|src|action)\s*=\s*[""']\s*(javascript|data|vbscript)\s*:", RegexOptions.IgnoreCase)]
    private static partial Regex DangerousAttrRegex();

    /// <summary>Strip dangerous protocol handlers from raw HTML content.</summary>
    private static string SanitizeHtml(string html)
    {
        if (string.IsNullOrEmpty(html)) return html;
        return DangerousAttrRegex().Replace(html, m => $"{m.Groups[1].Value}=\"about:blank\" data-stripped=\"");
    }

    /// <summary>Configures context for GET /page/{slug} inside platform chrome.</summary>
    public static async ValueTask ConfigurePageAsync(BmwContext context)
    {
        var slug = BinaryApiHandlers.GetRouteValue(context, "slug") ?? string.Empty;

        if (string.IsNullOrWhiteSpace(slug))
        {
            context.Response.StatusCode = 400;
            context.SetStringValue("title", "Page");
            context.SetStringValue("html_message", "<p>Page slug is required.</p>");
            return;
        }

        if (!DataScaffold.TryGetEntity("pages", out var meta))
        {
            context.Response.StatusCode = 500;
            context.SetStringValue("title", "Page");
            context.SetStringValue("html_message", "<p>Page entity not configured.</p>");
            return;
        }

        // Find published page by slug — use filtered query instead of full table scan
        var queryDef = new BareMetalWeb.Data.QueryDefinition
        {
            Clauses = new()
            {
                new BareMetalWeb.Data.QueryClause { Field = "Slug", Operator = BareMetalWeb.Data.QueryOperator.Equals, Value = slug },
                new BareMetalWeb.Data.QueryClause { Field = "Status", Operator = BareMetalWeb.Data.QueryOperator.Equals, Value = "published" }
            },
            Top = 1
        };
        var pages = await meta.Handlers.QueryAsync(queryDef, context.RequestAborted);
        DataRecord? pageObj = null;
        foreach (var p in pages)
        {
            pageObj = p;
            break;
        }

        if (pageObj == null)
        {
            context.Response.StatusCode = 404;
            context.SetStringValue("title", "Page Not Found");
            context.SetStringValue("html_message", "<p>Page not found.</p>");
            return;
        }

        var title = GetField(pageObj, meta, "Title");
        var content = GetField(pageObj, meta, "Content");
        var format = GetField(pageObj, meta, "Format");

        // Convert markdown to HTML if needed; sanitize dangerous protocols in both paths
        var htmlContent = string.Equals(format, "markdown", StringComparison.OrdinalIgnoreCase)
            ? ConvertMarkdownToHtml(content)
            : SanitizeHtml(content);

        var sb = new StringBuilder(4096);
        sb.AppendLine("""<div class="container-fluid py-4 px-4 bm-content">""");
        sb.AppendLine("""  <div class="card shadow-sm bm-page-card">""");
        sb.AppendLine("""    <div class="card-body">""");
        sb.AppendLine($"""      <h1 class="mb-4">{System.Net.WebUtility.HtmlEncode(title)}</h1>""");
        sb.AppendLine("""      <div class="page-content">""");
        sb.AppendLine(htmlContent);
        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");
        sb.AppendLine("  </div>");
        sb.AppendLine("</div>");

        context.SetStringValue("title", title);
        context.SetStringValue("html_message", sb.ToString());
    }

    /// <summary>API handler: GET /api/pages — list published pages for navigation.</summary>
    public static async ValueTask ListPagesHandler(BmwContext context)
    {
        if (!DataScaffold.TryGetEntity("pages", out var meta))
        {
            context.Response.StatusCode = 200;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("[]");
            return;
        }

        var pages = await meta.Handlers.QueryAsync(null, context.RequestAborted);
        var published = new List<(string Slug, string Title, int NavOrder, bool ShowInNav)>();

        foreach (var p in pages)
        {
            var status = GetField(p, meta, "Status");
            if (!string.Equals(status, "published", StringComparison.OrdinalIgnoreCase)) continue;

            published.Add((
                GetField(p, meta, "Slug"),
                GetField(p, meta, "Title"),
                int.TryParse(GetField(p, meta, "NavOrder"), out var order) ? order : 100,
                string.Equals(GetField(p, meta, "ShowInNav"), "True", StringComparison.OrdinalIgnoreCase)));
        }

        published.Sort((a, b) => a.NavOrder.CompareTo(b.NavOrder));

        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/json";
        await using var w = new System.Text.Json.Utf8JsonWriter(context.Response.Body);
        w.WriteStartArray();
        foreach (var (s, t, _, showNav) in published)
        {
            w.WriteStartObject();
            w.WriteString("slug", s);
            w.WriteString("title", t);
            w.WriteBoolean("showInNav", showNav);
            w.WriteString("url", $"/page/{s}");
            w.WriteEndObject();
        }
        w.WriteEndArray();
        await w.FlushAsync(context.RequestAborted);
    }

    // ── Minimal Markdown → HTML conversion ──────────────────────────────────

    private static string ConvertMarkdownToHtml(string markdown)
    {
        if (string.IsNullOrWhiteSpace(markdown)) return string.Empty;

        var lines = markdown.Split('\n');
        var sb = new StringBuilder(markdown.Length * 2);
        bool inList = false;
        bool inCodeBlock = false;

        foreach (var rawLine in lines)
        {
            var line = rawLine.TrimEnd('\r');

            // Fenced code blocks
            if (line.StartsWith("```"))
            {
                if (inCodeBlock) { sb.AppendLine("</code></pre>"); inCodeBlock = false; }
                else { sb.AppendLine("<pre><code>"); inCodeBlock = true; }
                continue;
            }
            if (inCodeBlock) { sb.AppendLine(System.Net.WebUtility.HtmlEncode(line)); continue; }

            // Headers
            if (line.StartsWith("### ")) { CloseLi(sb, ref inList); sb.AppendLine($"<h3>{InlineFormat(line[4..])}</h3>"); continue; }
            if (line.StartsWith("## ")) { CloseLi(sb, ref inList); sb.AppendLine($"<h2>{InlineFormat(line[3..])}</h2>"); continue; }
            if (line.StartsWith("# ")) { CloseLi(sb, ref inList); sb.AppendLine($"<h1>{InlineFormat(line[2..])}</h1>"); continue; }

            // Horizontal rule
            if (line.StartsWith("---") || line.StartsWith("***")) { CloseLi(sb, ref inList); sb.AppendLine("<hr/>"); continue; }

            // Unordered list
            if (line.StartsWith("- ") || line.StartsWith("* "))
            {
                if (!inList) { sb.AppendLine("<ul>"); inList = true; }
                sb.AppendLine($"<li>{InlineFormat(line[2..])}</li>");
                continue;
            }

            // Close list if non-list line
            CloseLi(sb, ref inList);

            // Empty line = paragraph break
            if (string.IsNullOrWhiteSpace(line)) { sb.AppendLine("<br/>"); continue; }

            // Regular paragraph
            sb.AppendLine($"<p>{InlineFormat(line)}</p>");
        }

        CloseLi(sb, ref inList);
        if (inCodeBlock) sb.AppendLine("</code></pre>");

        return sb.ToString();
    }

    private static void CloseLi(StringBuilder sb, ref bool inList)
    {
        if (inList) { sb.AppendLine("</ul>"); inList = false; }
    }

    private static string InlineFormat(string text)
    {
        var encoded = System.Net.WebUtility.HtmlEncode(text);
        // Bold
        encoded = BoldRegex().Replace(encoded, "<strong>$1</strong>");
        // Italic
        encoded = ItalicRegex().Replace(encoded, "<em>$1</em>");
        // Code
        encoded = CodeRegex().Replace(encoded, "<code>$1</code>");
        // Links [text](url) — validate URL protocol to prevent javascript: XSS
        encoded = LinkRegex().Replace(encoded, m =>
        {
            var linkText = m.Groups[1].Value;
            var url = System.Net.WebUtility.HtmlDecode(m.Groups[2].Value).Trim();
            if (IsSafeUrl(url))
                return $"""<a href="{System.Net.WebUtility.HtmlEncode(url)}">{linkText}</a>""";
            return linkText; // strip unsafe link, keep text
        });
        return encoded;
    }

    private static bool IsSafeUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url)) return false;
        // Allow relative URLs
        if (url.StartsWith('/') && !url.StartsWith("//")) return true;
        if (url.StartsWith('#') || url.StartsWith('?')) return true;
        // Allow safe protocols only
        if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) return true;
        if (url.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) return true;
        if (url.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static string GetField(DataRecord obj, DataEntityMetadata meta, string fieldName)
    {
        BareMetalWeb.Core.DataFieldMetadata? field = null;
        foreach (var f in meta.Fields)
        {
            if (string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase))
            {
                field = f;
                break;
            }
        }
        return field?.GetValueFn?.Invoke(obj)?.ToString() ?? string.Empty;
    }
}
