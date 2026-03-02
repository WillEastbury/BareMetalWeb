using System.Text;
using System.Text.RegularExpressions;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Utility methods for Page content rendering (Markdown → HTML conversion)
/// and the list API handler for published pages.
/// The actual page HTML rendering is handled by <see cref="RouteHandlers.PageContentHandler"/>
/// which uses the standard <c>IHtmlRenderer</c> for proper platform chrome and theming.
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

    /// <summary>API handler: GET /api/pages — list published pages for navigation.</summary>
    public static async ValueTask ListPagesHandler(HttpContext context)
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

    // ── Markdown → HTML conversion ──────────────────────────────────────────

    /// <summary>Converts a minimal subset of Markdown to HTML.</summary>
    internal static string ConvertMarkdownToHtml(string markdown)
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
            if (line.StartsWith("## "))  { CloseLi(sb, ref inList); sb.AppendLine($"<h2>{InlineFormat(line[3..])}</h2>"); continue; }
            if (line.StartsWith("# "))   { CloseLi(sb, ref inList); sb.AppendLine($"<h1>{InlineFormat(line[2..])}</h1>"); continue; }

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
        encoded = BoldRegex().Replace(encoded, "<strong>$1</strong>");
        encoded = ItalicRegex().Replace(encoded, "<em>$1</em>");
        encoded = CodeRegex().Replace(encoded, "<code>$1</code>");
        encoded = LinkRegex().Replace(encoded, """<a href="$2">$1</a>""");
        return encoded;
    }

    private static string GetField(BaseDataObject obj, DataEntityMetadata meta, string fieldName)
    {
        var field = meta.Fields.FirstOrDefault(f =>
            string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase));
        return field?.GetValueFn?.Invoke(obj)?.ToString() ?? string.Empty;
    }
}
