using System.IO.Pipelines;
using System.Net;
using System.Text;
using BareMetalWeb.Data;

namespace BareMetalWeb.Host;

/// <summary>
/// Renders a <see cref="ReportResult"/> as a self-contained HTML document, writing
/// directly to a <see cref="PipeWriter"/> for low-allocation streaming output.
/// </summary>
public static class ReportHtmlRenderer
{

    /// <summary>
    /// Renders the report result to the PipeWriter as a complete HTML document.
    /// </summary>
    public static async ValueTask RenderAsync(
        PipeWriter writer,
        ReportResult result,
        string title,
        string description = "",
        IReadOnlyList<ReportParameter>? parameters = null,
        IReadOnlyDictionary<string, string>? parameterValues = null,
        string reportId = "")
    {
        Write(writer, "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        Write(writer, "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        Write(writer, "<title>");
        WriteEncoded(writer, title);
        Write(writer, "</title>");
        Write(writer, ReportCss);
        Write(writer, "</head><body><div class=\"bm-page-card\">");

        // Header
        Write(writer, "<div class=\"report-header\"><h1 class=\"report-title\">");
        WriteEncoded(writer, title);
        Write(writer, "</h1>");
        if (!string.IsNullOrWhiteSpace(description))
        {
            Write(writer, "<p class=\"report-description\">");
            WriteEncoded(writer, description);
            Write(writer, "</p>");
        }
        Write(writer, "</div>");

        // Parameter form (if any)
        if (parameters != null && parameters.Count > 0)
        {
            Write(writer, "<form class=\"report-params\" method=\"get\">");
            Write(writer, "<div class=\"params-grid\">");
            foreach (var p in parameters)
            {
                Write(writer, "<div class=\"param-group\"><label>");
                WriteEncoded(writer, p.Label);
                Write(writer, "</label><input type=\"text\" name=\"");
                WriteEncoded(writer, p.Name);
                Write(writer, "\" value=\"");
                var val = parameterValues != null && parameterValues.TryGetValue(p.Name, out var pv) ? pv : p.DefaultValue;
                WriteEncoded(writer, val);
                Write(writer, "\"></div>");
            }
            Write(writer, "</div>");
            Write(writer, "<button type=\"submit\" class=\"btn-run\">Run Report</button>");
            Write(writer, "</form>");
        }

        // Results table
        Write(writer, "<div class=\"table-wrapper\"><table class=\"bm-table\">");

        // Column headers
        Write(writer, "<thead><tr>");
        foreach (var col in result.ColumnLabels)
        {
            Write(writer, "<th>");
            WriteEncoded(writer, col);
            Write(writer, "</th>");
        }
        Write(writer, "</tr></thead>");

        // Data rows
        Write(writer, "<tbody>");
        foreach (var row in result.Rows)
        {
            Write(writer, "<tr>");
            foreach (var cell in row)
            {
                Write(writer, "<td>");
                WriteEncoded(writer, cell ?? string.Empty);
                Write(writer, "</td>");
            }
            Write(writer, "</tr>");
        }
        Write(writer, "</tbody></table></div>");

        // Footer
        Write(writer, "<div class=\"report-footer\">");
        Write(writer, $"<span class=\"row-count\">{result.TotalRows:N0} row(s)</span>");
        if (result.IsTruncated)
            Write(writer, $" <span class=\"truncated-warning\">(results capped at {ReportExecutor.DefaultRowLimit:N0} rows)</span>");
        Write(writer, $" &mdash; Generated at {WebUtility.HtmlEncode(result.GeneratedAt.ToString("yyyy-MM-dd HH:mm:ss"))} UTC");

        // Export links
        if (!string.IsNullOrWhiteSpace(reportId))
        {
            Write(writer, " &mdash; <a href=\"/api/reports/");
            WriteEncoded(writer, reportId);
            Write(writer, "?format=csv\" class=\"export-link\">Export CSV</a>");
        }

        Write(writer, "</div></div></body></html>");

        await writer.FlushAsync();
    }

    // ── Low-allocation write helpers ─────────────────────────────────────────

    private static void Write(PipeWriter writer, string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        var byteCount = Encoding.UTF8.GetByteCount(text);
        var span = writer.GetSpan(byteCount);
        Encoding.UTF8.GetBytes(text.AsSpan(), span);
        writer.Advance(byteCount);
    }

    private static void WriteEncoded(PipeWriter writer, string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        Write(writer, WebUtility.HtmlEncode(text));
    }

    // ── Embedded CSS ─────────────────────────────────────────────────────────

    private const string ReportCss = """
        <style>
        *{box-sizing:border-box;margin:0;padding:0}
        body{font-family:system-ui,-apple-system,sans-serif;background:#f4f6f9;color:#333;padding:24px}
        .bm-page-card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.12);padding:24px;max-width:1400px;margin:0 auto}
        .report-header{margin-bottom:20px;border-bottom:2px solid #e8eaf6;padding-bottom:16px}
        .report-title{font-size:1.6em;font-weight:700;color:#1a1a2e}
        .report-description{color:#666;margin-top:8px;font-size:.95em}
        .report-params{background:#f8f9fc;border:1px solid #e0e0e0;border-radius:6px;padding:16px;margin-bottom:20px}
        .params-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-bottom:12px}
        .param-group label{display:block;font-size:.85em;font-weight:600;color:#555;margin-bottom:4px}
        .param-group input{width:100%;padding:8px 10px;border:1px solid #ccc;border-radius:4px;font-size:.9em}
        .btn-run{padding:8px 20px;background:#4361ee;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:.95em;font-weight:600}
        .btn-run:hover{background:#3a56d4}
        .table-wrapper{overflow-x:auto;margin-bottom:16px}
        .bm-table{width:100%;border-collapse:collapse;font-size:.9em}
        .bm-table th{background:#e8eaf6;text-align:left;padding:10px 12px;font-weight:600;color:#444;border-bottom:2px solid #c5cae9;white-space:nowrap}
        .bm-table td{padding:8px 12px;border-bottom:1px solid #eee;vertical-align:top}
        .bm-table tbody tr:hover{background:#f5f7ff}
        .bm-table tbody tr:nth-child(even){background:#fafbff}
        .bm-table tbody tr:nth-child(even):hover{background:#f0f3ff}
        .report-footer{font-size:.85em;color:#777;padding-top:12px;border-top:1px solid #eee}
        .row-count{font-weight:600;color:#333}
        .truncated-warning{color:#e65100;font-weight:600}
        .export-link{color:#4361ee;text-decoration:none;font-weight:600}
        .export-link:hover{text-decoration:underline}
        @media print{body{background:#fff;padding:0}.btn-run,.export-link{display:none}.bm-page-card{box-shadow:none;padding:8px}}
        </style>
        """;
}
