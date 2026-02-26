using System.IO.Pipelines;
using System.Net;
using System.Text;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Data;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Host;

/// <summary>
/// Renders a <see cref="ReportResult"/> as an HTML document using the standard
/// site chrome (Bootstrap navbar, Bootstrap CSS, site.css), writing directly to
/// a <see cref="PipeWriter"/> for low-allocation streaming output.
/// </summary>
public static class ReportHtmlRenderer
{

    /// <summary>
    /// Renders the report result to the PipeWriter as a complete HTML document
    /// using the standard VNext-style Bootstrap chrome.
    /// </summary>
    public static async ValueTask RenderAsync(
        PipeWriter writer,
        ReportResult result,
        string title,
        string description = "",
        IReadOnlyList<ReportParameter>? parameters = null,
        IReadOnlyDictionary<string, string>? parameterValues = null,
        string reportId = "",
        IBareWebHost? host = null,
        string? nonce = null,
        string? csrfToken = null)
    {
        var safeNonce = WebUtility.HtmlEncode(nonce ?? string.Empty);
        var safeToken = WebUtility.HtmlEncode(csrfToken ?? string.Empty);

        // Chrome head
        var headSb = new StringBuilder(2048);
        AppendChromeHead(headSb, title, safeNonce, safeToken);
        Write(writer, headSb.ToString());

        // Chrome navbar
        if (host != null)
        {
            var navSb = new StringBuilder(1024);
            AppendChromeNavbar(navSb, host, safeNonce);
            Write(writer, navSb.ToString());
        }

        Write(writer, "<div class=\"container-fluid py-4 px-4 bm-content\">");
        Write(writer, "<div class=\"card shadow-sm bm-page-card\">");
        Write(writer, "<div class=\"card-header d-flex align-items-center justify-content-between flex-wrap gap-2\">");
        Write(writer, "<h1 class=\"h5 mb-0\"><i class=\"bi bi-bar-chart-fill\"></i> ");
        WriteEncoded(writer, title);
        Write(writer, "</h1>");
        Write(writer, "<a href=\"/reports\" class=\"btn btn-sm btn-outline-secondary\"><i class=\"bi bi-arrow-left\"></i> All Reports</a>");
        Write(writer, "</div><div class=\"card-body\">");

        // Description
        if (!string.IsNullOrWhiteSpace(description))
        {
            Write(writer, "<p class=\"text-muted mb-3\">");
            WriteEncoded(writer, description);
            Write(writer, "</p>");
        }

        // Parameter form (if any)
        if (parameters != null && parameters.Count > 0)
        {
            Write(writer, "<form class=\"row g-3 mb-4\" method=\"get\">");
            foreach (var p in parameters)
            {
                Write(writer, "<div class=\"col-auto\"><label class=\"form-label fw-semibold\">");
                WriteEncoded(writer, p.Label);
                Write(writer, "</label><input type=\"text\" class=\"form-control\" name=\"");
                WriteEncoded(writer, p.Name);
                Write(writer, "\" value=\"");
                var val = parameterValues != null && parameterValues.TryGetValue(p.Name, out var pv) ? pv : p.DefaultValue;
                WriteEncoded(writer, val);
                Write(writer, "\"></div>");
            }
            Write(writer, "<div class=\"col-auto align-self-end\"><button type=\"submit\" class=\"btn btn-primary\"><i class=\"bi bi-play-fill\"></i> Run Report</button></div>");
            Write(writer, "</form>");
        }

        // Results table
        Write(writer, "<div class=\"table-responsive\"><table class=\"table table-hover table-bordered align-middle mb-0\">");

        // Column headers
        Write(writer, "<thead class=\"table-light\"><tr>");
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

        // Footer info
        Write(writer, "<div class=\"mt-3 small text-muted\">");
        Write(writer, $"<span class=\"fw-semibold text-body\">{result.TotalRows:N0} row(s)</span>");
        if (result.IsTruncated)
            Write(writer, $" <span class=\"text-warning fw-semibold\">(results capped at {ReportExecutor.DefaultRowLimit:N0} rows)</span>");
        Write(writer, $" &mdash; Generated at {WebUtility.HtmlEncode(result.GeneratedAt.ToString("yyyy-MM-dd HH:mm:ss"))} UTC");

        // Export link
        if (!string.IsNullOrWhiteSpace(reportId))
        {
            Write(writer, " &mdash; <a href=\"/api/reports/");
            WriteEncoded(writer, reportId);
            Write(writer, "?format=csv\" class=\"link-primary fw-semibold\"><i class=\"bi bi-download\"></i> Export CSV</a>");
        }

        Write(writer, "</div></div></div></div>");

        // Chrome footer
        var footerSb = new StringBuilder(512);
        AppendChromeFooter(footerSb, safeNonce, host);
        Write(writer, footerSb.ToString());

        await writer.FlushAsync();
    }

    // ── Chrome helpers (shared with RegisterReportRoutes listing page) ────────

    /// <summary>Appends the standard Bootstrap head section to <paramref name="sb"/>.</summary>
    internal static void AppendChromeHead(StringBuilder sb, string title, string safeNonce, string safeToken)
    {
        sb.Append("<!DOCTYPE html><html lang=\"en\"><head>");
        sb.Append("<meta charset=\"utf-8\">");
        sb.Append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
        sb.Append("<title>");
        sb.Append(WebUtility.HtmlEncode(title));
        sb.Append("</title>");
        sb.Append("<link rel=\"icon\" type=\"image/x-icon\" href=\"/static/favicon.ico\">");
        sb.Append("<link id=\"bootswatch-theme\" rel=\"stylesheet\" href=\"/static/css/bootstrap.min.css\">");
        sb.Append($"<script nonce=\"{safeNonce}\">(function(){{var m=document.cookie.match(/(?:^|;\\s*)bm-selected-theme=([^;]+)/);if(m){{var t=decodeURIComponent(m[1]),a=['cerulean','cosmo','cyborg','darkly','flatly','journal','litera','lumen','lux','materia','minty','morph','pulse','quartz','sandstone','simplex','sketchy','slate','solar','spacelab','superhero','united','vapor','yeti','zephyr'];if(a.indexOf(t)>=0)document.getElementById('bootswatch-theme').href='https://cdn.jsdelivr.net/npm/bootswatch@5.3.3/dist/'+encodeURIComponent(t)+'/bootstrap.min.css';}}}})()</script>");
        sb.Append("<link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css\" crossorigin=\"anonymous\">");
        sb.Append("<link rel=\"stylesheet\" href=\"/static/css/site.css\">");
        if (!string.IsNullOrEmpty(safeToken))
            sb.Append($"<meta name=\"csrf-token\" content=\"{safeToken}\">");
        sb.Append("</head>");
        sb.Append("<body>");
    }

    /// <summary>Appends the standard Bootstrap navbar to <paramref name="sb"/>.</summary>
    internal static void AppendChromeNavbar(StringBuilder sb, IBareWebHost host, string safeNonce)
    {
        sb.Append("<nav class=\"navbar navbar-expand-lg bg-primary navbar-dark fixed-top bm-navbar\">");
        sb.Append("<div class=\"container-fluid\">");
        sb.Append($"<a class=\"navbar-brand\" href=\"/\"><i class=\"bi bi-lightning-charge-fill\"></i> {WebUtility.HtmlEncode(host.AppName)}</a>");
        sb.Append("<button class=\"navbar-toggler\" type=\"button\" data-bs-toggle=\"collapse\" data-bs-target=\"#report-nav-content\" aria-controls=\"report-nav-content\" aria-expanded=\"false\" aria-label=\"Toggle navigation\">");
        sb.Append("<span class=\"navbar-toggler-icon\"></span></button>");
        sb.Append("<div class=\"collapse navbar-collapse\" id=\"report-nav-content\">");
        sb.Append("<ul id=\"vnext-nav-items\" class=\"navbar-nav me-auto mb-2 mb-lg-0\">");
        RouteRegistrationExtensions.AppendVNextLeftNavItems(sb, host.MenuOptionsList);
        sb.Append("</ul>");
        sb.Append("<ul class=\"navbar-nav ms-auto mb-2 mb-lg-0\">");
        RouteRegistrationExtensions.AppendVNextRightNavItems(sb, host.MenuOptionsList);
        sb.Append("</ul></div></div></nav>");
    }

    /// <summary>Appends the standard site footer element, closing Bootstrap scripts, and body/html tags to <paramref name="sb"/>.
    /// When <paramref name="host"/> is provided the footer includes the copyright bar and theme selector matching index.footer.html.</summary>
    internal static void AppendChromeFooter(StringBuilder sb, string safeNonce, IBareWebHost? host = null)
    {
        if (host != null)
        {
            var copyrightYear = WebUtility.HtmlEncode(host.CopyrightYear);
            var companyDesc = WebUtility.HtmlEncode(host.CompanyDescription);
            var appVersion = string.Empty;
            var metaKeys = host.AppMetaDataKeys;
            var metaValues = host.AppMetaDataValues;
            for (int i = 0; i < metaKeys.Length && i < metaValues.Length; i++)
            {
                if (string.Equals(metaKeys[i], "AppVersion", StringComparison.OrdinalIgnoreCase))
                {
                    appVersion = WebUtility.HtmlEncode(metaValues[i]);
                    break;
                }
            }

            sb.Append("<footer class=\"bg-dark text-white py-2 fixed-bottom bm-footer\">");
            sb.Append("<div class=\"container-fluid\"><div class=\"row align-items-center\">");
            sb.Append("<div class=\"col-md-6 small\">");
            sb.Append("<p class=\"mb-0\">&copy;");
            sb.Append(copyrightYear);
            sb.Append(" - ");
            sb.Append(companyDesc);
            sb.Append(", All rights reserved. <span id=\"tz-info\" class=\"ms-2\"></span> <span class=\"text-muted ms-2\">v");
            sb.Append(appVersion);
            sb.Append("</span></p>");
            sb.Append("</div>");
            sb.Append("<div class=\"col-md-6 text-end\">");
            sb.Append("<label for=\"bm-theme-select\" class=\"bm-theme-label\">Theme</label>");
            sb.Append("<select id=\"bm-theme-select\" class=\"bm-theme-select\" aria-label=\"Theme selector\">");
            sb.Append("<option value=\"vapor\">Vapor</option>");
            sb.Append("<option value=\"darkly\">Darkly</option>");
            sb.Append("<option value=\"cyborg\">Cyborg</option>");
            sb.Append("<option value=\"slate\">Slate</option>");
            sb.Append("<option value=\"superhero\">Superhero</option>");
            sb.Append("<option value=\"flatly\">Flatly</option>");
            sb.Append("<option value=\"lux\">Lux</option>");
            sb.Append("</select></div></div></div></footer>");
        }

        sb.Append("<script src=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js\" crossorigin=\"anonymous\"></script>");
        sb.Append($"<script src=\"/static/js/bundle.js\" nonce=\"{safeNonce}\" defer></script>");
        sb.Append("</body></html>");
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
}
