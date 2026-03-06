using System.IO.Pipelines;
using System.Net;
using System.Text;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Data;
using BareMetalWeb.Interfaces;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Renders a <see cref="DashboardDefinition"/> as a Bootstrap KPI grid, writing
/// directly to a <see cref="PipeWriter"/> for low-allocation streaming output.
/// Each KPI tile queries the configured entity aggregate and displays the result
/// as a coloured card with an optional SVG sparkline chart.
/// </summary>
public static class DashboardHtmlRenderer
{
    private static readonly string[] AllowedAggFunctions = ["count", "sum", "avg", "min", "max"];

    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>Renders the full dashboard HTML page to <paramref name="writer"/>.</summary>
    public static async ValueTask RenderAsync(
        PipeWriter writer,
        DashboardDefinition def,
        IBareWebHost? host = null,
        string? safeNonce = null,
        string? safeToken = null,
        HttpContext? context = null,
        CancellationToken cancellationToken = default)
    {
        safeNonce ??= string.Empty;
        safeToken ??= string.Empty;

        var headSb = new StringBuilder(2048);
        ReportHtmlRenderer.AppendChromeHead(headSb, def.Name, safeNonce, safeToken);
        Write(writer, headSb.ToString());

        if (host != null)
        {
            var navSb = new StringBuilder(1024);
            ReportHtmlRenderer.AppendChromeNavbar(navSb, host, safeNonce);
            Write(writer, navSb.ToString());
        }

        Write(writer, "<div class=\"container-fluid py-4 px-4 bm-content\">");
        Write(writer, "<div class=\"card shadow-sm bm-page-card\">");
        Write(writer, "<div class=\"card-header d-flex align-items-center justify-content-between flex-wrap gap-2\">");
        Write(writer, "<h1 class=\"h5 mb-0\"><i class=\"bi bi-speedometer2\"></i> ");
        WriteEncoded(writer, def.Name);
        Write(writer, "</h1>");
        Write(writer, "<a href=\"/dashboards\" class=\"btn btn-sm btn-outline-secondary\"><i class=\"bi bi-arrow-left\"></i> All Dashboards</a>");
        Write(writer, "</div><div class=\"card-body\">");

        if (!string.IsNullOrWhiteSpace(def.Description))
        {
            Write(writer, "<p class=\"text-muted mb-4\">");
            WriteEncoded(writer, def.Description);
            Write(writer, "</p>");
        }

        var tiles = def.Tiles;
        if (tiles.Count == 0)
        {
            Write(writer, "<div class=\"text-center py-5 text-muted\">No KPI tiles defined. Add tiles via <a href=\"/dashboard-definitions/");
            Write(writer, WebUtility.UrlEncode(def.Key.ToString()));
            Write(writer, "/edit\">Edit Dashboard</a>.</div>");
        }
        else
        {
            // Resolve all KPI values in parallel
            var resolved = await ResolveTilesAsync(tiles, cancellationToken);

            Write(writer, "<div class=\"row g-3\" id=\"bm-dashboard-tiles\">");
            for (int i = 0; i < resolved.Count; i++)
            {
                RenderTileAt(writer, tiles[i], resolved[i], i);
            }
            Write(writer, "</div>");

            // Auto-refresh script
            Write(writer, $"<script nonce=\"{safeNonce}\">");
            Write(writer, @"(function(){
  var refreshMs = 60000;
  function refreshTiles() {
    var id = location.pathname.split('/').filter(Boolean).pop();
    fetch('/api/dashboards/' + encodeURIComponent(id))
      .then(function(r){return r.json();})
      .then(function(data){
        if (!data || !data.tiles) return;
        data.tiles.forEach(function(t, idx) {
          var el = document.getElementById('bm-kpi-value-' + idx);
          if (el) el.textContent = t.displayValue || '—';
        });
      })
      .catch(function(){/* silent */});
  }
  setTimeout(function tick(){ refreshTiles(); setTimeout(tick, refreshMs); }, refreshMs);
})();");
            Write(writer, "</script>");
        }

        Write(writer, "</div></div></div>");

        var footerSb = new StringBuilder(512);
        ReportHtmlRenderer.AppendChromeFooter(footerSb, safeNonce, host, context);
        Write(writer, footerSb.ToString());

        await writer.FlushAsync(cancellationToken);
    }

    /// <summary>
    /// Resolves each <see cref="DashboardTile"/> to a <see cref="ResolvedTile"/> by executing
    /// the configured aggregate query against the data store.
    /// </summary>
    public static async ValueTask<IReadOnlyList<ResolvedTile>> ResolveTilesAsync(
        IReadOnlyList<DashboardTile> tiles,
        CancellationToken cancellationToken = default)
    {
        // Resolve all tiles in parallel — each tile is an independent aggregate query.
        var tasks = new Task<ResolvedTile>[tiles.Count];
        for (int i = 0; i < tiles.Count; i++)
        {
            var tile = tiles[i];
            tasks[i] = ResolveSingleTileAsync(tile, cancellationToken).AsTask();
        }
        return await Task.WhenAll(tasks).ConfigureAwait(false);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private static async ValueTask<ResolvedTile> ResolveSingleTileAsync(
        DashboardTile tile,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(tile.EntitySlug))
            return new ResolvedTile(tile, null, null, "—");

        if (!DataScaffold.TryGetEntity(tile.EntitySlug, out var meta))
            return new ResolvedTile(tile, null, null, "?");

        // Build query with optional filter
        var query = BuildTileQuery(tile, meta);

        // Resolve aggregate function
        var fn = tile.AggregateFunction?.ToLowerInvariant() ?? "count";
        if (Array.IndexOf(AllowedAggFunctions, fn) < 0) fn = "count";

        var aggFn = fn switch
        {
            "sum" => AggregateFunction.Sum,
            "avg" => AggregateFunction.Average,
            "min" => AggregateFunction.Min,
            "max" => AggregateFunction.Max,
            _ => AggregateFunction.Count,
        };

        AggregateResult aggResult;
        try
        {
            aggResult = await AggregationEngine.ComputeAsync(meta, query, tile.AggregateField ?? string.Empty, aggFn, cancellationToken);
        }
        catch
        {
            return new ResolvedTile(tile, null, null, "Err");
        }

        // Resolve sparkline if configured
        List<SparklineBar>? sparkline = null;
        if (!string.IsNullOrWhiteSpace(tile.SparklineEntitySlug) &&
            !string.IsNullOrWhiteSpace(tile.SparklineGroupField))
        {
            sparkline = await BuildSparklineAsync(tile, cancellationToken);
        }

        var raw = aggResult.Value;
        var display = FormatValue(raw, tile);
        return new ResolvedTile(tile, raw, sparkline, display);
    }

    private static QueryDefinition? BuildTileQuery(DashboardTile tile, DataEntityMetadata meta)
    {
        if (string.IsNullOrWhiteSpace(tile.FilterField) || string.IsNullOrWhiteSpace(tile.FilterValue))
            return null;

        var query = new QueryDefinition();
        query.Clauses.Add(new QueryClause
        {
            Field = tile.FilterField,
            Operator = QueryOperator.Equals,
            Value = tile.FilterValue
        });
        return query;
    }

    private static async ValueTask<List<SparklineBar>> BuildSparklineAsync(
        DashboardTile tile,
        CancellationToken cancellationToken)
    {
        if (!DataScaffold.TryGetEntity(tile.SparklineEntitySlug, out var meta))
            return [];

        var entities = await meta.Handlers.QueryAsync(null, cancellationToken);

        // Find getter for the group-by field
        Func<object, object?>? groupGetter = null;
        foreach (var f in meta.Fields)
        {
            if (string.Equals(f.Name, tile.SparklineGroupField, StringComparison.OrdinalIgnoreCase))
            { groupGetter = f.GetValueFn; break; }
        }
        if (groupGetter == null) return [];

        // Find getter for the aggregate field (may be null for count)
        Func<object, object?>? aggGetter = null;
        if (!string.IsNullOrWhiteSpace(tile.SparklineAggregateField))
        {
            foreach (var f in meta.Fields)
            {
                if (string.Equals(f.Name, tile.SparklineAggregateField, StringComparison.OrdinalIgnoreCase))
                { aggGetter = f.GetValueFn; break; }
            }
        }

        var fn = (tile.SparklineAggregateFunction ?? "count").ToLowerInvariant();

        // Group and accumulate
        var groups = new Dictionary<string, (long Count, double Sum)>(StringComparer.OrdinalIgnoreCase);
        foreach (var entity in entities)
        {
            var groupVal = groupGetter(entity);
            if (groupVal == null) continue;
            // Convert groupVal to string only once; use InvariantCulture for value types.
            var key = groupVal is IFormattable f ? f.ToString(null, System.Globalization.CultureInfo.InvariantCulture) : groupVal.ToString() ?? string.Empty;

            groups.TryGetValue(key, out var acc);
            double addend = 0;
            if (aggGetter != null)
            {
                var fv = aggGetter(entity);
                // Cast numeric types directly to avoid string round-trip allocations.
                if (fv != null)
                {
                    addend = fv switch
                    {
                        double dv   => dv,
                        float fv2   => fv2,
                        decimal dv  => (double)dv,
                        int iv      => iv,
                        long lv     => lv,
                        short sv    => sv,
                        byte bv     => bv,
                        _ when double.TryParse(fv.ToString(), System.Globalization.NumberStyles.Any,
                                System.Globalization.CultureInfo.InvariantCulture, out var parsed) => parsed,
                        _ => 0
                    };
                }
            }
            groups[key] = (acc.Count + 1, acc.Sum + addend);
        }

        if (groups.Count == 0) return [];

        var bars = new List<SparklineBar>(groups.Count);
        foreach (var kvp in groups.OrderBy(k => k.Key))
        {
            double value = fn == "sum" ? kvp.Value.Sum
                : fn == "avg" ? (kvp.Value.Count > 0 ? kvp.Value.Sum / kvp.Value.Count : 0)
                : kvp.Value.Count;
            bars.Add(new SparklineBar(kvp.Key, value));
        }
        return bars;
    }

    private static string FormatValue(object? raw, DashboardTile tile)
    {
        if (raw == null) return "—";
        var numStr = raw is double d ? FormatNumber(d, tile.DecimalPlaces)
                   : raw is long l ? l.ToString()
                   : raw.ToString() ?? "—";
        return $"{tile.ValuePrefix}{numStr}{tile.ValueSuffix}";
    }

    private static string FormatNumber(double value, int decimalPlaces)
    {
        if (decimalPlaces < 0)
            return value == Math.Floor(value) ? ((long)value).ToString("N0") : value.ToString("N2");
        return value.ToString($"N{decimalPlaces}");
    }

    private static void RenderTileAt(PipeWriter writer, DashboardTile tile, ResolvedTile resolved, int index)
    {
        var color = SanitizeColor(tile.Color);
        Write(writer, "<div class=\"col-6 col-md-4 col-lg-3\">");
        Write(writer, $"<div class=\"card border-{color} h-100\">");
        Write(writer, $"<div class=\"card-header bg-{color} text-white d-flex align-items-center gap-2\">");
        Write(writer, $"<i class=\"bi {WebUtility.HtmlEncode(tile.Icon)}\"></i>");
        Write(writer, " ");
        WriteEncoded(writer, tile.Title);
        Write(writer, "</div><div class=\"card-body text-center py-4\">");
        Write(writer, $"<div class=\"display-5 fw-bold\" id=\"bm-kpi-value-{index}\">");
        WriteEncoded(writer, resolved.DisplayValue);
        Write(writer, "</div>");

        if (resolved.Sparkline is { Count: > 0 } bars)
        {
            Write(writer, "<div class=\"mt-2\">");
            Write(writer, BuildSparklineSvg(bars, color));
            Write(writer, "</div>");
        }

        Write(writer, "</div></div></div>");
    }

    private static string BuildSparklineSvg(IReadOnlyList<SparklineBar> bars, string color)
    {
        const int w = 160, h = 40, pad = 2;
        if (bars.Count == 0) return string.Empty;

        var max = bars.Max(b => b.Value);
        if (max <= 0) max = 1;

        var sb = new StringBuilder(256);
        sb.Append($"<svg viewBox=\"0 0 {w} {h}\" width=\"{w}\" height=\"{h}\" aria-hidden=\"true\">");
        var barW = Math.Max(1, (w - pad * (bars.Count + 1)) / bars.Count);
        for (int i = 0; i < bars.Count; i++)
        {
            var barH = (int)Math.Max(1, (bars[i].Value / max) * (h - 2));
            var x = pad + i * (barW + pad);
            var y = h - barH;
            var cssColor = color switch
            {
                "success" => "#198754",
                "danger" => "#dc3545",
                "warning" => "#ffc107",
                "info" => "#0dcaf0",
                "secondary" => "#6c757d",
                _ => "#0d6efd" // primary
            };
            sb.Append($"<rect x=\"{x}\" y=\"{y}\" width=\"{barW}\" height=\"{barH}\" fill=\"{cssColor}\" opacity=\"0.7\" rx=\"1\"><title>{WebUtility.HtmlEncode(bars[i].Label)}: {bars[i].Value:N0}</title></rect>");
        }
        sb.Append("</svg>");
        return sb.ToString();
    }

    private static string SanitizeColor(string? color)
    {
        return color?.ToLowerInvariant() switch
        {
            "primary" or "success" or "danger" or "warning" or "info" or "secondary" or "dark" or "light" => color.ToLowerInvariant(),
            _ => "primary"
        };
    }

    private static void Write(PipeWriter writer, string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        var byteCount = Encoding.UTF8.GetByteCount(text);
        var span = writer.GetSpan(byteCount);
        Encoding.UTF8.GetBytes(text.AsSpan(), span);
        writer.Advance(byteCount);
    }

    private static void WriteEncoded(PipeWriter writer, string text)
        => Write(writer, WebUtility.HtmlEncode(text));
}

/// <summary>A resolved KPI tile with its computed aggregate value and optional sparkline data.</summary>
public sealed class ResolvedTile
{
    public ResolvedTile(DashboardTile tile, object? rawValue, IReadOnlyList<SparklineBar>? sparkline, string displayValue)
    {
        Tile = tile;
        RawValue = rawValue;
        Sparkline = sparkline;
        DisplayValue = displayValue;
    }

    public DashboardTile Tile { get; }
    public object? RawValue { get; }
    public IReadOnlyList<SparklineBar>? Sparkline { get; }
    public string DisplayValue { get; }
}

/// <summary>A single bar in a sparkline chart: label + value.</summary>
public sealed class SparklineBar
{
    public SparklineBar(string label, double value) { Label = label; Value = value; }
    public string Label { get; }
    public double Value { get; }
}
