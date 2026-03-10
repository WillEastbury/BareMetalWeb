using BareMetalWeb.Core;
using BareMetalWeb.Data;

namespace BareMetalWeb.Host;

/// <summary>
/// Resolves dashboard KPI tiles by querying entity aggregates and sparkline data.
/// </summary>
public static class DashboardHtmlRenderer
{
    private static readonly string[] AllowedAggFunctions = ["count", "sum", "avg", "min", "max"];

    // ── Public API ────────────────────────────────────────────────────────────
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
        foreach (var kvp in groups)
        {
            double value = fn == "sum" ? kvp.Value.Sum
                : fn == "avg" ? (kvp.Value.Count > 0 ? kvp.Value.Sum / kvp.Value.Count : 0)
                : kvp.Value.Count;
            bars.Add(new SparklineBar(kvp.Key, value));
        }
        bars.Sort((a, b) => string.Compare(a.Label, b.Label, StringComparison.Ordinal));
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
}

/// <summary>Resolved KPI tile with computed display value and optional sparkline.</summary>
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
