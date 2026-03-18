using System;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Runtime;

namespace BareMetalWeb.Host;

/// <summary>
/// Background service that handles automatic ring promotion.
/// After a deployment target has been Active with its current ImageTag for longer
/// than the ring's MonitoringWindowMinutes, and the ring has AutoPromote=true,
/// this service promotes targets in the next ring to the same tag.
///
/// Ring chain: canary → early-access → production (via PredecessorRingSlug).
/// </summary>
public sealed class RingPromotionService
{
    private static readonly TimeSpan CheckInterval = TimeSpan.FromMinutes(5);
    private readonly IBufferedLogger _logger;

    public RingPromotionService(IBufferedLogger logger)
    {
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken token)
    {
        _logger.LogInfo("RingPromotionService starting.");

        while (!token.IsCancellationRequested)
        {
            try
            {
                int promoted = ProcessPromotions();
                if (promoted > 0)
                    _logger.LogInfo($"RingPromotionService: Promoted {promoted} target(s) to next ring.");
            }
            catch (Exception ex)
            {
                _logger.LogError("RingPromotionService error.", ex);
            }

            try { await Task.Delay(CheckInterval, token); }
            catch (OperationCanceledException) { break; }
        }

        _logger.LogInfo("RingPromotionService stopped.");
    }

    public int ProcessPromotions()
    {
        var walProvider = DataStoreProvider.PrimaryProvider as WalDataProvider;
        if (walProvider == null) return 0;

        var registry = RuntimeEntityRegistry.Current;
        if (!registry.TryGet("deployment-rings", out var ringModel)) return 0;
        if (!registry.TryGet("deployment-targets", out var targetModel)) return 0;

        // Resolve ring fields
        int ringSlugOrd = -1, ringAutoPromoteOrd = -1, ringWindowOrd = -1, ringPredecessorOrd = -1;
        foreach (var f in ringModel.Fields)
        {
            switch (f.Name)
            {
                case "Slug": ringSlugOrd = f.Ordinal; break;
                case "AutoPromote": ringAutoPromoteOrd = f.Ordinal; break;
                case "MonitoringWindowMinutes": ringWindowOrd = f.Ordinal; break;
                case "PredecessorRingSlug": ringPredecessorOrd = f.Ordinal; break;
            }
        }
        if (ringSlugOrd < 0) return 0;

        // Load all rings into a dictionary keyed by record Key (string)
        var ringSchema = EntitySchemaFactory.FromModel(ringModel);
        var rings = new System.Collections.Generic.Dictionary<string, RingInfo>();
        foreach (var r in walProvider.QueryRecords(ringSchema))
        {
            var slug = r.GetValue(ringSlugOrd)?.ToString() ?? "";
            var autoPromote = ringAutoPromoteOrd >= 0 && r.GetValue(ringAutoPromoteOrd) is true;
            var windowMinutes = ringWindowOrd >= 0 && r.GetValue(ringWindowOrd) is int wm ? wm : 30;
            var predecessor = ringPredecessorOrd >= 0 ? r.GetValue(ringPredecessorOrd)?.ToString() : null;
            rings[r.Key.ToString()] = new RingInfo(slug, autoPromote, windowMinutes, predecessor, r.Key.ToString());
        }

        // Resolve target fields
        int statusOrd = -1, imageTagOrd = -1, ringIdOrd = -1, desiredTagOrd = -1;
        int lastDeployedOrd = -1, healthOrd = -1, nameOrd = -1;
        foreach (var f in targetModel.Fields)
        {
            switch (f.Name)
            {
                case "Status": statusOrd = f.Ordinal; break;
                case "ImageTag": imageTagOrd = f.Ordinal; break;
                case "RingId": ringIdOrd = f.Ordinal; break;
                case "DesiredImageTag": desiredTagOrd = f.Ordinal; break;
                case "LastDeployedAt": lastDeployedOrd = f.Ordinal; break;
                case "HealthStatus": healthOrd = f.Ordinal; break;
                case "Name": nameOrd = f.Ordinal; break;
            }
        }
        if (statusOrd < 0 || imageTagOrd < 0 || ringIdOrd < 0 || desiredTagOrd < 0) return 0;

        var targetSchema = EntitySchemaFactory.FromModel(targetModel);
        var allTargets = walProvider.QueryRecords(targetSchema);

        // For each ring that has AutoPromote and a predecessor:
        // Check if ALL predecessor-ring targets are Active + Healthy + deployed with the same tag
        // for longer than the monitoring window, then promote this ring's targets.
        int totalPromoted = 0;

        foreach (var (ringKey, ring) in rings)
        {
            if (!ring.AutoPromote || string.IsNullOrEmpty(ring.PredecessorSlug)) continue;

            // Find predecessor ring key
            string? predRingKey = null;
            foreach (var (rk, ri) in rings)
            {
                if (ri.Slug == ring.PredecessorSlug) { predRingKey = rk; break; }
            }
            if (predRingKey == null) continue;

            // Check all predecessor targets are stable
            string? promotionTag = null;
            bool allStable = true;
            var now = DateTime.UtcNow;

            foreach (var target in allTargets)
            {
                var targetRingId = target.GetValue(ringIdOrd)?.ToString();
                if (targetRingId != predRingKey) continue;

                var status = target.GetValue(statusOrd)?.ToString();
                var health = healthOrd >= 0 ? target.GetValue(healthOrd)?.ToString() : "Unknown";
                var tag = target.GetValue(imageTagOrd)?.ToString();
                var deployedAt = lastDeployedOrd >= 0 ? target.GetValue(lastDeployedOrd) as DateTime? : null;

                if (status != "Active" || string.IsNullOrEmpty(tag))
                {
                    allStable = false;
                    break;
                }

                if (health == "Degraded" || health == "Unhealthy" || health == "Unreachable")
                {
                    allStable = false;
                    break;
                }

                // Check monitoring window
                if (deployedAt.HasValue && (now - deployedAt.Value).TotalMinutes < ring.WindowMinutes)
                {
                    allStable = false;
                    break;
                }

                if (promotionTag == null)
                    promotionTag = tag;
                else if (promotionTag != tag)
                {
                    allStable = false; // Mixed versions in predecessor ring
                    break;
                }
            }

            if (!allStable || promotionTag == null) continue;

            // Promote all targets in this ring that don't already have the tag
            foreach (var target in allTargets)
            {
                var targetRingId = target.GetValue(ringIdOrd)?.ToString();
                if (targetRingId != ringKey) continue;

                var currentTag = target.GetValue(imageTagOrd)?.ToString();
                var status = target.GetValue(statusOrd)?.ToString();

                if (status != "Active" || currentTag == promotionTag) continue;

                var targetName = nameOrd >= 0 ? target.GetValue(nameOrd)?.ToString() ?? "?" : "?";
                _logger.LogInfo($"RingPromotionService: Auto-promoting {targetName} (ring: {ring.Slug}) to {promotionTag}.");

                target.SetValue(desiredTagOrd, promotionTag);
                target.SetValue(statusOrd, "Upgrading");
                walProvider.SaveRecord(target, targetSchema);
                totalPromoted++;
            }
        }

        return totalPromoted;
    }

    private sealed record RingInfo(string Slug, bool AutoPromote, int WindowMinutes, string? PredecessorSlug, string Key);
}
