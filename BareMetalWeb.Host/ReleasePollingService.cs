using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Runtime;

namespace BareMetalWeb.Host;

/// <summary>
/// Background service that polls Azure Container Registry (ACR) for new image tags.
/// When a new tag is detected, auto-promotes canary-ring deployment targets by setting
/// DesiredImageTag and Status=Upgrading. Subsequent ring promotion is handled by the
/// monitoring window configured on the deployment ring metadata.
///
/// Configuration (Metal.config / env):
///   ReleasePolling.Enabled          — master switch (default: false)
///   ReleasePolling.AcrLoginServer   — ACR hostname (e.g. metalclusterregistry.azurecr.io)
///   ReleasePolling.Repository       — image repository name (default: baremetalweb)
///   ReleasePolling.TagSuffix        — tag suffix filter (default: -linux-arm64)
///   ReleasePolling.PollSeconds      — poll interval (default: 300)
///   ReleasePolling.AcrUsername       — ACR username (for basic auth, or use managed identity)
///   ReleasePolling.AcrPassword       — ACR password
/// </summary>
public sealed class ReleasePollingService
{
    private readonly IBufferedLogger _logger;
    private readonly BmwConfig _config;
    private string? _lastKnownTag;

    private static readonly HttpClient Http = new(new SocketsHttpHandler
    {
        MaxConnectionsPerServer = 2,
        PooledConnectionLifetime = TimeSpan.FromMinutes(10),
        ConnectTimeout = TimeSpan.FromSeconds(10),
    })
    {
        Timeout = TimeSpan.FromSeconds(30),
    };

    public ReleasePollingService(IBufferedLogger logger, BmwConfig config)
    {
        _logger = logger;
        _config = config;
    }

    public async Task RunAsync(CancellationToken token)
    {
        var config = _config;
        if (!config.GetValue("ReleasePolling.Enabled", false))
        {
            _logger.LogInfo("ReleasePollingService disabled (ReleasePolling.Enabled=false).");
            return;
        }

        var acrServer = config.GetValue("ReleasePolling.AcrLoginServer", "metalclusterregistry.azurecr.io");
        var repository = config.GetValue("ReleasePolling.Repository", "baremetalweb");
        var tagSuffix = config.GetValue("ReleasePolling.TagSuffix", "-linux-arm64");
        var pollSeconds = config.GetValue("ReleasePolling.PollSeconds", 300);
        var acrUser = config.GetValue("ReleasePolling.AcrUsername", "");
        var acrPass = config.GetValue("ReleasePolling.AcrPassword", "");

        _logger.LogInfo($"ReleasePollingService starting — polling {acrServer}/{repository} every {pollSeconds}s.");

        // Seed last known tag from current canary targets
        _lastKnownTag = GetCurrentCanaryTag();

        while (!token.IsCancellationRequested)
        {
            try
            {
                var latestTag = await PollAcrForLatestTagAsync(acrServer, repository, tagSuffix, acrUser, acrPass, token);

                if (!string.IsNullOrEmpty(latestTag) && latestTag != _lastKnownTag)
                {
                    _logger.LogInfo($"ReleasePollingService: New tag detected: {latestTag} (was: {_lastKnownTag})");
                    int promoted = PromoteCanaryTargets(latestTag);
                    if (promoted > 0)
                    {
                        _logger.LogInfo($"ReleasePollingService: Promoted {promoted} canary target(s) to {latestTag}.");
                        _lastKnownTag = latestTag;
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("ReleasePollingService poll error.", ex);
            }

            try { await Task.Delay(TimeSpan.FromSeconds(pollSeconds), token); }
            catch (OperationCanceledException) { break; }
        }

        _logger.LogInfo("ReleasePollingService stopped.");
    }

    /// <summary>
    /// Queries ACR v2 API for the latest tag matching the suffix filter.
    /// Tags are sorted by version convention: {MAJOR}.{YYYYMMDD}.{BUILD}-suffix
    /// </summary>
    private static async Task<string?> PollAcrForLatestTagAsync(
        string acrServer, string repository, string tagSuffix,
        string acrUser, string acrPass, CancellationToken ct)
    {
        // ACR Docker Registry HTTP API v2: GET /v2/{repo}/tags/list
        var url = $"https://{acrServer}/v2/{repository}/tags/list";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        // Basic auth if credentials provided
        if (!string.IsNullOrEmpty(acrUser) && !string.IsNullOrEmpty(acrPass))
        {
            var creds = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{acrUser}:{acrPass}"));
            request.Headers.TryAddWithoutValidation("Authorization", $"Basic {creds}");
        }

        using var response = await Http.SendAsync(request, HttpCompletionOption.ResponseContentRead, ct);
        if (!response.IsSuccessStatusCode)
            return null;

        using var doc = await JsonDocument.ParseAsync(
            await response.Content.ReadAsStreamAsync(ct), cancellationToken: ct);

        if (!doc.RootElement.TryGetProperty("tags", out var tagsEl) || tagsEl.ValueKind != JsonValueKind.Array)
            return null;

        // Filter to matching suffix and find the latest by version sort
        string? latest = null;
        long latestScore = 0;

        foreach (var tagEl in tagsEl.EnumerateArray())
        {
            var tag = tagEl.GetString();
            if (tag == null || !tag.EndsWith(tagSuffix, StringComparison.Ordinal))
                continue;

            // Parse version: {MAJOR}.{YYYYMMDD}.{BUILD}-suffix → score = YYYYMMDD * 100000 + BUILD
            var versionPart = tag[..^tagSuffix.Length]; // strip suffix
            var parts = versionPart.Split('.');
            if (parts.Length != 3) continue;
            if (!long.TryParse(parts[1], out var datePart)) continue;
            if (!long.TryParse(parts[2], out var buildPart)) continue;

            var score = datePart * 100_000 + buildPart;
            if (score > latestScore)
            {
                latestScore = score;
                latest = tag;
            }
        }

        return latest;
    }

    /// <summary>
    /// Reads current ImageTag from canary-ring deployment targets to seed the baseline.
    /// </summary>
    private static string? GetCurrentCanaryTag()
    {
        var walProvider = DataStoreProvider.PrimaryProvider as WalDataProvider;
        if (walProvider == null) return null;

        var registry = RuntimeEntityRegistry.Current;
        if (!registry.TryGet("deployment-targets", out var targetModel)) return null;
        if (!registry.TryGet("deployment-rings", out var ringModel)) return null;

        var (statusOrd, imageTagOrd, ringIdOrd, _, _, _, _, _, _, _, _) = ResolveTargetOrdinals(targetModel);
        if (statusOrd < 0) return null;

        var targetSchema = EntitySchemaFactory.FromModel(targetModel);
        var records = walProvider.QueryRecords(targetSchema);

        foreach (var record in records)
        {
            var status = statusOrd >= 0 ? record.GetValue(statusOrd)?.ToString() : null;
            if (status != "Active") continue;

            var tag = imageTagOrd >= 0 ? record.GetValue(imageTagOrd)?.ToString() : null;
            if (!string.IsNullOrEmpty(tag)) return tag;
        }

        return null;
    }

    /// <summary>
    /// Sets DesiredImageTag and Status=Upgrading on all canary-ring targets.
    /// Returns the number of targets promoted.
    /// </summary>
    private int PromoteCanaryTargets(string newTag)
    {
        var walProvider = DataStoreProvider.PrimaryProvider as WalDataProvider;
        if (walProvider == null) return 0;

        var registry = RuntimeEntityRegistry.Current;
        if (!registry.TryGet("deployment-targets", out var targetModel)) return 0;
        if (!registry.TryGet("deployment-rings", out var ringModel)) return 0;

        var (statusOrd, _, ringIdOrd, desiredTagOrd, _, _, _, _, _, _, _) = ResolveTargetOrdinals(targetModel);
        if (statusOrd < 0 || desiredTagOrd < 0) return 0;

        // Find canary ring ID
        var canaryRingId = FindRingIdBySlug(walProvider, ringModel, "canary");

        var targetSchema = EntitySchemaFactory.FromModel(targetModel);
        var records = walProvider.QueryRecords(targetSchema);
        int promoted = 0;

        foreach (var record in records)
        {
            var status = record.GetValue(statusOrd)?.ToString();
            if (status != "Active") continue;

            // Match canary ring — if ringId matches canary, or if no rings are deployed yet, promote all
            if (canaryRingId != null && ringIdOrd >= 0)
            {
                var targetRingId = record.GetValue(ringIdOrd)?.ToString();
                if (targetRingId != canaryRingId) continue;
            }

            record.SetValue(desiredTagOrd, newTag);
            record.SetValue(statusOrd, "Upgrading");
            walProvider.SaveRecord(record, targetSchema);
            promoted++;

            _logger.LogInfo($"ReleasePollingService: Target promoted to Upgrading with tag {newTag}.");
        }

        return promoted;
    }

    /// <summary>
    /// Looks up a deployment ring record by slug and returns its Key as a string.
    /// </summary>
    private static string? FindRingIdBySlug(WalDataProvider walProvider, RuntimeEntityModel ringModel, string slug)
    {
        int slugOrd = -1;
        foreach (var f in ringModel.Fields)
        {
            if (f.Name == "Slug") { slugOrd = f.Ordinal; break; }
        }
        if (slugOrd < 0) return null;

        var ringSchema = EntitySchemaFactory.FromModel(ringModel);
        foreach (var record in walProvider.QueryRecords(ringSchema))
        {
            if (string.Equals(record.GetValue(slugOrd)?.ToString(), slug, StringComparison.OrdinalIgnoreCase))
                return record.Key.ToString();
        }

        return null;
    }

    private static (int statusOrd, int imageTagOrd, int ringIdOrd, int desiredTagOrd,
        int namespaceOrd, int clusterOrd, int deployTypeOrd, int statefulSetOrd,
        int nameOrd, int healthOrd, int currentVersionOrd)
        ResolveTargetOrdinals(RuntimeEntityModel model)
    {
        int statusOrd = -1, imageTagOrd = -1, ringIdOrd = -1, desiredTagOrd = -1;
        int namespaceOrd = -1, clusterOrd = -1, deployTypeOrd = -1, statefulSetOrd = -1;
        int nameOrd = -1, healthOrd = -1, currentVersionOrd = -1;

        foreach (var f in model.Fields)
        {
            switch (f.Name)
            {
                case "Status": statusOrd = f.Ordinal; break;
                case "ImageTag": imageTagOrd = f.Ordinal; break;
                case "RingId": ringIdOrd = f.Ordinal; break;
                case "DesiredImageTag": desiredTagOrd = f.Ordinal; break;
                case "Namespace": namespaceOrd = f.Ordinal; break;
                case "ClusterName": clusterOrd = f.Ordinal; break;
                case "DeploymentType": deployTypeOrd = f.Ordinal; break;
                case "StatefulSetName": statefulSetOrd = f.Ordinal; break;
                case "Name": nameOrd = f.Ordinal; break;
                case "HealthStatus": healthOrd = f.Ordinal; break;
                case "CurrentVersion": currentVersionOrd = f.Ordinal; break;
            }
        }

        return (statusOrd, imageTagOrd, ringIdOrd, desiredTagOrd,
                namespaceOrd, clusterOrd, deployTypeOrd, statefulSetOrd,
                nameOrd, healthOrd, currentVersionOrd);
    }
}
