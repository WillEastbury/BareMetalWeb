using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Runtime;

namespace BareMetalWeb.Host;

/// <summary>
/// Background service that polls for Deployment Target records with Status=Upgrading
/// and triggers kubectl rollouts via deploy-tenant.sh. After a successful deployment
/// the record is updated: Status → Active, ImageTag → DesiredImageTag, LastDeployedAt → now.
/// On failure: Status → Active (rollback), and the error is logged.
/// </summary>
public sealed class DeploymentWatcherService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(30);
    private readonly IBufferedLogger _logger;

    public DeploymentWatcherService(IBufferedLogger logger)
    {
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken token)
    {
        _logger.LogInfo("DeploymentWatcherService starting.");

        while (!token.IsCancellationRequested)
        {
            try
            {
                int count = ProcessUpgradingTargets();
                if (count > 0)
                    _logger.LogInfo($"DeploymentWatcherService processed {count} upgrade(s).");
            }
            catch (Exception ex)
            {
                _logger.LogError("DeploymentWatcherService processing error.", ex);
            }

            try
            {
                await Task.Delay(PollInterval, token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }

        _logger.LogInfo("DeploymentWatcherService stopped.");
    }

    /// <summary>
    /// Finds all deployment-targets with Status=Upgrading and deploys them.
    /// Returns the number of targets processed.
    /// </summary>
    public int ProcessUpgradingTargets()
    {
        var walProvider = DataStoreProvider.PrimaryProvider as WalDataProvider;
        if (walProvider == null) return 0;

        var registry = RuntimeEntityRegistry.Current;
        if (!registry.TryGet("deployment-targets", out var model))
            return 0;

        // Resolve field ordinals
        int statusOrd = -1, imageTagOrd = -1, desiredTagOrd = -1;
        int lastDeployedOrd = -1, namespaceOrd = -1, clusterOrd = -1;
        int deployTypeOrd = -1, statefulSetOrd = -1, nameOrd = -1;
        int healthOrd = -1, currentVersionOrd = -1;

        foreach (var f in model.Fields)
        {
            switch (f.Name)
            {
                case "Status":           statusOrd = f.Ordinal; break;
                case "ImageTag":         imageTagOrd = f.Ordinal; break;
                case "DesiredImageTag":  desiredTagOrd = f.Ordinal; break;
                case "LastDeployedAt":   lastDeployedOrd = f.Ordinal; break;
                case "Namespace":        namespaceOrd = f.Ordinal; break;
                case "ClusterName":      clusterOrd = f.Ordinal; break;
                case "DeploymentType":   deployTypeOrd = f.Ordinal; break;
                case "StatefulSetName":  statefulSetOrd = f.Ordinal; break;
                case "Name":            nameOrd = f.Ordinal; break;
                case "HealthStatus":     healthOrd = f.Ordinal; break;
                case "CurrentVersion":   currentVersionOrd = f.Ordinal; break;
            }
        }

        if (statusOrd < 0 || desiredTagOrd < 0)
            return 0;

        var schema = EntitySchemaFactory.FromModel(model);

        // Query for Status == Upgrading
        var query = new QueryDefinition
        {
            Clauses = { new QueryClause { Field = "Status", Operator = QueryOperator.Equals, Value = "Upgrading" } }
        };

        var records = walProvider.QueryRecords(schema, query);
        int processed = 0;

        foreach (var record in records)
        {
            var targetName = nameOrd >= 0 ? record.GetValue(nameOrd)?.ToString() ?? "unknown" : "unknown";
            var desiredTag = desiredTagOrd >= 0 ? record.GetValue(desiredTagOrd)?.ToString() : null;
            var deployType = deployTypeOrd >= 0 ? record.GetValue(deployTypeOrd)?.ToString() : "AKS";

            if (string.IsNullOrEmpty(desiredTag))
            {
                _logger.LogInfo($"DeploymentWatcher: {targetName} has Status=Upgrading but no DesiredImageTag — resetting to Active.");
                record.SetValue(statusOrd, "Active");
                walProvider.SaveRecord(record, schema);
                processed++;
                continue;
            }

            _logger.LogInfo($"DeploymentWatcher: Upgrading {targetName} to {desiredTag} (type={deployType}).");

            bool success;
            string output;

            if (string.Equals(deployType, "AKS", StringComparison.OrdinalIgnoreCase))
            {
                var ns = namespaceOrd >= 0 ? record.GetValue(namespaceOrd)?.ToString() : null;
                var ssName = statefulSetOrd >= 0 ? record.GetValue(statefulSetOrd)?.ToString() : null;

                // Fall back to target name for namespace/statefulset if not explicitly set
                ns = string.IsNullOrEmpty(ns) ? targetName : ns;
                ssName = string.IsNullOrEmpty(ssName) ? targetName : ssName;

                (success, output) = RunKubectlUpgrade(ns, ssName, desiredTag);
            }
            else
            {
                _logger.LogInfo($"DeploymentWatcher: Unsupported deployment type '{deployType}' for {targetName} — skipping.");
                continue;
            }

            if (success)
            {
                _logger.LogInfo($"DeploymentWatcher: {targetName} upgraded to {desiredTag} successfully.");
                record.SetValue(statusOrd, "Active");
                if (imageTagOrd >= 0) record.SetValue(imageTagOrd, desiredTag);
                if (lastDeployedOrd >= 0) record.SetValue(lastDeployedOrd, DateTime.UtcNow);
                if (healthOrd >= 0) record.SetValue(healthOrd, "Unknown");
                if (currentVersionOrd >= 0) record.SetValue(currentVersionOrd, desiredTag);
            }
            else
            {
                _logger.LogError($"DeploymentWatcher: {targetName} upgrade to {desiredTag} FAILED. Output: {output}", new InvalidOperationException("Deployment failed"));
                record.SetValue(statusOrd, "Active");
                if (healthOrd >= 0) record.SetValue(healthOrd, "Degraded");
            }

            walProvider.SaveRecord(record, schema);
            processed++;
        }

        return processed;
    }

    /// <summary>
    /// Runs kubectl set image + rollout status for an AKS StatefulSet upgrade.
    /// </summary>
    private (bool Success, string Output) RunKubectlUpgrade(string ns, string statefulSetName, string imageTag)
    {
        var image = $"metalclusterregistry.azurecr.io/baremetalweb:{imageTag}";

        // kubectl set image statefulset/{name} {name}={image} --namespace {ns}
        var (setOk, setOut) = RunProcess("kubectl",
            $"set image statefulset/{statefulSetName} {statefulSetName}={image} --namespace {ns}");

        if (!setOk)
            return (false, $"kubectl set image failed: {setOut}");

        // kubectl rollout status statefulset/{name} --namespace {ns} --timeout=300s
        var (rolloutOk, rolloutOut) = RunProcess("kubectl",
            $"rollout status statefulset/{statefulSetName} --namespace {ns} --timeout=300s");

        if (!rolloutOk)
            return (false, $"kubectl rollout status failed: {rolloutOut}");

        return (true, rolloutOut);
    }

    private static (bool Success, string Output) RunProcess(string fileName, string arguments)
    {
        try
        {
            var psi = new ProcessStartInfo(fileName, arguments)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using var proc = Process.Start(psi);
            if (proc == null)
                return (false, "Failed to start process");

            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(TimeSpan.FromMinutes(6));

            var output = string.IsNullOrEmpty(stderr) ? stdout : $"{stdout}\nSTDERR: {stderr}";
            return (proc.ExitCode == 0, output.Trim());
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }
}
