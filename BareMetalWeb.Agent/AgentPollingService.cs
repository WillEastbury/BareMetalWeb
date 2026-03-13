using System.Security.Cryptography;
using BareMetalWeb.ControlPlane;

namespace BareMetalWeb.Agent;

/// <summary>
/// Core bootstrap-agent polling loop.
///
/// Flow on each iteration (mirrors the reference design):
///   1. Poll <c>GET /api/runtime/desired/{nodeId}</c> with Bearer auth.
///   2. Compare the desired version with the symlink-detected current version.
///   3. If they differ, download the new binary (if not already cached), verify
///      the SHA-256 checksum, install it (symlink swap), then restart BMW.
///   4. If BMW is not running for any reason, start it.
///   5. Sleep for <c>PollSeconds + random jitter</c> before the next iteration.
///
/// An initial random delay (0 – <see cref="AgentConfig.MaxJitterSeconds"/> seconds)
/// is inserted before the very first poll to spread container/host reboots across
/// time and avoid a thundering-herd effect on the control plane.
/// </summary>
internal sealed class AgentPollingService
{
    private readonly AgentConfig _config;
    private readonly RuntimeProcessManager _pm;

    public AgentPollingService(AgentConfig config, RuntimeProcessManager pm)
    {
        _config = config;
        _pm     = pm;
    }

    /// <summary>Run the polling loop until <paramref name="ct"/> is cancelled.</summary>
    public async Task RunAsync(CancellationToken ct)
    {
        var node = _config.Node!;
        Log($"Agent started — nodeId={node.NodeId} ring={node.Ring} arch={_config.Architecture}");

        Directory.CreateDirectory(_config.RuntimeDir);

        // ── Startup jitter: spread container reboots over time ───────────────
        var startupJitter = Random.Shared.Next(0, _config.MaxJitterSeconds * 1_000 + 1);
        Log($"Startup jitter: {startupJitter / 1000.0:F1} s");
        try { await Task.Delay(startupJitter, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) { return; }

        // ── Main loop ────────────────────────────────────────────────────────
        int pollSeconds = _config.FallbackPollSeconds;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var runtime = await ControlPlaneClient.GetDesiredVersionAsync(
                    node.ClusterEndpoint, node.NodeId, node.Secret, _config.Architecture)
                    .ConfigureAwait(false);

                if (runtime != null)
                {
                    pollSeconds = runtime.PollSeconds > 0
                        ? runtime.PollSeconds
                        : _config.FallbackPollSeconds;

                    var current = _pm.GetCurrentVersion();

                    if (runtime.DesiredVersion != current)
                    {
                        Log($"Upgrade required → {runtime.DesiredVersion}");
                        await DownloadRuntimeAsync(runtime, ct).ConfigureAwait(false);
                        InstallRuntime(runtime);
                        _pm.Restart();
                    }
                }
                else
                {
                    Log("Control plane unreachable — keeping current runtime.");
                }

                // Ensure BMW is running (handles first start + unexpected exits)
                if (!_pm.IsRunning)
                {
                    Log("BMW not running → launching");
                    _pm.Start();
                }
            }
            catch (Exception ex)
            {
                Log($"ERROR: {ex.Message}");
                try { await Task.Delay(5_000, ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
                continue;
            }

            // Sleep until next poll (base interval + random jitter)
            var delay = ComputeDelay(pollSeconds, _config.MaxJitterSeconds);
            Log($"Next poll in {delay.TotalSeconds:F1} s.");
            try { await Task.Delay(delay, ct).ConfigureAwait(false); }
            catch (OperationCanceledException) { break; }
        }

        _pm.StopCurrent();
        Log("Shutdown complete.");
    }

    // ── Download ──────────────────────────────────────────────────────────────

    private async Task DownloadRuntimeAsync(RuntimeResponse runtime, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(runtime.DesiredVersion) ||
            string.IsNullOrEmpty(runtime.DownloadUrl))
        {
            Log("ERROR: DesiredVersion or DownloadUrl missing in poll response.");
            return;
        }

        var destPath = _pm.VersionedBinaryPath(runtime.DesiredVersion);

        if (File.Exists(destPath))
        {
            Log($"Runtime {runtime.DesiredVersion} already cached.");
            return;
        }

        Log($"Downloading runtime {runtime.DesiredVersion}...");

        var node = _config.Node!;
        var downloadUrl = runtime.DownloadUrl.StartsWith("http", StringComparison.OrdinalIgnoreCase)
            ? runtime.DownloadUrl
            : node.ClusterEndpoint.TrimEnd('/') + runtime.DownloadUrl;

        var tmpPath = destPath + ".tmp";
        bool ok = await ControlPlaneClient.DownloadRuntimeAsync(
                downloadUrl, node.Secret, tmpPath, ct)
            .ConfigureAwait(false);

        if (!ok)
        {
            Log("ERROR: Download failed.");
            TryDelete(tmpPath);
            return;
        }

        if (!string.IsNullOrEmpty(runtime.Sha256))
        {
            if (!VerifySha256(tmpPath, runtime.Sha256))
            {
                Log($"ERROR: SHA256 mismatch for {runtime.DesiredVersion} — discarding.");
                TryDelete(tmpPath);
                throw new InvalidDataException(
                    $"SHA256 mismatch for {runtime.DesiredVersion}: expected {runtime.Sha256}");
            }
        }

        File.Move(tmpPath, destPath, overwrite: true);
        Log($"Runtime {runtime.DesiredVersion} downloaded.");
    }

    // ── Install ───────────────────────────────────────────────────────────────

    private void InstallRuntime(RuntimeResponse runtime)
    {
        if (string.IsNullOrEmpty(runtime.DesiredVersion)) return;
        _pm.Install(runtime.DesiredVersion);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Compute the next poll delay: <paramref name="baseSeconds"/> plus a uniform
    /// random jitter in [0, <paramref name="maxJitterSeconds"/>].
    /// Minimum returned value is 1 second.
    /// </summary>
    internal static TimeSpan ComputeDelay(int baseSeconds, int maxJitterSeconds)
    {
        var jitter = maxJitterSeconds > 0 ? Random.Shared.Next(0, maxJitterSeconds + 1) : 0;
        return TimeSpan.FromSeconds(Math.Max(1, baseSeconds + jitter));
    }

    /// <summary>Verify the SHA-256 of a file against a hex string (case-insensitive).</summary>
    internal static bool VerifySha256(string filePath, string expectedHex)
    {
        try
        {
            using var fs = File.OpenRead(filePath);
            var hash     = SHA256.HashData(fs);
            var actual   = Convert.ToHexString(hash).ToLowerInvariant();
            return actual == expectedHex.Replace("-", "").ToLowerInvariant();
        }
        catch { return false; }
    }

    private static void TryDelete(string path)
    { try { File.Delete(path); } catch { /* best-effort */ } }

    private static void Log(string msg) =>
        Console.WriteLine($"{DateTime.UtcNow:O} | {msg}");
}
