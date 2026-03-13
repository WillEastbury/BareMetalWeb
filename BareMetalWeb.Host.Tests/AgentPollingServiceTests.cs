using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Agent;
using BareMetalWeb.ControlPlane;
using Xunit;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Unit tests for the bootstrap deployment agent:
///   • AgentPollingService.ComputeDelay  (jitter bounds)
///   • AgentPollingService.VerifySha256  (checksum verification)
///   • AgentConfig.Load                  (state-file + env-var loading)
///   • RuntimeProcessManager             (version parsing from symlink name)
///   • RuntimeResponse model             (field names)
/// </summary>
public class AgentPollingServiceTests : IDisposable
{
    private readonly string _tempDir;

    public AgentPollingServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"bmw_agent_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { /* best-effort */ }
    }

    // ── ComputeDelay ─────────────────────────────────────────────────────────

    [Fact]
    public void ComputeDelay_WithZeroJitter_ReturnsExactBase()
    {
        var delay = AgentPollingService.ComputeDelay(60, 0);
        Assert.Equal(TimeSpan.FromSeconds(60), delay);
    }

    [Theory]
    [InlineData(60, 30)]
    [InlineData(30, 15)]
    [InlineData(10, 10)]
    public void ComputeDelay_IsWithinBounds(int baseSeconds, int maxJitter)
    {
        // Run many iterations to verify the jitter never exceeds the max
        for (int i = 0; i < 200; i++)
        {
            var delay = AgentPollingService.ComputeDelay(baseSeconds, maxJitter);
            Assert.True(delay >= TimeSpan.FromSeconds(baseSeconds),
                $"Delay {delay.TotalSeconds}s was below base {baseSeconds}s");
            Assert.True(delay <= TimeSpan.FromSeconds(baseSeconds + maxJitter),
                $"Delay {delay.TotalSeconds}s exceeded base+jitter {baseSeconds + maxJitter}s");
        }
    }

    [Fact]
    public void ComputeDelay_NeverBelowOneSecond()
    {
        // Even with base=0, jitter=0, minimum is 1 second
        var delay = AgentPollingService.ComputeDelay(0, 0);
        Assert.True(delay >= TimeSpan.FromSeconds(1));
    }

    [Fact]
    public void ComputeDelay_JitterProducesVariance()
    {
        // With a large jitter range, at least two distinct values should appear
        var seen = new System.Collections.Generic.HashSet<double>();
        for (int i = 0; i < 100; i++)
            seen.Add(AgentPollingService.ComputeDelay(60, 30).TotalSeconds);
        Assert.True(seen.Count > 1, "Jitter produced no variance across 100 iterations");
    }

    // ── VerifySha256 ─────────────────────────────────────────────────────────

    [Fact]
    public void VerifySha256_CorrectHash_ReturnsTrue()
    {
        var path = Path.Combine(_tempDir, "testbin");
        var data = System.Text.Encoding.UTF8.GetBytes("hello BMW agent");
        File.WriteAllBytes(path, data);

        var expected = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
        Assert.True(AgentPollingService.VerifySha256(path, expected));
    }

    [Fact]
    public void VerifySha256_UpperCaseHash_ReturnsTrue()
    {
        var path = Path.Combine(_tempDir, "testbin_upper");
        var data = System.Text.Encoding.UTF8.GetBytes("hello BMW agent");
        File.WriteAllBytes(path, data);

        var expected = Convert.ToHexString(SHA256.HashData(data)).ToUpperInvariant();
        Assert.True(AgentPollingService.VerifySha256(path, expected));
    }

    [Fact]
    public void VerifySha256_WrongHash_ReturnsFalse()
    {
        var path = Path.Combine(_tempDir, "testbin_wrong");
        File.WriteAllBytes(path, System.Text.Encoding.UTF8.GetBytes("hello BMW agent"));
        Assert.False(AgentPollingService.VerifySha256(path, "deadbeef"));
    }

    [Fact]
    public void VerifySha256_MissingFile_ReturnsFalse()
    {
        Assert.False(AgentPollingService.VerifySha256(
            Path.Combine(_tempDir, "nonexistent"), "abc123"));
    }

    // ── AgentConfig ──────────────────────────────────────────────────────────

    [Fact]
    public void AgentConfig_LoadFromStateFile_PopulatesNodeIdentity()
    {
        var stateFile = Path.Combine(_tempDir, "node.json");
        File.WriteAllText(stateFile, """
            {
              "nodeId": "node-abc",
              "servicePrincipal": "sp-1",
              "secret": "s3cr3t",
              "clusterEndpoint": "https://cp.example.com",
              "certFingerprint": "AA:BB:CC",
              "ring": "Canary"
            }
            """);

        var cfg = AgentConfig.Load(stateFile);

        Assert.NotNull(cfg.Node);
        Assert.Equal("node-abc",             cfg.Node!.NodeId);
        Assert.Equal("sp-1",                 cfg.Node.ServicePrincipal);
        Assert.Equal("s3cr3t",               cfg.Node.Secret);
        Assert.Equal("https://cp.example.com", cfg.Node.ClusterEndpoint);
        Assert.Equal(DeploymentRing.Canary,  cfg.Node.Ring);
        Assert.True(cfg.IsValid);
    }

    [Fact]
    public void AgentConfig_MissingStateFile_IsNotValid()
    {
        var cfg = AgentConfig.Load(Path.Combine(_tempDir, "missing_node.json"));
        Assert.False(cfg.IsValid);
    }

    [Fact]
    public void AgentConfig_DefaultRuntimeDirAndLink_AreDerived()
    {
        var stateFile = Path.Combine(_tempDir, "node2.json");
        File.WriteAllText(stateFile, """
            {"nodeId":"n1","secret":"s","clusterEndpoint":"https://x","servicePrincipal":"sp","certFingerprint":"fp"}
            """);

        var cfg = AgentConfig.Load(stateFile);

        Assert.False(string.IsNullOrEmpty(cfg.RuntimeDir));
        Assert.False(string.IsNullOrEmpty(cfg.RuntimeLink));
        Assert.StartsWith(cfg.RuntimeDir, cfg.RuntimeLink);
    }

    // ── RuntimeResponse model ────────────────────────────────────────────────

    [Fact]
    public void RuntimeResponse_Fields_AreCorrectlyMapped()
    {
        var r = new RuntimeResponse
        {
            DesiredVersion = "1.6.0",
            Sha256         = "aabbcc",
            DownloadUrl    = "/api/runtime/download/1.6.0",
            PollSeconds    = 120,
        };

        Assert.Equal("1.6.0",                    r.DesiredVersion);
        Assert.Equal("/api/runtime/download/1.6.0", r.DownloadUrl);
        Assert.Equal(120,                        r.PollSeconds);
    }

    // ── RuntimeProcessManager version detection ──────────────────────────────

    [Fact]
    public void RuntimeProcessManager_GetCurrentVersion_ParsesVersionFromSymlinkTarget()
    {
        // Create a real symlink in the temp dir so we can exercise the path parsing
        if (OperatingSystem.IsWindows()) return; // symlinks need admin rights on Windows CI

        var runtimeDir  = Path.Combine(_tempDir, "opt_bmw");
        Directory.CreateDirectory(runtimeDir);

        var binary  = Path.Combine(runtimeDir, "BareMetalWeb.Host-2.1.0");
        File.WriteAllBytes(binary, []);

        var link = Path.Combine(runtimeDir, "bmw");
        File.CreateSymbolicLink(link, binary);

        var stateFile = Path.Combine(_tempDir, "node3.json");
        File.WriteAllText(stateFile, """
            {"nodeId":"n","secret":"s","clusterEndpoint":"https://x","servicePrincipal":"sp","certFingerprint":"fp"}
            """);

        var cfg = AgentConfig.Load(stateFile);
        cfg.RuntimeDir  = runtimeDir;
        cfg.RuntimeLink = link;
        cfg.RuntimeExeName = "BareMetalWeb.Host";

        using var pm = new RuntimeProcessManager(cfg);
        var version = pm.GetCurrentVersion();

        Assert.Equal("2.1.0", version);
    }

    [Fact]
    public void RuntimeProcessManager_GetCurrentVersion_ReturnsNullWhenLinkMissing()
    {
        var stateFile = Path.Combine(_tempDir, "node4.json");
        File.WriteAllText(stateFile, """
            {"nodeId":"n","secret":"s","clusterEndpoint":"https://x","servicePrincipal":"sp","certFingerprint":"fp"}
            """);

        var cfg = AgentConfig.Load(stateFile);
        cfg.RuntimeDir  = _tempDir;
        cfg.RuntimeLink = Path.Combine(_tempDir, "no_link_here");

        using var pm = new RuntimeProcessManager(cfg);
        Assert.Null(pm.GetCurrentVersion());
    }

    [Fact]
    public void RuntimeProcessManager_VersionedBinaryPath_ContainsVersion()
    {
        var stateFile = Path.Combine(_tempDir, "node5.json");
        File.WriteAllText(stateFile, """
            {"nodeId":"n","secret":"s","clusterEndpoint":"https://x","servicePrincipal":"sp","certFingerprint":"fp"}
            """);

        var cfg = AgentConfig.Load(stateFile);
        cfg.RuntimeDir     = _tempDir;
        cfg.RuntimeExeName = "BareMetalWeb.Host";

        using var pm = new RuntimeProcessManager(cfg);
        var path = pm.VersionedBinaryPath("3.0.1");

        Assert.Contains("3.0.1", path);
        Assert.StartsWith(_tempDir, path);
    }
}
