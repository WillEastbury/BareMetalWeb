using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using BareMetalWeb.ControlPlane;

namespace BareMetalWeb.Agent;

/// <summary>
/// Configuration for the bootstrap deployment agent.
///
/// The agent's identity is stored in a JSON file (default: /var/lib/bmw/node.json on Linux,
/// %PROGRAMDATA%\bmw\node.json on Windows).  This file is provisioned once by the control
/// plane at enrolment time and must not be checked into source control.
///
/// Override the file path with the BMW_STATE_FILE environment variable.
///
/// Additional tunables (environment variables):
///   BMW_RUNTIME_DIR          — directory where versioned runtime binaries are stored
///                              (default: /opt/bmw on Linux, %PROGRAMDATA%\bmw\runtime on Windows)
///   BMW_RUNTIME_LINK         — path of the symlink / shim pointing at the active binary
///                              (default: {RuntimeDir}/bmw on Linux, {RuntimeDir}\bmw.exe on Windows)
///   BMW_RUNTIME_EXE_NAME     — base name of the runtime executable inside RuntimeDir
///                              (default: BareMetalWeb.Host)
///   BMW_POLL_INTERVAL_SECONDS — fallback base poll interval when the control plane does not
///                              return a PollSeconds value (default: 60)
///   BMW_MAX_JITTER_SECONDS   — maximum random jitter added to each poll interval (default: 30)
/// </summary>
internal sealed class AgentConfig
{
    // ── Paths ────────────────────────────────────────────────────────────────
    public string StateFile      { get; set; } = DefaultStateFile();
    public string RuntimeDir     { get; set; } = DefaultRuntimeDir();
    public string RuntimeLink    { get; set; } = "";        // resolved after RuntimeDir is known
    public string RuntimeExeName { get; set; } = "BareMetalWeb.Host";

    // ── Polling ──────────────────────────────────────────────────────────────
    public int FallbackPollSeconds { get; set; } = 60;
    public int MaxJitterSeconds    { get; set; } = 30;

    // ── Identity (loaded from StateFile) ─────────────────────────────────────
    public NodeIdentity? Node { get; set; }

    /// <summary>True when the node identity has been loaded successfully.</summary>
    public bool IsValid => Node is { NodeId: { Length: > 0 }, Secret: { Length: > 0 } };

    // ── Architecture (auto-detected) ─────────────────────────────────────────
    public string Architecture { get; } = RuntimeInformation.ProcessArchitecture.ToString();

    // ── Factory ──────────────────────────────────────────────────────────────

    /// <summary>
    /// Load configuration from environment variables and the JSON state file.
    /// Environment variables override defaults; the state file provides node identity.
    /// </summary>
    public static AgentConfig Load(string? stateFileOverride = null)
    {
        var cfg = new AgentConfig();

        // Path overrides from environment
        cfg.StateFile      = Env("BMW_STATE_FILE",      stateFileOverride ?? cfg.StateFile);
        cfg.RuntimeDir     = Env("BMW_RUNTIME_DIR",     cfg.RuntimeDir);
        cfg.RuntimeExeName = Env("BMW_RUNTIME_EXE_NAME", cfg.RuntimeExeName);

        if (int.TryParse(Environment.GetEnvironmentVariable("BMW_POLL_INTERVAL_SECONDS"), out var pi))
            cfg.FallbackPollSeconds = pi;
        if (int.TryParse(Environment.GetEnvironmentVariable("BMW_MAX_JITTER_SECONDS"), out var jitter))
            cfg.MaxJitterSeconds = jitter;

        // Resolve RuntimeLink after RuntimeDir is finalised
        var linkDefault = OperatingSystem.IsWindows()
            ? Path.Combine(cfg.RuntimeDir, "bmw.exe")
            : Path.Combine(cfg.RuntimeDir, "bmw");
        cfg.RuntimeLink = Env("BMW_RUNTIME_LINK", linkDefault);

        // Load node identity
        if (!string.IsNullOrEmpty(cfg.StateFile) && File.Exists(cfg.StateFile))
        {
            try
            {
                var json = File.ReadAllText(cfg.StateFile);
                cfg.Node = JsonSerializer.Deserialize(json, AgentJsonContext.Default.NodeIdentity);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(
                    $"[BMW Agent] Could not read state file '{cfg.StateFile}': {ex.Message}");
            }
        }

        return cfg;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static string Env(string name, string fallback)
    {
        var val = Environment.GetEnvironmentVariable(name);
        return string.IsNullOrEmpty(val) ? fallback : val;
    }

    private static string DefaultStateFile() => OperatingSystem.IsWindows()
        ? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "bmw", "node.json")
        : "/var/lib/bmw/node.json";

    private static string DefaultRuntimeDir() => OperatingSystem.IsWindows()
        ? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "bmw", "runtime")
        : "/opt/bmw";
}

[JsonSerializable(typeof(NodeIdentity))]
[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
internal partial class AgentJsonContext : JsonSerializerContext { }
