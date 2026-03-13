using System.Diagnostics;

namespace BareMetalWeb.Agent;

/// <summary>
/// Manages the lifecycle of the BMW runtime process using a symlink-based
/// binary layout on disk:
///
/// <code>
///   {RuntimeDir}/
///     bmw              ← symlink → bmw-1.6.0   (RuntimeLink)
///     bmw-1.6.0        ← active native binary
///     bmw-1.5.0        ← previous version (kept for rollback)
/// </code>
///
/// On Linux/macOS the symlink is a real filesystem symlink.
/// On Windows a regular file copy is used as a fallback (no symlink privilege required).
///
/// The node identity environment variables are injected into the child process
/// so the runtime can authenticate itself with the control plane.
/// </summary>
internal sealed class RuntimeProcessManager : IDisposable
{
    private readonly AgentConfig _config;
    private Process? _process;

    public RuntimeProcessManager(AgentConfig config)
    {
        _config = config;
    }

    /// <summary>
    /// The version currently running (extracted from the symlink target filename),
    /// or <c>null</c> if no process is active.
    /// </summary>
    public string? CurrentVersion => GetCurrentVersion();

    /// <summary>True when the managed process is running.</summary>
    public bool IsRunning => _process is { HasExited: false };

    // ── Version detection ────────────────────────────────────────────────────

    /// <summary>
    /// Read the currently-active version from the symlink (or shim) target filename.
    /// Returns null if the link does not exist or the name cannot be parsed.
    /// </summary>
    public string? GetCurrentVersion()
    {
        if (!File.Exists(_config.RuntimeLink)) return null;
        var fi = new FileInfo(_config.RuntimeLink);
        var target = fi.LinkTarget;                   // null on non-symlink files
        if (target == null) return null;
        // Extract the version suffix: "BareMetalWeb.Host-2.1.0" → "2.1.0"
        var name = Path.GetFileName(target.TrimEnd('/', '\\'));
        var dash = name.LastIndexOf('-');
        return dash >= 0 ? name[(dash + 1)..] : null;
    }

    // ── Binary paths ─────────────────────────────────────────────────────────

    /// <summary>Full path for the versioned binary file.</summary>
    public string VersionedBinaryPath(string version)
    {
        var name = OperatingSystem.IsWindows()
            ? $"{_config.RuntimeExeName}-{version}.exe"
            : $"{_config.RuntimeExeName}-{version}";
        return Path.Combine(_config.RuntimeDir, name);
    }

    // ── Install ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Install the binary for <paramref name="version"/> and update the symlink / shim
    /// to point to it. The versioned binary must already be present at
    /// <see cref="VersionedBinaryPath"/> before calling this (placed by the download step).
    /// Does NOT start or stop the process — call <see cref="Restart"/> separately.
    /// </summary>
    public void Install(string version)
    {
        var target = VersionedBinaryPath(version);

        if (!File.Exists(target))
        {
            Console.Error.WriteLine(
                $"[BMW Agent] Binary not found at '{target}' — cannot install.");
            return;
        }

        if (!OperatingSystem.IsWindows())
            SetExecutable(target);

        UpdateLink(target);

        Log($"Runtime installed → {version}");
    }

    // ── Process lifecycle ─────────────────────────────────────────────────────

    /// <summary>Stop the current process (if running) and start a new one.</summary>
    public void Restart()
    {
        StopCurrent();
        Start();
    }

    /// <summary>Start the runtime via the symlink.</summary>
    public void Start()
    {
        if (!File.Exists(_config.RuntimeLink))
        {
            Console.Error.WriteLine("[BMW Agent] Runtime link not found — cannot start.");
            return;
        }

        var psi = new ProcessStartInfo(_config.RuntimeLink)
        {
            UseShellExecute        = false,
            CreateNoWindow         = false,
            WorkingDirectory       = _config.RuntimeDir,
        };

        // Inject node identity so the runtime can authenticate itself
        if (_config.Node is { } node)
        {
            psi.Environment["BMW_NODE_ID"]            = node.NodeId;
            psi.Environment["BMW_SERVICE_PRINCIPAL"]  = node.ServicePrincipal;
            psi.Environment["BMW_SECRET"]             = node.Secret;
            psi.Environment["BMW_CLUSTER_ENDPOINT"]   = node.ClusterEndpoint;
            psi.Environment["BMW_CERT_FINGERPRINT"]   = node.CertFingerprint;
        }

        try
        {
            _process = Process.Start(psi);
            Log($"BMW started (pid {_process?.Id})");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[BMW Agent] Failed to start runtime: {ex.Message}");
            _process = null;
        }
    }

    /// <summary>
    /// Gracefully stop the currently-running process.
    /// On Unix: sends SIGTERM via <c>kill</c> and waits up to 10 s before sending SIGKILL.
    /// On Windows: sends WM_QUIT via CloseMainWindow, then TerminateProcess after 10 s.
    /// </summary>
    public void StopCurrent()
    {
        if (_process is not { HasExited: false }) return;
        Log($"Stopping BMW (pid {_process.Id})…");
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                // Send SIGTERM to allow graceful shutdown, then SIGKILL after timeout
                try
                {
                    using var kill = Process.Start(new ProcessStartInfo("kill",
                        $"-TERM {_process.Id}") { UseShellExecute = false });
                    kill?.WaitForExit(1_000);
                }
                catch { /* kill may not be available — fall through to force-kill */ }
            }
            else
            {
                _process.CloseMainWindow();
            }

            if (!_process.WaitForExit(10_000))
                _process.Kill(entireProcessTree: false);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[BMW Agent] Error stopping runtime: {ex.Message}");
        }
        finally
        {
            _process.Dispose();
            _process = null;
        }
    }

    public void Dispose() => StopCurrent();

    // ── Private helpers ───────────────────────────────────────────────────────

    private void UpdateLink(string targetBinaryPath)
    {
        if (File.Exists(_config.RuntimeLink))
            File.Delete(_config.RuntimeLink);

        if (!OperatingSystem.IsWindows())
        {
            File.CreateSymbolicLink(_config.RuntimeLink, targetBinaryPath);
        }
        else
        {
            // Windows: copy as a shim (avoid requiring SeCreateSymbolicLinkPrivilege)
            File.Copy(targetBinaryPath, _config.RuntimeLink, overwrite: true);
        }
    }

    private static void SetExecutable(string path)
    {
        try
        {
            File.SetUnixFileMode(path,
                UnixFileMode.UserRead    |
                UnixFileMode.UserWrite   |
                UnixFileMode.UserExecute |
                UnixFileMode.GroupRead   |
                UnixFileMode.GroupExecute);
        }
        catch { /* best-effort */ }
    }

    private static void Log(string msg) =>
        Console.WriteLine($"{DateTime.UtcNow:O} | {msg}");
}
