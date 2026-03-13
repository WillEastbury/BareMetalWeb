using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BareMetalWeb.ControlPlane;

namespace BareMetalWeb.Agent;

/// <summary>
/// Handles first-boot registration and ongoing attestation of a node with the control plane.
///
/// On first boot (no valid state file), the agent:
///   1. Derives a stable hardware key from the CPU serial and first NIC MAC.
///   2. Derives a stable node ID and a per-boot secret from that key.
///   3. POSTs a <see cref="NodeRegistrationRequest"/> to the bootstrap endpoint.
///   4. Persists the returned <see cref="NodeIdentity"/> to disk.
///
/// On subsequent boots, the agent re-attests with the current OS/glibc version
/// so the control plane can verify the node is still on an approved platform.
/// </summary>
internal sealed class NodeRegistrationService
{
    private readonly AgentConfig _config;

    public NodeRegistrationService(AgentConfig config)
    {
        _config = config;
    }

    // ── Registration (first boot) ─────────────────────────────────────────────

    /// <summary>
    /// Perform first-boot registration: derive hardware credentials, send a
    /// <see cref="NodeRegistrationRequest"/> to the bootstrap endpoint, and persist
    /// the returned <see cref="NodeIdentity"/> to the state file.
    ///
    /// Returns the registered identity, or <c>null</c> on failure.
    /// </summary>
    public async Task<NodeIdentity?> RegisterAsync(CancellationToken ct)
    {
        var endpoint  = _config.BootstrapEndpoint;
        var principal = _config.BootstrapPrincipal;

        if (string.IsNullOrEmpty(endpoint))
        {
            Log("ERROR: BMW_BOOTSTRAP_ENDPOINT is not set — cannot self-register.");
            return null;
        }

        Log($"Starting first-boot registration → {endpoint}");

        var hardwareKey = DeviceIdentity.ComputeHardwareKey();
        var nodeId      = DeriveNodeId(hardwareKey);
        var secret      = DeriveSecret(hardwareKey);

        var req = new NodeRegistrationRequest
        {
            NodeId             = nodeId,
            SecretHash         = HashSecret(secret),
            BootstrapPrincipal = principal,
            Architecture       = _config.Architecture,
            OsDescription      = GetOsDescription(),
            GlibcVersion       = DeviceIdentity.GetGlibcVersion(),
            MacHash            = DeviceIdentity.GetFirstNicMacHash(),
        };

        var identity = await ControlPlaneClient.RegisterNodeAsync(endpoint, secret, req, ct)
            .ConfigureAwait(false);

        if (identity == null)
        {
            Log("ERROR: Registration failed — control plane returned no identity.");
            return null;
        }

        PersistIdentity(identity);
        Log($"Registration successful — nodeId={identity.NodeId} ring={identity.Ring}");
        return identity;
    }

    // ── Attestation (every boot after registration) ───────────────────────────

    /// <summary>
    /// Re-attest the node's platform with the control plane.  Non-fatal — a failed
    /// attestation is logged but does not block the agent from running.
    /// </summary>
    public async Task AttestAsync(NodeIdentity node, CancellationToken ct)
    {
        Log($"Attesting node {node.NodeId} with control plane…");
        try
        {
            var req = new NodeAttestationRequest
            {
                NodeId        = node.NodeId,
                Architecture  = _config.Architecture,
                OsDescription = GetOsDescription(),
                GlibcVersion  = DeviceIdentity.GetGlibcVersion(),
                MacHash       = DeviceIdentity.GetFirstNicMacHash(),
                Timestamp     = DateTime.UtcNow.ToString("O"),
            };

            var ok = await ControlPlaneClient.AttestNodeAsync(
                    node.ClusterEndpoint, node.Secret, req, ct)
                .ConfigureAwait(false);

            Log(ok ? "Attestation accepted." : "Attestation rejected — continuing with current identity.");
        }
        catch (Exception ex)
        {
            Log($"Attestation error (non-fatal): {ex.Message}");
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// <summary>
    /// Derive a stable UUID-shaped node ID from the first 16 bytes of the hardware key.
    /// Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    /// </summary>
    private static string DeriveNodeId(string hardwareKey)
    {
        // hardware key is 64 hex chars (32 bytes); take the first 32 hex chars (16 bytes)
        var h = hardwareKey[..32];
        return $"{h[..8]}-{h[8..12]}-{h[12..16]}-{h[16..20]}-{h[20..]}";
    }

    /// <summary>
    /// Derive a per-node secret from the last 32 chars of the hardware key (bytes 16-31).
    /// The secret is never stored — it is re-derived from hardware identity on each boot.
    /// </summary>
    private static string DeriveSecret(string hardwareKey)
        => hardwareKey[32..]; // last 32 hex chars

    private static string HashSecret(string secret)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string GetOsDescription()
    {
        if (OperatingSystem.IsLinux())
        {
            try
            {
                foreach (var line in File.ReadLines("/etc/os-release"))
                {
                    if (line.StartsWith("PRETTY_NAME=", StringComparison.Ordinal))
                        return line[12..].Trim('"');
                }
            }
            catch { /* fall through */ }
        }
        return System.Runtime.InteropServices.RuntimeInformation.OSDescription;
    }

    private void PersistIdentity(NodeIdentity identity)
    {
        try
        {
            var dir = Path.GetDirectoryName(_config.StateFile);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            var json = JsonSerializer.Serialize(identity, AgentJsonContext.Default.NodeIdentity);
            File.WriteAllText(_config.StateFile, json);

            // Restrict to owner read/write on Linux — the state file contains the node secret
            if (!OperatingSystem.IsWindows())
            {
                try
                {
                    File.SetUnixFileMode(_config.StateFile,
                        UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
                catch { /* best-effort */ }
            }

            Log($"Node identity written to {_config.StateFile}");
        }
        catch (Exception ex)
        {
            Log($"ERROR: Could not persist node identity: {ex.Message}");
        }
    }

    private static void Log(string msg)
        => Console.WriteLine($"{DateTime.UtcNow:O} | [Registration] {msg}");
}
