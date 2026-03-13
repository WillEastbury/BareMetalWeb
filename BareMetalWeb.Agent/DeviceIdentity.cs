using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace BareMetalWeb.Agent;

/// <summary>
/// Derives a stable, hardware-bound device identity from two entropy sources:
///   1. The CPU serial number (from /proc/cpuinfo on Linux; machine name as fallback)
///   2. A SHA-256 hash of the first physical NIC MAC address
///
/// The two values are combined with HMAC-SHA256 (CPU serial as key, MAC hash as message)
/// to produce a 32-byte hardware key that is deterministic, tamper-evident, and unique
/// to the physical device.  The key is never stored — it is re-derived on each agent boot.
/// </summary>
internal static class DeviceIdentity
{
    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>
    /// Compute the hardware key: HMAC-SHA256(cpuSerial, SHA256(macAddress)).
    /// Returns a 64-character lowercase hex string.
    /// </summary>
    public static string ComputeHardwareKey()
    {
        var cpuSerial = GetCpuSerial();
        var macHash   = GetFirstNicMacHash();

        // HMAC key = CPU serial bytes, message = MAC hash bytes
        var keyBytes  = Encoding.UTF8.GetBytes(cpuSerial);
        var msgBytes  = Encoding.UTF8.GetBytes(macHash);
        var hmac      = HMACSHA256.HashData(keyBytes, msgBytes);
        return Convert.ToHexString(hmac).ToLowerInvariant();
    }

    /// <summary>
    /// Read the CPU serial from /proc/cpuinfo on Linux (Raspberry Pi and similar ARM
    /// SBCs expose it there).  Falls back to the machine name if not available.
    /// </summary>
    public static string GetCpuSerial()
    {
        if (OperatingSystem.IsLinux())
        {
            try
            {
                foreach (var line in File.ReadLines("/proc/cpuinfo"))
                {
                    if (line.StartsWith("Serial", StringComparison.OrdinalIgnoreCase))
                    {
                        var idx = line.IndexOf(':');
                        if (idx >= 0)
                        {
                            var serial = line[(idx + 1)..].Trim();
                            if (!string.IsNullOrEmpty(serial))
                                return serial;
                        }
                    }
                }
            }
            catch { /* fall through to machine-name */ }
        }

        // Non-Linux or no serial in /proc/cpuinfo — use the machine name as a stable fallback.
        // This is not hardware-bound but is deterministic per host.
        return Environment.MachineName;
    }

    /// <summary>
    /// SHA-256 hash of the raw MAC address of the first physical (non-loopback) NIC.
    /// Returns a 64-character lowercase hex string.
    /// </summary>
    public static string GetFirstNicMacHash()
    {
        var mac   = GetFirstNicMac();
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(mac));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    /// <summary>
    /// Glibc version string (e.g. "2.38"), or "n/a" on non-Linux, "unknown" on any error.
    /// </summary>
    public static string GetGlibcVersion()
    {
        if (!OperatingSystem.IsLinux()) return "n/a";
        try
        {
            // gnu_get_libc_version() returns a null-terminated ASCII string such as "2.38"
            var ptr = GnuGetLibcVersion();
            if (ptr != IntPtr.Zero)
            {
                var v = Marshal.PtrToStringAnsi(ptr);
                if (!string.IsNullOrEmpty(v)) return v;
            }
        }
        catch { /* libc not available or symbol missing */ }
        return "unknown";
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// <summary>
    /// Raw MAC address string (12 hex digits, no separators) of the first physical NIC.
    /// Returns "000000000000" if no suitable NIC is found.
    /// </summary>
    internal static string GetFirstNicMac()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                     .OrderBy(n => n.Name, StringComparer.Ordinal))
        {
            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback
                                        or NetworkInterfaceType.Tunnel)
                continue;

            var addr = nic.GetPhysicalAddress();
            if (addr is null || addr.Equals(PhysicalAddress.None))
                continue;

            var mac = addr.ToString(); // e.g. "AABBCCDDEEFF"
            if (mac.Length >= 12)
                return mac;
        }

        return "000000000000";
    }

    [DllImport("libc", EntryPoint = "gnu_get_libc_version")]
    private static extern IntPtr GnuGetLibcVersion();
}
