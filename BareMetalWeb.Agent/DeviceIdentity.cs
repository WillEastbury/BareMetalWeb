using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
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
    // Maximum length accepted for the CPU serial (guards against injected garbage)
    private const int MaxSerialLength = 256;

    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>
    /// Compute the hardware key.  Prefers ATECC608A secure element (if present on i2c)
    /// which provides a 32-byte hardware-bound secret that never leaves the chip.
    /// Falls back to HMAC-SHA256(cpuSerial, SHA256(macAddress)).
    /// Returns a 64-character lowercase hex string.
    /// </summary>
    public static string ComputeHardwareKey()
    {
        // Try ATECC608A first — strongest hardware binding available
        if (OperatingSystem.IsLinux())
        {
            try
            {
                var slotKey = Data.Atecc608a.ReadSlotKey();
                if (slotKey is { Length: 32 })
                    return Convert.ToHexString(slotKey).ToLowerInvariant();
            }
            catch { /* chip absent or unreadable — fall through */ }
        }

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
    /// The value is sanitised to contain only ASCII alphanumeric characters before
    /// being used as cryptographic key material.
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
                            var raw = line[(idx + 1)..].Trim();
                            var sanitised = SanitiseSerial(raw);
                            if (!string.IsNullOrEmpty(sanitised))
                                return sanitised;
                        }
                    }
                }
            }
            catch { /* fall through to machine-name */ }
        }

        // Non-Linux or no serial in /proc/cpuinfo — use the machine name as a stable fallback.
        return SanitiseSerial(Environment.MachineName) is { Length: > 0 } s ? s : "baremetalweb-node";
    }

    /// <summary>
    /// SHA-256 hash of the raw MAC address of the first physical NIC.
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
    [SupportedOSPlatform("linux")]
    public static string GetGlibcVersion()
    {
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

    /// <summary>
    /// Returns the glibc version on Linux, or "n/a" on other platforms.
    /// </summary>
    public static string GetGlibcVersionCrossPlatform()
    {
        if (!OperatingSystem.IsLinux()) return "n/a";
        return GetGlibcVersion();
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// <summary>
    /// Raw MAC address string (12 hex digits, no separators) of the first physical NIC.
    /// Prefers Ethernet and Wi-Fi NICs over virtual/software-defined interfaces.
    /// Returns "000000000000" if no suitable NIC is found.
    /// </summary>
    internal static string GetFirstNicMac()
    {
        // Ordered preference: physical Ethernet, Wi-Fi, then any other non-virtual type
        static int NicPriority(NetworkInterfaceType t) => t switch
        {
            NetworkInterfaceType.Ethernet         => 0,
            NetworkInterfaceType.Wireless80211     => 1,
            NetworkInterfaceType.FastEthernetT    => 0,
            NetworkInterfaceType.GigabitEthernet  => 0,
            NetworkInterfaceType.FastEthernetFx   => 0,
            _                                     => 2,
        };

        static bool IsVirtual(NetworkInterfaceType t) => t is
            NetworkInterfaceType.Loopback or
            NetworkInterfaceType.Tunnel   or
            NetworkInterfaceType.Ppp      or
            NetworkInterfaceType.Slip     or
            NetworkInterfaceType.GenericModem;

        var candidate = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => !IsVirtual(n.NetworkInterfaceType))
            .OrderBy(n => NicPriority(n.NetworkInterfaceType))
            .ThenBy(n => n.Name, StringComparer.Ordinal)
            .FirstOrDefault(n =>
            {
                var addr = n.GetPhysicalAddress();
                return addr is not null && !addr.Equals(PhysicalAddress.None)
                    && addr.ToString().Length >= 12;
            });

        if (candidate is not null)
        {
            var mac = candidate.GetPhysicalAddress().ToString();
            if (mac.Length >= 12) return mac;
        }

        return "000000000000";
    }

    /// <summary>
    /// Sanitise a serial / name string for use as cryptographic key material.
    /// Keeps only ASCII letters, digits, hyphens, and underscores; truncates to
    /// <see cref="MaxSerialLength"/> characters.
    /// </summary>
    private static string SanitiseSerial(string raw)
    {
        if (string.IsNullOrEmpty(raw)) return "";

        Span<char> buf = stackalloc char[Math.Min(raw.Length, MaxSerialLength)];
        int idx = 0;
        foreach (var ch in raw.AsSpan())
        {
            if (idx >= MaxSerialLength) break;
            if (char.IsAsciiLetterOrDigit(ch) || ch == '-' || ch == '_')
                buf[idx++] = ch;
        }
        return idx > 0 ? new string(buf[..idx]) : "";
    }

    [DllImport("libc", EntryPoint = "gnu_get_libc_version",
               ExactSpelling = true, CharSet = CharSet.Ansi)]
    [SupportedOSPlatform("linux")]
    private static extern IntPtr GnuGetLibcVersion();
}

