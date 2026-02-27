using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// Software CRC-32C (Castagnoli) implementation.
/// Uses the reflected polynomial 0x82F63B78.
/// No external dependencies; AOT-friendly.
/// </summary>
internal static class WalCrc32C
{
    private static readonly uint[] Table = BuildTable();
    private const uint Poly = 0x82F63B78u; // Reflected CRC-32C polynomial

    private static uint[] BuildTable()
    {
        var t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint crc = i;
            for (int j = 0; j < 8; j++)
                crc = (crc & 1u) != 0u ? (crc >> 1) ^ Poly : crc >> 1;
            t[i] = crc;
        }
        return t;
    }

    /// <summary>Computes CRC-32C over <paramref name="data"/>.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint Compute(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFF_FFFFu;
        foreach (byte b in data)
            crc = (crc >> 8) ^ Table[(byte)(crc ^ b)];
        return ~crc;
    }
}
