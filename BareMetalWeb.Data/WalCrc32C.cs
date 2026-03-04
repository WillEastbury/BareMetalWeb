using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
#if NET7_0_OR_GREATER
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
#endif

namespace BareMetalWeb.Data;

/// <summary>
/// CRC-32C (Castagnoli) implementation with hardware acceleration.
/// Uses ARM CRC32C instructions or x86 SSE4.2 when available;
/// falls back to a table-lookup software path. AOT-friendly.
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
#if NET7_0_OR_GREATER
        if (Crc32.Arm64.IsSupported)
            return ComputeArm64(data);
        if (Sse42.X64.IsSupported)
            return ComputeSse42X64(data);
        if (Sse42.IsSupported)
            return ComputeSse42(data);
#endif
        return ComputeSoftware(data);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint ComputeSoftware(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFF_FFFFu;
        foreach (byte b in data)
            crc = (crc >> 8) ^ Table[(byte)(crc ^ b)];
        return ~crc;
    }

#if NET7_0_OR_GREATER
    private static uint ComputeArm64(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFF_FFFFu;
        int i = 0;

        // Process 8 bytes at a time using CRC32CD (64-bit)
        if (Crc32.Arm64.IsSupported)
        {
            var longs = MemoryMarshal.Cast<byte, ulong>(data);
            for (int k = 0; k < longs.Length; k++)
                crc = Crc32.Arm64.ComputeCrc32C(crc, longs[k]);
            i = longs.Length * 8;
        }

        // Process remaining bytes
        for (; i < data.Length; i++)
            crc = Crc32.ComputeCrc32C(crc, data[i]);

        return ~crc;
    }

    private static uint ComputeSse42X64(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFF_FFFFu;
        int i = 0;

        // Process 8 bytes at a time using CRC32C 64-bit
        var longs = MemoryMarshal.Cast<byte, ulong>(data);
        for (int k = 0; k < longs.Length; k++)
            crc = (uint)Sse42.X64.Crc32(crc, longs[k]);
        i = longs.Length * 8;

        // Process remaining bytes
        for (; i < data.Length; i++)
            crc = Sse42.Crc32(crc, data[i]);

        return ~crc;
    }

    private static uint ComputeSse42(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFF_FFFFu;
        int i = 0;

        // Process 4 bytes at a time using CRC32C 32-bit
        var ints = MemoryMarshal.Cast<byte, uint>(data);
        for (int k = 0; k < ints.Length; k++)
            crc = Sse42.Crc32(crc, ints[k]);
        i = ints.Length * 4;

        // Process remaining bytes
        for (; i < data.Length; i++)
            crc = Sse42.Crc32(crc, data[i]);

        return ~crc;
    }
#endif
}
