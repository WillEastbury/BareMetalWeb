using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace BareMetalWeb.Data;

/// <summary>
/// CRC-32C (Castagnoli) implementation with hardware acceleration.
/// Uses ARM CRC32C instructions or x86 SSE4.2 when available;
/// falls back to a slicing-by-4 software path for platforms without hardware CRC.
/// AOT-friendly.
/// </summary>
internal static class WalCrc32C
{
    // ── Software-fallback tables ─────────────────────────────────────────────
    // Four interleaved CRC tables for slicing-by-4: each table pre-folds one
    // additional byte so that four input bytes can be combined into the CRC
    // state in a single parallel step.  This is ~4× faster than byte-at-a-time
    // processing on platforms without hardware CRC32C (e.g. WASM, older ARM).
    private static readonly uint[] Table0 = BuildTable(0);
    private static readonly uint[] Table1 = BuildTable(1);
    private static readonly uint[] Table2 = BuildTable(2);
    private static readonly uint[] Table3 = BuildTable(3);

    private const uint Poly = 0x82F63B78u; // Reflected CRC-32C polynomial

    private static uint[] BuildTable(int slice)
    {
        var t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint crc = i;
            for (int j = 0; j < 8; j++)
                crc = (crc & 1u) != 0u ? (crc >> 1) ^ Poly : crc >> 1;
            t[i] = crc;
        }

        if (slice == 0) return t;

        // Higher slices: pre-compose additional byte-steps through slice-0 so
        // that table_k[b] represents the contribution of byte b at position k
        // within a 4-byte word.
        var t2 = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint crc = t[i];
            for (int s = 0; s < slice; s++)
                crc = (crc >> 8) ^ t[crc & 0xFF];
            t2[i] = crc;
        }
        return t2;
    }

    /// <summary>Computes CRC-32C over <paramref name="data"/>.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint Compute(ReadOnlySpan<byte> data)
    {
        if (Crc32.Arm64.IsSupported)
            return ComputeArm64(data);
        if (Sse42.X64.IsSupported)
            return ComputeSse42X64(data);
        if (Sse42.IsSupported)
            return ComputeSse42(data);
        return ComputeSoftware(data);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint ComputeSoftware(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFF_FFFFu;
        int i = 0;

        // Slicing-by-4: process 4 bytes per iteration using four pre-composed
        // CRC tables, folding all four bytes into the state without intermediate
        // carries. This is ~4× faster than the byte-at-a-time loop on CPUs that
        // lack hardware CRC32C support (e.g. WASM, older ARM).
        //
        // For a little-endian uint word = [b0, b1, b2, b3]:
        //   Table3[b0] folds b0 as if it were 3 bytes further left in the stream.
        //   Table2[b1] folds b1 as if it were 2 bytes further left.
        //   Table1[b2] folds b2 as if it were 1 byte further left.
        //   Table0[b3] folds b3 at its natural position.
        // XOR-ing the four results is equivalent to processing b0..b3 in order.
        var ints = MemoryMarshal.Cast<byte, uint>(data);
        for (; i < ints.Length; i++)
        {
            uint word = ints[i] ^ crc;
            crc = Table3[ word        & 0xFF]
                ^ Table2[(word >>  8) & 0xFF]
                ^ Table1[(word >> 16) & 0xFF]
                ^ Table0[ word >> 24];
        }

        // Process any remaining bytes one at a time
        i *= 4;
        for (; i < data.Length; i++)
            crc = (crc >> 8) ^ Table0[(byte)(crc ^ data[i])];

        return ~crc;
    }

    private static uint ComputeArm64(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFF_FFFFu;
        int i = 0;

        // Process 8 bytes at a time using CRC32CD (64-bit).
        // The ARM CRC32C instruction has ~3 cycle latency, so the CPU's
        // out-of-order engine can sustain near-throughput-limited performance
        // on modern cores.
        var longs = MemoryMarshal.Cast<byte, ulong>(data);
        for (int k = 0; k < longs.Length; k++)
            crc = Crc32.Arm64.ComputeCrc32C(crc, longs[k]);
        i = longs.Length * 8;

        // Process remaining bytes
        for (; i < data.Length; i++)
            crc = Crc32.ComputeCrc32C(crc, data[i]);

        return ~crc;
    }

    private static uint ComputeSse42X64(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFF_FFFFu;
        int i = 0;

        // Process 8 bytes at a time using CRC32Q (64-bit SSE4.2).
        var longs = MemoryMarshal.Cast<byte, ulong>(data);
        for (int k = 0; k < longs.Length; k++)
            crc = (uint)Sse42.X64.Crc32((ulong)crc, longs[k]);
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

        // Process 4 bytes at a time using CRC32D (32-bit SSE4.2)
        var ints = MemoryMarshal.Cast<byte, uint>(data);
        for (int k = 0; k < ints.Length; k++)
            crc = Sse42.Crc32(crc, ints[k]);
        i = ints.Length * 4;

        // Process remaining bytes
        for (; i < data.Length; i++)
            crc = Sse42.Crc32(crc, data[i]);

        return ~crc;
    }
}
