using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace BareMetalWeb.Data;

/// <summary>
/// SIMD-accelerated byte scanner for high-throughput buffer searching.
/// Dispatch order: AVX2 (32 bytes/cycle) → SSE2 (16 bytes/cycle) → AdvSimd/NEON (16 bytes/cycle) → Scalar.
/// All paths return identical results.
/// </summary>
public static class SimdByteScanner
{
    /// <summary>Describes the active SIMD path at runtime.</summary>
    public static string ActivePath
    {
        get
        {
            if (Avx2.IsSupported) return "x86 AVX2 (32 bytes/cycle)";
            if (Sse2.IsSupported) return "x86 SSE2 (16 bytes/cycle)";
            if (AdvSimd.IsSupported) return "ARM AdvSimd/NEON (16 bytes/cycle)";
            return "Scalar fallback";
        }
    }

    /// <summary>
    /// Returns the index of the first occurrence of <paramref name="target"/> in <paramref name="data"/>,
    /// or -1 if not found. Uses AVX2/SSE2/NEON when available.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int FindByte(ReadOnlySpan<byte> data, byte target)
    {
        if (Avx2.IsSupported)
            return FindByteAvx2(data, target);
        if (Sse2.IsSupported)
            return FindByteSse2(data, target);
        if (AdvSimd.IsSupported)
            return FindByteAdvSimd(data, target);
        return FindByteScalar(data, target);
    }

    /// <summary>
    /// Returns the index of the first occurrence of either <paramref name="a"/> or <paramref name="b"/>
    /// in <paramref name="data"/>, or -1 if neither is found.
    /// Useful for delimiter scanning (e.g. searching for '|' or '\n' simultaneously).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int FindAnyOfTwo(ReadOnlySpan<byte> data, byte a, byte b)
    {
        if (Avx2.IsSupported)
            return FindAnyOfTwoAvx2(data, a, b);
        if (Sse2.IsSupported)
            return FindAnyOfTwoSse2(data, a, b);
        if (AdvSimd.IsSupported)
            return FindAnyOfTwoAdvSimd(data, a, b);
        return FindAnyOfTwoScalar(data, a, b);
    }

    /// <summary>
    /// Counts occurrences of <paramref name="target"/> in <paramref name="data"/> using SIMD.
    /// Processes 32 bytes per iteration on AVX2 with POPCNT for mask counting.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int CountByte(ReadOnlySpan<byte> data, byte target)
    {
        if (Avx2.IsSupported)
            return CountByteAvx2(data, target);
        if (Sse2.IsSupported)
            return CountByteSse2(data, target);
        if (AdvSimd.IsSupported)
            return CountByteAdvSimd(data, target);
        return CountByteScalar(data, target);
    }

    // ── Scalar fallbacks ────────────────────────────────────────────────────

    private static int FindByteScalar(ReadOnlySpan<byte> data, byte target)
    {
        for (int i = 0; i < data.Length; i++)
        {
            if (data[i] == target) return i;
        }
        return -1;
    }

    private static int FindAnyOfTwoScalar(ReadOnlySpan<byte> data, byte a, byte b)
    {
        for (int i = 0; i < data.Length; i++)
        {
            byte v = data[i];
            if (v == a || v == b) return i;
        }
        return -1;
    }

    private static int CountByteScalar(ReadOnlySpan<byte> data, byte target)
    {
        int count = 0;
        for (int i = 0; i < data.Length; i++)
        {
            if (data[i] == target) count++;
        }
        return count;
    }


    // ── AVX2 paths (32 bytes per iteration) ─────────────────────────────────

    private static unsafe int FindByteAvx2(ReadOnlySpan<byte> data, byte target)
    {
        int length = data.Length;
        if (length == 0) return -1;

        fixed (byte* ptr = &MemoryMarshal.GetReference(data))
        {
            // Broadcast target byte to all 32 lanes of a 256-bit vector
            Vector256<byte> needle = Vector256.Create(target);
            int i = 0;

            // Process 32 bytes per iteration
            int vectorEnd = length - 31;
            for (; i < vectorEnd; i += 32)
            {
                // Load 32 bytes from the buffer
                Vector256<byte> chunk = Avx.LoadVector256(ptr + i);

                // Compare each byte lane: 0xFF where equal, 0x00 where not
                Vector256<byte> cmp = Avx2.CompareEqual(chunk, needle);

                // Collapse comparison to a 32-bit mask (one bit per byte lane)
                int mask = Avx2.MoveMask(cmp);

                if (mask != 0)
                {
                    // TrailingZeroCount gives the index of the first set bit
                    return i + BitOperations.TrailingZeroCount((uint)mask);
                }
            }

            // Handle remaining bytes with scalar fallback
            for (; i < length; i++)
            {
                if (ptr[i] == target) return i;
            }
        }

        return -1;
    }

    private static unsafe int FindAnyOfTwoAvx2(ReadOnlySpan<byte> data, byte a, byte b)
    {
        int length = data.Length;
        if (length == 0) return -1;

        fixed (byte* ptr = &MemoryMarshal.GetReference(data))
        {
            Vector256<byte> needleA = Vector256.Create(a);
            Vector256<byte> needleB = Vector256.Create(b);
            int i = 0;

            int vectorEnd = length - 31;
            for (; i < vectorEnd; i += 32)
            {
                Vector256<byte> chunk = Avx.LoadVector256(ptr + i);

                // Compare against both targets, OR the results
                Vector256<byte> cmpA = Avx2.CompareEqual(chunk, needleA);
                Vector256<byte> cmpB = Avx2.CompareEqual(chunk, needleB);
                Vector256<byte> combined = Avx2.Or(cmpA, cmpB);

                int mask = Avx2.MoveMask(combined);
                if (mask != 0)
                    return i + BitOperations.TrailingZeroCount((uint)mask);
            }

            for (; i < length; i++)
            {
                byte v = ptr[i];
                if (v == a || v == b) return i;
            }
        }

        return -1;
    }

    private static unsafe int CountByteAvx2(ReadOnlySpan<byte> data, byte target)
    {
        int length = data.Length;
        if (length == 0) return 0;

        int count = 0;
        fixed (byte* ptr = &MemoryMarshal.GetReference(data))
        {
            Vector256<byte> needle = Vector256.Create(target);
            int i = 0;

            int vectorEnd = length - 31;
            for (; i < vectorEnd; i += 32)
            {
                Vector256<byte> chunk = Avx.LoadVector256(ptr + i);
                Vector256<byte> cmp = Avx2.CompareEqual(chunk, needle);
                int mask = Avx2.MoveMask(cmp);

                // POPCNT counts the number of set bits = number of matching bytes
                count += BitOperations.PopCount((uint)mask);
            }

            for (; i < length; i++)
            {
                if (ptr[i] == target) count++;
            }
        }

        return count;
    }

    // ── SSE2 paths (16 bytes per iteration) ─────────────────────────────────

    private static unsafe int FindByteSse2(ReadOnlySpan<byte> data, byte target)
    {
        int length = data.Length;
        if (length == 0) return -1;

        fixed (byte* ptr = &MemoryMarshal.GetReference(data))
        {
            Vector128<byte> needle = Vector128.Create(target);
            int i = 0;

            int vectorEnd = length - 15;
            for (; i < vectorEnd; i += 16)
            {
                Vector128<byte> chunk = Sse2.LoadVector128(ptr + i);
                Vector128<byte> cmp = Sse2.CompareEqual(chunk, needle);
                int mask = Sse2.MoveMask(cmp);

                if (mask != 0)
                    return i + BitOperations.TrailingZeroCount((uint)mask);
            }

            for (; i < length; i++)
            {
                if (ptr[i] == target) return i;
            }
        }

        return -1;
    }

    private static unsafe int FindAnyOfTwoSse2(ReadOnlySpan<byte> data, byte a, byte b)
    {
        int length = data.Length;
        if (length == 0) return -1;

        fixed (byte* ptr = &MemoryMarshal.GetReference(data))
        {
            Vector128<byte> needleA = Vector128.Create(a);
            Vector128<byte> needleB = Vector128.Create(b);
            int i = 0;

            int vectorEnd = length - 15;
            for (; i < vectorEnd; i += 16)
            {
                Vector128<byte> chunk = Sse2.LoadVector128(ptr + i);
                Vector128<byte> cmpA = Sse2.CompareEqual(chunk, needleA);
                Vector128<byte> cmpB = Sse2.CompareEqual(chunk, needleB);
                Vector128<byte> combined = Sse2.Or(cmpA, cmpB);

                int mask = Sse2.MoveMask(combined);
                if (mask != 0)
                    return i + BitOperations.TrailingZeroCount((uint)mask);
            }

            for (; i < length; i++)
            {
                byte v = ptr[i];
                if (v == a || v == b) return i;
            }
        }

        return -1;
    }

    private static unsafe int CountByteSse2(ReadOnlySpan<byte> data, byte target)
    {
        int length = data.Length;
        if (length == 0) return 0;

        int count = 0;
        fixed (byte* ptr = &MemoryMarshal.GetReference(data))
        {
            Vector128<byte> needle = Vector128.Create(target);
            int i = 0;

            int vectorEnd = length - 15;
            for (; i < vectorEnd; i += 16)
            {
                Vector128<byte> chunk = Sse2.LoadVector128(ptr + i);
                Vector128<byte> cmp = Sse2.CompareEqual(chunk, needle);
                int mask = Sse2.MoveMask(cmp);
                count += BitOperations.PopCount((uint)mask);
            }

            for (; i < length; i++)
            {
                if (ptr[i] == target) count++;
            }
        }

        return count;
    }

    // ── ARM AdvSimd/NEON paths (16 bytes per iteration) ─────────────────────

    private static int FindByteAdvSimd(ReadOnlySpan<byte> data, byte target)
    {
        int length = data.Length;
        if (length == 0) return -1;

        int vectorizableLength = length & ~0xF; // Round down to 16-byte boundary
        var vecs = MemoryMarshal.Cast<byte, Vector128<byte>>(data[..vectorizableLength]);
        Vector128<byte> needle = Vector128.Create(target);

        for (int k = 0; k < vecs.Length; k++)
        {
            Vector128<byte> cmp = AdvSimd.CompareEqual(vecs[k], needle);

            // MaxAcross reduces all 16 lanes to a single max; non-zero means a hit
            if (AdvSimd.Arm64.MaxAcross(cmp).ToScalar() != 0)
            {
                int baseIdx = k * 16;
                for (int j = 0; j < 16 && baseIdx + j < length; j++)
                {
                    if (data[baseIdx + j] == target)
                        return baseIdx + j;
                }
            }
        }

        // Process remaining bytes beyond the 16-byte-aligned region
        for (int i = vectorizableLength; i < length; i++)
        {
            if (data[i] == target) return i;
        }

        return -1;
    }

    private static int FindAnyOfTwoAdvSimd(ReadOnlySpan<byte> data, byte a, byte b)
    {
        int length = data.Length;
        if (length == 0) return -1;

        int vectorizableLength = length & ~0xF; // Round down to 16-byte boundary
        var vecs = MemoryMarshal.Cast<byte, Vector128<byte>>(data[..vectorizableLength]);
        Vector128<byte> needleA = Vector128.Create(a);
        Vector128<byte> needleB = Vector128.Create(b);

        for (int k = 0; k < vecs.Length; k++)
        {
            Vector128<byte> cmpA = AdvSimd.CompareEqual(vecs[k], needleA);
            Vector128<byte> cmpB = AdvSimd.CompareEqual(vecs[k], needleB);
            Vector128<byte> combined = AdvSimd.Or(cmpA, cmpB);

            if (AdvSimd.Arm64.MaxAcross(combined).ToScalar() != 0)
            {
                int baseIdx = k * 16;
                for (int j = 0; j < 16 && baseIdx + j < length; j++)
                {
                    byte v = data[baseIdx + j];
                    if (v == a || v == b)
                        return baseIdx + j;
                }
            }
        }

        // Process remaining bytes beyond the 16-byte-aligned region
        for (int i = vectorizableLength; i < length; i++)
        {
            byte v = data[i];
            if (v == a || v == b) return i;
        }

        return -1;
    }

    private static int CountByteAdvSimd(ReadOnlySpan<byte> data, byte target)
    {
        int length = data.Length;
        if (length == 0) return 0;

        int count = 0;
        int vectorizableLength = length & ~0xF; // Round down to 16-byte boundary
        var vecs = MemoryMarshal.Cast<byte, Vector128<byte>>(data[..vectorizableLength]);
        Vector128<byte> needle = Vector128.Create(target);
        Vector128<byte> one = Vector128.Create((byte)1);

        for (int k = 0; k < vecs.Length; k++)
        {
            Vector128<byte> cmp = AdvSimd.CompareEqual(vecs[k], needle);
            // Each matching lane = 0xFF; mask to 0x01 to avoid overflow in AddAcross
            Vector128<byte> masked = AdvSimd.And(cmp, one);
            count += AdvSimd.Arm64.AddAcross(masked).ToScalar();
        }

        // Process remaining bytes beyond the 16-byte-aligned region
        for (int i = vectorizableLength; i < length; i++)
        {
            if (data[i] == target) count++;
        }

        return count;
    }
}
