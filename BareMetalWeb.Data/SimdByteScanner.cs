using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace BareMetalWeb.Data;

/// <summary>
/// High-performance SIMD byte scanner for <c>ReadOnlySpan&lt;byte&gt;</c> buffers.
/// Locates the first occurrence of a single target byte using the widest
/// available SIMD register width, with a scalar fallback for CPUs that lack
/// hardware vector support.
///
/// <para>Dispatch order (widest / fastest first):</para>
/// <list type="number">
///   <item>x86-64 AVX2 — 256-bit / 32 bytes per iteration (~20+ GB/s on modern hardware)</item>
///   <item>ARM AdvSimd (NEON) — 128-bit / 16 bytes per iteration</item>
///   <item>Portable <see cref="Vector{T}"/> — JIT-selected width (8 or 16 bytes/iter)</item>
///   <item>Scalar fallback — one byte per iteration</item>
/// </list>
///
/// <para>Zero allocations; uses <c>MemoryMarshal</c> and <c>Vector*.LoadUnsafe</c>
/// to avoid requiring an <c>unsafe</c> compilation context.</para>
///
/// <para><b>Performance goal:</b> scan buffers &gt;1 MB at memory-bandwidth speeds.
/// Run <c>ByteScannerBenchmarks</c> in <c>BareMetalWeb.Benchmarks</c> to measure.</para>
/// </summary>
public static class SimdByteScanner
{
    // ─── Diagnostics ──────────────────────────────────────────────────────────

    /// <summary>
    /// Human-readable label for the active acceleration path on this CPU.
    /// Use in startup log lines and the metrics dashboard.
    /// </summary>
    public static string ActivePath
    {
        get
        {
            if (Avx2.IsSupported)
                return $"x86 AVX2 (256-bit / 32 bytes per iteration)";
            if (AdvSimd.IsSupported)
                return $"ARM AdvSimd/NEON (128-bit / 16 bytes per iteration)";
            int vw = Vector<byte>.Count;
            if (vw > 1)
                return $"Portable Vector<byte> ({vw * 8}-bit / {vw} bytes per iteration)";
            return "Scalar (no SIMD)";
        }
    }

    // ─── Public API ───────────────────────────────────────────────────────────

    /// <summary>
    /// Returns the zero-based index of the first occurrence of <paramref name="target"/>
    /// in <paramref name="data"/>, or <c>-1</c> if not found.
    /// </summary>
    /// <remarks>
    /// The method dispatches to the highest-performance path available at runtime:
    /// AVX2 → ARM AdvSimd → portable Vector&lt;byte&gt; → scalar.
    /// All paths produce identical results.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int FindByte(ReadOnlySpan<byte> data, byte target)
    {
        if (data.IsEmpty) return -1;

        // Fast-path: delegate to the .NET runtime's own optimised search when the
        // buffer is small enough that SIMD setup overhead would dominate.
        if (data.Length < 32)
            return FindByteScalar(data, target);

        if (Avx2.IsSupported)
            return FindByteAvx2(data, target);

        if (AdvSimd.IsSupported)
            return FindByteAdvSimd(data, target);

        int vw = Vector<byte>.Count;
        if (data.Length >= vw && vw > 1)
            return FindByteVector(data, target);

        return FindByteScalar(data, target);
    }

    // ─── x86 AVX2: 256-bit / 32 bytes per iteration ──────────────────────────

    private static int FindByteAvx2(ReadOnlySpan<byte> data, byte target)
    {
        // Broadcast the target byte into all 32 lanes of a 256-bit register.
        // Every compare will check 32 bytes simultaneously.
        var targetVec = Vector256.Create(target);

        // Pin a ref to the first byte so LoadUnsafe can stride through the buffer
        // without allocating or using a fixed/unsafe block.
        ref byte origin = ref MemoryMarshal.GetReference(data);

        int i = 0;
        int limit = data.Length - 31; // last safe start position for a 32-byte load

        for (; i < limit; i += 32)
        {
            // Step 1: Load 32 consecutive bytes starting at data[i].
            var v = Vector256.LoadUnsafe(ref origin, (nuint)i);

            // Step 2: Compare each of the 32 byte-lanes with the target.
            //         Each lane becomes 0xFF (255) on a match, 0x00 otherwise.
            var cmp = Avx2.CompareEqual(v, targetVec);

            // Step 3: Pack the high bit of each byte-lane into a 32-bit integer.
            //         Bit j == 1  ⟺  data[i + j] == target.
            int mask = Avx2.MoveMask(cmp);

            // Step 4: If any bit is set, the position of the lowest set bit
            //         (trailing-zero count) is the lane index of the first match.
            if (mask != 0)
                return i + BitOperations.TrailingZeroCount(mask);
        }

        // Handle any remaining bytes that did not fill a full 32-byte vector.
        for (; i < data.Length; i++)
        {
            if (data[i] == target) return i;
        }

        return -1;
    }

    // ─── ARM AdvSimd (NEON): 128-bit / 16 bytes per iteration ─────────────────

    private static int FindByteAdvSimd(ReadOnlySpan<byte> data, byte target)
    {
        // Broadcast the target byte to all 16 lanes of a 128-bit NEON register.
        var targetVec = Vector128.Create(target);

        ref byte origin = ref MemoryMarshal.GetReference(data);
        int i = 0;
        int limit = data.Length - 15; // last safe start for a 16-byte load

        for (; i < limit; i += 16)
        {
            // Load 16 consecutive bytes.
            var v = Vector128.LoadUnsafe(ref origin, (nuint)i);

            // Compare each byte-lane; matches become 0xFF.
            var cmp = AdvSimd.CompareEqual(v, targetVec);

            // MaxAcross collapses the 16 lanes to the single highest byte value.
            // A non-zero result means at least one lane matched.
            if (AdvSimd.Arm64.MaxAcross(cmp).ToScalar() != 0)
            {
                // Pinpoint which byte in the 16-byte window matched.
                for (int j = i; j < i + 16; j++)
                {
                    if (data[j] == target) return j;
                }
            }
        }

        // Scalar tail for the remaining < 16 bytes.
        for (; i < data.Length; i++)
        {
            if (data[i] == target) return i;
        }

        return -1;
    }

    // ─── Portable SIMD – System.Numerics.Vector<byte> ────────────────────────
    // The JIT selects the underlying register width:
    //   AVX2  → Vector<byte>.Count == 32 (256-bit)
    //   SSE2 / NEON → Vector<byte>.Count == 16 (128-bit)

    private static int FindByteVector(ReadOnlySpan<byte> data, byte target)
    {
        int vLen = Vector<byte>.Count;
        var targetVec = new Vector<byte>(target);
        int i = 0;

        for (; i <= data.Length - vLen; i += vLen)
        {
            // Load one full vector-width chunk.
            var v = new Vector<byte>(data.Slice(i, vLen));

            // Equals: each matching lane becomes 0xFF, others 0x00.
            var cmp = Vector.Equals(v, targetVec);

            // If any lane matched, narrow down to the exact byte.
            if (cmp != Vector<byte>.Zero)
            {
                for (int j = i; j < i + vLen; j++)
                {
                    if (data[j] == target) return j;
                }
            }
        }

        // Scalar tail for remaining bytes.
        for (; i < data.Length; i++)
        {
            if (data[i] == target) return i;
        }

        return -1;
    }

    // ─── Scalar fallback ──────────────────────────────────────────────────────
    // Runs when the buffer is small, or when no SIMD is available.

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int FindByteScalar(ReadOnlySpan<byte> data, byte target)
    {
        for (int i = 0; i < data.Length; i++)
        {
            if (data[i] == target) return i;
        }
        return -1;
    }
}
