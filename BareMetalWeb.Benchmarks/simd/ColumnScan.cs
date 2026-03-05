using System.Numerics;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace BareMetalWeb.Benchmarks.Simd;

/// <summary>
/// SIMD-accelerated column scan operations.
/// Finds all row indices in a typed column array whose value equals a target.
///
/// Three implementations are provided, in ascending hardware specificity:
///   1. <see cref="ScanScalar"/>  – plain loop (baseline).
///   2. <see cref="ScanVector"/>  – portable <see cref="Vector{T}"/> (AVX / SSE / ARM Neon).
///   3. <see cref="ScanAvx2"/>    – AVX2 hardware intrinsics (x86/x64 only, guarded).
///
/// <b>Bitmask variants</b> (<see cref="ScanToBitmask"/>) return a <c>ulong[]</c> bitset
/// instead of an index list, which is preferable for downstream bitmask-AND/OR filter
/// composition.
/// </summary>
public static class ColumnScan
{
    // ── Scalar baseline ──────────────────────────────────────────────────

    /// <summary>Scalar baseline scan. O(n) comparisons, one per loop iteration.</summary>
    public static List<int> ScanScalar(int[] column, int target)
    {
        var results = new List<int>();
        for (int i = 0; i < column.Length; i++)
        {
            if (column[i] == target)
                results.Add(i);
        }
        return results;
    }

    // ── Portable SIMD – System.Numerics.Vector<T> ────────────────────────

    /// <summary>
    /// Portable SIMD scan using <see cref="Vector{T}"/>.
    /// Processes <see cref="Vector{int}.Count"/> elements per iteration (8 on AVX2,
    /// 4 on SSE2, 4 on ARM Neon with 128-bit vectors).
    /// </summary>
    public static List<int> ScanVector(int[] column, int target)
    {
        var results = new List<int>();
        int vLen = Vector<int>.Count;
        var targetVec = new Vector<int>(target);
        int i = 0;

        for (; i <= column.Length - vLen; i += vLen)
        {
            var v = new Vector<int>(column, i);
            var eq = Vector.Equals(v, targetVec);
            if (eq != Vector<int>.Zero)
            {
                for (int j = 0; j < vLen; j++)
                {
                    if (eq[j] != 0)
                        results.Add(i + j);
                }
            }
        }

        // Scalar remainder
        for (; i < column.Length; i++)
        {
            if (column[i] == target)
                results.Add(i);
        }

        return results;
    }

    // ── AVX2 hardware intrinsics ─────────────────────────────────────────

    /// <summary>
    /// AVX2 scan using 256-bit compare + <c>MoveMask</c>.
    /// Processes 8 ints per cycle. Falls back to <see cref="ScanVector"/> when
    /// AVX2 is not available (ARM, older x86, virtual machines).
    /// </summary>
    public static List<int> ScanAvx2(int[] column, int target)
    {
        if (!Avx2.IsSupported)
            return ScanVector(column, target);

        var results = new List<int>();
        const int vLen = 8; // 256 bits / 32 bits per int
        var targetVec = Vector256.Create(target);
        int i = 0;

        unsafe
        {
            fixed (int* ptr = column)
            {
                for (; i <= column.Length - vLen; i += vLen)
                {
                    var v = Avx.LoadVector256(ptr + i);
                    var cmp = Avx2.CompareEqual(v, targetVec);

                    // MoveMask on float reinterpretation gives 1 bit per 32-bit lane
                    int mask = Avx.MoveMask(cmp.AsSingle());
                    while (mask != 0)
                    {
                        int bit = BitOperations.TrailingZeroCount((uint)mask);
                        results.Add(i + bit);
                        mask &= mask - 1; // clear lowest set bit
                    }
                }
            }
        }

        // Scalar remainder
        for (; i < column.Length; i++)
        {
            if (column[i] == target)
                results.Add(i);
        }

        return results;
    }

    // ── Bitmask filter variants ──────────────────────────────────────────

    /// <summary>
    /// Returns a <c>ulong[]</c> bitset where bit <c>i</c> is set when
    /// <c>column[i] == target</c>.  Dispatches to AVX2 or scalar depending on
    /// CPU capabilities.
    /// </summary>
    public static ulong[] ScanToBitmask(int[] column, int target)
    {
        int wordCount = (column.Length + 63) >> 6;
        var bitmask = new ulong[wordCount];

        if (Avx2.IsSupported)
            ScanToBitmaskAvx2(column, target, bitmask);
        else
            ScanToBitmaskScalar(column, target, bitmask);

        return bitmask;
    }

    private static void ScanToBitmaskScalar(int[] column, int target, ulong[] bitmask)
    {
        for (int i = 0; i < column.Length; i++)
        {
            if (column[i] == target)
                bitmask[i >> 6] |= 1UL << (i & 63);
        }
    }

    private static unsafe void ScanToBitmaskAvx2(int[] column, int target, ulong[] bitmask)
    {
        const int vLen = 8;
        var targetVec = Vector256.Create(target);
        int i = 0;

        fixed (int* ptr = column)
        {
            for (; i <= column.Length - vLen; i += vLen)
            {
                var v = Avx.LoadVector256(ptr + i);
                var cmp = Avx2.CompareEqual(v, targetVec);
                int moveMask = Avx.MoveMask(cmp.AsSingle()); // 8-bit mask

                if (moveMask != 0)
                {
                    int wordIdx = i >> 6;
                    int bitOff = i & 63;
                    bitmask[wordIdx] |= (ulong)(byte)moveMask << bitOff;
                    // Handle cross-word spillover when bitOff > 56
                    if (bitOff + vLen > 64)
                        bitmask[wordIdx + 1] |= (ulong)(byte)moveMask >> (64 - bitOff);
                }
            }
        }

        // Scalar remainder
        for (; i < column.Length; i++)
        {
            if (column[i] == target)
                bitmask[i >> 6] |= 1UL << (i & 63);
        }
    }

    // ── long column variants ─────────────────────────────────────────────

    /// <summary>Scalar scan over a <c>long[]</c> column.</summary>
    public static List<int> ScanScalar(long[] column, long target)
    {
        var results = new List<int>();
        for (int i = 0; i < column.Length; i++)
        {
            if (column[i] == target)
                results.Add(i);
        }
        return results;
    }

    /// <summary>Portable Vector&lt;long&gt; scan (4 longs per vector on AVX2).</summary>
    public static List<int> ScanVector(long[] column, long target)
    {
        var results = new List<int>();
        int vLen = Vector<long>.Count;
        var targetVec = new Vector<long>(target);
        int i = 0;

        for (; i <= column.Length - vLen; i += vLen)
        {
            var v = new Vector<long>(column, i);
            var eq = Vector.Equals(v, targetVec);
            if (eq != Vector<long>.Zero)
            {
                for (int j = 0; j < vLen; j++)
                {
                    if (eq[j] != 0)
                        results.Add(i + j);
                }
            }
        }

        for (; i < column.Length; i++)
        {
            if (column[i] == target)
                results.Add(i);
        }

        return results;
    }

    /// <summary>AVX2 scan over a <c>long[]</c> column (4 longs per 256-bit register).</summary>
    public static List<int> ScanAvx2(long[] column, long target)
    {
        if (!Avx2.IsSupported)
            return ScanVector(column, target);

        var results = new List<int>();
        const int vLen = 4; // 256 bits / 64 bits per long
        var targetVec = Vector256.Create(target);
        int i = 0;

        unsafe
        {
            fixed (long* ptr = column)
            {
                for (; i <= column.Length - vLen; i += vLen)
                {
                    var v = Avx.LoadVector256(ptr + i);
                    var cmp = Avx2.CompareEqual(v, targetVec);

                    // MoveMask on double reinterpretation gives 1 bit per 64-bit lane
                    int mask = Avx.MoveMask(cmp.AsDouble());
                    while (mask != 0)
                    {
                        int bit = BitOperations.TrailingZeroCount((uint)mask);
                        results.Add(i + bit);
                        mask &= mask - 1;
                    }
                }
            }
        }

        for (; i < column.Length; i++)
        {
            if (column[i] == target)
                results.Add(i);
        }

        return results;
    }

    // ── CPU capability probe ─────────────────────────────────────────────

    /// <summary>
    /// Logs detected SIMD capabilities to <paramref name="output"/>.
    /// Call once at startup to record the execution environment.
    /// </summary>
    public static void LogCapabilities(Action<string> output)
    {
        output($"Vector<int>.Count  = {Vector<int>.Count} lanes ({Vector<int>.Count * 32}-bit)");
        output($"Vector128 supported: {Vector128.IsHardwareAccelerated}");
        output($"Vector256 supported: {Vector256.IsHardwareAccelerated}");
        output($"Avx   supported: {(Avx.IsSupported   ? "YES" : "no")}");
        output($"Avx2  supported: {(Avx2.IsSupported  ? "YES" : "no")}");
        output($"Sse4.2 supported: {(Sse42.IsSupported ? "YES" : "no")}");
    }
}
