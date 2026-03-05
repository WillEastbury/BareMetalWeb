using System.Numerics;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace BareMetalWeb.Benchmarks.Simd;

/// <summary>
/// SIMD-accelerated column copy / serialization operations.
///
/// Copies typed column arrays (int[], long[], byte[]) using three layers:
///   1. <see cref="CopyScalar{T}"/>  – plain loop (baseline).
///   2. <see cref="CopyVector{T}"/>  – portable <see cref="Vector{T}"/>.
///   3. <see cref="CopyAvx2"/>       – AVX2 hardware intrinsics for int and long.
///
/// Goal: approach the memory bandwidth ceiling (~50 GB/s on modern DDR5).
///
/// <b>Usage pattern</b>: operate on contiguous typed arrays (never <c>object[]</c>
/// or <c>List&lt;T&gt;</c>) to ensure SIMD-friendly memory layout.
/// </summary>
public static class ColumnCopy
{
    // ── Generic scalar baseline ──────────────────────────────────────────

    /// <summary>
    /// Scalar element-by-element copy. Serves as the timing baseline.
    /// </summary>
    public static void CopyScalar<T>(T[] source, T[] destination)
        where T : struct
    {
        int len = Math.Min(source.Length, destination.Length);
        for (int i = 0; i < len; i++)
            destination[i] = source[i];
    }

    // ── Portable SIMD – System.Numerics.Vector<T> ────────────────────────

    /// <summary>
    /// Portable SIMD copy using <see cref="Vector{T}"/>.
    /// Copies <see cref="Vector{T}.Count"/> elements per instruction.
    /// </summary>
    public static void CopyVector<T>(T[] source, T[] destination)
        where T : unmanaged
    {
        int len = Math.Min(source.Length, destination.Length);
        int vLen = Vector<T>.Count;
        int i = 0;

        for (; i <= len - vLen; i += vLen)
        {
            var v = new Vector<T>(source, i);
            v.CopyTo(destination, i);
        }

        // Scalar remainder
        for (; i < len; i++)
            destination[i] = source[i];
    }

    // ── AVX2 hardware intrinsics – int[] ────────────────────────────────

    /// <summary>
    /// AVX2 copy for <c>int[]</c> arrays: loads and stores 32 bytes (8 ints)
    /// per instruction. Falls back to <see cref="CopyVector{T}"/> when AVX2
    /// is unavailable.
    /// </summary>
    public static void CopyAvx2(int[] source, int[] destination)
    {
        if (!Avx2.IsSupported)
        {
            CopyVector<int>(source, destination);
            return;
        }

        int len = Math.Min(source.Length, destination.Length);
        const int vLen = 8;
        int i = 0;

        unsafe
        {
            fixed (int* src = source)
            fixed (int* dst = destination)
            {
                for (; i <= len - vLen; i += vLen)
                    Avx.Store(dst + i, Avx.LoadVector256(src + i));
            }
        }

        for (; i < len; i++)
            destination[i] = source[i];
    }

    // ── AVX2 hardware intrinsics – long[] ───────────────────────────────

    /// <summary>
    /// AVX2 copy for <c>long[]</c> arrays: loads and stores 32 bytes (4 longs)
    /// per instruction.
    /// </summary>
    public static void CopyAvx2(long[] source, long[] destination)
    {
        if (!Avx2.IsSupported)
        {
            CopyVector<long>(source, destination);
            return;
        }

        int len = Math.Min(source.Length, destination.Length);
        const int vLen = 4;
        int i = 0;

        unsafe
        {
            fixed (long* src = source)
            fixed (long* dst = destination)
            {
                for (; i <= len - vLen; i += vLen)
                    Avx.Store(dst + i, Avx.LoadVector256(src + i));
            }
        }

        for (; i < len; i++)
            destination[i] = source[i];
    }

    // ── AVX2 hardware intrinsics – byte[] ───────────────────────────────

    /// <summary>
    /// AVX2 copy for <c>byte[]</c> arrays: loads and stores 32 bytes per instruction.
    /// This is the most bandwidth-efficient variant; 32 bytes per VMOVDQA instruction.
    /// </summary>
    public static void CopyAvx2(byte[] source, byte[] destination)
    {
        if (!Avx2.IsSupported)
        {
            CopyVector<byte>(source, destination);
            return;
        }

        int len = Math.Min(source.Length, destination.Length);
        const int vLen = 32; // 256 bits = 32 bytes
        int i = 0;

        unsafe
        {
            fixed (byte* src = source)
            fixed (byte* dst = destination)
            {
                for (; i <= len - vLen; i += vLen)
                    Avx.Store(dst + i, Avx.LoadVector256(src + i));
            }
        }

        for (; i < len; i++)
            destination[i] = source[i];
    }

    // ── Span<T> overloads (zero-allocation callers) ───────────────────────

    /// <summary>
    /// AVX2 copy via <see cref="Span{T}"/> for zero-allocation call sites.
    /// Internally pins the spans and delegates to the array path.
    /// </summary>
    public static void CopyAvx2(Span<int> source, Span<int> destination)
    {
        if (!Avx2.IsSupported)
        {
            // Fallback: portable SIMD over spans
            int len = Math.Min(source.Length, destination.Length);
            int vLen = Vector<int>.Count;
            int i = 0;

            for (; i <= len - vLen; i += vLen)
            {
                var v = new Vector<int>(source.Slice(i, vLen));
                v.CopyTo(destination.Slice(i, vLen));
            }
            for (; i < len; i++)
                destination[i] = source[i];
            return;
        }

        int length = Math.Min(source.Length, destination.Length);
        const int vLen32 = 8;
        int idx = 0;

        unsafe
        {
            fixed (int* src = source)
            fixed (int* dst = destination)
            {
                for (; idx <= length - vLen32; idx += vLen32)
                    Avx.Store(dst + idx, Avx.LoadVector256(src + idx));
            }
        }

        for (; idx < length; idx++)
            destination[idx] = source[idx];
    }
}
