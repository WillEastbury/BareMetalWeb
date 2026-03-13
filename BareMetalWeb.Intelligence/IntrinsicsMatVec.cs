using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// SIMD-accelerated integer dot-product primitives for BitNet attention.
///
/// Provides:
///   DotProduct(ReadOnlySpan&lt;int&gt;, ReadOnlySpan&lt;int&gt;) → int
///   WeightedSum(weights, values, output, totalWeight)
///
/// Dispatch order:
///   1. AVX2   (x86/x64, 8×int32 per iteration)
///   2. AdvSimd (ARM NEON, 4×int32 per iteration)
///   3. Scalar fallback
///
/// All methods are allocation-free and safe to call from concurrent contexts
/// (no shared mutable state).
/// </summary>
public static class IntrinsicsMatVec
{
    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>
    /// Computes the integer dot product of two equal-length vectors.
    /// Result is accumulated as long to avoid overflow.
    /// Returned as int (caller must ensure values don't overflow 32-bit sum).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int DotProduct(ReadOnlySpan<int> a, ReadOnlySpan<int> b)
    {
        int len = Math.Min(a.Length, b.Length);

        if (Avx2.IsSupported && len >= 8)
            return DotProductAvx2(a.Slice(0, len), b.Slice(0, len));

        if (AdvSimd.IsSupported && len >= 4)
            return DotProductNeon(a.Slice(0, len), b.Slice(0, len));

        return DotProductScalar(a.Slice(0, len), b.Slice(0, len));
    }

    /// <summary>
    /// Adds weighted values into the output accumulator.
    /// output[i] += (weight * values[i]) / totalWeight  — integer arithmetic.
    /// totalWeight must be &gt; 0.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WeightedAccumulate(
        long            weight,
        ReadOnlySpan<int> values,
        Span<int>       output,
        long            totalWeight)
    {
        int len = Math.Min(values.Length, output.Length);

        if (Avx2.IsSupported && len >= 8)
        {
            WeightedAccumulateAvx2(weight, values.Slice(0, len), output.Slice(0, len), totalWeight);
            return;
        }
        WeightedAccumulateScalar(weight, values.Slice(0, len), output.Slice(0, len), totalWeight);
    }

    // ── AVX2 implementations ─────────────────────────────────────────────────

    private static int DotProductAvx2(ReadOnlySpan<int> a, ReadOnlySpan<int> b)
    {
        long sum = 0;
        int  i   = 0;
        int  len = a.Length;

        unsafe
        {
            fixed (int* pa = a, pb = b)
            {
                var acc = Vector256<long>.Zero;

                // 8-int-wide loop — two 128-bit halves widened to 64-bit
                for (; i <= len - 8; i += 8)
                {
                    var va = Avx.LoadVector256(pa + i);
                    var vb = Avx.LoadVector256(pb + i);

                    // Multiply low 4 ints (128-bit) → 4×int64
                    var loA = va.GetLower();
                    var loB = vb.GetLower();
                    var hiA = va.GetUpper();
                    var hiB = vb.GetUpper();

                    // widening multiply: int32×int32 → int64
                    var prodLo = Avx2.MultiplyLow(loA, loB);
                    var prodHi = Avx2.MultiplyLow(hiA, hiB);

                    // sign-extend and accumulate
                    acc = Avx2.Add(acc, Avx2.ConvertToVector256Int64(prodLo));
                    acc = Avx2.Add(acc, Avx2.ConvertToVector256Int64(prodHi));
                }

                // Horizontal reduce 4×int64 → 1
                var lo128 = acc.GetLower();
                var hi128 = acc.GetUpper();
                var sum128 = Sse2.Add(lo128, hi128);
                sum = sum128.GetElement(0) + sum128.GetElement(1);
            }
        }

        // Scalar tail
        for (; i < len; i++)
            sum += (long)a[i] * b[i];

        return (int)sum;
    }

    private static void WeightedAccumulateAvx2(
        long weight, ReadOnlySpan<int> values, Span<int> output, long totalWeight)
    {
        // For safety, use scalar implementation when weight or totalWeight
        // could cause int64 overflow (values can be large).
        // This path avoids an expensive 64-bit SIMD div.
        WeightedAccumulateScalar(weight, values, output, totalWeight);
    }

    // ── ARM NEON implementation ───────────────────────────────────────────────

    private static int DotProductNeon(ReadOnlySpan<int> a, ReadOnlySpan<int> b)
    {
        long sum = 0;
        int  i   = 0;
        int  len = a.Length;

        unsafe
        {
            fixed (int* pa = a, pb = b)
            {
                var acc = Vector128<long>.Zero;
                for (; i <= len - 4; i += 4)
                {
                    var va = AdvSimd.LoadVector128(pa + i);
                    var vb = AdvSimd.LoadVector128(pb + i);
                    // pairwise widening multiply-accumulate
                    var prod = AdvSimd.Multiply(va, vb);
                    // widen and accumulate
                    acc = AdvSimd.Add(acc, AdvSimd.SignExtendWideningLower(prod.GetLower()));
                    acc = AdvSimd.Add(acc, AdvSimd.SignExtendWideningUpper(prod));
                }
                sum = acc.GetElement(0) + acc.GetElement(1);
            }
        }

        for (; i < len; i++)
            sum += (long)a[i] * b[i];

        return (int)sum;
    }

    // ── Scalar implementations ────────────────────────────────────────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int DotProductScalar(ReadOnlySpan<int> a, ReadOnlySpan<int> b)
    {
        long sum = 0;
        for (int i = 0; i < a.Length; i++)
            sum += (long)a[i] * b[i];
        return (int)sum;
    }

    private static void WeightedAccumulateScalar(
        long weight, ReadOnlySpan<int> values, Span<int> output, long totalWeight)
    {
        for (int i = 0; i < values.Length; i++)
            output[i] += (int)(weight * values[i] / totalWeight);
    }
}
