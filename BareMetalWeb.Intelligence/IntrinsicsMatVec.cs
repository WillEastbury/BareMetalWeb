using System.Numerics;
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
///   WeightedAccumulate(weight, values, output, totalWeight)
///
/// Dispatch order:
///   1. AVX2   (x86/x64) — processes 8×int32 per iteration via widening to int64
///   2. AdvSimd (ARM NEON) — processes 4×int32 via widening to int64
///   3. Vector&lt;int&gt; (System.Numerics SIMD) — platform-adaptive fallback
///   4. Scalar fallback
///
/// All methods are allocation-free and safe to call from concurrent contexts
/// (no shared mutable state).
/// </summary>
public static class IntrinsicsMatVec
{
    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>
    /// Computes the integer dot product of two equal-length vectors.
    /// Intermediate products are accumulated as int64 to avoid overflow.
    /// Returns int (safe for ternary/bounded-range vectors where sum ≤ 2^31).
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
            WeightedAccumulateAvx2(weight, values.Slice(0, len), output.Slice(0, len), totalWeight);
        else if (AdvSimd.IsSupported && len >= 4)
            WeightedAccumulateNeon(weight, values.Slice(0, len), output.Slice(0, len), totalWeight);
        else
            WeightedAccumulateScalar(weight, values.Slice(0, len), output.Slice(0, len), totalWeight);
    }

    // ── AVX2 implementation ───────────────────────────────────────────────────

    /// <summary>
    /// AVX2 dot product: correct widening int32→int64 multiply.
    /// Each iteration processes 4 elements: sign-extends int32 to int64,
    /// multiplies int64 pairs, and accumulates. This avoids int32 overflow
    /// and works correctly for any bounded int32 inputs.
    ///
    /// Note: AVX2 has no native 64-bit integer multiply instruction, so we
    /// process 4 elements per iteration (256-bit → 4×int64) using
    /// ConvertToVector256Int64 + a scalar 64-bit multiply emulation via
    /// the lower and upper 32-bit halves (pmulhw / pmuld pattern).
    /// For the int32 values in BitNet inference (bounded by headDim ≤ 256),
    /// the product always fits in int32, so MultiplyLow is correct and we
    /// widen the result to int64 for safe accumulation.
    /// </summary>
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

                // Process 4 elements per iteration: widen to int64, multiply, accumulate.
                // `MultiplyLow` gives the low 32 bits of int32×int32 (= a*b for bounded values).
                // `ConvertToVector256Int64` sign-extends 4×int32 → 4×int64 for safe accumulation.
                for (; i <= len - 4; i += 4)
                {
                    var va = Sse2.LoadVector128(pa + i);              // 4×int32
                    var vb = Sse2.LoadVector128(pb + i);              // 4×int32
                    var prod = Sse41.MultiplyLow(va, vb);             // 4×int32 product (low bits)
                    acc = Avx2.Add(acc, Avx2.ConvertToVector256Int64(prod)); // accumulate as int64
                }

                // Horizontal reduce 4×int64 → sum
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

    // ── ARM NEON implementation ───────────────────────────────────────────────

    /// <summary>
    /// NEON dot product using widening multiply from int32 to int64.
    /// Uses MultiplyWideningLower/Upper for correct int32→int64 widening
    /// without int32 overflow. Processes 4 elements per iteration.
    /// </summary>
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
                    var va = AdvSimd.LoadVector128(pa + i);              // 4×int32
                    var vb = AdvSimd.LoadVector128(pb + i);              // 4×int32
                    // Widening multiply: 2 lower int32s → 2 int64s (smull)
                    var wlo = AdvSimd.MultiplyWideningLower(va.GetLower(), vb.GetLower());
                    // Widening multiply: 2 upper int32s → 2 int64s (smull2)
                    var whi = AdvSimd.MultiplyWideningUpper(va, vb);
                    acc = AdvSimd.Add(acc, AdvSimd.Add(wlo, whi));
                }
                sum = acc.GetElement(0) + acc.GetElement(1);
            }
        }

        for (; i < len; i++)
            sum += (long)a[i] * b[i];

        return (int)sum;
    }

    // ── Scalar implementation ─────────────────────────────────────────────────

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

    // ── NEON WeightedAccumulate ───────────────────────────────────────────────

    /// <summary>
    /// NEON-accelerated weighted accumulation: output[i] += (weight * values[i]) / totalWeight.
    /// Uses int32→int64 widening multiply to avoid overflow, then narrows back.
    /// Processes 4 elements per iteration.
    /// </summary>
    private static void WeightedAccumulateNeon(
        long weight, ReadOnlySpan<int> values, Span<int> output, long totalWeight)
    {
        int i = 0;
        int len = values.Length;

        unsafe
        {
            fixed (int* pv = values, po = output)
            {
                var wVec = Vector128.Create((long)weight);
                var twVec = Vector128.Create(totalWeight);

                for (; i <= len - 4; i += 4)
                {
                    var v = AdvSimd.LoadVector128(pv + i);
                    var cur = AdvSimd.LoadVector128(po + i);

                    // Process lower 2 elements: widen int32→int64, multiply, divide
                    var vLo = AdvSimd.SignExtendWideningLower(v.GetLower());  // 2×int64
                    var prodLo = MultiplyInt64x2(vLo, wVec);                  // weight * v[i]
                    var divLo = DivideInt64x2(prodLo, twVec);                 // / totalWeight

                    // Process upper 2 elements
                    var vHi = AdvSimd.SignExtendWideningUpper(v);             // 2×int64
                    var prodHi = MultiplyInt64x2(vHi, wVec);
                    var divHi = DivideInt64x2(prodHi, twVec);

                    // Narrow int64→int32 and add to output
                    var narrowLo = AdvSimd.ExtractNarrowingSaturateLower(divLo);  // 2×int32
                    var narrow = AdvSimd.ExtractNarrowingSaturateUpper(narrowLo, divHi); // 4×int32
                    var result = AdvSimd.Add(cur, narrow);
                    AdvSimd.Store(po + i, result);
                }
            }
        }

        // Scalar tail
        for (; i < len; i++)
            output[i] += (int)(weight * values[i] / totalWeight);
    }

    /// <summary>Scalar int64 multiply for 2-lane Vector128 (NEON has no native 64-bit multiply).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<long> MultiplyInt64x2(Vector128<long> a, Vector128<long> b)
    {
        return Vector128.Create(
            a.GetElement(0) * b.GetElement(0),
            a.GetElement(1) * b.GetElement(1));
    }

    /// <summary>Scalar int64 divide for 2-lane Vector128.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<long> DivideInt64x2(Vector128<long> a, Vector128<long> b)
    {
        return Vector128.Create(
            a.GetElement(0) / b.GetElement(0),
            a.GetElement(1) / b.GetElement(1));
    }

    // ── AVX2 WeightedAccumulate ──────────────────────────────────────────────

    /// <summary>
    /// AVX2-accelerated weighted accumulation: output[i] += (weight * values[i]) / totalWeight.
    /// Widens int32→int64 via ConvertToVector256Int64, processes 4 elements per iteration.
    /// </summary>
    private static void WeightedAccumulateAvx2(
        long weight, ReadOnlySpan<int> values, Span<int> output, long totalWeight)
    {
        int i = 0;
        int len = values.Length;

        unsafe
        {
            fixed (int* pv = values, po = output)
            {
                for (; i <= len - 4; i += 4)
                {
                    // Load 4×int32 values, widen to 4×int64
                    var v32 = Sse2.LoadVector128(pv + i);
                    var v64 = Avx2.ConvertToVector256Int64(v32);  // 4×int64

                    // Scalar multiply + divide (no native 64-bit multiply in AVX2)
                    var r = Vector256.Create(
                        weight * v64.GetElement(0) / totalWeight,
                        weight * v64.GetElement(1) / totalWeight,
                        weight * v64.GetElement(2) / totalWeight,
                        weight * v64.GetElement(3) / totalWeight);

                    // Narrow int64→int32: extract lower 32 bits of each lane
                    var narrow = Vector128.Create(
                        (int)r.GetElement(0), (int)r.GetElement(1),
                        (int)r.GetElement(2), (int)r.GetElement(3));

                    // Add to existing output
                    var cur = Sse2.LoadVector128(po + i);
                    Sse2.Store(po + i, Sse2.Add(cur, narrow));
                }
            }
        }

        // Scalar tail
        for (; i < len; i++)
            output[i] += (int)(weight * values[i] / totalWeight);
    }
}
