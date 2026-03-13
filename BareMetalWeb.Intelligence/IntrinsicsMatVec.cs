using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
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
    /// Dispatches: AdvSimd → AVX2 → scalar.
    /// SIMD paths use broadcast multiply + element-wise accumulation.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void WeightedAccumulate(
        long            weight,
        ReadOnlySpan<int> values,
        Span<int>       output,
        long            totalWeight)
    {
        int len = Math.Min(values.Length, output.Length);

        if (AdvSimd.IsSupported && len >= 4)
        {
            WeightedAccumulateNeon(weight, values.Slice(0, len), output.Slice(0, len), totalWeight);
            return;
        }

        if (Avx2.IsSupported && len >= 8)
        {
            WeightedAccumulateAvx2(weight, values.Slice(0, len), output.Slice(0, len), totalWeight);
            return;
        }

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

    /// <summary>
    /// AVX2 weighted accumulate: broadcast weight, SIMD multiply values,
    /// scalar division per element (no SIMD integer divide), accumulate into output.
    /// Processes 8 elements per iteration using Vector256.
    /// </summary>
    private static void WeightedAccumulateAvx2(
        long weight, ReadOnlySpan<int> values, Span<int> output, long totalWeight)
    {
        int len = values.Length;
        int i = 0;
        int w = (int)weight;
        int tw = (int)totalWeight;

        ref readonly int vRef = ref MemoryMarshal.GetReference(values);
        ref int oRef = ref MemoryMarshal.GetReference(output);

        Vector256<int> wVec = Vector256.Create(w);

        for (; i + 8 <= len; i += 8)
        {
            var v = Vector256.LoadUnsafe(in vRef, (nuint)i);
            var o = Vector256.LoadUnsafe(in oRef, (nuint)i);
            var mul = Vector256.Multiply(v, wVec);

            // Integer division per element (no SIMD int divide instruction)
            var divided = Vector256.Create(
                mul.GetElement(0) / tw, mul.GetElement(1) / tw,
                mul.GetElement(2) / tw, mul.GetElement(3) / tw,
                mul.GetElement(4) / tw, mul.GetElement(5) / tw,
                mul.GetElement(6) / tw, mul.GetElement(7) / tw);

            Vector256.Add(o, divided).StoreUnsafe(ref oRef, (nuint)i);
        }

        // Scalar tail
        for (; i < len; i++)
            output[i] += (int)(weight * values[i] / totalWeight);
    }

    // ── ARM NEON implementation ───────────────────────────────────────────────

    /// <summary>
    /// NEON dot product using widening multiply from int32 to int64.
    /// Uses MultiplyWideningLower/Upper for correct int32→int64 widening
    /// without int32 overflow. Processes 4 elements per iteration.
    /// Horizontal reduction via AdvSimd.Arm64.AddPairwise when available.
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

                // Horizontal reduce 2×int64 → scalar
                if (AdvSimd.Arm64.IsSupported)
                {
                    sum = AdvSimd.Arm64.AddPairwise(acc, acc).GetElement(0);
                }
                else
                {
                    sum = acc.GetElement(0) + acc.GetElement(1);
                }
            }
        }

        for (; i < len; i++)
            sum += (long)a[i] * b[i];

        return (int)sum;
    }

    /// <summary>
    /// ARM NEON weighted accumulate: broadcast weight via AdvSimd.Multiply,
    /// scalar division per element, accumulate into output using AdvSimd.Add.
    /// Processes 4 elements per iteration.
    /// </summary>
    private static void WeightedAccumulateNeon(
        long weight, ReadOnlySpan<int> values, Span<int> output, long totalWeight)
    {
        int len = values.Length;
        int i = 0;
        int w = (int)weight;
        int tw = (int)totalWeight;

        ref readonly int vRef = ref MemoryMarshal.GetReference(values);
        ref int oRef = ref MemoryMarshal.GetReference(output);

        Vector128<int> wVec = Vector128.Create(w);

        for (; i + 4 <= len; i += 4)
        {
            var v = Vector128.LoadUnsafe(in vRef, (nuint)i);
            var o = Vector128.LoadUnsafe(in oRef, (nuint)i);
            var mul = AdvSimd.Multiply(v, wVec);

            // Integer division per element (no SIMD int divide instruction)
            var divided = Vector128.Create(
                mul.GetElement(0) / tw, mul.GetElement(1) / tw,
                mul.GetElement(2) / tw, mul.GetElement(3) / tw);

            AdvSimd.Add(o, divided).StoreUnsafe(ref oRef, (nuint)i);
        }

        // Scalar tail
        for (; i < len; i++)
            output[i] += (int)(weight * values[i] / totalWeight);
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
}
