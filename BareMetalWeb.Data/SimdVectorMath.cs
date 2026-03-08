using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace BareMetalWeb.Data;

/// <summary>
/// SIMD-accelerated floating-point vector math primitives used by the ANN vector index.
/// Dispatch order (highest performance first):
///   x86-64:  AVX2 + FMA  →  AVX2  →  portable Vector&lt;float&gt;
///   ARM64:   AdvSimd (NEON)  →  portable Vector&lt;float&gt;
/// All paths give numerically equivalent results (within normal IEEE-754 float rounding).
/// </summary>
internal static class SimdVectorMath
{
    // Width used by the portable System.Numerics path:
    //   8 floats on AVX2, 4 floats on SSE2/NEON, 1 float when no SIMD is present.
    private static readonly int PortableVectorWidth = Vector<float>.Count;

    // ─── Public API ───────────────────────────────────────────────────────────

    /// <summary>Returns the dot product a·b.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static float DotProduct(ReadOnlySpan<float> a, ReadOnlySpan<float> b)
    {
        if (Fma.IsSupported && Avx.IsSupported)
            return DotProductFmaAvx(a, b);
        if (Avx2.IsSupported)
            return DotProductAvx2(a, b);
        if (AdvSimd.IsSupported)
            return DotProductAdvSimd(a, b);
        return DotProductPortable(a, b);
    }

    /// <summary>Returns ‖a‖² (sum of squares).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static float SumOfSquares(ReadOnlySpan<float> a) => DotProduct(a, a);

    /// <summary>Returns the squared Euclidean distance ‖a − b‖².</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static float EuclideanDistanceSquared(ReadOnlySpan<float> a, ReadOnlySpan<float> b)
    {
        if (Fma.IsSupported && Avx.IsSupported)
            return EuclideanSqFmaAvx(a, b);
        if (Avx2.IsSupported)
            return EuclideanSqAvx2(a, b);
        if (AdvSimd.IsSupported)
            return EuclideanSqAdvSimd(a, b);
        return EuclideanSqPortable(a, b);
    }

    /// <summary>
    /// Returns the cosine distance 1 − (a·b / (‖a‖·‖b‖)).
    /// Returns 1 when either vector is zero.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static float CosineDistance(ReadOnlySpan<float> a, ReadOnlySpan<float> b)
    {
        float dot   = DotProduct(a, b);
        float normA = DotProduct(a, a);
        float normB = DotProduct(b, b);
        if (MathF.Abs(normA) < 1e-7f || MathF.Abs(normB) < 1e-7f) return 1f;
        return 1f - dot / MathF.Sqrt(normA * normB);
    }

    // ─── Portable SIMD (System.Numerics.Vector<float>) ───────────────────────
    // JIT selects the widest register width available at compile time.

    private static float DotProductPortable(ReadOnlySpan<float> a, ReadOnlySpan<float> b)
    {
        int w   = PortableVectorWidth;
        int len = (a.Length / w) * w;
        var acc = Vector<float>.Zero;

        for (int i = 0; i < len; i += w)
            acc += new Vector<float>(a.Slice(i)) * new Vector<float>(b.Slice(i));

        float sum = Vector.Dot(acc, Vector<float>.One);
        for (int i = len; i < a.Length; i++)
            sum += a[i] * b[i];
        return sum;
    }

    private static float EuclideanSqPortable(ReadOnlySpan<float> a, ReadOnlySpan<float> b)
    {
        int w   = PortableVectorWidth;
        int len = (a.Length / w) * w;
        var acc = Vector<float>.Zero;

        for (int i = 0; i < len; i += w)
        {
            var diff = new Vector<float>(a.Slice(i)) - new Vector<float>(b.Slice(i));
            acc += diff * diff;
        }

        float sum = Vector.Dot(acc, Vector<float>.One);
        for (int i = len; i < a.Length; i++)
        {
            float d = a[i] - b[i];
            sum += d * d;
        }
        return sum;
    }

    // ─── x86 AVX2 + FMA paths ────────────────────────────────────────────────
    // FMA processes 8 floats per cycle with fused multiply-add (no intermediate rounding).

    private static float DotProductFmaAvx(ReadOnlySpan<float> a, ReadOnlySpan<float> b)
    {
        var aV  = MemoryMarshal.Cast<float, Vector256<float>>(a);
        var bV  = MemoryMarshal.Cast<float, Vector256<float>>(b);
        var acc = Vector256<float>.Zero;

        for (int k = 0; k < aV.Length; k++)
            acc = Fma.MultiplyAdd(aV[k], bV[k], acc);

        float sum = HorizontalSum256(acc);
        for (int i = aV.Length * 8; i < a.Length; i++)
            sum += a[i] * b[i];
        return sum;
    }

    private static float EuclideanSqFmaAvx(ReadOnlySpan<float> a, ReadOnlySpan<float> b)
    {
        var aV  = MemoryMarshal.Cast<float, Vector256<float>>(a);
        var bV  = MemoryMarshal.Cast<float, Vector256<float>>(b);
        var acc = Vector256<float>.Zero;

        for (int k = 0; k < aV.Length; k++)
        {
            var diff = Avx.Subtract(aV[k], bV[k]);
            acc = Fma.MultiplyAdd(diff, diff, acc);
        }

        float sum = HorizontalSum256(acc);
        for (int i = aV.Length * 8; i < a.Length; i++)
        {
            float d = a[i] - b[i];
            sum += d * d;
        }
        return sum;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float HorizontalSum256(Vector256<float> v)
    {
        // Fold 256→128: add the upper 128 bits into the lower 128 bits
        var lo   = v.GetLower();
        var hi   = v.GetUpper();
        var sum4 = Sse.Add(lo, hi);
        return HorizontalSum128(sum4);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float HorizontalSum128(Vector128<float> v)
    {
        // [a,b,c,d] → [c,d,a,b] then add → [a+c, b+d, c+a, d+b]
        // Shuffle to [b+d, ...] then add scalar → a+b+c+d
        var shuf1 = Sse.Shuffle(v, v, 0b_0100_1110);  // swap pairs of 64-bit halves
        var sum2  = Sse.Add(v, shuf1);
        var shuf2 = Sse.Shuffle(sum2, sum2, 0b_0001_0001); // move element 1 to position 0
        return Sse.AddScalar(sum2, shuf2).ToScalar();
    }

    // ─── x86 AVX2 paths (no FMA) ─────────────────────────────────────────────
    // AVX2 processes 8 floats per cycle using separate multiply + add.

    private static float DotProductAvx2(ReadOnlySpan<float> a, ReadOnlySpan<float> b)
    {
        var aV  = MemoryMarshal.Cast<float, Vector256<float>>(a);
        var bV  = MemoryMarshal.Cast<float, Vector256<float>>(b);
        var acc = Vector256<float>.Zero;

        for (int k = 0; k < aV.Length; k++)
            acc = Avx.Add(Avx.Multiply(aV[k], bV[k]), acc);

        float sum = HorizontalSum256(acc);
        for (int i = aV.Length * 8; i < a.Length; i++)
            sum += a[i] * b[i];
        return sum;
    }

    private static float EuclideanSqAvx2(ReadOnlySpan<float> a, ReadOnlySpan<float> b)
    {
        var aV  = MemoryMarshal.Cast<float, Vector256<float>>(a);
        var bV  = MemoryMarshal.Cast<float, Vector256<float>>(b);
        var acc = Vector256<float>.Zero;

        for (int k = 0; k < aV.Length; k++)
        {
            var diff = Avx.Subtract(aV[k], bV[k]);
            acc = Avx.Add(Avx.Multiply(diff, diff), acc);
        }

        float sum = HorizontalSum256(acc);
        for (int i = aV.Length * 8; i < a.Length; i++)
        {
            float d = a[i] - b[i];
            sum += d * d;
        }
        return sum;
    }

    // ─── ARM AdvSimd (NEON) paths ─────────────────────────────────────────────
    // AdvSimd processes 4 floats per cycle using 128-bit NEON registers.

    private static float DotProductAdvSimd(ReadOnlySpan<float> a, ReadOnlySpan<float> b)
    {
        var aV  = MemoryMarshal.Cast<float, Vector128<float>>(a);
        var bV  = MemoryMarshal.Cast<float, Vector128<float>>(b);
        var acc = Vector128<float>.Zero;

        for (int k = 0; k < aV.Length; k++)
            acc = AdvSimd.FusedMultiplyAdd(acc, aV[k], bV[k]);

        float sum = acc.GetElement(0) + acc.GetElement(1)
                  + acc.GetElement(2) + acc.GetElement(3);
        for (int i = aV.Length * 4; i < a.Length; i++)
            sum += a[i] * b[i];
        return sum;
    }

    private static float EuclideanSqAdvSimd(ReadOnlySpan<float> a, ReadOnlySpan<float> b)
    {
        var aV  = MemoryMarshal.Cast<float, Vector128<float>>(a);
        var bV  = MemoryMarshal.Cast<float, Vector128<float>>(b);
        var acc = Vector128<float>.Zero;

        for (int k = 0; k < aV.Length; k++)
        {
            var diff = AdvSimd.Subtract(aV[k], bV[k]);
            acc = AdvSimd.FusedMultiplyAdd(acc, diff, diff);
        }

        float sum = acc.GetElement(0) + acc.GetElement(1)
                  + acc.GetElement(2) + acc.GetElement(3);
        for (int i = aV.Length * 4; i < a.Length; i++)
        {
            float d = a[i] - b[i];
            sum += d * d;
        }
        return sum;
    }
}
