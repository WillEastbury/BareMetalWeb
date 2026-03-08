using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace BareMetalWeb.Data;

/// <summary>
/// SIMD-accelerated vector distance calculations.
/// Dispatches to the best available hardware path at runtime:
/// <list type="bullet">
///   <item>x86 AVX-512F: 16 floats/cycle with FMA</item>
///   <item>x86 AVX2 + FMA: 8 floats/cycle with fused multiply-add</item>
///   <item>x86 AVX2: 8 floats/cycle (multiply + add)</item>
///   <item>ARM64 AdvSimd: 4 floats/cycle with NEON FMA</item>
///   <item>Fallback: <see cref="Vector{T}"/> (auto-vectorised by the JIT)</item>
/// </list>
/// </summary>
internal static class SimdDistance
{
    /// <summary>Returns 1 − cos(θ) so 0 = identical, 2 = opposite.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static float Cosine(float[] a, float[] b)
    {
        System.Diagnostics.Debug.Assert(a.Length == b.Length,
            "SimdDistance: both vectors must have the same dimension.");
        if (Avx512F.IsSupported)   return CosineAvx512(a, b);
        if (Fma.IsSupported)       return CosineAvx2Fma(a, b);
        if (Avx2.IsSupported)      return CosineAvx2(a, b);
        if (AdvSimd.IsSupported)   return CosineNeon(a, b);
        return CosineVector(a, b);
    }

    /// <summary>Negated dot product so smaller = more similar.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static float DotProduct(float[] a, float[] b)
    {
        System.Diagnostics.Debug.Assert(a.Length == b.Length,
            "SimdDistance: both vectors must have the same dimension.");
        if (Avx512F.IsSupported)   return DotProductAvx512(a, b);
        if (Fma.IsSupported)       return DotProductAvx2Fma(a, b);
        if (Avx2.IsSupported)      return DotProductAvx2(a, b);
        if (AdvSimd.IsSupported)   return DotProductNeon(a, b);
        return DotProductVector(a, b);
    }

    /// <summary>L2 (Euclidean) distance.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static float Euclidean(float[] a, float[] b)
    {
        System.Diagnostics.Debug.Assert(a.Length == b.Length,
            "SimdDistance: both vectors must have the same dimension.");
        if (Avx512F.IsSupported)   return EuclideanAvx512(a, b);
        if (Fma.IsSupported)       return EuclideanAvx2Fma(a, b);
        if (Avx2.IsSupported)      return EuclideanAvx2(a, b);
        if (AdvSimd.IsSupported)   return EuclideanNeon(a, b);
        return EuclideanVector(a, b);
    }

    /// <summary>Dispatches to the appropriate distance function.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static float Compute(DistanceMetric metric, float[] a, float[] b)
    {
        return metric switch
        {
            DistanceMetric.Cosine      => Cosine(a, b),
            DistanceMetric.DotProduct  => DotProduct(a, b),
            DistanceMetric.Euclidean   => Euclidean(a, b),
            _                          => Cosine(a, b)
        };
    }

    /// <summary>
    /// Returns a human-readable description of the acceleration path that will
    /// be selected on this CPU for distance computations.
    /// </summary>
    public static string ActivePath
    {
        get
        {
            if (Avx512F.IsSupported) return "x86 AVX-512F (16 floats/iter, FMA)";
            if (Fma.IsSupported)     return "x86 AVX2 + FMA (8 floats/iter)";
            if (Avx2.IsSupported)    return "x86 AVX2 (8 floats/iter)";
            if (AdvSimd.IsSupported) return "ARM64 AdvSimd NEON (4 floats/iter, FMA)";
            return $"Vector<float> generic ({Vector<float>.Count} floats/iter)";
        }
    }

    // ── Generic fallback (System.Numerics.Vector<float>) ────────────────────

    private static float CosineVector(float[] a, float[] b)
    {
        int vecSize = Vector<float>.Count;
        int i = 0;

        var dotVec   = Vector<float>.Zero;
        var normAVec = Vector<float>.Zero;
        var normBVec = Vector<float>.Zero;

        for (; i <= a.Length - vecSize; i += vecSize)
        {
            var va = new Vector<float>(a, i);
            var vb = new Vector<float>(b, i);
            dotVec   += va * vb;
            normAVec += va * va;
            normBVec += vb * vb;
        }

        float dot   = Vector.Sum(dotVec);
        float normA = Vector.Sum(normAVec);
        float normB = Vector.Sum(normBVec);

        for (; i < a.Length; i++)
        {
            dot   += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }

        if (normA == 0 || normB == 0) return 1f;
        return 1f - dot / (MathF.Sqrt(normA) * MathF.Sqrt(normB));
    }

    private static float DotProductVector(float[] a, float[] b)
    {
        int vecSize = Vector<float>.Count;
        int i = 0;
        var dotVec = Vector<float>.Zero;

        for (; i <= a.Length - vecSize; i += vecSize)
        {
            var va = new Vector<float>(a, i);
            var vb = new Vector<float>(b, i);
            dotVec += va * vb;
        }

        float dot = Vector.Sum(dotVec);
        for (; i < a.Length; i++)
            dot += a[i] * b[i];

        return -dot;
    }

    private static float EuclideanVector(float[] a, float[] b)
    {
        int vecSize = Vector<float>.Count;
        int i = 0;
        var sumVec = Vector<float>.Zero;

        for (; i <= a.Length - vecSize; i += vecSize)
        {
            var diff = new Vector<float>(a, i) - new Vector<float>(b, i);
            sumVec += diff * diff;
        }

        float sum = Vector.Sum(sumVec);
        for (; i < a.Length; i++)
        {
            float d = a[i] - b[i];
            sum += d * d;
        }

        return MathF.Sqrt(sum);
    }

    // ── x86 AVX-512F + FMA (16 floats / iteration) ──────────────────────────

    private static float CosineAvx512(float[] a, float[] b)
    {
        int i = 0;
        var dotAcc   = Vector512<float>.Zero;
        var normAAcc = Vector512<float>.Zero;
        var normBAcc = Vector512<float>.Zero;

        for (; i <= a.Length - Vector512<float>.Count; i += Vector512<float>.Count)
        {
            var va = Vector512.LoadUnsafe(ref a[i]);
            var vb = Vector512.LoadUnsafe(ref b[i]);
            dotAcc   = Avx512F.FusedMultiplyAdd(va, vb, dotAcc);
            normAAcc = Avx512F.FusedMultiplyAdd(va, va, normAAcc);
            normBAcc = Avx512F.FusedMultiplyAdd(vb, vb, normBAcc);
        }

        float dot   = HSum512(dotAcc);
        float normA = HSum512(normAAcc);
        float normB = HSum512(normBAcc);

        for (; i < a.Length; i++)
        {
            dot   += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }

        if (normA == 0 || normB == 0) return 1f;
        return 1f - dot / (MathF.Sqrt(normA) * MathF.Sqrt(normB));
    }

    private static float DotProductAvx512(float[] a, float[] b)
    {
        int i = 0;
        var dotAcc = Vector512<float>.Zero;

        for (; i <= a.Length - Vector512<float>.Count; i += Vector512<float>.Count)
        {
            var va = Vector512.LoadUnsafe(ref a[i]);
            var vb = Vector512.LoadUnsafe(ref b[i]);
            dotAcc = Avx512F.FusedMultiplyAdd(va, vb, dotAcc);
        }

        float dot = HSum512(dotAcc);
        for (; i < a.Length; i++)
            dot += a[i] * b[i];

        return -dot;
    }

    private static float EuclideanAvx512(float[] a, float[] b)
    {
        int i = 0;
        var sumAcc = Vector512<float>.Zero;

        for (; i <= a.Length - Vector512<float>.Count; i += Vector512<float>.Count)
        {
            var diff = Vector512.LoadUnsafe(ref a[i]) - Vector512.LoadUnsafe(ref b[i]);
            sumAcc = Avx512F.FusedMultiplyAdd(diff, diff, sumAcc);
        }

        float sum = HSum512(sumAcc);
        for (; i < a.Length; i++)
        {
            float d = a[i] - b[i];
            sum += d * d;
        }

        return MathF.Sqrt(sum);
    }

    // ── x86 AVX2 + FMA (8 floats / iteration) ───────────────────────────────

    private static float CosineAvx2Fma(float[] a, float[] b)
    {
        int i = 0;
        var dotAcc   = Vector256<float>.Zero;
        var normAAcc = Vector256<float>.Zero;
        var normBAcc = Vector256<float>.Zero;

        for (; i <= a.Length - Vector256<float>.Count; i += Vector256<float>.Count)
        {
            var va = Vector256.LoadUnsafe(ref a[i]);
            var vb = Vector256.LoadUnsafe(ref b[i]);
            dotAcc   = Fma.MultiplyAdd(va, vb, dotAcc);
            normAAcc = Fma.MultiplyAdd(va, va, normAAcc);
            normBAcc = Fma.MultiplyAdd(vb, vb, normBAcc);
        }

        float dot   = HSum256(dotAcc);
        float normA = HSum256(normAAcc);
        float normB = HSum256(normBAcc);

        for (; i < a.Length; i++)
        {
            dot   += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }

        if (normA == 0 || normB == 0) return 1f;
        return 1f - dot / (MathF.Sqrt(normA) * MathF.Sqrt(normB));
    }

    private static float DotProductAvx2Fma(float[] a, float[] b)
    {
        int i = 0;
        var dotAcc = Vector256<float>.Zero;

        for (; i <= a.Length - Vector256<float>.Count; i += Vector256<float>.Count)
        {
            var va = Vector256.LoadUnsafe(ref a[i]);
            var vb = Vector256.LoadUnsafe(ref b[i]);
            dotAcc = Fma.MultiplyAdd(va, vb, dotAcc);
        }

        float dot = HSum256(dotAcc);
        for (; i < a.Length; i++)
            dot += a[i] * b[i];

        return -dot;
    }

    private static float EuclideanAvx2Fma(float[] a, float[] b)
    {
        int i = 0;
        var sumAcc = Vector256<float>.Zero;

        for (; i <= a.Length - Vector256<float>.Count; i += Vector256<float>.Count)
        {
            var diff = Vector256.LoadUnsafe(ref a[i]) - Vector256.LoadUnsafe(ref b[i]);
            sumAcc = Fma.MultiplyAdd(diff, diff, sumAcc);
        }

        float sum = HSum256(sumAcc);
        for (; i < a.Length; i++)
        {
            float d = a[i] - b[i];
            sum += d * d;
        }

        return MathF.Sqrt(sum);
    }

    // ── x86 AVX2 without FMA (8 floats / iteration, multiply + add) ────────

    private static float CosineAvx2(float[] a, float[] b)
    {
        int i = 0;
        var dotAcc   = Vector256<float>.Zero;
        var normAAcc = Vector256<float>.Zero;
        var normBAcc = Vector256<float>.Zero;

        for (; i <= a.Length - Vector256<float>.Count; i += Vector256<float>.Count)
        {
            var va = Vector256.LoadUnsafe(ref a[i]);
            var vb = Vector256.LoadUnsafe(ref b[i]);
            dotAcc   = Avx.Add(Avx.Multiply(va, vb), dotAcc);
            normAAcc = Avx.Add(Avx.Multiply(va, va), normAAcc);
            normBAcc = Avx.Add(Avx.Multiply(vb, vb), normBAcc);
        }

        float dot   = HSum256(dotAcc);
        float normA = HSum256(normAAcc);
        float normB = HSum256(normBAcc);

        for (; i < a.Length; i++)
        {
            dot   += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }

        if (normA == 0 || normB == 0) return 1f;
        return 1f - dot / (MathF.Sqrt(normA) * MathF.Sqrt(normB));
    }

    private static float DotProductAvx2(float[] a, float[] b)
    {
        int i = 0;
        var dotAcc = Vector256<float>.Zero;

        for (; i <= a.Length - Vector256<float>.Count; i += Vector256<float>.Count)
        {
            var va = Vector256.LoadUnsafe(ref a[i]);
            var vb = Vector256.LoadUnsafe(ref b[i]);
            dotAcc = Avx.Add(Avx.Multiply(va, vb), dotAcc);
        }

        float dot = HSum256(dotAcc);
        for (; i < a.Length; i++)
            dot += a[i] * b[i];

        return -dot;
    }

    private static float EuclideanAvx2(float[] a, float[] b)
    {
        int i = 0;
        var sumAcc = Vector256<float>.Zero;

        for (; i <= a.Length - Vector256<float>.Count; i += Vector256<float>.Count)
        {
            var diff = Vector256.LoadUnsafe(ref a[i]) - Vector256.LoadUnsafe(ref b[i]);
            sumAcc = Avx.Add(Avx.Multiply(diff, diff), sumAcc);
        }

        float sum = HSum256(sumAcc);
        for (; i < a.Length; i++)
        {
            float d = a[i] - b[i];
            sum += d * d;
        }

        return MathF.Sqrt(sum);
    }

    // ── ARM64 AdvSimd / NEON (4 floats / iteration, FMA) ────────────────────

    private static float CosineNeon(float[] a, float[] b)
    {
        int i = 0;
        var dotAcc   = Vector128<float>.Zero;
        var normAAcc = Vector128<float>.Zero;
        var normBAcc = Vector128<float>.Zero;

        for (; i <= a.Length - Vector128<float>.Count; i += Vector128<float>.Count)
        {
            var va = Vector128.LoadUnsafe(ref a[i]);
            var vb = Vector128.LoadUnsafe(ref b[i]);
            // FusedMultiplyAdd(addend, left, right) = addend + left * right
            dotAcc   = AdvSimd.FusedMultiplyAdd(dotAcc,   va, vb);
            normAAcc = AdvSimd.FusedMultiplyAdd(normAAcc, va, va);
            normBAcc = AdvSimd.FusedMultiplyAdd(normBAcc, vb, vb);
        }

        float dot   = HSum128(dotAcc);
        float normA = HSum128(normAAcc);
        float normB = HSum128(normBAcc);

        for (; i < a.Length; i++)
        {
            dot   += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }

        if (normA == 0 || normB == 0) return 1f;
        return 1f - dot / (MathF.Sqrt(normA) * MathF.Sqrt(normB));
    }

    private static float DotProductNeon(float[] a, float[] b)
    {
        int i = 0;
        var dotAcc = Vector128<float>.Zero;

        for (; i <= a.Length - Vector128<float>.Count; i += Vector128<float>.Count)
        {
            var va = Vector128.LoadUnsafe(ref a[i]);
            var vb = Vector128.LoadUnsafe(ref b[i]);
            dotAcc = AdvSimd.FusedMultiplyAdd(dotAcc, va, vb);
        }

        float dot = HSum128(dotAcc);
        for (; i < a.Length; i++)
            dot += a[i] * b[i];

        return -dot;
    }

    private static float EuclideanNeon(float[] a, float[] b)
    {
        int i = 0;
        var sumAcc = Vector128<float>.Zero;

        for (; i <= a.Length - Vector128<float>.Count; i += Vector128<float>.Count)
        {
            var diff = Vector128.LoadUnsafe(ref a[i]) - Vector128.LoadUnsafe(ref b[i]);
            sumAcc = AdvSimd.FusedMultiplyAdd(sumAcc, diff, diff);
        }

        float sum = HSum128(sumAcc);
        for (; i < a.Length; i++)
        {
            float d = a[i] - b[i];
            sum += d * d;
        }

        return MathF.Sqrt(sum);
    }

    // ── Horizontal-sum helpers ───────────────────────────────────────────────

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float HSum512(Vector512<float> v)
        => HSum256(v.GetLower() + v.GetUpper());

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float HSum256(Vector256<float> v)
        => HSum128(v.GetLower() + v.GetUpper());

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float HSum128(Vector128<float> v)
        => Vector128.Sum(v);
}
