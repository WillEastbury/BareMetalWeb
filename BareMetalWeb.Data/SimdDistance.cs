using System;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// SIMD-accelerated vector distance calculations.
/// Uses <see cref="Vector{T}"/> which automatically selects the best hardware
/// acceleration: NEON on ARM64, SSE/AVX on x86-64. Falls back to scalar on
/// platforms without SIMD support.
/// </summary>
internal static class SimdDistance
{
    /// <summary>Returns 1 − cos(θ) so 0 = identical, 2 = opposite.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static float Cosine(float[] a, float[] b)
    {
        int vecSize = Vector<float>.Count;
        int i = 0;

        var dotVec = Vector<float>.Zero;
        var normAVec = Vector<float>.Zero;
        var normBVec = Vector<float>.Zero;

        for (; i <= a.Length - vecSize; i += vecSize)
        {
            var va = new Vector<float>(a, i);
            var vb = new Vector<float>(b, i);
            dotVec += va * vb;
            normAVec += va * va;
            normBVec += vb * vb;
        }

        float dot = Vector.Sum(dotVec);
        float normA = Vector.Sum(normAVec);
        float normB = Vector.Sum(normBVec);

        // Scalar remainder
        for (; i < a.Length; i++)
        {
            dot += a[i] * b[i];
            normA += a[i] * a[i];
            normB += b[i] * b[i];
        }

        if (normA == 0 || normB == 0) return 1f;
        return 1f - dot / (MathF.Sqrt(normA) * MathF.Sqrt(normB));
    }

    /// <summary>Negated dot product so smaller = more similar.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static float DotProduct(float[] a, float[] b)
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

    /// <summary>L2 (Euclidean) distance.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static float Euclidean(float[] a, float[] b)
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

    /// <summary>Dispatches to the appropriate distance function.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static float Compute(DistanceMetric metric, float[] a, float[] b)
    {
        return metric switch
        {
            DistanceMetric.Cosine => Cosine(a, b),
            DistanceMetric.DotProduct => DotProduct(a, b),
            DistanceMetric.Euclidean => Euclidean(a, b),
            _ => Cosine(a, b)
        };
    }
}
