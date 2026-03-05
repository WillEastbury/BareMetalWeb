using System.Numerics;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Validates that SimdVectorMath produces numerically correct results.
/// All paths (portable Vector&lt;float&gt;, and any hardware intrinsic paths available
/// on the current machine) must agree to within a small tolerance.
/// </summary>
public class SimdVectorMathTests
{
    private const float Tolerance = 1e-4f;

    // ─── DotProduct ────────────────────────────────────────────────────────────

    [Fact]
    public void DotProduct_KnownValues_ReturnsCorrectResult()
    {
        float[] a = [1f, 2f, 3f, 4f];
        float[] b = [5f, 6f, 7f, 8f];

        float result = SimdVectorMath.DotProduct(a, b);

        // 1*5 + 2*6 + 3*7 + 4*8 = 5+12+21+32 = 70
        Assert.Equal(70f, result, Tolerance);
    }

    [Fact]
    public void DotProduct_OrthogonalVectors_ReturnsZero()
    {
        float[] a = [1f, 0f, 0f, 0f];
        float[] b = [0f, 1f, 0f, 0f];

        float result = SimdVectorMath.DotProduct(a, b);

        Assert.Equal(0f, result, Tolerance);
    }

    [Fact]
    public void DotProduct_LargeVector_MatchesScalar()
    {
        // Use a length that is NOT a multiple of 8 to exercise the tail loop
        var rng = new Random(42);
        float[] a = Enumerable.Range(0, 137).Select(_ => (float)rng.NextDouble()).ToArray();
        float[] b = Enumerable.Range(0, 137).Select(_ => (float)rng.NextDouble()).ToArray();

        float expected = ScalarDot(a, b);
        float actual   = SimdVectorMath.DotProduct(a, b);

        Assert.Equal(expected, actual, Tolerance);
    }

    [Fact]
    public void DotProduct_SingleElement_ReturnsProduct()
    {
        float[] a = [3.5f];
        float[] b = [2.0f];

        Assert.Equal(7f, SimdVectorMath.DotProduct(a, b), Tolerance);
    }

    // ─── EuclideanDistanceSquared ──────────────────────────────────────────────

    [Fact]
    public void EuclideanDistanceSquared_KnownValues_ReturnsCorrectResult()
    {
        float[] a = [1f, 2f, 3f];
        float[] b = [4f, 6f, 3f];

        float result = SimdVectorMath.EuclideanDistanceSquared(a, b);

        // (1-4)²+(2-6)²+(3-3)² = 9+16+0 = 25
        Assert.Equal(25f, result, Tolerance);
    }

    [Fact]
    public void EuclideanDistanceSquared_SameVector_ReturnsZero()
    {
        float[] v = [1f, 2f, 3f, 4f, 5f];

        Assert.Equal(0f, SimdVectorMath.EuclideanDistanceSquared(v, v), Tolerance);
    }

    [Fact]
    public void EuclideanDistanceSquared_LargeVector_MatchesScalar()
    {
        var rng = new Random(7);
        float[] a = Enumerable.Range(0, 200).Select(_ => (float)(rng.NextDouble() - 0.5)).ToArray();
        float[] b = Enumerable.Range(0, 200).Select(_ => (float)(rng.NextDouble() - 0.5)).ToArray();

        float expected = ScalarEuclideanSq(a, b);
        float actual   = SimdVectorMath.EuclideanDistanceSquared(a, b);

        Assert.Equal(expected, actual, Tolerance);
    }

    // ─── CosineDistance ───────────────────────────────────────────────────────

    [Fact]
    public void CosineDistance_IdenticalVectors_ReturnsZero()
    {
        float[] v = [1f, 2f, 3f, 4f, 5f, 6f, 7f, 8f];

        Assert.Equal(0f, SimdVectorMath.CosineDistance(v, v), Tolerance);
    }

    [Fact]
    public void CosineDistance_OppositeVectors_ReturnsTwo()
    {
        float[] a = [1f, 2f, 3f];
        float[] b = [-1f, -2f, -3f];

        Assert.Equal(2f, SimdVectorMath.CosineDistance(a, b), Tolerance);
    }

    [Fact]
    public void CosineDistance_OrthogonalVectors_ReturnsOne()
    {
        float[] a = [1f, 0f];
        float[] b = [0f, 1f];

        Assert.Equal(1f, SimdVectorMath.CosineDistance(a, b), Tolerance);
    }

    [Fact]
    public void CosineDistance_ZeroVector_ReturnsOne()
    {
        float[] a = [0f, 0f, 0f];
        float[] b = [1f, 2f, 3f];

        Assert.Equal(1f, SimdVectorMath.CosineDistance(a, b), Tolerance);
    }

    [Fact]
    public void CosineDistance_LargeVector_MatchesScalar()
    {
        var rng = new Random(99);
        float[] a = Enumerable.Range(0, 256).Select(_ => (float)rng.NextDouble()).ToArray();
        float[] b = Enumerable.Range(0, 256).Select(_ => (float)rng.NextDouble()).ToArray();

        float expected = ScalarCosine(a, b);
        float actual   = SimdVectorMath.CosineDistance(a, b);

        Assert.Equal(expected, actual, Tolerance);
    }

    // ─── SumOfSquares ─────────────────────────────────────────────────────────

    [Fact]
    public void SumOfSquares_KnownValues_ReturnsCorrectResult()
    {
        float[] v = [3f, 4f];

        // 9 + 16 = 25
        Assert.Equal(25f, SimdVectorMath.SumOfSquares(v), Tolerance);
    }

    // ─── SimdCapabilities ─────────────────────────────────────────────────────

    [Fact]
    public void SimdCapabilities_Current_IsNotNull()
    {
        var cap = SimdCapabilities.Current;

        Assert.NotNull(cap);
        Assert.NotEmpty(cap.BestTier);
    }

    [Fact]
    public void SimdCapabilities_ToLogLine_ContainsBestTier()
    {
        var cap = SimdCapabilities.Current;
        var line = cap.ToLogLine();

        Assert.Contains(cap.BestTier, line);
    }

    [Fact]
    public void SimdCapabilities_FloatVectorWidth_IsPositivePowerOfTwo()
    {
        int w = SimdCapabilities.Current.FloatVectorWidth;

        Assert.True(w > 0);            // must be at least 1 (scalar fallback)
        Assert.Equal(0, w & (w - 1)); // must be a power of two (1, 4, 8, 16, …)
    }

    // ─── Scalar reference implementations ────────────────────────────────────

    private static float ScalarDot(float[] a, float[] b)
    {
        float sum = 0;
        for (int i = 0; i < a.Length; i++) sum += a[i] * b[i];
        return sum;
    }

    private static float ScalarEuclideanSq(float[] a, float[] b)
    {
        float sum = 0;
        for (int i = 0; i < a.Length; i++) { float d = a[i] - b[i]; sum += d * d; }
        return sum;
    }

    private static float ScalarCosine(float[] a, float[] b)
    {
        float dot = 0, nA = 0, nB = 0;
        for (int i = 0; i < a.Length; i++)
        {
            dot += a[i] * b[i];
            nA  += a[i] * a[i];
            nB  += b[i] * b[i];
        }
        if (nA == 0 || nB == 0) return 1f;
        return 1f - dot / MathF.Sqrt(nA * nB);
    }
}
