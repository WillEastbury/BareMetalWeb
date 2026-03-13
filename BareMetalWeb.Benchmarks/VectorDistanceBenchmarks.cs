using BareMetalWeb.Data;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;

namespace BareMetalWeb.Benchmarks;

/// <summary>
/// Measures SIMD-accelerated vector distance computations against the plain scalar baseline.
/// Run with:  dotnet run -c Release --project BareMetalWeb.Benchmarks -- --filter *VectorDistance*
/// </summary>
[SimpleJob(RuntimeMoniker.Net90)]
[MemoryDiagnoser]
public class VectorDistanceBenchmarks
{
    [Params(64, 256, 1536)]
    public int Dimension { get; set; }

    private float[] _a = null!;
    private float[] _b = null!;

    [GlobalSetup]
    public void Setup()
    {
        var rng = new Random(42);
        _a = Enumerable.Range(0, Dimension).Select(_ => (float)rng.NextDouble()).ToArray();
        _b = Enumerable.Range(0, Dimension).Select(_ => (float)rng.NextDouble()).ToArray();
    }

    // ─── SIMD paths (via SimdVectorMath) ──────────────────────────────────────

    [Benchmark(Baseline = true)]
    public float Scalar_DotProduct()
    {
        float sum = 0;
        for (int i = 0; i < _a.Length; i++) sum += _a[i] * _b[i];
        return sum;
    }

    [Benchmark]
    public float Simd_DotProduct() => SimdVectorMath.DotProduct(_a, _b);

    [Benchmark]
    public float Scalar_EuclideanDistanceSq()
    {
        float sum = 0;
        for (int i = 0; i < _a.Length; i++) { float d = _a[i] - _b[i]; sum += d * d; }
        return sum;
    }

    [Benchmark]
    public float Simd_EuclideanDistanceSq() => SimdVectorMath.EuclideanDistanceSquared(_a, _b);

    [Benchmark]
    public float Scalar_CosineDistance()
    {
        float dot = 0, nA = 0, nB = 0;
        for (int i = 0; i < _a.Length; i++)
        {
            dot += _a[i] * _b[i];
            nA  += _a[i] * _a[i];
            nB  += _b[i] * _b[i];
        }
        if (nA == 0 || nB == 0) return 1f;
        return 1f - dot / MathF.Sqrt(nA * nB);
    }

    [Benchmark]
    public float Simd_CosineDistance() => SimdVectorMath.CosineDistance(_a, _b);
}
