using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Intelligence.Tests;

public class TernaryTensorTests
{
    [Fact]
    public void DotProductTernary_AllOnes_ReturnsSum()
    {
        // Arrange: weights all +1, input = [1, 2, 3, 4]
        var weights = new sbyte[] { 1, 1, 1, 1 };
        var input = new int[] { 1, 2, 3, 4 };

        // Act
        int result = TernaryTensor.DotProductTernary(weights, input);

        // Assert: 1+2+3+4 = 10
        Assert.Equal(10, result);
    }

    [Fact]
    public void DotProductTernary_AllNegativeOnes_ReturnsNegativeSum()
    {
        var weights = new sbyte[] { -1, -1, -1, -1 };
        var input = new int[] { 1, 2, 3, 4 };

        int result = TernaryTensor.DotProductTernary(weights, input);

        Assert.Equal(-10, result);
    }

    [Fact]
    public void DotProductTernary_AllZeros_ReturnsZero()
    {
        var weights = new sbyte[] { 0, 0, 0, 0 };
        var input = new int[] { 100, 200, 300, 400 };

        int result = TernaryTensor.DotProductTernary(weights, input);

        Assert.Equal(0, result);
    }

    [Fact]
    public void DotProductTernary_MixedTernary_ReturnsCorrectResult()
    {
        // weights: [1, -1, 0, 1, -1, 0, 1, -1]
        // input:   [10, 20, 30, 40, 50, 60, 70, 80]
        // expected: 10 - 20 + 0 + 40 - 50 + 0 + 70 - 80 = -30
        var weights = new sbyte[] { 1, -1, 0, 1, -1, 0, 1, -1 };
        var input = new int[] { 10, 20, 30, 40, 50, 60, 70, 80 };

        int result = TernaryTensor.DotProductTernary(weights, input);

        Assert.Equal(-30, result);
    }

    [Fact]
    public void DotProductTernary_LargeVector_UsesSimd()
    {
        // 256 elements — should exercise SIMD path
        int size = 256;
        var weights = new sbyte[size];
        var input = new int[size];

        for (int i = 0; i < size; i++)
        {
            weights[i] = 1;
            input[i] = i;
        }

        int result = TernaryTensor.DotProductTernary(weights, input);

        // Sum of 0..255 = 255*256/2 = 32640
        Assert.Equal(32640, result);
    }

    [Fact]
    public void MatVecMultiply_IdentityLike_ReturnsInput()
    {
        // 4×4 "identity" in ternary (diagonal = 1, rest = 0)
        var weights = new sbyte[]
        {
            1, 0, 0, 0,
            0, 1, 0, 0,
            0, 0, 1, 0,
            0, 0, 0, 1
        };
        var input = new int[] { 10, 20, 30, 40 };
        var output = new int[4];

        TernaryTensor.MatVecMultiply(weights, input, output, 4, 4);

        Assert.Equal(new int[] { 10, 20, 30, 40 }, output);
    }

    [Fact]
    public void MatVecMultiply_InvalidBufferSize_Throws()
    {
        var weights = new sbyte[4]; // Too small for 2×4
        var input = new int[4];
        var output = new int[2];

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            TernaryTensor.MatVecMultiply(weights, input, output, 2, 4));
    }

    [Fact]
    public void RmsNormalize_UniformInput_NormalizesCorrectly()
    {
        var input = new int[] { 100, 100, 100, 100 };
        var output = new int[4];

        TernaryTensor.RmsNormalize(input, output, 1024);

        // All values equal → RMS = 100, each output = 100 * 1024 / 100 = 1024
        Assert.All(output, v => Assert.Equal(1024, v));
    }

    [Fact]
    public void RmsNormalize_MismatchedLengths_Throws()
    {
        var input = new int[4];
        var output = new int[3];

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            TernaryTensor.RmsNormalize(input, output));
    }

    [Fact]
    public void TopK_ReturnsIndicesOfLargestValues()
    {
        var logits = new int[] { 5, 100, 3, 50, 1 };
        var topK = new int[2];

        TernaryTensor.TopK(logits, topK, 2);

        Assert.Equal(1, topK[0]); // Index of 100
        Assert.Equal(3, topK[1]); // Index of 50
    }

    [Fact]
    public void Add_VectorAddition_ReturnsCorrectResult()
    {
        var a = new int[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var b = new int[] { 10, 20, 30, 40, 50, 60, 70, 80 };
        var output = new int[8];

        TernaryTensor.Add(a, b, output);

        Assert.Equal(new int[] { 11, 22, 33, 44, 55, 66, 77, 88 }, output);
    }

    [Fact]
    public void DotProduct_MatchesScalar()
    {
        var a = new int[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var b = new int[] { 10, 20, 30, 40, 50, 60, 70, 80 };

        int result = TernaryTensor.DotProduct(a, b);

        // 1*10 + 2*20 + 3*30 + 4*40 + 5*50 + 6*60 + 7*70 + 8*80
        // = 10 + 40 + 90 + 160 + 250 + 360 + 490 + 640 = 2040
        Assert.Equal(2040, result);
    }

    [Fact]
    public void DotProduct_LargeVector_MatchesScalar()
    {
        int size = 256;
        var a = new int[size];
        var b = new int[size];
        var rng = new Random(42);

        int expected = 0;
        for (int i = 0; i < size; i++)
        {
            a[i] = rng.Next(-100, 100);
            b[i] = rng.Next(-100, 100);
            expected += a[i] * b[i];
        }

        int result = TernaryTensor.DotProduct(a, b);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void DotProduct_SmallVector_MatchesScalar()
    {
        var a = new int[] { 3, -5 };
        var b = new int[] { 7, 2 };

        int result = TernaryTensor.DotProduct(a, b);

        Assert.Equal(3 * 7 + (-5) * 2, result); // 21 - 10 = 11
    }

    [Fact]
    public void WeightedAccumulate_MatchesScalar()
    {
        var values = new int[] { 10, 20, 30, 40 };
        var output = new int[4];
        long weight = 3;
        long totalWeight = 6; // not used in SIMD path; division is deferred

        TernaryTensor.WeightedAccumulate(output, weight, values, totalWeight);

        // output[d] += weight * values[d] (no division — deferred to DivideInPlace)
        Assert.Equal(30, output[0]);   // 3*10 = 30
        Assert.Equal(60, output[1]);   // 3*20 = 60
        Assert.Equal(90, output[2]);   // 3*30 = 90
        Assert.Equal(120, output[3]);  // 3*40 = 120
    }

    [Fact]
    public void WeightedAccumulate_LargeVector_MatchesScalar()
    {
        int size = 64;
        var values = new int[size];
        var output = new int[size];
        var expected = new int[size];
        var rng = new Random(99);

        for (int i = 0; i < size; i++)
            values[i] = rng.Next(-200, 200);

        long weight = 7;
        long totalWeight = 10; // not used — division deferred

        // Compute expected scalar result (just weight * values[d])
        for (int i = 0; i < size; i++)
            expected[i] = (int)weight * values[i];

        TernaryTensor.WeightedAccumulate(output, weight, values, totalWeight);

        Assert.Equal(expected, output);
    }

    [Fact]
    public void WeightedAccumulate_AccumulatesIntoExistingOutput()
    {
        var values = new int[] { 100, 200, 300, 400 };
        var output = new int[] { 1, 2, 3, 4 };
        long weight = 2;
        long totalWeight = 1; // not used — division deferred

        TernaryTensor.WeightedAccumulate(output, weight, values, totalWeight);

        // output[d] += weight * values[d]
        Assert.Equal(201, output[0]);  // 1 + 2*100
        Assert.Equal(402, output[1]);  // 2 + 2*200
        Assert.Equal(603, output[2]);  // 3 + 2*300
        Assert.Equal(804, output[3]);  // 4 + 2*400
    }

    [Fact]
    public void DivideInPlace_DividesAllElements()
    {
        var output = new int[] { 30, 60, 90, 120 };

        TernaryTensor.DivideInPlace(output, 6);

        Assert.Equal(new int[] { 5, 10, 15, 20 }, output);
    }

    [Fact]
    public void WeightedAccumulate_ThenDivide_MatchesOriginalSemantics()
    {
        // Simulate the two-phase pattern used in MultiHeadAttention
        var values = new int[] { 10, 20, 30, 40 };
        var output = new int[4];
        int weight = 3;
        int totalWeight = 6;

        // Phase 1: accumulate
        TernaryTensor.WeightedAccumulate(output, weight, values, totalWeight);
        // Phase 2: normalize
        TernaryTensor.DivideInPlace(output, totalWeight);

        // 3*10/6=5, 3*20/6=10, 3*30/6=15, 3*40/6=20
        Assert.Equal(new int[] { 5, 10, 15, 20 }, output);
    }

    [Fact]
    public void IntegerSqrt_KnownValues_ReturnsCorrectResult()
    {
        Assert.Equal(0, TernaryTensor.IntegerSqrt(0));
        Assert.Equal(1, TernaryTensor.IntegerSqrt(1));
        Assert.Equal(3, TernaryTensor.IntegerSqrt(9));
        Assert.Equal(10, TernaryTensor.IntegerSqrt(100));
        Assert.Equal(31, TernaryTensor.IntegerSqrt(999));
    }
}
