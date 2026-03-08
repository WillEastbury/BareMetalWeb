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
    public void IntegerSqrt_KnownValues_ReturnsCorrectResult()
    {
        Assert.Equal(0, TernaryTensor.IntegerSqrt(0));
        Assert.Equal(1, TernaryTensor.IntegerSqrt(1));
        Assert.Equal(3, TernaryTensor.IntegerSqrt(9));
        Assert.Equal(10, TernaryTensor.IntegerSqrt(100));
        Assert.Equal(31, TernaryTensor.IntegerSqrt(999));
    }
}
