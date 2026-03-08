using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Intelligence.Tests;

public class NativeTernaryMatrixTests
{
    [Fact]
    public void Pack_CorrectSize()
    {
        var weights = new sbyte[] { 1, 0, -1, 1, 0, -1, 1, 0 };
        using var matrix = NativeTernaryMatrix.Pack(weights, 2, 4);

        Assert.Equal(2, matrix.Rows);
        Assert.Equal(4, matrix.Cols);
        Assert.Equal(2, matrix.BytesAllocated); // 2 rows × 1 byte/row
    }

    [Fact]
    public void DotProductRow_AllOnes_ReturnsSum()
    {
        var weights = new sbyte[] { 1, 1, 1, 1 };
        var input = new int[] { 1, 2, 3, 4 };
        using var matrix = NativeTernaryMatrix.Pack(weights, 1, 4);

        int result = matrix.DotProductRow(0, input);

        Assert.Equal(10, result);
    }

    [Fact]
    public void DotProductRow_AllNegativeOnes_ReturnsNegativeSum()
    {
        var weights = new sbyte[] { -1, -1, -1, -1 };
        var input = new int[] { 1, 2, 3, 4 };
        using var matrix = NativeTernaryMatrix.Pack(weights, 1, 4);

        int result = matrix.DotProductRow(0, input);

        Assert.Equal(-10, result);
    }

    [Fact]
    public void DotProductRow_AllZeros_ReturnsZero()
    {
        var weights = new sbyte[] { 0, 0, 0, 0 };
        var input = new int[] { 100, 200, 300, 400 };
        using var matrix = NativeTernaryMatrix.Pack(weights, 1, 4);

        int result = matrix.DotProductRow(0, input);

        Assert.Equal(0, result);
    }

    [Fact]
    public void DotProductRow_MixedTernary_MatchesReference()
    {
        // Same test as TernaryTensor: weights [1,-1,0,1,-1,0,1,-1], input [10..80]
        var weights = new sbyte[] { 1, -1, 0, 1, -1, 0, 1, -1 };
        var input = new int[] { 10, 20, 30, 40, 50, 60, 70, 80 };
        using var matrix = NativeTernaryMatrix.Pack(weights, 1, 8);

        int result = matrix.DotProductRow(0, input);

        Assert.Equal(-30, result); // 10-20+0+40-50+0+70-80 = -30
    }

    [Fact]
    public void DotProductRow_LargeVector_MatchesTernaryTensor()
    {
        int size = 256;
        var weights = new sbyte[size];
        var input = new int[size];
        var rng = new Random(42);

        for (int i = 0; i < size; i++)
        {
            weights[i] = (sbyte)(rng.Next(3) - 1);
            input[i] = rng.Next(-100, 100);
        }

        int expected = TernaryTensor.DotProductTernary(weights, input);
        using var matrix = NativeTernaryMatrix.Pack(weights, 1, size);
        int actual = matrix.DotProductRow(0, input);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void MatVecMultiply_IdentityLike_ReturnsInput()
    {
        // 4×4 diagonal identity in ternary
        var weights = new sbyte[]
        {
            1, 0, 0, 0,
            0, 1, 0, 0,
            0, 0, 1, 0,
            0, 0, 0, 1
        };
        var input = new int[] { 10, 20, 30, 40 };
        var output = new int[4];
        using var matrix = NativeTernaryMatrix.Pack(weights, 4, 4);

        matrix.MatVecMultiply(input, output);

        Assert.Equal(new int[] { 10, 20, 30, 40 }, output);
    }

    [Fact]
    public void MatVecMultiply_MatchesTernaryTensor()
    {
        int rows = 16, cols = 32;
        var weights = new sbyte[rows * cols];
        var input = new int[cols];
        var rng = new Random(123);

        for (int i = 0; i < weights.Length; i++)
            weights[i] = (sbyte)(rng.Next(3) - 1);
        for (int i = 0; i < input.Length; i++)
            input[i] = rng.Next(-50, 50);

        // Reference: TernaryTensor
        var expected = new int[rows];
        TernaryTensor.MatVecMultiply(weights, input, expected, rows, cols);

        // Packed native
        var actual = new int[rows];
        using var matrix = NativeTernaryMatrix.Pack(weights, rows, cols);
        matrix.MatVecMultiply(input, actual);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Pack_NonMultipleOf4Cols_HandlesCorrectly()
    {
        // 7 cols — not a multiple of 4, tests tail handling
        var weights = new sbyte[] { 1, -1, 0, 1, -1, 0, 1 };
        var input = new int[] { 10, 20, 30, 40, 50, 60, 70 };
        using var matrix = NativeTernaryMatrix.Pack(weights, 1, 7);

        int result = matrix.DotProductRow(0, input);
        int expected = TernaryTensor.DotProductTernary(weights, input);

        Assert.Equal(expected, result);
    }

    [Fact]
    public void CountNonZeros_ReturnsCorrectCount()
    {
        // 4 weights: 1, 0, -1, 1 → 3 non-zeros
        var weights = new sbyte[] { 1, 0, -1, 1 };
        using var matrix = NativeTernaryMatrix.Pack(weights, 1, 4);

        Assert.Equal(3, matrix.CountNonZeros());
    }

    [Fact]
    public void CountZeroBytes_AllZeros_AllBytesZero()
    {
        var weights = new sbyte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
        using var matrix = NativeTernaryMatrix.Pack(weights, 2, 4);

        Assert.Equal(2, matrix.CountZeroBytes()); // 2 bytes, both zero
    }

    [Fact]
    public void BytesAllocated_Is4xSmaller()
    {
        int rows = 64, cols = 128;
        var weights = new sbyte[rows * cols];
        using var matrix = NativeTernaryMatrix.Pack(weights, rows, cols);

        Assert.Equal(rows * cols / 4, matrix.BytesAllocated);
        Assert.Equal(weights.Length / 4, matrix.BytesAllocated);
    }

    [Fact]
    public void Dispose_FreesMemory()
    {
        var weights = new sbyte[256];
        var matrix = NativeTernaryMatrix.Pack(weights, 16, 16);

        matrix.Dispose();

        Assert.True(matrix.IsDisposed);
    }

    [Fact]
    public void Dispose_DoubleDispose_DoesNotThrow()
    {
        var weights = new sbyte[256];
        var matrix = NativeTernaryMatrix.Pack(weights, 16, 16);

        matrix.Dispose();
        matrix.Dispose(); // Should not throw
    }

    [Fact]
    public void GCHeap_DoesNotGrow_WithNativeWeights()
    {
        GC.Collect(2, GCCollectionMode.Aggressive, true, true);
        long heapBefore = GC.GetTotalMemory(true);

        // Allocate 1MB of weights in native memory
        int rows = 512, cols = 512;
        var managedWeights = new sbyte[rows * cols]; // 256KB managed (temporary)
        using var matrix = NativeTernaryMatrix.Pack(managedWeights, rows, cols);
        managedWeights = null!;

        GC.Collect(2, GCCollectionMode.Aggressive, true, true);
        long heapAfter = GC.GetTotalMemory(true);

        // The NativeTernaryMatrix object itself is small (~50 bytes on heap)
        // Weight data (64KB packed) is in native memory, not GC heap
        // Allow 512KB slack for test runner overhead
        long heapGrowth = heapAfter - heapBefore;
        Assert.True(heapGrowth < 512 * 1024,
            $"GC heap grew by {heapGrowth} bytes — expected < 512KB (weight data should be native)");
        Assert.Equal(64 * 1024, matrix.BytesAllocated); // 256KB / 4 = 64KB in native
    }
}
