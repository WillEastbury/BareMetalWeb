using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Intelligence.Tests;

public class NativeTernaryMatrixTests
{
    [Fact]
    public void Pack_CorrectDimensions()
    {
        var weights = new sbyte[] { 1, 0, -1, 1, 0, -1, 1, 0 };
        using var matrix = NativeTernaryMatrix.Pack(weights, 2, 4);

        Assert.Equal(2, matrix.Rows);
        Assert.Equal(4, matrix.Cols);
        Assert.Equal(1, matrix.PackedRowBytes);  // ceil(4/4) = 1
        Assert.Equal(32, matrix.RowStrideBytes); // AlignUp(1, 32) = 32
    }

    [Fact]
    public void Pack_RowAlignment_Is32ByteAligned()
    {
        // 17 cols → PackedRowBytes = 5, RowStrideBytes = 32
        var weights = new sbyte[3 * 17];
        using var matrix = NativeTernaryMatrix.Pack(weights, 3, 17);

        Assert.Equal(5, matrix.PackedRowBytes);
        Assert.Equal(32, matrix.RowStrideBytes);
        Assert.Equal(3 * 32, matrix.BytesAllocated);
    }

    [Fact]
    public void Pack_LargeRow_AlignedCorrectly()
    {
        // 2048 cols → PackedRowBytes = 512, RowStrideBytes = 512 (already aligned)
        var weights = new sbyte[2048];
        using var matrix = NativeTernaryMatrix.Pack(weights, 1, 2048);

        Assert.Equal(512, matrix.PackedRowBytes);
        Assert.Equal(512, matrix.RowStrideBytes);
    }

    [Fact]
    public void AlignUp_RoundsCorrectly()
    {
        Assert.Equal(32, NativeTernaryMatrix.AlignUp(1, 32));
        Assert.Equal(32, NativeTernaryMatrix.AlignUp(31, 32));
        Assert.Equal(32, NativeTernaryMatrix.AlignUp(32, 32));
        Assert.Equal(64, NativeTernaryMatrix.AlignUp(33, 32));
        Assert.Equal(512, NativeTernaryMatrix.AlignUp(512, 32));
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
        var weights = new sbyte[] { 1, -1, 0, 1, -1, 0, 1, -1 };
        var input = new int[] { 10, 20, 30, 40, 50, 60, 70, 80 };
        using var matrix = NativeTernaryMatrix.Pack(weights, 1, 8);

        int result = matrix.DotProductRow(0, input);

        Assert.Equal(-30, result);
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
    public void DotProductRow_2048Dim_MatchesTernaryTensor()
    {
        // Full-size dimension — exercises AVX2 path with prefetch
        int size = 2048;
        var weights = new sbyte[size];
        var input = new int[size];
        var rng = new Random(99);

        for (int i = 0; i < size; i++)
        {
            weights[i] = (sbyte)(rng.Next(3) - 1);
            input[i] = rng.Next(-500, 500);
        }

        int expected = TernaryTensor.DotProductTernary(weights, input);
        using var matrix = NativeTernaryMatrix.Pack(weights, 1, size);
        int actual = matrix.DotProductRow(0, input);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void MatVecMultiply_IdentityLike_ReturnsInput()
    {
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

        var expected = new int[rows];
        TernaryTensor.MatVecMultiply(weights, input, expected, rows, cols);

        var actual = new int[rows];
        using var matrix = NativeTernaryMatrix.Pack(weights, rows, cols);
        matrix.MatVecMultiply(input, actual);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void MatVecMultiply_LargeAligned_MatchesTernaryTensor()
    {
        // 128×128 — tests AVX2 + alignment on large data
        int rows = 128, cols = 128;
        var weights = new sbyte[rows * cols];
        var input = new int[cols];
        var rng = new Random(777);

        for (int i = 0; i < weights.Length; i++)
            weights[i] = (sbyte)(rng.Next(3) - 1);
        for (int i = 0; i < input.Length; i++)
            input[i] = rng.Next(-200, 200);

        var expected = new int[rows];
        TernaryTensor.MatVecMultiply(weights, input, expected, rows, cols);

        var actual = new int[rows];
        using var matrix = NativeTernaryMatrix.Pack(weights, rows, cols);
        matrix.MatVecMultiply(input, actual);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void Pack_NonMultipleOf4Cols_HandlesCorrectly()
    {
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
        var weights = new sbyte[] { 1, 0, -1, 1 };
        using var matrix = NativeTernaryMatrix.Pack(weights, 1, 4);

        Assert.Equal(3, matrix.CountNonZeros());
    }

    [Fact]
    public void CountZeroBytes_AllZeros_CountsLogicalOnly()
    {
        var weights = new sbyte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
        using var matrix = NativeTernaryMatrix.Pack(weights, 2, 4);

        // 2 logical bytes (1 per row), both zero — padding bytes excluded
        Assert.Equal(2, matrix.CountZeroBytes());
    }

    [Fact]
    public void Stats_ComputedDuringPack()
    {
        var weights = new sbyte[64];
        // Set some non-zero values
        for (int i = 0; i < 16; i++)
            weights[i] = 1;
        using var matrix = NativeTernaryMatrix.Pack(weights, 4, 16);

        var stats = matrix.Stats;
        Assert.Equal(64, stats.LogicalWeights);
        Assert.Equal(16, stats.PackedBytes);  // 4 rows × 4 bytes/row
        Assert.True(stats.ZeroByteCount > 0);
        Assert.True(stats.ZeroByteRatio > 0f);
        Assert.True(stats.ZeroByteRatio <= 1f);
    }

    [Fact]
    public void Stats_AllZeros_FullZeroByteRatio()
    {
        var weights = new sbyte[32];
        using var matrix = NativeTernaryMatrix.Pack(weights, 2, 16);

        Assert.Equal(1f, matrix.Stats.ZeroByteRatio);
        Assert.Equal(8, matrix.Stats.ZeroByteCount); // 2 rows × 4 bytes/row
    }

    [Fact]
    public void BytesAllocated_ReflectsAlignment()
    {
        // 64×128: PackedRowBytes=32 (aligned), so BytesAllocated = 64*32
        int rows = 64, cols = 128;
        var weights = new sbyte[rows * cols];
        using var matrix = NativeTernaryMatrix.Pack(weights, rows, cols);

        Assert.Equal(32, matrix.PackedRowBytes);
        Assert.Equal(32, matrix.RowStrideBytes);
        Assert.Equal(64 * 32, matrix.BytesAllocated);
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
        matrix.Dispose();
    }

    [Fact]
    public void GCHeap_DoesNotGrow_WithNativeWeights()
    {
        // Warmup: stabilise JIT and GC state before measuring
        {
            var warmup = new sbyte[512 * 512];
            using var _ = NativeTernaryMatrix.Pack(warmup, 512, 512);
        }
        GC.Collect(2, GCCollectionMode.Aggressive, true, true);
        GC.WaitForPendingFinalizers();
        GC.Collect();
        long heapBefore = GC.GetTotalMemory(true);

        int rows = 512, cols = 512;
        var managedWeights = new sbyte[rows * cols];
        using var matrix = NativeTernaryMatrix.Pack(managedWeights, rows, cols);
        managedWeights = null!;

        GC.Collect(2, GCCollectionMode.Aggressive, true, true);
        long heapAfter = GC.GetTotalMemory(true);

        long heapGrowth = heapAfter - heapBefore;
        Assert.True(heapGrowth < 1024 * 1024,
            $"GC heap grew by {heapGrowth} bytes — expected < 1MB (weight data should be native)");
        // 512 cols / 4 = 128 bytes/row, AlignUp(128,32)=128, 512*128 = 65536
        Assert.Equal(65536, matrix.BytesAllocated);
    }

    // ── Streaming pack API (used by HF importer) ──────────────────────────

    [Fact]
    public void AllocateAndPackRowInPlace_ProducesSameResultAsPack()
    {
        int rows = 4, cols = 8;
        var weights = new sbyte[rows * cols];
        var rng = Random.Shared;
        int[] vals = [-1, 0, 1];
        for (int i = 0; i < weights.Length; i++)
            weights[i] = (sbyte)vals[rng.Next(3)];

        // Build via Pack (reference)
        using var reference = NativeTernaryMatrix.Pack(weights, rows, cols);

        // Build via streaming API
        using var streamed = NativeTernaryMatrix.Allocate(rows, cols);
        for (int r = 0; r < rows; r++)
            streamed.PackRowInPlace(r, weights.AsSpan(r * cols, cols));
        streamed.FinalizeStats();

        // Both matrices must decode identically
        var refRow    = new int[cols];
        var streamRow = new int[cols];
        for (int r = 0; r < rows; r++)
        {
            reference.DecodeRow(r, refRow);
            streamed.DecodeRow(r, streamRow);
            Assert.Equal(refRow, streamRow);
        }
    }

    [Fact]
    public void FinalizeStats_ComputesCorrectZeroByteRatio()
    {
        // 4×4 matrix of all-zero weights → every packed byte is 0x00
        int rows = 4, cols = 4;
        using var m = NativeTernaryMatrix.Allocate(rows, cols);
        for (int r = 0; r < rows; r++)
            m.PackRowInPlace(r, new sbyte[cols]);
        m.FinalizeStats();

        Assert.Equal(1.0f, m.Stats.ZeroByteRatio);
        Assert.Equal(rows * cols, m.Stats.LogicalWeights);
    }

    [Fact]
    public void PackRowInPlace_OutOfRange_Throws()
    {
        using var m = NativeTernaryMatrix.Allocate(2, 4);
        Assert.Throws<ArgumentOutOfRangeException>(
            () => m.PackRowInPlace(2, new sbyte[4])); // row 2 >= rows 2
    }

    [Fact]
    public void PackRowInPlace_ShortRow_Throws()
    {
        using var m = NativeTernaryMatrix.Allocate(2, 4);
        Assert.Throws<ArgumentException>(
            () => m.PackRowInPlace(0, new sbyte[3])); // 3 < 4 cols
    }
}
