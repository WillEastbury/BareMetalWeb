using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Intelligence.Tests;

public class ModelSnapshotTests : IDisposable
{
    private readonly string _tempDir;

    public ModelSnapshotTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"bmwm_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, true); } catch { }
    }

    private string TempPath(string name) => Path.Combine(_tempDir, name);

    [Fact]
    public void Load_InvalidMagic_Throws()
    {
        string path = TempPath("bad.bmwm");
        File.WriteAllBytes(path, [0, 0, 0, 0, 0, 0, 0, 0]);

        using var engine = new BitNetEngine(new BitNetModelConfig(16, 1, 2, 32, 64));
        Assert.Throws<InvalidDataException>(() => engine.LoadSnapshot(path));
    }

    [Fact]
    public void Save_NotLoaded_Throws()
    {
        using var engine = new BitNetEngine(new BitNetModelConfig(16, 1, 2, 32, 64));
        Assert.Throws<InvalidOperationException>(() => engine.SaveSnapshot(TempPath("fail.bmwm")));
    }

    [Fact]
    public void FromPackedData_RoundTrips_WithPack()
    {
        sbyte[] weights = new sbyte[64];
        var rng = new Random(42);
        for (int i = 0; i < weights.Length; i++)
            weights[i] = (sbyte)(rng.Next(3) - 1);

        using var original = NativeTernaryMatrix.Pack(weights, 8, 8);

        var data = new byte[(int)original.TotalPackedDataBytes];
        original.CopyPackedDataTo(data);

        using var restored = NativeTernaryMatrix.FromPackedData(data, 8, 8);

        Assert.Equal(original.Rows, restored.Rows);
        Assert.Equal(original.Cols, restored.Cols);
        Assert.Equal(original.Stats.LogicalWeights, restored.Stats.LogicalWeights);
        Assert.Equal(original.Stats.ZeroByteCount, restored.Stats.ZeroByteCount);

        int[] input = new int[8];
        for (int i = 0; i < 8; i++)
            input[i] = i + 1;

        for (int r = 0; r < 8; r++)
            Assert.Equal(original.DotProductRow(r, input), restored.DotProductRow(r, input));
    }

    [Fact]
    public void FromPackedData_PreservesAlignment()
    {
        sbyte[] weights = new sbyte[20 * 4];
        for (int i = 0; i < weights.Length; i++)
            weights[i] = (sbyte)(i % 3 - 1);

        using var original = NativeTernaryMatrix.Pack(weights, 4, 20);
        Assert.True(original.RowStrideBytes >= original.PackedRowBytes);
        Assert.Equal(0, original.RowStrideBytes % 32);

        var data = new byte[(int)original.TotalPackedDataBytes];
        original.CopyPackedDataTo(data);

        using var restored = NativeTernaryMatrix.FromPackedData(data, 4, 20);
        Assert.Equal(original.RowStrideBytes, restored.RowStrideBytes);
    }
}
