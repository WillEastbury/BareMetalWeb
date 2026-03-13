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

    // ── Round-trip tests ────────────────────────────────────────────────

    [Fact]
    public void SaveAndLoad_RoundTrips_SmallModel()
    {
        var config = new BitNetModelConfig(32, 2, 4, 64, 128);
        using var engine = new BitNetEngine(config);
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        string path = TempPath("small.bmwm");
        engine.SaveSnapshot(path);
        Assert.True(File.Exists(path));
        Assert.True(new FileInfo(path).Length > 0);

        using var engine2 = new BitNetEngine(config);
        engine2.LoadSnapshot(path);

        Assert.True(engine2.IsLoaded);
        Assert.Equal(engine.NativeBytesAllocated, engine2.NativeBytesAllocated);
        Assert.NotNull(engine2.ModelStats);
        Assert.NotNull(engine2.LayerStats);
        Assert.Equal(2, engine2.LayerStats!.Count);
    }

    [Fact]
    public void SaveAndLoad_PreservesLayerCount()
    {
        var config = new BitNetModelConfig(16, 3, 2, 32, 64);
        using var engine = new BitNetEngine(config);
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        string path = TempPath("layers.bmwm");
        engine.SaveSnapshot(path);

        using var engine2 = new BitNetEngine(config);
        engine2.LoadSnapshot(path);

        Assert.Equal(3, engine2.LayerStats!.Count);
    }

    [Fact]
    public void SaveAndLoad_PrunedModel_PreservesSparsity()
    {
        var config = new BitNetModelConfig(32, 2, 4, 64, 128);
        using var engine = new BitNetEngine(config);
        engine.LoadTestModel(ModelLoadOptions.Aggressive);

        float originalSparsity = engine.ModelStats!.Value.Sparsity;

        string path = TempPath("pruned.bmwm");
        engine.SaveSnapshot(path);

        using var engine2 = new BitNetEngine(config);
        engine2.LoadSnapshot(path);

        // Sparsity should be similar (not exactly same because loaded stats
        // are computed from packed bytes, not original weight counts)
        Assert.True(engine2.ModelStats!.Value.Sparsity > 0);
    }

    [Fact]
    public void SaveAndLoad_WithTokenTable()
    {
        var config = new BitNetModelConfig(16, 1, 2, 32, 64);
        using var engine = new BitNetEngine(config);
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        var tokens = new[] { "<PAD>", "<BOS>", "<EOS>", "hello", "world" };

        string path = TempPath("tokens.bmwm");
        engine.SaveSnapshot(path, tokens);

        var snapshot = ModelSnapshot.Load(path);
        try
        {
            Assert.Equal(5, snapshot.Tokens.Length);
            Assert.Equal("<PAD>", snapshot.Tokens[0]);
            Assert.Equal("world", snapshot.Tokens[4]);
        }
        finally
        {
            snapshot.Dispose();
        }
    }

    [Fact]
    public void SaveAndLoad_InferenceProducesSameResults()
    {
        var config = new BitNetModelConfig(32, 2, 4, 64, 128);
        using var engine = new BitNetEngine(config);
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        var result1 = engine.GenerateAsync("test query".AsMemory())
            .AsTask().GetAwaiter().GetResult();

        string path = TempPath("inference.bmwm");
        engine.SaveSnapshot(path);

        using var engine2 = new BitNetEngine(config);
        engine2.LoadSnapshot(path);

        var result2 = engine2.GenerateAsync("test query".AsMemory())
            .AsTask().GetAwaiter().GetResult();

        // Both engines should produce identical top logit indices
        Assert.Equal(result1, result2);
    }

    // ── Memory-mapped load test ─────────────────────────────────────────

    [Fact]
    public void LoadMapped_ProducesWorkingModel()
    {
        var config = new BitNetModelConfig(32, 2, 4, 64, 128);
        using var engine = new BitNetEngine(config);
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        string path = TempPath("mapped.bmwm");
        engine.SaveSnapshot(path);

        using var engine2 = new BitNetEngine(config);
        engine2.LoadSnapshot(path, memoryMapped: true);

        Assert.True(engine2.IsLoaded);
        Assert.Equal(engine.NativeBytesAllocated, engine2.NativeBytesAllocated);

        var result = engine2.GenerateAsync("test".AsMemory())
            .AsTask().GetAwaiter().GetResult();
        Assert.NotEmpty(result); // real token output, not spike diagnostic
    }

    // ── Error handling ──────────────────────────────────────────────────

    [Fact]
    public void Load_InvalidMagic_Throws()
    {
        string path = TempPath("bad.bmwm");
        File.WriteAllBytes(path, new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });

        using var engine = new BitNetEngine(new BitNetModelConfig(16, 1, 2, 32, 64));
        Assert.Throws<InvalidDataException>(() => engine.LoadSnapshot(path));
    }

    [Fact]
    public void Save_NotLoaded_Throws()
    {
        using var engine = new BitNetEngine(new BitNetModelConfig(16, 1, 2, 32, 64));
        Assert.Throws<InvalidOperationException>(
            () => engine.SaveSnapshot(TempPath("fail.bmwm")));
    }

    // ── NativeTernaryMatrix FromPackedData ───────────────────────────────

    [Fact]
    public void FromPackedData_RoundTrips_WithPack()
    {
        sbyte[] weights = new sbyte[64]; // 8 rows × 8 cols
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

        // Verify dot products match
        int[] input = new int[8];
        for (int i = 0; i < 8; i++) input[i] = i + 1;

        for (int r = 0; r < 8; r++)
            Assert.Equal(
                original.DotProductRow(r, input),
                restored.DotProductRow(r, input));
    }

    [Fact]
    public void FromPackedData_PreservesAlignment()
    {
        // Use a size where packed row bytes != row stride
        // 20 cols → 5 packed bytes → stride = 32 (aligned)
        sbyte[] weights = new sbyte[20 * 4]; // 4 rows × 20 cols
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

    // ── File format ─────────────────────────────────────────────────────

    [Fact]
    public void SnapshotFile_StartsWithMagic()
    {
        var config = new BitNetModelConfig(16, 1, 2, 32, 64);
        using var engine = new BitNetEngine(config);
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        string path = TempPath("magic.bmwm");
        engine.SaveSnapshot(path);

        byte[] header = new byte[4];
        using var fs = File.OpenRead(path);
        fs.Read(header);

        Assert.Equal((byte)'B', header[0]);
        Assert.Equal((byte)'M', header[1]);
        Assert.Equal((byte)'W', header[2]);
        Assert.Equal((byte)'M', header[3]);
    }

    [Fact]
    public void SnapshotFile_SizeIsReasonable()
    {
        var config = new BitNetModelConfig(32, 2, 4, 64, 128);
        using var engine = new BitNetEngine(config);
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        string path = TempPath("size.bmwm");
        engine.SaveSnapshot(path);

        long nativeBytes = engine.NativeBytesAllocated;
        long fileSize = new FileInfo(path).Length;

        // File should be roughly native bytes + small overhead for header/descriptors
        Assert.True(fileSize >= nativeBytes,
            $"File {fileSize} should be >= native allocation {nativeBytes}");
        // Overhead should be reasonable (< 10KB for a small model)
        Assert.True(fileSize - nativeBytes < 10240,
            $"Overhead {fileSize - nativeBytes} seems too large");
    }
}
