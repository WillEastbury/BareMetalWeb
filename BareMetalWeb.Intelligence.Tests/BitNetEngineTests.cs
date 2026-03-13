using BareMetalWeb.Intelligence;
using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence.Tests;

public class BitNetEngineTests
{
    [Fact]
    public void IsLoaded_BeforeLoad_ReturnsFalse()
    {
        var engine = new BitNetEngine();

        Assert.False(engine.IsLoaded);
    }

    [Fact]
    public void LoadTestModel_SetsIsLoaded()
    {
        var engine = new BitNetEngine();

        engine.LoadTestModel();

        Assert.True(engine.IsLoaded);
    }

    [Fact]
    public async Task GenerateAsync_NotLoaded_ReturnsNotLoadedMessage()
    {
        var engine = new BitNetEngine();

        var result = await engine.GenerateAsync("test prompt".AsMemory());

        Assert.Contains("not loaded", result, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GenerateAsync_Loaded_ReturnsInferenceResult()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        var result = await engine.GenerateAsync("what is the system status".AsMemory());

        Assert.NotEmpty(result);
        Assert.DoesNotContain("[BitNet spike]", result);
    }

    [Fact]
    public async Task GenerateAsync_CustomConfig_UsesConfiguredDimensions()
    {
        var config = new BitNetModelConfig(
            HiddenDim: 64,
            NumLayers: 2,
            NumHeads: 2,
            VocabSize: 128,
            MaxSeqLen: 256);
        var engine = new BitNetEngine(config);
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        var result = await engine.GenerateAsync("test".AsMemory());

        // Shape verified via metrics:
        Assert.Equal(2, engine.LayerStats!.Count);
    }

    [Fact]
    public async Task GenerateAsync_ReportPromptLength()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        var result = await engine.GenerateAsync("hello world".AsMemory());

        Assert.Equal(11, engine.GetMetrics()!.Value.TotalTokensIn);
    }

    [Fact]
    public void LoadTestModel_WithVocabPruning_PrunesVocabulary()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(ModelLoadOptions.Default); // Default = prune vocab

        Assert.True(engine.IsLoaded);
        Assert.NotNull(engine.VocabPruneStats);
        Assert.True(engine.VocabPruneStats.Value.PrunedVocabSize < engine.VocabPruneStats.Value.OriginalVocabSize,
            "Pruned vocab should be smaller than original");
        Assert.True(engine.VocabPruneStats.Value.BytesSaved > 0,
            "Should report bytes saved");
    }

    [Fact]
    public void LoadTestModel_AggressivePruning_PrunesLayersAndHeads()
    {
        var config = new BitNetModelConfig(
            HiddenDim: 64,
            NumLayers: 8,
            NumHeads: 4,
            VocabSize: 128,
            MaxSeqLen: 256);
        var engine = new BitNetEngine(config);
        engine.LoadTestModel(ModelLoadOptions.Aggressive);

        Assert.True(engine.IsLoaded);
        Assert.NotNull(engine.ModelStats);
        // 25% layer prune: 8 → 6 layers
        Assert.Equal(6, engine.ModelStats.Value.LayerCount);
        // Should have some sparsity from head pruning
        Assert.True(engine.ModelStats.Value.Sparsity > 0,
            "Head pruning should introduce sparsity");
    }

    [Fact]
    public async Task GenerateAsync_WithPruning_ReportsVocabStats()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(); // Default pruning

        var result = await engine.GenerateAsync("show me data".AsMemory());

        Assert.NotNull(engine.VocabPruneStats);
    }

    [Fact]
    public void LoadTestModel_NoPruning_NoStats()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        Assert.True(engine.IsLoaded);
        Assert.Null(engine.VocabPruneStats);
        Assert.NotNull(engine.ModelStats);
        Assert.Equal(256, engine.ModelStats.Value.EmbeddingWeights / 128 / 2);
    }

    // ── GetMetrics tests ─────────────────────────────────────────────────────

    [Fact]
    public void GetMetrics_NotLoaded_ReturnsNull()
    {
        var engine = new BitNetEngine();

        Assert.Null(engine.GetMetrics());
    }

    [Fact]
    public void GetMetrics_AfterLoad_ReturnsMemoryStats()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        var metrics = engine.GetMetrics();

        Assert.NotNull(metrics);
        Assert.True(metrics!.Value.OriginalWeightBytes > 0, "OriginalWeightBytes should be positive");
        Assert.True(metrics.Value.TrimmedWeightBytes > 0, "TrimmedWeightBytes should be positive");
        Assert.True(metrics.Value.TrimmedWeightBytes < metrics.Value.OriginalWeightBytes,
            "Packed 2-bit weights should be smaller than original sbyte[] weights");
        Assert.True(metrics.Value.CompressionSavings > 0f && metrics.Value.CompressionSavings < 1f,
            "CompressionSavings should be between 0 and 1");
    }

    [Fact]
    public void GetMetrics_AfterLoad_ReturnsModelShape()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        var metrics = engine.GetMetrics()!.Value;

        Assert.True(metrics.TotalWeights > 0);
        Assert.True(metrics.LayerCount > 0);
        Assert.True(metrics.EmbeddingWeights > 0);
        Assert.True(metrics.Sparsity >= 0f && metrics.Sparsity <= 1f);
    }

    [Fact]
    public async Task GetMetrics_AfterGenerate_TracksTokenCounters()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        const string prompt = "hello world";
        await engine.GenerateAsync(prompt.AsMemory());

        var metrics = engine.GetMetrics()!.Value;

        Assert.Equal(1, metrics.TotalRequests);
        Assert.Equal(prompt.Length, metrics.TotalTokensIn);
        Assert.True(metrics.TotalTokensOut > 0, "Should have output tokens after generate");
        Assert.True(metrics.TotalInferenceMs >= 0, "Inference time should be non-negative");
    }

    [Fact]
    public async Task GetMetrics_MultipleGenerates_AccumulatesCounters()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        await engine.GenerateAsync("first prompt".AsMemory());
        await engine.GenerateAsync("second prompt".AsMemory());

        var metrics = engine.GetMetrics()!.Value;

        Assert.Equal(2, metrics.TotalRequests);
        Assert.Equal("first prompt".Length + "second prompt".Length, metrics.TotalTokensIn);
    }

    [Fact]
    public void GetMetrics_WithVocabPruning_ReportsVocabSizes()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(); // Default includes vocab pruning

        var metrics = engine.GetMetrics()!.Value;

        Assert.True(metrics.OriginalVocabSize > 0);
        Assert.True(metrics.PrunedVocabSize > 0);
        Assert.True(metrics.PrunedVocabSize <= metrics.OriginalVocabSize,
            "Pruned vocab should be no larger than original");
    }

    [Fact]
    public void GetMetrics_WithSemanticPruning_ReportsAccuracy()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(new ModelLoadOptions
        {
            PruneVocabulary = false,
            SemanticPruning = true,
        });

        var metrics = engine.GetMetrics()!.Value;

        Assert.NotNull(metrics.PrePruneAccuracy);
        Assert.NotNull(metrics.PostPruneAccuracy);
        Assert.NotNull(metrics.SemanticTestCaseCount);
        Assert.True(metrics.PrePruneAccuracy >= 0f && metrics.PrePruneAccuracy <= 1f);
        Assert.True(metrics.PostPruneAccuracy >= 0f && metrics.PostPruneAccuracy <= 1f);
    }

    [Fact]
    public void GetMetrics_WithoutSemanticPruning_AccuracyFieldsAreNull()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        var metrics = engine.GetMetrics()!.Value;

        Assert.Null(metrics.PrePruneAccuracy);
        Assert.Null(metrics.PostPruneAccuracy);
        Assert.Null(metrics.SemanticTestCaseCount);
    }

    [Fact]
    public void GetMetrics_Summary_IsNonEmpty()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        var metrics = engine.GetMetrics()!.Value;

        Assert.False(string.IsNullOrWhiteSpace(metrics.Summary));
        Assert.Contains("Memory:", metrics.Summary);
        Assert.Contains("Tokens:", metrics.Summary);
    }
}
