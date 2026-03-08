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

        Assert.Contains("BitNet spike", result);
        Assert.Contains("Inference complete", result);
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

        Assert.Contains("Hidden dim: 64", result);
        Assert.Contains("layers: 2", result);
    }

    [Fact]
    public async Task GenerateAsync_ReportPromptLength()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        var result = await engine.GenerateAsync("hello world".AsMemory());

        Assert.Contains("Prompt length: 11 chars", result);
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

        Assert.Contains("pruned from", result);
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
}
