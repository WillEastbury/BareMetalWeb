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
        engine.LoadTestModel();

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
        engine.LoadTestModel();

        var result = await engine.GenerateAsync("test".AsMemory());

        Assert.Contains("Hidden dim: 64", result);
        Assert.Contains("layers: 2", result);
    }

    [Fact]
    public async Task GenerateAsync_ReportPromptLength()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel();

        var result = await engine.GenerateAsync("hello world".AsMemory());

        Assert.Contains("Prompt length: 11 chars", result);
    }
}
