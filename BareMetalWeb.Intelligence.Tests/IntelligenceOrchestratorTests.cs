using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Intelligence.Tests;

public class IntelligenceOrchestratorTests
{
    private static IntelligenceOrchestrator CreateOrchestrator()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(ModelLoadOptions.NoPruning);
        return new IntelligenceOrchestrator(engine);
    }

    [Fact]
    public async Task ProcessAsync_EmptyQuery_ReturnsPrompt()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("");

        Assert.Contains("Please enter", response.Message);
        Assert.Equal("none", response.ResolvedIntent);
    }

    [Fact]
    public async Task ProcessAsync_ValidQuery_UsesBitNetEngine()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("system status");

        Assert.Equal("bitnet-generate", response.ResolvedIntent);
        Assert.Equal(0f, response.Confidence);
        Assert.NotNull(response.Message);
    }

    [Fact]
    public async Task ProcessAsync_AnyQuery_ReturnsInferenceResult()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("hello");

        Assert.Equal("bitnet-generate", response.ResolvedIntent);
        Assert.NotEmpty(response.Message);
    }

    [Fact]
    public async Task ProcessAsync_SanitisesLongInput()
    {
        var orch = CreateOrchestrator();
        var longInput = new string('a', 5000);

        var response = await orch.ProcessAsync(longInput);

        // Should not throw, input is truncated internally
        Assert.NotNull(response.Message);
    }

    [Fact]
    public async Task ProcessAsync_SanitisesControlCharacters()
    {
        var orch = CreateOrchestrator();
        var malicious = "help what can you do\x00\x01\x02\x03";

        var response = await orch.ProcessAsync(malicious);

        Assert.Equal("bitnet-generate", response.ResolvedIntent);
        Assert.NotNull(response.Message);
    }

    [Fact]
    public async Task ProcessAsync_WhitespaceOnly_ReturnsPrompt()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("   ");

        Assert.Contains("Please enter", response.Message);
        Assert.Equal("none", response.ResolvedIntent);
    }

    [Fact]
    public async Task ProcessAsync_AlwaysUsesBitNetEngine()
    {
        // Without a classifier, all queries go through the BitNet engine.
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("create a todo");

        Assert.Equal("bitnet-generate", response.ResolvedIntent);
        Assert.NotEmpty(response.Message);
        Assert.DoesNotContain("[BitNet spike]", response.Message);
    }
}
