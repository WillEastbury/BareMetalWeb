using BareMetalWeb.Intelligence;
using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence.Tests;

public class IntelligenceOrchestratorTests
{
    private static IntelligenceOrchestrator CreateOrchestrator(bool withBitNet = false)
    {
        var intents = AdminToolCatalogue.GetIntentDefinitions();
        var classifier = new KeywordIntentClassifier(intents);
        var executor = AdminToolCatalogue.CreateRegistry();

        BitNetEngine? engine = null;
        if (withBitNet)
        {
            engine = new BitNetEngine();
            engine.LoadTestModel(ModelLoadOptions.NoPruning);
        }

        return new IntelligenceOrchestrator(classifier, executor, engine);
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
    public async Task ProcessAsync_HelpQuery_ReturnsHelpMessage()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("help what can you do");

        Assert.Contains("Available commands", response.Message);
        Assert.Equal("help", response.ResolvedIntent);
    }

    [Fact]
    public async Task ProcessAsync_SystemStatus_ReturnsMemoryInfo()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("system status");

        Assert.Contains("System Status", response.Message);
        Assert.Equal("system-status", response.ResolvedIntent);
    }

    [Fact]
    public async Task ProcessAsync_Gibberish_WithBitNet_FallsThrough()
    {
        var orch = CreateOrchestrator(withBitNet: true);

        var response = await orch.ProcessAsync("xyzzy plugh completely random nonsensical input");

        // Should fall through to BitNet engine
        Assert.True(
            response.ResolvedIntent == "bitnet-generate" ||
            response.ResolvedIntent == "unknown" ||
            response.Message.Contains("BitNet") ||
            response.Message.Contains("didn't understand"),
            $"Expected fallback but got intent '{response.ResolvedIntent}'");
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

        Assert.Contains("Available commands", response.Message);
    }
}
