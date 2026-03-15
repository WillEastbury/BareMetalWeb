using BareMetalWeb.Intelligence;
using BareMetalWeb.Intelligence.Interfaces;

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
    public async Task ProcessAsync_ValidQuery_SystemStatus_RoutedByClassifier()
    {
        // "system status" is a known pattern — classifier routes it directly without the engine.
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("system status");

        Assert.Equal("system.status", response.ResolvedIntent);
        Assert.True(response.Confidence >= 0.6f);
        Assert.NotNull(response.Message);
    }

    [Fact]
    public async Task ProcessAsync_AnyQuery_ReturnsInferenceResult()
    {
        // Queries that don't match any keyword pattern fall through to the BitNet engine.
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("hello");

        // Unknown query — falls through to BitNet or returns low-confidence result.
        Assert.NotNull(response.Message);
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

        // Control characters are stripped; "help" triggers the classifier.
        Assert.NotNull(response.Message);
        Assert.NotEmpty(response.ResolvedIntent);
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
    public async Task ProcessAsync_KnownEntityAction_RoutedByClassifier()
    {
        // "create a user" is a known action+entity — classifier routes it directly.
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("create a user");

        Assert.StartsWith("entity.create.users", response.ResolvedIntent);
        Assert.True(response.Confidence >= 0.6f);
    }

    [Fact]
    public async Task ProcessAsync_ListEntities_RoutedToSystemIntent()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("list entities");

        Assert.Equal("system.list-entities", response.ResolvedIntent);
        Assert.True(response.Confidence >= 0.6f);
    }

    [Fact]
    public async Task ProcessAsync_LowConfidenceQuery_FallsThroughToEngine()
    {
        // Queries with no keyword matches fall through to the BitNet engine.
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("xyzzy plugh");

        // No keyword match → BitNet fallback
        Assert.Equal("bitnet-generate", response.ResolvedIntent);
        Assert.NotEmpty(response.Message);
    }

    [Fact]
    public async Task ProcessAsync_AlwaysReturnsNonNullMessage()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("create a todo");

        // Whether routed via classifier or BitNet, message must be non-null.
        Assert.NotNull(response.Message);
        Assert.NotEmpty(response.ResolvedIntent);
        Assert.DoesNotContain("[BitNet spike]", response.Message);
    }
}
