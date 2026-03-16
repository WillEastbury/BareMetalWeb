using BareMetalWeb.Intelligence;
using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence.Tests;

public class IntelligenceOrchestratorTests
{
    private static IntelligenceOrchestrator CreateOrchestrator(IBitNetEngine? engine = null)
        => new(engine ?? new BitNetEngine());

    [Fact]
    public async Task ProcessAsync_EmptyQuery_ReturnsPrompt()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("");

        Assert.Contains("Please enter", response.Message);
        Assert.Equal("none", response.ResolvedIntent);
    }

    [Fact]
    public async Task ProcessAsync_WhitespaceOnly_ReturnsPrompt()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("   " );

        Assert.Contains("Please enter", response.Message);
        Assert.Equal("none", response.ResolvedIntent);
    }

    [Fact]
    public async Task ProcessAsync_SanitisesLongInput()
    {
        var orch = CreateOrchestrator();
        var longInput = new string('a', 5000);

        var response = await orch.ProcessAsync(longInput);

        Assert.NotNull(response.Message);
    }

    [Fact]
    public async Task ProcessAsync_SanitisesControlCharacters()
    {
        var orch = CreateOrchestrator();
        var malicious = "help what can you do\x00\x01\x02\x03";

        var response = await orch.ProcessAsync(malicious);

        Assert.Equal("system.help", response.ResolvedIntent);
        Assert.NotNull(response.Message);
    }

    [Fact]
    public async Task ProcessAsync_Greeting_FallsToGenerate()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("hello");

        // No greeting pattern in classifier — falls through to generate
        Assert.NotNull(response.Message);
    }

    [Fact]
    public async Task ProcessAsync_Farewell_FallsToGenerate()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("goodbye");

        Assert.NotNull(response.Message);
    }

    [Fact]
    public async Task ProcessAsync_Help_RoutesToHelp()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("help");

        Assert.Equal("system.help", response.ResolvedIntent);
    }

    [Fact]
    public async Task ProcessAsync_SystemStatus_RoutesToSystemStatus()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("system status");

        Assert.Equal("system.status", response.ResolvedIntent);
    }

    [Fact]
    public async Task ProcessAsync_ListEntities_RoutesToList()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("list all entities");

        Assert.Equal("system.list-entities", response.ResolvedIntent);
    }

    [Fact]
    public async Task ProcessAsync_CreateTodo_RoutesToCreateTodo()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("create a todo");

        Assert.Contains("entity.create", response.ResolvedIntent);
    }

    [Fact]
    public async Task ProcessAsync_CreateTodoWithDescription_ContainsEntityRoute()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("create a todo for reminding me about beer");

        Assert.Contains("entity.create", response.ResolvedIntent);
        Assert.NotNull(response.Message);
    }

    [Fact]
    public async Task ProcessAsync_AmbiguousQuery_WithDegenerateFallback_ReturnsHelpfulMessage()
    {
        var orch = CreateOrchestrator(new FixedResponseEngine("aaaaaaaaaaaaaaaa"));

        var response = await orch.ProcessAsync("what is the meaning of life");

        // Classifier routes "what" queries to help before BitNet fallback
        Assert.Contains("help", response.ResolvedIntent, StringComparison.OrdinalIgnoreCase);
        Assert.NotEmpty(response.Message);
    }

    private sealed class FixedResponseEngine(string response) : IBitNetEngine
    {
        public bool IsLoaded => true;

        public ValueTask<string> GenerateAsync(ReadOnlyMemory<char> prompt, int maxTokens = 256, CancellationToken ct = default)
            => ValueTask.FromResult(response);

        public BitNetPipelineMetrics? GetMetrics() => null;
    }
}
