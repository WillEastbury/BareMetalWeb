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
    public async Task ProcessAsync_WhitespaceOnly_ReturnsPrompt()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("   ");

        Assert.Contains("Please enter", response.Message);
        Assert.Equal("none", response.ResolvedIntent);
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

        // "what can you do" should classify as help
        Assert.Equal("help", response.ResolvedIntent);
        Assert.NotNull(response.Message);
    }

    // ── Intent classification routing ───────────────────────────────────────

    [Fact]
    public async Task ProcessAsync_Greeting_RoutesToGreeting()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("hello");

        Assert.Equal("greeting", response.ResolvedIntent);
        Assert.True(response.Confidence >= 0.9f);
    }

    [Fact]
    public async Task ProcessAsync_Farewell_RoutesToFarewell()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("goodbye");

        Assert.Equal("farewell", response.ResolvedIntent);
    }

    [Fact]
    public async Task ProcessAsync_Help_RoutesToHelp()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("help");

        Assert.Equal("help", response.ResolvedIntent);
    }

    [Fact]
    public async Task ProcessAsync_SystemStatus_RoutesToSystemStatus()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("system status");

        Assert.Equal("system-status", response.ResolvedIntent);
    }

    [Fact]
    public async Task ProcessAsync_ListEntities_RoutesToList()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("list all entities");

        Assert.Equal("list-entities", response.ResolvedIntent);
    }

    [Fact]
    public async Task ProcessAsync_CreateTodo_RoutesToCreateTodo()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("create a todo");

        Assert.Equal("create-todo", response.ResolvedIntent);
        Assert.Equal("/to-do/new", response.NavigateUrl);
    }

    [Fact]
    public async Task ProcessAsync_CreateTodoWithDescription_PrefillsFields()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("create a todo for reminding me about beer");

        Assert.Equal("create-todo", response.ResolvedIntent);
        Assert.Equal("/to-do/new", response.NavigateUrl);
        Assert.NotNull(response.PrefillFields);
        Assert.True(response.PrefillFields!.ContainsKey("Title"));
        Assert.Contains("beer", response.PrefillFields["Title"], StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ProcessAsync_AmbiguousQuery_FallsBackWithHelpfulMessage()
    {
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("what is the meaning of life");

        // Test model produces degenerate output, so we should get the fallback message
        Assert.Equal("bitnet-fallback", response.ResolvedIntent);
        Assert.Contains("help", response.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("tok_", response.Message);
    }
}
