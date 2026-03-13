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

    private static IntelligenceOrchestrator CreateOrchestratorWithRouting()
    {
        var engine = new BitNetEngine();
        engine.LoadTestModel(ModelLoadOptions.NoPruning);

        var tools = AdminToolCatalogue.CreateRegistry();

        return new IntelligenceOrchestrator(engine, tools);
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

    // ── Tool routing tests ────────────────────────────────────────────────────

    [Fact]
    public async Task ProcessAsync_WithRouting_CreateTodo_RoutesToTodoTool()
    {
        var orch = CreateOrchestratorWithRouting();

        var response = await orch.ProcessAsync("create a todo");

        // "create a todo" should route to a tool rather than returning the raw BitNet
        // spike diagnostic. The response must be actionable (not "[BitNet spike] ...").
        Assert.DoesNotContain("[BitNet spike]", response.Message);
        Assert.NotEqual("bitnet-generate", response.ResolvedIntent);
        Assert.True(response.Confidence > 0f, "Confidence should be positive for a matched intent");
    }

    [Fact]
    public async Task ProcessAsync_WithRouting_Todo_RoutesDirectlyToTodoTool()
    {
        var orch = CreateOrchestratorWithRouting();

        var response = await orch.ProcessAsync("todo");

        Assert.Equal("create-todo", response.ResolvedIntent);
        Assert.Contains("/todo-items/new", response.Message);
    }

    [Fact]
    public async Task ProcessAsync_WithRouting_Greeting_RoutesToGreetingTool()
    {
        var orch = CreateOrchestratorWithRouting();

        var response = await orch.ProcessAsync("hello");

        Assert.Equal("greeting", response.ResolvedIntent);
        Assert.True(response.Confidence >= 0.7f, "Greeting confidence should be high");
        Assert.Contains("Hello", response.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ProcessAsync_WithRouting_Farewell_RoutesToFarewellTool()
    {
        var orch = CreateOrchestratorWithRouting();

        var response = await orch.ProcessAsync("bye");

        Assert.Equal("farewell", response.ResolvedIntent);
        Assert.Contains("Goodbye", response.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ProcessAsync_WithRouting_Help_RoutesToHelpTool()
    {
        var orch = CreateOrchestratorWithRouting();

        var response = await orch.ProcessAsync("help");

        Assert.Equal("help", response.ResolvedIntent);
        Assert.NotEmpty(response.Message);
    }

    [Fact]
    public async Task ProcessAsync_WithoutRouting_NoBitNetFallbackUnaffected()
    {
        // Without classifier/tools the engine is always used.
        // The engine now produces real generated tokens (not the old spike diagnostic).
        var orch = CreateOrchestrator();

        var response = await orch.ProcessAsync("create a todo");

        Assert.Equal("bitnet-generate", response.ResolvedIntent);
        Assert.NotEmpty(response.Message);
        Assert.DoesNotContain("[BitNet spike]", response.Message);
    }

    [Fact]
    public async Task ProcessAsync_WithRouting_EmptyQuery_StillReturnsPrompt()
    {
        var orch = CreateOrchestratorWithRouting();

        var response = await orch.ProcessAsync("");

        Assert.Contains("Please enter", response.Message);
        Assert.Equal("none", response.ResolvedIntent);
    }
}
