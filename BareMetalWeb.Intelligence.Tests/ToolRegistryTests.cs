using BareMetalWeb.Intelligence;
using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence.Tests;

public class ToolRegistryTests
{
    [Fact]
    public async Task ExecuteAsync_RegisteredTool_ReturnsSuccess()
    {
        // Arrange
        var registry = new ToolRegistry();
        registry.Register(
            "test-tool",
            "A test tool",
            [new ToolParameter("name", "test param", false)],
            (p, ct) => ValueTask.FromResult(ToolResult.Ok("Hello from test")));

        // Act
        var result = await registry.ExecuteAsync("test-tool", new Dictionary<string, string>());

        // Assert
        Assert.True(result.Success);
        Assert.Equal("Hello from test", result.Output);
    }

    [Fact]
    public async Task ExecuteAsync_UnknownTool_ReturnsFail()
    {
        var registry = new ToolRegistry();

        var result = await registry.ExecuteAsync("nonexistent", new Dictionary<string, string>());

        Assert.False(result.Success);
        Assert.Contains("Unknown tool", result.ErrorMessage);
    }

    [Fact]
    public async Task ExecuteAsync_ThrowingHandler_ReturnsFail()
    {
        var registry = new ToolRegistry();
        registry.Register(
            "bad-tool",
            "Throws",
            [],
            (p, ct) => throw new InvalidOperationException("boom"));

        var result = await registry.ExecuteAsync("bad-tool", new Dictionary<string, string>());

        Assert.False(result.Success);
        Assert.Contains("InvalidOperationException", result.ErrorMessage);
    }

    [Fact]
    public void GetTools_ReturnsAllRegistered()
    {
        var registry = new ToolRegistry();
        registry.Register("a", "Tool A", [], (p, ct) => ValueTask.FromResult(ToolResult.Ok("")));
        registry.Register("b", "Tool B", [], (p, ct) => ValueTask.FromResult(ToolResult.Ok("")));

        var tools = registry.GetTools();

        Assert.Equal(2, tools.Count);
    }

    [Fact]
    public void AdminToolCatalogue_CreateRegistry_HasExpectedTools()
    {
        var registry = AdminToolCatalogue.CreateRegistry();
        var tools = registry.GetTools();

        Assert.True(tools.Count >= 6);
        Assert.Contains(tools, t => t.Name == "list-entities");
        Assert.Contains(tools, t => t.Name == "describe-entity");
        Assert.Contains(tools, t => t.Name == "query-entity");
        Assert.Contains(tools, t => t.Name == "system-status");
        Assert.Contains(tools, t => t.Name == "index-status");
        Assert.Contains(tools, t => t.Name == "help");
    }

    [Fact]
    public async Task HelpTool_ReturnsAvailableCommands()
    {
        var registry = AdminToolCatalogue.CreateRegistry();

        var result = await registry.ExecuteAsync("help", new Dictionary<string, string>());

        Assert.True(result.Success);
        Assert.Contains("Available commands", result.Output);
    }
}
