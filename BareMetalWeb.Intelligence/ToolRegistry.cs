using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Registry of available admin tools with parameter schemas.
/// Maps intent names to executable tool definitions.
/// </summary>
public sealed class ToolRegistry : IToolExecutor
{
    private readonly Dictionary<string, RegisteredTool> _tools = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Register a tool with its handler function.
    /// </summary>
    public void Register(
        string name,
        string description,
        IReadOnlyList<ToolParameter> parameters,
        Func<IReadOnlyDictionary<string, string>, CancellationToken, ValueTask<ToolResult>> handler)
    {
        _tools[name] = new RegisteredTool(
            new ToolDefinition(name, description, parameters),
            handler);
    }

    public IReadOnlyList<ToolDefinition> GetTools()
    {
        var result = new ToolDefinition[_tools.Count];
        int i = 0;
        foreach (var kvp in _tools)
            result[i++] = kvp.Value.Definition;
        return result;
    }

    public async ValueTask<ToolResult> ExecuteAsync(
        string intentName,
        IReadOnlyDictionary<string, string> parameters,
        CancellationToken ct = default)
    {
        if (!_tools.TryGetValue(intentName, out var tool))
            return ToolResult.Fail($"Unknown tool: {intentName}");

        try
        {
            return await tool.Handler(parameters, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return ToolResult.Fail("Operation cancelled");
        }
        catch (Exception ex)
        {
            // Log but don't leak internal details
            return ToolResult.Fail($"Tool execution failed: {ex.Message}");
        }
    }

    private readonly record struct RegisteredTool(
        ToolDefinition Definition,
        Func<IReadOnlyDictionary<string, string>, CancellationToken, ValueTask<ToolResult>> Handler
    );
}
