namespace BareMetalWeb.Intelligence.Interfaces;

/// <summary>
/// Executes a tool action identified by intent classification.
/// </summary>
public interface IToolExecutor
{
    /// <summary>
    /// Execute the tool associated with the given intent.
    /// </summary>
    ValueTask<ToolResult> ExecuteAsync(
        string intentName,
        IReadOnlyDictionary<string, string> parameters,
        CancellationToken ct = default);

    /// <summary>
    /// Get all registered tool definitions.
    /// </summary>
    IReadOnlyList<ToolDefinition> GetTools();
}

/// <summary>
/// Definition of an available tool.
/// </summary>
public readonly record struct ToolDefinition(
    string Name,
    string Description,
    IReadOnlyList<ToolParameter> Parameters
);

/// <summary>
/// Parameter definition for a tool.
/// </summary>
public readonly record struct ToolParameter(
    string Name,
    string Description,
    bool Required
);

/// <summary>
/// Result of a tool execution.
/// </summary>
public readonly record struct ToolResult(
    bool Success,
    string Output,
    string? ErrorMessage = null
)
{
    public static ToolResult Ok(string output) => new(true, output);
    public static ToolResult Fail(string error) => new(false, string.Empty, error);
}
