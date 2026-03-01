namespace BareMetalWeb.Runtime;

/// <summary>
/// Compiled, immutable descriptor for a server-side action.
/// Execution is performed by <see cref="ICommandService"/>.
/// </summary>
/// <param name="ActionId">Stable identity (from <see cref="ActionDefinition.Id"/>).</param>
/// <param name="EntityId">Entity identity this action belongs to.</param>
/// <param name="Name">Canonical action name (used in POST /intent operation field).</param>
/// <param name="Label">Display label.</param>
/// <param name="Icon">Optional Bootstrap icon class.</param>
/// <param name="Permission">Optional permission token required to invoke this action.</param>
/// <param name="EnabledWhen">Optional boolean expression for client-side button state.</param>
/// <param name="Operations">Ordered list of legacy "SetField:Field=Value" operation strings (v1.0 compat).</param>
/// <param name="Commands">Structured v1.1 command primitives. When non-empty these take precedence over <paramref name="Operations"/>.</param>
/// <param name="Version">Schema version of the action definition.</param>
public sealed record RuntimeActionModel(
    string ActionId,
    string EntityId,
    string Name,
    string Label,
    string? Icon,
    string? Permission,
    string? EnabledWhen,
    IReadOnlyList<string> Operations,
    IReadOnlyList<ActionCommand> Commands,
    int Version = 1
);
