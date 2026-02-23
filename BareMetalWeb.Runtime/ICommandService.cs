namespace BareMetalWeb.Runtime;

/// <summary>
/// Unified command facade that executes create, update, delete and named action
/// operations against any registered entity — both compiled and runtime-defined.
/// </summary>
public interface ICommandService
{
    /// <summary>
    /// Executes the supplied <paramref name="intent"/> and returns the result.
    /// Never throws; errors are surfaced via <see cref="CommandResult.Success"/> = false.
    /// </summary>
    ValueTask<CommandResult> ExecuteAsync(CommandIntent intent, CancellationToken cancellationToken = default);
}
