using BareMetalWeb.Data;

namespace BareMetalWeb.Core;

/// <summary>
/// Describes a remote command method exposed on a data entity.
/// The <see cref="Invoker"/> delegate is pre-compiled at startup (no per-request reflection).
/// It is <c>null</c> for runtime-defined (workflow) actions, which are dispatched via
/// <see cref="BareMetalWeb.Runtime.CommandService"/> instead.
/// </summary>
public sealed record RemoteCommandMetadata(
    Func<object, ValueTask<RemoteCommandResult>>? Invoker,
    string Name,
    string Label,
    string? Icon,
    string? ConfirmMessage,
    bool Destructive,
    string? Permission,
    bool OverrideEntityPermissions,
    int Order
);
