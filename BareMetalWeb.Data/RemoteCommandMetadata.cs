using System.Reflection;

namespace BareMetalWeb.Core;

public sealed record RemoteCommandMetadata(
    MethodInfo Method,
    string Name,
    string Label,
    string? Icon,
    string? ConfirmMessage,
    bool Destructive,
    string? Permission,
    bool OverrideEntityPermissions,
    int Order
);
