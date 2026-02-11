namespace BareMetalWeb.Rendering.Models;

public sealed record FormDefinition(
    string Action,
    string Method,
    string SubmitLabel,
    IReadOnlyList<FormField> Fields
);
