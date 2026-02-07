using System.Collections.Generic;

namespace BareMetalWeb.Rendering;

public sealed record TemplateLoop(
    string Key,
    IReadOnlyList<IReadOnlyDictionary<string, string>> Items
);
