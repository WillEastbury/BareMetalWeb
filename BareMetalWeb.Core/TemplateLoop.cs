using System.Collections.Generic;

namespace BareMetalWeb.Rendering;

public record TemplateLoop(string Key, IReadOnlyList<IReadOnlyDictionary<string, string>> Items);
