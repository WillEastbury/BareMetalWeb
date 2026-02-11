
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Models;

namespace BareMetalWeb.Core;

public record PageContext(
    string[] PageMetaDataKeys,
    string[] PageMetaDataValues,
    string[]? TableColumnTitles = null,
    string[][]? TableData = null,
    FormDefinition? FormDefinition = null,
    TemplateLoop[]? TemplateLoops = null,
    string? NavGroup = null,
    NavAlignment NavAlignment = NavAlignment.Left,
    NavRenderStyle NavRenderStyle = NavRenderStyle.Link,
    string? NavColorClass = null
);
