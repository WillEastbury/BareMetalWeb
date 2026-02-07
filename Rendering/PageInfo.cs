using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Rendering;

public record PageMetaData(
    IHtmlTemplate Template,
    int StatusCode,
    string PermissionsNeeded = "", // AKA Anonymous if empty, or comma-separated list of permissions if needed, and a special value of "AnonymousOnly" if it should only be shown to anonymous users and hidden from logged in users regardless of permissions)
    bool ShowOnNavBar = true,
    int CacheExpiryInSeconds = -1 // in seconds; -1 means do not cache, 0 means cache indefinitely, or int in seconds for expiry
);

public enum NavAlignment
{
    Left,
    Right
}

public enum NavRenderStyle
{
    Link,
    Button
}

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

public record PageInfo(
    PageMetaData PageMetaData,
    PageContext PageContext
);

public delegate Task PageRequestHandler(HttpContext ctx);