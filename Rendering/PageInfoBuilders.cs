using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Rendering;

public sealed class PageInfoFactory : IPageInfoFactory
{
    public PageInfo TemplatedPage(IHtmlTemplate mainTemplate, int statusCode, string[] pageMetaDataKeys, string[] pageMetaDataValues, string permissionsNeeded, bool showOnNavBar, int CacheExpiryInSeconds, string? navGroup = null, NavAlignment navAlignment = NavAlignment.Left, NavRenderStyle navRenderStyle = NavRenderStyle.Link, string? navColorClass = null)
    {
        return new PageInfo(
            new PageMetaData(mainTemplate, statusCode, permissionsNeeded, showOnNavBar, CacheExpiryInSeconds),
            new PageContext(pageMetaDataKeys, pageMetaDataValues, NavGroup: navGroup, NavAlignment: navAlignment, NavRenderStyle: navRenderStyle, NavColorClass: navColorClass));
    }
    public PageInfo RawPage(string permissionsNeeded, bool showOnNavBar, string? navGroup = null, NavAlignment navAlignment = NavAlignment.Left, NavRenderStyle navRenderStyle = NavRenderStyle.Link, string? navColorClass = null)
    {
        return new PageInfo(
            new PageMetaData(null!, 200, permissionsNeeded, showOnNavBar, 0),
            new PageContext(Array.Empty<string>(), Array.Empty<string>(), NavGroup: navGroup, NavAlignment: navAlignment, NavRenderStyle: navRenderStyle, NavColorClass: navColorClass));
    }
}
