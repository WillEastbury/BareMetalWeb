using BareMetalWeb.Core;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Rendering;

public sealed class PageInfoFactory : IPageInfoFactory
{
    public PageInfo TemplatedPage(IHtmlTemplate mainTemplate, int statusCode, string[] pageMetaDataKeys, string[] pageMetaDataValues, string permissionsNeeded, bool showOnNavBar, int CacheExpiryInSeconds, string? navGroup = null, NavAlignment navAlignment = NavAlignment.Left, NavRenderStyle navRenderStyle = NavRenderStyle.Link, string? navColorClass = null)
    {
        return new PageInfo(
            new PageMetaData(mainTemplate, statusCode, permissionsNeeded, showOnNavBar, CacheExpiryInSeconds),
            new PageContext(pageMetaDataKeys, pageMetaDataValues, NavGroup: navGroup, NavAlignment: navAlignment, NavRenderStyle: navRenderStyle, NavColorClass: navColorClass)
        );
    }
    public PageInfo RawPage(string permissionsNeeded, bool showOnNavBar, string? navGroup = null, NavAlignment navAlignment = NavAlignment.Left, NavRenderStyle navRenderStyle = NavRenderStyle.Link, string? navColorClass = null, string? navLabel = null)
    {
        var labelKeys = navLabel != null ? new[] { "title" } : Array.Empty<string>();
        var labelValues = navLabel != null ? new[] { navLabel } : Array.Empty<string>();
        return new PageInfo(
            new PageMetaData(null!, 200, permissionsNeeded, showOnNavBar, 0),
            new PageContext(labelKeys, labelValues, NavGroup: navGroup, NavAlignment: navAlignment, NavRenderStyle: navRenderStyle, NavColorClass: navColorClass)
        );
    }
}
