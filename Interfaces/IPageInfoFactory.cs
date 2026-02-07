using BareMetalWeb.Rendering;

namespace BareMetalWeb.Interfaces;

public interface IPageInfoFactory
{
    PageInfo TemplatedPage(IHtmlTemplate mainTemplate, int statusCode, string[] pageMetaDataKeys, string[] pageMetaDataValues, string permissionsNeeded, bool showOnNavBar, int cacheExpiryInSeconds, string? navGroup = null, NavAlignment navAlignment = NavAlignment.Left, NavRenderStyle navRenderStyle = NavRenderStyle.Link, string? navColorClass = null);
    PageInfo RawPage(string permissionsNeeded, bool showOnNavBar, string? navGroup = null, NavAlignment navAlignment = NavAlignment.Left, NavRenderStyle navRenderStyle = NavRenderStyle.Link, string? navColorClass = null);
}
