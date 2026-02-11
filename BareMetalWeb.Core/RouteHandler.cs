using BareMetalWeb.Core;
using BareMetalWeb.Core.Delegates;
using BareMetalWeb.Rendering;

namespace BareMetalWeb.Host;

public record struct RouteHandlerData
{
    public RouteHandlerDelegate Handler { get; init; }
    public PageInfo? PageInfo { get; set; }

    public RouteHandlerData(PageInfo? pageInfo, RouteHandlerDelegate handler)
    {
        Handler = handler;
        PageInfo = pageInfo;
    }
}
