using BareMetalWeb.Rendering;

namespace BareMetalWeb.WebServer;

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
