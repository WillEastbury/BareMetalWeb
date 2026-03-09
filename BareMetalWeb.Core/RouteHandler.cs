using BareMetalWeb.Core;
using BareMetalWeb.Core.Delegates;

namespace BareMetalWeb.Host;

public record struct RouteHandlerData
{
    public RouteHandlerDelegate Handler { get; init; }
    public PageInfo? PageInfo { get; set; }

    /// <summary>
    /// Pre-compiled render plans for this route's template sections.
    /// Set at jump-table build time. Null for raw/API routes.
    /// </summary>
    public RouteRenderPlans? CompiledPlans { get; set; }

    public RouteHandlerData(PageInfo? pageInfo, RouteHandlerDelegate handler)
    {
        Handler = handler;
        PageInfo = pageInfo;
        CompiledPlans = null;
    }
}
