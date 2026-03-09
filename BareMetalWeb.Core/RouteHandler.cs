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

    /// <summary>
    /// Dense numeric route ID for O(1) array dispatch.
    /// Assigned at registration time. Clients can call /{RouteId} to bypass string routing.
    /// </summary>
    public ushort RouteId { get; set; }

    /// <summary>
    /// The original route key string (e.g. "GET /login") for metadata export.
    /// </summary>
    public string? RouteKey { get; set; }

    public RouteHandlerData(PageInfo? pageInfo, RouteHandlerDelegate handler)
    {
        Handler = handler;
        PageInfo = pageInfo;
        CompiledPlans = null;
        RouteId = 0;
        RouteKey = null;
    }
}
