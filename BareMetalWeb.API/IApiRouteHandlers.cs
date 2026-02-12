using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.API;

public interface IApiRouteHandlers
{
    ValueTask DataApiListHandler(HttpContext context);
    ValueTask DataApiGetHandler(HttpContext context);
    ValueTask DataApiPostHandler(HttpContext context);
    ValueTask DataApiPutHandler(HttpContext context);
    ValueTask DataApiPatchHandler(HttpContext context);
    ValueTask DataApiDeleteHandler(HttpContext context);
    ValueTask MetricsJsonHandler(HttpContext context);
}
