using System.Collections.Generic;
using System.Net;

namespace BareMetalWeb.Host;

public static class RouteInfoHelpers
{
    public static RouteHandlerData InjectRouteParametersIntoPageInfo(RouteHandlerData routeHandler, Dictionary<string, string> routeParams)
    {
        if (routeParams == null || routeParams.Count == 0)
            return routeHandler;

        var newKeys = new List<string>(routeHandler.PageInfo!.PageContext.PageMetaDataKeys);
        var newValues = new List<string>(routeHandler.PageInfo!.PageContext.PageMetaDataValues);
        foreach (var param in routeParams)
        {
            newKeys.Add(param.Key);
            newValues.Add(WebUtility.HtmlEncode(param.Value));
        }
        return routeHandler with
        {
            PageInfo = routeHandler.PageInfo with
            {
                PageContext = routeHandler.PageInfo.PageContext with
                {
                    PageMetaDataKeys = newKeys.ToArray(),
                    PageMetaDataValues = newValues.ToArray()
                }
            }
        };
    }
}