using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Core.Delegates;

public delegate ValueTask RouteHandlerDelegate(HttpContext context); // handlers read PageInfo/App from HttpContext
public delegate Task PageRequestHandler(HttpContext ctx);