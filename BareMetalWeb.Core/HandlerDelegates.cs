using BareMetalWeb.Core;

namespace BareMetalWeb.Core.Delegates;

public delegate ValueTask RouteHandlerDelegate(BmwContext context);
public delegate Task PageRequestHandler(BmwContext ctx);