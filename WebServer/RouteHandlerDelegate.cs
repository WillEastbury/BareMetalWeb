using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.WebServer;

public delegate ValueTask RouteHandlerDelegate(HttpContext context); // handlers read PageInfo/App from HttpContext
