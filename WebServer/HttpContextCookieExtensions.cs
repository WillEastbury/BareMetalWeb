using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.WebServer;

public static class HttpContextCookieExtensions
{
    public static string? GetCookie(this HttpContext context, string name)
    {
        return context.Request.Cookies.TryGetValue(name, out var value) ? value : null;
    }

    public static void SetCookie(this HttpContext context, string name, string value, CookieOptions? options = null)
    {
        options ??= new CookieOptions
        {
            HttpOnly = true,
            Secure = context.Request.IsHttps,
            SameSite = SameSiteMode.Lax
        };

        context.Response.Cookies.Append(name, value, options);
    }

    public static void DeleteCookie(this HttpContext context, string name)
    {
        context.Response.Cookies.Delete(name);
    }
}
