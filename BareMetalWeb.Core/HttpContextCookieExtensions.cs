using Microsoft.AspNetCore.Http;
using BareMetalWeb.Core;

namespace BareMetalWeb.Host;

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

    // ── BmwContext overloads ────────────────────────────────────────────

    public static string? GetCookie(this BmwContext context, string name)
        => context.HttpContext.GetCookie(name);

    public static void SetCookie(this BmwContext context, string name, string value, CookieOptions? options = null)
        => context.HttpContext.SetCookie(name, value, options);

    public static void DeleteCookie(this BmwContext context, string name)
        => context.HttpContext.DeleteCookie(name);
}
