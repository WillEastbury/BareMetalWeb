using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.WebServer;

public static class CsrfProtection
{
    public const string CookieName = "csrf_token";
    public const string FormFieldName = "csrf_token";

    public static string EnsureToken(HttpContext context)
    {
        if (context == null) throw new ArgumentNullException(nameof(context));

        var existing = context.GetCookie(CookieName);
        if (!string.IsNullOrWhiteSpace(existing))
            return existing;

        var token = GenerateToken();
        var options = new CookieOptions
        {
            HttpOnly = true,
            Secure = context.Request.IsHttps,
            SameSite = SameSiteMode.Lax
        };

        context.SetCookie(CookieName, token, options);
        return token;
    }

    public static bool ValidateFormToken(HttpContext context, IFormCollection form)
    {
        if (context == null) throw new ArgumentNullException(nameof(context));
        if (form == null) throw new ArgumentNullException(nameof(form));

        var cookieToken = context.GetCookie(CookieName);
        if (string.IsNullOrWhiteSpace(cookieToken))
            return false;

        if (!form.TryGetValue(FormFieldName, out var formTokenValues))
            return false;

        var formToken = formTokenValues.ToString();
        if (string.IsNullOrWhiteSpace(formToken))
            return false;

        return FixedTimeEquals(cookieToken, formToken);
    }

    private static string GenerateToken()
    {
        Span<byte> buffer = stackalloc byte[32];
        RandomNumberGenerator.Fill(buffer);
        return Base64UrlEncode(buffer);
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> input)
    {
        var base64 = Convert.ToBase64String(input);
        return base64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    private static bool FixedTimeEquals(string left, string right)
    {
        var leftBytes = Encoding.UTF8.GetBytes(left);
        var rightBytes = Encoding.UTF8.GetBytes(right);
        if (leftBytes.Length != rightBytes.Length)
            return false;

        return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }
}
