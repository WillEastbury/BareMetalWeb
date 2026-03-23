using System;
using System.Security.Cryptography;
using System.Text;
using BareMetalWeb.Core;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

public static class CsrfProtection
{
    public const string CookieName = "csrf_token";
    public const string FormFieldName = "csrf_token";

    public static string EnsureToken(BmwContext context)
    {
        if (context == null) throw new ArgumentNullException(nameof(context));

        var existing = context.GetCookie(CookieName);
        if (!string.IsNullOrWhiteSpace(existing))
            return existing;

        var token = GenerateToken();
        var options = new CookieOptions
        {
            HttpOnly = true,
            Secure = context.HttpRequest.IsHttps,
            SameSite = SameSiteMode.Strict,
            Expires = DateTimeOffset.UtcNow.AddHours(1)
        };

        context.SetCookie(CookieName, token, options);
        return token;
    }

    public static bool ValidateFormToken(BmwContext context, IFormCollection form)
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

    public const string ApiTokenHeaderName = "X-CSRF-Token";

    /// <summary>
    /// Validates CSRF for API requests using double-submit cookie pattern.
    /// Token is read from the X-CSRF-Token header instead of a form field.
    /// Requests authenticated via an API key header bypass this check because
    /// CSRF attacks rely on browser session cookies and cannot forge explicit API key headers.
    /// </summary>
    public static bool ValidateApiToken(BmwContext context)
    {
        if (context == null) throw new ArgumentNullException(nameof(context));

        // API key requests are not susceptible to CSRF; bypass the token check.
        if (UserAuth.HasApiKeyHeader(context))
            return true;

        var cookieToken = context.GetCookie(CookieName);
        if (string.IsNullOrWhiteSpace(cookieToken))
            return false;

        var headerToken = context.HttpRequest.Headers[ApiTokenHeaderName].ToString();
        if (string.IsNullOrWhiteSpace(headerToken))
            return false;

        return FixedTimeEquals(cookieToken, headerToken);
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
