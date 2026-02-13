using System;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Data;
using Microsoft.AspNetCore.Http;
using System.Linq;

namespace BareMetalWeb.Host;

public static class UserAuth
{
    public const string SessionCookieName = "session_id";
    private static readonly TimeSpan DefaultSessionLifetime = TimeSpan.FromHours(8);
    private static readonly TimeSpan RememberMeLifetime = TimeSpan.FromDays(30);

    // Note: Session expiration uses a fixed TTL model (not sliding window).
    // Sessions expire at ExpiresUtc regardless of activity. Active users will be
    // logged out after the TTL expires even with continuous use. This is intentional
    // for simplicity and predictable session lifetimes. To implement sliding expiration,
    // update LastSeenUtc and extend ExpiresUtc on each request.
    public static async ValueTask<UserSession?> GetSessionAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        if (context == null) throw new ArgumentNullException(nameof(context));

        var protectedSessionId = context.GetCookie(SessionCookieName);
        if (string.IsNullOrWhiteSpace(protectedSessionId))
            return null;

        var sessionId = CookieProtection.Unprotect(protectedSessionId);
        if (string.IsNullOrWhiteSpace(sessionId))
        {
            context.DeleteCookie(SessionCookieName);
            return null;
        }

        var session = await DataStoreProvider.Current.LoadAsync<UserSession>(sessionId, cancellationToken).ConfigureAwait(false);
        if (session == null)
            return null;

        if (string.IsNullOrWhiteSpace(session.UserId))
        {
            session.IsRevoked = true;
            await DataStoreProvider.Current.SaveAsync(session, cancellationToken).ConfigureAwait(false);
            context.DeleteCookie(SessionCookieName);
            return null;
        }

        if (session.IsExpired(DateTime.UtcNow))
        {
            session.IsRevoked = true;
            await DataStoreProvider.Current.SaveAsync(session, cancellationToken).ConfigureAwait(false);
            context.DeleteCookie(SessionCookieName);
            return null;
        }

        return session;
    }

    public static async ValueTask<User?> GetUserAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        var session = await GetSessionAsync(context, cancellationToken).ConfigureAwait(false);
        if (session == null)
            return null;

        var user = await Users.GetByIdAsync(session.UserId, cancellationToken).ConfigureAwait(false);
        if (user == null || !user.IsActive)
            return null;

        return user;
    }

    public static async ValueTask<User?> GetRequestUserAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        var sessionUser = await GetUserAsync(context, cancellationToken).ConfigureAwait(false);
        if (sessionUser != null)
            return sessionUser;

        if (!IsApiRequest(context))
            return null;

        if (!TryGetApiKey(context, out var apiKey))
            return null;

        return await SystemPrincipal.FindByApiKeyAsync(apiKey, cancellationToken).ConfigureAwait(false);
    }

    public static async ValueTask SignInAsync(HttpContext context, User user, bool rememberMe, CancellationToken cancellationToken = default)
    {
        if (context == null) throw new ArgumentNullException(nameof(context));
        if (user == null) throw new ArgumentNullException(nameof(user));

        var now = DateTime.UtcNow;
        var session = new UserSession
        {
            UserId = user.Id,
            UserName = user.UserName,
            DisplayName = user.DisplayName,
            Permissions = user.Permissions ?? Array.Empty<string>(),
            IssuedUtc = now,
            LastSeenUtc = now,
            ExpiresUtc = now.Add(rememberMe ? RememberMeLifetime : DefaultSessionLifetime),
            RememberMe = rememberMe,
            CreatedBy = user.UserName,
            UpdatedBy = user.UserName
        };

        await DataStoreProvider.Current.SaveAsync(session, cancellationToken).ConfigureAwait(false);

        var options = new CookieOptions
        {
            HttpOnly = true,
            Secure = context.Request.IsHttps,
            SameSite = SameSiteMode.Lax
        };

        if (rememberMe)
            options.Expires = session.ExpiresUtc;

        var protectedSessionId = CookieProtection.Protect(session.Id);
        context.SetCookie(SessionCookieName, protectedSessionId, options);
    }

    public static async ValueTask SignOutAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        if (context == null) throw new ArgumentNullException(nameof(context));

        var session = await GetSessionAsync(context, cancellationToken).ConfigureAwait(false);
        if (session != null)
        {
            session.IsRevoked = true;
            await DataStoreProvider.Current.SaveAsync(session, cancellationToken).ConfigureAwait(false);
        }

        context.DeleteCookie(SessionCookieName);
    }

    private static bool IsApiRequest(HttpContext context)
    {
        return context.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase);
    }

    private static bool TryGetApiKey(HttpContext context, out string apiKey)
    {
        apiKey = string.Empty;
        if (!context.Request.Headers.TryGetValue("Authorization", out var authValues))
            return false;

        var header = authValues.ToString().Trim();
        if (string.IsNullOrWhiteSpace(header))
            return false;

        const string prefix = "ApiKey ";
        if (!header.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return false;

        apiKey = header[prefix.Length..].Trim();
        return !string.IsNullOrWhiteSpace(apiKey);
    }
}
