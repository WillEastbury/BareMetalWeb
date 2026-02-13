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

    // Note: Session expiration uses a sliding window model.
    // Sessions extend their expiration time with each access, keeping active users
    // logged in. The session lifetime is reset on each request.
    public static UserSession? GetSession(HttpContext context)
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

        var session = DataStoreProvider.Current.Load<UserSession>(sessionId);
        if (session == null)
            return null;

        if (string.IsNullOrWhiteSpace(session.UserId))
        {
            session.IsRevoked = true;
            DataStoreProvider.Current.Save(session);
            context.DeleteCookie(SessionCookieName);
            return null;
        }

        if (session.IsExpired(DateTime.UtcNow))
        {
            RevokeSession(session);
            context.DeleteCookie(SessionCookieName);
            return null;
        }

        // Update LastSeenUtc and extend ExpiresUtc for sliding expiration
        // Note: Session updates are not synchronized across concurrent requests.
        // In the rare case of simultaneous access, the last write wins. This is
        // acceptable for session management and avoids locking overhead.
        var now = DateTime.UtcNow;
        session.LastSeenUtc = now;
        session.ExpiresUtc = now.Add(session.RememberMe ? RememberMeLifetime : DefaultSessionLifetime);
        DataStoreProvider.Current.Save(session);

        return session;
    }

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

        // Update LastSeenUtc and extend ExpiresUtc for sliding expiration
        // Note: Session updates are not synchronized across concurrent requests.
        // In the rare case of simultaneous access, the last write wins. This is
        // acceptable for session management and avoids locking overhead.
        var now = DateTime.UtcNow;
        session.LastSeenUtc = now;
        session.ExpiresUtc = now.Add(session.RememberMe ? RememberMeLifetime : DefaultSessionLifetime);
        await DataStoreProvider.Current.SaveAsync(session, cancellationToken).ConfigureAwait(false);

        return session;
    }

    public static User? GetUser(HttpContext context)
    {
        var session = GetSession(context);
        if (session == null)
            return null;

        var user = Users.GetById(session.UserId);
        if (user == null || !user.IsActive)
            return null;

        return user;
    }

    public static User? GetRequestUser(HttpContext context)
    {
        var sessionUser = GetUser(context);
        if (sessionUser != null)
            return sessionUser;

        if (!IsApiRequest(context))
            return null;

        if (!TryGetApiKey(context, out var apiKey))
            return null;

        return SystemPrincipal.FindByApiKey(apiKey);
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

        return await Task.FromResult(SystemPrincipal.FindByApiKey(apiKey));
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

    private static void RevokeSession(UserSession session)
    {
        session.IsRevoked = true;
        DataStoreProvider.Current.Save(session);
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
