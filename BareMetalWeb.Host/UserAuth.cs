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

    // Session expiration uses a sliding window model.
    // Sessions extend their expiration time with each access, keeping active users
    // logged in. For RememberMe sessions, the cookie Expires is also reissued to
    // match the extended server-side expiry.
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

        if (!uint.TryParse(sessionId, out var sessionKey))
        {
            context.DeleteCookie(SessionCookieName);
            return null;
        }

        var session = DataStoreProvider.Current.Load<UserSession>(sessionKey);
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
            session.IsRevoked = true;
            DataStoreProvider.Current.Save(session);
            context.DeleteCookie(SessionCookieName);
            return null;
        }

        // Update LastSeenUtc and extend ExpiresUtc for sliding expiration.
        // Only persist when the new expiry meaningfully extends the session (> 1 minute gain).
        // This avoids high-frequency concurrent saves on burst requests, which can cause a
        // transient race where a concurrent Load reads a stale (already-moved) record location.
        var now = DateTime.UtcNow;
        var lifetime = session.RememberMe ? RememberMeLifetime : DefaultSessionLifetime;
        var newExpiry = now.Add(lifetime);
        session.LastSeenUtc = now;
        if (newExpiry - session.ExpiresUtc > TimeSpan.FromMinutes(1))
        {
            session.ExpiresUtc = newExpiry;
            DataStoreProvider.Current.Save(session);
            if (session.RememberMe)
                ReissueCookie(context, protectedSessionId, session.ExpiresUtc);
        }

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

        if (!uint.TryParse(sessionId, out var sessionKey))
        {
            context.DeleteCookie(SessionCookieName);
            return null;
        }

        var session = await DataStoreProvider.Current.LoadAsync<UserSession>(sessionKey, cancellationToken).ConfigureAwait(false);
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

        // Update LastSeenUtc and extend ExpiresUtc for sliding expiration.
        // Only persist when the new expiry meaningfully extends the session (> 1 minute gain).
        // This avoids high-frequency concurrent saves on burst requests, which can cause a
        // transient race where a concurrent Load reads a stale (already-moved) record location.
        var now = DateTime.UtcNow;
        var lifetime = session.RememberMe ? RememberMeLifetime : DefaultSessionLifetime;
        var newExpiry = now.Add(lifetime);
        session.LastSeenUtc = now;
        if (newExpiry - session.ExpiresUtc > TimeSpan.FromMinutes(1))
        {
            session.ExpiresUtc = newExpiry;
            await DataStoreProvider.Current.SaveAsync(session, cancellationToken).ConfigureAwait(false);
            if (session.RememberMe)
                ReissueCookie(context, protectedSessionId, session.ExpiresUtc);
        }

        return session;
    }

    public static async ValueTask<User?> GetUserAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        var session = await GetSessionAsync(context, cancellationToken).ConfigureAwait(false);
        if (session == null)
            return null;

        if (!uint.TryParse(session.UserId, out var userId))
            return null;

        var user = await Users.GetByIdAsync(userId, cancellationToken).ConfigureAwait(false);
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
            UserId = user.Key.ToString(),
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

        var protectedSessionId = CookieProtection.Protect(session.Key.ToString());
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

    private static void ReissueCookie(HttpContext context, string protectedSessionId, DateTime expiresUtc)
    {
        var options = new CookieOptions
        {
            HttpOnly = true,
            Secure = context.Request.IsHttps,
            SameSite = SameSiteMode.Lax,
            Expires = expiresUtc
        };
        context.SetCookie(SessionCookieName, protectedSessionId, options);
    }

    private static bool IsApiRequest(HttpContext context)
    {
        return context.Request.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Returns true if the request contains an API key header (ApiKey header or Authorization: ApiKey prefix).
    /// Does not validate the key — use GetRequestUserAsync for full validation.
    /// CSRF attacks require a browser session cookie and cannot forge explicit API key headers,
    /// so this is sufficient to determine that CSRF protection can be safely bypassed.
    /// </summary>
    public static bool HasApiKeyHeader(HttpContext context)
        => TryGetApiKey(context, out _);

    private static bool TryGetApiKey(HttpContext context, out string apiKey)
    {
        apiKey = string.Empty;

        // Option 1: ApiKey header with raw value
        if (context.Request.Headers.TryGetValue("ApiKey", out var apiKeyHeader))
        {
            var raw = apiKeyHeader.ToString().Trim();
            if (!string.IsNullOrWhiteSpace(raw))
            {
                apiKey = raw;
                return true;
            }
        }

        // Option 2: Authorization header with "ApiKey <value>" or "Bearer <value>" prefix
        if (context.Request.Headers.TryGetValue("Authorization", out var authValues))
        {
            var header = authValues.ToString().Trim();
            const string apiKeyPrefix = "ApiKey ";
            if (!string.IsNullOrWhiteSpace(header) && header.StartsWith(apiKeyPrefix, StringComparison.OrdinalIgnoreCase))
            {
                apiKey = header[apiKeyPrefix.Length..].Trim();
                return !string.IsNullOrWhiteSpace(apiKey);
            }

            // Option 3: Authorization header with "Bearer <value>" prefix (standard OAuth2/OpenAPI)
            const string bearerPrefix = "Bearer ";
            if (!string.IsNullOrWhiteSpace(header) && header.StartsWith(bearerPrefix, StringComparison.OrdinalIgnoreCase))
            {
                apiKey = header[bearerPrefix.Length..].Trim();
                return !string.IsNullOrWhiteSpace(apiKey);
            }
        }

        return false;
    }

    /// <summary>
    /// Returns true if the request carries a valid API key that resolves to a known system principal.
    /// Used to bypass CSRF validation for authenticated external API clients (e.g. ChatGPT, OpenAPI clients).
    /// </summary>
    public static async ValueTask<bool> HasValidApiKeyAsync(HttpContext context, CancellationToken cancellationToken = default)
    {
        if (!TryGetApiKey(context, out var apiKey))
            return false;

        var principal = await SystemPrincipal.FindByApiKeyAsync(apiKey, cancellationToken).ConfigureAwait(false);
        return principal != null;
    }
}
