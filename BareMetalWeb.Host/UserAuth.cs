using BareMetalWeb.Core;
using System;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Data;
using Microsoft.AspNetCore.Http;
namespace BareMetalWeb.Host;

public static class UserAuth
{
    public const string SessionCookieName = "session_id";
    private static readonly TimeSpan DefaultSessionLifetime = TimeSpan.FromHours(8);
    private static readonly TimeSpan RememberMeLifetime = TimeSpan.FromDays(30);
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, SemaphoreSlim> _sessionLocks = new();

    // Session expiration uses a sliding window model.
    // Sessions extend their expiration time with each access, keeping active users
    // logged in. For RememberMe sessions, the cookie Expires is also reissued to
    // match the extended server-side expiry.
    public static UserSession? GetSession(BmwContext context)
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
            var sem = _sessionLocks.GetOrAdd(protectedSessionId, _ => new SemaphoreSlim(1, 1));
            if (sem.Wait(0))
            {
                try
                {
                    session.ExpiresUtc = newExpiry;
                    DataStoreProvider.Current.Save(session);
                    if (session.RememberMe)
                        ReissueCookie(context, protectedSessionId, session.ExpiresUtc);
                }
                finally
                {
                    sem.Release();
                    _sessionLocks.TryRemove(protectedSessionId, out _);
                }
            }
        }

        return session;
    }

    public static async ValueTask<UserSession?> GetSessionAsync(BmwContext context, CancellationToken cancellationToken = default)
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
            var sem = _sessionLocks.GetOrAdd(protectedSessionId, _ => new SemaphoreSlim(1, 1));
            if (await sem.WaitAsync(0, cancellationToken).ConfigureAwait(false))
            {
                try
                {
                    session.ExpiresUtc = newExpiry;
                    await DataStoreProvider.Current.SaveAsync(session, cancellationToken).ConfigureAwait(false);
                    if (session.RememberMe)
                        ReissueCookie(context, protectedSessionId, session.ExpiresUtc);
                }
                finally
                {
                    sem.Release();
                    _sessionLocks.TryRemove(protectedSessionId, out _);
                }
            }
        }

        return session;
    }

    public static async ValueTask<BaseDataObject?> GetUserAsync(BmwContext context, CancellationToken cancellationToken = default)
    {
        var session = await GetSessionAsync(context, cancellationToken).ConfigureAwait(false);
        if (session == null)
            return null;

        if (!uint.TryParse(session.UserId, out var userId))
            return null;

        var meta = UserAuthHelper.GetUserMeta();
        if (meta == null)
            return null;

        var user = await UserAuthHelper.GetUserByIdAsync(userId, cancellationToken).ConfigureAwait(false);
        if (user == null || !UserAuthHelper.GetIsActive(user, meta))
            return null;

        return user;
    }

    public static async ValueTask<BaseDataObject?> GetRequestUserAsync(BmwContext context, CancellationToken cancellationToken = default)
    {
        var sessionUser = await GetUserAsync(context, cancellationToken).ConfigureAwait(false);
        if (sessionUser != null)
            return sessionUser;

        if (!IsApiRequest(context))
            return null;

        if (!TryGetApiKey(context, out var apiKey))
            return null;

        return await UserAuthHelper.FindByApiKeyAsync(apiKey, cancellationToken).ConfigureAwait(false);
    }

    public static ValueTask SignInAsync(BmwContext context, BaseDataObject user, bool rememberMe, CancellationToken cancellationToken = default)
    {
        var meta = UserAuthHelper.GetUserMeta() ?? throw new InvalidOperationException("User metadata is not registered.");
        return SignInAsync(context, user, meta, rememberMe, cancellationToken);
    }

    public static async ValueTask SignInAsync(BmwContext context, BaseDataObject user, DataEntityMetadata meta, bool rememberMe, CancellationToken cancellationToken = default)
    {
        if (context == null) throw new ArgumentNullException(nameof(context));
        if (user == null) throw new ArgumentNullException(nameof(user));
        if (meta == null) throw new ArgumentNullException(nameof(meta));

        var userName = GetUserName(user);
        if (string.IsNullOrWhiteSpace(userName))
            userName = UserAuthHelper.GetUserName(user, meta);
        if (string.IsNullOrWhiteSpace(userName))
            userName = user.Key.ToString();

        var displayName = GetDisplayName(user);
        if (string.IsNullOrWhiteSpace(displayName))
            displayName = UserAuthHelper.GetDisplayName(user, meta);
        if (string.IsNullOrWhiteSpace(displayName))
            displayName = userName;

        var now = DateTime.UtcNow;
        var session = new UserSession
        {
            UserId = user.Key.ToString(),
            UserName = userName,
            DisplayName = displayName,
            Permissions = UserAuthHelper.GetPermissions(user, meta),
            IssuedUtc = now,
            LastSeenUtc = now,
            ExpiresUtc = now.Add(rememberMe ? RememberMeLifetime : DefaultSessionLifetime),
            RememberMe = rememberMe,
            CreatedBy = userName,
            UpdatedBy = userName
        };

        await DataStoreProvider.Current.SaveAsync(session, cancellationToken).ConfigureAwait(false);

        var options = new CookieOptions
        {
            HttpOnly = true,
            Secure = context.HttpRequest.IsHttps,
            SameSite = SameSiteMode.Lax
        };

        if (rememberMe)
            options.Expires = session.ExpiresUtc;

        var protectedSessionId = CookieProtection.Protect(session.Key.ToString());
        context.SetCookie(SessionCookieName, protectedSessionId, options);
    }

    public static async ValueTask SignOutAsync(BmwContext context, CancellationToken cancellationToken = default)
    {
        if (context == null) throw new ArgumentNullException(nameof(context));

        var session = await GetSessionAsync(context, cancellationToken).ConfigureAwait(false);
        if (session != null)
        {
            session.IsRevoked = true;
            await DataStoreProvider.Current.SaveAsync(session, cancellationToken).ConfigureAwait(false);
        }

        context.DeleteCookie(SessionCookieName);
        // SECURITY: Clear all security-relevant cookies on logout to prevent reuse (see #1231)
        context.DeleteCookie("csrf_token");
        context.DeleteCookie("mfa_challenge_id");
        context.DeleteCookie("bm-anon-id");
    }

    public static string? GetUserName(BaseDataObject? user)
    {
        if (user == null)
            return null;

        var meta = ResolveAuthMeta(user);
        if (meta == null)
            return null;

        var value = UserAuthHelper.GetUserName(user, meta);
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    public static string? GetDisplayName(BaseDataObject? user)
    {
        if (user == null)
            return null;

        var meta = ResolveAuthMeta(user);
        if (meta == null)
            return null;

        var value = UserAuthHelper.GetDisplayName(user, meta);
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    public static string? GetEmail(BaseDataObject? user)
    {
        if (user == null)
            return null;

        var meta = ResolveAuthMeta(user);
        if (meta == null)
            return null;

        var value = UserAuthHelper.GetEmail(user, meta);
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    public static string[] GetPermissions(BaseDataObject? user)
    {
        if (user == null)
            return Array.Empty<string>();

        var meta = ResolveAuthMeta(user);
        return meta == null ? Array.Empty<string>() : UserAuthHelper.GetPermissions(user, meta);
    }

    public static bool IsActive(BaseDataObject? user)
    {
        if (user == null)
            return false;

        var meta = ResolveAuthMeta(user);
        return meta != null && UserAuthHelper.GetIsActive(user, meta);
    }

    private static DataEntityMetadata? ResolveAuthMeta(BaseDataObject? user)
    {
        if (user == null)
            return null;

        var meta = DataScaffold.GetEntityByType(user.GetType());
        if (meta != null)
            return meta;

        if (user is DataRecord record)
        {
            var userMeta = UserAuthHelper.GetUserMeta();
            if (MatchesEntity(record.EntityTypeName, userMeta))
                return userMeta;

            var principalMeta = UserAuthHelper.GetPrincipalMeta();
            if (MatchesEntity(record.EntityTypeName, principalMeta))
                return principalMeta;
        }

        return null;
    }

    private static bool MatchesEntity(string entityTypeName, DataEntityMetadata? meta)
    {
        if (string.IsNullOrWhiteSpace(entityTypeName) || meta == null)
            return false;

        return string.Equals(entityTypeName, meta.Name, StringComparison.OrdinalIgnoreCase)
            || string.Equals(entityTypeName, meta.Slug, StringComparison.OrdinalIgnoreCase)
            || string.Equals(entityTypeName, meta.Type.Name, StringComparison.OrdinalIgnoreCase);
    }

    private static void ReissueCookie(BmwContext context, string protectedSessionId, DateTime expiresUtc)
    {
        var options = new CookieOptions
        {
            HttpOnly = true,
            Secure = context.HttpRequest.IsHttps,
            SameSite = SameSiteMode.Lax,
            Expires = expiresUtc
        };
        context.SetCookie(SessionCookieName, protectedSessionId, options);
    }

    private static bool IsApiRequest(BmwContext context)
    {
        return context.HttpRequest.Path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Returns true if the request contains an API key header (ApiKey header or Authorization: ApiKey prefix).
    /// Does not validate the key — use GetRequestUserAsync for full validation.
    /// CSRF attacks require a browser session cookie and cannot forge explicit API key headers,
    /// so this is sufficient to determine that CSRF protection can be safely bypassed.
    /// </summary>
    public static bool HasApiKeyHeader(BmwContext context)
        => TryGetApiKey(context, out _);

    private static bool TryGetApiKey(BmwContext context, out string apiKey)
    {
        apiKey = string.Empty;

        // Option 1: ApiKey header with raw value
        if (context.HttpRequest.Headers.TryGetValue("ApiKey", out var apiKeyHeader))
        {
            var raw = apiKeyHeader.ToString().Trim();
            if (!string.IsNullOrWhiteSpace(raw) && raw.Length <= 512)
            {
                apiKey = raw;
                return true;
            }
        }

        // Option 2: Authorization header with "ApiKey <value>" or "Bearer <value>" prefix
        if (context.HttpRequest.Headers.TryGetValue("Authorization", out var authValues))
        {
            var header = authValues.ToString().Trim();
            const string apiKeyPrefix = "ApiKey ";
            if (!string.IsNullOrWhiteSpace(header) && header.StartsWith(apiKeyPrefix, StringComparison.OrdinalIgnoreCase))
            {
                apiKey = header[apiKeyPrefix.Length..].Trim();
                return !string.IsNullOrWhiteSpace(apiKey) && apiKey.Length <= 512;
            }

            // Option 3: Authorization header with "Bearer <value>" prefix (standard OAuth2/OpenAPI)
            const string bearerPrefix = "Bearer ";
            if (!string.IsNullOrWhiteSpace(header) && header.StartsWith(bearerPrefix, StringComparison.OrdinalIgnoreCase))
            {
                apiKey = header[bearerPrefix.Length..].Trim();
                return !string.IsNullOrWhiteSpace(apiKey) && apiKey.Length <= 512;
            }
        }

        return false;
    }

    /// <summary>
    /// Returns true if the request carries a valid API key that resolves to a known system principal.
    /// Used to bypass CSRF validation for authenticated external API clients (e.g. ChatGPT, OpenAPI clients).
    /// </summary>
    public static async ValueTask<bool> HasValidApiKeyAsync(BmwContext context, CancellationToken cancellationToken = default)
    {
        if (!TryGetApiKey(context, out var apiKey))
            return false;

        var principal = await UserAuthHelper.FindByApiKeyAsync(apiKey, cancellationToken).ConfigureAwait(false);
        return principal != null;
    }
}
