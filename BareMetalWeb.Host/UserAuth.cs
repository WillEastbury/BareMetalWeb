using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
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

    // ── Password & Lockout ────────────────────────────────────────────
    public static bool VerifyPassword(BaseDataObject user, string password)
    {
        var meta = ResolveAuthMeta(user);
        return meta != null && UserAuthHelper.VerifyPassword(user, meta, password);
    }

    public static void SetPassword(BaseDataObject user, string password)
    {
        var meta = ResolveAuthMeta(user);
        if (meta != null) UserAuthHelper.SetPassword(user, meta, password);
    }

    public static bool IsLockedOut(BaseDataObject user)
    {
        var meta = ResolveAuthMeta(user);
        return meta != null && UserAuthHelper.IsLockedOut(user, meta);
    }

    public static void RegisterFailedLogin(BaseDataObject user)
    {
        var meta = ResolveAuthMeta(user);
        if (meta != null) UserAuthHelper.RegisterFailedLogin(user, meta);
    }

    public static void RegisterSuccessfulLogin(BaseDataObject user)
    {
        var meta = ResolveAuthMeta(user);
        if (meta != null) UserAuthHelper.RegisterSuccessfulLogin(user, meta);
    }

    // ── MFA ───────────────────────────────────────────────────────────
    public static bool IsMfaEnabled(BaseDataObject? user)
    {
        if (user == null) return false;
        var meta = ResolveAuthMeta(user);
        return meta != null && UserAuthHelper.IsMfaEnabled(user, meta);
    }

    public static void SetMfaEnabled(BaseDataObject user, bool value)
    {
        var meta = ResolveAuthMeta(user);
        if (meta != null) UserAuthHelper.SetMfaEnabled(user, meta, value);
    }

    public static string? GetMfaSecret(BaseDataObject user)
    {
        var meta = ResolveAuthMeta(user);
        return meta != null ? UserAuthHelper.GetMfaSecret(user, meta) : null;
    }

    public static void SetMfaSecret(BaseDataObject user, string? value)
    {
        var meta = ResolveAuthMeta(user);
        if (meta != null) UserAuthHelper.SetMfaSecret(user, meta, value);
    }

    public static string? GetMfaSecretEncrypted(BaseDataObject user)
    {
        var meta = ResolveAuthMeta(user);
        return meta != null ? UserAuthHelper.GetMfaSecretEncrypted(user, meta) : null;
    }

    public static void SetMfaSecretEncrypted(BaseDataObject user, string? value)
    {
        var meta = ResolveAuthMeta(user);
        if (meta != null) UserAuthHelper.SetMfaSecretEncrypted(user, meta, value);
    }

    public static long GetMfaLastVerifiedStep(BaseDataObject user)
    {
        var meta = ResolveAuthMeta(user);
        return meta != null ? UserAuthHelper.GetMfaLastVerifiedStep(user, meta) : 0;
    }

    public static void SetMfaLastVerifiedStep(BaseDataObject user, long step)
    {
        var meta = ResolveAuthMeta(user);
        if (meta != null) UserAuthHelper.SetMfaLastVerifiedStep(user, meta, step);
    }

    public static string? GetMfaPendingSecret(BaseDataObject user)
    {
        var meta = ResolveAuthMeta(user);
        return meta != null ? UserAuthHelper.GetMfaPendingSecret(user, meta) : null;
    }

    public static void SetMfaPendingSecret(BaseDataObject user, string? value)
    {
        var meta = ResolveAuthMeta(user);
        if (meta != null) UserAuthHelper.SetMfaPendingSecret(user, meta, value);
    }

    public static string? GetMfaPendingSecretEncrypted(BaseDataObject user)
    {
        var meta = ResolveAuthMeta(user);
        return meta != null ? UserAuthHelper.GetMfaPendingSecretEncrypted(user, meta) : null;
    }

    public static void SetMfaPendingSecretEncrypted(BaseDataObject user, string? value)
    {
        var meta = ResolveAuthMeta(user);
        if (meta != null) UserAuthHelper.SetMfaPendingSecretEncrypted(user, meta, value);
    }

    public static DateTime? GetMfaPendingExpiresUtc(BaseDataObject user)
    {
        var meta = ResolveAuthMeta(user);
        return meta != null ? UserAuthHelper.GetMfaPendingExpiresUtc(user, meta) : null;
    }

    public static void SetMfaPendingExpiresUtc(BaseDataObject user, DateTime? value)
    {
        var meta = ResolveAuthMeta(user);
        if (meta != null) UserAuthHelper.SetMfaPendingExpiresUtc(user, meta, value);
    }

    public static int GetMfaPendingFailedAttempts(BaseDataObject user)
    {
        var meta = ResolveAuthMeta(user);
        return meta != null ? UserAuthHelper.GetMfaPendingFailedAttempts(user, meta) : 0;
    }

    public static void SetMfaPendingFailedAttempts(BaseDataObject user, int value)
    {
        var meta = ResolveAuthMeta(user);
        if (meta != null) UserAuthHelper.SetMfaPendingFailedAttempts(user, meta, value);
    }

    public static string[]? GetMfaBackupCodeHashes(BaseDataObject user)
    {
        var meta = ResolveAuthMeta(user);
        return meta != null ? UserAuthHelper.GetMfaBackupCodeHashes(user, meta) : null;
    }

    public static void SetMfaBackupCodeHashes(BaseDataObject user, string[] value)
    {
        var meta = ResolveAuthMeta(user);
        if (meta != null) UserAuthHelper.SetMfaBackupCodeHashes(user, meta, value);
    }

    public static DateTime? GetMfaBackupCodesGeneratedUtc(BaseDataObject user)
    {
        var meta = ResolveAuthMeta(user);
        return meta != null ? UserAuthHelper.GetMfaBackupCodesGeneratedUtc(user, meta) : null;
    }

    public static void SetMfaBackupCodesGeneratedUtc(BaseDataObject user, DateTime? value)
    {
        var meta = ResolveAuthMeta(user);
        if (meta != null) UserAuthHelper.SetMfaBackupCodesGeneratedUtc(user, meta, value);
    }

    // ── User field setters ────────────────────────────────────────────
    public static void SetUserName(BaseDataObject user, string value)
    {
        var meta = ResolveAuthMeta(user);
        meta?.FindField("UserName")?.SetValueFn(user, value);
    }

    public static void SetDisplayName(BaseDataObject user, string value)
    {
        var meta = ResolveAuthMeta(user);
        meta?.FindField("DisplayName")?.SetValueFn(user, value);
    }

    public static void SetEmail(BaseDataObject user, string value)
    {
        var meta = ResolveAuthMeta(user);
        meta?.FindField("Email")?.SetValueFn(user, value);
    }

    public static void SetIsActive(BaseDataObject user, bool value)
    {
        var meta = ResolveAuthMeta(user);
        meta?.FindField("IsActive")?.SetValueFn(user, value);
    }

    public static void SetPermissions(BaseDataObject user, string[] value)
    {
        var meta = ResolveAuthMeta(user);
        meta?.FindField("Permissions")?.SetValueFn(user, value);
    }

    public static DateTime? GetLastLoginUtc(BaseDataObject? user)
    {
        if (user == null) return null;
        var meta = ResolveAuthMeta(user);
        if (meta == null) return null;
        var val = meta.FindField("LastLoginUtc")?.GetValueFn(user);
        return val is DateTime dt ? dt : null;
    }

    // ── User CRUD via metadata ────────────────────────────────────────
    public static BaseDataObject CreateUser()
    {
        var meta = UserAuthHelper.GetUserMeta();
        return meta?.Handlers.Create() ?? throw new InvalidOperationException("User entity metadata not found.");
    }

    public static BaseDataObject CreatePrincipal()
    {
        var meta = UserAuthHelper.GetPrincipalMeta();
        return meta?.Handlers.Create() ?? throw new InvalidOperationException("SystemPrincipal entity metadata not found.");
    }

    public static async ValueTask SaveUserAsync(BaseDataObject user, CancellationToken ct = default)
    {
        var meta = ResolveAuthMeta(user) ?? throw new InvalidOperationException("Cannot resolve entity metadata for user.");
        if (user.Key == 0)
            await DataScaffold.ApplyAutoIdAsync(meta, user, ct).ConfigureAwait(false);
        await meta.Handlers.SaveAsync(user, ct).ConfigureAwait(false);
    }

    public static async ValueTask<BaseDataObject?> LoadUserAsync(uint key, CancellationToken ct = default)
    {
        var meta = UserAuthHelper.GetUserMeta();
        return meta != null ? await meta.Handlers.LoadAsync(key, ct).ConfigureAwait(false) : null;
    }

    public static async ValueTask<IEnumerable<BaseDataObject>> QueryUsersAsync(QueryDefinition? query = null, CancellationToken ct = default)
    {
        var meta = UserAuthHelper.GetUserMeta();
        return meta != null
            ? await meta.Handlers.QueryAsync(query, ct).ConfigureAwait(false)
            : Array.Empty<BaseDataObject>();
    }

    public static async ValueTask<IEnumerable<BaseDataObject>> QueryPrincipalsAsync(QueryDefinition? query = null, CancellationToken ct = default)
    {
        var meta = UserAuthHelper.GetPrincipalMeta();
        return meta != null
            ? await meta.Handlers.QueryAsync(query, ct).ConfigureAwait(false)
            : Array.Empty<BaseDataObject>();
    }

    // ── SystemPrincipal helpers ───────────────────────────────────────
    public static string? GetPrincipalRole(BaseDataObject? principal)
    {
        if (principal == null) return null;
        var meta = ResolveAuthMeta(principal);
        return meta?.FindField("Role")?.GetValueFn(principal)?.ToString();
    }

    public static void SetPrincipalRole(BaseDataObject principal, string value)
    {
        var meta = ResolveAuthMeta(principal);
        meta?.FindField("Role")?.SetValueFn(principal, value);
    }

    public static void AddApiKey(BaseDataObject principal, string apiKey)
    {
        var meta = ResolveAuthMeta(principal);
        if (meta != null) UserAuthHelper.AddApiKey(principal, meta, apiKey);
    }

    public static bool HasApiKey(BaseDataObject principal, string apiKey)
    {
        var meta = ResolveAuthMeta(principal);
        return meta != null && UserAuthHelper.HasApiKey(principal, meta, apiKey);
    }

    private static DataEntityMetadata? ResolveAuthMeta(BaseDataObject? user)
    {
        if (user == null)
            return null;

        var meta = DataScaffold.GetEntityByName(user.EntityTypeName);
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
