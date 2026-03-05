using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;

namespace BareMetalWeb.Host;

/// <summary>
/// Configuration for Microsoft Entra ID (Azure AD) SSO via OpenID Connect.
/// </summary>
public sealed class EntraIdOptions
{
    public bool Enabled { get; set; }
    public string TenantId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string RedirectUri { get; set; } = "/auth/sso/callback";
    public bool AutoProvisionUsers { get; set; } = true;
    public string DefaultPermissions { get; set; } = "user";
    public Dictionary<string, string> GroupRoleMappings { get; set; } = new();
}

/// <summary>
/// Implements OIDC authorization code flow with PKCE for Microsoft Entra ID.
/// Zero external dependencies — all token exchange and validation done inline.
/// </summary>
public static class EntraIdService
{
    private const string StateCookieName = "sso_state";
    private const string VerifierCookieName = "sso_verifier";
    private const string NonceCookieName = "sso_nonce";
    private static readonly TimeSpan StateLifetime = TimeSpan.FromMinutes(10);
    private static IBufferedLogger? _logger;

    private static readonly HttpClient _http = new()
    {
        Timeout = TimeSpan.FromSeconds(15),
        DefaultRequestHeaders = { { "Accept", "application/json" } }
    };

    /// <summary>
    /// Initialise the service with a logger for audit trail.
    /// </summary>
    public static void Init(IBufferedLogger? logger) => _logger = logger;

    /// <summary>
    /// Builds the Microsoft Entra authorize URL and sets state/PKCE cookies.
    /// </summary>
    public static string BuildAuthorizeUrl(
        EntraIdOptions options,
        Microsoft.AspNetCore.Http.HttpContext context)
    {
        // Generate PKCE verifier + challenge
        var verifier = GenerateCodeVerifier();
        var challenge = ComputeCodeChallenge(verifier);

        // Generate state nonce for CSRF protection
        var state = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        // Generate OIDC nonce for token replay protection
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        // Store in encrypted cookies
        var cookieOptions = new Microsoft.AspNetCore.Http.CookieOptions
        {
            HttpOnly = true,
            Secure = context.Request.IsHttps,
            SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax,
            MaxAge = StateLifetime,
            Path = "/auth/sso"
        };

        context.SetCookie(StateCookieName, CookieProtection.Protect(state), cookieOptions);
        context.SetCookie(VerifierCookieName, CookieProtection.Protect(verifier), cookieOptions);
        context.SetCookie(NonceCookieName, CookieProtection.Protect(nonce), cookieOptions);

        var redirectUri = BuildAbsoluteRedirectUri(context, options.RedirectUri);

        var authorizeUrl = $"https://login.microsoftonline.com/{options.TenantId}/oauth2/v2.0/authorize"
            + $"?client_id={Uri.EscapeDataString(options.ClientId)}"
            + $"&response_type=code"
            + $"&redirect_uri={Uri.EscapeDataString(redirectUri)}"
            + $"&response_mode=query"
            + $"&scope={Uri.EscapeDataString("openid profile email")}"
            + $"&state={Uri.EscapeDataString(state)}"
            + $"&nonce={Uri.EscapeDataString(nonce)}"
            + $"&code_challenge={Uri.EscapeDataString(challenge)}"
            + $"&code_challenge_method=S256"
            + $"&prompt=select_account";

        return authorizeUrl;
    }

    /// <summary>
    /// Validates the callback state parameter against the cookie.
    /// </summary>
    public static bool ValidateState(Microsoft.AspNetCore.Http.HttpContext context, string state)
    {
        var protectedState = context.GetCookie(StateCookieName);
        if (string.IsNullOrEmpty(protectedState))
            return false;

        var expectedState = CookieProtection.Unprotect(protectedState);
        return string.Equals(expectedState, state, StringComparison.Ordinal);
    }

    /// <summary>
    /// Exchanges the authorization code for tokens, validates them,
    /// and returns the user's claims.
    /// </summary>
    public static async Task<EntraIdUserInfo?> ExchangeCodeAsync(
        EntraIdOptions options,
        Microsoft.AspNetCore.Http.HttpContext context,
        string code,
        CancellationToken cancellationToken = default)
    {
        // Retrieve PKCE verifier
        var protectedVerifier = context.GetCookie(VerifierCookieName);
        if (string.IsNullOrEmpty(protectedVerifier))
            return null;

        var verifier = CookieProtection.Unprotect(protectedVerifier);
        if (string.IsNullOrEmpty(verifier))
            return null;

        var redirectUri = BuildAbsoluteRedirectUri(context, options.RedirectUri);

        // Token exchange
        var tokenEndpoint = $"https://login.microsoftonline.com/{options.TenantId}/oauth2/v2.0/token";
        var form = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = options.ClientId,
            ["client_secret"] = options.ClientSecret,
            ["code"] = code,
            ["redirect_uri"] = redirectUri,
            ["code_verifier"] = verifier,
            ["scope"] = "openid profile email"
        };

        using var response = await _http.PostAsync(
            tokenEndpoint,
            new FormUrlEncodedContent(form),
            cancellationToken).ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
            return null;

        var json = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (!root.TryGetProperty("id_token", out var idTokenElement))
            return null;

        var idToken = idTokenElement.GetString();
        if (string.IsNullOrEmpty(idToken))
            return null;

        // Decode JWT payload (we trust the token because we got it directly from Microsoft's token endpoint over TLS)
        var userInfo = DecodeIdToken(idToken);

        // Validate nonce claim against stored cookie value
        var protectedNonce = context.GetCookie(NonceCookieName);
        if (!string.IsNullOrEmpty(protectedNonce))
        {
            var expectedNonce = CookieProtection.Unprotect(protectedNonce);
            if (string.IsNullOrEmpty(expectedNonce) || !string.Equals(expectedNonce, userInfo.Nonce, StringComparison.Ordinal))
            {
                _logger?.LogError("SSO nonce mismatch — possible token replay", new InvalidOperationException("OIDC nonce validation failed"));
                return null;
            }
        }

        // Get group memberships if we have an access token and group mappings are configured
        if (options.GroupRoleMappings.Count > 0
            && root.TryGetProperty("access_token", out var accessTokenElement))
        {
            var accessToken = accessTokenElement.GetString();
            if (!string.IsNullOrEmpty(accessToken))
            {
                userInfo.Groups = await GetUserGroupsAsync(accessToken, cancellationToken)
                    .ConfigureAwait(false);
            }
        }

        // Clean up state cookies
        context.DeleteCookie(StateCookieName);
        context.DeleteCookie(VerifierCookieName);
        context.DeleteCookie(NonceCookieName);

        return userInfo;
    }

    /// <summary>
    /// Provisions or updates a local User from Entra ID claims.
    /// Returns the user ready for sign-in.
    /// </summary>
    public static async Task<User?> ProvisionUserAsync(
        EntraIdOptions options,
        EntraIdUserInfo userInfo,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(userInfo.Email))
            return null;

        _logger?.LogInfo($"SSO|provision|email={userInfo.Email}|objectId={userInfo.ObjectId}");

        // Find existing user by email
        var user = await Users.FindByEmailAsync(userInfo.Email, cancellationToken)
            .ConfigureAwait(false);

        if (user == null)
        {
            if (!options.AutoProvisionUsers)
                return null;

            user = new User
            {
                UserName = userInfo.Email,
                Email = userInfo.Email,
                DisplayName = userInfo.DisplayName ?? userInfo.Email,
                IsActive = true,
                // SSO users don't have a local password
                PasswordHash = string.Empty,
                PasswordSalt = string.Empty,
                PasswordIterations = 0,
                CreatedBy = "SSO",
                UpdatedBy = "SSO"
            };
        }
        else
        {
            // Update display name from Entra if it changed
            if (!string.IsNullOrEmpty(userInfo.DisplayName))
                user.DisplayName = userInfo.DisplayName;
            user.UpdatedBy = "SSO";
        }

        // Map Entra groups → permissions
        var permissions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Start with defaults
        if (!string.IsNullOrEmpty(options.DefaultPermissions))
        {
            foreach (var p in options.DefaultPermissions.Split(',', StringSplitOptions.RemoveEmptyEntries))
                permissions.Add(p.Trim());
        }

        // Map group IDs to roles
        if (userInfo.Groups != null)
        {
            foreach (var groupId in userInfo.Groups)
            {
                if (options.GroupRoleMappings.TryGetValue(groupId, out var role))
                    permissions.Add(role);
            }
        }

        var permArray = new string[permissions.Count];
        permissions.CopyTo(permArray);
        user.Permissions = permArray;
        user.IsActive = true;

        await Users.SaveAsync(user, cancellationToken).ConfigureAwait(false);
        return user;
    }

    /// <summary>
    /// Builds the Entra front-channel logout URL.
    /// </summary>
    public static string BuildLogoutUrl(EntraIdOptions options, string postLogoutRedirectUri)
    {
        return $"https://login.microsoftonline.com/{options.TenantId}/oauth2/v2.0/logout"
            + $"?post_logout_redirect_uri={Uri.EscapeDataString(postLogoutRedirectUri)}";
    }

    // ── Private helpers ────────────────────────────────────────────

    private static string BuildAbsoluteRedirectUri(
        Microsoft.AspNetCore.Http.HttpContext context,
        string relativePath)
    {
        var scheme = context.Request.IsHttps ? "https" : "http";
        var host = context.Request.Host.Value;
        return $"{scheme}://{host}{relativePath}";
    }

    private static string GenerateCodeVerifier()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string ComputeCodeChallenge(string verifier)
    {
        var hash = SHA256.HashData(Encoding.ASCII.GetBytes(verifier));
        return Convert.ToBase64String(hash)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static EntraIdUserInfo DecodeIdToken(string idToken)
    {
        // JWT: header.payload.signature — we only need the payload
        var parts = idToken.Split('.');
        if (parts.Length < 2)
            return new EntraIdUserInfo();

        var payload = parts[1];
        // Pad base64url
        switch (payload.Length % 4)
        {
            case 2: payload += "=="; break;
            case 3: payload += "="; break;
        }
        payload = payload.Replace('-', '+').Replace('_', '/');

        var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        return new EntraIdUserInfo
        {
            ObjectId = root.TryGetProperty("oid", out var oid) ? oid.GetString() : null,
            Email = root.TryGetProperty("email", out var email) ? email.GetString()
                : root.TryGetProperty("preferred_username", out var upn) ? upn.GetString() : null,
            DisplayName = root.TryGetProperty("name", out var name) ? name.GetString() : null,
            TenantId = root.TryGetProperty("tid", out var tid) ? tid.GetString() : null,
            Nonce = root.TryGetProperty("nonce", out var nonce) ? nonce.GetString() : null,
        };
    }

    private static async Task<string[]> GetUserGroupsAsync(
        string accessToken,
        CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get,
                "https://graph.microsoft.com/v1.0/me/memberOf?$select=id");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            using var response = await _http.SendAsync(request, cancellationToken)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
                return Array.Empty<string>();

            var json = await response.Content.ReadAsStringAsync(cancellationToken)
                .ConfigureAwait(false);
            using var doc = JsonDocument.Parse(json);

            var groups = new List<string>();
            if (doc.RootElement.TryGetProperty("value", out var value))
            {
                foreach (var item in value.EnumerateArray())
                {
                    if (item.TryGetProperty("id", out var id))
                        groups.Add(id.GetString() ?? string.Empty);
                }
            }

            return groups.ToArray();
        }
        catch (Exception ex)
        {
            _logger?.LogError("SSO Graph API group membership fetch failed", ex);
            return Array.Empty<string>();
        }
    }
}

/// <summary>
/// User information extracted from Entra ID token claims.
/// </summary>
public sealed class EntraIdUserInfo
{
    public string? ObjectId { get; set; }
    public string? Email { get; set; }
    public string? DisplayName { get; set; }
    public string? TenantId { get; set; }
    public string? Nonce { get; set; }
    public string[]? Groups { get; set; }
}
