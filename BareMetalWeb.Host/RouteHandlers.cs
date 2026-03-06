using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using BareMetalWeb.Data;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Core.Delegates;
using BareMetalWeb.Rendering.Models;
using BareMetalWeb.Core;
using BareMetalWeb.Runtime;

namespace BareMetalWeb.Host;

public sealed class RouteHandlers : IRouteHandlers
{
    private readonly IHtmlRenderer _renderer;
    private readonly ITemplateStore _templateStore;
    private readonly bool _allowAccountCreation;
    private readonly MfaSecretProtector _mfaProtector;
    private readonly string _dataRootFolder;
    private readonly AuditService _auditService;
    private readonly IBufferedLogger? _logger;
    private readonly BmwConfig? _config;
    private readonly IReadOnlyList<(string SettingId, string Value, string Description)> _settingDefaults;
    private const string MfaChallengeCookieName = "mfa_challenge_id";
    private static readonly TimeSpan MfaPendingLifetime = TimeSpan.FromMinutes(5);
    private const int MfaPendingMaxFailures = 5;
    private const int MfaChallengeMaxFailures = 6;
    private static readonly TimeSpan MfaAttemptWindow = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MfaBaseBlockDuration = TimeSpan.FromSeconds(10);
    private static readonly ConcurrentDictionary<string, AttemptTracker> MfaAttempts = new(StringComparer.Ordinal);
    private const int LoginIpMaxAttempts = 10;
    private const int LoginUserMaxAttempts = 5;
    private const int SsoCallbackIpMaxAttempts = 10;
    private static readonly JsonSerializerOptions JsonIndented = new() { WriteIndented = true };
    private static readonly TimeSpan DataQueryTimeout = TimeSpan.FromSeconds(30);

    [ThreadStatic] private static StringBuilder? t_cachedSb;
    [ThreadStatic] private static Dictionary<string, string?>? t_formDict;
    [ThreadStatic] private static HashSet<string>? t_permSet;

    private static Dictionary<string, string?> RentFormDictionary(int capacity = 16)
    {
        var dict = t_formDict;
        if (dict != null)
        {
            t_formDict = null;
            dict.Clear();
            return dict;
        }
        return new Dictionary<string, string?>(capacity, StringComparer.OrdinalIgnoreCase);
    }

    private static void ReturnFormDictionary(Dictionary<string, string?> dict)
    {
        if (dict.Count < 1024)
        {
            dict.Clear();
            t_formDict = dict;
        }
    }

    private static HashSet<string> RentPermissionSet(IEnumerable<string> source)
    {
        var set = t_permSet;
        if (set != null)
        {
            t_permSet = null;
            set.Clear();
            foreach (var item in source)
                set.Add(item);
            return set;
        }
        return new HashSet<string>(source, StringComparer.OrdinalIgnoreCase);
    }

    private static void ReturnPermissionSet(HashSet<string> set)
    {
        if (set.Count < 256)
        {
            set.Clear();
            t_permSet = set;
        }
    }

    private static StringBuilder RentStringBuilder(int minimumCapacity = 512)
    {
        var sb = t_cachedSb;
        if (sb != null && sb.Capacity >= minimumCapacity)
        {
            t_cachedSb = null;
            sb.Clear();
            return sb;
        }
        return new StringBuilder(minimumCapacity);
    }
    private static void ReturnStringBuilder(StringBuilder sb)
    {
        if (sb.Capacity <= 8192)
        {
            sb.Clear();
            t_cachedSb = sb;
        }
    }

    public RouteHandlers(IHtmlRenderer renderer, ITemplateStore templateStore, bool allowAccountCreation, string mfaKeyRootFolder, AuditService auditService,
        IReadOnlyList<(string SettingId, string Value, string Description)>? settingDefaults = null, IBufferedLogger? logger = null, BmwConfig? config = null)
    {
        _renderer = renderer;
        _templateStore = templateStore;
        _allowAccountCreation = allowAccountCreation;
        _mfaProtector = MfaSecretProtector.CreateDefault(mfaKeyRootFolder);
        _dataRootFolder = mfaKeyRootFolder;
        _auditService = auditService;
        _logger = logger;
        _config = config;
        _settingDefaults = settingDefaults ?? Array.Empty<(string, string, string)>();
    }

    public ValueTask DefaultPageHandler(BmwContext context)
        => _renderer.RenderPage(context.HttpContext);

    public RouteHandlerDelegate BuildPageHandler(Action<BmwContext> configure)
    {
        if (configure == null) throw new ArgumentNullException(nameof(configure));
        return async context =>
        {
            configure(context);
            await _renderer.RenderPage(context.HttpContext);
        };
    }

    public RouteHandlerDelegate BuildPageHandler(Func<BmwContext, ValueTask> configureAsync)
    {
        if (configureAsync == null) throw new ArgumentNullException(nameof(configureAsync));
        return async context =>
        {
            await configureAsync(context);
            await _renderer.RenderPage(context.HttpContext);
        };
    }

    public RouteHandlerDelegate BuildPageHandler(Func<BmwContext, ValueTask<bool>> configureAsync, bool renderWhenTrue = true)
    {
        if (configureAsync == null) throw new ArgumentNullException(nameof(configureAsync));
        return async context =>
        {
            var shouldRender = await configureAsync(context);
            if (shouldRender == renderWhenTrue)
                await _renderer.RenderPage(context.HttpContext);
        };
    }

    public async ValueTask TimeRawHandler(BmwContext context)
    {
        context.Response.ContentType = "text/plain";
        await context.Response.WriteAsync($"Current server time is: {DateTime.UtcNow:O}");
    }

    public async ValueTask LoginHandler(BmwContext context)
    {
        await BuildPageHandler(ctx => RenderLoginForm(ctx, null, null))(context);
    }

    public async ValueTask LoginPostHandler(BmwContext context)
    {
        // IP-based rate limit — before any DB work
        var remoteIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var ipKey = BuildMfaAttemptKey("login:ip", remoteIp);
        if (IsThrottled(ipKey, LoginIpMaxAttempts, out var ipRetry))
        {
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            if (ipRetry.HasValue)
                context.Response.Headers.RetryAfter = ((int)Math.Ceiling(ipRetry.Value.TotalSeconds)).ToString();
            RenderLoginForm(context, FormatThrottleMessage(ipRetry), string.Empty);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        // Read form data; use empty collection for non-form requests so CSRF check always runs
        var form = context.HttpRequest.HasFormContentType
            ? await context.HttpRequest.ReadFormAsync()
            : FormCollection.Empty;

        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderLoginForm(context, "Invalid security token. Please try again.", string.Empty);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var identifier = form["email"].ToString().Trim();
        var password = form["password"].ToString();
        var rememberValue = form["remember"].ToString();
        bool rememberMe = string.Equals(rememberValue, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(rememberValue, "on", StringComparison.OrdinalIgnoreCase)
            || string.Equals(rememberValue, "yes", StringComparison.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(identifier) || string.IsNullOrWhiteSpace(password))
        {
            RenderLoginForm(context, "Please enter your email/username and password.", identifier);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var user = await Users.FindByEmailOrUserNameAsync(identifier, context.RequestAborted).ConfigureAwait(false);
        if (user == null || !user.IsActive)
        {
            RegisterFailure(ipKey, LoginIpMaxAttempts);
            RenderLoginForm(context, "Invalid credentials.", identifier);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        // Per-user rate limit — after user is found, before password check
        var userKey = BuildMfaAttemptKey("login:user", user.Key.ToString());
        if (IsThrottled(userKey, LoginUserMaxAttempts, out var userRetry))
        {
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            if (userRetry.HasValue)
                context.Response.Headers.RetryAfter = ((int)Math.Ceiling(userRetry.Value.TotalSeconds)).ToString();
            RenderLoginForm(context, FormatThrottleMessage(userRetry), identifier);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        if (user.IsLockedOut)
        {
            RenderLoginForm(context, "Account is temporarily locked. Try again later.", identifier);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        if (!user.VerifyPassword(password))
        {
            RegisterFailure(ipKey, LoginIpMaxAttempts);
            RegisterFailure(userKey, LoginUserMaxAttempts);
            user.RegisterFailedLogin();
            await Users.SaveAsync(user);
            RenderLoginForm(context, "Invalid credentials.", identifier);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        if (user.MfaEnabled)
        {
            if (!TryGetActiveSecret(user, out _, out var upgraded))
            {
                RenderLoginForm(context, "MFA is misconfigured. Contact support.", identifier);
                await _renderer.RenderPage(context.HttpContext);
                return;
            }

            if (upgraded)
                await Users.SaveAsync(user);

            var challenge = new MfaChallenge
            {
                UserId = user.Key.ToString(),
                RememberMe = rememberMe,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(5),
                CreatedBy = user.UserName,
                UpdatedBy = user.UserName
            };
            await DataStoreProvider.Current.SaveAsync(challenge);
            context.SetCookie(MfaChallengeCookieName, challenge.Key.ToString(), new CookieOptions
            {
                HttpOnly = true,
                Secure = context.HttpRequest.IsHttps,
                SameSite = SameSiteMode.Lax,
                Expires = challenge.ExpiresUtc
            });
            RegisterSuccess(ipKey);
            RegisterSuccess(userKey);
            context.Response.Redirect("/mfa");
            return;
        }

        RegisterSuccess(ipKey);
        RegisterSuccess(userKey);
        user.RegisterSuccessfulLogin();
        await Users.SaveAsync(user);
        await UserAuth.SignInAsync(context, user, rememberMe);
        context.Response.Redirect("/");
    }

    public async ValueTask MfaChallengeHandler(BmwContext context)
    {
        await BuildPageHandler(async ctx =>
        {
            var challenge = await GetMfaChallengeAsync(ctx, context.RequestAborted).ConfigureAwait(false);
            if (challenge == null)
            {
                ctx.Response.Redirect("/login");
                return false;
            }

            RenderMfaChallengeForm(ctx, null);
            return true;
        })(context);
    }

    public async ValueTask MfaChallengePostHandler(BmwContext context)
    {
        var challenge = await GetMfaChallengeAsync(context, context.RequestAborted).ConfigureAwait(false);
        if (challenge == null)
        {
            context.Response.Redirect("/login");
            return;
        }

        // Read form data; use empty collection for non-form requests so CSRF check always runs
        var form = context.HttpRequest.HasFormContentType
            ? await context.HttpRequest.ReadFormAsync()
            : FormCollection.Empty;

        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderMfaChallengeForm(context, "Invalid security token. Please try again.");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var code = NormalizeOtpCode(form["code"].ToString());
        if (code == null)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            RenderMfaChallengeForm(context, "Please enter your authentication code.");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var user = await Users.GetByIdAsync(uint.Parse(challenge.UserId), context.RequestAborted).ConfigureAwait(false);
        if (user == null || !user.IsActive || !user.MfaEnabled || !TryGetActiveSecret(user, out var activeSecret, out var upgraded))
        {
            RenderMfaChallengeForm(context, "MFA is not available for this account.");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        if (upgraded)
            await Users.SaveAsync(user);

        var remoteIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (IsThrottled(BuildMfaAttemptKey("challenge:user", user.Key.ToString()), MfaChallengeMaxFailures, out var retryAfter)
            || IsThrottled(BuildMfaAttemptKey("challenge:ip", remoteIp), MfaChallengeMaxFailures, out retryAfter))
        {
            RenderMfaChallengeForm(context, FormatThrottleMessage(retryAfter));
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var secretBytes = Array.Empty<byte>();
        try
        {
            secretBytes = Encoding.UTF8.GetBytes(activeSecret);
            if (!MfaTotp.ValidateCode(activeSecret, code, out var matchedStep))
            {
                RegisterFailure(BuildMfaAttemptKey("challenge:user", user.Key.ToString()), MfaChallengeMaxFailures);
                RegisterFailure(BuildMfaAttemptKey("challenge:ip", remoteIp), MfaChallengeMaxFailures);
                RenderMfaChallengeForm(context, "Invalid authentication code.");
                await _renderer.RenderPage(context.HttpContext);
                return;
            }

            if (matchedStep <= user.MfaLastVerifiedStep)
            {
                RenderMfaChallengeForm(context, "Authentication code already used. Please wait for a new code.");
                await _renderer.RenderPage(context.HttpContext);
                return;
            }

            user.MfaLastVerifiedStep = matchedStep;
            user.RegisterSuccessfulLogin();
            await Users.SaveAsync(user);

            RegisterSuccess(BuildMfaAttemptKey("challenge:user", user.Key.ToString()));
            RegisterSuccess(BuildMfaAttemptKey("challenge:ip", remoteIp));

            challenge.IsUsed = true;
            await DataStoreProvider.Current.SaveAsync(challenge);
            context.DeleteCookie(MfaChallengeCookieName);

            await UserAuth.SignInAsync(context, user, challenge.RememberMe);
            context.Response.Redirect("/");
            return;
        }
        finally
        {
            if (secretBytes.Length > 0)
                CryptographicOperations.ZeroMemory(secretBytes);
        }
    }

    public async ValueTask RegisterHandler(BmwContext context)
    {
        await BuildPageHandler(ctx =>
        {
            if (!_allowAccountCreation)
            {
                ctx.SetStringValue("title", "Create Account");
                ctx.SetStringValue("html_message", "<p>Account creation is disabled in this environment.</p>");
                return;
            }

            RenderRegisterForm(ctx, null, null, null, null);
        })(context);
    }

    public async ValueTask RegisterPostHandler(BmwContext context)
    {
        if (!_allowAccountCreation)
        {
            context.SetStringValue("title", "Create Account");
            context.SetStringValue("html_message", "<p>Account creation is disabled in this environment.</p>");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        // Rate limiting — same pattern as login
        var remoteIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var regIpKey = BuildMfaAttemptKey("register:ip", remoteIp);
        if (IsThrottled(regIpKey, LoginIpMaxAttempts, out var regRetry))
        {
            RenderRegisterForm(context, $"Too many registration attempts. Try again later.", null, null, null);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        if (!context.HttpRequest.HasFormContentType)
        {
            RenderRegisterForm(context, "Invalid registration request.", null, null, null);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var form = await context.HttpRequest.ReadFormAsync();
        var userName = form["username"].ToString().Trim();
        var displayName = form["displayname"].ToString().Trim();
        var email = form["email"].ToString().Trim();
        var password = form["password"].ToString();
        var confirm = form["confirm"].ToString();

        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderRegisterForm(context, "Invalid security token. Please try again.", userName, displayName, email);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            RenderRegisterForm(context, "Please complete all required fields.", userName, displayName, email);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        if (!string.Equals(password, confirm, StringComparison.Ordinal))
        {
            RenderRegisterForm(context, "Passwords do not match.", userName, displayName, email);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        if (await Users.FindByEmailAsync(email, context.RequestAborted).ConfigureAwait(false) != null)
        {
            RenderRegisterForm(context, "Email is already registered.", userName, displayName, email);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        if (await Users.FindByUserNameAsync(userName, context.RequestAborted).ConfigureAwait(false) != null)
        {
            RenderRegisterForm(context, "Username is already taken.", userName, displayName, email);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var user = new User
        {
            UserName = userName,
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? userName : displayName,
            Email = email,
            Permissions = new[] { "user" },
            IsActive = true,
            CreatedBy = userName,
            UpdatedBy = userName
        };
        user.SetPassword(password);
        await Users.SaveAsync(user);
        await UserAuth.SignInAsync(context, user, rememberMe: true);
        context.Response.Redirect("/account");
    }

    public async ValueTask LogoutHandler(BmwContext context)
    {
        await BuildPageHandler(ctx => RenderLogoutForm(ctx, null))(context);
    }

    public async ValueTask LogoutPostHandler(BmwContext context)
    {
        if (!context.HttpRequest.HasFormContentType)
        {
            RenderLogoutForm(context, "Invalid logout request.");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var form = await context.HttpRequest.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderLogoutForm(context, "Invalid security token. Please try again.");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        await UserAuth.SignOutAsync(context);
        context.Response.Redirect("/");
    }

    // ── SSO (Entra ID) ────────────────────────────────────────────────

    private EntraIdOptions? GetEntraIdOptions(BmwContext context)
    {
        if (_config == null || !_config.GetValue("EntraId.Enabled", false))
            return null;

        var options = new EntraIdOptions
        {
            Enabled = _config.GetValue("EntraId.Enabled", false),
            TenantId = _config.GetValue("EntraId.TenantId", ""),
            ClientId = _config.GetValue("EntraId.ClientId", ""),
            ClientSecret = _config.GetValue("EntraId.ClientSecret", ""),
            RedirectUri = _config.GetValue("EntraId.RedirectUri", "/auth/sso/callback"),
            BaseUrl = _config.GetValue("EntraId.BaseUrl", ""),
            AutoProvisionUsers = _config.GetValue("EntraId.AutoProvisionUsers", true),
            DefaultPermissions = _config.GetValue("EntraId.DefaultPermissions", "user"),
        };

        return options.Enabled && !string.IsNullOrEmpty(options.TenantId) && !string.IsNullOrEmpty(options.ClientId)
            ? options : null;
    }

    public ValueTask SsoLoginHandler(BmwContext context)
    {
        var options = GetEntraIdOptions(context);
        if (options == null)
        {
            context.Response.StatusCode = 404;
            return ValueTask.CompletedTask;
        }

        var sourceIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        _logger?.LogInfo($"SSO|login-initiate|{sourceIp}");

        var authorizeUrl = EntraIdService.BuildAuthorizeUrl(options, context);
        context.Response.Redirect(authorizeUrl);
        return ValueTask.CompletedTask;
    }

    public async ValueTask SsoCallbackHandler(BmwContext context)
    {
        var options = GetEntraIdOptions(context);
        if (options == null)
        {
            context.Response.StatusCode = 404;
            return;
        }

        var sourceIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        // Rate limit SSO callbacks by IP
        var ssoIpKey = BuildMfaAttemptKey("sso:ip", sourceIp);
        if (IsThrottled(ssoIpKey, SsoCallbackIpMaxAttempts, out var ssoRetry))
        {
            _logger?.LogInfo($"SSO|callback-throttled|{sourceIp}|retry={FormatThrottleMessage(ssoRetry)}");
            await BuildPageHandler(ctx =>
            {
                RenderLoginForm(ctx, $"Too many SSO attempts. {FormatThrottleMessage(ssoRetry)}", null);
                return ValueTask.FromResult(true);
            })(context);
            return;
        }

        var code = context.HttpRequest.Query["code"].ToString();
        var state = context.HttpRequest.Query["state"].ToString();
        var error = context.HttpRequest.Query["error"].ToString();

        // Handle error from Entra
        if (!string.IsNullOrEmpty(error))
        {
            var errorDesc = context.HttpRequest.Query["error_description"].ToString();
            _logger?.LogInfo($"SSO|callback-error|{sourceIp}|error={error}");
            RegisterFailure(ssoIpKey, SsoCallbackIpMaxAttempts);
            await BuildPageHandler(ctx =>
            {
                RenderLoginForm(ctx, "SSO authentication was not completed. Please try again.", null);
                return ValueTask.FromResult(true);
            })(context);
            return;
        }

        // Validate state
        if (string.IsNullOrEmpty(state) || !EntraIdService.ValidateState(context, state))
        {
            _logger?.LogInfo($"SSO|callback-invalid-state|{sourceIp}");
            RegisterFailure(ssoIpKey, SsoCallbackIpMaxAttempts);
            await BuildPageHandler(ctx =>
            {
                RenderLoginForm(ctx, "Invalid SSO state. Please try again.", null);
                return ValueTask.FromResult(true);
            })(context);
            return;
        }

        // Exchange code for tokens
        var userInfo = await EntraIdService.ExchangeCodeAsync(options, context, code, context.RequestAborted)
            .ConfigureAwait(false);

        if (userInfo == null || string.IsNullOrEmpty(userInfo.Email))
        {
            _logger?.LogInfo($"SSO|callback-token-exchange-failed|{sourceIp}");
            RegisterFailure(ssoIpKey, SsoCallbackIpMaxAttempts);
            await BuildPageHandler(ctx =>
            {
                RenderLoginForm(ctx, "SSO authentication failed. Could not retrieve user information.", null);
                return ValueTask.FromResult(true);
            })(context);
            return;
        }

        // Provision or update user
        var user = await EntraIdService.ProvisionUserAsync(options, userInfo, context.RequestAborted)
            .ConfigureAwait(false);

        if (user == null)
        {
            _logger?.LogInfo($"SSO|callback-provision-denied|{sourceIp}|email={userInfo.Email}");
            await BuildPageHandler(ctx =>
            {
                RenderLoginForm(ctx, "Your account could not be provisioned. Contact your administrator.", null);
                return ValueTask.FromResult(true);
            })(context);
            return;
        }

        if (!user.IsActive)
        {
            _logger?.LogInfo($"SSO|callback-inactive|{sourceIp}|email={userInfo.Email}");
            await BuildPageHandler(ctx =>
            {
                RenderLoginForm(ctx, "Your account has been deactivated.", null);
                return ValueTask.FromResult(true);
            })(context);
            return;
        }

        // Sign in
        RegisterSuccess(ssoIpKey);
        _logger?.LogInfo($"SSO|callback-success|{sourceIp}|email={userInfo.Email}|user={user.Key}");
        await UserAuth.SignInAsync(context, user, rememberMe: false, context.RequestAborted)
            .ConfigureAwait(false);

        context.Response.Redirect("/");
    }

    public async ValueTask SsoLogoutHandler(BmwContext context)
    {
        var options = GetEntraIdOptions(context);
        var sourceIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        _logger?.LogInfo($"SSO|logout|{sourceIp}");

        await UserAuth.SignOutAsync(context, context.RequestAborted).ConfigureAwait(false);

        if (options != null)
        {
            // Build post-logout URI using the configured BaseUrl to avoid relying on the
            // user-controlled Host header for the redirect destination.
            var postLogoutUri = EntraIdService.BuildPostLogoutRedirectUri(options, context);
            var logoutUrl = EntraIdService.BuildLogoutUrl(options, postLogoutUri);
            context.Response.Redirect(logoutUrl);
        }
        else
        {
            context.Response.Redirect("/login");
        }
    }

    public async ValueTask AccountHandler(BmwContext context)
    {
        await BuildPageHandler(async ctx =>
        {
            var user = await UserAuth.GetUserAsync(ctx);
            if (user == null)
            {
                ctx.Response.Redirect("/login");
                return false;
            }

            ctx.SetStringValue("title", "Account");
            var permissions = user.Permissions?.Length > 0
                ? string.Join(", ", user.Permissions)
                : "None";
            var mfaStatus = user.MfaEnabled ? "Enabled" : "Disabled";
            var mfaLinks = user.MfaEnabled
                ? "<a href=\"/account/mfa\">Manage MFA</a> | <a href=\"/account/mfa/reset\">Reset MFA</a>"
                : "<a href=\"/account/mfa\">Manage MFA</a>";
            var message = $"<p>Signed in as <strong>{WebUtility.HtmlEncode(user.DisplayName)}</strong> ({WebUtility.HtmlEncode(user.UserName)}).</p>" +
                         $"<p>Email: {WebUtility.HtmlEncode(user.Email)}</p>" +
                         $"<p>Permissions: {WebUtility.HtmlEncode(permissions)}</p>" +
                         $"<p>MFA: {WebUtility.HtmlEncode(mfaStatus)} - {mfaLinks}</p>";
            ctx.SetStringValue("html_message", message);
            return true;
        })(context);
    }

    public async ValueTask MfaStatusHandler(BmwContext context)
    {
        await BuildPageHandler(async ctx =>
        {
            var user = await UserAuth.GetUserAsync(ctx);
            if (user == null)
            {
                ctx.Response.Redirect("/login");
                return false;
            }

            ctx.SetStringValue("title", "Multi-Factor Authentication");
            var status = user.MfaEnabled ? "<strong>Enabled</strong>" : "<strong>Disabled</strong>";
            var message = $"<p>MFA status: {status}.</p>";
            if (!user.MfaEnabled)
                message += "<p><a href=\"/account/mfa/setup\">Enable MFA</a></p>";
            ctx.SetStringValue("html_message", message);
            return true;
        })(context);
    }

    public async ValueTask MfaSetupHandler(BmwContext context)
    {
        await BuildPageHandler(async ctx =>
        {
            var user = await UserAuth.GetUserAsync(ctx);
            if (user == null)
            {
                ctx.Response.Redirect("/login");
                return false;
            }

            if (user.MfaEnabled)
            {
                ctx.SetStringValue("title", "Enable MFA");
                ctx.SetStringValue("html_message", "<p>MFA is already enabled for your account.</p>");
                return true;
            }

            if (RegeneratePendingMfaSecret(user, forceNew: true))
                await Users.SaveAsync(user);

            var issuer = ctx.GetApp()?.AppName ?? "BareMetalWeb";
            var pendingSecret = GetPendingSecret(user, out var pendingUpgraded);
            if (pendingUpgraded)
                await Users.SaveAsync(user);
            var otpauth = MfaTotp.GetOtpAuthUri(issuer, user.Email, pendingSecret ?? string.Empty);
            RenderMfaSetupForm(ctx, pendingSecret ?? string.Empty, otpauth, null);
            return true;
        })(context);
    }

    public async ValueTask MfaSetupPostHandler(BmwContext context)
    {
        var user = await UserAuth.GetUserAsync(context);
        if (user == null)
        {
            context.Response.Redirect("/login");
            return;
        }

        if (!context.HttpRequest.HasFormContentType)
        {
            if (RegeneratePendingMfaSecret(user, forceNew: false))
                await Users.SaveAsync(user);
            var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
            var pendingSecret = GetPendingSecret(user, out var pendingUpgraded);
            if (pendingUpgraded)
                await Users.SaveAsync(user);
            var otpauth = string.IsNullOrWhiteSpace(pendingSecret) ? string.Empty : MfaTotp.GetOtpAuthUri(issuer, user.Email, pendingSecret);
            RenderMfaSetupForm(context, pendingSecret ?? string.Empty, otpauth, "Invalid setup request.");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var form = await context.HttpRequest.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            if (RegeneratePendingMfaSecret(user, forceNew: false))
                await Users.SaveAsync(user);
            var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
            var pendingSecret = GetPendingSecret(user, out var pendingUpgraded);
            if (pendingUpgraded)
                await Users.SaveAsync(user);
            var otpauth = string.IsNullOrWhiteSpace(pendingSecret) ? string.Empty : MfaTotp.GetOtpAuthUri(issuer, user.Email, pendingSecret);
            RenderMfaSetupForm(context, pendingSecret ?? string.Empty, otpauth, "Invalid security token. Please try again.");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var code = NormalizeOtpCode(form["code"].ToString());
        if (code == null)
        {
            var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
            var pendingSecret = GetPendingSecret(user, out var pendingUpgraded);
            if (pendingUpgraded)
                await Users.SaveAsync(user);
            var otpauth = string.IsNullOrWhiteSpace(pendingSecret) ? string.Empty : MfaTotp.GetOtpAuthUri(issuer, user.Email, pendingSecret);
            RenderMfaSetupForm(context, pendingSecret ?? string.Empty, otpauth, "Please enter a valid 6-digit code.");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var currentPendingSecret = GetPendingSecret(user, out var currentUpgraded);
        if (currentUpgraded)
            await Users.SaveAsync(user);
        if (string.IsNullOrWhiteSpace(currentPendingSecret) || user.MfaPendingExpiresUtc is null || user.MfaPendingExpiresUtc <= DateTime.UtcNow)
        {
            if (RegeneratePendingMfaSecret(user, forceNew: true))
                await Users.SaveAsync(user);
            var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
            var refreshedSecret = GetPendingSecret(user, out var refreshedUpgraded);
            if (refreshedUpgraded)
                await Users.SaveAsync(user);
            var otpauth = MfaTotp.GetOtpAuthUri(issuer, user.Email, refreshedSecret ?? string.Empty);
            RenderMfaSetupForm(context, refreshedSecret ?? string.Empty, otpauth, "Setup token expired. A new secret was generated.");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var setupIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (IsThrottled(BuildMfaAttemptKey("setup:user", user.Key.ToString()), MfaPendingMaxFailures, out var setupRetry)
            || IsThrottled(BuildMfaAttemptKey("setup:ip", setupIp), MfaPendingMaxFailures, out setupRetry)
            || IsThrottled(BuildMfaAttemptKey("setup:secret", currentPendingSecret), MfaPendingMaxFailures, out setupRetry))
        {
            var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
            var otpauth = MfaTotp.GetOtpAuthUri(issuer, user.Email, currentPendingSecret);
            RenderMfaSetupForm(context, currentPendingSecret, otpauth, FormatThrottleMessage(setupRetry));
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var pendingBytes = Array.Empty<byte>();
        try
        {
            pendingBytes = Encoding.UTF8.GetBytes(currentPendingSecret);
            if (!MfaTotp.ValidateCode(currentPendingSecret, code, out var matchedStep))
            {
                var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
                var otpauth = MfaTotp.GetOtpAuthUri(issuer, user.Email, currentPendingSecret);
                user.MfaPendingFailedAttempts++;
                if (user.MfaPendingFailedAttempts >= MfaPendingMaxFailures)
                {
                    if (RegeneratePendingMfaSecret(user, forceNew: true))
                        await Users.SaveAsync(user);
                    var refreshedSecret = GetPendingSecret(user, out var refreshedUpgraded) ?? string.Empty;
                    if (refreshedUpgraded)
                        await Users.SaveAsync(user);
                    otpauth = MfaTotp.GetOtpAuthUri(issuer, user.Email, refreshedSecret);
                    RenderMfaSetupForm(context, refreshedSecret, otpauth, "Too many failed attempts. A new secret was generated.");
                    await _renderer.RenderPage(context.HttpContext);
                    return;
                }

                RegisterFailure(BuildMfaAttemptKey("setup:user", user.Key.ToString()), MfaPendingMaxFailures);
                RegisterFailure(BuildMfaAttemptKey("setup:ip", setupIp), MfaPendingMaxFailures);
                RegisterFailure(BuildMfaAttemptKey("setup:secret", currentPendingSecret), MfaPendingMaxFailures);

                RenderMfaSetupForm(context, currentPendingSecret, otpauth, "Invalid authentication code.");
                await _renderer.RenderPage(context.HttpContext);
                return;
            }

            if (matchedStep <= user.MfaLastVerifiedStep)
            {
                var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
                var otpauth = MfaTotp.GetOtpAuthUri(issuer, user.Email, currentPendingSecret);
                RenderMfaSetupForm(context, currentPendingSecret, otpauth, "Authentication code already used. Please wait for a new code.");
                await _renderer.RenderPage(context.HttpContext);
                return;
            }

            user.MfaEnabled = true;
            user.MfaLastVerifiedStep = matchedStep;
            user.MfaSecretEncrypted = _mfaProtector.EncryptSecret(currentPendingSecret, user.Key.ToString());
            user.MfaSecret = null;
            user.MfaPendingSecret = null;
            user.MfaPendingSecretEncrypted = null;
            user.MfaPendingExpiresUtc = null;
            user.MfaPendingFailedAttempts = 0;

            var backupCodes = GenerateBackupCodes(user, count: 8);
            user.MfaBackupCodeHashes = backupCodes.Hashes;
            user.MfaBackupCodesGeneratedUtc = DateTime.UtcNow;
            await Users.SaveAsync(user);

            RegisterSuccess(BuildMfaAttemptKey("setup:user", user.Key.ToString()));
            RegisterSuccess(BuildMfaAttemptKey("setup:ip", setupIp));
            RegisterSuccess(BuildMfaAttemptKey("setup:secret", currentPendingSecret));

            context.SetStringValue("title", "Enable MFA");
            var backupListBuilder = new StringBuilder(512);
            foreach (var codeValue in backupCodes.Codes)
                backupListBuilder.Append($"<li><code>{WebUtility.HtmlEncode(codeValue)}</code></li>");
            var backupList = backupListBuilder.ToString();
            var backupHtml = string.IsNullOrWhiteSpace(backupList)
                ? string.Empty
                : $"<div class=\"mt-3\"><p><strong>Backup codes (save these now):</strong></p><ul>{backupList}</ul><p class=\"text-warning\">These codes are shown once.</p></div>";
            context.SetStringValue("html_message", "<p>MFA enabled successfully.</p>" + backupHtml + "<p><a href=\"/account\">Back to account</a></p>");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }
        finally
        {
            if (pendingBytes.Length > 0)
                CryptographicOperations.ZeroMemory(pendingBytes);
        }
    }

    public async ValueTask MfaResetHandler(BmwContext context)
    {
        await BuildPageHandler(async ctx =>
        {
            var user = await UserAuth.GetUserAsync(ctx);
            if (user == null)
            {
                ctx.Response.Redirect("/login");
                return false;
            }

            ctx.SetStringValue("title", "Reset MFA");
            if (!user.MfaEnabled)
            {
                ctx.SetStringValue("html_message", "<p>MFA is not enabled for your account.</p><p><a href=\"/account\">Back to account</a></p>");
                return true;
            }

            RenderMfaResetForm(ctx, null);
            return true;
        })(context);
    }

    public async ValueTask MfaResetPostHandler(BmwContext context)
    {
        var user = await UserAuth.GetUserAsync(context);
        if (user == null)
        {
            context.Response.Redirect("/login");
            return;
        }

        if (!context.HttpRequest.HasFormContentType)
        {
            RenderMfaResetForm(context, "Invalid request.");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var form = await context.HttpRequest.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderMfaResetForm(context, "Invalid security token. Please try again.");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        user.MfaEnabled = false;
        user.MfaSecret = null;
        user.MfaSecretEncrypted = null;
        user.MfaLastVerifiedStep = 0;
        user.MfaPendingSecret = null;
        user.MfaPendingSecretEncrypted = null;
        user.MfaPendingExpiresUtc = null;
        user.MfaPendingFailedAttempts = 0;
        user.MfaBackupCodeHashes = Array.Empty<string>();
        user.MfaBackupCodesGeneratedUtc = null;
        await Users.SaveAsync(user);

        context.SetStringValue("title", "Reset MFA");
        context.SetStringValue("html_message", "<p>MFA has been reset.</p><p><a href=\"/account\">Back to account</a></p>");
        await _renderer.RenderPage(context.HttpContext);
    }

    public async ValueTask UsersListHandler(BmwContext context)
    {
        await BuildPageHandler(async ctx =>
        {
            ctx.SetStringValue("title", "Users");

            using var rows = new BmwValueList<string[]>(16);
            var users = await DataStoreProvider.Current.QueryAsync<User>(new QueryDefinition()).ConfigureAwait(false);
            foreach (var user in users)
            {
                rows.Add(new[]
                {
                    WebUtility.HtmlEncode(user.UserName),
                    WebUtility.HtmlEncode(user.DisplayName),
                    WebUtility.HtmlEncode(user.Email),
                    user.IsActive ? "Yes" : "No",
                    WebUtility.HtmlEncode(user.Permissions != null && user.Permissions.Length > 0
                        ? string.Join(", ", user.Permissions)
                        : "None"),
                    user.LastLoginUtc?.ToString("u") ?? "Never"
                });
            }

            ctx.AddTable(
                new[] { "Username", "Display Name", "Email", "Active", "Permissions", "Last Login" },
                rows.ToArray());
        })(context);
    }

    public async ValueTask SetupHandler(BmwContext context)
    {
        await BuildPageHandler(async ctx =>
        {
            if (await RootUserExistsAsync(context.RequestAborted).ConfigureAwait(false))
            {
                var lockedUser = await GetLockedRootUserAsync(context.RequestAborted).ConfigureAwait(false);
                if (lockedUser != null)
                {
                    RenderUnlockForm(ctx, "Your admin account is locked. Enter your current password to unlock it.");
                    return;
                }

                ctx.SetStringValue("title", "Setup");
                ctx.SetStringValue("html_message", "<p>Root user already exists.</p>");
                return;
            }

            RenderSetupForm(ctx, null, null, null);
        })(context);
    }

    public async ValueTask SetupPostHandler(BmwContext context)
    {
        if (await RootUserExistsAsync(context.RequestAborted).ConfigureAwait(false))
        {
            var lockedUser = await GetLockedRootUserAsync(context.RequestAborted).ConfigureAwait(false);
            if (lockedUser == null)
            {
                context.SetStringValue("title", "Setup");
                context.SetStringValue("html_message", "<p>Root user already exists.</p>");
                await _renderer.RenderPage(context.HttpContext);
                return;
            }

            // Read form data; use empty collection for non-form requests so CSRF check always runs
            var unlockForm = context.HttpRequest.HasFormContentType
                ? await context.HttpRequest.ReadFormAsync()
                : FormCollection.Empty;

            if (!CsrfProtection.ValidateFormToken(context, unlockForm))
            {
                RenderUnlockForm(context, "Invalid security token. Please try again.");
                await _renderer.RenderPage(context.HttpContext);
                return;
            }

            var unlockPassword = unlockForm["password"].ToString();
            if (string.IsNullOrWhiteSpace(unlockPassword) || !lockedUser.VerifyPassword(unlockPassword))
            {
                RenderUnlockForm(context, "Invalid password. Account remains locked.");
                await _renderer.RenderPage(context.HttpContext);
                return;
            }

            lockedUser.RegisterSuccessfulLogin();
            await Users.SaveAsync(lockedUser);
            context.SetStringValue("title", "Setup");
            context.SetStringValue("html_message", "<p>Account unlocked successfully. You may now sign in.</p>");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        // Read form data; use empty collection for non-form requests so CSRF check always runs
        var form = context.HttpRequest.HasFormContentType
            ? await context.HttpRequest.ReadFormAsync()
            : FormCollection.Empty;

        var userName = form["username"].ToString().Trim();
        var email = form["email"].ToString().Trim();
        var password = form["password"].ToString();

        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderSetupForm(context, "Invalid security token. Please try again.", userName, email);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            RenderSetupForm(context, "Please complete all required fields.", userName, email);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var user = new User
        {
            UserName = userName,
            DisplayName = userName,
            Email = email,
            Permissions = BuildRootPermissions(),
            IsActive = true,
            CreatedBy = userName,
            UpdatedBy = userName
        };
        user.SetPassword(password);
        await Users.SaveAsync(user);
        await SettingsService.EnsureDefaultsAsync(DataStoreProvider.Current, _settingDefaults, userName, context.RequestAborted).ConfigureAwait(false);
        await EnsureDefaultReports(userName);
        // Redirect to gallery so the user can deploy modules
        context.Response.Redirect("/admin/gallery");
    }

    private static string[] BuildRootPermissions()
    {
        var permissions = new HashSet<string>(DataScaffold.Entities.Count + 2, StringComparer.OrdinalIgnoreCase)
        {
            "admin",
            "monitoring"
        };

        foreach (var entity in DataScaffold.Entities)
        {
            var value = entity.Permissions?.Trim();
            if (string.IsNullOrWhiteSpace(value))
                continue;

            var parts = value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var part in parts)
            {
                permissions.Add(part);
            }
        }

        return permissions.ToArray();
    }

    private async ValueTask EnsureDefaultReports(string createdBy)
    {
        var existing = await DataStoreProvider.Current.QueryAsync<ReportDefinition>(null).ConfigureAwait(false);
        var existingNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in existing)
            existingNames.Add(r.Name);

        var reports = new List<ReportDefinition>
        {
            new ReportDefinition(createdBy)
            {
                Name = "Customer List",
                Description = "All customers with contact details.",
                RootEntity = "customers",
                Columns = new List<ReportColumn>
                {
                    new ReportColumn { Entity = "customers", Field = "Name",    Label = "Name" },
                    new ReportColumn { Entity = "customers", Field = "Email",   Label = "Email" },
                    new ReportColumn { Entity = "customers", Field = "Company", Label = "Company" },
                    new ReportColumn { Entity = "customers", Field = "Phone",   Label = "Phone" },
                },
                SortField = "customers.Name"
            },
            new ReportDefinition(createdBy)
            {
                Name = "Orders with Customer",
                Description = "Orders joined to customer details.",
                RootEntity = "orders",
                Joins = new List<ReportJoin>
                {
                    new ReportJoin { FromEntity = "orders", FromField = "CustomerId", ToEntity = "customers", ToField = "Id" }
                },
                Columns = new List<ReportColumn>
                {
                    new ReportColumn { Entity = "orders",    Field = "OrderNumber", Label = "Order #" },
                    new ReportColumn { Entity = "customers", Field = "Name",        Label = "Customer" },
                    new ReportColumn { Entity = "orders",    Field = "OrderDate",   Label = "Order Date" },
                    new ReportColumn { Entity = "orders",    Field = "Status",      Label = "Status" },
                },
                SortField = "orders.OrderDate",
                SortDescending = true
            },
            new ReportDefinition(createdBy)
            {
                Name = "Product Catalog",
                Description = "All products with pricing and inventory information.",
                RootEntity = "products",
                Columns = new List<ReportColumn>
                {
                    new ReportColumn { Entity = "products", Field = "Name",           Label = "Name" },
                    new ReportColumn { Entity = "products", Field = "Sku",            Label = "SKU" },
                    new ReportColumn { Entity = "products", Field = "Category",       Label = "Category" },
                    new ReportColumn { Entity = "products", Field = "Price",          Label = "Price" },
                    new ReportColumn { Entity = "products", Field = "InventoryCount", Label = "Inventory" },
                },
                SortField = "products.Name"
            }
        };

        foreach (var report in reports)
        {
            if (existingNames.Contains(report.Name))
                continue;

            await DataStoreProvider.Current.SaveAsync(report).ConfigureAwait(false);
        }
    }

    public async ValueTask ReloadTemplatesHandler(BmwContext context)
    {
        _templateStore.ReloadAll();
        context.SetStringValue("title", "Reload Templates");
        context.SetStringValue("html_message", "Templates reloaded successfully.");
        await _renderer.RenderPage(context.HttpContext);
    }

    private void RenderLoginForm(BmwContext context, string? message, string? emailValue)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Login");
        context.SetStringValue("html_message", string.IsNullOrWhiteSpace(message)
            ? string.Empty
            : $"<div class=\"alert alert-danger\">{WebUtility.HtmlEncode(message)}</div>");
        var fields = new List<FormField>
        {
            new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken),
            new FormField(FormFieldType.Email, "email", "Email or Username", true, "you@example.com", Value: emailValue),
            new FormField(FormFieldType.Password, "password", "Password", true, "Enter password"),
            new FormField(FormFieldType.YesNo, "remember", "Remember me", false, SelectedValue: "false")
        };

        if (_allowAccountCreation)
        {
            fields.Add(new FormField(FormFieldType.Link, "register", "", false, LinkUrl: "/register", LinkText: "Create Account", LinkClass: "link-secondary"));
        }

        // Add SSO button if Entra ID is configured
        var entraOptions = GetEntraIdOptions(context);
        if (entraOptions != null)
        {
            fields.Add(new FormField(FormFieldType.Link, "sso", "", false,
                LinkUrl: "/auth/sso/login",
                LinkText: "Sign in with Microsoft",
                LinkClass: "btn btn-outline-primary w-100 mt-2"));
        }

        context.AddFormDefinition(new FormDefinition(
            Action: "/login",
            Method: "post",
            SubmitLabel: "Sign In",
            Fields: fields.ToArray()
        ));
    }

    private void RenderRegisterForm(BmwContext context, string? message, string? userName, string? displayName, string? email)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Create Account");
        context.SetStringValue("html_message", string.IsNullOrWhiteSpace(message)
            ? string.Empty
            : $"<div class=\"alert alert-danger\">{WebUtility.HtmlEncode(message)}</div>");
        context.AddFormDefinition(new FormDefinition(
            Action: "/register",
            Method: "post",
            SubmitLabel: "Create Account",
            Fields: new[]
            {
                new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken),
                new FormField(FormFieldType.String, "username", "Username", true, "yourname", Value: userName),
                new FormField(FormFieldType.String, "displayname", "Display Name", false, "How you want to be seen", Value: displayName),
                new FormField(FormFieldType.Email, "email", "Email", true, "you@example.com", Value: email),
                new FormField(FormFieldType.Password, "password", "Password", true, "Enter password"),
                new FormField(FormFieldType.Password, "confirm", "Confirm Password", true, "Re-enter password"),
                new FormField(FormFieldType.Link, "login", "", false, LinkUrl: "/login", LinkText: "Already have an account? Sign in", LinkClass: "link-secondary")
            }
        ));
    }

    private void RenderSetupForm(BmwContext context, string? message, string? userName, string? email)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Initial Setup");
        context.SetStringValue("html_message", string.IsNullOrWhiteSpace(message)
            ? "<p>Create the first admin account.</p>"
            : $"<div class=\"alert alert-danger\">{WebUtility.HtmlEncode(message)}</div>");
        context.AddFormDefinition(new FormDefinition(
            Action: "/setup",
            Method: "post",
            SubmitLabel: "Create Admin",
            Fields: new[]
            {
                new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken),
                new FormField(FormFieldType.String, "username", "Username", true, "root", Value: userName),
                new FormField(FormFieldType.Email, "email", "Email", true, "root@example.com", Value: email),
                new FormField(FormFieldType.Password, "password", "Password", true, "Enter password")
            }
        ));
    }

    private void RenderUnlockForm(BmwContext context, string? message)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Unlock Admin Account");
        context.SetStringValue("html_message", string.IsNullOrWhiteSpace(message)
            ? "<p>Enter your current password to unlock your admin account.</p>"
            : $"<div class=\"alert alert-warning\">{WebUtility.HtmlEncode(message)}</div>");
        context.AddFormDefinition(new FormDefinition(
            Action: "/setup",
            Method: "post",
            SubmitLabel: "Unlock Account",
            Fields: new[]
            {
                new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken),
                new FormField(FormFieldType.Password, "password", "Current Password", true, "Enter your current password")
            }
        ));
    }

    private void RenderLogoutForm(BmwContext context, string? message)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Logout");
        context.SetStringValue("html_message", string.IsNullOrWhiteSpace(message)
            ? "<p>Are you sure you want to sign out?</p>"
            : $"<div class=\"alert alert-danger\">{WebUtility.HtmlEncode(message)}</div>");
        context.AddFormDefinition(new FormDefinition(
            Action: "/logout",
            Method: "post",
            SubmitLabel: "Sign Out",
            Fields: new[]
            {
                new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken)
            }
        ));
    }

    private void RenderMfaChallengeForm(BmwContext context, string? message)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Verify MFA");
        var info = string.IsNullOrWhiteSpace(message)
            ? "<p>Enter the 6-digit code from your authenticator app.</p>"
            : $"<div class=\"alert alert-danger\">{WebUtility.HtmlEncode(message)}</div>";
        context.SetStringValue("html_message", info + BuildOtpClientScript(context, "/mfa"));

        context.AddFormDefinition(new FormDefinition(
            Action: "/mfa",
            Method: "post",
            SubmitLabel: "Verify",
            Fields: new[]
            {
                new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken),
                new FormField(FormFieldType.Otp, "code", "Authentication Code", true, "123456")
            }
        ));
    }

    private void RenderMfaSetupForm(BmwContext context, string secret, string otpauthUrl, string? message)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Enable MFA");
        var intro = string.IsNullOrWhiteSpace(message)
            ? "<p>Scan the QR code in your authenticator app. Use manual entry only if needed.</p>"
            : $"<div class=\"alert alert-danger\">{WebUtility.HtmlEncode(message)}</div>";

        string qrHtml = string.Empty;
        if (!string.IsNullOrWhiteSpace(otpauthUrl))
        {
            var qrDataUri = QrCodeGenerator.GenerateSvgDataUri(otpauthUrl, pixelsPerModule: 4, border: 4);
            qrHtml = $"<div class=\"my-3\"><img class=\"img-thumbnail\" alt=\"MFA QR Code\" src=\"{qrDataUri}\"/></div>";
        }

        var maskedSecret = MaskSecret(secret);

        // Show QR code and masked secret only — never render plaintext secret in HTML
        var payload = string.IsNullOrWhiteSpace(secret)
            ? string.Empty
            : $"<p><strong>Secret:</strong> <code>{WebUtility.HtmlEncode(maskedSecret)}</code></p>" +
              qrHtml +
              "<p class=\"text-muted small\">Can't scan the QR code? Use the masked secret above with your authenticator app's manual entry option.</p>";

        context.SetStringValue("html_message", intro + payload + BuildOtpClientScript(context, "/account/mfa/setup"));
        context.AddFormDefinition(new FormDefinition(
            Action: "/account/mfa/setup",
            Method: "post",
            SubmitLabel: "Enable MFA",
            Fields: new[]
            {
                new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken),
                new FormField(FormFieldType.Otp, "code", "Authentication Code", true, "123456")
            }
        ));
    }

    private bool RegeneratePendingMfaSecret(User user, bool forceNew)
    {
        var changed = false;
        if (forceNew || string.IsNullOrWhiteSpace(user.MfaPendingSecretEncrypted) || user.MfaPendingExpiresUtc is null || user.MfaPendingExpiresUtc <= DateTime.UtcNow)
        {
            var secret = MfaTotp.GenerateSecret();
            user.MfaPendingSecretEncrypted = _mfaProtector.EncryptSecret(secret, user.Key.ToString());
            user.MfaPendingSecret = null;
            user.MfaPendingExpiresUtc = DateTime.UtcNow.Add(MfaPendingLifetime);
            user.MfaPendingFailedAttempts = 0;
            changed = true;
        }

        return changed;
    }

    private string? GetPendingSecret(User user, out bool upgraded)
    {
        upgraded = false;
        if (!string.IsNullOrWhiteSpace(user.MfaPendingSecretEncrypted))
        {
            if (_mfaProtector.TryDecryptSecret(user.MfaPendingSecretEncrypted, user.Key.ToString(), out var bytes))
            {
                try
                {
                    return Encoding.UTF8.GetString(bytes);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(user.MfaPendingSecret))
        {
            var legacy = user.MfaPendingSecret;
            user.MfaPendingSecretEncrypted = _mfaProtector.EncryptSecret(legacy, user.Key.ToString());
            user.MfaPendingSecret = null;
            upgraded = true;
            return legacy;
        }

        return null;
    }

    private bool TryGetActiveSecret(User user, out string secret, out bool upgraded)
    {
        secret = string.Empty;
        upgraded = false;
        if (!string.IsNullOrWhiteSpace(user.MfaSecretEncrypted))
        {
            if (_mfaProtector.TryDecryptSecret(user.MfaSecretEncrypted, user.Key.ToString(), out var bytes))
            {
                try
                {
                    secret = Encoding.UTF8.GetString(bytes);
                    return !string.IsNullOrWhiteSpace(secret);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }

            return false;
        }

        if (!string.IsNullOrWhiteSpace(user.MfaSecret))
        {
            var legacy = user.MfaSecret;
            user.MfaSecretEncrypted = _mfaProtector.EncryptSecret(legacy, user.Key.ToString());
            user.MfaSecret = null;
            secret = legacy;
            upgraded = true;
            return true;
        }

        return false;
    }

    private static string? NormalizeOtpCode(string code)
    {
        if (string.IsNullOrWhiteSpace(code))
            return null;

        var trimmed = code.Trim();
        if (trimmed.Length != 6)
            return null;

        for (int i = 0; i < trimmed.Length; i++)
        {
            if (trimmed[i] < '0' || trimmed[i] > '9')
                return null;
        }

        return trimmed;
    }

    private static string MaskSecret(string secret)
    {
        if (string.IsNullOrWhiteSpace(secret))
            return string.Empty;

        const int reveal = 4;
        if (secret.Length <= reveal)
            return new string('*', secret.Length);

        return new string('*', secret.Length - reveal) + secret[^reveal..];
    }

    private static string BuildOtpClientScript(BmwContext context, string formAction)
    {
        var action = formAction.Replace("\\", "\\\\").Replace("'", "\\'").Replace("\"", "\\\"");
        var nonce = context.GetCspNonce();
        return $"<script nonce=\"{nonce}\">setupOtpValidation('{action}');</script>";
    }

    private static string BuildMfaAttemptKey(string scope, string key)
        => $"{scope}:{key}";

    private static bool IsThrottled(string key, int maxAttempts, out TimeSpan? retryAfter)
    {
        retryAfter = null;
        var tracker = MfaAttempts.GetOrAdd(key, _ => new AttemptTracker());
        return tracker.IsBlocked(MfaAttemptWindow, maxAttempts, MfaBaseBlockDuration, out retryAfter);
    }

    private static void RegisterFailure(string key, int maxAttempts)
    {
        var tracker = MfaAttempts.GetOrAdd(key, _ => new AttemptTracker());
        tracker.RegisterFailure(MfaAttemptWindow, maxAttempts, MfaBaseBlockDuration);
    }

    private static void RegisterSuccess(string key)
    {
        if (MfaAttempts.TryGetValue(key, out var tracker))
            tracker.Reset();
    }

    private static string FormatThrottleMessage(TimeSpan? retryAfter)
    {
        if (retryAfter.HasValue)
            return $"Too many attempts. Try again in {(int)Math.Ceiling(retryAfter.Value.TotalSeconds)} seconds.";

        return "Too many attempts. Please try again shortly.";
    }

    private static BackupCodeResult GenerateBackupCodes(User user, int count)
    {
        if (count <= 0)
            return new BackupCodeResult(Array.Empty<string>(), Array.Empty<string>());

        var codes = new string[count];
        var hashes = new string[count];
        for (int i = 0; i < count; i++)
        {
            var code = GenerateBackupCode();
            codes[i] = code;
            hashes[i] = HashBackupCode(user, code);
        }

        return new BackupCodeResult(codes, hashes);
    }

    private static string GenerateBackupCode()
    {
        Span<byte> bytes = stackalloc byte[8];
        RandomNumberGenerator.Fill(bytes);
        return Convert.ToHexString(bytes);
    }

    private static string HashBackupCode(User user, string code)
    {
        using var sha = SHA256.Create();
        var payload = Encoding.UTF8.GetBytes($"{user.Key}:{code}");
        return Convert.ToHexString(sha.ComputeHash(payload));
    }

    private sealed class AttemptTracker
    {
        private readonly object _sync = new();
        private DateTime _windowStartUtc = DateTime.UtcNow;
        private DateTime? _blockedUntilUtc;
        private int _count;

        public bool IsBlocked(TimeSpan window, int maxAttempts, TimeSpan baseBlock, out TimeSpan? retryAfter)
        {
            lock (_sync)
            {
                var now = DateTime.UtcNow;
                if (_blockedUntilUtc.HasValue && _blockedUntilUtc.Value > now)
                {
                    retryAfter = _blockedUntilUtc.Value - now;
                    return true;
                }

                if (now - _windowStartUtc > window)
                {
                    _windowStartUtc = now;
                    _count = 0;
                    _blockedUntilUtc = null;
                }

                retryAfter = null;
                return false;
            }
        }

        public void RegisterFailure(TimeSpan window, int maxAttempts, TimeSpan baseBlock)
        {
            lock (_sync)
            {
                var now = DateTime.UtcNow;
                if (now - _windowStartUtc > window)
                {
                    _windowStartUtc = now;
                    _count = 0;
                }

                _count++;
                if (_count >= maxAttempts)
                {
                    var exponent = Math.Min(6, _count - maxAttempts);
                    var delay = TimeSpan.FromSeconds(baseBlock.TotalSeconds * Math.Pow(2, exponent));
                    _blockedUntilUtc = now.Add(delay);
                }
            }
        }

        public void Reset()
        {
            lock (_sync)
            {
                _count = 0;
                _blockedUntilUtc = null;
                _windowStartUtc = DateTime.UtcNow;
            }
        }
    }

    private readonly record struct BackupCodeResult(string[] Codes, string[] Hashes);

    public async ValueTask DataApiListHandler(BmwContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        if (meta == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Entity not found.");
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        var queryDict = ToQueryDictionary(context.HttpRequest.Query);
        var query = DataScaffold.BuildQueryDefinition(queryDict, meta);

        var format = context.HttpRequest.Query["format"].ToString().ToLowerInvariant();
        var acceptCsv = context.HttpRequest.Headers["Accept"].ToString().Contains("text/csv", StringComparison.OrdinalIgnoreCase);

        // When pagination parameters are present, run the data and count queries concurrently
        // and return { items, total } so the VNext UI can render page controls correctly.
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
        cts.CancelAfter(DataQueryTimeout);

        if (query.Skip.HasValue || query.Top.HasValue)
        {
            var countQuery = DataScaffold.BuildQueryDefinition(queryDict, meta);
            countQuery.Skip = null;
            countQuery.Top = null;

            var dataTask  = DataScaffold.QueryAsync(meta, query, cts.Token).AsTask();
            var countTask = DataScaffold.CountAsync(meta, countQuery, cts.Token).AsTask();
            await Task.WhenAll(dataTask, countTask).ConfigureAwait(false);

            var results = await dataTask;
            var total   = await countTask;

            if (format == "csv" || acceptCsv)
            {
                var resultsList = new List<object?>();
                foreach (var item in results)
                    resultsList.Add((object?)item);
                var rows = BuildListPlainRowsWithId(meta, resultsList, out var headers);
                var csv = BuildCsv(headers, rows);
                await WriteTextResponseAsync(context, "text/csv", csv, $"{typeSlug}_list.csv");
                return;
            }

            using var payloadList = new BmwValueList<Dictionary<string, object?>>(32);
            foreach (var item in results)
                payloadList.Add(BuildApiModel(meta, (object)item));
            var payload = payloadList.ToArray();
            // Clamp total: if fewer items than requested were returned, the real total cannot exceed skip + returned count.
            // This prevents inflated page counts when the location map has stale entries for unreadable records.
            // Applies whether or not Top was specified: without a top limit we also know the total is at most skip + payload.Length.
            if (!query.Top.HasValue || payload.Length < query.Top.Value)
                total = Math.Min(total, (query.Skip ?? 0) + payload.Length);
            await WriteJsonResponseAsync(context, new Dictionary<string, object?>(2) { ["items"] = payload, ["total"] = total });
            return;
        }

        var allResults = await DataScaffold.QueryAsync(meta, query, cts.Token).ConfigureAwait(false);

        if (format == "csv" || acceptCsv)
        {
            var resultsList = new List<object?>();
            foreach (var item in allResults)
                resultsList.Add((object?)item);
            var rows = BuildListPlainRowsWithId(meta, resultsList, out var headers);
            var csv = BuildCsv(headers, rows);
            await WriteTextResponseAsync(context, "text/csv", csv, $"{typeSlug}_list.csv");
            return;
        }

        using var allPayloadList = new BmwValueList<Dictionary<string, object?>>(32);
        foreach (var item in allResults)
            allPayloadList.Add(BuildApiModel(meta, (object)item));
        var allPayload = allPayloadList.ToArray();
        await WriteJsonResponseAsync(context, allPayload);
    }

    public async ValueTask DataApiImportHandler(BmwContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        if (meta == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(errorMessage ?? "Entity not found.");
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"Access denied.\"}");
            return;
        }

        if (!await UserAuth.HasValidApiKeyAsync(context, context.RequestAborted).ConfigureAwait(false) &&
            (!ValidateApiCsrfHeader(context) || !CsrfProtection.ValidateApiToken(context)))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"CSRF validation failed.\"}");
            return;
        }

        if (!context.HttpRequest.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"Multipart form data required.\"}");
            return;
        }

        var form = await context.HttpRequest.ReadFormAsync();
        var file = form.Files.GetFile("csv_file");
        if (file == null || file.Length == 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"No CSV file uploaded.\"}");
            return;
        }

        var upsert = DataScaffold.IsTruthy(form["upsert"].ToString());
        string csvText;
        await using (var stream = file.OpenReadStream())
        using (var reader = new StreamReader(stream))
        {
            csvText = await reader.ReadToEndAsync();
        }

        var rows = ParseCsvRows(csvText);
        if (rows.Count < 2)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"CSV file is empty or missing headers.\"}");
            return;
        }

        var header = rows[0];
        var mapping = BuildCsvMapping(meta, header, out var idIndex, out var passwordIndex);

        int created = 0, updated = 0, skipped = 0;
        var importErrors = new List<string>();

        for (int i = 1; i < rows.Count; i++)
        {
            var row = rows[i];
            bool allBlankApi = true;
            foreach (var cell in row)
            {
                if (!string.IsNullOrWhiteSpace(cell))
                {
                    allBlankApi = false;
                    break;
                }
            }
            if (allBlankApi) continue;

            var rowNumber = i + 1;
            var idValue = idIndex >= 0 && idIndex < row.Length ? row[idIndex]?.Trim() : string.Empty;
            var isCreate = true;
            BaseDataObject instance;
            var upsertWithExplicitId = false;
            if (upsert && !string.IsNullOrWhiteSpace(idValue))
            {
                var existing = await DataScaffold.LoadAsync(meta, uint.Parse(idValue!));
                if (existing is BaseDataObject existingObject)
                {
                    instance = existingObject;
                    isCreate = false;
                }
                else
                {
                    instance = meta.Handlers.Create();
                    instance.Key = uint.Parse(idValue);
                    upsertWithExplicitId = true;
                }
            }
            else
            {
                instance = meta.Handlers.Create();
                DataScaffold.ApplyAutoGeneratedIds(meta, instance);
            }

            var values = RentFormDictionary(mapping.Count);
            foreach (var kvp in mapping)
            {
                var colIdx = kvp.Value;
                if (colIdx < row.Length)
                    values[kvp.Key] = row[colIdx];
            }

            var fieldErrors = DataScaffold.ApplyValuesFromForm(meta, instance, values, forCreate: isCreate || upsertWithExplicitId);
            ReturnFormDictionary(values);
            if (fieldErrors.Count > 0)
            {
                importErrors.Add($"Row {rowNumber}: {string.Join(", ", fieldErrors)}");
                skipped++;
                continue;
            }

            try
            {
                await DataScaffold.SaveAsync(meta, instance);
                if (isCreate) created++; else updated++;
            }
            catch (Exception ex)
            {
                importErrors.Add($"Row {rowNumber}: {ex.Message}");
                skipped++;
            }
        }

        var result = new { created, updated, skipped, errors = importErrors };
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(result));
    }

    public async ValueTask DataApiGetHandler(BmwContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        var id = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(id))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Entity not found.");
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, uint.Parse(id));
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Item not found.");
            return;
        }

        await WriteJsonResponseAsync(context, BuildApiModel(meta, instance));
    }

    public async ValueTask DataApiPostHandler(BmwContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        if (meta == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Entity not found.");
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        if (!await UserAuth.HasValidApiKeyAsync(context, context.RequestAborted).ConfigureAwait(false) &&
            (!ValidateApiCsrfHeader(context) || !CsrfProtection.ValidateApiToken(context)))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("CSRF validation failed.");
            return;
        }

        var instance = meta.Handlers.Create();

        // Apply auto-generated IDs before binding JSON values
        DataScaffold.ApplyAutoGeneratedIds(meta, instance);

        List<string> errors;
        if (context.HttpRequest.HasFormContentType)
        {
            var form = await context.HttpRequest.ReadFormAsync();
            var values = RentFormDictionary(form.Count);
            foreach (var kvp in form)
                values[kvp.Key] = (string?)kvp.Value.ToString();
            errors = DataScaffold.ApplyValuesFromForm(meta, instance, values, forCreate: true);
            await ApplyUploadFieldsFromFormAsync(context, meta, (BaseDataObject)instance, form, errors).ConfigureAwait(false);
            ReturnFormDictionary(values);
        }
        else
        {
            var payload = await ReadJsonBodyAsync(context);
            if (payload == null)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Invalid JSON body.");
                return;
            }
            errors = DataScaffold.ApplyValuesFromJson(meta, instance, payload, forCreate: true, allowMissing: false);
        }

        if (errors.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync(string.Join(" | ", errors));
            return;
        }

        // Run entity-level expression validation
        var validationResult = DataScaffold.ValidateEntity(meta, instance);
        if (!validationResult.IsValid)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync(string.Join(" | ", validationResult.AllErrors()));
            return;
        }

        var apiCreateErrors = new List<string>();
        await ValidateUserUniquenessAsync(meta, instance, excludeId: null, apiCreateErrors, context.RequestAborted).ConfigureAwait(false);
        if (apiCreateErrors.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status409Conflict;
            await context.Response.WriteAsync(string.Join(" | ", apiCreateErrors));
            return;
        }

        ApplyAuditInfo(instance, (await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false))?.UserName ?? "system", isCreate: true);
        await DataScaffold.ApplyAutoIdAsync(meta, instance, context.RequestAborted).ConfigureAwait(false);
        await DataScaffold.ApplyComputedFieldsAsync(meta, instance, ComputedTrigger.OnCreate, context.RequestAborted).ConfigureAwait(false);
        DataScaffold.ApplyCalculatedFields(meta, instance);
        await DataScaffold.SaveAsync(meta, instance);
        context.Response.StatusCode = StatusCodes.Status201Created;
        await WriteJsonResponseAsync(context, BuildApiModel(meta, instance));
    }

    public async ValueTask DataApiPutHandler(BmwContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        var id = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(id))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Entity not found.");
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        if (!await UserAuth.HasValidApiKeyAsync(context, context.RequestAborted).ConfigureAwait(false) &&
            (!ValidateApiCsrfHeader(context) || !CsrfProtection.ValidateApiToken(context)))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("CSRF validation failed.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, uint.Parse(id));
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Item not found.");
            return;
        }

        List<string> errors;
        if (context.HttpRequest.HasFormContentType)
        {
            var form = await context.HttpRequest.ReadFormAsync();
            var values = RentFormDictionary(form.Count);
            foreach (var kvp in form)
                values[kvp.Key] = (string?)kvp.Value.ToString();
            errors = DataScaffold.ApplyValuesFromForm(meta, instance, values, forCreate: false);
            errors = FilterMissingRequiredErrorsForPatchForm(meta, values, errors);
            await ApplyUploadFieldsFromFormAsync(context, meta, (BaseDataObject)instance, form, errors).ConfigureAwait(false);
            ReturnFormDictionary(values);
        }
        else
        {
            var payload = await ReadJsonBodyAsync(context);
            if (payload == null)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Invalid JSON body.");
                return;
            }
            errors = DataScaffold.ApplyValuesFromJson(meta, instance, payload, forCreate: false, allowMissing: false);
        }

        if (errors.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync(string.Join(" | ", errors));
            return;
        }

        // Run entity-level expression validation
        var validationResult = DataScaffold.ValidateEntity(meta, instance);
        if (!validationResult.IsValid)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync(string.Join(" | ", validationResult.AllErrors()));
            return;
        }

        var apiPutErrors = new List<string>();
        await ValidateUserUniquenessAsync(meta, instance, excludeId: id, apiPutErrors, context.RequestAborted).ConfigureAwait(false);
        if (apiPutErrors.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status409Conflict;
            await context.Response.WriteAsync(string.Join(" | ", apiPutErrors));
            return;
        }

        ApplyAuditInfo(instance, (await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false))?.UserName ?? "system", isCreate: false);
        await DataScaffold.ApplyComputedFieldsAsync(meta, (BaseDataObject)instance, ComputedTrigger.OnUpdate, context.RequestAborted).ConfigureAwait(false);
        DataScaffold.ApplyCalculatedFields(meta, (BaseDataObject)instance);
        await DataScaffold.SaveAsync(meta, instance);
        await WriteJsonResponseAsync(context, BuildApiModel(meta, instance));
    }

    public async ValueTask DataApiPatchHandler(BmwContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        var id = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(id))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Entity not found.");
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        if (!await UserAuth.HasValidApiKeyAsync(context, context.RequestAborted).ConfigureAwait(false) &&
            (!ValidateApiCsrfHeader(context) || !CsrfProtection.ValidateApiToken(context)))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("CSRF validation failed.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, uint.Parse(id));
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Item not found.");
            return;
        }

        List<string> errors;
        if (context.HttpRequest.HasFormContentType)
        {
            var form = await context.HttpRequest.ReadFormAsync();
            var values = RentFormDictionary(form.Count);
            foreach (var kvp in form)
                values[kvp.Key] = (string?)kvp.Value.ToString();
            errors = DataScaffold.ApplyValuesFromForm(meta, instance, values, forCreate: false);
            await ApplyUploadFieldsFromFormAsync(context, meta, (BaseDataObject)instance, form, errors).ConfigureAwait(false);
            ReturnFormDictionary(values);
        }
        else
        {
            var payload = await ReadJsonBodyAsync(context);
            if (payload == null)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                await context.Response.WriteAsync("Invalid JSON body.");
                return;
            }
            errors = DataScaffold.ApplyValuesFromJson(meta, instance, payload, forCreate: false, allowMissing: true);
        }

        if (errors.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync(string.Join(" | ", errors));
            return;
        }

        // Run entity-level expression validation
        var validationResult = DataScaffold.ValidateEntity(meta, instance);
        if (!validationResult.IsValid)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync(string.Join(" | ", validationResult.AllErrors()));
            return;
        }

        ApplyAuditInfo(instance, (await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false))?.UserName ?? "system", isCreate: false);
        await DataScaffold.ApplyComputedFieldsAsync(meta, (BaseDataObject)instance, ComputedTrigger.OnUpdate, context.RequestAborted).ConfigureAwait(false);
        DataScaffold.ApplyCalculatedFields(meta, (BaseDataObject)instance);
        await DataScaffold.SaveAsync(meta, instance);
        await WriteJsonResponseAsync(context, BuildApiModel(meta, instance));
    }

    public async ValueTask DataApiDeleteHandler(BmwContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        var id = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(id))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Entity not found.");
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        if (!await UserAuth.HasValidApiKeyAsync(context, context.RequestAborted).ConfigureAwait(false) &&
            (!ValidateApiCsrfHeader(context) || !CsrfProtection.ValidateApiToken(context)))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("CSRF validation failed.");
            return;
        }

        await DataScaffold.DeleteAsync(meta, uint.Parse(id));
        context.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    public async ValueTask DataApiFileGetHandler(BmwContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        var id = GetRouteValue(context, "id");
        var fieldName = GetRouteValue(context, "field");
        if (meta == null || string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(fieldName))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Entity not found.");
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, uint.Parse(id));
        if (instance is not BaseDataObject)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Item not found.");
            return;
        }

        var field = meta.FindField(fieldName);
        if (field == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Field not found.");
            return;
        }

        if (field.GetValueFn(instance) is not StoredFileData fileData || string.IsNullOrWhiteSpace(fileData.StorageKey))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("File not found.");
            return;
        }

        var fullPath = ResolveUploadPath(context, fileData.StorageKey);
        if (!File.Exists(fullPath))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("File not found.");
            return;
        }

        context.Response.ContentType = string.IsNullOrWhiteSpace(fileData.ContentType) ? "application/octet-stream" : fileData.ContentType;
        context.Response.Headers.ContentDisposition = $"inline; filename=\"{SanitizeFileName(fileData.FileName)}\"";
        await using var source = File.OpenRead(fullPath);
        await source.CopyToAsync(context.Response.Body, context.RequestAborted).ConfigureAwait(false);
    }

    // ── Generic attachment endpoints ─────────────────────────────────────────────

    private static bool TryGetAttachmentMeta(out DataEntityMetadata attachMeta)
        => DataScaffold.TryGetEntity("fileattachment", out attachMeta);

    private static Dictionary<string, object?> BuildAttachmentApiModel(FileAttachment a) =>
        new()
        {
            ["id"]               = a.Key,
            ["fileName"]         = a.FileName,
            ["contentType"]      = a.ContentType,
            ["sizeBytes"]        = a.SizeBytes,
            ["description"]      = a.Description,
            ["versionNumber"]    = a.VersionNumber,
            ["attachmentGroupId"] = a.AttachmentGroupId,
            ["isCurrentVersion"] = a.IsCurrentVersion,
            ["uploadedAt"]       = a.CreatedOnUtc,
            ["uploadedBy"]       = a.CreatedBy,
            ["downloadUrl"]      = $"/api/_attachments/{a.Key}/download"
        };

    /// <summary>GET /api/{type}/{id}/_attachments — list current-version attachments for a record.</summary>
    public async ValueTask AttachmentsListHandler(BmwContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        var idStr = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(idStr) || !uint.TryParse(idStr, out var recordKey))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Not found.").ConfigureAwait(false);
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.").ConfigureAwait(false);
            return;
        }

        if (!TryGetAttachmentMeta(out var attachMeta))
        {
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("[]").ConfigureAwait(false);
            return;
        }

        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = nameof(FileAttachment.RecordType),        Operator = QueryOperator.Equals, Value = meta.Slug },
                new QueryClause { Field = nameof(FileAttachment.RecordKey),         Operator = QueryOperator.Equals, Value = recordKey.ToString() },
                new QueryClause { Field = nameof(FileAttachment.IsCurrentVersion),  Operator = QueryOperator.Equals, Value = "true" }
            }
        };

        var rawItems = await DataScaffold.QueryAsync(attachMeta, query, context.RequestAborted).ConfigureAwait(false);
        var result = new List<Dictionary<string, object?>>();
        foreach (var item in rawItems)
        {
            if (item is FileAttachment a)
                result.Add(BuildAttachmentApiModel(a));
        }

        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(result, JsonIndented)).ConfigureAwait(false);
    }

    /// <summary>POST /api/{type}/{id}/_attachments — upload a new attachment (or new version) for a record.</summary>
    public async ValueTask AttachmentsUploadHandler(BmwContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        var idStr = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(idStr) || !uint.TryParse(idStr, out var recordKey))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Not found.").ConfigureAwait(false);
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.").ConfigureAwait(false);
            return;
        }

        if (!TryGetAttachmentMeta(out var attachMeta))
        {
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await context.Response.WriteAsync("{\"error\":\"Attachment entity not registered.\"}").ConfigureAwait(false);
            return;
        }

        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
        var userName = user?.UserName ?? "anonymous";

        if (!context.HttpRequest.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("{\"error\":\"Multipart form required.\"}").ConfigureAwait(false);
            return;
        }

        var form = await context.HttpRequest.ReadFormAsync(context.RequestAborted).ConfigureAwait(false);
        var uploadedFile = form.Files.GetFile("file");
        if (uploadedFile == null || uploadedFile.Length <= 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("{\"error\":\"No file uploaded.\"}").ConfigureAwait(false);
            return;
        }

        // Optional: description and replacesId (for versioning)
        form.TryGetValue("description", out var descValues);
        var description = descValues.Count > 0 ? (string?)descValues[0] : null;

        form.TryGetValue("replacesId", out var replacesValues);
        uint replacesKey = 0;
        if (replacesValues.Count > 0) uint.TryParse(replacesValues[0], out replacesKey);

        var safeName   = SanitizeFileName(uploadedFile.FileName);
        var extension  = Path.GetExtension(safeName);
        var storageKey = $"_attachments/{meta.Slug}/{recordKey}/{Guid.NewGuid():N}{extension}";
        var fullPath   = ResolveUploadPath(context, storageKey);
        var folder     = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(folder))
            Directory.CreateDirectory(folder);

        await using (var src = uploadedFile.OpenReadStream())
        await using (var dst = File.Create(fullPath))
        {
            await src.CopyToAsync(dst, context.RequestAborted).ConfigureAwait(false);
        }

        int nextVersion = 1;
        uint groupId    = 0;

        if (replacesKey > 0)
        {
            var previousRaw = await DataScaffold.LoadAsync(attachMeta, replacesKey, context.RequestAborted).ConfigureAwait(false);
            if (previousRaw is FileAttachment previous)
            {
                groupId = previous.AttachmentGroupId == 0 ? previous.Key : previous.AttachmentGroupId;

                var groupQuery = new QueryDefinition
                {
                    Clauses = new List<QueryClause>
                    {
                        new QueryClause { Field = nameof(FileAttachment.AttachmentGroupId), Operator = QueryOperator.Equals, Value = groupId.ToString() }
                    }
                };
                var groupRaw = await DataScaffold.QueryAsync(attachMeta, groupQuery, context.RequestAborted).ConfigureAwait(false);
                foreach (var raw in groupRaw)
                {
                    if (raw is not FileAttachment gi) continue;
                    if (gi.VersionNumber >= nextVersion) nextVersion = gi.VersionNumber + 1;
                    if (gi.IsCurrentVersion)
                    {
                        gi.IsCurrentVersion = false;
                        gi.Touch(userName);
                        await DataScaffold.SaveAsync(attachMeta, gi, context.RequestAborted).ConfigureAwait(false);
                    }
                }

                if (nextVersion == 1) nextVersion = 2;
            }
        }

        var attachment = new FileAttachment(userName)
        {
            RecordType        = meta.Slug,
            RecordKey         = recordKey,
            FileName          = safeName,
            ContentType       = string.IsNullOrWhiteSpace(uploadedFile.ContentType) ? "application/octet-stream" : uploadedFile.ContentType,
            SizeBytes         = uploadedFile.Length,
            StorageKey        = storageKey,
            Description       = description,
            AttachmentGroupId = groupId,
            VersionNumber     = nextVersion,
            IsCurrentVersion  = true
        };

        await DataScaffold.ApplyAutoIdAsync(attachMeta, attachment, context.RequestAborted).ConfigureAwait(false);
        await DataScaffold.SaveAsync(attachMeta, attachment, context.RequestAborted).ConfigureAwait(false);

        // If this is the root version (no group yet), set groupId = its own Key
        if (groupId == 0)
        {
            attachment.AttachmentGroupId = attachment.Key;
            await DataScaffold.SaveAsync(attachMeta, attachment, context.RequestAborted).ConfigureAwait(false);
        }

        context.Response.StatusCode = StatusCodes.Status201Created;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(BuildAttachmentApiModel(attachment), JsonIndented)).ConfigureAwait(false);
    }

    /// <summary>GET /api/_attachments/{id}/download — stream an attachment file to the client.</summary>
    public async ValueTask AttachmentsDownloadHandler(BmwContext context)
    {
        var idStr = GetRouteValue(context, "id");
        if (string.IsNullOrWhiteSpace(idStr) || !uint.TryParse(idStr, out var attachmentKey)
            || !TryGetAttachmentMeta(out var attachMeta))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Not found.").ConfigureAwait(false);
            return;
        }

        var raw = await DataScaffold.LoadAsync(attachMeta, attachmentKey, context.RequestAborted).ConfigureAwait(false);
        if (raw is not FileAttachment attachment || string.IsNullOrWhiteSpace(attachment.StorageKey))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Attachment not found.").ConfigureAwait(false);
            return;
        }

        // Check permission against the owning entity
        if (!string.IsNullOrWhiteSpace(attachment.RecordType)
            && DataScaffold.TryGetEntity(attachment.RecordType, out var ownerMeta)
            && !await HasEntityPermissionAsync(context, ownerMeta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.").ConfigureAwait(false);
            return;
        }

        var fullPath = ResolveUploadPath(context, attachment.StorageKey);
        if (!File.Exists(fullPath))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("File not found on disk.").ConfigureAwait(false);
            return;
        }

        // Serve inline for previewable types; force download otherwise
        var ct = string.IsNullOrWhiteSpace(attachment.ContentType) ? "application/octet-stream" : attachment.ContentType;
        var disposition = "attachment";
        if (ct.StartsWith("image/", StringComparison.OrdinalIgnoreCase)
            || ct.StartsWith("text/plain", StringComparison.OrdinalIgnoreCase)
            || ct.Equals("application/pdf", StringComparison.OrdinalIgnoreCase))
        {
            disposition = "inline";
        }

        context.Response.ContentType = ct;
        context.Response.Headers.ContentDisposition = $"{disposition}; filename=\"{SanitizeFileName(attachment.FileName)}\"";
        await using var src = File.OpenRead(fullPath);
        await src.CopyToAsync(context.Response.Body, context.RequestAborted).ConfigureAwait(false);
    }

    /// <summary>DELETE /api/_attachments/{id} — delete an attachment and its physical file.</summary>
    public async ValueTask AttachmentsDeleteHandler(BmwContext context)
    {
        var idStr = GetRouteValue(context, "id");
        if (string.IsNullOrWhiteSpace(idStr) || !uint.TryParse(idStr, out var attachmentKey)
            || !TryGetAttachmentMeta(out var attachMeta))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Not found.").ConfigureAwait(false);
            return;
        }

        var raw = await DataScaffold.LoadAsync(attachMeta, attachmentKey, context.RequestAborted).ConfigureAwait(false);
        if (raw is not FileAttachment attachment)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Attachment not found.").ConfigureAwait(false);
            return;
        }

        // Check permission against the owning entity
        if (!string.IsNullOrWhiteSpace(attachment.RecordType)
            && DataScaffold.TryGetEntity(attachment.RecordType, out var ownerMeta)
            && !await HasEntityPermissionAsync(context, ownerMeta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.").ConfigureAwait(false);
            return;
        }

        // Delete physical file
        if (!string.IsNullOrWhiteSpace(attachment.StorageKey))
        {
            var fullPath = ResolveUploadPath(context, attachment.StorageKey);
            if (File.Exists(fullPath))
                File.Delete(fullPath);
        }

        await DataScaffold.DeleteAsync(attachMeta, attachmentKey, context.RequestAborted).ConfigureAwait(false);

        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync("{\"deleted\":true}").ConfigureAwait(false);
    }

    /// <summary>GET /api/_attachments/{id}/versions — list all versions of an attachment group.</summary>
    public async ValueTask AttachmentsVersionsHandler(BmwContext context)
    {
        var idStr = GetRouteValue(context, "id");
        if (string.IsNullOrWhiteSpace(idStr) || !uint.TryParse(idStr, out var attachmentKey)
            || !TryGetAttachmentMeta(out var attachMeta))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Not found.").ConfigureAwait(false);
            return;
        }

        var rootRaw = await DataScaffold.LoadAsync(attachMeta, attachmentKey, context.RequestAborted).ConfigureAwait(false);
        if (rootRaw is not FileAttachment root)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Attachment not found.").ConfigureAwait(false);
            return;
        }

        // Check permission against the owning entity
        if (!string.IsNullOrWhiteSpace(root.RecordType)
            && DataScaffold.TryGetEntity(root.RecordType, out var ownerMeta)
            && !await HasEntityPermissionAsync(context, ownerMeta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.").ConfigureAwait(false);
            return;
        }

        var groupId = root.AttachmentGroupId == 0 ? root.Key : root.AttachmentGroupId;
        var groupQuery = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = nameof(FileAttachment.AttachmentGroupId), Operator = QueryOperator.Equals, Value = groupId.ToString() }
            }
        };

        var rawVersions = await DataScaffold.QueryAsync(attachMeta, groupQuery, context.RequestAborted).ConfigureAwait(false);

        // Collect and sort by VersionNumber ascending
        var versionList = new List<FileAttachment>();
        foreach (var rv in rawVersions)
        {
            if (rv is FileAttachment fa) versionList.Add(fa);
        }
        versionList.Sort(static (a, b) => a.VersionNumber.CompareTo(b.VersionNumber));

        var result = new List<Dictionary<string, object?>>(versionList.Count);
        foreach (var v in versionList)
            result.Add(BuildAttachmentApiModel(v));

        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(result, JsonIndented)).ConfigureAwait(false);
    }

    // ── Record comment endpoints ────────────────────────────────────────────────

    private static bool TryGetCommentMeta(out DataEntityMetadata commentMeta)
        => DataScaffold.TryGetEntity("recordcomment", out commentMeta);

    private static Dictionary<string, object?> BuildCommentApiModel(RecordComment c) =>
        new()
        {
            ["id"]        = c.Key,
            ["text"]      = c.Text,
            ["author"]    = c.CreatedBy,
            ["createdAt"] = c.CreatedOnUtc,
            ["updatedAt"] = c.UpdatedOnUtc,
            ["updatedBy"] = c.UpdatedBy
        };

    /// <summary>GET /api/{type}/{id}/_comments — list comments for a record.</summary>
    public async ValueTask CommentsListHandler(BmwContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        var idStr = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(idStr) || !uint.TryParse(idStr, out var recordKey))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Not found.").ConfigureAwait(false);
            return;
        }
        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.").ConfigureAwait(false);
            return;
        }
        if (!TryGetCommentMeta(out var commentMeta))
        {
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("[]").ConfigureAwait(false);
            return;
        }

        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = nameof(RecordComment.RecordType), Operator = QueryOperator.Equals, Value = meta.Slug },
                new QueryClause { Field = nameof(RecordComment.RecordKey),  Operator = QueryOperator.Equals, Value = recordKey.ToString() }
            }
        };

        var rawItems = await DataScaffold.QueryAsync(commentMeta, query, context.RequestAborted).ConfigureAwait(false);
        var result = new List<Dictionary<string, object?>>();
        foreach (var item in rawItems)
        {
            if (item is RecordComment c)
                result.Add(BuildCommentApiModel(c));
        }
        // Sort by creation time ascending (oldest first, chat-style)
        result.Sort((a, b) => ((DateTime)a["createdAt"]!).CompareTo((DateTime)b["createdAt"]!));

        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(result, JsonIndented)).ConfigureAwait(false);
    }

    /// <summary>POST /api/{type}/{id}/_comments — add a comment to a record.</summary>
    public async ValueTask CommentsAddHandler(BmwContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        var idStr = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(idStr) || !uint.TryParse(idStr, out var recordKey))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Not found.").ConfigureAwait(false);
            return;
        }
        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.").ConfigureAwait(false);
            return;
        }
        if (!TryGetCommentMeta(out var commentMeta))
        {
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await context.Response.WriteAsync("Comment entity not registered.").ConfigureAwait(false);
            return;
        }

        string? text = null;
        if (context.HttpRequest.ContentType?.Contains("application/json") == true)
        {
            using var reader = new StreamReader(context.HttpRequest.Body);
            var body = await reader.ReadToEndAsync().ConfigureAwait(false);
            var doc = JsonSerializer.Deserialize<Dictionary<string, string>>(body);
            text = doc?.GetValueOrDefault("text");
        }
        else if (context.HttpRequest.HasFormContentType)
        {
            var form = await context.HttpRequest.ReadFormAsync().ConfigureAwait(false);
            text = form["text"].ToString();
        }

        if (string.IsNullOrWhiteSpace(text))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Comment text is required.").ConfigureAwait(false);
            return;
        }

        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
        var userName = user?.UserName ?? "anonymous";
        var comment = new RecordComment(userName)
        {
            RecordType = meta.Slug,
            RecordKey  = recordKey,
            Text       = text.Trim()
        };

        await DataScaffold.ApplyAutoIdAsync(commentMeta, comment, context.RequestAborted).ConfigureAwait(false);
        await DataScaffold.SaveAsync(commentMeta, comment, context.RequestAborted).ConfigureAwait(false);

        context.Response.StatusCode = StatusCodes.Status201Created;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(BuildCommentApiModel(comment), JsonIndented)).ConfigureAwait(false);
    }

    /// <summary>PATCH /api/_comments/{id} — edit a comment (own comments only).</summary>
    public async ValueTask CommentsEditHandler(BmwContext context)
    {
        var idStr = GetRouteValue(context, "id");
        if (string.IsNullOrWhiteSpace(idStr) || !uint.TryParse(idStr, out var commentId))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid comment ID.").ConfigureAwait(false);
            return;
        }
        if (!TryGetCommentMeta(out var commentMeta))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Not found.").ConfigureAwait(false);
            return;
        }

        var existing = await DataScaffold.LoadAsync(commentMeta, commentId, context.RequestAborted).ConfigureAwait(false);
        if (existing is not RecordComment comment)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Comment not found.").ConfigureAwait(false);
            return;
        }

        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
        var userName = user?.UserName ?? "anonymous";
        if (!string.Equals(comment.CreatedBy, userName, StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("You can only edit your own comments.").ConfigureAwait(false);
            return;
        }

        string? text = null;
        if (context.HttpRequest.ContentType?.Contains("application/json") == true)
        {
            using var reader = new StreamReader(context.HttpRequest.Body);
            var body = await reader.ReadToEndAsync().ConfigureAwait(false);
            var doc = JsonSerializer.Deserialize<Dictionary<string, string>>(body);
            text = doc?.GetValueOrDefault("text");
        }

        if (string.IsNullOrWhiteSpace(text))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Comment text is required.").ConfigureAwait(false);
            return;
        }

        comment.Text = text.Trim();
        comment.Touch(userName);
        await DataScaffold.SaveAsync(commentMeta, comment, context.RequestAborted).ConfigureAwait(false);

        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(BuildCommentApiModel(comment), JsonIndented)).ConfigureAwait(false);
    }

    /// <summary>DELETE /api/_comments/{id} — delete a comment (own comments only).</summary>
    public async ValueTask CommentsDeleteHandler(BmwContext context)
    {
        var idStr = GetRouteValue(context, "id");
        if (string.IsNullOrWhiteSpace(idStr) || !uint.TryParse(idStr, out var commentId))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid comment ID.").ConfigureAwait(false);
            return;
        }
        if (!TryGetCommentMeta(out var commentMeta))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Not found.").ConfigureAwait(false);
            return;
        }

        var existing = await DataScaffold.LoadAsync(commentMeta, commentId, context.RequestAborted).ConfigureAwait(false);
        if (existing is not RecordComment comment)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Comment not found.").ConfigureAwait(false);
            return;
        }

        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
        var userName = user?.UserName ?? "anonymous";
        if (!string.Equals(comment.CreatedBy, userName, StringComparison.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("You can only delete your own comments.").ConfigureAwait(false);
            return;
        }

        await DataScaffold.DeleteAsync(commentMeta, commentId, context.RequestAborted).ConfigureAwait(false);
        context.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    public async ValueTask GlobalSearchHandler(BmwContext context)
    {
        var q = context.HttpRequest.Query["q"].ToString().Trim();
        if (string.IsNullOrWhiteSpace(q) || q.Length < 2)
        {
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"groups\":[]}").ConfigureAwait(false);
            return;
        }

        const int maxPerGroup = 5;

        var user            = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
        var userPermissions = user?.Permissions ?? Array.Empty<string>();

        var groups = new List<Dictionary<string, object?>>();

        foreach (var entityMeta in DataScaffold.Entities)
        {
            if (!string.IsNullOrEmpty(entityMeta.Permissions) && !userPermissions.Contains(entityMeta.Permissions))
                continue;

            // Build OR-group of Contains clauses for each searchable string list field
            var stringListFields = entityMeta.ListFields
                .Where(f => f.FieldType is FormFieldType.String
                                        or FormFieldType.TextArea
                                        or FormFieldType.Email
                                        or FormFieldType.Link
                                        or FormFieldType.Tags
                                        or FormFieldType.Markdown)
                .ToList();

            if (stringListFields.Count == 0)
                continue;

            var orGroup = new QueryGroup { Logic = QueryGroupLogic.Or };
            foreach (var f in stringListFields)
                orGroup.Clauses.Add(new QueryClause { Field = f.Name, Operator = QueryOperator.Contains, Value = q });

            var query = new QueryDefinition
            {
                Top    = maxPerGroup,
                Groups = new List<QueryGroup> { orGroup }
            };

            IEnumerable<BaseDataObject> results;
            try
            {
                results = await entityMeta.Handlers.QueryAsync(query, context.RequestAborted).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger?.LogError($"GlobalSearch|query-error|entity={entityMeta.Slug}|q={q}|msg={ex.Message}", ex);
                continue;
            }

            var items = new List<Dictionary<string, object?>>();
            foreach (var record in results)
            {
                // Build a display label from the first non-empty string list field value
                string label = string.Empty;
                foreach (var f in stringListFields)
                {
                    var v = f.GetValueFn(record)?.ToString();
                    if (!string.IsNullOrWhiteSpace(v)) { label = v; break; }
                }
                if (string.IsNullOrWhiteSpace(label))
                    label = record.Key.ToString();

                items.Add(new Dictionary<string, object?>
                {
                    ["id"]    = record.Key,
                    ["label"] = label
                });
            }

            if (items.Count == 0)
                continue;

            groups.Add(new Dictionary<string, object?>
            {
                ["slug"]  = entityMeta.Slug,
                ["name"]  = entityMeta.Name,
                ["items"] = items
            });
        }

        await WriteJsonResponseAsync(context, new Dictionary<string, object?> { ["groups"] = groups }).ConfigureAwait(false);
    }

    public async ValueTask MetricsJsonHandler(BmwContext context)
    {
        var app = context.GetApp();
        if (app == null)
        {
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            return;
        }

        var snapshot = app.Metrics.GetSnapshot();
        var payload = new Dictionary<string, object?>
        {
            ["totalRequests"] = snapshot.TotalRequests,
            ["errorRequests"] = snapshot.ErrorRequests,
            ["averageResponseTimeMs"] = snapshot.AverageResponseTime.TotalMilliseconds,
            ["recentMinimumResponseTimeMs"] = snapshot.RecentMinimumResponseTime.TotalMilliseconds,
            ["recentMaximumResponseTimeMs"] = snapshot.RecentMaximumResponseTime.TotalMilliseconds,
            ["recentAverageResponseTimeMs"] = snapshot.RecentAverageResponseTime.TotalMilliseconds,
            ["recentP95ResponseTimeMs"] = snapshot.RecentP95ResponseTime.TotalMilliseconds,
            ["recentP99ResponseTimeMs"] = snapshot.RecentP99ResponseTime.TotalMilliseconds,
            ["recent10sAverageResponseTimeMs"] = snapshot.Recent10sAverageResponseTime.TotalMilliseconds,
            ["requests2xx"] = snapshot.Requests2xx,
            ["requests4xx"] = snapshot.Requests4xx,
            ["requests5xx"] = snapshot.Requests5xx,
            ["requestsOther"] = snapshot.RequestsOther,
            ["throttledRequests"] = snapshot.ThrottledRequests,
            ["processUptimeSeconds"] = (long)snapshot.ProcessUptime.TotalSeconds,
            ["operatingSystem"] = RuntimeInformation.OSDescription,
            ["osArchitecture"] = RuntimeInformation.OSArchitecture.ToString(),
            ["processArchitecture"] = RuntimeInformation.ProcessArchitecture.ToString(),
            ["processorCount"] = Environment.ProcessorCount,
            ["dotnetRuntime"] = RuntimeInformation.FrameworkDescription,
            ["dataLocation"] = MetricsTracker.DataRoot,
            ["processId"] = snapshot.ProcessId,
            ["workingSet64"] = snapshot.WorkingSet64,
            ["virtualMemorySize64"] = snapshot.VirtualMemorySize64
        };

        await WriteJsonResponseAsync(context, payload);
    }

    public async ValueTask LogsViewerHandler(BmwContext context)
    {
        await BuildPageHandler(ctx =>
        {
            var root = GetLogRoot(ctx);
            ctx.SetStringValue("title", "Logs");

            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            {
                ctx.SetStringValue("html_message", "<p>No log folders found.</p>");
                return;
            }

            var date = ctx.HttpRequest.Query["date"].ToString();
            var hour = ctx.HttpRequest.Query["hour"].ToString();
            var file = ctx.HttpRequest.Query["file"].ToString();
            var year = ctx.HttpRequest.Query["year"].ToString();
            var month = ctx.HttpRequest.Query["month"].ToString();

            var dates = new List<string>();
            foreach (var dir in Directory.GetDirectories(root))
            {
                var dirName = Path.GetFileName(dir);
                if (!string.IsNullOrWhiteSpace(dirName))
                    dates.Add(dirName!);
            }

            {
                bool dateFound = false;
                foreach (var d in dates)
                {
                    if (string.Equals(d, date, StringComparison.OrdinalIgnoreCase))
                    {
                        dateFound = true;
                        break;
                    }
                }
                if (!dateFound)
                    date = string.Empty;
            }

            List<string> hours;
            if (string.IsNullOrWhiteSpace(date))
            {
                hours = new List<string>();
            }
            else
            {
                hours = new List<string>();
                foreach (var dir in Directory.GetDirectories(Path.Combine(root, date)))
                {
                    var dirName = Path.GetFileName(dir);
                    if (!string.IsNullOrWhiteSpace(dirName))
                        hours.Add(dirName!);
                }
            }

            hours.Sort((a, b) =>
            {
                int cmp = ParseHourValue(a).CompareTo(ParseHourValue(b));
                return cmp != 0 ? cmp : string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
            });

            {
                bool hourFound = false;
                foreach (var h in hours)
                {
                    if (string.Equals(h, hour, StringComparison.OrdinalIgnoreCase))
                    {
                        hourFound = true;
                        break;
                    }
                }
                if (!hourFound)
                    hour = string.Empty;
            }

            List<LogFileEntry> fileEntries;
            if (string.IsNullOrWhiteSpace(date) || string.IsNullOrWhiteSpace(hour))
            {
                fileEntries = new List<LogFileEntry>();
            }
            else
            {
                fileEntries = new List<LogFileEntry>();
                foreach (var filePath in Directory.GetFiles(Path.Combine(root, date, hour), "*.log"))
                {
                    var fileName = Path.GetFileName(filePath);
                    if (!string.IsNullOrWhiteSpace(fileName))
                        fileEntries.Add(BuildLogFileEntry(fileName!));
                }
                fileEntries.Sort((a, b) =>
                {
                    int cmp = a.SortKey.CompareTo(b.SortKey);
                    return cmp != 0 ? cmp : string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
                });
            }

            {
                bool fileFound = false;
                foreach (var entry in fileEntries)
                {
                    if (string.Equals(entry.Name, file, StringComparison.OrdinalIgnoreCase))
                    {
                        fileFound = true;
                        break;
                    }
                }
                if (!fileFound)
                    file = string.Empty;
            }

            var yearEntries = BuildLogYears(root, dates);
            var selectedYearKey = string.IsNullOrWhiteSpace(year) ? ResolveYearKey(selectedDate: date) : year;
            var selectedMonthKey = string.IsNullOrWhiteSpace(month) ? ResolveMonthKey(selectedDate: date) : month;

            {
                bool yearFound = false;
                foreach (var entry in yearEntries)
                {
                    if (string.Equals(entry.Key, selectedYearKey, StringComparison.OrdinalIgnoreCase))
                    {
                        yearFound = true;
                        break;
                    }
                }
                if (!yearFound)
                    selectedYearKey = string.Empty;
            }

            if (string.IsNullOrWhiteSpace(selectedYearKey) && yearEntries.Count > 0)
            {
                var latestYear = yearEntries[0];
                for (int yi = 1; yi < yearEntries.Count; yi++)
                {
                    if (yearEntries[yi].YearDate > latestYear.YearDate)
                        latestYear = yearEntries[yi];
                }
                selectedYearKey = latestYear.Key;
            }

            LogYearEntry selectedYear = default;
            foreach (var entry in yearEntries)
            {
                if (string.Equals(entry.Key, selectedYearKey, StringComparison.OrdinalIgnoreCase))
                {
                    selectedYear = entry;
                    break;
                }
            }
            {
                bool monthFound = false;
                if (selectedYear.Months != null)
                {
                    foreach (var entry in selectedYear.Months)
                    {
                        if (string.Equals(entry.Key, selectedMonthKey, StringComparison.OrdinalIgnoreCase))
                        {
                            monthFound = true;
                            break;
                        }
                    }
                }
                if (!monthFound)
                    selectedMonthKey = string.Empty;
            }

            if (string.IsNullOrWhiteSpace(selectedMonthKey) && selectedYear.Months?.Count > 0)
            {
                var latestMonth = selectedYear.Months![0];
                for (int mi = 1; mi < selectedYear.Months.Count; mi++)
                {
                    if (selectedYear.Months[mi].MonthDate > latestMonth.MonthDate)
                        latestMonth = selectedYear.Months[mi];
                }
                selectedMonthKey = latestMonth.Key;
            }

            var monthEntries = new List<LogMonthEntry>();
            foreach (var entry in yearEntries)
            {
                if (entry.Months != null)
                    monthEntries.AddRange(entry.Months);
            }
            var actionsHtml = RenderLogActions(yearEntries, selectedYearKey, selectedMonthKey, date, hour);

            var html = new StringBuilder(2048);
            if (!string.IsNullOrWhiteSpace(actionsHtml))
                html.Append(actionsHtml);
            html.Append("<div class=\"bm-log-layout\">");
            html.Append("<div class=\"bm-log-panel bm-log-tree\">");
            html.Append(RenderLogTree(yearEntries, hours, fileEntries, selectedYearKey, selectedMonthKey, date, hour, file));
            html.Append("</div>");
            html.Append("<div class=\"bm-log-panel bm-log-viewer\">");
            if (!string.IsNullOrWhiteSpace(file))
            {
                var fullPath = Path.GetFullPath(Path.Combine(root, date ?? string.Empty, hour ?? string.Empty, file));
                var normalizedRoot = Path.GetFullPath(root);
                LogFileEntry selectedEntry = default;
                foreach (var fe in fileEntries)
                {
                    if (string.Equals(fe.Name, file, StringComparison.OrdinalIgnoreCase))
                    {
                        selectedEntry = fe;
                        break;
                    }
                }

                var isUnderRoot = fullPath.StartsWith(normalizedRoot, StringComparison.OrdinalIgnoreCase)
                    && (fullPath.Length == normalizedRoot.Length
                        || fullPath[normalizedRoot.Length] == Path.DirectorySeparatorChar
                        || fullPath[normalizedRoot.Length] == Path.AltDirectorySeparatorChar);

                if (isUnderRoot && selectedEntry.Name != null && File.Exists(fullPath))
                {
                    html.Append(RenderLogFile(fullPath, file, selectedEntry.IsError));
                }
                else
                {
                    html.Append("<p class=\"text-danger mb-0\">Invalid log file selection.</p>");
                }
            }
            else
            {
                html.Append("<p class=\"text-muted mb-0\">Select a log file to view.</p>");
            }
            html.Append("</div>");
            html.Append("</div>");

            ctx.SetStringValue("html_message", html.ToString());
        })(context);
    }

    public async ValueTask LogsPruneHandler(BmwContext context)
    {
        await BuildPageHandler(ctx =>
        {
            var root = GetLogRoot(ctx);
            if (!TryResolveLogTarget(ctx.HttpRequest.Query, root, out var target, out var errorMessage))
            {
                ctx.SetStringValue("title", "Prune Logs");
                ctx.SetStringValue("html_message", $"<p class=\"text-danger\">{WebUtility.HtmlEncode(errorMessage)}</p>");
                return;
            }

            var csrfToken = CsrfProtection.EnsureToken(ctx);
            var fields = new List<FormField>
            {
                new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken),
                new FormField(FormFieldType.Hidden, "scope", string.Empty, Value: target.Scope),
                new FormField(FormFieldType.Hidden, "year", string.Empty, Value: target.MonthKey ?? string.Empty),
                new FormField(FormFieldType.Hidden, "month", string.Empty, Value: target.MonthKey ?? string.Empty),
                new FormField(FormFieldType.Hidden, "date", string.Empty, Value: target.DateFolder ?? string.Empty),
                new FormField(FormFieldType.Hidden, "hour", string.Empty, Value: target.Hour ?? string.Empty)
            };

            ctx.SetStringValue("title", "Prune Logs");
            ctx.SetStringValue("html_message", $"<p>Are you sure you want to delete logs for <strong>{WebUtility.HtmlEncode(target.Label)}</strong>?</p>");
            ctx.AddFormDefinition(new FormDefinition("/admin/logs/prune", "post", "Confirm Delete", fields));
        })(context);
    }

    public async ValueTask LogsPrunePostHandler(BmwContext context)
    {
        if (!context.HttpRequest.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var form = await context.HttpRequest.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var root = GetLogRoot(context);
        var query = new Dictionary<string, StringValues>(5, StringComparer.OrdinalIgnoreCase)
        {
            ["scope"] = form["scope"],
            ["year"] = form["year"],
            ["month"] = form["month"],
            ["date"] = form["date"],
            ["hour"] = form["hour"]
        };

        if (!TryResolveLogTarget(query, root, out var target, out _))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        foreach (var directory in target.Directories)
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }

        CleanupEmptyLogParents(target, root);
        context.Response.Redirect("/admin/logs", permanent: false);
    }

    public async ValueTask LogsDownloadHandler(BmwContext context)
    {
        var root = GetLogRoot(context);
        if (!TryResolveLogTarget(context.HttpRequest.Query, root, out var target, out var errorMessage))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync(errorMessage ?? "Invalid log selection.");
            return;
        }

        context.Response.ContentType = "application/zip";
        context.Response.Headers["Content-Disposition"] = $"attachment; filename=\"{target.ZipName}\"";

        var tempPath = Path.Combine(Path.GetTempPath(), $"logs_{Guid.NewGuid():N}.zip");
        try
        {
            await using (var tempStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write, FileShare.None, 64 * 1024, useAsync: true))
            using (var archive = new ZipArchive(tempStream, ZipArchiveMode.Create, leaveOpen: true))
            {
                foreach (var directory in target.Directories)
                {
                    if (!Directory.Exists(directory))
                        continue;

                    foreach (var file in Directory.EnumerateFiles(directory, "*.log", SearchOption.AllDirectories))
                    {
                        var relative = Path.GetRelativePath(root, file).Replace('\\', '/');
                        var entry = archive.CreateEntry(relative, CompressionLevel.Fastest);
                        await using var entryStream = entry.Open();
                        await using var sourceStream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 64 * 1024, useAsync: true);
                        await sourceStream.CopyToAsync(entryStream);
                    }
                }
            }

            await using var readStream = new FileStream(tempPath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, useAsync: true);
            await readStream.CopyToAsync(context.Response.Body);
        }
        finally
        {
            try
            {
                if (File.Exists(tempPath))
                    File.Delete(tempPath);
            }
            catch
            {
            }
        }
    }

    public async ValueTask SampleDataHandler(BmwContext context)
    {
        var entities = RuntimeEntityRegistry.Current.All;
        if (entities.Count == 0)
        {
            await BuildPageHandler(ctx =>
            {
                ctx.SetStringValue("title", "Generate Sample Data");
                ctx.SetStringValue("html_message", "<div class=\"alert alert-info\">No entity types are registered. " +
                    "Deploy modules from the <a href=\"/admin/gallery\">Gallery</a> first.</div>");
            })(context);
            return;
        }
        await BuildPageHandler(ctx =>
        {
            RenderSampleDataForm(ctx, "<p>Generate sample data for load and indexing tests.</p>", entities, 10, clearExisting: false);
        })(context);
    }

    public async ValueTask SampleDataPostHandler(BmwContext context)
    {
        if (!context.HttpRequest.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.SetStringValue("title", "Generate Sample Data");
            context.SetStringValue("html_message", "<p>Invalid form submission.</p>");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var form = await context.HttpRequest.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            var entities = RuntimeEntityRegistry.Current.All;
            context.SetStringValue("title", "Generate Sample Data");
            context.SetStringValue("html_message", "<p>Invalid security token. Please try again.</p>");
            RenderSampleDataForm(context, "<p>Invalid security token. Please try again.</p>", entities, 10, clearExisting: false);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var errors = new List<string>();
        var registry = RuntimeEntityRegistry.Current;
        var entityCounts = new Dictionary<string, int>(registry.All.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var model in registry.All)
        {
            var count = ParseSampleCount(form, model.Slug, errors);
            if (count > 0)
                entityCounts[model.Slug] = count;
        }
        var clearExisting = ParseSampleToggle(form, "clearExisting");

        if (errors.Count > 0)
        {
            context.SetStringValue("title", "Generate Sample Data");
            context.SetStringValue("html_message", $"<div class=\"alert alert-danger\">{JoinEncoded("<br/>", errors)}</div>");
            RenderSampleDataForm(context, $"<div class=\"alert alert-danger\">{JoinEncoded("<br/>", errors)}</div>", registry.All, 10, clearExisting);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var userName = (await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false))?.UserName ?? "system";

        var capturedCounts = new Dictionary<string, int>(entityCounts, StringComparer.OrdinalIgnoreCase);
        var capturedClear = clearExisting;
        var capturedUser = userName;

        var jobId = BackgroundJobService.Instance.StartJob(
            "Generate Sample Data",
            "/admin/sample-data",
            async (progress, ct) =>
            {
                progress.Report(0, "Starting sample data generation…");
                var walProvider = DataStoreProvider.PrimaryProvider as WalDataProvider;
                if (walProvider == null)
                {
                    progress.Report(100, "Error: WalDataProvider is not available.");
                    return;
                }

                var slugs = new List<string>(capturedCounts.Keys);
                int totalEntities = slugs.Count;
                int entityIndex = 0;
                int totalRecords = 0;
                foreach (var v in capturedCounts.Values)
                    totalRecords += v;
                int savedRecords = 0;

                foreach (var slug in slugs)
                {
                    ct.ThrowIfCancellationRequested();
                    if (!registry.TryGet(slug, out var model))
                        continue;

                    var schema = EntitySchemaFactory.FromModel(model);
                    var count = capturedCounts[slug];

                    if (capturedClear)
                    {
                        progress.Report(
                            (int)(entityIndex * 10.0 / totalEntities),
                            $"Clearing existing {model.Name} records…");
                        var existing = await walProvider.QueryRecordsAsync(schema, null, ct).ConfigureAwait(false);
                        foreach (var rec in existing)
                        {
                            ct.ThrowIfCancellationRequested();
                            if (rec.Key != 0)
                                await walProvider.DeleteRecordAsync(rec.Key, schema, ct).ConfigureAwait(false);
                        }
                    }

                    var rng = new Random();
                    for (int i = 0; i < count; i++)
                    {
                        ct.ThrowIfCancellationRequested();
                        var record = schema.CreateRecord();
                        record.Key = (uint)rng.Next(1, int.MaxValue);
                        record.CreatedOnUtc = DateTime.UtcNow;
                        record.UpdatedOnUtc = DateTime.UtcNow;
                        record.CreatedBy = capturedUser;
                        record.UpdatedBy = capturedUser;

                        foreach (var field in model.Fields)
                        {
                            if (schema.TryGetOrdinal(field.Name, out var ordinal))
                                record.SetValue(ordinal, GenerateSampleValue(field, rng));
                        }

                        await walProvider.SaveRecordAsync(record, schema, ct).ConfigureAwait(false);
                        savedRecords++;
                        if (totalRecords > 0)
                            progress.Report(
                                10 + (int)(savedRecords * 85.0 / totalRecords),
                                $"Saving {model.Name}… ({savedRecords}/{totalRecords})");
                    }

                    entityIndex++;
                }

                var summaryParts = new List<string>();
                foreach (var s in slugs)
                {
                    if (capturedCounts[s] > 0)
                        summaryParts.Add($"{capturedCounts[s]} {s}");
                }
                var summary = string.Join(", ", summaryParts);
                progress.Report(100, $"Done. Created {summary}.");
            });

        var statusUrl = $"/api/jobs/{jobId}";
        var returnUrl = "/admin/sample-data";
        await RenderJobProgressPage(context, jobId, statusUrl, returnUrl, "Generate Sample Data");
    }

    public async ValueTask WipeDataHandler(BmwContext context)
    {
        var wipeToken = SettingsService.GetValue(WellKnownSettings.AllowWipeData);
        if (string.IsNullOrEmpty(wipeToken))
        {
            await BuildPageHandler(ctx =>
            {
                ctx.SetStringValue("title", "Wipe All Data");
                ctx.SetStringValue("html_message",
                    "<div class=\"alert alert-warning\">" +
                    "<h4 class=\"alert-heading\">Endpoint Disabled</h4>" +
                    $"<p>The wipe-data endpoint is disabled because the <code>{WellKnownSettings.AllowWipeData}</code> setting is empty or missing.</p>" +
                    "<p>To enable it, go to <strong>Settings</strong> in the admin UI and set <code>" +
                    WebUtility.HtmlEncode(WellKnownSettings.AllowWipeData) +
                    "</code> to a secret token value. You can also set it via config (<code>Admin:AllowWipeData</code>) or environment variable (<code>Admin__AllowWipeData</code>).</p>" +
                    "</div>");
            })(context);
            return;
        }

        await BuildPageHandler(ctx => RenderWipeDataForm(ctx, null, wipeToken))(context);
    }

    public async ValueTask WipeDataPostHandler(BmwContext context)
    {
        var wipeToken = SettingsService.GetValue(WellKnownSettings.AllowWipeData);
        if (string.IsNullOrEmpty(wipeToken))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Wipe All Data");
            context.SetStringValue("html_message",
                "<div class=\"alert alert-warning\">" +
                "<h4 class=\"alert-heading\">Endpoint Disabled</h4>" +
                $"<p>The <code>{WebUtility.HtmlEncode(WellKnownSettings.AllowWipeData)}</code> setting is empty or missing.</p></div>");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        if (!context.HttpRequest.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.SetStringValue("title", "Wipe All Data");
            context.SetStringValue("html_message", "<p>Invalid form submission.</p>");
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var form = await context.HttpRequest.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderWipeDataForm(context, "<div class=\"alert alert-danger\">Invalid security token. Please try again.</div>", wipeToken);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var confirmText = form["confirm_wipe"].ToString().Trim();
        if (!string.Equals(confirmText, wipeToken, StringComparison.Ordinal))
        {
            RenderWipeDataForm(context, "<div class=\"alert alert-danger\">Confirmation text did not match. Enter the configured wipe token exactly to proceed.</div>", wipeToken);
            await _renderer.RenderPage(context.HttpContext);
            return;
        }

        var providers = new List<BareMetalWeb.Data.Interfaces.IDataProvider>(DataStoreProvider.Current.Providers);
        int totalProviders = providers.Count;

        var jobId = BackgroundJobService.Instance.StartJob(
            "Wipe All Data",
            "/admin/wipe-data",
            async (progress, ct) =>
            {
                progress.Report(0, "Starting wipe…");
                int done = 0;
                foreach (var provider in providers)
                {
                    ct.ThrowIfCancellationRequested();
                    progress.Report(
                        totalProviders == 0 ? 0 : (int)(done * 95.0 / totalProviders),
                        $"Wiping storage ({provider.Name})…");
                    await provider.WipeStorageAsync(ct).ConfigureAwait(false);
                    done++;
                }
                progress.Report(100, $"Done. Wiped storage for {done} provider{(done == 1 ? "" : "s")}.");
            });

        var statusUrl = $"/api/jobs/{jobId}";
        var returnUrl = "/admin/wipe-data";
        await RenderJobProgressPage(context, jobId, statusUrl, returnUrl, "Wipe All Data");
    }

    private async ValueTask RenderJobProgressPage(BmwContext context, string jobId, string statusUrl, string returnUrl, string operationName)
    {
        var nonce = context.GetCspNonce();
        var nonceAttr = string.IsNullOrEmpty(nonce) ? string.Empty : $" nonce=\"{WebUtility.HtmlEncode(nonce)}\"";

        var html = new StringBuilder(4096);
        html.Append("<div class=\"card\">");
        html.Append("<div class=\"card-body\">");
        html.Append($"<h5 class=\"card-title\" id=\"job-title\">{WebUtility.HtmlEncode(operationName)}</h5>");
        html.Append("<div class=\"progress mb-3 bm-progress-xl\">");
        html.Append("<div class=\"progress-bar progress-bar-striped progress-bar-animated\" id=\"job-progress\" role=\"progressbar\" aria-valuenow=\"0\" aria-valuemin=\"0\" aria-valuemax=\"100\">0%</div>");
        html.Append("</div>");
        html.Append("<p id=\"job-description\" class=\"text-muted mb-2\">Starting\u2026</p>");
        html.Append("<div id=\"job-result\" class=\"d-none\"></div>");
        html.Append($"<a id=\"job-return\" class=\"btn btn-primary d-none\" href=\"{WebUtility.HtmlEncode(returnUrl)}\"><i class=\"bi bi-arrow-left\" aria-hidden=\"true\"></i> Back</a>");
        html.Append("</div></div>");

        html.Append($"<script{nonceAttr}>");
        html.Append("(function(){");
        html.Append($"var url='{statusUrl.Replace("'", "\\'")}';");
        html.Append("var bar=document.getElementById('job-progress');");
        html.Append("bar.style.width='0%';");
        html.Append("var desc=document.getElementById('job-description');");
        html.Append("var result=document.getElementById('job-result');");
        html.Append("var ret=document.getElementById('job-return');");
        html.Append("function poll(){");
        html.Append("fetch(url).then(function(r){return r.json();}).then(function(d){");
        html.Append("var pct=d.percentComplete||0;");
        html.Append("bar.style.width=pct+'%';bar.textContent=pct+'%';bar.setAttribute('aria-valuenow',pct);");
        html.Append("desc.textContent=d.description||d.status||'';");
        html.Append("if(d.status==='succeeded'){");
        html.Append("bar.classList.remove('progress-bar-animated','progress-bar-striped');bar.classList.add('bg-success');");
        html.Append("result.className='alert alert-success mt-3';result.textContent=d.description||'Completed successfully.';");
        html.Append("ret.classList.remove('d-none');");
        html.Append("}else if(d.status==='failed'){");
        html.Append("bar.classList.remove('progress-bar-animated','progress-bar-striped');bar.classList.add('bg-danger');");
        html.Append("result.className='alert alert-danger mt-3';result.textContent=d.error||'Job failed.';");
        html.Append("ret.classList.remove('d-none');");
        html.Append("}else{setTimeout(poll,2000);}");
        html.Append("}).catch(function(){setTimeout(poll,3000);});");
        html.Append("}");
        html.Append("poll();");
        html.Append("})();");
        html.Append("</script>");

        context.SetStringValue("title", operationName);
        context.SetStringValue("html_message", html.ToString());
        await _renderer.RenderPage(context.HttpContext);
    }

    private void RenderWipeDataForm(BmwContext context, string? message, string wipeToken)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Wipe All Data");

        var warningHtml = new StringBuilder(1024);
        warningHtml.Append("<div class=\"alert alert-danger\">");
        warningHtml.Append("<h4 class=\"alert-heading\">&#9888; DANGER ZONE &#9888;</h4>");
        warningHtml.Append("<p><strong>This action will permanently delete ALL data in every entity store.</strong></p>");
        warningHtml.Append("<p>This operation is <strong>irreversible</strong>. All records across every entity type will be removed immediately.</p>");
        warningHtml.Append($"<p>Enter the configured wipe token (the value of <code>{WellKnownSettings.AllowWipeData}</code> in Settings) to confirm.</p>");
        warningHtml.Append("</div>");

        if (!string.IsNullOrWhiteSpace(message))
            warningHtml.Append(message);

        context.SetStringValue("html_message", warningHtml.ToString());

        var fields = new List<FormField>
        {
            new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken),
            new FormField(FormFieldType.String, "confirm_wipe", "Enter wipe token to confirm", Required: true, Value: string.Empty)
        };

        context.AddFormDefinition(new FormDefinition("/admin/wipe-data", "post", "WIPE ALL DATA", fields));
    }

    /// <summary>
    /// JSON API endpoint for the VNext SPA to start a sample-data background job.
    /// Accepts a JSON body: { entities: { "entity-slug": count, ... }, clearExisting: bool }
    /// Returns 202 Accepted with job info.
    /// </summary>
    public async ValueTask AdminSampleDataJsonHandler(BmwContext context)
    {
        if (!CsrfProtection.ValidateApiToken(context))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"CSRF validation failed.\"}").ConfigureAwait(false);
            return;
        }

        string body;
        using (var reader = new System.IO.StreamReader(context.HttpRequest.Body))
            body = await reader.ReadToEndAsync().ConfigureAwait(false);

        var entityCounts = new Dictionary<string, int>(8, StringComparer.OrdinalIgnoreCase);
        bool clearExisting = false;

        try
        {
            var doc = System.Text.Json.JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.TryGetProperty("clearExisting", out var cv)) clearExisting = cv.GetBoolean();
            if (root.TryGetProperty("entities", out var entitiesEl) && entitiesEl.ValueKind == System.Text.Json.JsonValueKind.Object)
            {
                foreach (var prop in entitiesEl.EnumerateObject())
                    entityCounts[prop.Name] = prop.Value.GetInt32();
            }
        }
        catch (System.Text.Json.JsonException)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"Invalid JSON body.\"}").ConfigureAwait(false);
            return;
        }

        var errors = new List<string>();
        var registry = RuntimeEntityRegistry.Current;

        foreach (var (slug, count) in entityCounts)
        {
            if (!registry.TryGet(slug, out _))
                errors.Add($"Unknown entity '{slug}'.");
            if (count < 0 || count > 100000)
                errors.Add($"{slug} must be between 0 and 100000.");
        }

        if (errors.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(
                JsonSerializer.Serialize(new { error = string.Join(" ", errors) })).ConfigureAwait(false);
            return;
        }

        var userName = (await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false))?.UserName ?? "system";

        var capturedCounts = new Dictionary<string, int>(entityCounts, StringComparer.OrdinalIgnoreCase);
        var capturedClear = clearExisting;
        var capturedUser = userName;

        var jobId = BackgroundJobService.Instance.StartJob(
            "Generate Sample Data",
            "/admin/sample-data",
            async (progress, ct) =>
            {
                progress.Report(0, "Starting sample data generation…");
                var walProvider = DataStoreProvider.PrimaryProvider as WalDataProvider;
                if (walProvider == null)
                {
                    progress.Report(100, "Error: WalDataProvider is not available.");
                    return;
                }

                var slugs = new List<string>(capturedCounts.Keys);
                int totalRecords = 0;
                foreach (var v in capturedCounts.Values)
                    totalRecords += v;
                int savedRecords = 0;
                int entityIndex = 0;
                int totalEntities = slugs.Count;

                foreach (var slug in slugs)
                {
                    ct.ThrowIfCancellationRequested();
                    if (!registry.TryGet(slug, out var model))
                        continue;

                    var schema = EntitySchemaFactory.FromModel(model);
                    var count = capturedCounts[slug];

                    if (capturedClear)
                    {
                        progress.Report(
                            (int)(entityIndex * 10.0 / totalEntities),
                            $"Clearing existing {model.Name} records…");
                        var existing = await walProvider.QueryRecordsAsync(schema, null, ct).ConfigureAwait(false);
                        foreach (var rec in existing)
                        {
                            ct.ThrowIfCancellationRequested();
                            if (rec.Key != 0)
                                await walProvider.DeleteRecordAsync(rec.Key, schema, ct).ConfigureAwait(false);
                        }
                    }

                    var rng = new Random();
                    for (int i = 0; i < count; i++)
                    {
                        ct.ThrowIfCancellationRequested();
                        var record = schema.CreateRecord();
                        record.Key = (uint)rng.Next(1, int.MaxValue);
                        record.CreatedOnUtc = DateTime.UtcNow;
                        record.UpdatedOnUtc = DateTime.UtcNow;
                        record.CreatedBy = capturedUser;
                        record.UpdatedBy = capturedUser;

                        foreach (var field in model.Fields)
                        {
                            if (schema.TryGetOrdinal(field.Name, out var ordinal))
                                record.SetValue(ordinal, GenerateSampleValue(field, rng));
                        }

                        await walProvider.SaveRecordAsync(record, schema, ct).ConfigureAwait(false);
                        savedRecords++;
                        if (totalRecords > 0)
                            progress.Report(
                                10 + (int)(savedRecords * 85.0 / totalRecords),
                                $"Saving {model.Name}… ({savedRecords}/{totalRecords})");
                    }

                    entityIndex++;
                }

                var summaryParts2 = new List<string>();
                foreach (var s in slugs)
                {
                    if (capturedCounts[s] > 0)
                        summaryParts2.Add($"{capturedCounts[s]} {s}");
                }
                var summary = string.Join(", ", summaryParts2);
                progress.Report(100, $"Done. Created {summary}.");
            });

        var baseUrl   = $"{context.HttpRequest.Scheme}://{context.HttpRequest.Host}";
        var statusUrl = $"{baseUrl}/api/jobs/{jobId}";
        context.Response.StatusCode = StatusCodes.Status202Accepted;
        context.Response.Headers["Location"] = statusUrl;
        context.Response.Headers["Retry-After"] = "2";
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(
            JsonSerializer.Serialize(new { jobId, status = "queued", operationName = "Generate Sample Data", statusUrl })).ConfigureAwait(false);
    }

    /// <summary>
    /// JSON API endpoint for the VNext SPA to start a wipe-all-data background job.
    /// Accepts a JSON body: { confirmToken }
    /// Returns 202 Accepted with job info.
    /// </summary>
    public async ValueTask AdminWipeDataJsonHandler(BmwContext context)
    {
        if (!CsrfProtection.ValidateApiToken(context))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"CSRF validation failed.\"}").ConfigureAwait(false);
            return;
        }

        var wipeToken = SettingsService.GetValue(WellKnownSettings.AllowWipeData);
        if (string.IsNullOrEmpty(wipeToken))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"Wipe-data endpoint is disabled (AllowWipeData setting is empty).\"}").ConfigureAwait(false);
            return;
        }

        string body;
        using (var reader = new System.IO.StreamReader(context.HttpRequest.Body))
            body = await reader.ReadToEndAsync().ConfigureAwait(false);

        string confirmToken = string.Empty;
        try
        {
            var doc  = System.Text.Json.JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.TryGetProperty("confirmToken", out var v)) confirmToken = v.GetString() ?? string.Empty;
        }
        catch (System.Text.Json.JsonException)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"Invalid JSON body.\"}").ConfigureAwait(false);
            return;
        }

        if (!string.Equals(confirmToken, wipeToken, StringComparison.Ordinal))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"Confirmation token did not match.\"}").ConfigureAwait(false);
            return;
        }

        var providers = new List<BareMetalWeb.Data.Interfaces.IDataProvider>(DataStoreProvider.Current.Providers);
        int totalProviders = providers.Count;

        var jobId = BackgroundJobService.Instance.StartJob(
            "Wipe All Data",
            "/admin/wipe-data",
            async (progress, ct) =>
            {
                progress.Report(0, "Starting wipe…");
                int done = 0;
                foreach (var provider in providers)
                {
                    ct.ThrowIfCancellationRequested();
                    progress.Report(
                        totalProviders == 0 ? 0 : (int)(done * 95.0 / totalProviders),
                        $"Wiping storage ({provider.Name})…");
                    await provider.WipeStorageAsync(ct).ConfigureAwait(false);
                    done++;
                }
                progress.Report(100, $"Done. Wiped storage for {done} provider{(done == 1 ? "" : "s")}.");
            });

        var baseUrl   = $"{context.HttpRequest.Scheme}://{context.HttpRequest.Host}";
        var statusUrl = $"{baseUrl}/api/jobs/{jobId}";
        context.Response.StatusCode = StatusCodes.Status202Accepted;
        context.Response.Headers["Location"] = statusUrl;
        context.Response.Headers["Retry-After"] = "2";
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(
            JsonSerializer.Serialize(new { jobId, status = "queued", operationName = "Wipe All Data", statusUrl })).ConfigureAwait(false);
    }

    /// <summary>
    /// GET /api/admin/query-plans — returns the in-memory query plan history as JSON.
    /// Each entry includes timing, steps, and missing-index recommendations.
    /// </summary>
    public async ValueTask QueryPlanHistoryHandler(BmwContext context)
    {
        var entries = QueryPlanHistory.GetSnapshot();

        var payload = new List<Dictionary<string, object?>>();
        foreach (var e in entries)
        {
            var stepsList = new List<Dictionary<string, object?>>();
            foreach (var s in e.Plan.Steps)
            {
                stepsList.Add(new Dictionary<string, object?>
                {
                    ["stepType"]     = s.StepType.ToString(),
                    ["entitySlug"]   = s.EntitySlug,
                    ["estimatedRows"] = s.EstimatedRows,
                    ["indexedFields"] = s.IndexedFields,
                    ["join"] = s.JoinInfo == null ? null : new Dictionary<string, object?>
                    {
                        ["fromEntity"]        = s.JoinInfo.FromEntity,
                        ["fromField"]         = s.JoinInfo.FromField,
                        ["toField"]           = s.JoinInfo.ToField,
                        ["joinType"]          = s.JoinInfo.JoinType.ToString(),
                        ["buildSideIndexed"]  = s.JoinInfo.BuildSideIndexed
                    }
                });
            }
            var missingIndexList = new List<Dictionary<string, object?>>();
            foreach (var r in e.Plan.MissingIndexRecommendations)
            {
                missingIndexList.Add(new Dictionary<string, object?>
                {
                    ["entitySlug"] = r.EntitySlug,
                    ["fieldName"]  = r.FieldName,
                    ["reason"]     = r.Reason
                });
            }
            payload.Add(new Dictionary<string, object?>
            {
                ["executedAt"]     = e.ExecutedAt.ToString("o"),
                ["rootEntity"]     = e.RootEntity,
                ["joinCount"]      = e.JoinCount,
                ["resultRowCount"] = e.ResultRowCount,
                ["elapsedMs"]      = Math.Round(e.ElapsedMs, 3),
                ["canStreamAggregate"]   = e.Plan.CanStreamAggregate,
                ["joinOrderOptimised"]   = e.Plan.JoinOrderOptimised,
                ["steps"] = stepsList,
                ["missingIndexRecommendations"] = missingIndexList
            });
        }

        await WriteJsonResponseAsync(context, payload);
    }

    public async ValueTask EntityDesignerHandler(BmwContext context)
    {
        await BuildPageHandler(ctx =>
        {
            ctx.SetStringValue("title", "Entity Designer");
            ctx.SetStringValue("html_message",
                "<div id=\"designer-root\"><p class=\"text-muted\">Loading designer…</p></div>" +
                "<script src=\"/static/js/entity-designer.js\"></script>");
        })(context);
    }

    public async ValueTask GalleryHandler(BmwContext context)
    {
        await BuildPageHandler(async ctx =>
        {
            var packages = SampleGalleryService.GetAllPackages();

            // Determine which packages are already deployed (have at least one EntityDefinition with matching slug)
            var deployedSlugs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var existingDefsRaw = await DataStoreProvider.Current.QueryAsync<EntityDefinition>(null, ctx.RequestAborted)
                .ConfigureAwait(false);
            var existingDefs = new List<EntityDefinition>();
            foreach (var def in existingDefsRaw)
                existingDefs.Add(def);
            var existingSlugs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var e in existingDefs)
            {
                var slug = e.Slug ?? string.Empty;
                if (slug.Length > 0)
                    existingSlugs.Add(slug);
            }

            foreach (var pkg in packages)
            {
                bool hasMatchingEntity = false;
                foreach (var e in pkg.Entities)
                {
                    if (existingSlugs.Contains(e.Slug ?? string.Empty))
                    {
                        hasMatchingEntity = true;
                        break;
                    }
                }
                if (hasMatchingEntity)
                    deployedSlugs.Add(pkg.Slug);
            }

            var sb = new StringBuilder(4096);
            sb.Append("<h4>Sample Metadata Gallery</h4>");
            sb.Append("<p class=\"text-muted\">Deploy pre-built entity schemas to get started quickly. Deploying a package imports its <em>EntityDefinition</em>, <em>FieldDefinition</em>, and <em>IndexDefinition</em> records.</p>");
            sb.Append("<div class=\"row g-3\">");

            var csrfToken = CsrfProtection.EnsureToken(ctx);

            foreach (var pkg in packages)
            {
                var isDeployed = deployedSlugs.Contains(pkg.Slug);
                var badgeClass = isDeployed ? "bg-success" : "bg-secondary";
                var badgeLabel = isDeployed ? "Deployed" : "Not Deployed";
                var btnClass = isDeployed ? "btn-outline-secondary" : "btn-primary";
                var btnLabel = isDeployed ? "Re-deploy" : "Deploy";

                sb.Append("<div class=\"col-md-6 col-lg-4\">");
                sb.Append("<div class=\"card h-100\">");
                sb.Append("<div class=\"card-body\">");
                sb.Append($"<h5 class=\"card-title\"><i class=\"bi {WebUtility.HtmlEncode(pkg.Icon)} me-2\"></i>{WebUtility.HtmlEncode(pkg.Name)}</h5>");
                sb.Append($"<p class=\"card-text text-muted small\">{WebUtility.HtmlEncode(pkg.Description)}</p>");
                sb.Append($"<p><span class=\"badge {badgeClass}\">{badgeLabel}</span> ");
                sb.Append($"<span class=\"text-muted small\">{pkg.Entities.Count} entit{(pkg.Entities.Count == 1 ? "y" : "ies")}, {pkg.Fields.Count} field{(pkg.Fields.Count == 1 ? "" : "s")}</span></p>");
                sb.Append($"<form method=\"post\" action=\"/admin/gallery/deploy/{WebUtility.HtmlEncode(pkg.Slug)}\">");
                sb.Append($"<input type=\"hidden\" name=\"{CsrfProtection.FormFieldName}\" value=\"{WebUtility.HtmlEncode(csrfToken)}\">");
                sb.Append($"<button type=\"submit\" class=\"btn {btnClass} btn-sm\">{btnLabel}</button>");
                sb.Append("</form>");
                sb.Append("</div></div></div>");
            }

            sb.Append("</div>");

            ctx.SetStringValue("title", "Sample Gallery");
            ctx.SetStringValue("html_message", sb.ToString());
        })(context);
    }

    public async ValueTask GalleryDeployPostHandler(BmwContext context)
    {
        var packageSlug = GetRouteValue(context, "package") ?? string.Empty;

        if (!context.HttpRequest.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid form submission.");
            return;
        }

        var form = await context.HttpRequest.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            await BuildPageHandler(ctx =>
            {
                ctx.SetStringValue("title", "Sample Gallery");
                ctx.SetStringValue("html_message", "<div class=\"alert alert-danger\">Invalid security token. Please try again.</div>");
            })(context);
            return;
        }

        var pkg = SampleGalleryService.GetPackage(packageSlug);
        if (pkg == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await BuildPageHandler(ctx =>
            {
                ctx.SetStringValue("title", "Sample Gallery");
                ctx.SetStringValue("html_message", $"<div class=\"alert alert-danger\">Package '{WebUtility.HtmlEncode(packageSlug)}' not found.</div>");
            })(context);
            return;
        }

        var messages = new List<string>();
        var deployed = await SampleGalleryService.DeployPackageAsync(
            pkg,
            DataStoreProvider.Current,
            overwrite: false,
            msg => messages.Add(msg),
            context.RequestAborted)
            .ConfigureAwait(false);

        // Hot-reload the entity registry so deployed entities are immediately usable
        if (deployed.Count > 0)
        {
            try
            {
                await RuntimeEntityRegistry.RebuildAsync().ConfigureAwait(false);
                _logger?.LogInfo($"Gallery|deployed|{packageSlug}|entities={deployed.Count}|registry-rebuilt");
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Gallery|rebuild-failed|{packageSlug}", ex);
            }
        }

        var message = deployed.Count > 0
            ? $"<div class=\"alert alert-success\">Deployed <strong>{WebUtility.HtmlEncode(pkg.Name)}</strong>: {deployed.Count} entit{(deployed.Count == 1 ? "y" : "ies")} imported.</div>"
            : $"<div class=\"alert alert-info\">Package <strong>{WebUtility.HtmlEncode(pkg.Name)}</strong> entities are already deployed. No changes made.</div>";

        context.Response.Redirect("/admin/gallery");
        _ = message; // redirect supersedes any rendered message
    }

    private async ValueTask ApplyUploadFieldsFromFormAsync(BmwContext context, DataEntityMetadata meta, BaseDataObject instance, IFormCollection form, List<string> errors)
    {
        foreach (var field in meta.Fields)
        {
            if (field.FieldType != FormFieldType.File && field.FieldType != FormFieldType.Image)
                continue;
            var deleteKey = $"{field.Name}__delete";
            var deleteRequested = form.TryGetValue(deleteKey, out var deleteValue) && DataScaffold.IsTruthy(deleteValue.ToString());
            var uploadedFile = form.Files.GetFile(field.Name);
            var existingFile = field.GetValueFn(instance) as StoredFileData;

            if (deleteRequested && uploadedFile == null)
            {
                if (existingFile != null)
                    DeleteStoredFile(context, existingFile);
                field.SetValueFn(instance, null);
                continue;
            }

            if (uploadedFile == null || uploadedFile.Length <= 0)
            {
                if (field.Required && existingFile == null)
                    errors.Add($"{field.Label} is required.");
                continue;
            }

            var config = field.Upload;
            if (config != null)
            {
                if (config.MaxFileSizeBytes > 0 && uploadedFile.Length > config.MaxFileSizeBytes)
                {
                    errors.Add($"{field.Label} exceeds maximum file size.");
                    continue;
                }

                if (config.AllowedMimeTypes.Length > 0)
                {
                    bool mimeAllowed = false;
                    foreach (var mime in config.AllowedMimeTypes)
                    {
                        if (string.Equals(mime, uploadedFile.ContentType, StringComparison.OrdinalIgnoreCase))
                        {
                            mimeAllowed = true;
                            break;
                        }
                    }
                    if (!mimeAllowed)
                    {
                        errors.Add($"{field.Label} has an invalid file type.");
                        continue;
                    }
                }
            }

            var safeName = SanitizeFileName(uploadedFile.FileName);
            var extension = Path.GetExtension(safeName);
            var storageKey = $"{meta.Slug}/{instance.Key}/{field.Name}/{Guid.NewGuid():N}{extension}";
            var fullPath = ResolveUploadPath(context, storageKey);
            var folder = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrWhiteSpace(folder))
                Directory.CreateDirectory(folder);

            await using (var source = uploadedFile.OpenReadStream())
            await using (var destination = File.Create(fullPath))
            {
                await source.CopyToAsync(destination, context.RequestAborted).ConfigureAwait(false);
            }

            if (existingFile != null && !string.IsNullOrWhiteSpace(existingFile.StorageKey))
                DeleteStoredFile(context, existingFile);

            var storedFile = new StoredFileData
            {
                FileName = safeName,
                ContentType = string.IsNullOrWhiteSpace(uploadedFile.ContentType) ? "application/octet-stream" : uploadedFile.ContentType,
                SizeBytes = uploadedFile.Length,
                StorageKey = storageKey,
                IsImage = field.FieldType == FormFieldType.Image
            };

            field.SetValueFn(instance, storedFile);
        }
    }

    private static string SanitizeFileName(string? fileName)
    {
        var safeName = Path.GetFileName(fileName ?? string.Empty);
        return string.IsNullOrWhiteSpace(safeName) ? "upload.bin" : safeName;
    }

    private string ResolveUploadPath(BmwContext context, string storageKey)
    {
        var rootPath = GetUploadRootPath(context);
        return ResolveUploadPathFromRoot(rootPath, storageKey);
    }

    /// <summary>
    /// Resolves and validates the full path for an upload storage key within the given root directory.
    /// Prevents path traversal via "../", null byte injection, and directory-name prefix bypass.
    /// </summary>
    internal static string ResolveUploadPathFromRoot(string rootPath, string storageKey)
    {
        if (storageKey.Contains('\0'))
            throw new InvalidOperationException("Invalid upload storage key.");

        var sanitizedKey = storageKey.Replace('\\', '/').TrimStart('/');
        var combined = Path.Combine(rootPath, sanitizedKey.Replace('/', Path.DirectorySeparatorChar));
        var full = Path.GetFullPath(combined);

        // Resolve root once and append a separator so that "/uploads_evil" cannot match "/uploads"
        var resolvedRoot = Path.GetFullPath(rootPath);
        if (!Path.EndsInDirectorySeparator(resolvedRoot))
            resolvedRoot += Path.DirectorySeparatorChar;

        if (!full.StartsWith(resolvedRoot, StringComparison.Ordinal))
            throw new InvalidOperationException("Invalid upload storage key.");

        return full;
    }

    private string GetUploadRootPath(BmwContext context)
    {
        var configured = _config?.GetValue("Uploads.RootDirectory", "uploads") ?? "uploads";
        if (Path.IsPathRooted(configured))
            return configured;
        return Path.Combine(_dataRootFolder, configured);
    }

    private void DeleteStoredFile(BmwContext context, StoredFileData storedFile)
    {
        if (string.IsNullOrWhiteSpace(storedFile.StorageKey))
            return;

        var fullPath = ResolveUploadPath(context, storedFile.StorageKey);
        if (File.Exists(fullPath))
            File.Delete(fullPath);
    }

    internal static Dictionary<string, object?> BuildApiModel(DataEntityMetadata meta, object instance)
    {
        var data = new Dictionary<string, object?>(meta.ViewFields.Length + 1, StringComparer.OrdinalIgnoreCase);
        var id = instance is BaseDataObject dataObject ? DataScaffold.GetIdValue(dataObject) : null;
        if (!string.IsNullOrWhiteSpace(id))
            data["id"] = id;

        foreach (var field in meta.ViewFields)
        {
            var value = field.GetValueFn(instance);
            if (value is StoredFileData fileData && instance is BaseDataObject obj)
            {
                data[field.Name] = new Dictionary<string, object?>
                {
                    ["fileName"] = fileData.FileName,
                    ["contentType"] = fileData.ContentType,
                    ["sizeBytes"] = fileData.SizeBytes,
                    ["storageKey"] = fileData.StorageKey,
                    ["isImage"] = fileData.IsImage,
                    ["width"] = fileData.Width,
                    ["height"] = fileData.Height,
                    ["url"] = $"/api/{meta.Slug}/{Uri.EscapeDataString(obj.Key.ToString())}/files/{Uri.EscapeDataString(field.Name)}"
                };
                continue;
            }

            data[field.Name] = value;
        }

        return data;
    }


    private static string GetLogRoot(BmwContext context)
    {
        var logFolder = "Logs";
        if (Path.IsPathRooted(logFolder))
            return logFolder;

        return Path.Combine(AppContext.BaseDirectory, logFolder);
    }

    private static string RenderLogTree(IReadOnlyList<LogYearEntry> years, IReadOnlyList<string> hours, IReadOnlyList<LogFileEntry> files, string selectedYearKey, string selectedMonthKey, string selectedDate, string selectedHour, string selectedFile)
    {
        var html = RentStringBuilder(2048);
        try
        {
        html.Append("<div class=\"bm-log-tree-header\">Log Tree</div>");
        if (years.Count == 0)
        {
            html.Append("<p class=\"text-muted mb-0\">No log folders found.</p>");
            return html.ToString();
        }

        html.Append("<ul class=\"bm-log-tree-list\">");
        foreach (var year in years)
        {
            html.Append("<li>");
            var yearActive = string.Equals(year.Key, selectedYearKey, StringComparison.OrdinalIgnoreCase) ? " bm-log-tree-active" : string.Empty;
            var yearLabel = $"{year.Label} ({FormatSizeBytes(year.SizeBytes)})";
            var yearHref = $"/admin/logs?year={WebUtility.UrlEncode(year.Key)}";
            html.Append($"<a class=\"bm-log-tree-link{yearActive}\" href=\"{yearHref}\">{WebUtility.HtmlEncode(yearLabel)}</a>");

            if (string.Equals(year.Key, selectedYearKey, StringComparison.OrdinalIgnoreCase) && year.Months.Count > 0)
            {
                html.Append("<ul class=\"bm-log-tree-list\">");
                foreach (var month in year.Months)
                {
                    html.Append("<li>");
                    var monthActive = string.Equals(month.Key, selectedMonthKey, StringComparison.OrdinalIgnoreCase) ? " bm-log-tree-active" : string.Empty;
                    var monthLabel = $"{month.Label} ({FormatSizeBytes(month.SizeBytes)})";
                    var monthHref = $"/admin/logs?year={WebUtility.UrlEncode(year.Key)}&month={WebUtility.UrlEncode(month.Key)}";
                    html.Append($"<a class=\"bm-log-tree-link{monthActive}\" href=\"{monthHref}\">{WebUtility.HtmlEncode(monthLabel)}</a>");

                    if (string.Equals(month.Key, selectedMonthKey, StringComparison.OrdinalIgnoreCase) && month.Days.Count > 0)
                    {
                        html.Append("<ul class=\"bm-log-tree-list\">");
                        foreach (var day in month.Days)
                        {
                            html.Append("<li>");
                            var dayLabel = WebUtility.HtmlEncode(day.Label);
                            var dayHref = $"/admin/logs?date={WebUtility.UrlEncode(day.Folder)}";
                            var dayActive = string.Equals(day.Folder, selectedDate, StringComparison.OrdinalIgnoreCase) ? " bm-log-tree-active" : string.Empty;
                            html.Append($"<a class=\"bm-log-tree-link{dayActive}\" href=\"{dayHref}\">{dayLabel}</a>");

                            if (string.Equals(day.Folder, selectedDate, StringComparison.OrdinalIgnoreCase) && hours.Count > 0)
                            {
                                html.Append("<ul class=\"bm-log-tree-list\">");
                                foreach (var hour in hours)
                                {
                                    var hourLabel = WebUtility.HtmlEncode(hour);
                                    var hourHref = $"/admin/logs?date={WebUtility.UrlEncode(day.Folder)}&hour={WebUtility.UrlEncode(hour)}";
                                    var hourActive = string.Equals(hour, selectedHour, StringComparison.OrdinalIgnoreCase) ? " bm-log-tree-active" : string.Empty;
                                    html.Append("<li>");
                                    html.Append($"<a class=\"bm-log-tree-link{hourActive}\" href=\"{hourHref}\">{hourLabel}</a>");

                                    if (string.Equals(hour, selectedHour, StringComparison.OrdinalIgnoreCase) && files.Count > 0)
                                    {
                                        html.Append("<ul class=\"bm-log-tree-list\">");
                                        foreach (var file in files)
                                        {
                                            var fileLabel = WebUtility.HtmlEncode(file.Name);
                                            var fileHref = $"/admin/logs?date={WebUtility.UrlEncode(day.Folder)}&hour={WebUtility.UrlEncode(hour)}&file={WebUtility.UrlEncode(file.Name)}";
                                            var fileActive = string.Equals(file.Name, selectedFile, StringComparison.OrdinalIgnoreCase) ? " bm-log-tree-active" : string.Empty;
                                            var errorClass = file.IsError ? " bm-log-tree-error" : string.Empty;
                                            html.Append("<li>");
                                            html.Append($"<a class=\"bm-log-tree-link{fileActive}{errorClass}\" href=\"{fileHref}\">{fileLabel}</a>");
                                            html.Append("</li>");
                                        }
                                        html.Append("</ul>");
                                    }

                                    html.Append("</li>");
                                }
                                html.Append("</ul>");
                            }

                            html.Append("</li>");
                        }
                        html.Append("</ul>");
                    }

                    html.Append("</li>");
                }
                html.Append("</ul>");
            }

            html.Append("</li>");
        }
        html.Append("</ul>");
        return html.ToString();
        }
        finally { ReturnStringBuilder(html); }
    }

    private static string RenderLogActions(IReadOnlyList<LogYearEntry> years, string selectedYearKey, string selectedMonthKey, string selectedDate, string selectedHour)
    {
        var html = RentStringBuilder(2048);
        try
        {
        if (string.IsNullOrWhiteSpace(selectedYearKey) && string.IsNullOrWhiteSpace(selectedMonthKey) && string.IsNullOrWhiteSpace(selectedDate) && string.IsNullOrWhiteSpace(selectedHour))
            return string.Empty;

        LogYearEntry year = default;
        foreach (var entry in years)
        {
            if (string.Equals(entry.Key, selectedYearKey, StringComparison.OrdinalIgnoreCase))
            {
                year = entry;
                break;
            }
        }
        var months = year.Months ?? Array.Empty<LogMonthEntry>();
        LogMonthEntry month = default;
        foreach (var entry in months)
        {
            if (string.Equals(entry.Key, selectedMonthKey, StringComparison.OrdinalIgnoreCase))
            {
                month = entry;
                break;
            }
        }
        var days = month.Days ?? Array.Empty<LogDayEntry>();
        LogDayEntry day = default;
        foreach (var entry in days)
        {
            if (string.Equals(entry.Folder, selectedDate, StringComparison.OrdinalIgnoreCase))
            {
                day = entry;
                break;
            }
        }

        html.Append("<nav class=\"bm-log-actions mb-3\" aria-label=\"Log scope\">");
        html.Append("<div class=\"bm-log-actions-row\">Log scope</div>");
        html.Append("<ol class=\"breadcrumb bm-log-breadcrumb mb-0\">");

        if (!string.IsNullOrWhiteSpace(selectedYearKey))
        {
            var label = year.Label ?? selectedYearKey;
            var actions = RenderLogActionButtons(
                $"/admin/logs/download?scope=year&year={WebUtility.UrlEncode(selectedYearKey)}",
                $"/admin/logs/prune?scope=year&year={WebUtility.UrlEncode(selectedYearKey)}");
            html.Append($"<li class=\"breadcrumb-item bm-log-crumb\"><span class=\"bm-log-crumb-label\">Year: {WebUtility.HtmlEncode(label)}</span>{actions}</li>");
        }

        if (!string.IsNullOrWhiteSpace(selectedMonthKey))
        {
            var label = month.Label ?? selectedMonthKey;
            var actions = RenderLogActionButtons(
                $"/admin/logs/download?scope=month&month={WebUtility.UrlEncode(selectedMonthKey)}",
                $"/admin/logs/prune?scope=month&month={WebUtility.UrlEncode(selectedMonthKey)}");
            html.Append($"<li class=\"breadcrumb-item bm-log-crumb\"><span class=\"bm-log-crumb-label\">Month: {WebUtility.HtmlEncode(label)}</span>{actions}</li>");
        }

        if (!string.IsNullOrWhiteSpace(selectedDate))
        {
            var label = day.Label ?? selectedDate;
            var actions = RenderLogActionButtons(
                $"/admin/logs/download?scope=day&date={WebUtility.UrlEncode(selectedDate)}",
                $"/admin/logs/prune?scope=day&date={WebUtility.UrlEncode(selectedDate)}");
            html.Append($"<li class=\"breadcrumb-item bm-log-crumb\"><span class=\"bm-log-crumb-label\">Day: {WebUtility.HtmlEncode(label)}</span>{actions}</li>");
        }

        if (!string.IsNullOrWhiteSpace(selectedDate) && !string.IsNullOrWhiteSpace(selectedHour))
        {
            var label = $"{selectedHour}:00";
            var actions = RenderLogActionButtons(
                $"/admin/logs/download?scope=hour&date={WebUtility.UrlEncode(selectedDate)}&hour={WebUtility.UrlEncode(selectedHour)}",
                $"/admin/logs/prune?scope=hour&date={WebUtility.UrlEncode(selectedDate)}&hour={WebUtility.UrlEncode(selectedHour)}");
            html.Append($"<li class=\"breadcrumb-item bm-log-crumb\"><span class=\"bm-log-crumb-label\">Hour: {WebUtility.HtmlEncode(label)}</span>{actions}</li>");
        }

        html.Append("</ol>");
        html.Append("</nav>");
        return html.ToString();
        }
        finally { ReturnStringBuilder(html); }
    }

    private static string RenderLogActionButtons(string downloadHref, string pruneHref)
    {
        return $"<span class=\"bm-log-crumb-actions\"><a class=\"btn btn-sm btn-outline-secondary\" href=\"{downloadHref}\" aria-label=\"Download ZIP\" title=\"Download ZIP\"><i class=\"bi bi-save\" aria-hidden=\"true\"></i></a><a class=\"btn btn-sm btn-outline-danger\" href=\"{pruneHref}\" aria-label=\"Prune logs\" title=\"Prune logs\"><i class=\"bi bi-x-lg\" aria-hidden=\"true\"></i></a></span>";
    }

    private static string RenderLogFile(string path, string fileName, bool isError)
    {
        var html = RentStringBuilder(2048);
        try
        {
        var headerClass = isError ? "bm-log-viewer-header bm-log-error" : "bm-log-viewer-header";
        html.Append($"<div class=\"{headerClass}\">{WebUtility.HtmlEncode(fileName)}</div>");

        if (!File.Exists(path))
        {
            html.Append("<p class=\"text-danger mb-0\">Log file not found.</p>");
            return html.ToString();
        }

        const int maxLines = 2000;
        var truncated = false;
        var lines = RentStringBuilder(4096);
        try
        {
        var count = 0;
        foreach (var line in File.ReadLines(path))
        {
            count++;
            if (count > maxLines)
            {
                truncated = true;
                break;
            }
            lines.Append(WebUtility.HtmlEncode(line));
            lines.Append('\n');
        }

        html.Append("<pre class=\"bm-log-viewer-content\">");
        html.Append(lines.ToString());
        html.Append("</pre>");
        }
        finally { ReturnStringBuilder(lines); }
        if (truncated)
        {
            html.Append("<p class=\"text-muted mt-2 mb-0\">Output truncated.</p>");
        }
        return html.ToString();
        }
        finally { ReturnStringBuilder(html); }
    }

    private static bool TryResolveLogTarget(IQueryCollection query, string root, out LogTarget target, out string errorMessage)
    {
        var scope = query["scope"].ToString().Trim();
        var year = query["year"].ToString().Trim();
        var month = query["month"].ToString().Trim();
        var date = query["date"].ToString().Trim();
        var hour = query["hour"].ToString().Trim();

        return TryResolveLogTarget(scope, string.IsNullOrWhiteSpace(year) ? month : year, date, hour, root, out target, out errorMessage);
    }

    private static bool TryResolveLogTarget(IReadOnlyDictionary<string, StringValues> query, string root, out LogTarget target, out string errorMessage)
    {
        var scope = query.TryGetValue("scope", out var scopeValue) ? scopeValue.ToString() : string.Empty;
        var year = query.TryGetValue("year", out var yearValue) ? yearValue.ToString() : string.Empty;
        var month = query.TryGetValue("month", out var monthValue) ? monthValue.ToString() : string.Empty;
        var date = query.TryGetValue("date", out var dateValue) ? dateValue.ToString() : string.Empty;
        var hour = query.TryGetValue("hour", out var hourValue) ? hourValue.ToString() : string.Empty;

        return TryResolveLogTarget(scope, string.IsNullOrWhiteSpace(year) ? month : year, date, hour, root, out target, out errorMessage);
    }

    private static bool TryResolveLogTarget(string scope, string month, string date, string hour, string root, out LogTarget target, out string errorMessage)
    {
        target = default;
        errorMessage = "Invalid log selection.";

        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
        {
            errorMessage = "Log folder not found.";
            return false;
        }

        scope = scope.ToLowerInvariant();
        if (scope == "year")
        {
            if (!int.TryParse(month, NumberStyles.Integer, CultureInfo.InvariantCulture, out var yearValue))
            {
                errorMessage = "Invalid year selection.";
                return false;
            }

            var dayFolders = new List<string>();
            foreach (var dir in Directory.GetDirectories(root))
            {
                var name = Path.GetFileName(dir);
                if (string.IsNullOrWhiteSpace(name)) continue;
                if (!TryParseDayFolder(name!, out var dv) || dv.Year != yearValue) continue;
                var fullPath = Path.Combine(root, name!);
                if (Directory.Exists(fullPath))
                    dayFolders.Add(fullPath);
            }

            if (dayFolders.Count == 0)
            {
                errorMessage = "No logs found for the selected year.";
                return false;
            }

            target = new LogTarget("year", yearValue.ToString(CultureInfo.InvariantCulture), null, null, yearValue.ToString(CultureInfo.InvariantCulture), dayFolders, $"logs_{yearValue}.zip");
            return true;
        }

        if (scope == "month")
        {
            if (!TryParseMonthKey(month, out var monthDate))
            {
                errorMessage = "Invalid month selection.";
                return false;
            }

            var dayFolders = new List<string>();
            foreach (var dir in Directory.GetDirectories(root))
            {
                var name = Path.GetFileName(dir);
                if (string.IsNullOrWhiteSpace(name)) continue;
                if (!TryParseDayFolder(name!, out var dv) || dv.Year != monthDate.Year || dv.Month != monthDate.Month) continue;
                var fullPath = Path.Combine(root, name!);
                if (Directory.Exists(fullPath))
                    dayFolders.Add(fullPath);
            }

            if (dayFolders.Count == 0)
            {
                errorMessage = "No logs found for the selected month.";
                return false;
            }

            target = new LogTarget("month", month, null, null, monthDate.ToString("MMMM yyyy", CultureInfo.InvariantCulture), dayFolders, $"logs_{month}.zip");
            return true;
        }

        if (scope == "day")
        {
            if (!TryParseDayFolder(date, out var dayDate))
            {
                errorMessage = "Invalid day selection.";
                return false;
            }

            var dayPath = Path.Combine(root, date);
            if (!Directory.Exists(dayPath))
            {
                errorMessage = "Selected day not found.";
                return false;
            }

            target = new LogTarget("day", ResolveMonthKey(date), date, null, dayDate.ToString("MMM d, yyyy", CultureInfo.InvariantCulture), new List<string> { dayPath }, $"logs_{date}.zip");
            return true;
        }

        if (scope == "hour")
        {
            if (!TryParseDayFolder(date, out var dayDate) || !IsValidHour(hour))
            {
                errorMessage = "Invalid hour selection.";
                return false;
            }

            var hourPath = Path.Combine(root, date, hour);
            if (!Directory.Exists(hourPath))
            {
                errorMessage = "Selected hour not found.";
                return false;
            }

            target = new LogTarget("hour", ResolveMonthKey(date), date, hour, $"{dayDate:MMM d, yyyy} {hour}:00", new List<string> { hourPath }, $"logs_{date}_{hour}.zip");
            return true;
        }

        errorMessage = "Unknown log scope.";
        return false;
    }

    private static bool TryParseMonthKey(string monthKey, out DateTime monthDate)
    {
        return DateTime.TryParseExact(
            monthKey,
            "yyyy-MM",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out monthDate);
    }

    private static bool IsValidHour(string hour)
    {
        return int.TryParse(hour, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            && value >= 0
            && value <= 23;
    }

    private static void CleanupEmptyLogParents(LogTarget target, string root)
    {
        if (target.Scope != "hour")
            return;

        if (string.IsNullOrWhiteSpace(target.DateFolder))
            return;

        var dayPath = Path.Combine(root, target.DateFolder);
        if (!Directory.Exists(dayPath))
            return;

        bool hasEntries = false;
        foreach (var _ in Directory.EnumerateFileSystemEntries(dayPath))
        {
            hasEntries = true;
            break;
        }
        if (hasEntries)
            return;

        Directory.Delete(dayPath, recursive: false);
    }

    private static IReadOnlyList<LogYearEntry> BuildLogYears(string root, IEnumerable<string> dayFolders)
    {
        var dayEntries = new List<LogDayEntry>();
        foreach (var folder in dayFolders)
        {
            var fullPath = Path.Combine(root, folder);
            var sizeBytes = GetDirectorySize(fullPath);
            if (TryParseDayFolder(folder, out var date))
            {
                var yearKey = date.ToString("yyyy", CultureInfo.InvariantCulture);
                var yearLabel = date.ToString("yyyy", CultureInfo.InvariantCulture);
                var monthKey = date.ToString("yyyy-MM", CultureInfo.InvariantCulture);
                var monthLabel = date.ToString("MMMM yyyy", CultureInfo.InvariantCulture);
                var dayLabel = date.ToString("MMM d, yyyy", CultureInfo.InvariantCulture);
                dayEntries.Add(new LogDayEntry(folder, date, dayLabel, monthKey, monthLabel, yearKey, yearLabel, sizeBytes));
            }
            else
            {
                dayEntries.Add(new LogDayEntry(folder, DateTime.MinValue, folder, folder, folder, folder, folder, sizeBytes));
            }
        }

        // Group by year
        var yearDict = new Dictionary<string, List<LogDayEntry>>(8, StringComparer.OrdinalIgnoreCase);
        foreach (var entry in dayEntries)
        {
            if (!yearDict.TryGetValue(entry.YearKey, out var yearGroup))
            {
                yearGroup = new List<LogDayEntry>();
                yearDict[entry.YearKey] = yearGroup;
            }
            yearGroup.Add(entry);
        }

        var years = new List<LogYearEntry>();
        foreach (var (yearKey, yearGroup) in yearDict)
        {
            var first = yearGroup[0];
            var yearDate = first.Date == DateTime.MinValue
                ? DateTime.MaxValue
                : new DateTime(first.Date.Year, 1, 1, 0, 0, 0, DateTimeKind.Utc);

            // Group by month within year
            var monthDict = new Dictionary<string, List<LogDayEntry>>(12, StringComparer.OrdinalIgnoreCase);
            foreach (var entry in yearGroup)
            {
                if (!monthDict.TryGetValue(entry.MonthKey, out var monthGroup))
                {
                    monthGroup = new List<LogDayEntry>();
                    monthDict[entry.MonthKey] = monthGroup;
                }
                monthGroup.Add(entry);
            }

            var monthsList = new List<LogMonthEntry>();
            foreach (var (monthKey, monthGroup) in monthDict)
            {
                var monthFirst = monthGroup[0];
                var monthDate = monthFirst.Date == DateTime.MinValue
                    ? DateTime.MaxValue
                    : new DateTime(monthFirst.Date.Year, monthFirst.Date.Month, 1, 0, 0, 0, DateTimeKind.Utc);
                var days = new List<LogDayEntry>(monthGroup);
                days.Sort((a, b) =>
                {
                    var da = a.Date == DateTime.MinValue ? DateTime.MaxValue : a.Date;
                    var db = b.Date == DateTime.MinValue ? DateTime.MaxValue : b.Date;
                    int cmp = da.CompareTo(db);
                    return cmp != 0 ? cmp : string.Compare(a.Folder, b.Folder, StringComparison.OrdinalIgnoreCase);
                });
                long monthSize = 0;
                foreach (var d in days)
                    monthSize += d.SizeBytes;
                monthsList.Add(new LogMonthEntry(monthKey, monthFirst.MonthLabel, monthDate, days, monthSize));
            }
            monthsList.Sort((a, b) => a.MonthDate.CompareTo(b.MonthDate));

            long yearSize = 0;
            foreach (var m in monthsList)
                yearSize += m.SizeBytes;
            years.Add(new LogYearEntry(yearKey, first.YearLabel, yearDate, monthsList, yearSize));
        }
        years.Sort((a, b) => a.YearDate.CompareTo(b.YearDate));

        return years;
    }

    private static string ResolveMonthKey(string selectedDate)
    {
        if (TryParseDayFolder(selectedDate, out var date))
            return date.ToString("yyyy-MM", CultureInfo.InvariantCulture);

        return selectedDate;
    }

    private static string ResolveYearKey(string selectedDate)
    {
        if (TryParseDayFolder(selectedDate, out var date))
            return date.ToString("yyyy", CultureInfo.InvariantCulture);

        return selectedDate;
    }

    private static LogFileEntry BuildLogFileEntry(string fileName)
    {
        var isError = fileName.StartsWith("error_", StringComparison.OrdinalIgnoreCase);
        if (TryParseLogFileTimestamp(fileName, out var timestamp))
        {
            return new LogFileEntry(fileName, timestamp, isError, timestamp);
        }

        return new LogFileEntry(fileName, null, isError, DateTime.MaxValue);
    }

    private static bool TryParseDayFolder(string folderName, out DateTime date)
    {
        return DateTime.TryParseExact(
            folderName,
            "yyyyMMdd",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out date);
    }

    private static int ParseHourValue(string hour)
    {
        return int.TryParse(hour, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
            ? value
            : int.MaxValue;
    }

    private static bool TryParseLogFileTimestamp(string fileName, out DateTime timestamp)
    {
        timestamp = DateTime.MinValue;
        var underscore = fileName.LastIndexOf('_');
        var dot = fileName.LastIndexOf('.');
        if (underscore < 0 || dot < 0 || dot <= underscore)
            return false;

        var stamp = fileName.Substring(underscore + 1, dot - underscore - 1);
        return DateTime.TryParseExact(
            stamp,
            "yyyyMMdd_HHmm",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out timestamp);
    }

    private static long GetDirectorySize(string path)
    {
        try
        {
            if (!Directory.Exists(path))
                return 0;

            long total = 0;
            foreach (var file in Directory.EnumerateFiles(path, "*.log", SearchOption.AllDirectories))
            {
                try
                {
                    total += new FileInfo(file).Length;
                }
                catch
                {
                }
            }
            return total;
        }
        catch
        {
            return 0;
        }
    }

    private static string FormatSizeBytes(long bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        double size = bytes;
        int unitIndex = 0;
        while (size >= 1024 && unitIndex < units.Length - 1)
        {
            size /= 1024;
            unitIndex++;
        }

        return unitIndex == 0
            ? $"{size:0} {units[unitIndex]}"
            : $"{size:0.##} {units[unitIndex]}";
    }

    private readonly record struct LogDayEntry(string Folder, DateTime Date, string Label, string MonthKey, string MonthLabel, string YearKey, string YearLabel, long SizeBytes);
    private readonly record struct LogMonthEntry(string Key, string Label, DateTime MonthDate, IReadOnlyList<LogDayEntry> Days, long SizeBytes);
    private readonly record struct LogYearEntry(string Key, string Label, DateTime YearDate, IReadOnlyList<LogMonthEntry> Months, long SizeBytes);
    private readonly record struct LogFileEntry(string Name, DateTime? Timestamp, bool IsError, DateTime SortKey);
    private readonly record struct LogTarget(string Scope, string? MonthKey, string? DateFolder, string? Hour, string Label, IReadOnlyList<string> Directories, string ZipName);

    private static DataEntityMetadata? ResolveEntity(BmwContext context, out string typeSlug, out string? errorMessage)
    {
        typeSlug = GetRouteValue(context, "type") ?? string.Empty;
        if (string.IsNullOrWhiteSpace(typeSlug))
        {
            errorMessage = "Entity type not specified.";
            return null;
        }

        if (DataScaffold.TryGetEntity(typeSlug, out var metadata))
        {
            errorMessage = null;
            return metadata;
        }

        errorMessage = $"Unknown entity '{WebUtility.HtmlEncode(typeSlug)}'.";
        return null;
    }

    private static string? GetRouteValue(BmwContext context, string key)
    {
        // Fast path: prefix router sets these directly (zero allocation)
        if (string.Equals(key, "type", StringComparison.OrdinalIgnoreCase) && context.EntitySlug != null)
            return context.EntitySlug;
        if (string.Equals(key, "id", StringComparison.OrdinalIgnoreCase) && context.EntityId != null)
            return context.EntityId;
        if (context.RouteExtraKey != null && string.Equals(key, context.RouteExtraKey, StringComparison.OrdinalIgnoreCase))
            return context.RouteExtra;

        var pageContext = context.GetPageContext();
        if (pageContext == null)
            return null;

        for (int i = 0; i < pageContext.PageMetaDataKeys.Length; i++)
        {
            if (string.Equals(pageContext.PageMetaDataKeys[i], key, StringComparison.OrdinalIgnoreCase))
                return pageContext.PageMetaDataValues[i];
        }

        return null;
    }

    private static Dictionary<string, string?> ToQueryDictionary(IQueryCollection query)
    {
        var dict = new Dictionary<string, string?>(query.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in query)
        {
            dict[kvp.Key] = kvp.Value.ToString();
        }

        return dict;
    }

    private static string[][] BuildListPlainRows(DataEntityMetadata metadata, IEnumerable items)
    {
        var rows = DataScaffold.BuildListRows(metadata, items, string.Empty, includeActions: false);
        using var result = new BmwValueList<string[]>(16);
        foreach (var row in rows)
        {
            var cleanRow = new string[row.Length];
            for (int ci = 0; ci < row.Length; ci++)
                cleanRow[ci] = StripHtml(WebUtility.HtmlDecode(row[ci] ?? string.Empty));
            result.Add(cleanRow);
        }
        return result.ToArray();
    }

    private static string[][] BuildListPlainRowsWithId(DataEntityMetadata metadata, IReadOnlyList<object?> items, out string[] headers)
    {
        var filteredItems = new List<object?>();
        foreach (var item in items)
        {
            if (item != null)
                filteredItems.Add(item);
        }
        var baseRows = BuildListPlainRows(metadata, filteredItems);
        var baseHeaders = DataScaffold.BuildListHeaders(metadata, includeActions: false);
        var headerList = new List<string> { "Id" };
        headerList.AddRange(baseHeaders);
        headers = headerList.ToArray();

        var output = new string[baseRows.Length][];
        for (int i = 0; i < baseRows.Length; i++)
        {
            var id = filteredItems[i] is BaseDataObject dataObject
                ? DataScaffold.GetIdValue(dataObject) ?? string.Empty
                : string.Empty;
            var concatRow = new string[1 + baseRows[i].Length];
            concatRow[0] = id;
            Array.Copy(baseRows[i], 0, concatRow, 1, baseRows[i].Length);
            output[i] = concatRow;
        }

        return output;
    }

    private static async ValueTask WriteTextResponseAsync(BmwContext context, string contentType, string content, string fileName)
    {
        context.Response.ContentType = contentType;
        context.Response.Headers["Content-Disposition"] = $"attachment; filename=\"{fileName}\"";
        await context.Response.WriteAsync(content);
    }

    private static string BuildCsv(string[] headers, string[][] rows)
    {
        var sb = RentStringBuilder(1024);
        try
        {
        AppendCsvRow(sb, headers);
        foreach (var row in rows)
        {
            AppendCsvRow(sb, row);
        }

        return sb.ToString();
        }
        finally { ReturnStringBuilder(sb); }
    }

    private static void AppendCsvRow(StringBuilder sb, string[] cells)
    {
        for (int i = 0; i < cells.Length; i++)
        {
            if (i > 0) sb.Append(',');
            CsvEscapeTo(sb, cells[i]);
        }
        sb.AppendLine();
    }

    private static void CsvEscapeTo(StringBuilder sb, string value)
    {
        var safe = value ?? string.Empty;
        if (safe.Contains('"') || safe.Contains(',') || safe.Contains('\n') || safe.Contains('\r'))
        {
            sb.Append('"');
            foreach (char c in safe)
            {
                if (c == '"') sb.Append('"');
                sb.Append(c);
            }
            sb.Append('"');
        }
        else
        {
            sb.Append(safe);
        }
    }

    private static string CsvEscape(string value)
    {
        var safe = value ?? string.Empty;
        if (safe.Contains('"') || safe.Contains(',') || safe.Contains('\n') || safe.Contains('\r'))
        {
            safe = safe.Replace("\"", "\"\"");
            return $"\"{safe}\"";
        }

        return safe;
    }

    private static string[][] ViewRowsToArray(IReadOnlyList<(string Label, string Value)> viewRows)
    {
        var result = new string[viewRows.Count][];
        for (int i = 0; i < viewRows.Count; i++)
            result[i] = new[] { viewRows[i].Label, viewRows[i].Value };
        return result;
    }

    private static string[][] PrependIdRow(string recordId, string[][] rows)
    {
        var result = new string[rows.Length + 1][];
        result[0] = new[] { "Id", recordId };
        Array.Copy(rows, 0, result, 1, rows.Length);
        return result;
    }

    private static string[] ConcatArrays(string[] a, string[] b)
    {
        var result = new string[a.Length + b.Length];
        Array.Copy(a, 0, result, 0, a.Length);
        Array.Copy(b, 0, result, a.Length, b.Length);
        return result;
    }

    private static string[] BuildParentValueRow(string parentId, List<(string Label, string Value)> fields)
    {
        var result = new string[1 + fields.Count];
        result[0] = parentId;
        for (int i = 0; i < fields.Count; i++)
            result[i + 1] = fields[i].Value;
        return result;
    }

    private static string JoinEncoded(string separator, IReadOnlyList<string> items)
    {
        var sb = new StringBuilder(256);
        for (int i = 0; i < items.Count; i++)
        {
            if (i > 0) sb.Append(separator);
            sb.Append(WebUtility.HtmlEncode(items[i]));
        }
        return sb.ToString();
    }

    // Export helper methods for nested/embedded components

    private async ValueTask ExportHierarchicalJson(BmwContext context, DataEntityMetadata meta, string typeSlug, IReadOnlyList<object?> items, ExportOptions options)
    {
        var jsonOptions = JsonIndented;
        #pragma warning disable IL2026 // Serializing IReadOnlyList<object?> — all entity types preserved via TrimmerRootAssembly
        var json = JsonSerializer.Serialize(items, jsonOptions);
        #pragma warning restore IL2026
        context.Response.ContentType = "application/json";
        context.Response.Headers["Content-Disposition"] = $"attachment; filename=\"{typeSlug}_export.json\"";
        await context.Response.WriteAsync(json);
    }

    private async ValueTask ExportSingleHierarchicalJson(BmwContext context, DataEntityMetadata meta, string typeSlug, string id, object instance, ExportOptions options)
    {
        var jsonOptions = JsonIndented;
        #pragma warning disable IL2026 // Serializing entity instance — all entity types preserved via TrimmerRootAssembly
        var json = JsonSerializer.Serialize(instance, jsonOptions);
        #pragma warning restore IL2026
        context.Response.ContentType = "application/json";
        context.Response.Headers["Content-Disposition"] = $"attachment; filename=\"{typeSlug}_{WebUtility.UrlEncode(id)}.json\"";
        await context.Response.WriteAsync(json);
    }

    private async ValueTask ExportFlatCsv(BmwContext context, DataEntityMetadata meta, string typeSlug, IReadOnlyList<object?> items, ExportOptions options)
    {
        if (!options.IncludeNested || options.MaxDepth < 1)
        {
            // No nested data, fall back to simple CSV
            var rows = BuildListPlainRowsWithId(meta, items, out var headers);
            var csv = BuildCsv(headers, rows);
            await WriteTextResponseAsync(context, "text/csv", csv, $"{typeSlug}_flat.csv");
            return;
        }

        var nestedComponents = DataScaffold.GetNestedComponents(meta);
        if (nestedComponents.Count == 0)
        {
            // No nested components, fall back to simple CSV
            var rows = BuildListPlainRowsWithId(meta, items, out var headers);
            var csv = BuildCsv(headers, rows);
            await WriteTextResponseAsync(context, "text/csv", csv, $"{typeSlug}_flat.csv");
            return;
        }

        // Build flat CSV with parent fields repeated for each child row
        var flatRows = new List<string[]>();
        var parentHeadersList = new List<string> { "Id" };
        parentHeadersList.AddRange(DataScaffold.BuildListHeaders(meta, includeActions: false));
        var allHeaders = new List<string>(parentHeadersList);
        
        // Add headers for first nested component (for simplicity, we'll flatten only the first one)
        var firstNested = nestedComponents[0];
        object firstItem = new object();
        foreach (var it in items)
        {
            if (it != null) { firstItem = it; break; }
        }
        var nestedData = DataScaffold.ExtractNestedData(meta, firstItem);
        if (nestedData.Count > 0)
        {
            foreach (var h in nestedData[0].Headers)
                allHeaders.Add($"{firstNested.Field.Label}.{h}");
        }

        foreach (var item in items)
        {
            if (item == null)
                continue;

            var id = item is BaseDataObject dataObject ? DataScaffold.GetIdValue(dataObject) ?? string.Empty : string.Empty;
            var baseRow = BuildListPlainRows(meta, new[] { item })[0];
            var parentRow = new string[1 + baseRow.Length];
            parentRow[0] = id;
            Array.Copy(baseRow, 0, parentRow, 1, baseRow.Length);
            
            var nested = DataScaffold.ExtractNestedData(meta, item);
            if (nested.Count > 0 && nested[0].Rows.Length > 0)
            {
                foreach (var childRow in nested[0].Rows)
                {
                    var combined = new string[parentRow.Length + childRow.Length];
                    Array.Copy(parentRow, 0, combined, 0, parentRow.Length);
                    Array.Copy(childRow, 0, combined, parentRow.Length, childRow.Length);
                    flatRows.Add(combined);
                }
            }
            else
            {
                var emptyChild = nestedData.Count > 0 ? new string[nestedData[0].Headers.Length] : Array.Empty<string>();
                var combined = new string[parentRow.Length + emptyChild.Length];
                Array.Copy(parentRow, 0, combined, 0, parentRow.Length);
                Array.Copy(emptyChild, 0, combined, parentRow.Length, emptyChild.Length);
                flatRows.Add(combined);
            }
        }

        var flatCsv = BuildCsv(allHeaders.ToArray(), flatRows.ToArray());
        await WriteTextResponseAsync(context, "text/csv", flatCsv, $"{typeSlug}_flat.csv");
    }

    private async ValueTask ExportSingleFlatCsv(BmwContext context, DataEntityMetadata meta, string typeSlug, string id, object instance, ExportOptions options)
    {
        if (!options.IncludeNested || options.MaxDepth < 1)
        {
            var rows = ViewRowsToArray(DataScaffold.BuildViewRows(meta, instance));
            if (instance is BaseDataObject dataObject)
                rows = PrependIdRow(DataScaffold.GetIdValue(dataObject) ?? string.Empty, rows);
            var headers = new[] { "Field", "Value" };
            var csv = BuildCsv(headers, rows);
            await WriteTextResponseAsync(context, "text/csv", csv, $"{typeSlug}_{WebUtility.UrlEncode(id)}_flat.csv");
            return;
        }

        var nestedComponents = DataScaffold.GetNestedComponents(meta);
        if (nestedComponents.Count == 0)
        {
            var rows = ViewRowsToArray(DataScaffold.BuildViewRows(meta, instance));
            if (instance is BaseDataObject dataObject)
                rows = PrependIdRow(DataScaffold.GetIdValue(dataObject) ?? string.Empty, rows);
            var headers = new[] { "Field", "Value" };
            var csv = BuildCsv(headers, rows);
            await WriteTextResponseAsync(context, "text/csv", csv, $"{typeSlug}_{WebUtility.UrlEncode(id)}_flat.csv");
            return;
        }

        // Build flat CSV with parent fields repeated for each child row
        var flatRows = new List<string[]>();
        var parentId = instance is BaseDataObject dobj ? DataScaffold.GetIdValue(dobj) ?? string.Empty : string.Empty;
        var parentFieldsList = new List<(string Label, string Value)>(DataScaffold.BuildViewRows(meta, instance));
        var parentHeaders = new List<string> { "Id" };
        foreach (var f in parentFieldsList)
            parentHeaders.Add(f.Label);

        var allHeaders = new List<string>(parentHeaders);
        var nested = DataScaffold.ExtractNestedData(meta, instance);
        
        if (nested.Count > 0)
        {
            foreach (var h in nested[0].Headers)
                allHeaders.Add($"{nested[0].FieldName}.{h}");

            var parentRow = BuildParentValueRow(parentId, parentFieldsList);
            
            if (nested[0].Rows.Length > 0)
            {
                foreach (var childRow in nested[0].Rows)
                    flatRows.Add(ConcatArrays(parentRow, childRow));
            }
            else
            {
                var emptyChild = new string[nested[0].Headers.Length];
                flatRows.Add(ConcatArrays(parentRow, emptyChild));
            }
        }
        else
        {
            var parentRow = BuildParentValueRow(parentId, parentFieldsList);
            flatRows.Add(parentRow);
        }

        var flatCsv = BuildCsv(allHeaders.ToArray(), flatRows.ToArray());
        await WriteTextResponseAsync(context, "text/csv", flatCsv, $"{typeSlug}_{WebUtility.UrlEncode(id)}_flat.csv");
    }

    private async ValueTask ExportMultiSheetZip(BmwContext context, DataEntityMetadata meta, string typeSlug, IReadOnlyList<object?> items, ExportOptions options)
    {
        using var memoryStream = new MemoryStream();
        using (var archive = new ZipArchive(memoryStream, ZipArchiveMode.Create, leaveOpen: true))
        {
            // Add parent CSV
            var parentRows = BuildListPlainRowsWithId(meta, items, out var parentHeaders);
            var parentCsv = BuildCsv(parentHeaders, parentRows);
            var parentEntry = archive.CreateEntry($"{typeSlug}.csv");
            using (var entryStream = parentEntry.Open())
            using (var writer = new StreamWriter(entryStream))
            {
                await writer.WriteAsync(parentCsv);
            }

            if (options.IncludeNested && options.MaxDepth >= 1)
            {
                var nestedComponents = DataScaffold.GetNestedComponents(meta);
                foreach (var (field, childType) in nestedComponents)
                {
                    var childRows = new List<string[]>();
                    var childHeaders = new List<string> { "ParentId" };
                    string[]? headers = null;

                    foreach (var item in items)
                    {
                        if (item == null)
                            continue;

                        var parentId = item is BaseDataObject dobj ? DataScaffold.GetIdValue(dobj) ?? string.Empty : string.Empty;
                        var nested = DataScaffold.ExtractNestedData(meta, item);
                        (string FieldName, string[] Headers, string[][] Rows) matchingNested = default;
                        foreach (var n in nested)
                        {
                            if (string.Equals(n.FieldName, field.Name, StringComparison.OrdinalIgnoreCase))
                            {
                                matchingNested = n;
                                break;
                            }
                        }
                        
                        if (headers == null && matchingNested.Headers != null && matchingNested.Headers.Length > 0)
                        {
                            headers = matchingNested.Headers;
                            childHeaders.AddRange(headers);
                        }

                        if (matchingNested.Rows != null)
                        {
                            foreach (var row in matchingNested.Rows)
                            {
                                var concatRow = new string[1 + row.Length];
                                concatRow[0] = parentId;
                                Array.Copy(row, 0, concatRow, 1, row.Length);
                                childRows.Add(concatRow);
                            }
                        }
                    }

                    if (childRows.Count > 0 && headers != null)
                    {
                        var childCsv = BuildCsv(childHeaders.ToArray(), childRows.ToArray());
                        var childEntry = archive.CreateEntry($"{typeSlug}_{field.Name}.csv");
                        using var childStream = childEntry.Open();
                        using var childWriter = new StreamWriter(childStream);
                        await childWriter.WriteAsync(childCsv);
                    }
                }
            }
        }

        memoryStream.Position = 0;
        context.Response.ContentType = "application/zip";
        context.Response.Headers["Content-Disposition"] = $"attachment; filename=\"{typeSlug}_export.zip\"";
        await memoryStream.CopyToAsync(context.Response.Body);
    }

    private async ValueTask ExportSingleMultiSheetZip(BmwContext context, DataEntityMetadata meta, string typeSlug, string id, object instance, ExportOptions options)
    {
        using var memoryStream = new MemoryStream();
        using (var archive = new ZipArchive(memoryStream, ZipArchiveMode.Create, leaveOpen: true))
        {
            // Add parent CSV
            var parentRows = ViewRowsToArray(DataScaffold.BuildViewRows(meta, instance));
            if (instance is BaseDataObject dataObject)
                parentRows = PrependIdRow(DataScaffold.GetIdValue(dataObject) ?? string.Empty, parentRows);
            var parentHeaders = new[] { "Field", "Value" };
            var parentCsv = BuildCsv(parentHeaders, parentRows);
            var parentEntry = archive.CreateEntry($"{typeSlug}.csv");
            using (var entryStream = parentEntry.Open())
            using (var writer = new StreamWriter(entryStream))
            {
                await writer.WriteAsync(parentCsv);
            }

            if (options.IncludeNested && options.MaxDepth >= 1)
            {
                var nested = DataScaffold.ExtractNestedData(meta, instance);
                foreach (var (fieldName, headers, rows) in nested)
                {
                    if (rows.Length > 0)
                    {
                        var childCsv = BuildCsv(headers, rows);
                        var childEntry = archive.CreateEntry($"{typeSlug}_{fieldName}.csv");
                        using var childStream = childEntry.Open();
                        using var childWriter = new StreamWriter(childStream);
                        await childWriter.WriteAsync(childCsv);
                    }
                }
            }
        }

        memoryStream.Position = 0;
        context.Response.ContentType = "application/zip";
        context.Response.Headers["Content-Disposition"] = $"attachment; filename=\"{typeSlug}_{WebUtility.UrlEncode(id)}_export.zip\"";
        await memoryStream.CopyToAsync(context.Response.Body);
    }

    private static string BuildHtmlTableDocument(string title, string[] headers, string[][] rows)
    {
        var sb = RentStringBuilder(4096);
        try
        {
        sb.Append("<!doctype html><html><head><meta charset=\"utf-8\" />");
        sb.Append($"<title>{WebUtility.HtmlEncode(title)}</title>");
        sb.Append("<style>body{font-family:Arial,Helvetica,sans-serif;margin:24px;}table{border-collapse:collapse;width:100%;}th,td{border:1px solid #ddd;padding:8px;text-align:left;}th{background:#f2f2f2;}</style>");
        sb.Append("</head><body>");
        sb.Append($"<h1>{WebUtility.HtmlEncode(title)}</h1>");
        sb.Append("<table><thead><tr>");
        foreach (var header in headers)
        {
            sb.Append("<th>");
            sb.Append(WebUtility.HtmlEncode(header));
            sb.Append("</th>");
        }
        sb.Append("</tr></thead><tbody>");
        foreach (var row in rows)
        {
            sb.Append("<tr>");
            foreach (var cell in row)
            {
                sb.Append("<td>");
                sb.Append(WebUtility.HtmlEncode(cell));
                sb.Append("</td>");
            }
            sb.Append("</tr>");
        }
        sb.Append("</tbody></table></body></html>");
        return sb.ToString();
        }
        finally { ReturnStringBuilder(sb); }
    }

    private static string BuildRtfDocument(string title, string[][] rows)
    {
        var sb = RentStringBuilder(2048);
        try
        {
        sb.Append("{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Arial;}}\\fs20 ");
        sb.Append("\\b ");
        sb.Append(EscapeRtf(title));
        sb.Append("\\b0\\par ");
        sb.Append("\\par ");
        foreach (var row in rows)
        {
            var label = row.Length > 0 ? row[0] : string.Empty;
            var value = row.Length > 1 ? row[1] : string.Empty;
            sb.Append("\\b ");
            sb.Append(EscapeRtf(label));
            sb.Append(":\\b0 ");
            sb.Append(EscapeRtf(value));
            sb.Append("\\par ");
        }
        sb.Append("}");
        return sb.ToString();
        }
        finally { ReturnStringBuilder(sb); }
    }

    private static string EscapeRtf(string text)
    {
        if (string.IsNullOrEmpty(text))
            return string.Empty;

        var builder = new StringBuilder(text.Length);
        foreach (var ch in text)
        {
            switch (ch)
            {
                case '\\':
                    builder.Append("\\\\");
                    break;
                case '{':
                    builder.Append("\\{");
                    break;
                case '}':
                    builder.Append("\\}");
                    break;
                case '\n':
                    builder.Append("\\par ");
                    break;
                case '\r':
                    break;
                default:
                    builder.Append(ch <= 0x7E && ch >= 0x20 ? ch : '?');
                    break;
            }
        }

        return builder.ToString();
    }

    private static string StripHtml(string value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        var builder = new StringBuilder(value.Length);
        var insideTag = false;
        foreach (var ch in value)
        {
            if (ch == '<')
            {
                insideTag = true;
                continue;
            }
            if (ch == '>')
            {
                insideTag = false;
                continue;
            }
            if (!insideTag)
                builder.Append(ch);
        }

        return builder.ToString();
    }

    private static string BuildExportDropdown(string typeSlug, string queryString, bool includeNested, string? id = null)
    {
        var baseUrl = id != null 
            ? $"/ssr/admin/data/{typeSlug}/{WebUtility.UrlEncode(id)}/export"
            : $"/ssr/admin/data/{typeSlug}/export";
        
        var separator = string.IsNullOrEmpty(queryString) || queryString == "?" ? "?" : "&";
        var baseQueryString = queryString == "?" ? "" : queryString;
        
        var hasNested = includeNested;
        var nestedLabel = hasNested ? " (with nested)" : "";
        
        var dropdownId = id != null ? $"export-dropdown-{WebUtility.UrlEncode(id)}" : "export-dropdown-list";
        
        var html = RentStringBuilder(512);
        try
        {
        html.Append("<div class=\"btn-group ms-2\" role=\"group\">");
        html.Append($"<button type=\"button\" class=\"btn btn-sm btn-outline-success dropdown-toggle\" data-bs-toggle=\"dropdown\" aria-expanded=\"false\" id=\"{dropdownId}\">");
        html.Append("<i class=\"bi bi-download\" aria-hidden=\"true\"></i> Export");
        html.Append("</button>");
        html.Append($"<ul class=\"dropdown-menu\" aria-labelledby=\"{dropdownId}\">");
        
        // Simple CSV (no nested)
        html.Append($"<li><a class=\"dropdown-item\" href=\"{baseUrl}{baseQueryString}{separator}format=SimpleCSV\">");
        html.Append("<i class=\"bi bi-file-earmark-spreadsheet\"></i> CSV (simple)</a></li>");
        
        if (hasNested)
        {
            // Flat CSV (nested denormalized)
            html.Append($"<li><a class=\"dropdown-item\" href=\"{baseUrl}{baseQueryString}{separator}format=FlatCSV\">");
            html.Append("<i class=\"bi bi-file-earmark-spreadsheet\"></i> CSV (flat with nested)</a></li>");
            
            // Multi-sheet ZIP
            html.Append($"<li><a class=\"dropdown-item\" href=\"{baseUrl}{baseQueryString}{separator}format=MultiSheetZip\">");
            html.Append("<i class=\"bi bi-file-earmark-zip\"></i> ZIP (multi-sheet)</a></li>");
        }
        
        // Hierarchical JSON
        html.Append($"<li><a class=\"dropdown-item\" href=\"{baseUrl}{baseQueryString}{separator}format=HierarchicalJSON\">");
        html.Append("<i class=\"bi bi-filetype-json\"></i> JSON{nestedLabel}</a></li>");
        
        html.Append("</ul>");
        html.Append("</div>");
        
        return html.ToString();
        }
        finally { ReturnStringBuilder(html); }
    }

    private const string ApiCsrfHeaderName = "X-Requested-With";
    private const string ApiCsrfHeaderValue = "BareMetalWeb";

    private static bool ValidateApiCsrfHeader(BmwContext context)
        => UserAuth.HasApiKeyHeader(context) ||
           string.Equals(context.HttpRequest.Headers[ApiCsrfHeaderName], ApiCsrfHeaderValue, StringComparison.Ordinal);

    private static async ValueTask<bool> HasEntityPermissionAsync(BmwContext context, DataEntityMetadata meta, CancellationToken cancellationToken = default)
    {
        var permissionsNeeded = meta.Permissions?.Trim();
        if (string.IsNullOrWhiteSpace(permissionsNeeded) || string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase))
            return true;

        var user = await UserAuth.GetRequestUserAsync(context, cancellationToken).ConfigureAwait(false);
        if (user == null)
        {
            return string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase);
        }

        if (string.Equals(permissionsNeeded, "Authenticated", StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase))
            return false;

        var userPermissions = RentPermissionSet(user.Permissions ?? Array.Empty<string>());
        try
        {
        var altLookup = userPermissions.GetAlternateLookup<ReadOnlySpan<char>>();
        var remaining = permissionsNeeded.AsSpan();
        while (remaining.Length > 0)
        {
            int idx = remaining.IndexOf(',');
            ReadOnlySpan<char> segment;
            if (idx < 0) { segment = remaining; remaining = default; }
            else { segment = remaining[..idx]; remaining = remaining[(idx + 1)..]; }
            var trimmed = segment.Trim();
            if (trimmed.IsEmpty) continue;
            if (!altLookup.Contains(trimmed))
                return false;
        }
        return true;
        }
        finally { ReturnPermissionSet(userPermissions); }
    }

    private static List<string[]> ParseCsvRows(string content)
    {
        var rows = new List<string[]>();
        if (string.IsNullOrEmpty(content))
            return rows;

        var current = new List<string>();
        var field = new StringBuilder(128);
        bool inQuotes = false;

        for (int i = 0; i < content.Length; i++)
        {
            var ch = content[i];

            if (inQuotes)
            {
                if (ch == '"')
                {
                    var nextIsQuote = i + 1 < content.Length && content[i + 1] == '"';
                    if (nextIsQuote)
                    {
                        field.Append('"');
                        i++;
                    }
                    else
                    {
                        inQuotes = false;
                    }
                }
                else
                {
                    field.Append(ch);
                }
                continue;
            }

            switch (ch)
            {
                case '"':
                    inQuotes = true;
                    break;
                case ',':
                    current.Add(field.ToString());
                    field.Clear();
                    break;
                case '\r':
                    if (i + 1 < content.Length && content[i + 1] == '\n')
                        i++;
                    current.Add(field.ToString());
                    field.Clear();
                    rows.Add(current.ToArray());
                    current.Clear();
                    break;
                case '\n':
                    current.Add(field.ToString());
                    field.Clear();
                    rows.Add(current.ToArray());
                    current.Clear();
                    break;
                default:
                    field.Append(ch);
                    break;
            }
        }

        current.Add(field.ToString());
        {
            bool hasNonBlank = false;
            foreach (var value in current)
            {
                if (!string.IsNullOrWhiteSpace(value))
                {
                    hasNonBlank = true;
                    break;
                }
            }
            if (hasNonBlank)
                rows.Add(current.ToArray());
        }

        return rows;
    }

    private static Dictionary<string, int> BuildCsvMapping(DataEntityMetadata meta, string[] header, out int idIndex, out int passwordIndex)
    {
        var mapping = new Dictionary<string, int>(header.Length, StringComparer.OrdinalIgnoreCase);
        idIndex = -1;
        passwordIndex = -1;

        var fieldMap = new Dictionary<string, DataFieldMetadata>(meta.Fields.Count * 2, StringComparer.OrdinalIgnoreCase);
        foreach (var field in meta.Fields)
        {
            if (!((field.Create || field.Edit) && !field.ReadOnly))
                continue;
            if (!fieldMap.ContainsKey(field.Name))
                fieldMap[field.Name] = field;
            if (!string.IsNullOrWhiteSpace(field.Label) && !fieldMap.ContainsKey(field.Label))
                fieldMap[field.Label] = field;
        }

        for (int i = 0; i < header.Length; i++)
        {
            var name = header[i]?.Trim() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(name))
                continue;
            if (string.Equals(name, "id", StringComparison.OrdinalIgnoreCase))
            {
                idIndex = i;
                continue;
            }
            if (string.Equals(name, "password", StringComparison.OrdinalIgnoreCase))
            {
                passwordIndex = i;
                continue;
            }

            if (fieldMap.TryGetValue(name, out var fieldMeta))
                mapping[fieldMeta.Name] = i;
        }

        return mapping;
    }

    private static void ApplyUserPasswordForImport(DataEntityMetadata meta, BaseDataObject instance, string[] row, int passwordIndex, bool isCreate, List<string> errors)
    {
        if (meta.Type != typeof(User))
            return;

        var password = passwordIndex >= 0 && passwordIndex < row.Length
            ? row[passwordIndex]
            : string.Empty;

        if (string.IsNullOrWhiteSpace(password))
        {
            if (isCreate)
                errors.Add("Password is required.");
            return;
        }

        if (instance is User user)
            user.SetPassword(password);
    }

    private static void ApplyAuditInfo(object instance, string userName, bool isCreate)
    {
        if (instance is not BaseDataObject dataObject)
            return;

        if (isCreate)
        {
            dataObject.CreatedBy = userName;
            dataObject.UpdatedBy = userName;
            dataObject.CreatedOnUtc = DateTime.UtcNow;
            dataObject.UpdatedOnUtc = dataObject.CreatedOnUtc;
        }
        else
        {
            dataObject.Touch(userName);
        }
    }

    private static void ApplyPrefillFromQuery(DataEntityMetadata meta, object instance, IQueryCollection query)
    {
        if (meta == null || instance == null)
            return;

        var fieldName = query["field"].ToString();
        var value = query["value"].ToString();
        if (string.IsNullOrWhiteSpace(fieldName) || string.IsNullOrWhiteSpace(value))
            return;

        var field = meta.FindField(fieldName);
        if (field == null)
            return;

        if (DataScaffold.TryConvertValue(value, field.Property.PropertyType, out var converted) && converted != null)
        {
            field.SetValueFn(instance, converted);
            return;
        }

        var effectiveType = Nullable.GetUnderlyingType(field.Property.PropertyType) ?? field.Property.PropertyType;
        if (effectiveType == typeof(string))
        {
            field.SetValueFn(instance, value);
        }
    }

    private void RenderSampleDataForm(BmwContext context, string? message, IReadOnlyList<RuntimeEntityModel> entities, int defaultCount, bool clearExisting)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Generate Sample Data");
        context.SetStringValue("html_message", string.IsNullOrWhiteSpace(message) ? string.Empty : message);

        var fields = new List<FormField>
        {
            new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken)
        };

        foreach (var entity in entities)
        {
            fields.Add(new FormField(FormFieldType.Integer, entity.Slug, entity.Name, Required: true, Value: defaultCount.ToString(CultureInfo.InvariantCulture)));
        }

        fields.Add(new FormField(FormFieldType.YesNo, "clearExisting", "Clear existing data", false, SelectedValue: clearExisting ? "true" : "false"));

        context.AddFormDefinition(new FormDefinition("/admin/sample-data", "post", "Generate", fields));
    }

    private static bool ParseSampleToggle(IFormCollection form, string key)
    {
        var raw = form[key].ToString();
        if (string.IsNullOrWhiteSpace(raw))
            return false;

        return string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(raw, "on", StringComparison.OrdinalIgnoreCase)
            || string.Equals(raw, "yes", StringComparison.OrdinalIgnoreCase)
            || string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase);
    }

    private static int ParseSampleCount(IFormCollection form, string key, List<string> errors)
    {
        var raw = form[key].ToString();
        if (!int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) || value < 0)
        {
            errors.Add($"{key} must be a non-negative number.");
            return 0;
        }

        if (value > 100000)
        {
            errors.Add($"{key} is too large (max 100000).");
            return 0;
        }

        return value;
    }

    private static object? GenerateSampleValue(RuntimeFieldModel field, Random rng)
    {
        return field.FieldType switch
        {
            FormFieldType.String => $"Sample {field.Label} {rng.Next(1, 10000)}",
            FormFieldType.Email => $"user{rng.Next(1, 10000)}@example.com",
            FormFieldType.Integer => rng.Next(1, 1000),
            FormFieldType.Decimal or FormFieldType.Money => Math.Round((decimal)rng.NextDouble() * 1000, 2),
            FormFieldType.YesNo => rng.Next(2) == 1,
            FormFieldType.DateTime => DateTime.UtcNow.AddDays(-rng.Next(365)),
            FormFieldType.DateOnly => DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-rng.Next(365))),
            FormFieldType.TimeOnly => TimeOnly.FromDateTime(DateTime.UtcNow.AddHours(rng.Next(24))),
            FormFieldType.Enum => field.EnumValues.Count > 0 ? field.EnumValues[rng.Next(field.EnumValues.Count)] : null,
            FormFieldType.TextArea => $"Sample {field.Label} text content for record {rng.Next(1, 10000)}.",
            FormFieldType.LookupList => null,
            _ => $"Value-{rng.Next(1, 10000)}"
        };
    }

    private static async ValueTask<Dictionary<string, JsonElement>?> ReadJsonBodyAsync(BmwContext context)
    {
        if (context.HttpRequest.ContentLength.HasValue && context.HttpRequest.ContentLength.Value == 0)
            return null;

        try
        {
            using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body).ConfigureAwait(false);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return null;

            var payload = new Dictionary<string, JsonElement>(16, StringComparer.OrdinalIgnoreCase);
            foreach (var property in doc.RootElement.EnumerateObject())
            {
                payload[property.Name] = property.Value.Clone();
            }

            return payload;
        }
        catch
        {
            return null;
        }
    }

    private static async ValueTask WriteJsonResponseAsync(BmwContext context, object payload)
    {
        context.Response.ContentType = "application/json";
        await using var writer = new Utf8JsonWriter(context.Response.Body, new JsonWriterOptions { Indented = true });
        WriteJsonValue(writer, payload);
        await writer.FlushAsync();
    }

    private static void WriteJsonValue(Utf8JsonWriter writer, object? value)
    {
        if (value == null)
        {
            writer.WriteNullValue();
            return;
        }

        switch (value)
        {
            case JsonElement element:
                element.WriteTo(writer);
                return;
            case string s:
                writer.WriteStringValue(s);
                return;
            case bool b:
                writer.WriteBooleanValue(b);
                return;
            case int i:
                writer.WriteNumberValue(i);
                return;
            case long l:
                writer.WriteNumberValue(l);
                return;
            case double d:
                writer.WriteNumberValue(d);
                return;
            case decimal m:
                writer.WriteNumberValue(m);
                return;
            case float f:
                writer.WriteNumberValue(f);
                return;
            case DateTime dt:
                writer.WriteStringValue(dt.ToString("O"));
                return;
            case DateTimeOffset dto:
                writer.WriteStringValue(dto.ToString("O"));
                return;
            case Guid g:
                writer.WriteStringValue(g);
                return;
        }

        if (value is IDictionary<string, object?> dict)
        {
            writer.WriteStartObject();
            foreach (var kvp in dict)
            {
                writer.WritePropertyName(kvp.Key);
                WriteJsonValue(writer, kvp.Value);
            }
            writer.WriteEndObject();
            return;
        }

        if (value is System.Collections.IEnumerable enumerable && value is not string)
        {
            writer.WriteStartArray();
            foreach (var item in enumerable)
            {
                WriteJsonValue(writer, item);
            }
            writer.WriteEndArray();
            return;
        }

        writer.WriteStringValue(value?.ToString() ?? "");
    }

    private static void AppendUserPasswordFieldsIfNeeded(DataEntityMetadata meta, List<FormField> fields, bool isCreate)
    {
        if (meta.Type != typeof(User))
            return;

        var passwordLabel = isCreate ? "Password" : "New Password (leave blank to keep current)";
        fields.Add(new FormField(FormFieldType.Password, "password", passwordLabel, Required: isCreate, Placeholder: "Enter password"));
        if (isCreate)
        {
            fields.Add(new FormField(FormFieldType.Password, "password_confirm", "Confirm Password", Required: true, Placeholder: "Re-enter password"));
        }
    }

    private static void ApplyUserPasswordIfNeeded(DataEntityMetadata meta, object instance, IDictionary<string, string?> values, List<string> errors, bool isCreate)
    {
        if (meta.Type != typeof(User))
            return;

        if (instance is not User user)
            return;

        values.TryGetValue("password", out var password);
        values.TryGetValue("password_confirm", out var confirmPassword);

        var hasPassword = !string.IsNullOrWhiteSpace(password);
        if (isCreate && !hasPassword)
        {
            errors.Add("Password is required.");
            return;
        }

        if (hasPassword)
        {
            if (isCreate && !string.Equals(password, confirmPassword, StringComparison.Ordinal))
            {
                errors.Add("Passwords do not match.");
                return;
            }

            user.SetPassword(password!);
        }
    }

    private static async ValueTask ValidateUserUniquenessAsync(DataEntityMetadata meta, object instance, string? excludeId, List<string> errors, CancellationToken cancellationToken)
    {
        if (meta.Type == typeof(AppSetting))
        {
            if (instance is AppSetting appSetting && !string.IsNullOrWhiteSpace(appSetting.SettingId))
            {
                var query = new QueryDefinition
                {
                    Clauses = new List<QueryClause>
                    {
                        new() { Field = nameof(AppSetting.SettingId), Operator = QueryOperator.Equals, Value = appSetting.SettingId }
                    },
                    Top = 1
                };
                var existingResults = await DataStoreProvider.Current.QueryAsync<AppSetting>(query, cancellationToken).ConfigureAwait(false);
                AppSetting? existing = null;
                foreach (var e in existingResults)
                {
                    existing = e;
                    break;
                }
                if (existing != null && !string.Equals(existing.Key.ToString(), excludeId, StringComparison.OrdinalIgnoreCase))
                    errors.Add("A setting with this Setting ID already exists.");
            }
            return;
        }

        if (meta.Type != typeof(User))
            return;

        if (instance is not User user)
            return;

        if (!string.IsNullOrWhiteSpace(user.UserName))
        {
            var existing = await Users.FindByUserNameAsync(user.UserName, cancellationToken).ConfigureAwait(false);
            if (existing != null && !string.Equals(existing.Key.ToString(), excludeId, StringComparison.OrdinalIgnoreCase))
                errors.Add("Username is already taken.");
        }

        if (!string.IsNullOrWhiteSpace(user.Email))
        {
            var existing = await Users.FindByEmailAsync(user.Email, cancellationToken).ConfigureAwait(false);
            if (existing != null && !string.Equals(existing.Key.ToString(), excludeId, StringComparison.OrdinalIgnoreCase))
                errors.Add("Email is already registered.");
        }
    }

    private static List<string> FilterMissingRequiredErrorsForPatchForm(DataEntityMetadata meta, IDictionary<string, string?> values, List<string> errors)
    {
        if (errors.Count == 0)
            return errors;

        const string requiredSuffix = " is required.";
        var fieldByLabel = new Dictionary<string, DataFieldMetadata>(meta.Fields.Count, StringComparer.OrdinalIgnoreCase);
        foreach (var f in meta.Fields)
            fieldByLabel[f.Label] = f;
        var filtered = new List<string>(errors.Count);
        foreach (var error in errors)
        {
            if (!error.EndsWith(requiredSuffix, StringComparison.Ordinal))
            {
                filtered.Add(error);
                continue;
            }

            var label = error[..^requiredSuffix.Length];
            if (!fieldByLabel.TryGetValue(label, out var field))
            {
                filtered.Add(error);
                continue;
            }

            if (values.ContainsKey(field.Name))
            {
                filtered.Add(error);
                continue;
            }
        }

        return filtered;
    }

    private void RenderMfaResetForm(BmwContext context, string? message)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Reset MFA");
        context.SetStringValue("html_message", string.IsNullOrWhiteSpace(message)
            ? "<p>This will disable MFA and remove your secret. You can re-enable it later.</p>"
            : $"<div class=\"alert alert-danger\">{WebUtility.HtmlEncode(message)}</div>");

        context.AddFormDefinition(new FormDefinition(
            Action: "/account/mfa/reset",
            Method: "post",
            SubmitLabel: "Reset MFA",
            Fields: new[]
            {
                new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken)
            }
        ));
    }

    private static async ValueTask<MfaChallenge?> GetMfaChallengeAsync(BmwContext context, CancellationToken cancellationToken = default)
    {
        var challengeId = context.GetCookie(MfaChallengeCookieName);
        if (string.IsNullOrWhiteSpace(challengeId))
            return null;

        var challenge = await DataStoreProvider.Current.LoadAsync<MfaChallenge>(uint.Parse(challengeId), cancellationToken).ConfigureAwait(false);
        if (challenge == null || challenge.IsExpired())
        {
            if (challenge != null)
            {
                challenge.IsUsed = true;
                await DataStoreProvider.Current.SaveAsync(challenge, cancellationToken).ConfigureAwait(false);
            }
            context.DeleteCookie(MfaChallengeCookieName);
            return null;
        }

        return challenge;
    }

    private static async ValueTask<bool> RootUserExistsAsync(CancellationToken cancellationToken = default)
    {
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = nameof(User.Permissions), Operator = QueryOperator.Contains, Value = "admin" },
                new QueryClause { Field = nameof(User.Permissions), Operator = QueryOperator.Contains, Value = "monitoring" }
            }
        };

        var users = await DataStoreProvider.Current.QueryAsync<User>(query, cancellationToken).ConfigureAwait(false);
        bool hasUsers = false;
        foreach (var _ in users)
        {
            hasUsers = true;
            break;
        }
        return hasUsers;
    }

    private static async ValueTask<User?> GetLockedRootUserAsync(CancellationToken cancellationToken = default)
    {
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = nameof(User.Permissions), Operator = QueryOperator.Contains, Value = "admin" },
                new QueryClause { Field = nameof(User.Permissions), Operator = QueryOperator.Contains, Value = "monitoring" }
            }
        };

        var users = await DataStoreProvider.Current.QueryAsync<User>(query, cancellationToken).ConfigureAwait(false);
        User? lockedUser = null;
        foreach (var u in users)
        {
            if (u.IsLockedOut)
            {
                lockedUser = u;
                break;
            }
        }
        return lockedUser;
    }

    private static string BuildViewSwitcher(string typeSlug, ViewType currentView, DataEntityMetadata meta)
    {
        var html = RentStringBuilder(512);
        try
        {
        html.Append("<div class=\"btn-group btn-group-sm\" role=\"group\" aria-label=\"View Type\">");
        
        var tableActive = currentView == ViewType.Table ? " active" : string.Empty;
        html.Append($"<a class=\"btn btn-outline-secondary{tableActive}\" href=\"/ssr/admin/data/{typeSlug}?view=table\" title=\"Table View\"><i class=\"bi bi-table\" aria-hidden=\"true\"></i> Table</a>");
        
        if (meta.ParentField != null)
        {
            var treeActive = currentView == ViewType.TreeView ? " active" : string.Empty;
            html.Append($"<a class=\"btn btn-outline-secondary{treeActive}\" href=\"/ssr/admin/data/{typeSlug}?view=tree\" title=\"Tree View\"><i class=\"bi bi-diagram-3\" aria-hidden=\"true\"></i> Tree</a>");
            
            var orgActive = currentView == ViewType.OrgChart ? " active" : string.Empty;
            html.Append($"<a class=\"btn btn-outline-secondary{orgActive}\" href=\"/ssr/admin/data/{typeSlug}?view=orgchart\" title=\"Org Chart\"><i class=\"bi bi-diagram-2\" aria-hidden=\"true\"></i> Org Chart</a>");
        }

        if (DataScaffold.CanShowTimetableView(meta))
        {
            var timetableActive = currentView == ViewType.Timetable ? " active" : string.Empty;
            html.Append($"<a class=\"btn btn-outline-secondary{timetableActive}\" href=\"/ssr/admin/data/{typeSlug}?view=timetable\" title=\"Timetable View\"><i class=\"bi bi-calendar-week\" aria-hidden=\"true\"></i> Timetable</a>");
        }
        
        // Check if entity has any DateOnly or DateTime fields for timeline view
        if (DataScaffold.CanShowTimelineView(meta))
        {
            var timelineActive = currentView == ViewType.Timeline ? " active" : string.Empty;
            html.Append($"<a class=\"btn btn-outline-secondary{timelineActive}\" href=\"/ssr/admin/data/{typeSlug}?view=timeline\" title=\"Timeline View\"><i class=\"bi bi-clock-history\" aria-hidden=\"true\"></i> Timeline</a>");
        }
        
        html.Append("</div>");
        return html.ToString();
        }
        finally { ReturnStringBuilder(html); }
    }

    private static string BuildTimelineViewHtml(
        DataEntityMetadata meta,
        IEnumerable<BaseDataObject> allItems,
        string basePath,
        Func<DataEntityMetadata, bool>? canRenderLookupLink = null,
        string? cloneToken = null,
        string? cloneReturnUrl = null)
    {
        var html = RentStringBuilder(4096);
        try
        {

        // Find the first two DateOnly/DateTime fields: first is start date, second (if any) is end date
        var dateFields = new List<DataFieldMetadata>();
        foreach (var f in meta.Fields)
        {
            if (f.FieldType == FormFieldType.DateOnly || f.FieldType == FormFieldType.DateTime)
            {
                dateFields.Add(f);
                if (dateFields.Count >= 2) break;
            }
        }

        if (dateFields.Count == 0)
            return "<p class=\"text-warning\">Timeline view requires a DateOnly or DateTime field.</p>";

        var itemsList = new List<BaseDataObject>();
        foreach (var item in allItems)
            itemsList.Add(item);
        if (itemsList.Count == 0)
            return "<p class=\"text-muted\">No items found.</p>";

        var startField = dateFields[0];
        var endField = dateFields.Count > 1 ? dateFields[1] : null;

        // Extract start/end dates for each item
        var ganttItems = new List<(BaseDataObject Item, DateOnly Start, DateOnly End, string Label)>();
        foreach (var item in itemsList)
        {
            var startValue = startField.Property.GetValue(item);
            DateOnly? startDate = startValue switch
            {
                DateOnly d => d,
                DateTime dt => DateOnly.FromDateTime(dt),
                _ => null
            };
            // Skip items with unset/default dates (DateOnly.MinValue = 0001-01-01)
            if (startDate == null || startDate.Value == DateOnly.MinValue) continue;

            DateOnly endDate;
            if (endField != null)
            {
                var endValue = endField.Property.GetValue(item);
                endDate = endValue switch
                {
                    DateOnly d => d,
                    DateTime dt => DateOnly.FromDateTime(dt),
                    _ => startDate.Value
                };
                if (endDate < startDate.Value) endDate = startDate.Value;
            }
            else
            {
                endDate = startDate.Value;
            }

            ganttItems.Add((item, startDate.Value, endDate, GetDisplayValue(meta, item)));
        }

        if (ganttItems.Count == 0)
            return "<p class=\"text-muted\">No items with valid dates found.</p>";

        // Sort by start date ascending so the chart renders like a Gantt chart
        ganttItems.Sort((a, b) => a.Start.CompareTo(b.Start));

        // Expand date range to full month boundaries
        var minDate = ganttItems[0].Start;
        var maxDate = ganttItems[0].End;
        for (int gi = 1; gi < ganttItems.Count; gi++)
        {
            if (ganttItems[gi].Start < minDate) minDate = ganttItems[gi].Start;
            if (ganttItems[gi].End > maxDate) maxDate = ganttItems[gi].End;
        }
        var chartStart = new DateOnly(minDate.Year, minDate.Month, 1);
        var chartEndExclusive = maxDate.Month == 12
            ? new DateOnly(maxDate.Year + 1, 1, 1)
            : new DateOnly(maxDate.Year, maxDate.Month + 1, 1);
        var totalDays = Math.Max(
            (chartEndExclusive.ToDateTime(TimeOnly.MinValue) - chartStart.ToDateTime(TimeOnly.MinValue)).TotalDays,
            1.0);

        // Build list of month columns
        var months = new List<(int Year, int Month, double LeftPct, double WidthPct)>();
        var cur = chartStart;
        double runningLeft = 0.0;
        while (cur < chartEndExclusive)
        {
            var daysInMonth = DateTime.DaysInMonth(cur.Year, cur.Month);
            var widthPct = daysInMonth / totalDays * 100.0;
            months.Add((cur.Year, cur.Month, runningLeft, widthPct));
            runningLeft += widthPct;
            cur = cur.Month == 12 ? new DateOnly(cur.Year + 1, 1, 1) : new DateOnly(cur.Year, cur.Month + 1, 1);
        }

        // Build year groups (contiguous runs of months sharing the same year)
        var years = new List<(int Year, double LeftPct, double WidthPct)>();
        foreach (var (year, _, leftPct, widthPct) in months)
        {
            if (years.Count > 0 && years[^1].Year == year)
            {
                var last = years[^1];
                years[^1] = (last.Year, last.LeftPct, last.WidthPct + widthPct);
            }
            else
            {
                years.Add((year, leftPct, widthPct));
            }
        }

        // Bar colours (cycling)
        string[] barColors = ["#4472c4", "#c0504d", "#9bbb59", "#f79646", "#8064a2"];

        html.Append("<div class=\"bm-gantt-container\">");
        html.Append("<div class=\"bm-gantt-inner\">");

        // Year header row
        html.Append("<div class=\"bm-gantt-header-row\">");
        html.Append("<div class=\"bm-gantt-label-col\"></div>");
        html.Append("<div class=\"bm-gantt-years-hdr\">");
        foreach (var (year, leftPct, widthPct) in years)
            html.Append($"<div class=\"bm-gantt-year-lbl\" data-gantt-left=\"{leftPct:F2}%\" data-gantt-width=\"{widthPct:F2}%\">{year}</div>");
        html.Append("</div>");
        html.Append("</div>");

        // Month header row
        html.Append("<div class=\"bm-gantt-header-row\">");
        html.Append("<div class=\"bm-gantt-label-col\"></div>");
        html.Append("<div class=\"bm-gantt-months-hdr\">");
        foreach (var (year, month, leftPct, widthPct) in months)
        {
            var monthName = new DateOnly(year, month, 1).ToString("MMM");
            html.Append($"<div class=\"bm-gantt-month-lbl\" data-gantt-left=\"{leftPct:F2}%\" data-gantt-width=\"{widthPct:F2}%\">{WebUtility.HtmlEncode(monthName)}</div>");
        }
        html.Append("</div>");
        html.Append("</div>");

        // One row per item
        for (int i = 0; i < ganttItems.Count; i++)
        {
            var (item, start, end, label) = ganttItems[i];
            var itemId = DataScaffold.GetIdValue(item) ?? string.Empty;
            var safeId = Uri.EscapeDataString(itemId);
            var color = barColors[i % barColors.Length];

            var startDays = (start.ToDateTime(TimeOnly.MinValue) - chartStart.ToDateTime(TimeOnly.MinValue)).TotalDays;
            var endDays = (end.ToDateTime(TimeOnly.MinValue) - chartStart.ToDateTime(TimeOnly.MinValue)).TotalDays + 1;
            var barLeft = startDays / totalDays * 100.0;
            var barWidth = Math.Max((endDays - startDays) / totalDays * 100.0, 0.5);

            var tooltip = endField != null
                ? $"{WebUtility.HtmlEncode(label)}: {start:yyyy-MM-dd} \u2013 {end:yyyy-MM-dd}"
                : $"{WebUtility.HtmlEncode(label)}: {start:yyyy-MM-dd}";

            html.Append("<div class=\"bm-gantt-row\">");
            html.Append($"<div class=\"bm-gantt-lbl\" title=\"{WebUtility.HtmlEncode(label)}\"><a href=\"{basePath}/{safeId}\">{WebUtility.HtmlEncode(label)}</a></div>");
            html.Append("<div class=\"bm-gantt-bar-area\">");
            foreach (var (_, _, mLeft, _) in months)
                html.Append($"<div class=\"bm-gantt-sep\" data-gantt-left=\"{mLeft:F2}%\"></div>");
            html.Append($"<a href=\"{basePath}/{safeId}/edit\" class=\"bm-gantt-bar\" data-gantt-left=\"{barLeft:F2}%\" data-gantt-width=\"{barWidth:F2}%\" data-gantt-bg=\"{WebUtility.HtmlEncode(color)}\" title=\"{tooltip}\">");
            html.Append($"<span class=\"bm-gantt-bar-text\">{WebUtility.HtmlEncode(label)}</span>");
            html.Append("</a>");
            html.Append("</div>");
            html.Append("</div>");
        }

        html.Append("</div>"); // bm-gantt-inner
        html.Append("</div>"); // bm-gantt-container
        return html.ToString();
        }
        finally { ReturnStringBuilder(html); }
    }

    private static string GetDisplayValue(DataEntityMetadata meta, BaseDataObject item)
    {
        // Try common name fields first (same heuristic as DataScaffold.GetDisplayValue)
        DataFieldMetadata? nameField = null;
        foreach (var f in meta.Fields)
        {
            if (string.Equals(f.Name, "Name", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(f.Name, "Title", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(f.Name, "DisplayName", StringComparison.OrdinalIgnoreCase))
            {
                nameField = f;
                break;
            }
        }
        if (nameField != null)
        {
            var value = nameField.Property.GetValue(item)?.ToString();
            if (!string.IsNullOrWhiteSpace(value))
                return value;
        }

        // Fall back to first List string field
        DataFieldMetadata? displayField = null;
        foreach (var f in meta.Fields)
        {
            if (f.List && f.FieldType == FormFieldType.String)
            {
                displayField = f;
                break;
            }
        }
        if (displayField != null)
        {
            var value = displayField.Property.GetValue(item)?.ToString();
            if (!string.IsNullOrWhiteSpace(value))
                return value;
        }

        // Last resort: ID
        return DataScaffold.GetIdValue(item) ?? "Unknown";
    }

    private static string GetViewTypeName(ViewType viewType)
    {
        return viewType switch
        {
            ViewType.TreeView => "Tree View",
            ViewType.OrgChart => "Org Chart",
            ViewType.Timeline => "Timeline",
            ViewType.Timetable => "Timetable",
            _ => "Table View"
        };
    }

    private static string BuildPageSizeSelector(int currentPageSize, string basePath, IDictionary<string, string?> queryParams)
    {
        var sizes = new[] { 10, 25, 50, 100 };
        var html = RentStringBuilder(512);
        try
        {
        html.Append(@"<div class=""d-flex align-items-center gap-2"">
    <label class=""form-label mb-0 small text-nowrap"">Page size:</label>
    <select class=""form-select form-select-sm bm-w-auto"" onchange=""window.location.href=this.value;"" aria-label=""Page size"">");

        foreach (var size in sizes)
        {
            var selected = size == currentPageSize ? " selected" : string.Empty;
            var url = BuildUrlWithParam(basePath, queryParams, "size", size.ToString(), excludeParams: new[] { "page" });
            html.Append($@"<option value=""{WebUtility.HtmlEncode(url)}""{selected}>{size}</option>");
        }

        html.Append("</select></div>");
        return html.ToString();
        }
        finally { ReturnStringBuilder(html); }
    }

    private static string BuildEnhancedPagination(int currentPage, int totalRecords, int pageSize, string basePath, IDictionary<string, string?> queryParams)
    {
        var maxPage = totalRecords == 0 ? 1 : (int)Math.Ceiling(totalRecords / (double)pageSize);
        var startRecord = totalRecords == 0 ? 0 : (currentPage - 1) * pageSize + 1;
        var endRecord = Math.Min(currentPage * pageSize, totalRecords);

        var html = RentStringBuilder(1024);
        try
        {
        html.Append(@"<div class=""d-flex flex-wrap align-items-center justify-content-between gap-2 mb-2"">");
        
        // Record count
        html.Append($@"<div class=""small text-muted"">Records {startRecord} to {endRecord} of {totalRecords} total</div>");
        
        // Pagination controls
        html.Append(@"<nav aria-label=""Page navigation""><ul class=""pagination pagination-sm mb-0"">");
        
        // Previous button
        if (currentPage > 1)
        {
            var prevUrl = BuildUrlWithParam(basePath, queryParams, "page", (currentPage - 1).ToString());
            html.Append($@"<li class=""page-item""><a class=""page-link"" href=""{WebUtility.HtmlEncode(prevUrl)}"" aria-label=""Previous""><i class=""bi bi-arrow-left"" aria-hidden=""true""></i></a></li>");
        }
        else
        {
            html.Append(@"<li class=""page-item disabled""><span class=""page-link"" aria-disabled=""true""><i class=""bi bi-arrow-left"" aria-hidden=""true""></i></span></li>");
        }

        // Page numbers (show current +/- 2 pages)
        var startPage = Math.Max(1, currentPage - 2);
        var endPage = Math.Min(maxPage, currentPage + 2);
        
        if (startPage > 1)
        {
            var firstUrl = BuildUrlWithParam(basePath, queryParams, "page", "1");
            html.Append($@"<li class=""page-item""><a class=""page-link"" href=""{WebUtility.HtmlEncode(firstUrl)}"">1</a></li>");
            if (startPage > 2)
            {
                html.Append(@"<li class=""page-item disabled""><span class=""page-link"">...</span></li>");
            }
        }

        for (var i = startPage; i <= endPage; i++)
        {
            if (i == currentPage)
            {
                html.Append($@"<li class=""page-item active"" aria-current=""page""><span class=""page-link"">{i}</span></li>");
            }
            else
            {
                var pageUrl = BuildUrlWithParam(basePath, queryParams, "page", i.ToString());
                html.Append($@"<li class=""page-item""><a class=""page-link"" href=""{WebUtility.HtmlEncode(pageUrl)}"">{i}</a></li>");
            }
        }

        if (endPage < maxPage)
        {
            if (endPage < maxPage - 1)
            {
                html.Append(@"<li class=""page-item disabled""><span class=""page-link"">...</span></li>");
            }
            var lastUrl = BuildUrlWithParam(basePath, queryParams, "page", maxPage.ToString());
            html.Append($@"<li class=""page-item""><a class=""page-link"" href=""{WebUtility.HtmlEncode(lastUrl)}"">{maxPage}</a></li>");
        }

        // Next button
        if (currentPage < maxPage)
        {
            var nextUrl = BuildUrlWithParam(basePath, queryParams, "page", (currentPage + 1).ToString());
            html.Append($@"<li class=""page-item""><a class=""page-link"" href=""{WebUtility.HtmlEncode(nextUrl)}"" aria-label=""Next""><i class=""bi bi-arrow-right"" aria-hidden=""true""></i></a></li>");
        }
        else
        {
            html.Append(@"<li class=""page-item disabled""><span class=""page-link"" aria-disabled=""true""><i class=""bi bi-arrow-right"" aria-hidden=""true""></i></span></li>");
        }

        html.Append("</ul></nav></div>");
        return html.ToString();
        }
        finally { ReturnStringBuilder(html); }
    }

    private static string BuildUrlWithParam(string basePath, IDictionary<string, string?> queryParams, string key, string value, string[]? excludeParams = null)
    {
        var parts = new List<string>();
        var exclude = new HashSet<string>((excludeParams?.Length ?? 0) + 1, StringComparer.OrdinalIgnoreCase);
        if (excludeParams != null)
        {
            foreach (var p in excludeParams)
                exclude.Add(p);
        }
        exclude.Add(key); // Always exclude the key we're setting

        foreach (var pair in queryParams)
        {
            if (exclude.Contains(pair.Key))
                continue;

            var pairValue = pair.Value ?? string.Empty;
            if (!string.IsNullOrWhiteSpace(pairValue))
            {
                parts.Add($"{WebUtility.UrlEncode(pair.Key)}={WebUtility.UrlEncode(pairValue)}");
            }
        }

        if (!string.IsNullOrWhiteSpace(value))
        {
            parts.Add($"{WebUtility.UrlEncode(key)}={WebUtility.UrlEncode(value)}");
        }

        var queryString = parts.Count > 0 ? "?" + string.Join("&", parts) : string.Empty;
        return $"{basePath}{queryString}";
    }

    private static string BuildSortableColumnHeaders(DataEntityMetadata metadata, string basePath, IDictionary<string, string?> queryParams, bool includeActions, bool includeBulkSelection = false)
    {
        var currentSort = queryParams.TryGetValue("sort", out var sortValue) ? sortValue : null;
        var currentDir = queryParams.TryGetValue("dir", out var dirValue) ? dirValue : "asc";
        
        var html = RentStringBuilder(1024);
        try
        {
        html.Append("<thead><tr>");

        if (includeBulkSelection)
        {
            html.Append(@"<th scope=""col"" class=""bm-col-check""><input type=""checkbox"" data-bulk-select-all aria-label=""Select all"" /></th>");
        }

        if (includeActions)
        {
            html.Append(@"<th scope=""col"">Actions</th>");
        }

        foreach (var field in metadata.ListFields)
        {
            var isSorted = string.Equals(field.Name, currentSort, StringComparison.OrdinalIgnoreCase);
            var nextDir = isSorted && string.Equals(currentDir, "asc", StringComparison.OrdinalIgnoreCase) ? "desc" : "asc";
            
            // Build sort URL - need to update both sort and dir parameters
            var parts = new List<string>();
            foreach (var pair in queryParams)
            {
                if (string.Equals(pair.Key, "sort", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(pair.Key, "dir", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(pair.Key, "page", StringComparison.OrdinalIgnoreCase))
                    continue;

                var pairValue = pair.Value ?? string.Empty;
                if (!string.IsNullOrWhiteSpace(pairValue))
                {
                    parts.Add($"{WebUtility.UrlEncode(pair.Key)}={WebUtility.UrlEncode(pairValue)}");
                }
            }
            parts.Add($"sort={WebUtility.UrlEncode(field.Name)}");
            parts.Add($"dir={nextDir}");
            var queryString = parts.Count > 0 ? "?" + string.Join("&", parts) : string.Empty;
            var sortUrl = $"{basePath}{queryString}";
            
            var sortIcon = string.Empty;
            if (isSorted)
            {
                sortIcon = string.Equals(currentDir, "desc", StringComparison.OrdinalIgnoreCase)
                    ? @" <i class=""bi bi-arrow-down"" aria-hidden=""true""></i>"
                    : @" <i class=""bi bi-arrow-up"" aria-hidden=""true""></i>";
            }
            else
            {
                sortIcon = @" <i class=""bi bi-arrow-down-up text-muted bm-sort-icon-dim"" aria-hidden=""true""></i>";
            }

            html.Append($@"<th scope=""col""><a href=""{WebUtility.HtmlEncode(sortUrl)}"" class=""text-decoration-none text-reset"" title=""Sort by {WebUtility.HtmlEncode(field.Label)}"">{WebUtility.HtmlEncode(field.Label)}{sortIcon}</a></th>");
        }

        html.Append("</tr></thead>");
        return html.ToString();
        }
        finally { ReturnStringBuilder(html); }
    }

    private static string BuildTableWithSortableHeaders(DataEntityMetadata metadata, IReadOnlyList<string[]> rows, string basePath, IDictionary<string, string?> queryParams, bool includeActions, bool includeBulkSelection = false)
    {
        var html = RentStringBuilder(4096);
        try
        {
        html.Append(@"<table class=""table table-striped table-sm align-middle mb-0 bm-table"">");
        
        // Add sortable headers
        html.Append(BuildSortableColumnHeaders(metadata, basePath, queryParams, includeActions, includeBulkSelection));
        
        // Add body rows
        html.Append("<tbody>");
        
        var columnTitles = new List<string>();
        if (includeBulkSelection)
            columnTitles.Add("");
        if (includeActions)
            columnTitles.Add("Actions");
        foreach (var f in metadata.ListFields)
            columnTitles.Add(f.Label);
        
        foreach (var row in rows)
        {
            html.Append("<tr>");
            for (int i = 0; i < row.Length; i++)
            {
                var label = i < columnTitles.Count ? columnTitles[i] : string.Empty;
                html.Append($@"<td data-label=""{WebUtility.HtmlEncode(label)}"">{row[i]}</td>");
            }
            html.Append("</tr>");
        }
        
        html.Append("</tbody></table>");
        return html.ToString();
        }
        finally { ReturnStringBuilder(html); }
    }

    private static string BuildBulkActionsBar(string typeSlug, string returnUrl, long totalCount, string csrfToken)
    {
        var sb = new StringBuilder(1024);
        sb.Append($"<div data-bulk-container data-entity-slug=\"{WebUtility.HtmlEncode(typeSlug)}\" data-return-url=\"{WebUtility.HtmlEncode(returnUrl)}\">");
        sb.Append("<div data-bulk-actions-bar class=\"alert alert-info d-flex flex-wrap align-items-center justify-content-between gap-2 mb-2 d-none\" role=\"status\">");
        sb.Append("<div class=\"d-flex align-items-center gap-2\">");
        sb.Append("<strong><span data-selected-count>0</span> of <span data-total-count>");
        sb.Append(totalCount);
        sb.Append("</span> selected</strong>");
        sb.Append("<button type=\"button\" class=\"btn btn-sm btn-outline-secondary\" data-bulk-clear aria-label=\"Clear selection\"><i class=\"bi bi-x-lg\" aria-hidden=\"true\"></i> Clear</button>");
        sb.Append("</div>");
        sb.Append("<div class=\"btn-group btn-group-sm\" role=\"group\" aria-label=\"Bulk actions\">");
        sb.Append("<button type=\"button\" class=\"btn btn-danger\" data-bulk-action=\"delete\" title=\"Delete selected\" aria-label=\"Delete selected\"><i class=\"bi bi-trash\" aria-hidden=\"true\"></i> Delete</button>");
        sb.Append("<button type=\"button\" class=\"btn btn-success\" data-bulk-action=\"export-csv\" title=\"Export to CSV\" aria-label=\"Export to CSV\"><i class=\"bi bi-file-earmark-spreadsheet\" aria-hidden=\"true\"></i> CSV</button>");
        sb.Append("<button type=\"button\" class=\"btn btn-primary\" data-bulk-action=\"export-json\" title=\"Export to JSON\" aria-label=\"Export to JSON\"><i class=\"bi bi-filetype-json\" aria-hidden=\"true\"></i> JSON</button>");
        sb.Append("<button type=\"button\" class=\"btn btn-info\" data-bulk-action=\"export-html\" title=\"Export to HTML\" aria-label=\"Export to HTML\"><i class=\"bi bi-filetype-html\" aria-hidden=\"true\"></i> HTML</button>");
        sb.Append("</div>");
        sb.Append("</div>");
        sb.Append($"<input type=\"hidden\" name=\"csrf_token\" value=\"{WebUtility.HtmlEncode(csrfToken)}\" />");
        sb.Append("</div>");
        return sb.ToString();
    }

    /// <summary>
    /// Build form fields with per-field validation error messages attached.
    /// </summary>
    private static List<FormField> BuildFormFieldsWithErrors(
        DataEntityMetadata meta, object instance, bool forCreate, ValidationResult validationResult, string? cspNonce = null)
    {
        var fields = new List<FormField>(DataScaffold.BuildFormFields(meta, instance, forCreate, cspNonce: cspNonce));
        if (!validationResult.IsValid)
        {
            for (int i = 0; i < fields.Count; i++)
            {
                if (validationResult.FieldErrors.TryGetValue(fields[i].Name, out var fieldErrors) && fieldErrors.Count > 0)
                {
                    fields[i] = fields[i] with { ValidationError = string.Join("; ", fieldErrors) };
                }
            }
        }
        return fields;
    }

    private static string BuildCommandButtonsHtml(DataEntityMetadata meta, string typeSlug, string id, string csrfToken)
    {
        if (meta.Commands.Count == 0) return string.Empty;
        var sb = new StringBuilder(512);
        var safeId = WebUtility.UrlEncode(id);
        var safeToken = WebUtility.HtmlEncode(csrfToken);
        foreach (var cmd in meta.Commands)
        {
            var btnClass = cmd.Destructive ? "btn-outline-danger" : "btn-outline-secondary";
            var icon = string.IsNullOrEmpty(cmd.Icon) ? "" : $"<i class=\"bi {WebUtility.HtmlEncode(cmd.Icon)}\" aria-hidden=\"true\"></i> ";
            var confirm = string.IsNullOrEmpty(cmd.ConfirmMessage) ? "" : $" data-confirm=\"{WebUtility.HtmlEncode(cmd.ConfirmMessage)}\"";
            sb.Append($"<button class=\"btn btn-sm {btnClass} ms-2\" data-command-url=\"/api/{typeSlug}/{safeId}/_command/{WebUtility.UrlEncode(cmd.Name)}\" data-csrf-token=\"{safeToken}\"{confirm}>{icon}{WebUtility.HtmlEncode(cmd.Label)}</button>");
        }
        return sb.ToString();
    }

    public async ValueTask DataCommandHandler(BmwContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        var id = GetRouteValue(context, "id");
        var commandName = GetRouteValue(context, "command");
        if (meta == null || string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(commandName))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await WriteJsonResponseAsync(context, new { success = false, message = errorMessage ?? "Not found." });
            return;
        }

        RemoteCommandMetadata? cmd = null;
        foreach (var c in meta.Commands)
        {
            if (string.Equals(c.Name, commandName, StringComparison.OrdinalIgnoreCase))
            {
                cmd = c;
                break;
            }
        }
        if (cmd == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await WriteJsonResponseAsync(context, new { success = false, message = $"Command '{commandName}' not found." });
            return;
        }

        // Permission check
        if (!cmd.OverrideEntityPermissions)
        {
            if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await WriteJsonResponseAsync(context, new { success = false, message = "Access denied." });
                return;
            }
        }

        if (!await UserAuth.HasValidApiKeyAsync(context, context.RequestAborted).ConfigureAwait(false) &&
            (!ValidateApiCsrfHeader(context) || !CsrfProtection.ValidateApiToken(context)))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await WriteJsonResponseAsync(context, new { success = false, message = "CSRF validation failed." });
            return;
        }

        if (!string.IsNullOrEmpty(cmd.Permission))
        {
            var user = await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            bool hasPermission = false;
            if (user != null)
            {
                foreach (var perm in user.Permissions)
                {
                    if (string.Equals(perm, cmd.Permission, StringComparison.OrdinalIgnoreCase))
                    {
                        hasPermission = true;
                        break;
                    }
                }
            }
            if (user == null || !hasPermission)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await WriteJsonResponseAsync(context, new { success = false, message = "Insufficient permissions." });
                return;
            }
        }

        var instance = await DataScaffold.LoadAsync(meta, uint.Parse(id));
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await WriteJsonResponseAsync(context, new { success = false, message = "Item not found." });
            return;
        }

        try
        {
            var userName = (await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false))?.UserName ?? "system";
            
            RemoteCommandResult result;
            var returnType = cmd.Method.ReturnType;
            if (returnType == typeof(RemoteCommandResult))
            {
                result = (RemoteCommandResult)cmd.Method.Invoke(instance, null)!;
            }
            else if (returnType == typeof(Task<RemoteCommandResult>))
            {
                result = await (Task<RemoteCommandResult>)cmd.Method.Invoke(instance, null)!;
            }
            else
            {
                result = await (ValueTask<RemoteCommandResult>)cmd.Method.Invoke(instance, null)!;
            }

            // Save the entity in case the command modified it
            await DataScaffold.ApplyComputedFieldsAsync(meta, (BaseDataObject)instance, ComputedTrigger.OnUpdate, context.RequestAborted).ConfigureAwait(false);
            DataScaffold.ApplyCalculatedFields(meta, (BaseDataObject)instance);
            await DataScaffold.SaveAsync(meta, instance);

            // Audit the remote command execution
            if (instance is BaseDataObject baseDataObject)
            {
                await _auditService.AuditRemoteCommandAsync(baseDataObject, commandName, userName, null, result, context.RequestAborted).ConfigureAwait(false);
            }

            context.Response.StatusCode = result.Success ? StatusCodes.Status200OK : StatusCodes.Status422UnprocessableEntity;
            var entityData = result.Success ? BuildApiModel(meta, instance) : null;
            await WriteJsonResponseAsync(context, new { success = result.Success, message = result.Message, redirectUrl = result.RedirectUrl, data = entityData });
        }
        catch (Exception ex)
        {
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await WriteJsonResponseAsync(context, new { success = false, message = $"Command failed: {ex.InnerException?.Message ?? ex.Message}" });
        }
    }

    // ── Data & Index Sizing ───────────────────────────────────────────────────

    public async ValueTask DataSizingHandler(BmwContext context)
    {
        await BuildPageHandler(ctx =>
        {
            ctx.SetStringValue("title", "Data & Index Sizing");

            var dataRoot = _dataRootFolder;
            var walDir   = Path.Combine(dataRoot, "wal");
            var html     = new StringBuilder(2048);

            // ── WAL store ──────────────────────────────────────────────────
            long walSegBytes = 0, walSnapshotBytes = 0, walIdMapBytes = 0;
            int  walSegCount = 0;
            var  idMapSizes  = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);

            if (Directory.Exists(walDir))
            {
                foreach (var fi in new DirectoryInfo(walDir).EnumerateFiles())
                {
                    var  name = fi.Name;
                    long size = fi.Length;

                    if (name.StartsWith("wal_seg_", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".log", StringComparison.OrdinalIgnoreCase))
                    {
                        walSegBytes += size;
                        walSegCount++;
                    }
                    else if (string.Equals(name, "snapshot.bin", StringComparison.OrdinalIgnoreCase))
                    {
                        walSnapshotBytes = size;
                    }
                    else if (name.EndsWith("_idmap.bin", StringComparison.OrdinalIgnoreCase))
                    {
                        walIdMapBytes += size;
                        var typeName = name[..^"_idmap.bin".Length];
                        idMapSizes[typeName] = size;
                    }
                }
            }

            long walTotalBytes = walSegBytes + walSnapshotBytes + walIdMapBytes;

            // ── Per-entity ─────────────────────────────────────────────────
            var entities         = DataScaffold.Entities;
            long totalSchemaBytes = 0;
            long totalIndexBytes  = 0;

            var rows = new List<(string Name, string Slug, long SchemaBytes, long IdMapBytes, long IndexBytes)>();

            foreach (var entity in entities)
            {
                var typeName     = entity.Type?.Name ?? entity.Name;
                var entityFolder = Path.Combine(dataRoot, typeName);

                // Schema / direct files (top-level only — no subfolders)
                long schemaBytes = 0;
                if (Directory.Exists(entityFolder))
                {
                    foreach (var fi in new DirectoryInfo(entityFolder).EnumerateFiles("*", SearchOption.TopDirectoryOnly))
                        schemaBytes += fi.Length;
                }

                idMapSizes.TryGetValue(typeName, out long idMapBytes);

                // Index / paged files — stored under <dataRoot>/Index/<entity> and <dataRoot>/Paged/<entity>
                long indexBytes  = 0;
                foreach (var sub in new[] { "Paged", "Index" })
                {
                    var subDir = Path.Combine(dataRoot, sub, typeName);
                    if (Directory.Exists(subDir))
                    {
                        foreach (var fi in new DirectoryInfo(subDir).EnumerateFiles("*", SearchOption.AllDirectories))
                            indexBytes += fi.Length;
                    }
                }

                totalSchemaBytes += schemaBytes;
                totalIndexBytes  += indexBytes;

                rows.Add((entity.Name, entity.Slug, schemaBytes, idMapBytes, indexBytes));
            }

            // ── Summary cards ──────────────────────────────────────────────
            long grandTotal = walTotalBytes + totalSchemaBytes + totalIndexBytes;

            html.Append("<div class=\"row g-3 mb-4\">");
            html.Append(DataSizeCard("WAL Segments",  walSegBytes,      $"{walSegCount} file{(walSegCount == 1 ? "" : "s")}",        "bi-journals"));
            html.Append(DataSizeCard("WAL Snapshot",  walSnapshotBytes, "compact checkpoint",                                        "bi-bookmark-check"));
            html.Append(DataSizeCard("ID Maps",       walIdMapBytes,    $"{idMapSizes.Count} table{(idMapSizes.Count == 1 ? "" : "s")}", "bi-key"));
            html.Append(DataSizeCard("Index Files",   totalIndexBytes,  "in-memory index store on disk",                             "bi-lightning-charge"));
            html.Append(DataSizeCard("Schema Files",  totalSchemaBytes, "per-entity versioned schemas",                              "bi-file-binary"));
            html.Append(DataSizeCard("Grand Total",   grandTotal,       "all data on disk",                                          "bi-hdd-stack"));
            html.Append("</div>");

            // ── Per-entity table ───────────────────────────────────────────
            html.Append("<h5 class=\"mb-3\">Per-Table Breakdown</h5>");
            html.Append("<div class=\"table-responsive\">");
            html.Append("<table class=\"table table-sm table-striped table-hover align-middle\">");
            html.Append("<thead class=\"table-dark\"><tr>");
            html.Append("<th>Table</th>");
            html.Append("<th class=\"text-end\">Schema Files</th>");
            html.Append("<th class=\"text-end\">ID Map</th>");
            html.Append("<th class=\"text-end\">Index Files</th>");
            html.Append("<th class=\"text-end\">Table Total</th>");
            html.Append("</tr></thead><tbody>");

            var sortedRows = new List<(string Name, string Slug, long SchemaBytes, long IdMapBytes, long IndexBytes)>(rows);
            sortedRows.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
            foreach (var (name, slug, schemaBytes, idMapBytes, indexBytes) in sortedRows)
            {
                long tableTotal = schemaBytes + idMapBytes + indexBytes;
                html.Append("<tr>");
                html.Append($"<td><a href=\"/ssr/admin/data/{WebUtility.HtmlEncode(slug)}\">{WebUtility.HtmlEncode(name)}</a></td>");
                html.Append($"<td class=\"text-end\">{FormatSizeBytes(schemaBytes)}</td>");
                html.Append($"<td class=\"text-end\">{FormatSizeBytes(idMapBytes)}</td>");
                html.Append($"<td class=\"text-end\">{FormatSizeBytes(indexBytes)}</td>");
                html.Append($"<td class=\"text-end fw-semibold\">{FormatSizeBytes(tableTotal)}</td>");
                html.Append("</tr>");
            }

            // Totals row
            long perTableTotal = totalSchemaBytes + walIdMapBytes + totalIndexBytes;
            html.Append("<tr class=\"table-secondary fw-bold\">");
            html.Append($"<td>TOTAL — {rows.Count} table{(rows.Count == 1 ? "" : "s")}</td>");
            html.Append($"<td class=\"text-end\">{FormatSizeBytes(totalSchemaBytes)}</td>");
            html.Append($"<td class=\"text-end\">{FormatSizeBytes(walIdMapBytes)}</td>");
            html.Append($"<td class=\"text-end\">{FormatSizeBytes(totalIndexBytes)}</td>");
            html.Append($"<td class=\"text-end\">{FormatSizeBytes(perTableTotal)}</td>");
            html.Append("</tr>");

            html.Append("</tbody></table></div>");
            html.Append($"<p class=\"text-muted small mt-2\">WAL store (segments + snapshot + id maps): <strong>{FormatSizeBytes(walTotalBytes)}</strong> in {walSegCount} segment{(walSegCount == 1 ? "" : "s")}. " +
                        $"Sizes read from <code>{WebUtility.HtmlEncode(dataRoot)}</code>.</p>");

            ctx.SetStringValue("html_message", html.ToString());
        })(context);
    }

    private static string DataSizeCard(string label, long bytes, string subtitle, string icon)
    {
        return $"<div class=\"col-12 col-sm-6 col-xl-4\">" +
               $"<div class=\"card h-100\">" +
               $"<div class=\"card-body d-flex align-items-center gap-3\">" +
               $"<i class=\"bi {WebUtility.HtmlEncode(icon)} fs-2 text-secondary\"></i>" +
               $"<div><div class=\"fs-5 fw-semibold\">{FormatSizeBytes(bytes)}</div>" +
               $"<div class=\"fw-semibold\">{WebUtility.HtmlEncode(label)}</div>" +
               $"<div class=\"text-muted small\">{WebUtility.HtmlEncode(subtitle)}</div>" +
               $"</div></div></div></div>";
    }

    // ──────────────────────────────────────────────────────────────
    // Background job status endpoint (Azure async-request-reply)
    // ──────────────────────────────────────────────────────────────

    /// <summary>
    /// GET /api/jobs/{jobId}
    /// Returns the status of a background job following the Azure async-request-reply pattern:
    ///   - 202 Accepted (+ Retry-After header) while the job is still running.
    ///   - 200 OK (+ Location header when a resultUrl was provided) when the job completes.
    ///   - 404 if the job ID is unknown or has been pruned.
    /// </summary>
    public async ValueTask JobStatusHandler(BmwContext context)
    {
        var jobId = GetRouteValue(context, "jobId") ?? string.Empty;

        if (string.IsNullOrEmpty(jobId) ||
            !BackgroundJobService.Instance.TryGetJob(jobId, out var snapshot) ||
            snapshot == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"Job not found.\"}").ConfigureAwait(false);
            return;
        }

        var isComplete = snapshot.Status is BackgroundJobStatus.Succeeded or BackgroundJobStatus.Failed;

        context.Response.StatusCode = isComplete
            ? StatusCodes.Status200OK
            : StatusCodes.Status202Accepted;

        if (!isComplete)
            context.Response.Headers["Retry-After"] = "2";

        if (snapshot.Status == BackgroundJobStatus.Succeeded &&
            !string.IsNullOrEmpty(snapshot.ResultUrl))
        {
            context.Response.Headers["Location"] = snapshot.ResultUrl;
        }

        context.Response.ContentType = "application/json";

        var statusStr = snapshot.Status switch
        {
            BackgroundJobStatus.Queued    => "queued",
            BackgroundJobStatus.Running   => "running",
            BackgroundJobStatus.Succeeded => "succeeded",
            BackgroundJobStatus.Failed    => "failed",
            _                             => "unknown"
        };

        var json = JsonSerializer.Serialize(new
        {
            jobId            = snapshot.JobId,
            operationName    = snapshot.OperationName,
            status           = statusStr,
            percentComplete  = snapshot.PercentComplete,
            description      = snapshot.Description,
            startedAt        = snapshot.StartedAt.ToString("O"),
            completedAt      = snapshot.CompletedAt?.ToString("O"),
            error            = snapshot.Error,
            resultUrl        = snapshot.ResultUrl
        });

        await context.Response.WriteAsync(json).ConfigureAwait(false);
    }

    /// <summary>
    /// GET /api/jobs
    /// Returns all tracked background jobs (active and recently completed) as a JSON array.
    /// </summary>
    public async ValueTask JobsListHandler(BmwContext context)
    {
        var jobs = BackgroundJobService.Instance.GetAllJobs();

        var jobsList = new List<JobStatusSnapshot>(jobs);
        jobsList.Sort((a, b) => b.StartedAt.CompareTo(a.StartedAt));
        var items = new object[jobsList.Count];
        for (int ji = 0; ji < jobsList.Count; ji++)
        {
            var snapshot = jobsList[ji];
            items[ji] = new
            {
                jobId           = snapshot.JobId,
                operationName   = snapshot.OperationName,
                status          = snapshot.Status switch
                {
                    BackgroundJobStatus.Queued    => "queued",
                    BackgroundJobStatus.Running   => "running",
                    BackgroundJobStatus.Succeeded => "succeeded",
                    BackgroundJobStatus.Failed    => "failed",
                    _                             => "unknown"
                },
                percentComplete = snapshot.PercentComplete,
                description     = snapshot.Description,
                startedAt       = snapshot.StartedAt.ToString("O"),
                completedAt     = snapshot.CompletedAt?.ToString("O"),
                error           = snapshot.Error,
                resultUrl       = snapshot.ResultUrl
            };
        }

        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(items)).ConfigureAwait(false);
    }

    /// <summary>
    /// DELETE /api/jobs/{jobId}
    /// Cancels a running or queued background job. Returns 200 OK if cancellation was
    /// requested, 404 if the job is unknown, or 409 Conflict if it has already completed.
    /// Requires admin permission.
    /// </summary>
    public async ValueTask CancelJobHandler(BmwContext context)
    {
        var jobId = GetRouteValue(context, "jobId") ?? string.Empty;

        if (string.IsNullOrEmpty(jobId))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"Missing job ID.\"}").ConfigureAwait(false);
            return;
        }

        if (!BackgroundJobService.Instance.TryGetJob(jobId, out var snapshot) || snapshot == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"Job not found.\"}").ConfigureAwait(false);
            return;
        }

        if (!BackgroundJobService.Instance.CancelJob(jobId))
        {
            context.Response.StatusCode = StatusCodes.Status409Conflict;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"Job has already completed and cannot be cancelled.\"}").ConfigureAwait(false);
            return;
        }

        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync("{\"status\":\"cancellation requested\"}").ConfigureAwait(false);
    }
}
