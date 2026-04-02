using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using BareMetalWeb.ControlPlane;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Delegates;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Models;
using BareMetalWeb.Runtime;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

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
    internal static ControlPlaneClient? WebStoreClient { get; set; }
    private const string MfaChallengeCookieName = "mfa_challenge_id";
    private static readonly TimeSpan MfaPendingLifetime = TimeSpan.FromMinutes(5);
    private const int MfaPendingMaxFailures = 5;
    private const int MfaChallengeMaxFailures = 6;
    private static readonly TimeSpan MfaAttemptWindow = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MfaBaseBlockDuration = TimeSpan.FromSeconds(10);
    private static readonly ConcurrentDictionary<string, AttemptTracker> MfaAttempts = new(StringComparer.Ordinal);
    private static DateTime _lastMfaScavenge = DateTime.UtcNow;
    private const int LoginIpMaxAttempts = 10;
    private const int MfaMaxTrackedKeys = 100_000;
    private const int LoginUserMaxAttempts = 5;
    private const int RegisterIpMaxAttempts = 3;
    private const int SsoCallbackIpMaxAttempts = 10;
    private static readonly TimeSpan DataQueryTimeout = TimeSpan.FromSeconds(30);
    private const string ManagementRegistrationEnabledSettingId = "management.registration.enabled";
    private const string ManagementRegistrationCallbackUrlSettingId = "management.registration.callbackUrl";
    private const string ManagementRegistrationPrincipalNameSettingId = "management.registration.principalName";
    private const string ManagementRegistrationTenantIdSettingId = "management.registration.tenantId";
    private const string ManagementRegistrationClientIdSettingId = "management.registration.clientId";
    private const string ManagementRegistrationLastStatusSettingId = "management.registration.lastStatus";
    private const string ManagementRegistrationLastAttemptUtcSettingId = "management.registration.lastAttemptUtc";
    private const string DefaultManagementPrincipalName = "bmw-deployment-agent";
    private static readonly HttpClient SetupRegistrationHttp = new(new SocketsHttpHandler
    {
        MaxConnectionsPerServer = 2,
        PooledConnectionLifetime = TimeSpan.FromMinutes(3),
        PooledConnectionIdleTimeout = TimeSpan.FromMinutes(1),
        ConnectTimeout = TimeSpan.FromSeconds(5),
    })
    {
        Timeout = TimeSpan.FromSeconds(10),
    };

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

    // ────── ThreadStatic pools for hot-path collection types ──────

    [ThreadStatic] private static List<string>? t_stringList;
    [ThreadStatic] private static Dictionary<string, object?>? t_objectDict;
    [ThreadStatic] private static List<Dictionary<string, object?>>? t_dictList;
    [ThreadStatic] private static List<QueryClause>? t_queryClauseList;

    private static List<string> RentStringList(int capacity = 16)
    {
        var list = t_stringList;
        if (list != null) { t_stringList = null; list.Clear(); return list; }
        return new List<string>(capacity);
    }
    private static void ReturnStringList(List<string> list)
    {
        if (list.Count < 1024) { list.Clear(); t_stringList = list; }
    }

    private static Dictionary<string, object?> RentObjectDictionary(int capacity = 16)
    {
        var dict = t_objectDict;
        if (dict != null) { t_objectDict = null; dict.Clear(); return dict; }
        return new Dictionary<string, object?>(capacity, StringComparer.OrdinalIgnoreCase);
    }

    private static List<Dictionary<string, object?>> RentDictList(int capacity = 16)
    {
        var list = t_dictList;
        if (list != null) { t_dictList = null; list.Clear(); return list; }
        return new List<Dictionary<string, object?>>(capacity);
    }
    private static void ReturnDictList(List<Dictionary<string, object?>> list)
    {
        if (list.Count < 1024) { list.Clear(); t_dictList = list; }
    }

    private static List<QueryClause> RentQueryClauseList(int capacity = 8)
    {
        var list = t_queryClauseList;
        if (list != null) { t_queryClauseList = null; list.Clear(); return list; }
        return new List<QueryClause>(capacity);
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
        => _renderer.RenderPage(context);

    public RouteHandlerDelegate BuildPageHandler(Action<BmwContext> configure)
    {
        if (configure == null) throw new ArgumentNullException(nameof(configure));
        return async context =>
        {
            configure(context);
            await _renderer.RenderPage(context);
        };
    }

    public RouteHandlerDelegate BuildPageHandler(Func<BmwContext, ValueTask> configureAsync)
    {
        if (configureAsync == null) throw new ArgumentNullException(nameof(configureAsync));
        return async context =>
        {
            await configureAsync(context);
            await _renderer.RenderPage(context);
        };
    }

    public RouteHandlerDelegate BuildPageHandler(Func<BmwContext, ValueTask<bool>> configureAsync, bool renderWhenTrue = true)
    {
        if (configureAsync == null) throw new ArgumentNullException(nameof(configureAsync));
        return async context =>
        {
            var shouldRender = await configureAsync(context);
            if (shouldRender == renderWhenTrue)
                await _renderer.RenderPage(context);
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
            _logger?.LogInfo($"login|rate-limit|ip={remoteIp}|retry={FormatThrottleMessage(ipRetry)}");
            RenderLoginForm(context, FormatThrottleMessage(ipRetry), string.Empty);
            await _renderer.RenderPage(context);
            return;
        }

        // Read form data; use empty collection for non-form requests so CSRF check always runs
        var form = context.HttpRequest.HasFormContentType
            ? await context.HttpRequest.ReadFormAsync()
            : FormCollection.Empty;

        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderLoginForm(context, "Invalid security token. Please try again.", string.Empty);
            await _renderer.RenderPage(context);
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
            await _renderer.RenderPage(context);
            return;
        }

        if (password.Length > 1024)
        {
            RenderLoginForm(context, "Password exceeds maximum allowed length.", identifier);
            await _renderer.RenderPage(context);
            return;
        }

        BaseDataObject? user = await UserAuthHelper.FindUserByEmailOrUserNameAsync(identifier, context.RequestAborted).ConfigureAwait(false);
        if (user == null || !UserAuth.IsActive(user))
        {
            // SECURITY: Perform dummy hash to equalize timing regardless of user existence (see #1219)
            PasswordHasher.Verify(password, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AAAAAAAAAAAAAAAAAAAAAA==", 100_000);
            RegisterFailure(ipKey, LoginIpMaxAttempts);
            RenderLoginForm(context, "Invalid credentials.", identifier);
            await _renderer.RenderPage(context);
            return;
        }

        // Per-user rate limit — after user is found, before password check
        var userKey = BuildMfaAttemptKey("login:user", user.Key.ToString());
        if (IsThrottled(userKey, LoginUserMaxAttempts, out var userRetry))
        {
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            if (userRetry.HasValue)
                context.Response.Headers.RetryAfter = ((int)Math.Ceiling(userRetry.Value.TotalSeconds)).ToString();
            _logger?.LogInfo($"login|rate-limit|user={identifier}|ip={remoteIp}|retry={FormatThrottleMessage(userRetry)}");
            RenderLoginForm(context, FormatThrottleMessage(userRetry), identifier);
            await _renderer.RenderPage(context);
            return;
        }

        if (UserAuth.IsLockedOut(user))
        {
            RenderLoginForm(context, "Account is temporarily locked. Try again later.", identifier);
            await _renderer.RenderPage(context);
            return;
        }

        if (!UserAuth.VerifyPassword(user, password))
        {
            RegisterFailure(ipKey, LoginIpMaxAttempts);
            RegisterFailure(userKey, LoginUserMaxAttempts);
            UserAuth.RegisterFailedLogin(user);
            await UserAuth.SaveUserAsync(user, context.RequestAborted);
            RenderLoginForm(context, "Invalid credentials.", identifier);
            await _renderer.RenderPage(context);
            return;
        }

        if (UserAuth.IsMfaEnabled(user))
        {
            if (!TryGetActiveSecret(user, out _, out var upgraded))
            {
                RenderLoginForm(context, "MFA is misconfigured. Contact support.", identifier);
                await _renderer.RenderPage(context);
                return;
            }

            if (upgraded)
                await UserAuth.SaveUserAsync(user, context.RequestAborted);

            var userName = UserAuth.GetUserName(user) ?? user.Key.ToString();
            var challenge = new MfaChallenge
            {
                UserId = user.Key.ToString(),
                RememberMe = rememberMe,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(5),
                CreatedBy = userName,
                UpdatedBy = userName
            };
            await DataStoreProvider.Current.SaveAsync(challenge.EntityTypeName, challenge);
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
        UserAuth.RegisterSuccessfulLogin(user);
        await UserAuth.SaveUserAsync(user, context.RequestAborted);
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
            await _renderer.RenderPage(context);
            return;
        }

        var code = NormalizeOtpCode(form["code"].ToString());
        if (code == null)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            RenderMfaChallengeForm(context, "Please enter your authentication code.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!uint.TryParse(challenge.UserId, out var parsedUserId))
        {
            RenderMfaChallengeForm(context, "Invalid user account.");
            await _renderer.RenderPage(context);
            return;
        }

        BaseDataObject? user = await UserAuth.LoadUserAsync(parsedUserId, context.RequestAborted).ConfigureAwait(false);
        if (user == null || !UserAuth.IsActive(user) || !UserAuth.IsMfaEnabled(user) || !TryGetActiveSecret(user, out var activeSecret, out var upgraded))
        {
            RenderMfaChallengeForm(context, "MFA is not available for this account.");
            await _renderer.RenderPage(context);
            return;
        }

        if (upgraded)
            await UserAuth.SaveUserAsync(user, context.RequestAborted);

        var remoteIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (IsThrottled(BuildMfaAttemptKey("challenge:user", user.Key.ToString()), MfaChallengeMaxFailures, out var retryAfter)
            || IsThrottled(BuildMfaAttemptKey("challenge:ip", remoteIp), MfaChallengeMaxFailures, out retryAfter))
        {
            RenderMfaChallengeForm(context, FormatThrottleMessage(retryAfter));
            await _renderer.RenderPage(context);
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
                await _renderer.RenderPage(context);
                return;
            }

            if (matchedStep <= UserAuth.GetMfaLastVerifiedStep(user))
            {
                RenderMfaChallengeForm(context, "Authentication code already used. Please wait for a new code.");
                await _renderer.RenderPage(context);
                return;
            }

            UserAuth.SetMfaLastVerifiedStep(user, matchedStep);
            UserAuth.RegisterSuccessfulLogin(user);
            await UserAuth.SaveUserAsync(user, context.RequestAborted);

            RegisterSuccess(BuildMfaAttemptKey("challenge:user", user.Key.ToString()));
            RegisterSuccess(BuildMfaAttemptKey("challenge:ip", remoteIp));

            challenge.IsUsed = true;
            await DataStoreProvider.Current.SaveAsync(challenge.EntityTypeName, challenge);
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
            await _renderer.RenderPage(context);
            return;
        }

        // Rate limiting — same pattern as login
        var remoteIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var regIpKey = BuildMfaAttemptKey("register:ip", remoteIp);
        if (IsThrottled(regIpKey, RegisterIpMaxAttempts, out var regRetry))
        {
            context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
            if (regRetry.HasValue)
                context.Response.Headers.RetryAfter = ((int)Math.Ceiling(regRetry.Value.TotalSeconds)).ToString();
            _logger?.LogInfo($"register|rate-limit|ip={remoteIp}|retry={FormatThrottleMessage(regRetry)}");
            RenderRegisterForm(context, FormatThrottleMessage(regRetry), null, null, null);
            await _renderer.RenderPage(context);
            return;
        }

        if (!context.HttpRequest.HasFormContentType)
        {
            RenderRegisterForm(context, "Invalid registration request.", null, null, null);
            await _renderer.RenderPage(context);
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
            await _renderer.RenderPage(context);
            return;
        }

        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            RenderRegisterForm(context, "Please complete all required fields.", userName, displayName, email);
            await _renderer.RenderPage(context);
            return;
        }

        if (password.Length > 1024)
        {
            RenderRegisterForm(context, "Password exceeds maximum allowed length.", userName, displayName, email);
            await _renderer.RenderPage(context);
            return;
        }

        if (!string.Equals(password, confirm, StringComparison.Ordinal))
        {
            RenderRegisterForm(context, "Passwords do not match.", userName, displayName, email);
            await _renderer.RenderPage(context);
            return;
        }

        if (await UserAuthHelper.FindUserByEmailAsync(email, context.RequestAborted).ConfigureAwait(false) != null)
        {
            // SECURITY: Generic message to prevent account enumeration (see #1219)
            RenderRegisterForm(context, "Registration could not be completed. Please try again or use a different email.", userName, displayName, email);
            await _renderer.RenderPage(context);
            return;
        }

        if (await UserAuthHelper.FindUserByUserNameAsync(userName, context.RequestAborted).ConfigureAwait(false) != null)
        {
            // SECURITY: Generic message to prevent account enumeration (see #1219)
            RenderRegisterForm(context, "Registration could not be completed. Please try again or use a different username.", userName, displayName, email);
            await _renderer.RenderPage(context);
            return;
        }

        var user = UserAuth.CreateUser();
        UserAuth.SetUserName(user, userName);
        UserAuth.SetDisplayName(user, string.IsNullOrWhiteSpace(displayName) ? userName : displayName);
        UserAuth.SetEmail(user, email);
        UserAuth.SetPermissions(user, new[] { "user" });
        UserAuth.SetIsActive(user, true);
        user.CreatedBy = userName;
        user.UpdatedBy = userName;
        UserAuth.SetPassword(user, password);
        await UserAuth.SaveUserAsync(user, context.RequestAborted);
        await UserAuth.SignInAsync(context, user, rememberMe: true);
        context.Response.Redirect("/system/me");
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
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.HttpRequest.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderLogoutForm(context, "Invalid security token. Please try again.");
            await _renderer.RenderPage(context);
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
        BaseDataObject? user = await EntraIdService.ProvisionUserAsync(options, userInfo, context.RequestAborted)
            .ConfigureAwait(false);

        if (user == null)
        {
            _logger?.LogInfo($"SSO|callback-provision-denied|{sourceIp}|email={LogRedactor.RedactEmail(userInfo.Email)}");
            await BuildPageHandler(ctx =>
            {
                RenderLoginForm(ctx, "Your account could not be provisioned. Contact your administrator.", null);
                return ValueTask.FromResult(true);
            })(context);
            return;
        }

        if (!UserAuth.IsActive(user))
        {
            _logger?.LogInfo($"SSO|callback-inactive|{sourceIp}|email={LogRedactor.RedactEmail(userInfo.Email)}");
            await BuildPageHandler(ctx =>
            {
                RenderLoginForm(ctx, "Your account has been deactivated.", null);
                return ValueTask.FromResult(true);
            })(context);
            return;
        }

        // Sign in
        RegisterSuccess(ssoIpKey);
        _logger?.LogInfo($"SSO|callback-success|{sourceIp}|email={LogRedactor.RedactEmail(userInfo.Email)}|user={user.Key}");
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

    public ValueTask AccountRedirectHandler(BmwContext context)
    {
        context.Response.Redirect("/system/me");
        return ValueTask.CompletedTask;
    }

    public async ValueTask AccountHandler(BmwContext context)
    {
        await BuildPageHandler(async ctx =>
        {
            var user = await UserAuth.GetUserAsync(ctx).ConfigureAwait(false);
            if (user == null)
            {
                ctx.Response.Redirect("/login");
                return false;
            }

            ctx.SetStringValue("title", "Account");
            var userPermissions = UserAuth.GetPermissions(user);
            var permissions = userPermissions.Length > 0
                ? string.Join(", ", userPermissions)
                : "None";
            var mfaEnabled = UserAuth.IsMfaEnabled(user);
            var mfaStatus = mfaEnabled ? "Enabled" : "Disabled";
            var mfaLinks = mfaEnabled
                ? "<a href=\"/account/mfa\">Manage MFA</a> | <a href=\"/account/mfa/reset\">Reset MFA</a>"
                : "<a href=\"/account/mfa\">Manage MFA</a>";
            var message = $"<p>Signed in as <strong>{WebUtility.HtmlEncode(UserAuth.GetDisplayName(user))}</strong> ({WebUtility.HtmlEncode(UserAuth.GetUserName(user))}).</p>" +
                         $"<p>Email: {WebUtility.HtmlEncode(UserAuth.GetEmail(user))}</p>" +
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
            var user = await UserAuth.GetUserAsync(ctx).ConfigureAwait(false);
            if (user == null)
            {
                ctx.Response.Redirect("/login");
                return false;
            }

            ctx.SetStringValue("title", "Multi-Factor Authentication");
            var mfaEnabled = UserAuth.IsMfaEnabled(user);
            var status = mfaEnabled ? "<strong>Enabled</strong>" : "<strong>Disabled</strong>";
            var message = $"<p>MFA status: {status}.</p>";
            if (!mfaEnabled)
                message += "<p><a href=\"/account/mfa/setup\">Enable MFA</a></p>";
            ctx.SetStringValue("html_message", message);
            return true;
        })(context);
    }

    public async ValueTask MfaSetupHandler(BmwContext context)
    {
        await BuildPageHandler(async ctx =>
        {
            var user = await UserAuth.GetUserAsync(ctx).ConfigureAwait(false);
            if (user == null)
            {
                ctx.Response.Redirect("/login");
                return false;
            }

            if (UserAuth.IsMfaEnabled(user))
            {
                ctx.SetStringValue("title", "Enable MFA");
                ctx.SetStringValue("html_message", "<p>MFA is already enabled for your account.</p>");
                return true;
            }

            if (RegeneratePendingMfaSecret(user, forceNew: true))
                await UserAuth.SaveUserAsync(user, ctx.RequestAborted);

            var issuer = ctx.GetApp()?.AppName ?? "BareMetalWeb";
            var pendingSecret = GetPendingSecret(user, out var pendingUpgraded);
            if (pendingUpgraded)
                await UserAuth.SaveUserAsync(user, ctx.RequestAborted);
            var otpauth = MfaTotp.GetOtpAuthUri(issuer, UserAuth.GetEmail(user) ?? string.Empty, pendingSecret ?? string.Empty);
            RenderMfaSetupForm(ctx, pendingSecret ?? string.Empty, otpauth, null);
            return true;
        })(context);
    }

    public async ValueTask MfaSetupPostHandler(BmwContext context)
    {
        var user = await UserAuth.GetUserAsync(context).ConfigureAwait(false);
        if (user == null)
        {
            context.Response.Redirect("/login");
            return;
        }

        if (!context.HttpRequest.HasFormContentType)
        {
            if (RegeneratePendingMfaSecret(user, forceNew: false))
                await UserAuth.SaveUserAsync(user, context.RequestAborted);
            var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
            var pendingSecret = GetPendingSecret(user, out var pendingUpgraded);
            if (pendingUpgraded)
                await UserAuth.SaveUserAsync(user, context.RequestAborted);
            var otpauth = string.IsNullOrWhiteSpace(pendingSecret) ? string.Empty : MfaTotp.GetOtpAuthUri(issuer, UserAuth.GetEmail(user) ?? string.Empty, pendingSecret);
            RenderMfaSetupForm(context, pendingSecret ?? string.Empty, otpauth, "Invalid setup request.");
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.HttpRequest.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            if (RegeneratePendingMfaSecret(user, forceNew: false))
                await UserAuth.SaveUserAsync(user, context.RequestAborted);
            var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
            var pendingSecret = GetPendingSecret(user, out var pendingUpgraded);
            if (pendingUpgraded)
                await UserAuth.SaveUserAsync(user, context.RequestAborted);
            var otpauth = string.IsNullOrWhiteSpace(pendingSecret) ? string.Empty : MfaTotp.GetOtpAuthUri(issuer, UserAuth.GetEmail(user) ?? string.Empty, pendingSecret);
            RenderMfaSetupForm(context, pendingSecret ?? string.Empty, otpauth, "Invalid security token. Please try again.");
            await _renderer.RenderPage(context);
            return;
        }

        var code = NormalizeOtpCode(form["code"].ToString());
        if (code == null)
        {
            var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
            var pendingSecret = GetPendingSecret(user, out var pendingUpgraded);
            if (pendingUpgraded)
                await UserAuth.SaveUserAsync(user, context.RequestAborted);
            var otpauth = string.IsNullOrWhiteSpace(pendingSecret) ? string.Empty : MfaTotp.GetOtpAuthUri(issuer, UserAuth.GetEmail(user) ?? string.Empty, pendingSecret);
            RenderMfaSetupForm(context, pendingSecret ?? string.Empty, otpauth, "Please enter a valid 6-digit code.");
            await _renderer.RenderPage(context);
            return;
        }

        var currentPendingSecret = GetPendingSecret(user, out var currentUpgraded);
        if (currentUpgraded)
            await UserAuth.SaveUserAsync(user, context.RequestAborted);
        var pendingExpiresUtc = UserAuth.GetMfaPendingExpiresUtc(user);
        if (string.IsNullOrWhiteSpace(currentPendingSecret) || pendingExpiresUtc is null || pendingExpiresUtc <= DateTime.UtcNow)
        {
            if (RegeneratePendingMfaSecret(user, forceNew: true))
                await UserAuth.SaveUserAsync(user, context.RequestAborted);
            var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
            var refreshedSecret = GetPendingSecret(user, out var refreshedUpgraded);
            if (refreshedUpgraded)
                await UserAuth.SaveUserAsync(user, context.RequestAborted);
            var otpauth = MfaTotp.GetOtpAuthUri(issuer, UserAuth.GetEmail(user) ?? string.Empty, refreshedSecret ?? string.Empty);
            RenderMfaSetupForm(context, refreshedSecret ?? string.Empty, otpauth, "Setup token expired. A new secret was generated.");
            await _renderer.RenderPage(context);
            return;
        }

        var setupIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (IsThrottled(BuildMfaAttemptKey("setup:user", user.Key.ToString()), MfaPendingMaxFailures, out var setupRetry)
            || IsThrottled(BuildMfaAttemptKey("setup:ip", setupIp), MfaPendingMaxFailures, out setupRetry)
            || IsThrottled(BuildMfaAttemptKey("setup:secret", currentPendingSecret), MfaPendingMaxFailures, out setupRetry))
        {
            var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
            var otpauth = MfaTotp.GetOtpAuthUri(issuer, UserAuth.GetEmail(user) ?? string.Empty, currentPendingSecret);
            RenderMfaSetupForm(context, currentPendingSecret, otpauth, FormatThrottleMessage(setupRetry));
            await _renderer.RenderPage(context);
            return;
        }

        var pendingBytes = Array.Empty<byte>();
        try
        {
            pendingBytes = Encoding.UTF8.GetBytes(currentPendingSecret);
            if (!MfaTotp.ValidateCode(currentPendingSecret, code, out var matchedStep))
            {
                var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
                var otpauth = MfaTotp.GetOtpAuthUri(issuer, UserAuth.GetEmail(user) ?? string.Empty, currentPendingSecret);
                var pendingFailedAttempts = UserAuth.GetMfaPendingFailedAttempts(user) + 1;
                UserAuth.SetMfaPendingFailedAttempts(user, pendingFailedAttempts);
                if (pendingFailedAttempts >= MfaPendingMaxFailures)
                {
                    if (RegeneratePendingMfaSecret(user, forceNew: true))
                        await UserAuth.SaveUserAsync(user, context.RequestAborted);
                    var refreshedSecret = GetPendingSecret(user, out var refreshedUpgraded) ?? string.Empty;
                    if (refreshedUpgraded)
                        await UserAuth.SaveUserAsync(user, context.RequestAborted);
                    otpauth = MfaTotp.GetOtpAuthUri(issuer, UserAuth.GetEmail(user) ?? string.Empty, refreshedSecret);
                    RenderMfaSetupForm(context, refreshedSecret, otpauth, "Too many failed attempts. A new secret was generated.");
                    await _renderer.RenderPage(context);
                    return;
                }

                RegisterFailure(BuildMfaAttemptKey("setup:user", user.Key.ToString()), MfaPendingMaxFailures);
                RegisterFailure(BuildMfaAttemptKey("setup:ip", setupIp), MfaPendingMaxFailures);
                RegisterFailure(BuildMfaAttemptKey("setup:secret", currentPendingSecret), MfaPendingMaxFailures);

                RenderMfaSetupForm(context, currentPendingSecret, otpauth, "Invalid authentication code.");
                await _renderer.RenderPage(context);
                return;
            }

            if (matchedStep <= UserAuth.GetMfaLastVerifiedStep(user))
            {
                var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
                var otpauth = MfaTotp.GetOtpAuthUri(issuer, UserAuth.GetEmail(user) ?? string.Empty, currentPendingSecret);
                RenderMfaSetupForm(context, currentPendingSecret, otpauth, "Authentication code already used. Please wait for a new code.");
                await _renderer.RenderPage(context);
                return;
            }

            UserAuth.SetMfaEnabled(user, true);
            UserAuth.SetMfaLastVerifiedStep(user, matchedStep);
            UserAuth.SetMfaSecretEncrypted(user, _mfaProtector.EncryptSecret(currentPendingSecret, user.Key.ToString()));
            UserAuth.SetMfaSecret(user, null);
            UserAuth.SetMfaPendingSecret(user, null);
            UserAuth.SetMfaPendingSecretEncrypted(user, null);
            UserAuth.SetMfaPendingExpiresUtc(user, null);
            UserAuth.SetMfaPendingFailedAttempts(user, 0);

            var backupCodes = GenerateBackupCodes(user, count: 8);
            UserAuth.SetMfaBackupCodeHashes(user, backupCodes.Hashes);
            UserAuth.SetMfaBackupCodesGeneratedUtc(user, DateTime.UtcNow);
            await UserAuth.SaveUserAsync(user, context.RequestAborted);

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
            context.SetStringValue("html_message", "<p>MFA enabled successfully.</p>" + backupHtml + "<p><a href=\"/system/me\">Back to account</a></p>");
            await _renderer.RenderPage(context);
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
            var user = await UserAuth.GetUserAsync(ctx).ConfigureAwait(false);
            if (user == null)
            {
                ctx.Response.Redirect("/login");
                return false;
            }

            ctx.SetStringValue("title", "Reset MFA");
            if (!UserAuth.IsMfaEnabled(user))
            {
                ctx.SetStringValue("html_message", "<p>MFA is not enabled for your account.</p><p><a href=\"/system/me\">Back to account</a></p>");
                return true;
            }

            RenderMfaResetForm(ctx, null);
            return true;
        })(context);
    }

    public async ValueTask MfaResetPostHandler(BmwContext context)
    {
        var user = await UserAuth.GetUserAsync(context).ConfigureAwait(false);
        if (user == null)
        {
            context.Response.Redirect("/login");
            return;
        }

        if (!context.HttpRequest.HasFormContentType)
        {
            RenderMfaResetForm(context, "Invalid request.");
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.HttpRequest.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderMfaResetForm(context, "Invalid security token. Please try again.");
            await _renderer.RenderPage(context);
            return;
        }

        UserAuth.SetMfaEnabled(user, false);
        UserAuth.SetMfaSecret(user, null);
        UserAuth.SetMfaSecretEncrypted(user, null);
        UserAuth.SetMfaLastVerifiedStep(user, 0);
        UserAuth.SetMfaPendingSecret(user, null);
        UserAuth.SetMfaPendingSecretEncrypted(user, null);
        UserAuth.SetMfaPendingExpiresUtc(user, null);
        UserAuth.SetMfaPendingFailedAttempts(user, 0);
        UserAuth.SetMfaBackupCodeHashes(user, Array.Empty<string>());
        UserAuth.SetMfaBackupCodesGeneratedUtc(user, null);
        await UserAuth.SaveUserAsync(user, context.RequestAborted);

        context.SetStringValue("title", "Reset MFA");
        context.SetStringValue("html_message", "<p>MFA has been reset.</p><p><a href=\"/system/me\">Back to account</a></p>");
        await _renderer.RenderPage(context);
    }

    public async ValueTask UsersListHandler(BmwContext context)
    {
        await BuildPageHandler(async ctx =>
        {
            ctx.SetStringValue("title", "Users");

            using var rows = new BmwValueList<string[]>(16);
            var users = await UserAuth.QueryUsersAsync(new QueryDefinition(), ctx.RequestAborted).ConfigureAwait(false);
            foreach (var user in users)
            {
                var permissions = UserAuth.GetPermissions(user);
                rows.Add(new[]
                {
                    WebUtility.HtmlEncode(UserAuth.GetUserName(user) ?? string.Empty),
                    WebUtility.HtmlEncode(UserAuth.GetDisplayName(user) ?? string.Empty),
                    WebUtility.HtmlEncode(UserAuth.GetEmail(user) ?? string.Empty),
                    UserAuth.IsActive(user) ? "Yes" : "No",
                    WebUtility.HtmlEncode(permissions.Length > 0
                        ? string.Join(", ", permissions)
                        : "None") ?? string.Empty,
                    UserAuth.GetLastLoginUtc(user)?.ToString("u") ?? "Never"
                });
            }

            ctx.AddTable(
                new[] { "Username", "Display Name", "Email", "Active", "Permissions", "Last Login" },
                rows.ToArray());
        })(context);
    }

    public async ValueTask SetupHandler(BmwContext context)
    {
        if (await RootUserExistsAsync(context.RequestAborted).ConfigureAwait(false))
        {
            await WriteSetupAlreadyCompleteAsync(context);
            return;
        }

        await BuildPageHandler(ctx =>
        {
            RenderSetupForm(ctx, null, null, null, new SetupRegistrationInput());
            return ValueTask.CompletedTask;
        })(context);
    }

    public async ValueTask SetupPostHandler(BmwContext context)
    {
        if (await RootUserExistsAsync(context.RequestAborted).ConfigureAwait(false))
        {
            await WriteSetupAlreadyCompleteAsync(context);
            return;
        }

        // Read form data; use empty collection for non-form requests so CSRF check always runs
        var form = context.HttpRequest.HasFormContentType
            ? await context.HttpRequest.ReadFormAsync()
            : FormCollection.Empty;

        var userName = form["username"].ToString().Trim();
        var email = form["email"].ToString().Trim();
        var password = form["password"].ToString();
        var registrationInput = ReadSetupRegistrationInput(form);

        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderSetupForm(context, "Invalid security token. Please try again.", userName, email, registrationInput);
            await _renderer.RenderPage(context);
            return;
        }

        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            RenderSetupForm(context, "Please complete all required fields.", userName, email, registrationInput);
            await _renderer.RenderPage(context);
            return;
        }

        if (password.Length > 1024)
        {
            RenderSetupForm(context, "Password exceeds maximum allowed length.", userName, email, registrationInput);
            await _renderer.RenderPage(context);
            return;
        }

        if (registrationInput.Enabled)
        {
            var registrationValidationError = ValidateSetupRegistrationInput(registrationInput);
            if (!string.IsNullOrEmpty(registrationValidationError))
            {
                RenderSetupForm(context, registrationValidationError, userName, email, registrationInput);
                await _renderer.RenderPage(context);
                return;
            }
        }

        // Double-check race condition: another request may have created the root user
        if (await RootUserExistsAsync(context.RequestAborted).ConfigureAwait(false))
        {
            await WriteSetupAlreadyCompleteAsync(context);
            return;
        }

        var user = UserAuth.CreateUser();
        UserAuth.SetUserName(user, userName);
        UserAuth.SetDisplayName(user, userName);
        UserAuth.SetEmail(user, email);
        UserAuth.SetPermissions(user, BuildRootPermissions());
        UserAuth.SetIsActive(user, true);
        user.CreatedBy = userName;
        user.UpdatedBy = userName;
        UserAuth.SetPassword(user, password);
        await UserAuth.SaveUserAsync(user, context.RequestAborted);
        await SettingsService.EnsureDefaultsAsync(DataStoreProvider.Current, _settingDefaults, userName, context.RequestAborted).ConfigureAwait(false);
        await EnsureDefaultReports(userName);

        if (!registrationInput.Enabled)
        {
            // Redirect to gallery so the user can deploy modules
            context.Response.Redirect("/admin/gallery");
            return;
        }

        var registrationResult = await RegisterManagementPrincipalAsync(registrationInput, userName, context.RequestAborted).ConfigureAwait(false);
        if (!registrationResult.Success)
        {
            context.SetStringValue("title", "Setup Complete");
            context.SetStringValue("html_message",
                $"<div class=\"alert alert-warning\">Admin account created, but management registration failed: {WebUtility.HtmlEncode(registrationResult.Message)}</div>" +
                "<p>You can still sign in and continue setup. Review settings in <strong>Admin → Settings</strong>.</p>" +
                "<p><a class=\"btn btn-primary\" href=\"/login\">Go to Login</a></p>");
            await _renderer.RenderPage(context);
            return;
        }

        context.SetStringValue("title", "Setup Complete");
        context.SetStringValue("html_message",
            $"<div class=\"alert alert-success\">Admin account created and management registration completed for principal <code>{WebUtility.HtmlEncode(registrationResult.PrincipalName)}</code>.</div>" +
            "<p><a class=\"btn btn-primary\" href=\"/admin/gallery\">Continue to Gallery</a></p>");
        await _renderer.RenderPage(context);
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

    private static SetupRegistrationInput ReadSetupRegistrationInput(IFormCollection form)
    {
        var principalName = form["management_principal_name"].ToString().Trim();
        if (string.IsNullOrWhiteSpace(principalName))
            principalName = DefaultManagementPrincipalName;

        return new SetupRegistrationInput
        {
            Enabled = IsTruthyFormValue(form["management_registration_enabled"]),
            CallbackUrl = form["management_callback_url"].ToString().Trim(),
            PrincipalName = principalName,
            TenantId = form["management_tenant_id"].ToString().Trim(),
            ClientId = form["management_client_id"].ToString().Trim()
        };
    }

    private static bool IsTruthyFormValue(StringValues value)
    {
        if (value.Count == 0)
            return false;

        var raw = value.ToString().Trim();
        return string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase)
               || string.Equals(raw, "on", StringComparison.OrdinalIgnoreCase)
               || raw == "1";
    }

    private static string? ValidateSetupRegistrationInput(SetupRegistrationInput input)
    {
        if (string.IsNullOrWhiteSpace(input.CallbackUrl))
            return "Management callback URL is required when registration is enabled.";

        if (!Uri.TryCreate(input.CallbackUrl, UriKind.Absolute, out var callbackUri))
            return "Management callback URL must be an absolute URL.";

        var isHttps = string.Equals(callbackUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        var isLocalHttp = string.Equals(callbackUri.Scheme, Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                          && callbackUri.IsLoopback;
        if (!isHttps && !isLocalHttp)
            return "Management callback URL must use HTTPS (HTTP allowed only for localhost).";

        if (string.IsNullOrWhiteSpace(input.PrincipalName))
            return "Management principal name is required when registration is enabled.";

        return null;
    }

    private async ValueTask<SetupRegistrationResult> RegisterManagementPrincipalAsync(
        SetupRegistrationInput input,
        string actor,
        CancellationToken cancellationToken)
    {
        var principal = await LoadSystemPrincipalByUserNameAsync(input.PrincipalName, cancellationToken).ConfigureAwait(false);
        var isNewPrincipal = principal is null;
        if (principal is null)
        {
            principal = UserAuth.CreatePrincipal();
            UserAuth.SetUserName(principal, input.PrincipalName);
            UserAuth.SetDisplayName(principal, input.PrincipalName);
            UserAuth.SetEmail(principal, $"{input.PrincipalName}@local.invalid");
            UserAuth.SetPermissions(principal, new[] { "deployment-agent", "monitoring" });
            UserAuth.SetIsActive(principal, true);
            principal.CreatedBy = actor;
            principal.UpdatedBy = actor;
        }

        var rawApiKey = UserAuthHelper.GenerateRawApiKey();
        UserAuth.AddApiKey(principal, rawApiKey);
        principal.UpdatedBy = actor;
        await UserAuth.SaveUserAsync(principal, cancellationToken).ConfigureAwait(false);

        await UpsertAppSettingAsync(ManagementRegistrationEnabledSettingId, "true",
            "Enable setup-based management callback registration.", actor, cancellationToken).ConfigureAwait(false);
        await UpsertAppSettingAsync(ManagementRegistrationCallbackUrlSettingId, input.CallbackUrl,
            "Management callback endpoint used by setup registration.", actor, cancellationToken).ConfigureAwait(false);
        await UpsertAppSettingAsync(ManagementRegistrationPrincipalNameSettingId, input.PrincipalName,
            "System principal name used for setup registration.", actor, cancellationToken).ConfigureAwait(false);
        await UpsertAppSettingAsync(ManagementRegistrationTenantIdSettingId, input.TenantId,
            "Management tenant identifier reference.", actor, cancellationToken).ConfigureAwait(false);
        await UpsertAppSettingAsync(ManagementRegistrationClientIdSettingId, input.ClientId,
            "Management client identifier reference.", actor, cancellationToken).ConfigureAwait(false);
        await UpsertAppSettingAsync(ManagementRegistrationLastAttemptUtcSettingId, DateTime.UtcNow.ToString("O"),
            "Timestamp of the last setup registration attempt.", actor, cancellationToken).ConfigureAwait(false);

        var registrationRequest = new SetupRegistrationRequest
        {
            InstanceId = Environment.MachineName,
            PrincipalName = input.PrincipalName,
            PrincipalApiKey = rawApiKey,
            TenantId = input.TenantId,
            ClientId = input.ClientId,
            RegisteredBy = actor,
            RegisteredAtUtc = DateTime.UtcNow.ToString("O")
        };

        using var request = new HttpRequestMessage(HttpMethod.Post, input.CallbackUrl)
        {
            Content = new StringContent(DataJsonWriter.ToJsonString(registrationRequest), Encoding.UTF8, "application/json")
        };
        request.Headers.TryAddWithoutValidation("X-Bmw-Registration-Version", "1");
        request.Headers.TryAddWithoutValidation("X-Bmw-Principal", input.PrincipalName);

        HttpResponseMessage response;
        try
        {
            response = await SetupRegistrationHttp.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            await UpsertAppSettingAsync(ManagementRegistrationLastStatusSettingId, "failed:request-exception",
                "Result of the most recent setup registration callback.", actor, cancellationToken).ConfigureAwait(false);
            _logger?.LogError("Setup registration callback request failed.", ex);
            return new SetupRegistrationResult(false, "Callback request failed.", input.PrincipalName);
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            await UpsertAppSettingAsync(ManagementRegistrationLastStatusSettingId, "failed:timeout",
                "Result of the most recent setup registration callback.", actor, cancellationToken).ConfigureAwait(false);
            _logger?.LogError("Setup registration callback timed out.", ex);
            return new SetupRegistrationResult(false, "Callback request timed out.", input.PrincipalName);
        }

        using (response)
        {
            if (!response.IsSuccessStatusCode)
            {
                await UpsertAppSettingAsync(ManagementRegistrationLastStatusSettingId,
                    $"failed:{(int)response.StatusCode}",
                    "Result of the most recent setup registration callback.", actor, cancellationToken).ConfigureAwait(false);
                var body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                _logger?.Log(BmwLogLevel.Warn, $"Setup registration callback failed ({(int)response.StatusCode}) for principal '{input.PrincipalName}'.");
                return new SetupRegistrationResult(false,
                    $"Callback returned {(int)response.StatusCode}. {TrimForDisplay(body, 256)}",
                    input.PrincipalName);
            }
        }

        await UpsertAppSettingAsync(ManagementRegistrationLastStatusSettingId, "success",
            "Result of the most recent setup registration callback.", actor, cancellationToken).ConfigureAwait(false);
        _logger?.LogInfo($"Setup registration completed for principal '{input.PrincipalName}' (newPrincipal={isNewPrincipal}).");
        return new SetupRegistrationResult(true, "Management registration completed.", input.PrincipalName);
    }

    private static string TrimForDisplay(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        var trimmed = value.Trim();
        if (trimmed.Length <= maxLength)
            return trimmed;
        return trimmed[..maxLength] + "...";
    }

    private static async ValueTask<BaseDataObject?> LoadSystemPrincipalByUserNameAsync(string userName, CancellationToken cancellationToken)
    {
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new() { Field = "UserName", Operator = QueryOperator.Equals, Value = userName }
            },
            Top = 1
        };

        var principals = await UserAuth.QueryPrincipalsAsync(query, cancellationToken).ConfigureAwait(false);
        foreach (var principal in principals)
        {
            if (string.Equals(UserAuth.GetUserName(principal), userName, StringComparison.OrdinalIgnoreCase))
                return principal;
        }

        return null;
    }

    private static async ValueTask UpsertAppSettingAsync(
        string settingId,
        string value,
        string description,
        string actor,
        CancellationToken cancellationToken)
    {
        if (!TryGetAppSettingMeta(out var settingMeta))
            return;

        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new() { Field = "SettingId", Operator = QueryOperator.Equals, Value = settingId }
            },
            Top = 1
        };

        var settings = await DataScaffold.QueryAsync(settingMeta, query, cancellationToken).ConfigureAwait(false);
        BaseDataObject? setting = null;
        foreach (var existing in settings)
        {
            if (existing is BaseDataObject obj
                && string.Equals(GetMetaString(obj, settingMeta, "SettingId"), settingId, StringComparison.OrdinalIgnoreCase))
            {
                setting = obj;
                break;
            }
        }

        if (setting is null)
        {
            setting = settingMeta.Handlers.Create();
            setting.CreatedBy = actor;
            setting.UpdatedBy = actor;
            settingMeta.FindField("SettingId")?.SetValueFn(setting, settingId);
        }
        else
        {
            setting.UpdatedBy = actor;
        }

        settingMeta.FindField("Value")?.SetValueFn(setting, value);
        settingMeta.FindField("Description")?.SetValueFn(setting, description);

        if (setting.Key == 0)
            await DataScaffold.ApplyAutoIdAsync(settingMeta, setting, cancellationToken).ConfigureAwait(false);
        await DataScaffold.SaveAsync(settingMeta, setting, cancellationToken).ConfigureAwait(false);
        SettingsService.InvalidateCache(settingId);
    }

    private async ValueTask EnsureDefaultReports(string createdBy)
    {
        var existingNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var reportMeta = DataScaffold.GetEntityByName("ReportDefinition");
        var nameField = reportMeta?.FindField("Name");
        var existing = await DataStoreProvider.Current.QueryAsync("ReportDefinition", null).ConfigureAwait(false);
        foreach (var r in existing)
        {
            var name = nameField?.GetValueFn(r)?.ToString();
            if (!string.IsNullOrEmpty(name))
                existingNames.Add(name);
        }

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

            await DataStoreProvider.Current.SaveAsync(report.EntityTypeName, report).ConfigureAwait(false);
        }
    }

    public async ValueTask ReloadTemplatesHandler(BmwContext context)
    {
        _templateStore.ReloadAll();
        context.SetStringValue("title", "Reload Templates");
        context.SetStringValue("html_message", "Templates reloaded successfully.");
        await _renderer.RenderPage(context);
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

    /// <summary>Returns 409 Conflict — system is already configured.</summary>
    private static async ValueTask WriteSetupAlreadyCompleteAsync(BmwContext context)
    {
        await ApiErrorWriter.WriteAsync(context,
            ApiErrorWriter.Conflict(detail: "System is already configured.", instance: "/setup"),
            context.RequestAborted);
    }

    private void RenderSetupForm(BmwContext context, string? message, string? userName, string? email, SetupRegistrationInput registrationInput)
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
                new FormField(FormFieldType.Password, "password", "Password", true, "Enter password"),
                new FormField(FormFieldType.YesNo, "management_registration_enabled", "Enable management principal registration", false, SelectedValue: registrationInput.Enabled ? "true" : "false"),
                new FormField(FormFieldType.String, "management_callback_url", "Management callback/home URL", false, "https://controlplane.example/api/setup/register", Value: registrationInput.CallbackUrl),
                new FormField(FormFieldType.String, "management_principal_name", "Management principal name", false, DefaultManagementPrincipalName, Value: registrationInput.PrincipalName),
                new FormField(FormFieldType.String, "management_tenant_id", "Management tenant ID (reference)", false, "tenant-001", Value: registrationInput.TenantId),
                new FormField(FormFieldType.String, "management_client_id", "Management client ID (reference)", false, "client-001", Value: registrationInput.ClientId)
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

    private bool RegeneratePendingMfaSecret(BaseDataObject user, bool forceNew)
    {
        var changed = false;
        var pendingSecretEncrypted = UserAuth.GetMfaPendingSecretEncrypted(user);
        var pendingExpiresUtc = UserAuth.GetMfaPendingExpiresUtc(user);
        if (forceNew || string.IsNullOrWhiteSpace(pendingSecretEncrypted) || pendingExpiresUtc is null || pendingExpiresUtc <= DateTime.UtcNow)
        {
            var secret = MfaTotp.GenerateSecret();
            UserAuth.SetMfaPendingSecretEncrypted(user, _mfaProtector.EncryptSecret(secret, user.Key.ToString()));
            UserAuth.SetMfaPendingSecret(user, null);
            UserAuth.SetMfaPendingExpiresUtc(user, DateTime.UtcNow.Add(MfaPendingLifetime));
            UserAuth.SetMfaPendingFailedAttempts(user, 0);
            changed = true;
        }

        return changed;
    }

    private string? GetPendingSecret(BaseDataObject user, out bool upgraded)
    {
        upgraded = false;
        var pendingSecretEncrypted = UserAuth.GetMfaPendingSecretEncrypted(user);
        if (!string.IsNullOrWhiteSpace(pendingSecretEncrypted))
        {
            if (_mfaProtector.TryDecryptSecret(pendingSecretEncrypted, user.Key.ToString(), out var bytes))
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

        var pendingSecret = UserAuth.GetMfaPendingSecret(user);
        if (!string.IsNullOrWhiteSpace(pendingSecret))
        {
            UserAuth.SetMfaPendingSecretEncrypted(user, _mfaProtector.EncryptSecret(pendingSecret, user.Key.ToString()));
            UserAuth.SetMfaPendingSecret(user, null);
            upgraded = true;
            return pendingSecret;
        }

        return null;
    }

    private bool TryGetActiveSecret(BaseDataObject user, out string secret, out bool upgraded)
    {
        secret = string.Empty;
        upgraded = false;
        var activeSecretEncrypted = UserAuth.GetMfaSecretEncrypted(user);
        if (!string.IsNullOrWhiteSpace(activeSecretEncrypted))
        {
            if (_mfaProtector.TryDecryptSecret(activeSecretEncrypted, user.Key.ToString(), out var bytes))
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

        var activeSecret = UserAuth.GetMfaSecret(user);
        if (!string.IsNullOrWhiteSpace(activeSecret))
        {
            UserAuth.SetMfaSecretEncrypted(user, _mfaProtector.EncryptSecret(activeSecret, user.Key.ToString()));
            UserAuth.SetMfaSecret(user, null);
            secret = activeSecret;
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
        ScavengeMfaAttempts();
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
        if (MfaAttempts.TryRemove(key, out _)) { }
    }

    /// <summary>Evict MFA attempt trackers idle for longer than the attempt window (5 min). Runs at most once per minute.</summary>
    private static void ScavengeMfaAttempts()
    {
        var now = DateTime.UtcNow;
        bool overCap = MfaAttempts.Count > MfaMaxTrackedKeys;
        if (!overCap && (now - _lastMfaScavenge).TotalSeconds < 60) return;
        _lastMfaScavenge = now;

        var cutoff = now - MfaAttemptWindow - MfaAttemptWindow; // 2x window = 10 min stale
        foreach (var kvp in MfaAttempts)
        {
            if (kvp.Value.LastActivityUtc < cutoff)
                MfaAttempts.TryRemove(kvp.Key, out _);
        }

        // Hard cap: if still over limit after time-based eviction, drop oldest entries
        if (MfaAttempts.Count > MfaMaxTrackedKeys)
        {
            foreach (var kvp in MfaAttempts.OrderBy(x => x.Value.LastActivityUtc))
            {
                MfaAttempts.TryRemove(kvp.Key, out _);
                if (MfaAttempts.Count <= MfaMaxTrackedKeys) break;
            }
        }
    }

    private static string FormatThrottleMessage(TimeSpan? retryAfter)
    {
        if (retryAfter.HasValue)
            return $"Too many attempts. Try again in {(int)Math.Ceiling(retryAfter.Value.TotalSeconds)} seconds.";

        return "Too many attempts. Please try again shortly.";
    }

    private static BackupCodeResult GenerateBackupCodes(BaseDataObject user, int count)
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

    private static string HashBackupCode(BaseDataObject user, string code)
    {
        var payload = Encoding.UTF8.GetBytes($"{user.Key}:{code}");
        return Convert.ToHexString(SHA256.HashData(payload));
    }

    private sealed class AttemptTracker
    {
        private readonly object _sync = new();
        private DateTime _windowStartUtc = DateTime.UtcNow;
        private DateTime? _blockedUntilUtc;
        private int _count;
        public DateTime LastActivityUtc = DateTime.UtcNow;

        public bool IsBlocked(TimeSpan window, int maxAttempts, TimeSpan baseBlock, out TimeSpan? retryAfter)
        {
            lock (_sync)
            {
                var now = DateTime.UtcNow;
                LastActivityUtc = now;
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
                LastActivityUtc = now;
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

        if (!await CheckPrincipalRolePolicyAsync(context, meta, "Read", context.RequestAborted).ConfigureAwait(false))
            return;

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
                var resultsList = new List<object?>(results is ICollection csvCol ? csvCol.Count : 32);
                foreach (var item in results)
                    resultsList.Add((object?)item);
                var rows = BuildListPlainRowsWithId(meta, resultsList, out var headers);
                var csv = BuildCsv(headers, rows);
                await WriteTextResponseAsync(context, "text/csv", csv, $"{typeSlug}_list.csv");
                return;
            }

            int resultCount = results is ICollection resultCol ? resultCol.Count : 0;
            Dictionary<string, object?>[] payload;
            if (resultCount > 0)
            {
                payload = new Dictionary<string, object?>[resultCount];
                int pi = 0;
                foreach (var item in results)
                    payload[pi++] = BuildApiModel(meta, (object)item);
            }
            else
            {
                using var payloadList = new BmwValueList<Dictionary<string, object?>>(32);
                foreach (var item in results)
                    payloadList.Add(BuildApiModel(meta, (object)item));
                payload = payloadList.ToArray();
            }
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
            var resultsList = new List<object?>(allResults is ICollection csvCol2 ? csvCol2.Count : 32);
            foreach (var item in allResults)
                resultsList.Add((object?)item);
            var rows = BuildListPlainRowsWithId(meta, resultsList, out var headers);
            var csv = BuildCsv(headers, rows);
            await WriteTextResponseAsync(context, "text/csv", csv, $"{typeSlug}_list.csv");
            return;
        }

        int allCount = allResults is ICollection allCol ? allCol.Count : 0;
        Dictionary<string, object?>[] allPayload;
        if (allCount > 0)
        {
            allPayload = new Dictionary<string, object?>[allCount];
            int ai = 0;
            foreach (var item in allResults)
                allPayload[ai++] = BuildApiModel(meta, (object)item);
        }
        else
        {
            using var allPayloadList = new BmwValueList<Dictionary<string, object?>>(32);
            foreach (var item in allResults)
                allPayloadList.Add(BuildApiModel(meta, (object)item));
            allPayload = allPayloadList.ToArray();
        }
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

        if (!await CheckPrincipalRolePolicyAsync(context, meta, "Create", context.RequestAborted).ConfigureAwait(false))
            return;

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

        // SECURITY: Enforce max file size (50 MB) to prevent memory exhaustion (see #1206)
        const long MaxCsvFileSize = 50L * 1024 * 1024;
        if (file.Length > MaxCsvFileSize)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"CSV file exceeds 50 MB size limit.\"}");
            return;
        }

        var upsert = DataScaffold.IsTruthy(form["upsert"].ToString());
        // #1250: Stream CSV line by line instead of buffering entire file
        const int MaxCsvRows = 100_000;
        var rows = new List<string[]>();
        using (var cts = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted))
        {
            cts.CancelAfter(TimeSpan.FromSeconds(60));
            await using (var stream = file.OpenReadStream())
            using (var reader = new StreamReader(stream))
            {
                string? line;
                while ((line = await reader.ReadLineAsync(cts.Token)) != null)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    rows.Add(ParseCsvLine(line));
                    if (rows.Count > MaxCsvRows + 1)
                    {
                        context.Response.StatusCode = StatusCodes.Status400BadRequest;
                        context.Response.ContentType = "application/json";
                        await context.Response.WriteAsync($"{{\"error\":\"CSV exceeds {MaxCsvRows:N0} row limit.\"}}");
                        return;
                    }
                }
            }
        }

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
                if (!uint.TryParse(idValue, out var parsedIdValue))
                {
                    importErrors.Add($"Row {rowNumber}: Invalid ID '{idValue}'.");
                    skipped++;
                    continue;
                }
                var existing = await DataScaffold.LoadAsync(meta, parsedIdValue);
                if (existing is BaseDataObject existingObject)
                {
                    instance = existingObject;
                    isCreate = false;
                }
                else
                {
                    instance = meta.Handlers.Create();
                    instance.Key = parsedIdValue;
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
            catch (Exception)
            {
                importErrors.Add($"Row {rowNumber}: Import failed.");
                skipped++;
            }
        }

        context.Response.ContentType = "application/json";
        await using (var w = new Utf8JsonWriter(context.Response.Body))
        {
            w.WriteStartObject();
            w.WriteNumber("created", created);
            w.WriteNumber("updated", updated);
            w.WriteNumber("skipped", skipped);
            w.WritePropertyName("errors");
            w.WriteStartArray();
            foreach (var e in importErrors)
                w.WriteStringValue(e);
            w.WriteEndArray();
            w.WriteEndObject();
        }
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

        if (!await CheckPrincipalRolePolicyAsync(context, meta, "Read", context.RequestAborted).ConfigureAwait(false))
            return;

        if (!uint.TryParse(id, out var parsedId))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid entity id.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, parsedId);
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Item not found.");
            return;
        }

        // TenantCallback principals can only read their own records
        var getUser = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
        var getRestricted = PrincipalAuthorizationPolicy.AsRestrictedPrincipal(getUser);
        if (getRestricted != null && string.Equals(UserAuth.GetPrincipalRole(getRestricted), nameof(PrincipalRole.TenantCallback), StringComparison.OrdinalIgnoreCase) && instance is BaseDataObject getBdo &&
            !PrincipalAuthorizationPolicy.IsRecordOwner(getRestricted, getBdo))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied: record not owned by this principal.");
            await _auditService.AuditDeniedAsync(
                meta.Slug, parsedId, "Read", UserAuth.GetUserName(getRestricted) ?? getRestricted.Key.ToString(),
                "TenantCallback principal attempted to read non-owned record", context.RequestAborted).ConfigureAwait(false);
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

        if (!await CheckPrincipalRolePolicyAsync(context, meta, "Create", context.RequestAborted).ConfigureAwait(false))
            return;

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

        var apiCreateErrors = RentStringList();
        await ValidateUserUniquenessAsync(meta, instance, excludeId: null, apiCreateErrors, context.RequestAborted).ConfigureAwait(false);
        if (apiCreateErrors.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status409Conflict;
            await context.Response.WriteAsync(string.Join(" | ", apiCreateErrors));
            ReturnStringList(apiCreateErrors);
            return;
        }
        ReturnStringList(apiCreateErrors);

        ApplyAuditInfo(instance, UserAuth.GetUserName(await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false)) ?? "system", isCreate: true);
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

        if (!await CheckPrincipalRolePolicyAsync(context, meta, "Update", context.RequestAborted).ConfigureAwait(false))
            return;

        if (!await UserAuth.HasValidApiKeyAsync(context, context.RequestAborted).ConfigureAwait(false) &&
            (!ValidateApiCsrfHeader(context) || !CsrfProtection.ValidateApiToken(context)))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("CSRF validation failed.");
            return;
        }

        if (!uint.TryParse(id, out var parsedId))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid entity id.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, parsedId);
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Item not found.");
            return;
        }

        // TenantCallback principals can only update their own records
        var putUser = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
        var putRestricted = PrincipalAuthorizationPolicy.AsRestrictedPrincipal(putUser);
        if (putRestricted != null && string.Equals(UserAuth.GetPrincipalRole(putRestricted), nameof(PrincipalRole.TenantCallback), StringComparison.OrdinalIgnoreCase) && instance is BaseDataObject putBdo &&
            !PrincipalAuthorizationPolicy.IsRecordOwner(putRestricted, putBdo))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied: record not owned by this principal.");
            await _auditService.AuditDeniedAsync(
                meta.Slug, parsedId, "Update", UserAuth.GetUserName(putRestricted) ?? putRestricted.Key.ToString(),
                "TenantCallback principal attempted to update non-owned record", context.RequestAborted).ConfigureAwait(false);
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

        var apiPutErrors = RentStringList();
        await ValidateUserUniquenessAsync(meta, instance, excludeId: id, apiPutErrors, context.RequestAborted).ConfigureAwait(false);
        if (apiPutErrors.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status409Conflict;
            await context.Response.WriteAsync(string.Join(" | ", apiPutErrors));
            ReturnStringList(apiPutErrors);
            return;
        }
        ReturnStringList(apiPutErrors);

        ApplyAuditInfo(instance, UserAuth.GetUserName(await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false)) ?? "system", isCreate: false);
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

        if (!await CheckPrincipalRolePolicyAsync(context, meta, "Update", context.RequestAborted).ConfigureAwait(false))
            return;

        if (!await UserAuth.HasValidApiKeyAsync(context, context.RequestAborted).ConfigureAwait(false) &&
            (!ValidateApiCsrfHeader(context) || !CsrfProtection.ValidateApiToken(context)))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("CSRF validation failed.");
            return;
        }

        if (!uint.TryParse(id, out var parsedId))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid entity id.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, parsedId);
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Item not found.");
            return;
        }

        // TenantCallback principals can only update their own records
        var patchUser = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
        var patchRestricted = PrincipalAuthorizationPolicy.AsRestrictedPrincipal(patchUser);
        if (patchRestricted != null && string.Equals(UserAuth.GetPrincipalRole(patchRestricted), nameof(PrincipalRole.TenantCallback), StringComparison.OrdinalIgnoreCase) && instance is BaseDataObject patchBdo &&
            !PrincipalAuthorizationPolicy.IsRecordOwner(patchRestricted, patchBdo))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied: record not owned by this principal.");
            await _auditService.AuditDeniedAsync(
                meta.Slug, parsedId, "Update", UserAuth.GetUserName(patchRestricted) ?? patchRestricted.Key.ToString(),
                "TenantCallback principal attempted to update non-owned record", context.RequestAborted).ConfigureAwait(false);
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

        ApplyAuditInfo(instance, UserAuth.GetUserName(await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false)) ?? "system", isCreate: false);
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

        if (!await CheckPrincipalRolePolicyAsync(context, meta, "Delete", context.RequestAborted).ConfigureAwait(false))
            return;

        if (!await UserAuth.HasValidApiKeyAsync(context, context.RequestAborted).ConfigureAwait(false) &&
            (!ValidateApiCsrfHeader(context) || !CsrfProtection.ValidateApiToken(context)))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("CSRF validation failed.");
            return;
        }

        if (!uint.TryParse(id, out var parsedId))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid entity id.");
            return;
        }

        await DataScaffold.DeleteAsync(meta, parsedId);
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

        if (!uint.TryParse(id, out var parsedId))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid entity id.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, parsedId);
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

    private static bool TryGetAppSettingMeta(out DataEntityMetadata settingMeta)
        => DataScaffold.TryGetEntity("app-settings", out settingMeta)
            || DataScaffold.TryGetEntity("settings", out settingMeta);

    private static bool TryGetAttachmentMeta(out DataEntityMetadata attachMeta)
        => DataScaffold.TryGetEntity("file-attachments", out attachMeta)
            || DataScaffold.TryGetEntity("fileattachment", out attachMeta);

    private static bool TryGetCommentMeta(out DataEntityMetadata commentMeta)
        => DataScaffold.TryGetEntity("record-comments", out commentMeta)
            || DataScaffold.TryGetEntity("recordcomment", out commentMeta);

    private static string GetMetaString(BaseDataObject obj, DataEntityMetadata meta, string fieldName)
        => meta.FindField(fieldName)?.GetValueFn(obj)?.ToString() ?? string.Empty;

    private static uint GetMetaUInt(BaseDataObject obj, DataEntityMetadata meta, string fieldName)
        => Convert.ToUInt32(meta.FindField(fieldName)?.GetValueFn(obj) ?? 0);

    private static long GetMetaLong(BaseDataObject obj, DataEntityMetadata meta, string fieldName)
        => Convert.ToInt64(meta.FindField(fieldName)?.GetValueFn(obj) ?? 0L);

    private static int GetMetaInt(BaseDataObject obj, DataEntityMetadata meta, string fieldName)
        => Convert.ToInt32(meta.FindField(fieldName)?.GetValueFn(obj) ?? 0);

    private static bool GetMetaBool(BaseDataObject obj, DataEntityMetadata meta, string fieldName)
    {
        var value = meta.FindField(fieldName)?.GetValueFn(obj);
        return value switch
        {
            bool flag => flag,
            string text when bool.TryParse(text, out var parsed) => parsed,
            _ => false
        };
    }

    private static Dictionary<string, object?> BuildAttachmentApiModel(BaseDataObject a, DataEntityMetadata meta) =>
        new()
        {
            ["id"] = a.Key,
            ["fileName"] = GetMetaString(a, meta, "FileName"),
            ["contentType"] = GetMetaString(a, meta, "ContentType"),
            ["sizeBytes"] = GetMetaLong(a, meta, "SizeBytes"),
            ["description"] = meta.FindField("Description")?.GetValueFn(a)?.ToString(),
            ["versionNumber"] = GetMetaInt(a, meta, "VersionNumber"),
            ["attachmentGroupId"] = GetMetaUInt(a, meta, "AttachmentGroupId"),
            ["isCurrentVersion"] = GetMetaBool(a, meta, "IsCurrentVersion"),
            ["uploadedAt"] = a.CreatedOnUtc,
            ["uploadedBy"] = a.CreatedBy,
            ["downloadUrl"] = $"/api/_attachments/{a.Key}/download"
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
                new QueryClause { Field = "RecordType", Operator = QueryOperator.Equals, Value = meta.Slug },
                new QueryClause { Field = "RecordKey", Operator = QueryOperator.Equals, Value = recordKey.ToString() },
                new QueryClause { Field = "IsCurrentVersion", Operator = QueryOperator.Equals, Value = "true" }
            }
        };

        var rawItems = await DataScaffold.QueryAsync(attachMeta, query, context.RequestAborted).ConfigureAwait(false);
        var result = RentDictList();
        foreach (var item in rawItems)
        {
            if (item is BaseDataObject a)
                result.Add(BuildAttachmentApiModel(a, attachMeta));
        }

        await WriteJsonResponseAsync(context, result);
        ReturnDictList(result);
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
        var userName = UserAuth.GetUserName(user) ?? "anonymous";

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
            if (previousRaw is BaseDataObject previous)
            {
                groupId = GetMetaUInt(previous, attachMeta, "AttachmentGroupId");
                if (groupId == 0)
                    groupId = previous.Key;

                var groupQuery = new QueryDefinition
                {
                    Clauses = new List<QueryClause>
                    {
                        new QueryClause { Field = "AttachmentGroupId", Operator = QueryOperator.Equals, Value = groupId.ToString() }
                    }
                };
                var groupRaw = await DataScaffold.QueryAsync(attachMeta, groupQuery, context.RequestAborted).ConfigureAwait(false);
                foreach (var raw in groupRaw)
                {
                    if (raw is not BaseDataObject gi) continue;
                    var versionNumber = GetMetaInt(gi, attachMeta, "VersionNumber");
                    if (versionNumber >= nextVersion) nextVersion = versionNumber + 1;
                    if (GetMetaBool(gi, attachMeta, "IsCurrentVersion"))
                    {
                        attachMeta.FindField("IsCurrentVersion")?.SetValueFn(gi, false);
                        gi.Touch(userName);
                        await DataScaffold.SaveAsync(attachMeta, gi, context.RequestAborted).ConfigureAwait(false);
                    }
                }

                if (nextVersion == 1) nextVersion = 2;
            }
        }

        var attachment = attachMeta.Handlers.Create();
        attachment.CreatedBy = userName;
        attachment.UpdatedBy = userName;
        attachMeta.FindField("RecordType")?.SetValueFn(attachment, meta.Slug);
        attachMeta.FindField("RecordKey")?.SetValueFn(attachment, recordKey);
        attachMeta.FindField("FileName")?.SetValueFn(attachment, safeName);
        attachMeta.FindField("ContentType")?.SetValueFn(attachment, string.IsNullOrWhiteSpace(uploadedFile.ContentType) ? "application/octet-stream" : uploadedFile.ContentType);
        attachMeta.FindField("SizeBytes")?.SetValueFn(attachment, uploadedFile.Length);
        attachMeta.FindField("StorageKey")?.SetValueFn(attachment, storageKey);
        attachMeta.FindField("Description")?.SetValueFn(attachment, description);
        attachMeta.FindField("AttachmentGroupId")?.SetValueFn(attachment, groupId);
        attachMeta.FindField("VersionNumber")?.SetValueFn(attachment, nextVersion);
        attachMeta.FindField("IsCurrentVersion")?.SetValueFn(attachment, true);

        await DataScaffold.ApplyAutoIdAsync(attachMeta, attachment, context.RequestAborted).ConfigureAwait(false);
        await DataScaffold.SaveAsync(attachMeta, attachment, context.RequestAborted).ConfigureAwait(false);

        // If this is the root version (no group yet), set groupId = its own Key
        if (groupId == 0)
        {
            attachMeta.FindField("AttachmentGroupId")?.SetValueFn(attachment, attachment.Key);
            await DataScaffold.SaveAsync(attachMeta, attachment, context.RequestAborted).ConfigureAwait(false);
        }

        context.Response.StatusCode = StatusCodes.Status201Created;
        await WriteJsonResponseAsync(context, BuildAttachmentApiModel(attachment, attachMeta));
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
        if (raw is not BaseDataObject attachment)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Attachment not found.").ConfigureAwait(false);
            return;
        }

        var storageKey = GetMetaString(attachment, attachMeta, "StorageKey");
        if (string.IsNullOrWhiteSpace(storageKey))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Attachment not found.").ConfigureAwait(false);
            return;
        }

        // Check permission against the owning entity
        var recordType = GetMetaString(attachment, attachMeta, "RecordType");
        if (!string.IsNullOrWhiteSpace(recordType)
            && DataScaffold.TryGetEntity(recordType, out var ownerMeta)
            && !await HasEntityPermissionAsync(context, ownerMeta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.").ConfigureAwait(false);
            return;
        }

        var fullPath = ResolveUploadPath(context, storageKey);
        if (!File.Exists(fullPath))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("File not found on disk.").ConfigureAwait(false);
            return;
        }

        // Serve inline for previewable types; force download otherwise
        var ct = GetMetaString(attachment, attachMeta, "ContentType");
        if (string.IsNullOrWhiteSpace(ct))
            ct = "application/octet-stream";
        var disposition = "attachment";
        if (ct.StartsWith("image/", StringComparison.OrdinalIgnoreCase)
            || ct.StartsWith("text/plain", StringComparison.OrdinalIgnoreCase)
            || ct.Equals("application/pdf", StringComparison.OrdinalIgnoreCase))
        {
            disposition = "inline";
        }

        var fileName = GetMetaString(attachment, attachMeta, "FileName");
        context.Response.ContentType = ct;
        context.Response.Headers.ContentDisposition = $"{disposition}; filename=\"{SanitizeFileName(fileName)}\"";
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
        if (raw is not BaseDataObject attachment)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Attachment not found.").ConfigureAwait(false);
            return;
        }

        // Check permission against the owning entity
        var recordType = GetMetaString(attachment, attachMeta, "RecordType");
        if (!string.IsNullOrWhiteSpace(recordType)
            && DataScaffold.TryGetEntity(recordType, out var ownerMeta)
            && !await HasEntityPermissionAsync(context, ownerMeta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.").ConfigureAwait(false);
            return;
        }

        // Delete physical file
        var storageKey = GetMetaString(attachment, attachMeta, "StorageKey");
        if (!string.IsNullOrWhiteSpace(storageKey))
        {
            var fullPath = ResolveUploadPath(context, storageKey);
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
        if (rootRaw is not BaseDataObject root)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Attachment not found.").ConfigureAwait(false);
            return;
        }

        // Check permission against the owning entity
        var recordType = GetMetaString(root, attachMeta, "RecordType");
        if (!string.IsNullOrWhiteSpace(recordType)
            && DataScaffold.TryGetEntity(recordType, out var ownerMeta)
            && !await HasEntityPermissionAsync(context, ownerMeta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.").ConfigureAwait(false);
            return;
        }

        var groupId = GetMetaUInt(root, attachMeta, "AttachmentGroupId");
        if (groupId == 0)
            groupId = root.Key;
        var groupQuery = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "AttachmentGroupId", Operator = QueryOperator.Equals, Value = groupId.ToString() }
            }
        };

        var rawVersions = await DataScaffold.QueryAsync(attachMeta, groupQuery, context.RequestAborted).ConfigureAwait(false);

        // Collect and sort by VersionNumber ascending
        var versionList = new List<BaseDataObject>();
        foreach (var rv in rawVersions)
        {
            if (rv is BaseDataObject fa) versionList.Add(fa);
        }
        versionList.Sort((a, b) => GetMetaInt(a, attachMeta, "VersionNumber").CompareTo(GetMetaInt(b, attachMeta, "VersionNumber")));

        var result = new List<Dictionary<string, object?>>(versionList.Count);
        foreach (var v in versionList)
            result.Add(BuildAttachmentApiModel(v, attachMeta));

        await WriteJsonResponseAsync(context, result);
    }

    // ── Record comment endpoints ────────────────────────────────────────────────

    private static Dictionary<string, object?> BuildCommentApiModel(BaseDataObject c, DataEntityMetadata meta) =>
        new()
        {
            ["id"] = c.Key,
            ["text"] = GetMetaString(c, meta, "Text"),
            ["author"] = c.CreatedBy,
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
                new QueryClause { Field = "RecordType", Operator = QueryOperator.Equals, Value = meta.Slug },
                new QueryClause { Field = "RecordKey", Operator = QueryOperator.Equals, Value = recordKey.ToString() }
            }
        };

        var rawItems = await DataScaffold.QueryAsync(commentMeta, query, context.RequestAborted).ConfigureAwait(false);
        var result = RentDictList();
        foreach (var item in rawItems)
        {
            if (item is BaseDataObject c)
                result.Add(BuildCommentApiModel(c, commentMeta));
        }
        // Sort by creation time ascending (oldest first, chat-style)
        result.Sort((a, b) => ((DateTime)a["createdAt"]!).CompareTo((DateTime)b["createdAt"]!));

        await WriteJsonResponseAsync(context, result);
        ReturnDictList(result);
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
            Dictionary<string, string> doc;
            using (var jdoc = JsonDocument.Parse(body))
            {
                doc = new Dictionary<string, string>();
                foreach (var prop in jdoc.RootElement.EnumerateObject())
                    doc[prop.Name] = prop.Value.GetString() ?? "";
            }
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
        var userName = UserAuth.GetUserName(user) ?? "anonymous";
        var comment = commentMeta.Handlers.Create();
        comment.CreatedBy = userName;
        comment.UpdatedBy = userName;
        commentMeta.FindField("RecordType")?.SetValueFn(comment, meta.Slug);
        commentMeta.FindField("RecordKey")?.SetValueFn(comment, recordKey);
        commentMeta.FindField("Text")?.SetValueFn(comment, text.Trim());

        await DataScaffold.ApplyAutoIdAsync(commentMeta, comment, context.RequestAborted).ConfigureAwait(false);
        await DataScaffold.SaveAsync(commentMeta, comment, context.RequestAborted).ConfigureAwait(false);

        context.Response.StatusCode = StatusCodes.Status201Created;
        await WriteJsonResponseAsync(context, BuildCommentApiModel(comment, commentMeta));
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
        if (existing is not BaseDataObject comment)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Comment not found.").ConfigureAwait(false);
            return;
        }

        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
        var userName = UserAuth.GetUserName(user) ?? "anonymous";
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
            Dictionary<string, string> doc;
            using (var jdoc = JsonDocument.Parse(body))
            {
                doc = new Dictionary<string, string>();
                foreach (var prop in jdoc.RootElement.EnumerateObject())
                    doc[prop.Name] = prop.Value.GetString() ?? "";
            }
            text = doc?.GetValueOrDefault("text");
        }

        if (string.IsNullOrWhiteSpace(text))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Comment text is required.").ConfigureAwait(false);
            return;
        }

        commentMeta.FindField("Text")?.SetValueFn(comment, text.Trim());
        comment.Touch(userName);
        await DataScaffold.SaveAsync(commentMeta, comment, context.RequestAborted).ConfigureAwait(false);

        await WriteJsonResponseAsync(context, BuildCommentApiModel(comment, commentMeta));
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
        if (existing is not BaseDataObject comment)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Comment not found.").ConfigureAwait(false);
            return;
        }

        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
        var userName = UserAuth.GetUserName(user) ?? "anonymous";
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
        var userPermissions = UserAuth.GetPermissions(user);

        var groups = new List<Dictionary<string, object?>>();

        foreach (var entityMeta in DataScaffold.Entities)
        {
            if (!string.IsNullOrEmpty(entityMeta.Permissions) && !userPermissions.Contains(entityMeta.Permissions))
                continue;

            // Build OR-group of Contains clauses for each searchable string list field
            var listFieldsArr = entityMeta.ListFields;
            var stringListFields = new List<DataFieldMetadata>(listFieldsArr.Length);
            foreach (var f in listFieldsArr)
            {
                if (f.FieldType is FormFieldType.String
                                or FormFieldType.TextArea
                                or FormFieldType.Email
                                or FormFieldType.Link
                                or FormFieldType.Tags
                                or FormFieldType.Markdown)
                    stringListFields.Add(f);
            }

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
        var responseTiming = ResponseTimingMetrics.GetSnapshot();
        var gcInfo = GC.GetGCMemoryInfo();
        var payload = new Dictionary<string, object?>
        {
            // ── Request metrics ──
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

            // ── Subsystem timers — since start ──
            ["routeDispatchCount"] = snapshot.RouteDispatchCount,
            ["routeDispatchAvgMs"] = snapshot.RouteDispatchAverage.TotalMilliseconds,
            ["walReadCount"] = snapshot.WalReadCount,
            ["walReadAvgMs"] = snapshot.WalReadAverage.TotalMilliseconds,
            ["uiRenderCount"] = snapshot.UiRenderCount,
            ["uiRenderAvgMs"] = snapshot.UiRenderAverage.TotalMilliseconds,
            ["serializationCount"] = snapshot.SerializationCount,
            ["serializationAvgMs"] = snapshot.SerializationAverage.TotalMilliseconds,

            // ── Subsystem timers — last 5 minutes ──
            ["routeDispatchRecentCount"] = snapshot.RouteDispatchRecentCount,
            ["routeDispatchRecentAvgMs"] = snapshot.RouteDispatchRecentAverage.TotalMilliseconds,
            ["walReadRecentCount"] = snapshot.WalReadRecentCount,
            ["walReadRecentAvgMs"] = snapshot.WalReadRecentAverage.TotalMilliseconds,
            ["uiRenderRecentCount"] = snapshot.UiRenderRecentCount,
            ["uiRenderRecentAvgMs"] = snapshot.UiRenderRecentAverage.TotalMilliseconds,
            ["serializationRecentCount"] = snapshot.SerializationRecentCount,
            ["serializationRecentAvgMs"] = snapshot.SerializationRecentAverage.TotalMilliseconds,

            // ── Subsystem timers — last observed call ──
            ["routeDispatchLastMs"] = snapshot.RouteDispatchLast.TotalMilliseconds,
            ["walReadLastMs"] = snapshot.WalReadLast.TotalMilliseconds,
            ["uiRenderLastMs"] = snapshot.UiRenderLast.TotalMilliseconds,
            ["serializationLastMs"] = snapshot.SerializationLast.TotalMilliseconds,

            // ── Response write stage timings (recent 5m window) ──
            ["responseTimingSampleCount"] = responseTiming.SampleCount,
            ["responseTimingParseToFirstAvgMs"] = responseTiming.ParseToFirst.Average.TotalMilliseconds,
            ["responseTimingParseToFirstP95Ms"] = responseTiming.ParseToFirst.P95.TotalMilliseconds,
            ["responseTimingParseToFirstMaxMs"] = responseTiming.ParseToFirst.Max.TotalMilliseconds,
            ["responseTimingFirstToFlushStartAvgMs"] = responseTiming.FirstToFlushStart.Average.TotalMilliseconds,
            ["responseTimingFirstToFlushStartP95Ms"] = responseTiming.FirstToFlushStart.P95.TotalMilliseconds,
            ["responseTimingFirstToFlushStartMaxMs"] = responseTiming.FirstToFlushStart.Max.TotalMilliseconds,
            ["responseTimingFlushAwaitAvgMs"] = responseTiming.FlushAwait.Average.TotalMilliseconds,
            ["responseTimingFlushAwaitP95Ms"] = responseTiming.FlushAwait.P95.TotalMilliseconds,
            ["responseTimingFlushAwaitMaxMs"] = responseTiming.FlushAwait.Max.TotalMilliseconds,
            ["responseTimingFirstToFlushAvgMs"] = responseTiming.FirstToFlush.Average.TotalMilliseconds,
            ["responseTimingFirstToFlushP95Ms"] = responseTiming.FirstToFlush.P95.TotalMilliseconds,
            ["responseTimingFirstToFlushMaxMs"] = responseTiming.FirstToFlush.Max.TotalMilliseconds,

            // ── GC / Heap metrics ──
            ["gcGen0Collections"] = snapshot.GcGen0Collections,
            ["gcGen1Collections"] = snapshot.GcGen1Collections,
            ["gcGen2Collections"] = snapshot.GcGen2Collections,
            ["gcTotalAllocatedBytes"] = snapshot.GcTotalAllocatedBytes,
            ["gcHeapSizeBytes"] = GC.GetTotalMemory(false),
            ["gcFragmentedBytes"] = gcInfo.FragmentedBytes,
            ["gcHighMemoryLoadThresholdBytes"] = gcInfo.HighMemoryLoadThresholdBytes,
            ["gcMemoryLoadBytes"] = gcInfo.MemoryLoadBytes,
            ["gcTotalAvailableMemoryBytes"] = gcInfo.TotalAvailableMemoryBytes,
            ["gcPauseTimePercentage"] = gcInfo.PauseTimePercentage,
            ["gcConcurrent"] = gcInfo.Concurrent,
            ["gcCompacted"] = gcInfo.Compacted,

            // ── Process / Platform ──
            ["processUptimeSeconds"] = (long)snapshot.ProcessUptime.TotalSeconds,
            ["processId"] = snapshot.ProcessId,
            ["workingSet64"] = snapshot.WorkingSet64,
            ["virtualMemorySize64"] = snapshot.VirtualMemorySize64,
            ["operatingSystem"] = RuntimeInformation.OSDescription,
            ["osArchitecture"] = RuntimeInformation.OSArchitecture.ToString(),
            ["processArchitecture"] = RuntimeInformation.ProcessArchitecture.ToString(),
            ["processorCount"] = Environment.ProcessorCount,
            ["cpuModel"] = GetCpuModel(),
            ["totalMemoryMb"] = gcInfo.TotalAvailableMemoryBytes / (1024 * 1024),
            ["storageFreeGb"] = GetStorageFreeGb(),
            ["storageTotalGb"] = GetStorageTotalGb(),
            ["dotnetRuntime"] = RuntimeInformation.FrameworkDescription,
            ["simdTier"] = BareMetalWeb.Data.SimdCapabilities.Current.BestTier,
            ["dataLocation"] = MetricsTracker.DataRoot,
        };

        // ── Cluster / Lease ──
        var clusterSnapshot = MetricsTracker.ClusterState?.GetSnapshot();
        if (clusterSnapshot != null)
        {
            payload["clusterInstanceId"] = clusterSnapshot.InstanceId;
            payload["clusterRole"] = clusterSnapshot.Role.ToString().ToLowerInvariant();
            payload["clusterIsLeader"] = clusterSnapshot.Role == BareMetalWeb.Data.ClusterRole.Leader;
            payload["clusterLeaseValid"] = clusterSnapshot.IsLeaseValid;
            payload["clusterEpoch"] = clusterSnapshot.Epoch;
            payload["clusterLastLsn"] = clusterSnapshot.LastLsn;
        }

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

    /// <summary>
    /// JSON API endpoint for the VNext SPA to start a sample-data background job.
    /// Accepts a JSON body: { entities: { "entity-slug": count, ... }, clearExisting: bool }
    /// Returns 202 Accepted with job info.
    /// </summary>
    public async ValueTask AdminSampleDataJsonHandler(BmwContext context)
    {
        if (await BinaryApiHandlers.RejectInvalidContentTypeAsync(context).ConfigureAwait(false))
            return;

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
            await using (var w = new Utf8JsonWriter(context.Response.Body))
            {
                w.WriteStartObject();
                w.WriteString("error", string.Join(" ", errors));
                w.WriteEndObject();
            }
            return;
        }

        var userName = UserAuth.GetUserName(await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false)) ?? "system";

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

                    var rng = Random.Shared;
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

        var statusUri = $"/api/jobs/{jobId}";
        context.Response.StatusCode = StatusCodes.Status202Accepted;
        context.Response.Headers["Location"] = statusUri;
        context.Response.Headers["Retry-After"] = "2";
        context.Response.ContentType = "application/json";
        await using (var w = new Utf8JsonWriter(context.Response.Body))
        {
            w.WriteStartObject();
            w.WriteString("jobId", jobId);
            w.WriteString("status", "queued");
            w.WriteString("operationName", "Generate Sample Data");
            w.WriteString("statusUrl", statusUri);
            w.WriteEndObject();
        }
    }

    /// <summary>
    /// JSON API endpoint for the VNext SPA to start a wipe-all-data background job.
    /// Accepts a JSON body: { confirmToken }
    /// Returns 202 Accepted with job info.
    /// </summary>
    public async ValueTask AdminWipeDataJsonHandler(BmwContext context)
    {
        if (await BinaryApiHandlers.RejectInvalidContentTypeAsync(context).ConfigureAwait(false))
            return;

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

        var statusUri = $"/api/jobs/{jobId}";
        context.Response.StatusCode = StatusCodes.Status202Accepted;
        context.Response.Headers["Location"] = statusUri;
        context.Response.Headers["Retry-After"] = "2";
        context.Response.ContentType = "application/json";
        await using (var w = new Utf8JsonWriter(context.Response.Body))
        {
            w.WriteStartObject();
            w.WriteString("jobId", jobId);
            w.WriteString("status", "queued");
            w.WriteString("operationName", "Wipe All Data");
            w.WriteString("statusUrl", statusUri);
            w.WriteEndObject();
        }
    }

    /// <summary>
    /// GET /api/admin/query-plans — returns the in-memory query plan history as JSON.
    /// Each entry includes timing, steps, and missing-index recommendations.
    /// </summary>
    public async ValueTask QueryPlanHistoryHandler(BmwContext context)
    {
        var entries = QueryPlanHistory.GetSnapshot();

        var payload = RentDictList();
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
        ReturnDictList(payload);
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
            var existingDefsRaw = (await DataStoreProvider.Current.QueryAsync("EntityDefinition", null, ctx.RequestAborted)
                .ConfigureAwait(false)).Cast<EntityDefinition>();
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

        var messages = RentStringList();
        var deployed = await SampleGalleryService.DeployPackageAsync(
            pkg,
            DataStoreProvider.Current,
            overwrite: false,
            msg => messages.Add(msg),
            context.RequestAborted)
            .ConfigureAwait(false);
        ReturnStringList(messages);

        // Hot-reload the entity registry so deployed entities are immediately usable
        if (deployed.Count > 0)
        {
            try
            {
                await RuntimeEntityRegistry.RebuildAsync().ConfigureAwait(false);
                MetadataCompiler.CompileAndSwap(DataScaffold.Entities);
                PermissionResolver.Invalidate();
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

    // ── Webstore: browse + install remote templates from control plane ───────

    public async ValueTask WebStoreHandler(BmwContext context)
    {
        await BuildPageHandler(async ctx =>
        {
            var sb = new StringBuilder(4096);
            sb.Append("<h4><i class=\"bi bi-shop me-2\"></i>Template Webstore</h4>");

            if (WebStoreClient is null || !WebStoreClient.IsConfigured)
            {
                sb.Append("<div class=\"alert alert-info\">Webstore is not configured. Set <code>ControlPlane.Url</code> and <code>ControlPlane.ApiKey</code> in Metal.config to browse shared templates.</div>");
                ctx.SetStringValue("title", "Template Webstore");
                ctx.SetStringValue("html_message", sb.ToString());
                return;
            }

            // Fetch remote listings
            var listings = await WebStoreClient.GetGalleryListingsAsync(
                "/api/data/GalleryTemplate").ConfigureAwait(false);

            if (listings is null || listings.Count == 0)
            {
                sb.Append("<div class=\"alert alert-secondary\">No templates available on the control plane. Publish packages to the <code>GalleryTemplate</code> entity on the control plane to make them available here.</div>");
                ctx.SetStringValue("title", "Template Webstore");
                ctx.SetStringValue("html_message", sb.ToString());
                return;
            }

            // Check which are already deployed locally
            var existingDefs = (await DataStoreProvider.Current
                .QueryAsync("EntityDefinition", null, ctx.RequestAborted).ConfigureAwait(false)).Cast<EntityDefinition>();
            var existingSlugs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var def in existingDefs)
            {
                var slug = def.Slug ?? string.Empty;
                if (slug.Length > 0) existingSlugs.Add(slug);
            }

            sb.Append("<p class=\"text-muted\">Browse and install shared templates from the central control plane.</p>");
            sb.Append("<div class=\"row g-3\">");

            var csrfToken = CsrfProtection.EnsureToken(ctx);

            foreach (var listing in listings)
            {
                var slug = listing.Slug ?? string.Empty;
                var isDeployed = existingSlugs.Contains(slug);
                var badgeClass = isDeployed ? "bg-success" : "bg-secondary";
                var badgeLabel = isDeployed ? "Installed" : "Available";
                var btnClass = isDeployed ? "btn-outline-secondary" : "btn-primary";
                var btnLabel = isDeployed ? "Re-install" : "Install";

                sb.Append("<div class=\"col-md-6 col-lg-4\">");
                sb.Append("<div class=\"card h-100\">");
                sb.Append("<div class=\"card-body\">");
                sb.Append($"<h5 class=\"card-title\"><i class=\"bi {WebUtility.HtmlEncode(listing.Icon ?? "bi-box")} me-2\"></i>{WebUtility.HtmlEncode(listing.Name ?? slug)}</h5>");
                if (!string.IsNullOrEmpty(listing.Author))
                    sb.Append($"<p class=\"text-muted small mb-1\">by {WebUtility.HtmlEncode(listing.Author)}</p>");
                sb.Append($"<p class=\"card-text text-muted small\">{WebUtility.HtmlEncode(listing.Description ?? "")}</p>");
                sb.Append($"<p><span class=\"badge {badgeClass}\">{badgeLabel}</span>");
                if (!string.IsNullOrEmpty(listing.Version))
                    sb.Append($" <span class=\"badge bg-light text-dark\">v{WebUtility.HtmlEncode(listing.Version)}</span>");
                sb.Append($" <span class=\"text-muted small\">{listing.EntityCount} entit{(listing.EntityCount == 1 ? "y" : "ies")}, {listing.FieldCount} field{(listing.FieldCount == 1 ? "" : "s")}</span>");
                if (listing.Downloads > 0)
                    sb.Append($" <span class=\"text-muted small\">· {listing.Downloads} install{(listing.Downloads == 1 ? "" : "s")}</span>");
                sb.Append("</p>");
                sb.Append($"<form method=\"post\" action=\"/admin/webstore/install/{WebUtility.HtmlEncode(slug)}\">");
                sb.Append($"<input type=\"hidden\" name=\"{CsrfProtection.FormFieldName}\" value=\"{WebUtility.HtmlEncode(csrfToken)}\">");
                sb.Append($"<button type=\"submit\" class=\"btn {btnClass} btn-sm\">{btnLabel}</button>");
                sb.Append("</form>");
                sb.Append("</div></div></div>");
            }

            sb.Append("</div>");
            ctx.SetStringValue("title", "Template Webstore");
            ctx.SetStringValue("html_message", sb.ToString());
        })(context);
    }

    public async ValueTask WebStoreInstallHandler(BmwContext context)
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
                ctx.SetStringValue("title", "Template Webstore");
                ctx.SetStringValue("html_message", "<div class=\"alert alert-danger\">Invalid security token. Please try again.</div>");
            })(context);
            return;
        }

        if (WebStoreClient is null || !WebStoreClient.IsConfigured)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await context.Response.WriteAsync("Webstore not configured.");
            return;
        }

        // Fetch the full package JSON from the control plane
        var packageJson = await WebStoreClient.GetRawAsync(
            $"/api/data/GalleryTemplate/{WebUtility.UrlEncode(packageSlug)}/package")
            .ConfigureAwait(false);

        if (string.IsNullOrEmpty(packageJson))
        {
            await BuildPageHandler(ctx =>
            {
                ctx.SetStringValue("title", "Template Webstore");
                ctx.SetStringValue("html_message", $"<div class=\"alert alert-danger\">Package '{WebUtility.HtmlEncode(packageSlug)}' not found on control plane.</div>");
            })(context);
            return;
        }

        // Deserialize using manual JSON reader (no JsonSerializer)
        SamplePackage? pkg;
        try
        {
            pkg = SamplePackageJson.Deserialize(packageJson);
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Webstore|deserialize-failed|{packageSlug}", ex);
            await BuildPageHandler(ctx =>
            {
                ctx.SetStringValue("title", "Template Webstore");
                ctx.SetStringValue("html_message", $"<div class=\"alert alert-danger\">Failed to parse package '{WebUtility.HtmlEncode(packageSlug)}': {WebUtility.HtmlEncode(ex.Message)}</div>");
            })(context);
            return;
        }

        if (pkg is null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Invalid package data.");
            return;
        }

        // Deploy using existing gallery infrastructure
        var messages = RentStringList();
        var deployed = await SampleGalleryService.DeployPackageAsync(
            pkg,
            DataStoreProvider.Current,
            overwrite: false,
            msg => messages.Add(msg),
            context.RequestAborted)
            .ConfigureAwait(false);
        ReturnStringList(messages);

        // Hot-reload
        if (deployed.Count > 0)
        {
            try
            {
                await RuntimeEntityRegistry.RebuildAsync().ConfigureAwait(false);
                MetadataCompiler.CompileAndSwap(DataScaffold.Entities);
                PermissionResolver.Invalidate();
                _logger?.LogInfo($"Webstore|installed|{packageSlug}|entities={deployed.Count}|registry-rebuilt");
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Webstore|rebuild-failed|{packageSlug}", ex);
            }
        }

        context.Response.Redirect("/admin/webstore");
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

        const int maxLines = 2000;
        var truncated = false;
        var lines = RentStringBuilder(4096);
        try
        {
        var count = 0;
        try
        {
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
        }
        catch (FileNotFoundException)
        {
            html.Append("<p class=\"text-danger mb-0\">Log file not found.</p>");
            return html.ToString();
        }
        catch (DirectoryNotFoundException)
        {
            html.Append("<p class=\"text-danger mb-0\">Log file not found.</p>");
            return html.ToString();
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

    // Export helper methods for nested/embedded components

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

        var userPermissions = RentPermissionSet(UserAuth.GetPermissions(user));
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

    /// <summary>
    /// Checks whether the current user (if a role-restricted <see cref="SystemPrincipal"/>)
    /// is allowed to perform <paramref name="action"/> on the entity identified by <paramref name="meta"/>.
    /// Returns true when the action is permitted (or the user is not a restricted principal).
    /// On denial, sets 403 status, writes the reason, and fires an audit entry.
    /// </summary>
    private async ValueTask<bool> CheckPrincipalRolePolicyAsync(
        BmwContext context, DataEntityMetadata meta, string action, CancellationToken cancellationToken)
    {
        var user = await UserAuth.GetRequestUserAsync(context, cancellationToken).ConfigureAwait(false);
        var restricted = PrincipalAuthorizationPolicy.AsRestrictedPrincipal(user);
        if (restricted == null)
            return true; // not a restricted principal

        var denial = PrincipalAuthorizationPolicy.CheckEntityAction(restricted, meta.Slug, action);
        if (denial == null)
            return true;

        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        await context.Response.WriteAsync(denial);
        await _auditService.AuditDeniedAsync(
            meta.Slug, 0, action, UserAuth.GetUserName(restricted) ?? restricted.Key.ToString(),
            denial, cancellationToken).ConfigureAwait(false);
        return false;
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

    /// <summary>Parse a single CSV line into an array of field values, respecting quoted fields.</summary>
    private static string[] ParseCsvLine(string line)
    {
        var fields = new List<string>();
        var field = new StringBuilder(64);
        bool inQuotes = false;

        for (int i = 0; i < line.Length; i++)
        {
            var ch = line[i];
            if (inQuotes)
            {
                if (ch == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"')
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
            }
            else if (ch == '"')
            {
                inQuotes = true;
            }
            else if (ch == ',')
            {
                fields.Add(field.ToString());
                field.Clear();
            }
            else if (ch != '\r')
            {
                field.Append(ch);
            }
        }
        fields.Add(field.ToString());
        return fields.ToArray();
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

    private static void WriteJobSnapshot(Utf8JsonWriter w, string jobId, string operationName,
        string status, int percentComplete, string? description,
        string startedAt, string? completedAt, string? error, string? resultUrl,
        string? instanceId = null)
    {
        w.WriteStartObject();
        w.WriteString("jobId", jobId);
        w.WriteString("operationName", operationName);
        w.WriteString("status", status);
        w.WriteNumber("percentComplete", percentComplete);
        w.WriteString("description", description);
        w.WriteString("startedAt", startedAt);
        if (completedAt != null) w.WriteString("completedAt", completedAt); else w.WriteNull("completedAt");
        if (error != null) w.WriteString("error", error); else w.WriteNull("error");
        if (resultUrl != null) w.WriteString("resultUrl", resultUrl); else w.WriteNull("resultUrl");
        w.WriteString("instanceId", instanceId ?? string.Empty);
        w.WriteEndObject();
    }

    private static async ValueTask ValidateUserUniquenessAsync(DataEntityMetadata meta, object instance, string? excludeId, List<string> errors, CancellationToken cancellationToken)
    {
        if (string.Equals(meta.Slug, "app-settings", StringComparison.OrdinalIgnoreCase)
            || string.Equals(meta.Slug, "settings", StringComparison.OrdinalIgnoreCase))
        {
            if (instance is BaseDataObject setting)
            {
                var settingId = meta.FindField("SettingId")?.GetValueFn(setting)?.ToString();
                if (!string.IsNullOrWhiteSpace(settingId))
                {
                    var query = new QueryDefinition
                    {
                        Clauses = new List<QueryClause>
                        {
                            new() { Field = "SettingId", Operator = QueryOperator.Equals, Value = settingId }
                        },
                        Top = 1
                    };
                    var existingResults = await DataScaffold.QueryAsync(meta, query, cancellationToken).ConfigureAwait(false);
                    BaseDataObject? existing = null;
                    foreach (var e in existingResults)
                    {
                        if (e is BaseDataObject existingSetting)
                        {
                            existing = existingSetting;
                            break;
                        }
                    }
                    if (existing != null && !string.Equals(existing.Key.ToString(), excludeId, StringComparison.OrdinalIgnoreCase))
                        errors.Add("A setting with this Setting ID already exists.");
                }
            }
            return;
        }

        var userMeta = UserAuthHelper.GetUserMeta();
        if (userMeta == null || !string.Equals(meta.Slug, userMeta.Slug, StringComparison.OrdinalIgnoreCase))
            return;

        if (instance is not BaseDataObject user)
            return;

        var userName = UserAuth.GetUserName(user);
        if (!string.IsNullOrWhiteSpace(userName))
        {
            var existing = await UserAuthHelper.FindUserByUserNameAsync(userName, cancellationToken).ConfigureAwait(false);
            if (existing != null && !string.Equals(existing.Key.ToString(), excludeId, StringComparison.OrdinalIgnoreCase))
                errors.Add("Username is already taken.");
        }

        var email = UserAuth.GetEmail(user);
        if (!string.IsNullOrWhiteSpace(email))
        {
            var existing = await UserAuthHelper.FindUserByEmailAsync(email, cancellationToken).ConfigureAwait(false);
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

        if (!uint.TryParse(challengeId, out var parsedChallengeId))
            return null;

        var challenge = (MfaChallenge?)(await DataStoreProvider.Current.LoadAsync("MfaChallenge", parsedChallengeId, cancellationToken).ConfigureAwait(false));
        if (challenge == null || challenge.IsExpired())
        {
            if (challenge != null)
            {
                challenge.IsUsed = true;
                await DataStoreProvider.Current.SaveAsync(challenge.EntityTypeName, challenge, cancellationToken).ConfigureAwait(false);
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
                new QueryClause { Field = "Permissions", Operator = QueryOperator.Contains, Value = "admin" },
                new QueryClause { Field = "Permissions", Operator = QueryOperator.Contains, Value = "monitoring" }
            }
        };

        var users = await UserAuth.QueryUsersAsync(query, cancellationToken).ConfigureAwait(false);
        bool hasUsers = false;
        foreach (var _ in users)
        {
            hasUsers = true;
            break;
        }
        return hasUsers;
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
            var value = nameField.GetValueFn(item)?.ToString();
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
            var value = displayField.GetValueFn(item)?.ToString();
            if (!string.IsNullOrWhiteSpace(value))
                return value;
        }

        // Last resort: ID
        return DataScaffold.GetIdValue(item) ?? "Unknown";
    }

    public async ValueTask DataCommandHandler(BmwContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        var id = GetRouteValue(context, "id");
        var commandName = GetRouteValue(context, "command");
        if (meta == null || string.IsNullOrWhiteSpace(id) || string.IsNullOrWhiteSpace(commandName))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await WriteJsonResponseAsync(context, new Dictionary<string, object?> { ["success"] = false, ["message"] = errorMessage ?? "Not found." });
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
            await WriteJsonResponseAsync(context, new Dictionary<string, object?> { ["success"] = false, ["message"] = $"Command '{commandName}' not found." });
            return;
        }

        // Permission check
        if (!cmd.OverrideEntityPermissions)
        {
            if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await WriteJsonResponseAsync(context, new Dictionary<string, object?> { ["success"] = false, ["message"] = "Access denied." });
                return;
            }
        }

        if (!await UserAuth.HasValidApiKeyAsync(context, context.RequestAborted).ConfigureAwait(false) &&
            (!ValidateApiCsrfHeader(context) || !CsrfProtection.ValidateApiToken(context)))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await WriteJsonResponseAsync(context, new Dictionary<string, object?> { ["success"] = false, ["message"] = "CSRF validation failed." });
            return;
        }

        if (!string.IsNullOrEmpty(cmd.Permission))
        {
            var user = await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false);
            bool hasPermission = false;
            if (user != null)
            {
                foreach (var perm in UserAuth.GetPermissions(user))
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
                await WriteJsonResponseAsync(context, new Dictionary<string, object?> { ["success"] = false, ["message"] = "Insufficient permissions." });
                return;
            }
        }

        if (!uint.TryParse(id, out var parsedId))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await WriteJsonResponseAsync(context, new Dictionary<string, object?> { ["success"] = false, ["message"] = "Invalid entity id." });
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, parsedId);
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await WriteJsonResponseAsync(context, new Dictionary<string, object?> { ["success"] = false, ["message"] = "Item not found." });
            return;
        }

        try
        {
            var userName = UserAuth.GetUserName(await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false)) ?? "system";

            // Runtime-defined actions have Invoker == null; delegate to CommandService
            if (cmd.Invoker == null)
            {
                var svc = new CommandService();
                var intent = new CommandIntent
                {
                    EntitySlug = meta.Slug,
                    EntityId = id,
                    Operation = commandName,
                    Fields = new Dictionary<string, string?>()
                };
                var cmdResult = await svc.ExecuteAsync(intent, context.RequestAborted).ConfigureAwait(false);

                var msg = cmdResult.Success ? "Command executed." : cmdResult.Error;

                if (instance is BaseDataObject bdoRuntime)
                    await _auditService.AuditRemoteCommandAsync(meta.Name, bdoRuntime, commandName, userName, null,
                        new RemoteCommandResult(cmdResult.Success, msg ?? string.Empty),
                        context.RequestAborted).ConfigureAwait(false);

                context.Response.StatusCode = cmdResult.Success ? StatusCodes.Status200OK : StatusCodes.Status422UnprocessableEntity;
                await WriteJsonResponseAsync(context, new Dictionary<string, object?>
                {
                    ["success"] = cmdResult.Success,
                    ["message"] = msg,
                    ["data"] = cmdResult.Success ? cmdResult.Data : null
                });
                return;
            }

            RemoteCommandResult result;
            result = await cmd.Invoker(instance).ConfigureAwait(false);

            // Save the entity in case the command modified it
            await DataScaffold.ApplyComputedFieldsAsync(meta, (BaseDataObject)instance, ComputedTrigger.OnUpdate, context.RequestAborted).ConfigureAwait(false);
            DataScaffold.ApplyCalculatedFields(meta, (BaseDataObject)instance);
            await DataScaffold.SaveAsync(meta, instance);

            // Audit the remote command execution
            if (instance is BaseDataObject baseDataObject)
            {
                await _auditService.AuditRemoteCommandAsync(meta.Name, baseDataObject, commandName, userName, null, result, context.RequestAborted).ConfigureAwait(false);
            }

            context.Response.StatusCode = result.Success ? StatusCodes.Status200OK : StatusCodes.Status422UnprocessableEntity;
            var entityData = result.Success ? BuildApiModel(meta, instance) : null;
            await WriteJsonResponseAsync(context, new Dictionary<string, object?> { ["success"] = result.Success, ["message"] = result.Message, ["redirectUrl"] = result.RedirectUrl, ["data"] = entityData });
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[DataCommandHandler] Command '{commandName}' on '{meta.Slug}/{id}' failed: {ex}");
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await WriteJsonResponseAsync(context, new Dictionary<string, object?> { ["success"] = false, ["message"] = $"Command failed: {ex.Message}" });
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
                html.Append($"<td><a href=\"/{WebUtility.HtmlEncode(slug)}\">{WebUtility.HtmlEncode(name)}</a></td>");
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

        await using (var w = new Utf8JsonWriter(context.Response.Body))
        {
            WriteJobSnapshot(w, snapshot.JobId, snapshot.OperationName, statusStr,
                snapshot.PercentComplete, snapshot.Description,
                snapshot.StartedAt.ToString("O"), snapshot.CompletedAt?.ToString("O"),
                snapshot.Error, snapshot.ResultUrl, snapshot.InstanceId);
        }
    }

    /// <summary>
    /// GET /api/jobs
    /// Returns all tracked background jobs (active and recently completed) as a JSON array.
    /// Merges in-memory jobs (this instance) with WAL-persisted jobs (all instances).
    /// </summary>
    public async ValueTask JobsListHandler(BmwContext context)
    {
        var cutoff = DateTime.UtcNow - BackgroundJobService.RetentionPeriod;

        // In-memory jobs from this instance (freshest data for local jobs).
        var localJobs = BackgroundJobService.Instance.GetAllJobs();
        var mergedById = new Dictionary<string, JobStatusSnapshot>(
            localJobs.Count + 64, StringComparer.OrdinalIgnoreCase);
        foreach (var j in localJobs)
            mergedById[j.JobId] = j;

        // WAL-persisted jobs from all instances — provides cross-instance visibility.
        try
        {
            var walJobs = (await DataStoreProvider.Current
                .QueryAsync("WalPersistedJob", null, context.RequestAborted)
                .ConfigureAwait(false)).Cast<WalPersistedJob>();

            foreach (var walJob in walJobs)
            {
                if (walJob.StartedAtUtc < cutoff) continue; // skip expired
                if (mergedById.ContainsKey(walJob.JobId)) continue; // local copy is fresher

                var walStatus = walJob.Status switch
                {
                    "queued"    => BackgroundJobStatus.Queued,
                    "running"   => BackgroundJobStatus.Running,
                    "succeeded" => BackgroundJobStatus.Succeeded,
                    "failed"    => BackgroundJobStatus.Failed,
                    _           => BackgroundJobStatus.Failed
                };

                mergedById[walJob.JobId] = new JobStatusSnapshot(
                    walJob.JobId,
                    walJob.OperationName,
                    walStatus,
                    walJob.PercentComplete,
                    walJob.Description,
                    walJob.StartedAtUtc,
                    walJob.CompletedAtUtc,
                    walJob.Error,
                    walJob.ResultUrl,
                    walJob.InstanceId);
            }
        }
        catch
        {
            // WAL query failure is non-fatal; fall back to local in-memory jobs.
        }

        var jobsList = new List<JobStatusSnapshot>(mergedById.Values);
        jobsList.Sort((a, b) => b.StartedAt.CompareTo(a.StartedAt));
        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "application/json";
        await using (var w = new Utf8JsonWriter(context.Response.Body))
        {
            w.WriteStartArray();
            for (int ji = 0; ji < jobsList.Count; ji++)
            {
                var snapshot = jobsList[ji];
                var statusStr = snapshot.Status switch
                {
                    BackgroundJobStatus.Queued    => "queued",
                    BackgroundJobStatus.Running   => "running",
                    BackgroundJobStatus.Succeeded => "succeeded",
                    BackgroundJobStatus.Failed    => "failed",
                    _                             => "unknown"
                };
                WriteJobSnapshot(w, snapshot.JobId, snapshot.OperationName, statusStr,
                    snapshot.PercentComplete, snapshot.Description,
                    snapshot.StartedAt.ToString("O"), snapshot.CompletedAt?.ToString("O"),
                    snapshot.Error, snapshot.ResultUrl, snapshot.InstanceId);
            }
            w.WriteEndArray();
        }
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

    private static string GetCpuModel()
    {
        try
        {
            if (OperatingSystem.IsLinux() && File.Exists("/proc/cpuinfo"))
            {
                string? modelName = null;
                string? model = null;
                foreach (var line in File.ReadLines("/proc/cpuinfo"))
                {
                    if (line.StartsWith("model name", StringComparison.OrdinalIgnoreCase))
                    {
                        var idx = line.IndexOf(':');
                        if (idx >= 0) { modelName = line[(idx + 1)..].Trim(); break; }
                    }
                    else if (model == null && line.StartsWith("Model", StringComparison.OrdinalIgnoreCase)
                             && !line.StartsWith("model name", StringComparison.OrdinalIgnoreCase))
                    {
                        var idx = line.IndexOf(':');
                        if (idx >= 0) model = line[(idx + 1)..].Trim();
                    }
                }
                if (!string.IsNullOrEmpty(modelName)) return modelName;
                if (!string.IsNullOrEmpty(model)) return model;
            }
        }
        catch { }
        return RuntimeInformation.ProcessArchitecture.ToString();
    }

    private static long GetStorageFreeGb()
    {
        try { return new DriveInfo(Path.GetPathRoot(Environment.CurrentDirectory) ?? "/").AvailableFreeSpace / (1024 * 1024 * 1024); }
        catch { return -1; }
    }

    private static long GetStorageTotalGb()
    {
        try { return new DriveInfo(Path.GetPathRoot(Environment.CurrentDirectory) ?? "/").TotalSize / (1024 * 1024 * 1024); }
        catch { return -1; }
    }

    private sealed class SetupRegistrationInput
    {
        public bool Enabled { get; init; }
        public string CallbackUrl { get; init; } = string.Empty;
        public string PrincipalName { get; init; } = DefaultManagementPrincipalName;
        public string TenantId { get; init; } = string.Empty;
        public string ClientId { get; init; } = string.Empty;
    }

    private sealed class SetupRegistrationRequest
    {
        public string InstanceId { get; init; } = string.Empty;
        public string PrincipalName { get; init; } = string.Empty;
        public string PrincipalApiKey { get; init; } = string.Empty;
        public string TenantId { get; init; } = string.Empty;
        public string ClientId { get; init; } = string.Empty;
        public string RegisteredBy { get; init; } = string.Empty;
        public string RegisteredAtUtc { get; init; } = string.Empty;
    }

    private sealed class SetupRegistrationResult
    {
        public bool Success { get; }
        public string Message { get; }
        public string PrincipalName { get; }

        public SetupRegistrationResult(bool success, string message, string principalName)
        {
            Success = success;
            Message = message;
            PrincipalName = principalName;
        }
    }
}
