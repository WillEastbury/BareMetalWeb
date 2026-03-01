using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.IO.Compression;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;
using BareMetalWeb.UserClasses.DataObjects;
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
    private readonly IReadOnlyList<(string SettingId, string Value, string Description)> _settingDefaults;
    private const string MfaChallengeCookieName = "mfa_challenge_id";
    private static readonly TimeSpan MfaPendingLifetime = TimeSpan.FromMinutes(5);
    private const int MfaPendingMaxFailures = 5;
    private const int MfaChallengeMaxFailures = 6;
    private static readonly TimeSpan MfaAttemptWindow = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MfaBaseBlockDuration = TimeSpan.FromSeconds(10);
    private static readonly ConcurrentDictionary<string, AttemptTracker> MfaAttempts = new(StringComparer.Ordinal);

    public RouteHandlers(IHtmlRenderer renderer, ITemplateStore templateStore, bool allowAccountCreation, string mfaKeyRootFolder, AuditService auditService,
        IReadOnlyList<(string SettingId, string Value, string Description)>? settingDefaults = null)
    {
        _renderer = renderer;
        _templateStore = templateStore;
        _allowAccountCreation = allowAccountCreation;
        _mfaProtector = MfaSecretProtector.CreateDefault(mfaKeyRootFolder);
        _dataRootFolder = mfaKeyRootFolder;
        _auditService = auditService;
        _settingDefaults = settingDefaults ?? Array.Empty<(string, string, string)>();
    }

    public ValueTask DefaultPageHandler(HttpContext context)
        => _renderer.RenderPage(context);

    public RouteHandlerDelegate BuildPageHandler(Action<HttpContext> configure)
    {
        if (configure == null) throw new ArgumentNullException(nameof(configure));
        return async context =>
        {
            configure(context);
            await _renderer.RenderPage(context);
        };
    }

    public RouteHandlerDelegate BuildPageHandler(Func<HttpContext, ValueTask> configureAsync)
    {
        if (configureAsync == null) throw new ArgumentNullException(nameof(configureAsync));
        return async context =>
        {
            await configureAsync(context);
            await _renderer.RenderPage(context);
        };
    }

    public RouteHandlerDelegate BuildPageHandler(Func<HttpContext, ValueTask<bool>> configureAsync, bool renderWhenTrue = true)
    {
        if (configureAsync == null) throw new ArgumentNullException(nameof(configureAsync));
        return async context =>
        {
            var shouldRender = await configureAsync(context);
            if (shouldRender == renderWhenTrue)
                await _renderer.RenderPage(context);
        };
    }

    public async ValueTask TimeRawHandler(HttpContext context)
    {
        context.Response.ContentType = "text/plain";
        await context.Response.WriteAsync($"Current server time is: {DateTime.UtcNow:O}");
    }

    public async ValueTask LoginHandler(HttpContext context)
    {
        await BuildPageHandler(ctx => RenderLoginForm(ctx, null, null))(context);
    }

    public async ValueTask LoginPostHandler(HttpContext context)
    {
        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
            await context.Response.WriteAsync("Unsupported content type.");
            return;
        }

        var form = await context.Request.ReadFormAsync();
        var identifier = form["email"].ToString().Trim();
        var password = form["password"].ToString();
        var rememberValue = form["remember"].ToString();
        bool rememberMe = string.Equals(rememberValue, "true", StringComparison.OrdinalIgnoreCase)
            || string.Equals(rememberValue, "on", StringComparison.OrdinalIgnoreCase)
            || string.Equals(rememberValue, "yes", StringComparison.OrdinalIgnoreCase);

        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderLoginForm(context, "Invalid security token. Please try again.", identifier);
            await _renderer.RenderPage(context);
            return;
        }

        if (string.IsNullOrWhiteSpace(identifier) || string.IsNullOrWhiteSpace(password))
        {
            RenderLoginForm(context, "Please enter your email/username and password.", identifier);
            await _renderer.RenderPage(context);
            return;
        }

        var user = await Users.FindByEmailOrUserNameAsync(identifier, context.RequestAborted).ConfigureAwait(false);
        if (user == null || !user.IsActive)
        {
            RenderLoginForm(context, "Invalid credentials.", identifier);
            await _renderer.RenderPage(context);
            return;
        }

        if (user.IsLockedOut)
        {
            RenderLoginForm(context, "Account is temporarily locked. Try again later.", identifier);
            await _renderer.RenderPage(context);
            return;
        }

        if (!user.VerifyPassword(password))
        {
            user.RegisterFailedLogin();
            await Users.SaveAsync(user);
            RenderLoginForm(context, "Invalid credentials.", identifier);
            await _renderer.RenderPage(context);
            return;
        }

        if (user.MfaEnabled)
        {
            if (!TryGetActiveSecret(user, out _, out var upgraded))
            {
                RenderLoginForm(context, "MFA is misconfigured. Contact support.", identifier);
                await _renderer.RenderPage(context);
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
                Secure = context.Request.IsHttps,
                SameSite = SameSiteMode.Lax,
                Expires = challenge.ExpiresUtc
            });
            context.Response.Redirect("/mfa");
            return;
        }

        user.RegisterSuccessfulLogin();
        await Users.SaveAsync(user);
        await UserAuth.SignInAsync(context, user, rememberMe);
        context.Response.Redirect("/");
    }

    public async ValueTask MfaChallengeHandler(HttpContext context)
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

    public async ValueTask MfaChallengePostHandler(HttpContext context)
    {
        var challenge = await GetMfaChallengeAsync(context, context.RequestAborted).ConfigureAwait(false);
        if (challenge == null)
        {
            context.Response.Redirect("/login");
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
            await context.Response.WriteAsync("Unsupported content type.");
            return;
        }

        var form = await context.Request.ReadFormAsync();
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

        var user = await Users.GetByIdAsync(uint.Parse(challenge.UserId), context.RequestAborted).ConfigureAwait(false);
        if (user == null || !user.IsActive || !user.MfaEnabled || !TryGetActiveSecret(user, out var activeSecret, out var upgraded))
        {
            RenderMfaChallengeForm(context, "MFA is not available for this account.");
            await _renderer.RenderPage(context);
            return;
        }

        if (upgraded)
            await Users.SaveAsync(user);

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

            if (matchedStep <= user.MfaLastVerifiedStep)
            {
                RenderMfaChallengeForm(context, "Authentication code already used. Please wait for a new code.");
                await _renderer.RenderPage(context);
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

    public async ValueTask RegisterHandler(HttpContext context)
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

    public async ValueTask RegisterPostHandler(HttpContext context)
    {
        if (!_allowAccountCreation)
        {
            context.SetStringValue("title", "Create Account");
            context.SetStringValue("html_message", "<p>Account creation is disabled in this environment.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            RenderRegisterForm(context, "Invalid registration request.", null, null, null);
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.Request.ReadFormAsync();
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

        if (!string.Equals(password, confirm, StringComparison.Ordinal))
        {
            RenderRegisterForm(context, "Passwords do not match.", userName, displayName, email);
            await _renderer.RenderPage(context);
            return;
        }

        if (await Users.FindByEmailAsync(email, context.RequestAborted).ConfigureAwait(false) != null)
        {
            RenderRegisterForm(context, "Email is already registered.", userName, displayName, email);
            await _renderer.RenderPage(context);
            return;
        }

        if (await Users.FindByUserNameAsync(userName, context.RequestAborted).ConfigureAwait(false) != null)
        {
            RenderRegisterForm(context, "Username is already taken.", userName, displayName, email);
            await _renderer.RenderPage(context);
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

    public async ValueTask LogoutHandler(HttpContext context)
    {
        await BuildPageHandler(ctx => RenderLogoutForm(ctx, null))(context);
    }

    public async ValueTask LogoutPostHandler(HttpContext context)
    {
        if (!context.Request.HasFormContentType)
        {
            RenderLogoutForm(context, "Invalid logout request.");
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderLogoutForm(context, "Invalid security token. Please try again.");
            await _renderer.RenderPage(context);
            return;
        }

        await UserAuth.SignOutAsync(context);
        context.Response.Redirect("/");
    }

    public async ValueTask AccountHandler(HttpContext context)
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

    public async ValueTask MfaStatusHandler(HttpContext context)
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

    public async ValueTask MfaSetupHandler(HttpContext context)
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

    public async ValueTask MfaSetupPostHandler(HttpContext context)
    {
        var user = await UserAuth.GetUserAsync(context);
        if (user == null)
        {
            context.Response.Redirect("/login");
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            if (RegeneratePendingMfaSecret(user, forceNew: false))
                await Users.SaveAsync(user);
            var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
            var pendingSecret = GetPendingSecret(user, out var pendingUpgraded);
            if (pendingUpgraded)
                await Users.SaveAsync(user);
            var otpauth = string.IsNullOrWhiteSpace(pendingSecret) ? string.Empty : MfaTotp.GetOtpAuthUri(issuer, user.Email, pendingSecret);
            RenderMfaSetupForm(context, pendingSecret ?? string.Empty, otpauth, "Invalid setup request.");
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.Request.ReadFormAsync();
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
            await _renderer.RenderPage(context);
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
            await _renderer.RenderPage(context);
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
            await _renderer.RenderPage(context);
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

            if (matchedStep <= user.MfaLastVerifiedStep)
            {
                var issuer = context.GetApp()?.AppName ?? "BareMetalWeb";
                var otpauth = MfaTotp.GetOtpAuthUri(issuer, user.Email, currentPendingSecret);
                RenderMfaSetupForm(context, currentPendingSecret, otpauth, "Authentication code already used. Please wait for a new code.");
                await _renderer.RenderPage(context);
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
            var backupList = string.Join(string.Empty, backupCodes.Codes.Select(codeValue => $"<li><code>{WebUtility.HtmlEncode(codeValue)}</code></li>"));
            var backupHtml = string.IsNullOrWhiteSpace(backupList)
                ? string.Empty
                : $"<div class=\"mt-3\"><p><strong>Backup codes (save these now):</strong></p><ul>{backupList}</ul><p class=\"text-warning\">These codes are shown once.</p></div>";
            context.SetStringValue("html_message", "<p>MFA enabled successfully.</p>" + backupHtml + "<p><a href=\"/account\">Back to account</a></p>");
            await _renderer.RenderPage(context);
            return;
        }
        finally
        {
            if (pendingBytes.Length > 0)
                CryptographicOperations.ZeroMemory(pendingBytes);
        }
    }

    public async ValueTask MfaResetHandler(HttpContext context)
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

    public async ValueTask MfaResetPostHandler(HttpContext context)
    {
        var user = await UserAuth.GetUserAsync(context);
        if (user == null)
        {
            context.Response.Redirect("/login");
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            RenderMfaResetForm(context, "Invalid request.");
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderMfaResetForm(context, "Invalid security token. Please try again.");
            await _renderer.RenderPage(context);
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
        await _renderer.RenderPage(context);
    }

    public async ValueTask UsersListHandler(HttpContext context)
    {
        await BuildPageHandler(async ctx =>
        {
            ctx.SetStringValue("title", "Users");

            var rows = new List<string[]>();
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

    public async ValueTask SetupHandler(HttpContext context)
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

    public async ValueTask SetupPostHandler(HttpContext context)
    {
        if (await RootUserExistsAsync(context.RequestAborted).ConfigureAwait(false))
        {
            var lockedUser = await GetLockedRootUserAsync(context.RequestAborted).ConfigureAwait(false);
            if (lockedUser == null)
            {
                context.SetStringValue("title", "Setup");
                context.SetStringValue("html_message", "<p>Root user already exists.</p>");
                await _renderer.RenderPage(context);
                return;
            }

            if (!context.Request.HasFormContentType)
            {
                RenderUnlockForm(context, "Invalid request.");
                await _renderer.RenderPage(context);
                return;
            }

            var unlockForm = await context.Request.ReadFormAsync();

            if (!CsrfProtection.ValidateFormToken(context, unlockForm))
            {
                RenderUnlockForm(context, "Invalid security token. Please try again.");
                await _renderer.RenderPage(context);
                return;
            }

            var unlockPassword = unlockForm["password"].ToString();
            if (string.IsNullOrWhiteSpace(unlockPassword) || !lockedUser.VerifyPassword(unlockPassword))
            {
                RenderUnlockForm(context, "Invalid password. Account remains locked.");
                await _renderer.RenderPage(context);
                return;
            }

            lockedUser.RegisterSuccessfulLogin();
            await Users.SaveAsync(lockedUser);
            context.SetStringValue("title", "Setup");
            context.SetStringValue("html_message", "<p>Account unlocked successfully. You may now sign in.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            RenderSetupForm(context, "Invalid setup request.", null, null);
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.Request.ReadFormAsync();
        var userName = form["username"].ToString().Trim();
        var email = form["email"].ToString().Trim();
        var password = form["password"].ToString();

        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderSetupForm(context, "Invalid security token. Please try again.", userName, email);
            await _renderer.RenderPage(context);
            return;
        }

        if (string.IsNullOrWhiteSpace(userName) || string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            RenderSetupForm(context, "Please complete all required fields.", userName, email);
            await _renderer.RenderPage(context);
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
        await EnsureDefaultCurrencies(userName);
        await EnsureDefaultUnitsOfMeasure(userName);
        await EnsureDefaultAddress(userName);
        await EnsureDefaultReports(userName);
        context.SetStringValue("title", "Setup");
        context.SetStringValue("html_message", "<p>Root user created successfully.</p>");
        await _renderer.RenderPage(context);
    }

    private static string[] BuildRootPermissions()
    {
        var permissions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
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

    private async ValueTask EnsureDefaultCurrencies(string createdBy)
    {
        var existing = (await DataStoreProvider.Current.QueryAsync<Currency>(null).ConfigureAwait(false)).ToList();
        var hasUsd = existing.Any(currency => string.Equals(currency.IsoCode, "USD", StringComparison.OrdinalIgnoreCase));
        var hasGbp = existing.Any(currency => string.Equals(currency.IsoCode, "GBP", StringComparison.OrdinalIgnoreCase));
        var hasBase = existing.Any(currency => currency.IsBase);

        if (!hasUsd)
        {
            var usd = new Currency
            {
                IsoCode = "USD",
                Description = "US Dollar",
                Symbol = "$",
                DecimalPlaces = 2,
                IsEnabled = true,
                IsBase = !hasBase,
                CreatedBy = createdBy,
                UpdatedBy = createdBy
            };
            await DataStoreProvider.Current.SaveAsync(usd);
            hasBase = hasBase || usd.IsBase;
        }

        if (!hasGbp)
        {
            var gbp = new Currency
            {
                IsoCode = "GBP",
                Description = "Pound Sterling",
                Symbol = "GBP",
                DecimalPlaces = 2,
                IsEnabled = true,
                IsBase = !hasBase,
                CreatedBy = createdBy,
                UpdatedBy = createdBy
            };
            await DataStoreProvider.Current.SaveAsync(gbp);
        }
    }

    private async ValueTask EnsureDefaultUnitsOfMeasure(string createdBy)
    {
        var existing = (await DataStoreProvider.Current.QueryAsync<UnitOfMeasure>(null).ConfigureAwait(false)).ToList();
        var hasEa = existing.Any(unit => string.Equals(unit.Abbreviation, "EA", StringComparison.OrdinalIgnoreCase)
            || string.Equals(unit.Name, "EA", StringComparison.OrdinalIgnoreCase)
            || string.Equals(unit.Name, "Each", StringComparison.OrdinalIgnoreCase));

        if (hasEa)
            return;

        var unitOfMeasure = new UnitOfMeasure
        {
            Name = "Each",
            Abbreviation = "EA",
            Description = "Each",
            IsActive = true,
            CreatedBy = createdBy,
            UpdatedBy = createdBy
        };

        await DataStoreProvider.Current.SaveAsync(unitOfMeasure);
    }

    private async ValueTask EnsureDefaultAddress(string createdBy)
    {
        var addresses = await DataStoreProvider.Current.QueryAsync<Address>(null).ConfigureAwait(false);
        var hasAddress = addresses.Any();
        if (hasAddress)
            return;

        var address = new Address
        {
            Label = "Main",
            Line1 = "123 Example Street",
            City = "London",
            Region = "Greater London",
            PostalCode = "SW1A 1AA",
            Country = "GB",
            CreatedBy = createdBy,
            UpdatedBy = createdBy
        };

        await DataStoreProvider.Current.SaveAsync(address);
    }

    private async ValueTask EnsureDefaultReports(string createdBy)
    {
        var existing = await DataStoreProvider.Current.QueryAsync<ReportDefinition>(null).ConfigureAwait(false);
        var existingNames = new HashSet<string>(
            existing.Select(r => r.Name),
            StringComparer.OrdinalIgnoreCase);

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

    public async ValueTask ReloadTemplatesHandler(HttpContext context)
    {
        _templateStore.ReloadAll();
        context.SetStringValue("title", "Reload Templates");
        context.SetStringValue("html_message", "Templates reloaded successfully.");
        await _renderer.RenderPage(context);
    }

    private void RenderLoginForm(HttpContext context, string? message, string? emailValue)
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

        context.AddFormDefinition(new FormDefinition(
            Action: "/login",
            Method: "post",
            SubmitLabel: "Sign In",
            Fields: fields.ToArray()
        ));
    }

    private void RenderRegisterForm(HttpContext context, string? message, string? userName, string? displayName, string? email)
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

    private void RenderSetupForm(HttpContext context, string? message, string? userName, string? email)
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

    private void RenderUnlockForm(HttpContext context, string? message)
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

    private void RenderLogoutForm(HttpContext context, string? message)
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

    private void RenderMfaChallengeForm(HttpContext context, string? message)
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

    private void RenderMfaSetupForm(HttpContext context, string secret, string otpauthUrl, string? message)
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
        var revealSecret = string.IsNullOrWhiteSpace(secret)
            ? string.Empty
            : $"<details class=\"mb-2\"><summary>Reveal secret</summary><p><code>{WebUtility.HtmlEncode(secret)}</code></p></details>";
        var revealOtpAuth = string.IsNullOrWhiteSpace(otpauthUrl)
            ? string.Empty
            : $"<details class=\"mb-2\"><summary>Show otpauth URI</summary><p class=\"small text-break\">{WebUtility.HtmlEncode(otpauthUrl)}</p></details>";

        var payload = string.IsNullOrWhiteSpace(secret)
            ? string.Empty
            : $"<p><strong>Secret:</strong> <code>{WebUtility.HtmlEncode(maskedSecret)}</code></p>" +
              qrHtml +
              revealSecret +
              revealOtpAuth;

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

    private static string BuildOtpClientScript(HttpContext context, string formAction)
    {
        var action = formAction.Replace("\\", "\\\\").Replace("'", "\\'").Replace("\"", "\\\"");
        var nonce = context.GetCspNonce();
        return $"<script nonce=\"{nonce}\">setupOtpValidation('{action}');</script>";
    }

    private static async ValueTask NotImplementedHandler(HttpContext context, string message)
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        context.Response.ContentType = "text/plain";
        await context.Response.WriteAsync(message);
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

    public async ValueTask DataEntitiesHandler(HttpContext context)
    {
        await BuildPageHandler(ctx =>
        {
            ctx.SetStringValue("title", "Data");
            ctx.SetStringValue("html_message", "<p>Manage data entities.</p>");

            var rows = DataScaffold.Entities
                .OrderBy(e => e.NavOrder)
                .ThenBy(e => e.Name)
                .Select(entity => new[]
                {
                    $"<a class=\"btn btn-sm btn-outline-info me-1\" href=\"/ssr/admin/data/{entity.Slug}\" title=\"Open\" aria-label=\"Open\"><i class=\"bi bi-search\" aria-hidden=\"true\"></i></a><a class=\"btn btn-sm btn-outline-success\" href=\"/ssr/admin/data/{entity.Slug}/import\" title=\"Import CSV\" aria-label=\"Import CSV\"><i class=\"bi bi-upload\" aria-hidden=\"true\"></i></a>",
                    WebUtility.HtmlEncode(entity.Name),
                    WebUtility.HtmlEncode(entity.Slug),
                    string.IsNullOrWhiteSpace(entity.Permissions) ? "Public" : WebUtility.HtmlEncode(entity.Permissions)
                })
                .ToArray();

            ctx.AddTable(new[] { "Actions", "Entity", "Slug", "Permissions" }, rows);
        })(context);
    }

    public async ValueTask DataListHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        if (meta == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Data");
            context.SetStringValue("html_message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("html_message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        // Fetch user once for permission checks in callbacks
        var currentUser = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
        bool HasPermissionForMeta(DataEntityMetadata m)
        {
            var permissionsNeeded = m.Permissions?.Trim();
            if (string.IsNullOrWhiteSpace(permissionsNeeded) || string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase))
                return true;
            if (currentUser == null)
                return string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase);
            if (string.Equals(permissionsNeeded, "Authenticated", StringComparison.OrdinalIgnoreCase))
                return true;
            if (string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase))
                return false;
            var userPermissions = new HashSet<string>(currentUser.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            var required = permissionsNeeded.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            return required.Length == 0 || required.All(userPermissions.Contains);
        }

        var queryDictionary = ToQueryDictionary(context.Request.Query);
        
        // Check for view parameter to override entity's default view type
        var viewParam = context.Request.Query.TryGetValue("view", out var viewValue) ? viewValue.ToString() : null;
        var selectedId = context.Request.Query.TryGetValue("selected", out var selectedValue) ? selectedValue.ToString() : null;
        var effectiveViewType = meta.ViewType;
        
        if (!string.IsNullOrWhiteSpace(viewParam))
        {
            if (string.Equals(viewParam, "tree", StringComparison.OrdinalIgnoreCase))
                effectiveViewType = ViewType.TreeView;
            else if (string.Equals(viewParam, "orgchart", StringComparison.OrdinalIgnoreCase))
                effectiveViewType = ViewType.OrgChart;
            else if (string.Equals(viewParam, "table", StringComparison.OrdinalIgnoreCase))
                effectiveViewType = ViewType.Table;
            else if (string.Equals(viewParam, "timeline", StringComparison.OrdinalIgnoreCase))
                effectiveViewType = ViewType.Timeline;
            else if (string.Equals(viewParam, "timetable", StringComparison.OrdinalIgnoreCase))
                effectiveViewType = ViewType.Timetable;
        }

        var cloneToken = CsrfProtection.EnsureToken(context);
        var returnUrl = $"{context.Request.Path}{context.Request.QueryString}";

        // For tree/org chart/timeline/timetable views, load all items (no pagination)
        if (effectiveViewType == ViewType.TreeView || effectiveViewType == ViewType.OrgChart || effectiveViewType == ViewType.Timeline || effectiveViewType == ViewType.Timetable)
        {
            var allQuery = DataScaffold.BuildQueryDefinition(queryDictionary, meta);
            var allResults = (await DataScaffold.QueryAsync(meta, allQuery)).Cast<BaseDataObject>().ToList();
            
            var basePath = $"/ssr/admin/data/{typeSlug}";

            string viewHtml;
            if (effectiveViewType == ViewType.TreeView)
            {
                viewHtml = DataScaffold.BuildTreeViewHtml(meta, allResults, selectedId, basePath, HasPermissionForMeta, cloneToken, returnUrl);
            }
            else if (effectiveViewType == ViewType.Timeline)
            {
                viewHtml = BuildTimelineViewHtml(meta, allResults, basePath, HasPermissionForMeta, cloneToken, returnUrl);
            }
            else if (effectiveViewType == ViewType.OrgChart)
            {
                viewHtml = DataScaffold.BuildOrgChartHtml(meta, allResults, selectedId, basePath, HasPermissionForMeta);
            }
            else // Timetable
            {
                viewHtml = DataScaffold.BuildTimetableHtml(meta, allResults, basePath, HasPermissionForMeta, cloneToken, returnUrl);
            }

            var treeToastHtml = BuildToastHtml(context, meta.Name);
            var treeViewSwitcher = BuildViewSwitcher(typeSlug, effectiveViewType, meta);
            var treeAddButtonHtml = $"<a class=\"btn btn-sm btn-success\" href=\"/ssr/admin/data/{typeSlug}/create\" title=\"Create {WebUtility.HtmlEncode(meta.Name)}\" aria-label=\"Create {WebUtility.HtmlEncode(meta.Name)}\"><i class=\"bi bi-plus-lg\" aria-hidden=\"true\"></i> Add</a>";
            
            context.SetStringValue("title", $"{meta.Name} - {GetViewTypeName(effectiveViewType)}");
            context.SetStringValue("html_header_controls", "<div class=\"d-flex align-items-center gap-2 flex-wrap\">" + treeViewSwitcher + treeAddButtonHtml + "</div>");
            context.SetStringValue("html_message", treeToastHtml + viewHtml);
            await _renderer.RenderPage(context);
            return;
        }

        // Standard table view with pagination
        var countQuery = DataScaffold.BuildQueryDefinition(queryDictionary, meta);
        var totalCount = await DataScaffold.CountAsync(meta, countQuery);
        
        // Configurable page size (default 25)
        var pageSize = 25;
        if (queryDictionary.TryGetValue("size", out var sizeValue) 
            && int.TryParse(sizeValue, out var parsedSize) 
            && parsedSize > 0 && parsedSize <= 100)
        {
            pageSize = parsedSize;
        }
        
        var page = 1;
        if (context.Request.Query.TryGetValue("page", out var pageValue)
            && int.TryParse(pageValue.ToString(), out var parsedPage)
            && parsedPage > 1)
        {
            page = parsedPage;
        }

        var maxPage = totalCount == 0 ? 1 : (int)Math.Ceiling(totalCount / (double)pageSize);
        if (page > maxPage)
            page = maxPage;

        var query = DataScaffold.BuildQueryDefinition(queryDictionary, meta);
        query.Skip = (page - 1) * pageSize;
        query.Top = pageSize;
        var results = await DataScaffold.QueryAsync(meta, query);

        var headers = DataScaffold.BuildListHeaders(meta, includeActions: true, includeBulkSelection: true);
        var rows = DataScaffold.BuildListRows(
            meta,
            results,
            $"/ssr/admin/data/{typeSlug}",
            includeActions: true,
            canRenderLookupLink: HasPermissionForMeta,
            cloneToken: cloneToken,
            cloneReturnUrl: returnUrl,
            includeBulkSelection: true);

        var toastHtml = BuildToastHtml(context, meta.Name);
        
        // Build UI components
        var currentSearchText = queryDictionary.TryGetValue("q", out var searchVal) ? searchVal : null;
        var pageSizeHtml = BuildPageSizeSelector(pageSize, $"/ssr/admin/data/{typeSlug}", queryDictionary);
        var pagerHtml = BuildEnhancedPagination(page, totalCount, pageSize, $"/ssr/admin/data/{typeSlug}", queryDictionary);
        
        var queryString = context.Request.QueryString.HasValue ? context.Request.QueryString.Value : string.Empty;
        
        // Check if entity has nested components
        var nestedComponents = DataScaffold.GetNestedComponents(meta);
        var hasNested = nestedComponents.Count > 0;
        
        var exportDropdown = BuildExportDropdown(typeSlug, queryString, hasNested);
        var htmlHtml = $"<a class=\"btn btn-sm btn-outline-primary\" href=\"/ssr/admin/data/{typeSlug}/html{WebUtility.HtmlEncode(queryString)}\" title=\"Download HTML\" aria-label=\"Download HTML\"><i class=\"bi bi-download\" aria-hidden=\"true\"></i><i class=\"bi bi-filetype-html ms-1\" aria-hidden=\"true\"></i> HTML</a>";
        var viewSwitcher = BuildViewSwitcher(typeSlug, effectiveViewType, meta);
        var addButtonHtml = $"<a class=\"btn btn-sm btn-success\" href=\"/ssr/admin/data/{typeSlug}/create\" title=\"Create {WebUtility.HtmlEncode(meta.Name)}\" aria-label=\"Create {WebUtility.HtmlEncode(meta.Name)}\"><i class=\"bi bi-plus-lg\" aria-hidden=\"true\"></i> Add</a>";
        
        // Compact inline search form for the card header
        var safeSearchText = WebUtility.HtmlEncode(currentSearchText ?? string.Empty);
        var safeActionUrl = WebUtility.HtmlEncode($"/ssr/admin/data/{typeSlug}");
        var compactSearchHtml = $"<form method=\"get\" action=\"{safeActionUrl}\" class=\"d-flex align-items-center gap-1\">" +
            $"<input type=\"search\" class=\"form-control form-control-sm bm-list-search\" name=\"q\" placeholder=\"Search...\" value=\"{safeSearchText}\" aria-label=\"Search\" />" +
            "<button type=\"submit\" class=\"btn btn-sm btn-primary\" aria-label=\"Submit search\"><i class=\"bi bi-search\" aria-hidden=\"true\"></i></button>" +
            "</form>";
        
        // Header controls: view switcher + search + add + export (right-aligned in card header)
        var headerControlsHtml = "<div class=\"d-flex align-items-center gap-2 flex-wrap\">" + viewSwitcher + compactSearchHtml + addButtonHtml + exportDropdown + htmlHtml + "</div>";
        
        // Bulk actions bar with CSRF token
        var bulkActionsBar = BuildBulkActionsBar(typeSlug, returnUrl, totalCount, cloneToken);
        
        // Build custom table with sortable headers
        var tableHtml = BuildTableWithSortableHeaders(meta, rows, $"/ssr/admin/data/{typeSlug}", queryDictionary, includeActions: true, includeBulkSelection: true);
        
        // Pagination row below the table
        var paginationRowHtml = "<div class=\"d-flex justify-content-between align-items-center mt-2 mb-2\">" + pagerHtml + pageSizeHtml + "</div>";
        
        context.SetStringValue("title", $"{meta.Name} List");
        context.SetStringValue("html_header_controls", headerControlsHtml);
        context.SetStringValue("html_message", toastHtml + tableHtml + paginationRowHtml + bulkActionsBar);
        await _renderer.RenderPage(context);
    }

    public async ValueTask DataViewHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        var id = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(id))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Data");
            context.SetStringValue("html_message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("html_message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        // Fetch user once for permission checks in callbacks
        var currentUser = await UserAuth.GetRequestUserAsync(context, context.RequestAborted).ConfigureAwait(false);
        bool HasPermissionForMeta(DataEntityMetadata m)
        {
            var permissionsNeeded = m.Permissions?.Trim();
            if (string.IsNullOrWhiteSpace(permissionsNeeded) || string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase))
                return true;
            if (currentUser == null)
                return string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase);
            if (string.Equals(permissionsNeeded, "Authenticated", StringComparison.OrdinalIgnoreCase))
                return true;
            if (string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase))
                return false;
            var userPermissions = new HashSet<string>(currentUser.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
            var required = permissionsNeeded.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            return required.Length == 0 || required.All(userPermissions.Contains);
        }

        var instance = await DataScaffold.LoadAsync(meta, uint.Parse(id));
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Not Found");
            context.SetStringValue("html_message", "<p>Item not found.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var rows = DataScaffold.BuildViewRowsHtml(meta, instance, HasPermissionForMeta)
            .Select(row => new[]
            {
                WebUtility.HtmlEncode(row.Label),
                row.IsHtml ? row.Value : WebUtility.HtmlEncode(row.Value)
            })
            .ToArray();

        // Check if entity has nested components
        var nestedComponents = DataScaffold.GetNestedComponents(meta);
        var hasNested = nestedComponents.Count > 0;
        
        var exportDropdown = BuildExportDropdown(typeSlug, string.Empty, hasNested, id);
        var rtfHtml = $"<a class=\"btn btn-sm btn-outline-info ms-2\" href=\"/ssr/admin/data/{typeSlug}/{WebUtility.UrlEncode(id)}/rtf\" title=\"Download RTF\" aria-label=\"Download RTF\"><i class=\"bi bi-download\" aria-hidden=\"true\"></i><i class=\"bi bi-file-earmark-text ms-1\" aria-hidden=\"true\"></i> RTF</a>";
        var htmlHtml = $"<a class=\"btn btn-sm btn-outline-primary ms-2\" href=\"/ssr/admin/data/{typeSlug}/{WebUtility.UrlEncode(id)}/html\" title=\"Download HTML\" aria-label=\"Download HTML\"><i class=\"bi bi-download\" aria-hidden=\"true\"></i><i class=\"bi bi-filetype-html ms-1\" aria-hidden=\"true\"></i> HTML</a>";
        var commandButtons = BuildCommandButtonsHtml(meta, typeSlug, id, CsrfProtection.EnsureToken(context));
        context.SetStringValue("title", $"{meta.Name} Details");
        context.SetStringValue("html_message", $"<p><a class=\"btn btn-sm btn-outline-warning\" href=\"/ssr/admin/data/{typeSlug}/{WebUtility.UrlEncode(id)}/edit\" title=\"Edit\" aria-label=\"Edit\"><i class=\"bi bi-pencil\" aria-hidden=\"true\"></i> Edit</a>{exportDropdown}{rtfHtml}{htmlHtml}{commandButtons}</p>");
        context.AddTable(new[] { "Field", "Value" }, rows);
        await _renderer.RenderPage(context);
    }

    public async ValueTask DataListCsvHandler(HttpContext context)
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

        var query = DataScaffold.BuildQueryDefinition(ToQueryDictionary(context.Request.Query), meta);
        var results = await DataScaffold.QueryAsync(meta, query);
        var resultsList = results.Cast<object?>().ToList();

        var rows = BuildListPlainRowsWithId(meta, resultsList, out var headers);
        var csv = BuildCsv(headers, rows);
        await WriteTextResponseAsync(context, "text/csv", csv, $"{typeSlug}_list.csv");
    }

    public async ValueTask DataListHtmlHandler(HttpContext context)
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

        var query = DataScaffold.BuildQueryDefinition(ToQueryDictionary(context.Request.Query), meta);
        var results = await DataScaffold.QueryAsync(meta, query);
        var resultsList = results.Cast<object?>().ToList();

        var rows = BuildListPlainRowsWithId(meta, resultsList, out var headers);
        var title = $"{meta.Name} List";
        var html = BuildHtmlTableDocument(title, headers, rows);
        await WriteTextResponseAsync(context, "text/html", html, $"{typeSlug}_list.html");
    }

    public async ValueTask DataListExportHandler(HttpContext context)
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

        var options = ExportOptions.FromQuery(context.Request.Query);
        var query = DataScaffold.BuildQueryDefinition(ToQueryDictionary(context.Request.Query), meta);
        var results = await DataScaffold.QueryAsync(meta, query);
        var resultsList = results.Cast<object?>().ToList();

        switch (options.Format)
        {
            case ExportFormat.HierarchicalJSON:
                await ExportHierarchicalJson(context, meta, typeSlug, resultsList, options);
                break;
            case ExportFormat.FlatCSV:
                await ExportFlatCsv(context, meta, typeSlug, resultsList, options);
                break;
            case ExportFormat.MultiSheetZip:
                await ExportMultiSheetZip(context, meta, typeSlug, resultsList, options);
                break;
            case ExportFormat.SimpleCSV:
            default:
                // Fall back to simple CSV (no nested data)
                var rows = BuildListPlainRowsWithId(meta, resultsList, out var headers);
                var csv = BuildCsv(headers, rows);
                await WriteTextResponseAsync(context, "text/csv", csv, $"{typeSlug}_list.csv");
                break;
        }
    }

    public async ValueTask DataViewExportHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
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

        var options = ExportOptions.FromQuery(context.Request.Query);
        
        switch (options.Format)
        {
            case ExportFormat.HierarchicalJSON:
                await ExportSingleHierarchicalJson(context, meta, typeSlug, id, instance, options);
                break;
            case ExportFormat.FlatCSV:
                await ExportSingleFlatCsv(context, meta, typeSlug, id, instance, options);
                break;
            case ExportFormat.MultiSheetZip:
                await ExportSingleMultiSheetZip(context, meta, typeSlug, id, instance, options);
                break;
            case ExportFormat.SimpleCSV:
            default:
                // Fall back to simple CSV (entity fields only, no nested)
                var rows = DataScaffold.BuildViewRows(meta, instance)
                    .Select(row => new[] { row.Label, row.Value })
                    .ToArray();
                if (instance is BaseDataObject dataObject)
                {
                    var recordId = DataScaffold.GetIdValue(dataObject) ?? string.Empty;
                    rows = new[] { new[] { "Id", recordId } }.Concat(rows).ToArray();
                }
                var headers = new[] { "Field", "Value" };
                var csv = BuildCsv(headers, rows);
                await WriteTextResponseAsync(context, "text/csv", csv, $"{typeSlug}_{WebUtility.UrlEncode(id)}.csv");
                break;
        }
    }

    public async ValueTask DataViewRtfHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
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

        var rows = DataScaffold.BuildViewRows(meta, instance)
            .Select(row => new[] { row.Label, row.Value })
            .ToArray();
        if (instance is BaseDataObject dataObject)
        {
            var recordId = DataScaffold.GetIdValue(dataObject) ?? string.Empty;
            rows = new[] { new[] { "Id", recordId } }.Concat(rows).ToArray();
        }
        var title = $"{meta.Name} Details";
        var rtf = BuildRtfDocument(title, rows);
        await WriteTextResponseAsync(context, "application/rtf", rtf, $"{typeSlug}_{WebUtility.UrlEncode(id)}.rtf");
    }

    public async ValueTask DataViewHtmlHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
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

        var rows = DataScaffold.BuildViewRows(meta, instance)
            .Select(row => new[] { row.Label, row.Value })
            .ToArray();
        if (instance is BaseDataObject dataObject)
        {
            var recordId = DataScaffold.GetIdValue(dataObject) ?? string.Empty;
            rows = new[] { new[] { "Id", recordId } }.Concat(rows).ToArray();
        }
        var title = $"{meta.Name} Details";
        var html = BuildHtmlTableDocument(title, new[] { "Field", "Value" }, rows);
        await WriteTextResponseAsync(context, "text/html", html, $"{typeSlug}_{WebUtility.UrlEncode(id)}.html");
    }

    public async ValueTask DataImportHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        if (meta == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Import CSV");
            context.SetStringValue("html_message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("html_message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var csrfToken = CsrfProtection.EnsureToken(context);
        var fields = new List<FormField>
        {
            new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken),
            new FormField(FormFieldType.File, "csv_file", "CSV File", Required: true),
            new FormField(FormFieldType.YesNo, "upsert", "Upsert by Id", Required: false, SelectedValue: "false")
        };

        var help = "<p>Upload a CSV file. Columns map by field name or label (case-insensitive). If \"Upsert by Id\" is Yes and the CSV includes an Id column, existing records will be updated.</p>";
        context.SetStringValue("title", $"Import CSV: {meta.Name}");
        context.SetStringValue("html_message", help);
        context.AddFormDefinition(new FormDefinition($"/ssr/admin/data/{typeSlug}/import", "post", "Import CSV", fields));
        await _renderer.RenderPage(context);
    }

    public async ValueTask DataImportPostHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        if (meta == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Import CSV");
            context.SetStringValue("html_message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("html_message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.SetStringValue("title", "Import CSV");
            context.SetStringValue("html_message", "<p>Invalid form submission.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            context.SetStringValue("title", "Import CSV");
            context.SetStringValue("html_message", "<p>Invalid security token. Please try again.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var file = form.Files.GetFile("csv_file");
        if (file == null || file.Length == 0)
        {
            context.SetStringValue("title", "Import CSV");
            context.SetStringValue("html_message", "<p>No CSV file uploaded.</p>");
            await _renderer.RenderPage(context);
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
            context.SetStringValue("title", "Import CSV");
            context.SetStringValue("html_message", "<p>CSV file is empty or missing headers.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var header = rows[0];
        var mapping = BuildCsvMapping(meta, header, out var idIndex, out var passwordIndex);

        int created = 0;
        int updated = 0;
        int skipped = 0;
        var errors = new List<string>();

        for (int i = 1; i < rows.Count; i++)
        {
            var row = rows[i];
            if (row.All(string.IsNullOrWhiteSpace))
                continue;

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
                // Apply auto-generated IDs for new CSV rows
                DataScaffold.ApplyAutoGeneratedIds(meta, instance);
            }

            var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in mapping)
            {
                if (entry.Value < 0 || entry.Value >= row.Length)
                    continue;
                values[entry.Key] = row[entry.Value];
            }

            var rowErrors = DataScaffold.ApplyValuesFromForm(meta, instance, values, forCreate: isCreate);
            ApplyUserPasswordForImport(meta, instance, row, passwordIndex, isCreate, rowErrors);

            if (rowErrors.Count > 0)
            {
                skipped++;
                errors.Add($"Row {rowNumber}: {string.Join("; ", rowErrors)}");
                continue;
            }

            ApplyAuditInfo(instance, (await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false))?.UserName ?? "system", isCreate);
            if (isCreate && !upsertWithExplicitId)
                await DataScaffold.ApplyAutoIdAsync(meta, instance, context.RequestAborted).ConfigureAwait(false);
            if (isCreate)
                await DataScaffold.ApplyComputedFieldsAsync(meta, instance, ComputedTrigger.OnCreate, context.RequestAborted).ConfigureAwait(false);
            else
                await DataScaffold.ApplyComputedFieldsAsync(meta, instance, ComputedTrigger.OnUpdate, context.RequestAborted).ConfigureAwait(false);
            DataScaffold.ApplyCalculatedFields(meta, instance);
            await DataScaffold.SaveAsync(meta, instance);
            if (isCreate)
                created++;
            else
                updated++;
        }

        var summary = $"<p>Import complete. Created: {created}, Updated: {updated}, Skipped: {skipped}.</p>";
        if (errors.Count > 0)
        {
            var preview = string.Join("<br/>", errors.Take(10).Select(WebUtility.HtmlEncode));
            var more = errors.Count > 10 ? $"<p>And {errors.Count - 10} more errors.</p>" : string.Empty;
            summary += $"<div class=\"alert alert-warning\"><strong>Errors:</strong><br/>{preview}{more}</div>";
        }

        context.SetStringValue("title", $"Import CSV: {meta.Name}");
        context.SetStringValue("html_message", summary + $"<p><a class=\"btn btn-sm btn-outline-secondary\" href=\"/ssr/admin/data/{typeSlug}\">Back to list</a></p>");
        await _renderer.RenderPage(context);
    }

    public async ValueTask DataCreateHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        if (meta == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Data");
            context.SetStringValue("html_message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("html_message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var csrfToken = CsrfProtection.EnsureToken(context);
        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true, cspNonce: context.GetCspNonce()).ToList();
        AppendUserPasswordFieldsIfNeeded(meta, fields, isCreate: true);
        fields.Insert(0, new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken));

        var isPopup = context.Request.Query.ContainsKey("popup");
        var createAction = isPopup ? $"/ssr/admin/data/{typeSlug}/create?popup=1" : $"/ssr/admin/data/{typeSlug}/create";
        context.SetStringValue("title", $"Create {meta.Name}");
        context.AddFormDefinition(new FormDefinition(createAction, "post", $"Create {meta.Name}", fields));
        await _renderer.RenderPage(context);
    }

    public async ValueTask DataCreatePostHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        if (meta == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Data");
            context.SetStringValue("html_message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("html_message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.SetStringValue("title", "Invalid Request");
            context.SetStringValue("html_message", "<p>Invalid form submission.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            context.SetStringValue("title", "Invalid Request");
            context.SetStringValue("html_message", "<p>Invalid security token. Please try again.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var instance = meta.Handlers.Create();

        // Apply auto-generated IDs before binding form values
        DataScaffold.ApplyAutoGeneratedIds(meta, instance);

        var values = form.ToDictionary(k => k.Key, v => (string?)v.Value.ToString(), StringComparer.OrdinalIgnoreCase);
        var apiKeyInputs = ExtractSystemPrincipalKeys(values);
        var errors = DataScaffold.ApplyValuesFromForm(meta, instance, values, forCreate: true);
        await ApplyUploadFieldsFromFormAsync(context, meta, (BaseDataObject)instance, form, errors).ConfigureAwait(false);
        ApplyUserPasswordIfNeeded(meta, instance, values, errors, isCreate: true);
        await ValidateUserUniquenessAsync(meta, instance, excludeId: null, errors, context.RequestAborted).ConfigureAwait(false);

        // Run entity-level expression validation (cross-field rules)
        var validationResult = DataScaffold.ValidateEntity(meta, instance);
        errors.AddRange(validationResult.AllErrors());

        var isPopup = context.Request.Query.ContainsKey("popup");

        if (errors.Count > 0)
        {
            context.SetStringValue("title", $"Create {meta.Name}");
            context.SetStringValue("html_message", $"<div class=\"alert alert-danger\">{string.Join("<br/>", errors.Select(WebUtility.HtmlEncode))}</div>");
            var fields = BuildFormFieldsWithErrors(meta, instance, forCreate: true, validationResult, cspNonce: context.GetCspNonce());
            AppendUserPasswordFieldsIfNeeded(meta, fields, isCreate: true);
            fields.Insert(0, new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: CsrfProtection.EnsureToken(context)));
            var createAction = isPopup ? $"/ssr/admin/data/{typeSlug}/create?popup=1" : $"/ssr/admin/data/{typeSlug}/create";
            context.AddFormDefinition(new FormDefinition(createAction, "post", $"Create {meta.Name}", fields));
            await _renderer.RenderPage(context);
            return;
        }

        string? newApiKey = null;
        if (instance is SystemPrincipal principal)
        {
            var createdKeys = ApplySystemPrincipalKeys(principal, apiKeyInputs, isCreate: true);
            newApiKey = createdKeys.FirstOrDefault();
        }

        var userName = (await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false))?.UserName ?? "system";
        ApplyAuditInfo(instance, userName, isCreate: true);
        await DataScaffold.ApplyAutoIdAsync(meta, instance, context.RequestAborted).ConfigureAwait(false);
        await DataScaffold.ApplyComputedFieldsAsync(meta, instance, ComputedTrigger.OnCreate, context.RequestAborted).ConfigureAwait(false);
        DataScaffold.ApplyCalculatedFields(meta, instance);
        await DataScaffold.SaveAsync(meta, instance);
        
        // Audit the create operation
        if (instance is BaseDataObject baseDataObject)
        {
            await _auditService.AuditCreateAsync(baseDataObject, userName, context.RequestAborted).ConfigureAwait(false);
        }
        
        var newId = instance is BaseDataObject dataObject ? DataScaffold.GetIdValue(dataObject) : null;
        var keyQuery = string.IsNullOrWhiteSpace(newApiKey) ? string.Empty : $"&apikey={WebUtility.UrlEncode(newApiKey)}";

        if (isPopup)
        {
            context.Response.ContentType = "text/html";
            await context.Response.WriteAsync("<!DOCTYPE html><html><head><title>Saved</title></head><body><script>window.close();</script><p>Saved. You may close this window.</p></body></html>").ConfigureAwait(false);
            return;
        }

        context.Response.Redirect($"/ssr/admin/data/{typeSlug}?toast=created&id={WebUtility.UrlEncode(newId ?? string.Empty)}{keyQuery}");
    }

    public async ValueTask DataEditHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        var id = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(id))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Data");
            context.SetStringValue("html_message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("html_message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, uint.Parse(id));
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Not Found");
            context.SetStringValue("html_message", "<p>Item not found.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var csrfToken = CsrfProtection.EnsureToken(context);
        var fields = DataScaffold.BuildFormFields(meta, instance, forCreate: false, cspNonce: context.GetCspNonce()).ToList();
        AppendUserPasswordFieldsIfNeeded(meta, fields, isCreate: false);
        fields.Insert(0, new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken));

        context.SetStringValue("title", $"Edit {meta.Name}");
        context.AddFormDefinition(new FormDefinition($"/ssr/admin/data/{typeSlug}/{WebUtility.UrlEncode(id)}/edit", "post", $"Save {meta.Name}", fields));
        await _renderer.RenderPage(context);
    }

    public async ValueTask DataEditPostHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        var id = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(id))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Data");
            context.SetStringValue("html_message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("html_message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.SetStringValue("title", "Invalid Request");
            context.SetStringValue("html_message", "<p>Invalid form submission.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, uint.Parse(id));
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Not Found");
            context.SetStringValue("html_message", "<p>Item not found.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        // Capture the old state for audit trail (before any modifications)
        BaseDataObject? oldInstance = null;
        if (instance is BaseDataObject baseDataObjectOriginal)
        {
            try
            {
                var json = JsonSerializer.Serialize(baseDataObjectOriginal);
                oldInstance = (BaseDataObject?)JsonSerializer.Deserialize(json, baseDataObjectOriginal.GetType());
            }
            catch
            {
                // If cloning fails, continue without audit trail for this update
            }
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            context.SetStringValue("title", "Invalid Request");
            context.SetStringValue("html_message", "<p>Invalid security token. Please try again.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var values = form.ToDictionary(k => k.Key, v => (string?)v.Value.ToString(), StringComparer.OrdinalIgnoreCase);
        var apiKeyInputs = ExtractSystemPrincipalKeys(values);
        var errors = DataScaffold.ApplyValuesFromForm(meta, instance, values, forCreate: false);
        await ApplyUploadFieldsFromFormAsync(context, meta, (BaseDataObject)instance, form, errors).ConfigureAwait(false);
        ApplyUserPasswordIfNeeded(meta, instance, values, errors, isCreate: false);
        await ValidateUserUniquenessAsync(meta, instance, excludeId: id, errors, context.RequestAborted).ConfigureAwait(false);

        // Run entity-level expression validation (cross-field rules)
        var validationResult = DataScaffold.ValidateEntity(meta, instance);
        errors.AddRange(validationResult.AllErrors());

        if (errors.Count > 0)
        {
            context.SetStringValue("title", $"Edit {meta.Name}");
            context.SetStringValue("html_message", $"<div class=\"alert alert-danger\">{string.Join("<br/>", errors.Select(WebUtility.HtmlEncode))}</div>");
            var fields = BuildFormFieldsWithErrors(meta, instance, forCreate: false, validationResult, cspNonce: context.GetCspNonce());
            AppendUserPasswordFieldsIfNeeded(meta, fields, isCreate: false);
            fields.Insert(0, new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: CsrfProtection.EnsureToken(context)));
            context.AddFormDefinition(new FormDefinition($"/ssr/admin/data/{typeSlug}/{WebUtility.UrlEncode(id)}/edit", "post", $"Save {meta.Name}", fields));
            await _renderer.RenderPage(context);
            return;
        }

        if (instance is SystemPrincipal principal)
        {
            ApplySystemPrincipalKeys(principal, apiKeyInputs, isCreate: false);
        }

        var userName = (await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false))?.UserName ?? "system";
        ApplyAuditInfo(instance, userName, isCreate: false);
        await DataScaffold.ApplyComputedFieldsAsync(meta, (BaseDataObject)instance, ComputedTrigger.OnUpdate, context.RequestAborted).ConfigureAwait(false);
        DataScaffold.ApplyCalculatedFields(meta, (BaseDataObject)instance);
        await DataScaffold.SaveAsync(meta, instance);
        
        // Audit the update operation
        if (instance is BaseDataObject newBaseDataObject && oldInstance != null)
        {
            await _auditService.AuditUpdateAsync(oldInstance, newBaseDataObject, userName, context.RequestAborted).ConfigureAwait(false);
        }
        
        context.Response.Redirect($"/ssr/admin/data/{typeSlug}?toast=updated&id={WebUtility.UrlEncode(id)}");
    }

    private static IReadOnlyList<string> ExtractSystemPrincipalKeys(IDictionary<string, string?> values)
    {
        if (!values.TryGetValue(nameof(SystemPrincipal.ApiKeyHashes), out var raw))
            return Array.Empty<string>();

        values.Remove(nameof(SystemPrincipal.ApiKeyHashes));
        if (string.IsNullOrWhiteSpace(raw))
            return Array.Empty<string>();

        return DataScaffold.ParseStringList(raw);
    }

    private static IReadOnlyList<string> ApplySystemPrincipalKeys(SystemPrincipal principal, IReadOnlyList<string> rawKeys, bool isCreate)
    {
        var createdKeys = new List<string>();
        if (rawKeys.Count == 0)
        {
            if (!isCreate)
                return createdKeys;

            rawKeys = new[] { SystemPrincipal.GenerateRawApiKey() };
        }

        foreach (var rawKey in rawKeys)
        {
            var key = rawKey?.Trim();
            if (string.IsNullOrWhiteSpace(key))
                continue;
            if (string.Equals(key, "generate", StringComparison.OrdinalIgnoreCase))
                key = SystemPrincipal.GenerateRawApiKey();

            principal.AddApiKey(key);
            createdKeys.Add(key);
        }

        return createdKeys;
    }

    public async ValueTask DataClonePostHandler(HttpContext context)
        => await HandleClonePost(context, redirectToEdit: false);

    public async ValueTask DataCloneEditPostHandler(HttpContext context)
        => await HandleClonePost(context, redirectToEdit: true);

    public async ValueTask DataDeleteHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        var id = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(id))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Data");
            context.SetStringValue("html_message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("html_message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var csrfToken = CsrfProtection.EnsureToken(context);
        var fields = new List<FormField>
        {
            new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken)
        };

            var instance = meta.Handlers.Create();
            ApplyPrefillFromQuery(meta, instance, context.Request.Query);
        context.SetStringValue("html_message", $"<p>Delete this {WebUtility.HtmlEncode(meta.Name)} record? This cannot be undone.</p>");
        context.AddFormDefinition(new FormDefinition($"/ssr/admin/data/{typeSlug}/{WebUtility.UrlEncode(id)}/delete", "post", $"Delete {meta.Name}", fields));
        await _renderer.RenderPage(context);
    }

    public async ValueTask DataDeletePostHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        var id = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(id))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Data");
            context.SetStringValue("html_message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("html_message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.SetStringValue("title", "Invalid Request");
            context.SetStringValue("html_message", "<p>Invalid form submission.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            context.SetStringValue("title", "Invalid Request");
            context.SetStringValue("html_message", "<p>Invalid security token. Please try again.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var userName = (await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false))?.UserName ?? "system";
        
        // Capture entity type for audit before deletion
        var entityTypeName = meta.Type.Name;
        
        await DataScaffold.DeleteAsync(meta, uint.Parse(id));
        
        // Audit the delete operation - create audit entry with entity type and ID
        var auditEntry = new AuditEntry(userName)
        {
            EntityType = entityTypeName,
            EntityKey = uint.Parse(id),
            Operation = AuditOperation.Delete,
            TimestampUtc = DateTime.UtcNow,
            UserName = userName,
            Notes = "Entity deleted"
        };
        _ = Task.Run(async () =>
        {
            try
            {
                await DataStoreProvider.Current.SaveAsync(auditEntry, context.RequestAborted).ConfigureAwait(false);
            }
            catch
            {
                // Swallow audit errors - don't block the delete operation
            }
        }, context.RequestAborted);
        
        context.Response.Redirect($"/ssr/admin/data/{typeSlug}?toast=deleted&id={WebUtility.UrlEncode(id)}");
    }

    public async ValueTask DataBulkDeleteHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        if (meta == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await WriteJsonResponseAsync(context, new { success = false, message = errorMessage ?? "Entity not found." });
            return;
        }

        if (!await HasEntityPermissionAsync(context, meta, context.RequestAborted).ConfigureAwait(false))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await WriteJsonResponseAsync(context, new { success = false, message = "Access denied." });
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await WriteJsonResponseAsync(context, new { success = false, message = "Invalid form submission." });
            return;
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await WriteJsonResponseAsync(context, new { success = false, message = "Invalid security token." });
            return;
        }

        var ids = form["ids"].ToArray();
        if (ids.Length == 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await WriteJsonResponseAsync(context, new { success = false, message = "No records selected." });
            return;
        }

        var successCount = 0;
        var failureCount = 0;
        var errors = new List<string>();

        foreach (var id in ids)
        {
            if (id == null) continue;
            try
            {
                await DataScaffold.DeleteAsync(meta, uint.Parse(id));
                successCount++;
            }
            catch (Exception ex)
            {
                failureCount++;
                errors.Add($"Failed to delete {id}: {ex.Message}");
            }
        }

        var message = successCount > 0
            ? $"{successCount} record(s) deleted successfully" + (failureCount > 0 ? $", {failureCount} failed" : "")
            : $"All {failureCount} delete operations failed";

        await WriteJsonResponseAsync(context, new
        {
            success = successCount > 0,
            message,
            successCount,
            failureCount,
            errors = errors.Count > 0 ? errors.ToArray() : null
        });
    }

    public async ValueTask DataBulkExportHandler(HttpContext context)
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

        var idsParam = context.Request.Query["ids"].ToString();
        if (string.IsNullOrWhiteSpace(idsParam))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("No records selected.");
            return;
        }

        var ids = idsParam.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (ids.Length == 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("No records selected.");
            return;
        }

        // Load the selected items
        var items = new List<object>();
        foreach (var id in ids)
        {
            var item = await DataScaffold.LoadAsync(meta, uint.Parse(id));
            if (item != null)
                items.Add(item);
        }

        if (items.Count == 0)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("No matching records found.");
            return;
        }

        // Determine export format
        var format = context.Request.Query["format"].ToString()?.ToLowerInvariant() ?? "csv";
        
        if (format == "json")
        {
            context.Response.ContentType = "application/json";
            context.Response.Headers.Append("Content-Disposition", $"attachment; filename=\"{typeSlug}-bulk-export.json\"");
            await using var writer = new Utf8JsonWriter(context.Response.Body, new JsonWriterOptions { Indented = true });
            writer.WriteStartArray();
            foreach (var item in items)
            {
                WriteJsonValue(writer, item);
            }
            writer.WriteEndArray();
            await writer.FlushAsync();
        }
        else if (format == "html")
        {
            var headers = DataScaffold.BuildListHeaders(meta, includeActions: false);
            var rows = DataScaffold.BuildListRows(meta, items, string.Empty, includeActions: false);
            
            context.Response.ContentType = "text/html";
            context.Response.Headers.Append("Content-Disposition", $"attachment; filename=\"{typeSlug}-bulk-export.html\"");
            
            var html = new StringBuilder();
            html.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>");
            html.Append(WebUtility.HtmlEncode(meta.Name));
            html.Append(" Bulk Export</title></head><body><h1>");
            html.Append(WebUtility.HtmlEncode(meta.Name));
            html.Append("</h1><table border=\"1\"><thead><tr>");
            
            foreach (var header in headers)
            {
                html.Append("<th>");
                html.Append(WebUtility.HtmlEncode(header));
                html.Append("</th>");
            }
            
            html.Append("</tr></thead><tbody>");
            
            foreach (var row in rows)
            {
                html.Append("<tr>");
                foreach (var cell in row)
                {
                    html.Append("<td>");
                    html.Append(cell); // Already HTML-encoded by BuildListRows
                    html.Append("</td>");
                }
                html.Append("</tr>");
            }
            
            html.Append("</tbody></table></body></html>");
            await context.Response.WriteAsync(html.ToString());
        }
        else // Default to CSV
        {
            var headers = DataScaffold.BuildListHeaders(meta, includeActions: false);
            var rows = DataScaffold.BuildListRows(meta, items, string.Empty, includeActions: false);
            
            context.Response.ContentType = "text/csv";
            context.Response.Headers.Append("Content-Disposition", $"attachment; filename=\"{typeSlug}-bulk-export.csv\"");
            
            using var writer = new StreamWriter(context.Response.Body);
            await writer.WriteLineAsync(string.Join(",", headers.Select(EscapeCsvValue)));
            
            foreach (var row in rows)
            {
                var cleanRow = row.Select(cell => StripHtmlTags(cell)).ToArray();
                await writer.WriteLineAsync(string.Join(",", cleanRow.Select(EscapeCsvValue)));
            }
        }
    }

    private static string StripHtmlTags(string html)
    {
        if (string.IsNullOrWhiteSpace(html))
            return string.Empty;
        
        // Simple HTML tag removal (for checkbox and link elements in list rows)
        var text = System.Text.RegularExpressions.Regex.Replace(html, "<[^>]+>", string.Empty);
        return WebUtility.HtmlDecode(text);
    }

    private static string EscapeCsvValue(string value)
    {
        if (string.IsNullOrEmpty(value))
            return "\"\"";
        
        if (value.Contains('"') || value.Contains(',') || value.Contains('\n') || value.Contains('\r'))
        {
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }
        
        return value;
    }

    private async ValueTask HandleClonePost(HttpContext context, bool redirectToEdit)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
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

        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid form submission.");
            return;
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid security token.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, uint.Parse(id));
        if (instance is not BaseDataObject source)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Item not found.");
            return;
        }

        var clone = CreateClone(meta, source);
        ApplyAuditInfo(clone, (await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false))?.UserName ?? "system", isCreate: true);
        await DataScaffold.ApplyAutoIdAsync(meta, clone, context.RequestAborted).ConfigureAwait(false);
        await DataScaffold.ApplyComputedFieldsAsync(meta, clone, ComputedTrigger.OnCreate, context.RequestAborted).ConfigureAwait(false);
        DataScaffold.ApplyCalculatedFields(meta, clone);

        var cloneErrors = new List<string>();
        await ValidateUserUniquenessAsync(meta, clone, excludeId: null, cloneErrors, context.RequestAborted).ConfigureAwait(false);
        if (cloneErrors.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync(string.Join(" | ", cloneErrors));
            return;
        }

        await DataScaffold.SaveAsync(meta, clone);

        var newId = DataScaffold.GetIdValue(clone) ?? string.Empty;
        if (redirectToEdit)
        {
            var editUrl = $"/ssr/admin/data/{typeSlug}/{WebUtility.UrlEncode(newId)}/edit?toast=cloned&id={WebUtility.UrlEncode(newId)}";
            context.Response.Redirect(editUrl);
            return;
        }

        var returnUrl = form["returnUrl"].ToString();
        if (IsValidCloneReturnUrl(returnUrl))
        {
            var separator = returnUrl.Contains('?') ? "&" : "?";
            context.Response.Redirect($"{returnUrl}{separator}toast=cloned&id={WebUtility.UrlEncode(newId)}");
        }
        else
        {
            context.Response.Redirect($"/ssr/admin/data/{typeSlug}?toast=cloned&id={WebUtility.UrlEncode(newId)}");
        }
    }

    private static bool IsValidCloneReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
            return false;
        if (returnUrl.Contains("://") || returnUrl.StartsWith("//", StringComparison.Ordinal))
            return false;
        if (!returnUrl.StartsWith("/ssr/admin/data/", StringComparison.OrdinalIgnoreCase))
            return false;
        return true;
    }

    private static BaseDataObject CreateClone(DataEntityMetadata meta, BaseDataObject source)
    {
        var clone = meta.Handlers.Create();
        foreach (var field in meta.Fields.OrderBy(f => f.Order))
        {
            var property = field.Property;
            if (!property.CanWrite)
                continue;
            if (IsCloneExcluded(property.Name))
                continue;
            property.SetValue(clone, property.GetValue(source));
        }

        return clone;
    }

    private static bool IsCloneExcluded(string propertyName)
    {
        return string.Equals(propertyName, nameof(BaseDataObject.Key), StringComparison.OrdinalIgnoreCase)
            || string.Equals(propertyName, nameof(BaseDataObject.CreatedOnUtc), StringComparison.OrdinalIgnoreCase)
            || string.Equals(propertyName, nameof(BaseDataObject.UpdatedOnUtc), StringComparison.OrdinalIgnoreCase)
            || string.Equals(propertyName, nameof(BaseDataObject.CreatedBy), StringComparison.OrdinalIgnoreCase)
            || string.Equals(propertyName, nameof(BaseDataObject.UpdatedBy), StringComparison.OrdinalIgnoreCase)
            || string.Equals(propertyName, nameof(BaseDataObject.ETag), StringComparison.OrdinalIgnoreCase);
    }

    private static string BuildToastHtml(HttpContext context, string entityName)
    {
        var toast = context.Request.Query["toast"].ToString();
        if (string.IsNullOrWhiteSpace(toast))
            return string.Empty;

        var action = toast.Trim().ToLowerInvariant();
        var id = context.Request.Query["id"].ToString();
        var idSuffix = string.IsNullOrWhiteSpace(id) ? string.Empty : $" (ID: {WebUtility.HtmlEncode(id)})";
        var name = WebUtility.HtmlEncode(entityName);
        var apiKey = context.Request.Query["apikey"].ToString();
        var apiKeyNote = string.IsNullOrWhiteSpace(apiKey)
            ? string.Empty
            : $"<div class=\"small mt-2\"><strong>API Key:</strong> {WebUtility.HtmlEncode(apiKey)}<br/><strong>STORE THIS IN A SECURE PLACE - you will not see it again.</strong></div>";
        var message = action switch
        {
            "created" => $"{name} created successfully{idSuffix}.{apiKeyNote}",
            "updated" => $"{name} updated successfully{idSuffix}.",
            "deleted" => $"{name} deleted successfully{idSuffix}.",
            "cloned" => $"{name} cloned successfully{idSuffix}.",
            _ => string.Empty
        };

        if (string.IsNullOrWhiteSpace(message))
            return string.Empty;

        return $"<div class=\"toast-container position-fixed bottom-0 end-0 p-3 toast-z-index\">" +
             $"<div id=\"scaffold-toast\" class=\"toast text-bg-success border-0\" role=\"alert\" aria-live=\"assertive\" aria-atomic=\"true\" data-bs-delay=\"2500\">" +
             $"<div class=\"d-flex\"><div class=\"toast-body\">{message}</div>" +
             $"<button type=\"button\" class=\"btn-close btn-close-white me-2 m-auto\" data-bs-dismiss=\"toast\" aria-label=\"Close\"></button></div></div></div>";
    }

    public async ValueTask DataApiListHandler(HttpContext context)
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

        var queryDict = ToQueryDictionary(context.Request.Query);
        var query = DataScaffold.BuildQueryDefinition(queryDict, meta);

        var format = context.Request.Query["format"].ToString().ToLowerInvariant();
        var acceptCsv = context.Request.Headers["Accept"].ToString().Contains("text/csv", StringComparison.OrdinalIgnoreCase);

        // When pagination parameters are present, run the data and count queries concurrently
        // and return { items, total } so the VNext UI can render page controls correctly.
        if (query.Skip.HasValue || query.Top.HasValue)
        {
            var countQuery = DataScaffold.BuildQueryDefinition(queryDict, meta);
            countQuery.Skip = null;
            countQuery.Top = null;

            var dataTask  = DataScaffold.QueryAsync(meta, query, context.RequestAborted).AsTask();
            var countTask = DataScaffold.CountAsync(meta, countQuery, context.RequestAborted).AsTask();
            await Task.WhenAll(dataTask, countTask).ConfigureAwait(false);

            var results = await dataTask;
            var total   = await countTask;

            if (format == "csv" || acceptCsv)
            {
                var resultsList = results.Cast<object?>().ToList();
                var rows = BuildListPlainRowsWithId(meta, resultsList, out var headers);
                var csv = BuildCsv(headers, rows);
                await WriteTextResponseAsync(context, "text/csv", csv, $"{typeSlug}_list.csv");
                return;
            }

            var payload = results.Cast<object>().Select(item => BuildApiModel(meta, item)).ToArray();
            // Clamp total: if fewer items than requested were returned, the real total cannot exceed skip + returned count.
            // This prevents inflated page counts when the location map has stale entries for unreadable records.
            // Applies whether or not Top was specified: without a top limit we also know the total is at most skip + payload.Length.
            if (!query.Top.HasValue || payload.Length < query.Top.Value)
                total = Math.Min(total, (query.Skip ?? 0) + payload.Length);
            await WriteJsonResponseAsync(context, new Dictionary<string, object?> { ["items"] = payload, ["total"] = total });
            return;
        }

        var allResults = await DataScaffold.QueryAsync(meta, query, context.RequestAborted).ConfigureAwait(false);

        if (format == "csv" || acceptCsv)
        {
            var resultsList = allResults.Cast<object?>().ToList();
            var rows = BuildListPlainRowsWithId(meta, resultsList, out var headers);
            var csv = BuildCsv(headers, rows);
            await WriteTextResponseAsync(context, "text/csv", csv, $"{typeSlug}_list.csv");
            return;
        }

        var allPayload = allResults.Cast<object>().Select(item => BuildApiModel(meta, item)).ToArray();
        await WriteJsonResponseAsync(context, allPayload);
    }

    public async ValueTask DataApiImportHandler(HttpContext context)
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

        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\":\"Multipart form data required.\"}");
            return;
        }

        var form = await context.Request.ReadFormAsync();
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
            if (row.All(string.IsNullOrWhiteSpace)) continue;

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

            var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
            foreach (var kvp in mapping)
            {
                var colIdx = kvp.Value;
                if (colIdx < row.Length)
                    values[kvp.Key] = row[colIdx];
            }

            var fieldErrors = DataScaffold.ApplyValuesFromForm(meta, instance, values, forCreate: isCreate || upsertWithExplicitId);
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

    public async ValueTask DataApiGetHandler(HttpContext context)
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

    public async ValueTask DataApiPostHandler(HttpContext context)
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
        if (context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync();
            var values = form.ToDictionary(k => k.Key, v => (string?)v.Value.ToString(), StringComparer.OrdinalIgnoreCase);
            errors = DataScaffold.ApplyValuesFromForm(meta, instance, values, forCreate: true);
            await ApplyUploadFieldsFromFormAsync(context, meta, (BaseDataObject)instance, form, errors).ConfigureAwait(false);
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

    public async ValueTask DataApiPutHandler(HttpContext context)
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
        if (context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync();
            var values = form.ToDictionary(k => k.Key, v => (string?)v.Value.ToString(), StringComparer.OrdinalIgnoreCase);
            errors = DataScaffold.ApplyValuesFromForm(meta, instance, values, forCreate: false);
            errors = FilterMissingRequiredErrorsForPatchForm(meta, values, errors);
            await ApplyUploadFieldsFromFormAsync(context, meta, (BaseDataObject)instance, form, errors).ConfigureAwait(false);
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

        ApplyAuditInfo(instance, (await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false))?.UserName ?? "system", isCreate: false);
        await DataScaffold.ApplyComputedFieldsAsync(meta, (BaseDataObject)instance, ComputedTrigger.OnUpdate, context.RequestAborted).ConfigureAwait(false);
        DataScaffold.ApplyCalculatedFields(meta, (BaseDataObject)instance);
        await DataScaffold.SaveAsync(meta, instance);
        await WriteJsonResponseAsync(context, BuildApiModel(meta, instance));
    }

    public async ValueTask DataApiPatchHandler(HttpContext context)
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
        if (context.Request.HasFormContentType)
        {
            var form = await context.Request.ReadFormAsync();
            var values = form.ToDictionary(k => k.Key, v => (string?)v.Value.ToString(), StringComparer.OrdinalIgnoreCase);
            errors = DataScaffold.ApplyValuesFromForm(meta, instance, values, forCreate: false);
            await ApplyUploadFieldsFromFormAsync(context, meta, (BaseDataObject)instance, form, errors).ConfigureAwait(false);
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

    public async ValueTask DataApiDeleteHandler(HttpContext context)
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

    public async ValueTask DataApiFileGetHandler(HttpContext context)
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

        var field = meta.Fields.FirstOrDefault(f => string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase));
        if (field == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Field not found.");
            return;
        }

        if (field.Property.GetValue(instance) is not StoredFileData fileData || string.IsNullOrWhiteSpace(fileData.StorageKey))
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

    public async ValueTask MetricsJsonHandler(HttpContext context)
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
            ["processUptimeSeconds"] = (long)snapshot.ProcessUptime.TotalSeconds
        };

        await WriteJsonResponseAsync(context, payload);
    }

    public async ValueTask LogsViewerHandler(HttpContext context)
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

            var date = ctx.Request.Query["date"].ToString();
            var hour = ctx.Request.Query["hour"].ToString();
            var file = ctx.Request.Query["file"].ToString();
            var year = ctx.Request.Query["year"].ToString();
            var month = ctx.Request.Query["month"].ToString();

            var dates = Directory.GetDirectories(root)
                .Select(Path.GetFileName)
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Select(name => name!)
                .ToList();

            if (!dates.Contains(date, StringComparer.OrdinalIgnoreCase))
                date = string.Empty;

            var hours = string.IsNullOrWhiteSpace(date)
                ? new List<string>()
                : Directory.GetDirectories(Path.Combine(root, date))
                    .Select(Path.GetFileName)
                    .Where(name => !string.IsNullOrWhiteSpace(name))
                    .Select(name => name!)
                    .ToList();

            hours = hours
                .OrderBy(h => ParseHourValue(h))
                .ThenBy(h => h, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (!hours.Contains(hour, StringComparer.OrdinalIgnoreCase))
                hour = string.Empty;

            var fileEntries = string.IsNullOrWhiteSpace(date) || string.IsNullOrWhiteSpace(hour)
                ? new List<LogFileEntry>()
                : Directory.GetFiles(Path.Combine(root, date, hour), "*.log")
                    .Select(Path.GetFileName)
                    .Where(name => !string.IsNullOrWhiteSpace(name))
                    .Select(name => BuildLogFileEntry(name!))
                    .OrderBy(entry => entry.SortKey)
                    .ThenBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
                    .ToList();

            if (!fileEntries.Any(entry => string.Equals(entry.Name, file, StringComparison.OrdinalIgnoreCase)))
                file = string.Empty;

            var yearEntries = BuildLogYears(root, dates);
            var selectedYearKey = string.IsNullOrWhiteSpace(year) ? ResolveYearKey(selectedDate: date) : year;
            var selectedMonthKey = string.IsNullOrWhiteSpace(month) ? ResolveMonthKey(selectedDate: date) : month;

            if (!yearEntries.Any(entry => string.Equals(entry.Key, selectedYearKey, StringComparison.OrdinalIgnoreCase)))
                selectedYearKey = string.Empty;

            if (string.IsNullOrWhiteSpace(selectedYearKey) && yearEntries.Count > 0)
            {
                var latestYear = yearEntries.OrderByDescending(entry => entry.YearDate).First();
                selectedYearKey = latestYear.Key;
            }

            var selectedYear = yearEntries.FirstOrDefault(entry => string.Equals(entry.Key, selectedYearKey, StringComparison.OrdinalIgnoreCase));
            if (!(selectedYear.Months?.Any(entry => string.Equals(entry.Key, selectedMonthKey, StringComparison.OrdinalIgnoreCase)) ?? false))
                selectedMonthKey = string.Empty;

            if (string.IsNullOrWhiteSpace(selectedMonthKey) && selectedYear.Months?.Count > 0)
            {
                var latestMonth = selectedYear.Months!.OrderByDescending(entry => entry.MonthDate).First();
                selectedMonthKey = latestMonth.Key;
            }

            var monthEntries = yearEntries.SelectMany(entry => entry.Months).ToList();
            var actionsHtml = RenderLogActions(yearEntries, selectedYearKey, selectedMonthKey, date, hour);

            var html = new StringBuilder();
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
                var selectedEntry = fileEntries.FirstOrDefault(entry => string.Equals(entry.Name, file, StringComparison.OrdinalIgnoreCase));

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

    public async ValueTask LogsPruneHandler(HttpContext context)
    {
        await BuildPageHandler(ctx =>
        {
            var root = GetLogRoot(ctx);
            if (!TryResolveLogTarget(ctx.Request.Query, root, out var target, out var errorMessage))
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

    public async ValueTask LogsPrunePostHandler(HttpContext context)
    {
        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var root = GetLogRoot(context);
        var query = new Dictionary<string, StringValues>(StringComparer.OrdinalIgnoreCase)
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

    public async ValueTask LogsDownloadHandler(HttpContext context)
    {
        var root = GetLogRoot(context);
        if (!TryResolveLogTarget(context.Request.Query, root, out var target, out var errorMessage))
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

    public async ValueTask SampleDataHandler(HttpContext context)
    {
        await BuildPageHandler(ctx =>
        {
            RenderSampleDataForm(ctx, "<p>Generate sample data for load and indexing tests.</p>", 100, 50, 25, 25, 10, 25, 20, 10, 10, clearExisting: false);
        })(context);
    }

    public async ValueTask SampleDataPostHandler(HttpContext context)
    {
        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.SetStringValue("title", "Generate Sample Data");
            context.SetStringValue("html_message", "<p>Invalid form submission.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            context.SetStringValue("title", "Generate Sample Data");
            context.SetStringValue("html_message", "<p>Invalid security token. Please try again.</p>");
            RenderSampleDataForm(context, "<p>Invalid security token. Please try again.</p>", 100, 50, 25, 25, 10, 25, 20, 10, 10, clearExisting: false);
            await _renderer.RenderPage(context);
            return;
        }

        var errors = new List<string>();
        var addressCount = ParseSampleCount(form, "addresses", errors);
        var customerCount = ParseSampleCount(form, "customers", errors);
        var unitCount = ParseSampleCount(form, "units", errors);
        var productCount = ParseSampleCount(form, "products", errors);
        var employeeCount = ParseSampleCount(form, "employees", errors);
        var orderCount = ParseSampleCount(form, "orders", errors);
        var todoCount = ParseSampleCount(form, "todos", errors);
        var timeTablePlanCount = ParseSampleCount(form, "timeTablePlans", errors);
        var lessonLogCount = ParseSampleCount(form, "lessonLogs", errors);
        var clearExisting = ParseSampleToggle(form, "clearExisting");

        if (customerCount > 0 && addressCount == 0)
            errors.Add("Customers require at least one address.");
        if (productCount > 0 && unitCount == 0)
            errors.Add("Products require at least one unit of measure.");
        if (orderCount > 0 && customerCount == 0)
            errors.Add("Orders require at least one customer.");

        if (errors.Count > 0)
        {
            context.SetStringValue("title", "Generate Sample Data");
            context.SetStringValue("html_message", $"<div class=\"alert alert-danger\">{string.Join("<br/>", errors.Select(WebUtility.HtmlEncode))}</div>");
            RenderSampleDataForm(context, $"<div class=\"alert alert-danger\">{string.Join("<br/>", errors.Select(WebUtility.HtmlEncode))}</div>", addressCount, customerCount, unitCount, productCount, employeeCount, orderCount, todoCount, timeTablePlanCount, lessonLogCount, clearExisting);
            await _renderer.RenderPage(context);
            return;
        }

        var userName = (await UserAuth.GetUserAsync(context, context.RequestAborted).ConfigureAwait(false))?.UserName ?? "system";

        // Capture parameters so the background task doesn't reference HttpContext.
        var capturedAddressCount  = addressCount;  var capturedCustomerCount  = customerCount;
        var capturedUnitCount     = unitCount;      var capturedProductCount   = productCount;
        var capturedEmployeeCount = employeeCount;  var capturedOrderCount     = orderCount;
        var capturedTodoCount     = todoCount;      var capturedTtpCount       = timeTablePlanCount;
        var capturedLlCount       = lessonLogCount; var capturedClearExisting  = clearExisting;
        var capturedUserName      = userName;

        var jobId = BackgroundJobService.Instance.StartJob(
            "Generate Sample Data",
            "/admin/sample-data",
            async (progress, ct) =>
            {
                progress.Report(0, "Starting sample data generation…");

                if (capturedClearExisting)
                {
                    progress.Report(2, "Clearing existing data…");
                    await DeleteAllAsync<Customer>(ct);
                    await DeleteAllAsync<Product>(ct);
                    await DeleteAllAsync<Address>(ct);
                    await DeleteAllAsync<UnitOfMeasure>(ct);
                    await DeleteAllAsync<Employee>(ct);
                    await DeleteAllAsync<Order>(ct);
                    await DeleteAllAsync<ToDo>(ct);
                    await DeleteAllAsync<TimeTablePlan>(ct);
                    await DeleteAllAsync<LessonLog>(ct);
                }

                progress.Report(5, "Querying existing records…");
                var addresses_query = await DataStoreProvider.Current.QueryAsync<Address>(null, ct).ConfigureAwait(false);
                var usedAddressIds = new HashSet<string>(addresses_query.Select(a => a.Key.ToString()), StringComparer.OrdinalIgnoreCase);
                var units_query = await DataStoreProvider.Current.QueryAsync<UnitOfMeasure>(null, ct).ConfigureAwait(false);
                var usedUnitIds = new HashSet<string>(units_query.Select(u => u.Key.ToString()), StringComparer.OrdinalIgnoreCase);
                var customers_query = await DataStoreProvider.Current.QueryAsync<Customer>(null, ct).ConfigureAwait(false);
                var usedCustomerIds = new HashSet<string>(customers_query.Select(c => c.Key.ToString()), StringComparer.OrdinalIgnoreCase);
                var products_query = await DataStoreProvider.Current.QueryAsync<Product>(null, ct).ConfigureAwait(false);
                var usedProductIds = new HashSet<string>(products_query.Select(p => p.Key.ToString()), StringComparer.OrdinalIgnoreCase);
                var employees_query = await DataStoreProvider.Current.QueryAsync<Employee>(null, ct).ConfigureAwait(false);
                var usedEmployeeIds = new HashSet<string>(employees_query.Select(e => e.Key.ToString()), StringComparer.OrdinalIgnoreCase);
                var orders_query = await DataStoreProvider.Current.QueryAsync<Order>(null, ct).ConfigureAwait(false);
                var usedOrderIds = new HashSet<string>(orders_query.Select(o => o.Key.ToString()), StringComparer.OrdinalIgnoreCase);
                var todos_query = await DataStoreProvider.Current.QueryAsync<ToDo>(null, ct).ConfigureAwait(false);
                var usedTodoIds = new HashSet<string>(todos_query.Select(t => t.Key.ToString()), StringComparer.OrdinalIgnoreCase);
                var ttpQuery = await DataStoreProvider.Current.QueryAsync<TimeTablePlan>(null, ct).ConfigureAwait(false);
                var usedTtpIds = new HashSet<string>(ttpQuery.Select(t => t.Key.ToString()), StringComparer.OrdinalIgnoreCase);
                var llQuery = await DataStoreProvider.Current.QueryAsync<LessonLog>(null, ct).ConfigureAwait(false);
                var usedLessonLogIds = new HashSet<string>(llQuery.Select(l => l.Key.ToString()), StringComparer.OrdinalIgnoreCase);

                progress.Report(10, "Generating addresses and units…");
                var addresses = GenerateAddresses(capturedAddressCount, usedAddressIds);
                var units = GenerateUnits(capturedUnitCount, usedUnitIds);

                progress.Report(20, "Generating customers and products…");
                var customers = GenerateCustomers(capturedCustomerCount, addresses, usedCustomerIds);
                var products = GenerateProducts(capturedProductCount, units, usedProductIds);
                var employees = GenerateEmployees(capturedEmployeeCount, usedEmployeeIds);

                progress.Report(30, "Generating currencies and orders…");
                var existingCurrencies = (await DataStoreProvider.Current.QueryAsync<Currency>(null, ct).ConfigureAwait(false)).ToList();
                var usedCurrencyIds = new HashSet<string>(existingCurrencies.Select(c => c.Key.ToString()), StringComparer.OrdinalIgnoreCase);
                List<Currency> seedCurrencies = new();
                if (capturedOrderCount > 0 && existingCurrencies.Count == 0)
                    seedCurrencies = GenerateSeedCurrencies(usedCurrencyIds);

                var allCurrencies = existingCurrencies.Concat(seedCurrencies).ToList();
                var allCustomers = customers_query.ToList().Concat(customers).ToList();
                var allProducts = products_query.ToList().Concat(products).ToList();
                var orders = GenerateOrders(capturedOrderCount, allCustomers, allProducts, allCurrencies, usedOrderIds);

                progress.Report(40, "Generating subjects, todos and timetable plans…");
                var existingSubjects = (await DataStoreProvider.Current.QueryAsync<Subject>(null, ct).ConfigureAwait(false)).ToList();
                var usedSubjectIds = new HashSet<string>(existingSubjects.Select(s => s.Key.ToString()), StringComparer.OrdinalIgnoreCase);
                List<Subject> seedSubjects = new();
                if ((capturedTtpCount > 0 || capturedLlCount > 0) && existingSubjects.Count == 0)
                    seedSubjects = GenerateSeedSubjects(usedSubjectIds);

                var allSubjects = existingSubjects.Concat(seedSubjects).ToList();
                var todos = GenerateToDos(capturedTodoCount, usedTodoIds);
                var timeTablePlans = GenerateTimeTablePlans(capturedTtpCount, allSubjects, usedTtpIds);
                var lessonLogs = GenerateLessonLogs(capturedLlCount, allSubjects, usedLessonLogIds);

                // Calculate total items to save for per-item progress reporting.
                // Progress range: 50 (start of save phase) to 95 (end of save phase) = 45 points.
                const int saveProgressStart = 50;
                const int saveProgressRange = 45;
                int totalItems = addresses.Count + units.Count + customers.Count + products.Count +
                                 employees.Count + seedCurrencies.Count + orders.Count +
                                 seedSubjects.Count + todos.Count + timeTablePlans.Count + lessonLogs.Count;
                int saved = 0;

                async Task SaveItemsWithProgress<T>(List<T> items, string label) where T : BaseDataObject
                {
                    foreach (var item in items)
                    {
                        ct.ThrowIfCancellationRequested();
                        ApplyAuditInfo(item, capturedUserName, isCreate: true);
                        await DataStoreProvider.Current.SaveAsync(item, ct).ConfigureAwait(false);
                        saved++;
                        if (totalItems > 0)
                            progress.Report(
                                saveProgressStart + (int)(saved * (double)saveProgressRange / totalItems),
                                $"Saving {label}… ({saved}/{totalItems})");
                    }
                }

                progress.Report(saveProgressStart, "Saving generated records…");
                await SaveItemsWithProgress(addresses, "addresses");
                await SaveItemsWithProgress(units, "units");
                await SaveItemsWithProgress(customers, "customers");
                await SaveItemsWithProgress(products, "products");
                await SaveItemsWithProgress(employees, "employees");
                await SaveItemsWithProgress(seedCurrencies, "currencies");
                await SaveItemsWithProgress(orders, "orders");
                await SaveItemsWithProgress(seedSubjects, "subjects");
                await SaveItemsWithProgress(todos, "to-dos");
                await SaveItemsWithProgress(timeTablePlans, "timetable plans");
                await SaveItemsWithProgress(lessonLogs, "lesson logs");

                progress.Report(100, $"Done. Created {addresses.Count} addresses, {customers.Count} customers, " +
                    $"{units.Count} units, {products.Count} products, {employees.Count} employees, " +
                    $"{orders.Count} orders, {todos.Count} to-dos, {timeTablePlans.Count} timetable plans, " +
                    $"{lessonLogs.Count} lesson logs." +
                    (seedCurrencies.Count > 0 ? $" Seeded {seedCurrencies.Count} currencies." : "") +
                    (seedSubjects.Count > 0 ? $" Seeded {seedSubjects.Count} subjects." : ""));
            });

        var baseUrl = $"{context.Request.Scheme}://{context.Request.Host}";
        var statusUrl = $"{baseUrl}/api/jobs/{jobId}";
        context.Response.StatusCode = StatusCodes.Status202Accepted;
        context.Response.Headers["Location"] = statusUrl;
        context.Response.Headers["Retry-After"] = "2";
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(
            JsonSerializer.Serialize(new
            {
                jobId,
                status = "queued",
                operationName = "Generate Sample Data",
                statusUrl
            })).ConfigureAwait(false);
    }

    public async ValueTask WipeDataHandler(HttpContext context)
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

    public async ValueTask WipeDataPostHandler(HttpContext context)
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
            await _renderer.RenderPage(context);
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.SetStringValue("title", "Wipe All Data");
            context.SetStringValue("html_message", "<p>Invalid form submission.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            RenderWipeDataForm(context, "<div class=\"alert alert-danger\">Invalid security token. Please try again.</div>", wipeToken);
            await _renderer.RenderPage(context);
            return;
        }

        var confirmText = form["confirm_wipe"].ToString().Trim();
        if (!string.Equals(confirmText, wipeToken, StringComparison.Ordinal))
        {
            RenderWipeDataForm(context, "<div class=\"alert alert-danger\">Confirmation text did not match. Enter the configured wipe token exactly to proceed.</div>", wipeToken);
            await _renderer.RenderPage(context);
            return;
        }

        var entities = DataScaffold.Entities;
        int totalEntities = entities.Count;

        var jobId = BackgroundJobService.Instance.StartJob(
            "Wipe All Data",
            "/admin/wipe-data",
            async (progress, ct) =>
            {
                progress.Report(0, "Starting wipe…");
                int done = 0;
                foreach (var entity in entities)
                {
                    ct.ThrowIfCancellationRequested();
                    progress.Report(
                        totalEntities == 0 ? 0 : (int)(done * 95.0 / totalEntities),
                        $"Wiping {entity.Name}…");

                    var items = (await entity.Handlers.QueryAsync(null, ct).ConfigureAwait(false)).ToList();
                    foreach (var item in items)
                    {
                        if (item == null || item.Key == 0)
                            continue;
                        ct.ThrowIfCancellationRequested();
                        await entity.Handlers.DeleteAsync(item.Key, ct).ConfigureAwait(false);
                    }
                    done++;
                }
                progress.Report(100, $"Done. Wiped {done} entity store{(done == 1 ? "" : "s")}.");
            });

        var baseUrl = $"{context.Request.Scheme}://{context.Request.Host}";
        var statusUrl = $"{baseUrl}/api/jobs/{jobId}";
        context.Response.StatusCode = StatusCodes.Status202Accepted;
        context.Response.Headers["Location"] = statusUrl;
        context.Response.Headers["Retry-After"] = "2";
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(
            JsonSerializer.Serialize(new
            {
                jobId,
                status = "queued",
                operationName = "Wipe All Data",
                statusUrl
            })).ConfigureAwait(false);
    }

    private void RenderWipeDataForm(HttpContext context, string? message, string wipeToken)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Wipe All Data");

        var warningHtml = new StringBuilder();
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

    public async ValueTask EntityDesignerHandler(HttpContext context)
    {
        await BuildPageHandler(ctx =>
        {
            ctx.SetStringValue("title", "Entity Designer");
            ctx.SetStringValue("html_message",
                "<div id=\"designer-root\"><p class=\"text-muted\">Loading designer…</p></div>" +
                "<script src=\"/static/js/entity-designer.js\"></script>");
        })(context);
    }

    public async ValueTask GalleryHandler(HttpContext context)
    {
        await BuildPageHandler(async ctx =>
        {
            var packages = SampleGalleryService.GetAllPackages();

            // Determine which packages are already deployed (have at least one EntityDefinition with matching slug)
            var deployedSlugs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var existingDefs = (await DataStoreProvider.Current.QueryAsync<EntityDefinition>(null, ctx.RequestAborted)
                .ConfigureAwait(false)).ToList();
            var existingSlugs = existingDefs
                .Select(e => e.Slug ?? string.Empty)
                .Where(s => s.Length > 0)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            foreach (var pkg in packages)
            {
                if (pkg.Entities.Any(e => existingSlugs.Contains(e.Slug ?? string.Empty)))
                    deployedSlugs.Add(pkg.Slug);
            }

            var sb = new StringBuilder();
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

    public async ValueTask GalleryDeployPostHandler(HttpContext context)
    {
        var packageSlug = GetRouteValue(context, "package") ?? string.Empty;

        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid form submission.");
            return;
        }

        var form = await context.Request.ReadFormAsync();
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

        var message = deployed.Count > 0
            ? $"<div class=\"alert alert-success\">Deployed <strong>{WebUtility.HtmlEncode(pkg.Name)}</strong>: {deployed.Count} entit{(deployed.Count == 1 ? "y" : "ies")} imported.</div>"
            : $"<div class=\"alert alert-info\">Package <strong>{WebUtility.HtmlEncode(pkg.Name)}</strong> entities are already deployed. No changes made.</div>";

        context.Response.Redirect("/admin/gallery");
        _ = message; // redirect supersedes any rendered message
    }

    private async ValueTask ApplyUploadFieldsFromFormAsync(HttpContext context, DataEntityMetadata meta, BaseDataObject instance, IFormCollection form, List<string> errors)
    {
        foreach (var field in meta.Fields.Where(f => f.FieldType == FormFieldType.File || f.FieldType == FormFieldType.Image))
        {
            var deleteKey = $"{field.Name}__delete";
            var deleteRequested = form.TryGetValue(deleteKey, out var deleteValue) && DataScaffold.IsTruthy(deleteValue.ToString());
            var uploadedFile = form.Files.GetFile(field.Name);
            var existingFile = field.Property.GetValue(instance) as StoredFileData;

            if (deleteRequested && uploadedFile == null)
            {
                if (existingFile != null)
                    DeleteStoredFile(context, existingFile);
                field.Property.SetValue(instance, null);
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

                if (config.AllowedMimeTypes.Length > 0 && !config.AllowedMimeTypes.Contains(uploadedFile.ContentType, StringComparer.OrdinalIgnoreCase))
                {
                    errors.Add($"{field.Label} has an invalid file type.");
                    continue;
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

            field.Property.SetValue(instance, storedFile);
        }
    }

    private static string SanitizeFileName(string? fileName)
    {
        var safeName = Path.GetFileName(fileName ?? string.Empty);
        return string.IsNullOrWhiteSpace(safeName) ? "upload.bin" : safeName;
    }

    private string ResolveUploadPath(HttpContext context, string storageKey)
    {
        var rootPath = GetUploadRootPath(context);
        var sanitizedKey = storageKey.Replace('\\', '/').TrimStart('/');
        var combined = Path.Combine(rootPath, sanitizedKey.Replace('/', Path.DirectorySeparatorChar));
        var full = Path.GetFullPath(combined);
        if (!full.StartsWith(Path.GetFullPath(rootPath), StringComparison.Ordinal))
            throw new InvalidOperationException("Invalid upload storage key.");
        return full;
    }

    private string GetUploadRootPath(HttpContext context)
    {
        var configuration = context.RequestServices.GetService(typeof(IConfiguration)) as IConfiguration;
        #pragma warning disable IL2026 // ConfigurationBinder.GetValue with string primitive is trim-safe
        var configured = configuration?.GetValue("Uploads:RootDirectory", "uploads") ?? "uploads";
        #pragma warning restore IL2026
        if (Path.IsPathRooted(configured))
            return configured;
        return Path.Combine(_dataRootFolder, configured);
    }

    private void DeleteStoredFile(HttpContext context, StoredFileData storedFile)
    {
        if (string.IsNullOrWhiteSpace(storedFile.StorageKey))
            return;

        var fullPath = ResolveUploadPath(context, storedFile.StorageKey);
        if (File.Exists(fullPath))
            File.Delete(fullPath);
    }

    internal static Dictionary<string, object?> BuildApiModel(DataEntityMetadata meta, object instance)
    {
        var data = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        var id = instance is BaseDataObject dataObject ? DataScaffold.GetIdValue(dataObject) : null;
        if (!string.IsNullOrWhiteSpace(id))
            data["id"] = id;

        foreach (var field in meta.Fields.Where(f => f.View))
        {
            var value = field.Property.GetValue(instance);
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


    private static string GetLogRoot(HttpContext context)
    {
        var config = context.RequestServices.GetService(typeof(IConfiguration)) as IConfiguration;
        #pragma warning disable IL2026 // ConfigurationBinder.GetValue with string primitive is trim-safe
        var logFolder = config?.GetValue("Logging:LogFolder", "Logs") ?? "Logs";
        #pragma warning restore IL2026
        if (Path.IsPathRooted(logFolder))
            return logFolder;

        return Path.Combine(AppContext.BaseDirectory, logFolder);
    }

    private static string RenderLogTree(IReadOnlyList<LogYearEntry> years, IReadOnlyList<string> hours, IReadOnlyList<LogFileEntry> files, string selectedYearKey, string selectedMonthKey, string selectedDate, string selectedHour, string selectedFile)
    {
        var html = new StringBuilder();
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

    private static string RenderLogActions(IReadOnlyList<LogYearEntry> years, string selectedYearKey, string selectedMonthKey, string selectedDate, string selectedHour)
    {
        var html = new StringBuilder();
        if (string.IsNullOrWhiteSpace(selectedYearKey) && string.IsNullOrWhiteSpace(selectedMonthKey) && string.IsNullOrWhiteSpace(selectedDate) && string.IsNullOrWhiteSpace(selectedHour))
            return string.Empty;

        var year = years.FirstOrDefault(entry => string.Equals(entry.Key, selectedYearKey, StringComparison.OrdinalIgnoreCase));
        var months = year.Months ?? Array.Empty<LogMonthEntry>();
        var month = months.FirstOrDefault(entry => string.Equals(entry.Key, selectedMonthKey, StringComparison.OrdinalIgnoreCase));
        var days = month.Days ?? Array.Empty<LogDayEntry>();
        var day = days.FirstOrDefault(entry => string.Equals(entry.Folder, selectedDate, StringComparison.OrdinalIgnoreCase));

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

    private static string RenderLogActionButtons(string downloadHref, string pruneHref)
    {
        return $"<span class=\"bm-log-crumb-actions\"><a class=\"btn btn-sm btn-outline-secondary\" href=\"{downloadHref}\" aria-label=\"Download ZIP\" title=\"Download ZIP\"><i class=\"bi bi-save\" aria-hidden=\"true\"></i></a><a class=\"btn btn-sm btn-outline-danger\" href=\"{pruneHref}\" aria-label=\"Prune logs\" title=\"Prune logs\"><i class=\"bi bi-x-lg\" aria-hidden=\"true\"></i></a></span>";
    }

    private static string RenderLogFile(string path, string fileName, bool isError)
    {
        var html = new StringBuilder();
        var headerClass = isError ? "bm-log-viewer-header bm-log-error" : "bm-log-viewer-header";
        html.Append($"<div class=\"{headerClass}\">{WebUtility.HtmlEncode(fileName)}</div>");

        if (!File.Exists(path))
        {
            html.Append("<p class=\"text-danger mb-0\">Log file not found.</p>");
            return html.ToString();
        }

        const int maxLines = 2000;
        var lines = new StringBuilder();
        var truncated = false;
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
        if (truncated)
        {
            html.Append("<p class=\"text-muted mt-2 mb-0\">Output truncated.</p>");
        }
        return html.ToString();
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

            var dayFolders = Directory.GetDirectories(root)
                .Select(Path.GetFileName)
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Select(name => name!)
                .Where(name => TryParseDayFolder(name, out var dateValue) && dateValue.Year == yearValue)
                .Select(name => Path.Combine(root, name))
                .Where(Directory.Exists)
                .ToList();

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

            var dayFolders = Directory.GetDirectories(root)
                .Select(Path.GetFileName)
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Select(name => name!)
                .Where(name => TryParseDayFolder(name, out var dateValue) && dateValue.Year == monthDate.Year && dateValue.Month == monthDate.Month)
                .Select(name => Path.Combine(root, name))
                .Where(Directory.Exists)
                .ToList();

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

        if (Directory.EnumerateFileSystemEntries(dayPath).Any())
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

        var years = dayEntries
            .GroupBy(entry => entry.YearKey, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var first = group.First();
                var yearDate = first.Date == DateTime.MinValue
                    ? DateTime.MaxValue
                    : new DateTime(first.Date.Year, 1, 1, 0, 0, 0, DateTimeKind.Utc);

                var months = group
                    .GroupBy(entry => entry.MonthKey, StringComparer.OrdinalIgnoreCase)
                    .Select(monthGroup =>
                    {
                        var monthFirst = monthGroup.First();
                        var monthDate = monthFirst.Date == DateTime.MinValue
                            ? DateTime.MaxValue
                            : new DateTime(monthFirst.Date.Year, monthFirst.Date.Month, 1, 0, 0, 0, DateTimeKind.Utc);
                        var days = monthGroup
                            .OrderBy(entry => entry.Date == DateTime.MinValue ? DateTime.MaxValue : entry.Date)
                            .ThenBy(entry => entry.Folder, StringComparer.OrdinalIgnoreCase)
                            .ToList();
                        var monthSize = days.Sum(entry => entry.SizeBytes);
                        return new LogMonthEntry(monthGroup.Key, monthFirst.MonthLabel, monthDate, days, monthSize);
                    })
                    .OrderBy(entry => entry.MonthDate)
                    .ToList();

                var yearSize = months.Sum(entry => entry.SizeBytes);
                return new LogYearEntry(group.Key, first.YearLabel, yearDate, months, yearSize);
            })
            .OrderBy(entry => entry.YearDate)
            .ToList();

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

    private static DataEntityMetadata? ResolveEntity(HttpContext context, out string typeSlug, out string? errorMessage)
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

    private static string? GetRouteValue(HttpContext context, string key)
    {
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
        var dict = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in query)
        {
            dict[kvp.Key] = kvp.Value.ToString();
        }

        return dict;
    }

    private static string[][] BuildListPlainRows(DataEntityMetadata metadata, IEnumerable items)
    {
        var rows = DataScaffold.BuildListRows(metadata, items, string.Empty, includeActions: false);
        return rows
            .Select(row => row.Select(cell => StripHtml(WebUtility.HtmlDecode(cell ?? string.Empty))).ToArray())
            .ToArray();
    }

    private static string[][] BuildListPlainRowsWithId(DataEntityMetadata metadata, IReadOnlyList<object?> items, out string[] headers)
    {
        var filteredItems = items.Where(item => item != null).ToList();
        var baseRows = BuildListPlainRows(metadata, filteredItems);
        headers = new[] { "Id" }.Concat(DataScaffold.BuildListHeaders(metadata, includeActions: false)).ToArray();

        var output = new string[baseRows.Length][];
        for (int i = 0; i < baseRows.Length; i++)
        {
            var id = filteredItems[i] is BaseDataObject dataObject
                ? DataScaffold.GetIdValue(dataObject) ?? string.Empty
                : string.Empty;
            output[i] = new[] { id }.Concat(baseRows[i]).ToArray();
        }

        return output;
    }

    private static async ValueTask WriteTextResponseAsync(HttpContext context, string contentType, string content, string fileName)
    {
        context.Response.ContentType = contentType;
        context.Response.Headers["Content-Disposition"] = $"attachment; filename=\"{fileName}\"";
        await context.Response.WriteAsync(content);
    }

    private static string BuildCsv(string[] headers, string[][] rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(",", headers.Select(CsvEscape)));
        foreach (var row in rows)
        {
            sb.AppendLine(string.Join(",", row.Select(CsvEscape)));
        }

        return sb.ToString();
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

    private async ValueTask ExportHierarchicalJson(HttpContext context, DataEntityMetadata meta, string typeSlug, IReadOnlyList<object?> items, ExportOptions options)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
        #pragma warning disable IL2026 // Serializing IReadOnlyList<object?> — all entity types preserved via TrimmerRootAssembly
        var json = JsonSerializer.Serialize(items, jsonOptions);
        #pragma warning restore IL2026
        context.Response.ContentType = "application/json";
        context.Response.Headers["Content-Disposition"] = $"attachment; filename=\"{typeSlug}_export.json\"";
        await context.Response.WriteAsync(json);
    }

    private async ValueTask ExportSingleHierarchicalJson(HttpContext context, DataEntityMetadata meta, string typeSlug, string id, object instance, ExportOptions options)
    {
        var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
        #pragma warning disable IL2026 // Serializing entity instance — all entity types preserved via TrimmerRootAssembly
        var json = JsonSerializer.Serialize(instance, jsonOptions);
        #pragma warning restore IL2026
        context.Response.ContentType = "application/json";
        context.Response.Headers["Content-Disposition"] = $"attachment; filename=\"{typeSlug}_{WebUtility.UrlEncode(id)}.json\"";
        await context.Response.WriteAsync(json);
    }

    private async ValueTask ExportFlatCsv(HttpContext context, DataEntityMetadata meta, string typeSlug, IReadOnlyList<object?> items, ExportOptions options)
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
        var parentHeaders = new[] { "Id" }.Concat(DataScaffold.BuildListHeaders(meta, includeActions: false)).ToList();
        var allHeaders = new List<string>(parentHeaders);
        
        // Add headers for first nested component (for simplicity, we'll flatten only the first one)
        var firstNested = nestedComponents[0];
        var nestedData = DataScaffold.ExtractNestedData(meta, items.FirstOrDefault() ?? new object());
        if (nestedData.Count > 0)
        {
            var childHeaders = nestedData[0].Headers.Select(h => $"{firstNested.Field.Label}.{h}");
            allHeaders.AddRange(childHeaders);
        }

        foreach (var item in items)
        {
            if (item == null)
                continue;

            var id = item is BaseDataObject dataObject ? DataScaffold.GetIdValue(dataObject) ?? string.Empty : string.Empty;
            var parentRow = new[] { id }.Concat(BuildListPlainRows(meta, new[] { item })[0]).ToArray();
            
            var nested = DataScaffold.ExtractNestedData(meta, item);
            if (nested.Count > 0 && nested[0].Rows.Length > 0)
            {
                // Repeat parent row for each child
                foreach (var childRow in nested[0].Rows)
                {
                    flatRows.Add(parentRow.Concat(childRow).ToArray());
                }
            }
            else
            {
                // No children, just add parent row with empty child fields
                var emptyChild = nestedData.Count > 0 ? new string[nestedData[0].Headers.Length] : Array.Empty<string>();
                flatRows.Add(parentRow.Concat(emptyChild).ToArray());
            }
        }

        var flatCsv = BuildCsv(allHeaders.ToArray(), flatRows.ToArray());
        await WriteTextResponseAsync(context, "text/csv", flatCsv, $"{typeSlug}_flat.csv");
    }

    private async ValueTask ExportSingleFlatCsv(HttpContext context, DataEntityMetadata meta, string typeSlug, string id, object instance, ExportOptions options)
    {
        if (!options.IncludeNested || options.MaxDepth < 1)
        {
            // No nested data, fall back to simple CSV
            var rows = DataScaffold.BuildViewRows(meta, instance)
                .Select(row => new[] { row.Label, row.Value })
                .ToArray();
            if (instance is BaseDataObject dataObject)
            {
                var recordId = DataScaffold.GetIdValue(dataObject) ?? string.Empty;
                rows = new[] { new[] { "Id", recordId } }.Concat(rows).ToArray();
            }
            var headers = new[] { "Field", "Value" };
            var csv = BuildCsv(headers, rows);
            await WriteTextResponseAsync(context, "text/csv", csv, $"{typeSlug}_{WebUtility.UrlEncode(id)}_flat.csv");
            return;
        }

        var nestedComponents = DataScaffold.GetNestedComponents(meta);
        if (nestedComponents.Count == 0)
        {
            // No nested components
            var rows = DataScaffold.BuildViewRows(meta, instance)
                .Select(row => new[] { row.Label, row.Value })
                .ToArray();
            if (instance is BaseDataObject dataObject)
            {
                var recordId = DataScaffold.GetIdValue(dataObject) ?? string.Empty;
                rows = new[] { new[] { "Id", recordId } }.Concat(rows).ToArray();
            }
            var headers = new[] { "Field", "Value" };
            var csv = BuildCsv(headers, rows);
            await WriteTextResponseAsync(context, "text/csv", csv, $"{typeSlug}_{WebUtility.UrlEncode(id)}_flat.csv");
            return;
        }

        // Build flat CSV with parent fields repeated for each child row
        var flatRows = new List<string[]>();
        var parentId = instance is BaseDataObject dobj ? DataScaffold.GetIdValue(dobj) ?? string.Empty : string.Empty;
        var parentFields = DataScaffold.BuildViewRows(meta, instance).ToList();
        var parentHeaders = new List<string> { "Id" };
        parentHeaders.AddRange(parentFields.Select(f => f.Label));

        var allHeaders = new List<string>(parentHeaders);
        var nested = DataScaffold.ExtractNestedData(meta, instance);
        
        if (nested.Count > 0)
        {
            var childHeaders = nested[0].Headers.Select(h => $"{nested[0].FieldName}.{h}");
            allHeaders.AddRange(childHeaders);

            var parentRow = new[] { parentId }.Concat(parentFields.Select(f => f.Value)).ToArray();
            
            if (nested[0].Rows.Length > 0)
            {
                foreach (var childRow in nested[0].Rows)
                {
                    flatRows.Add(parentRow.Concat(childRow).ToArray());
                }
            }
            else
            {
                var emptyChild = new string[nested[0].Headers.Length];
                flatRows.Add(parentRow.Concat(emptyChild).ToArray());
            }
        }
        else
        {
            var parentRow = new[] { parentId }.Concat(parentFields.Select(f => f.Value)).ToArray();
            flatRows.Add(parentRow);
        }

        var flatCsv = BuildCsv(allHeaders.ToArray(), flatRows.ToArray());
        await WriteTextResponseAsync(context, "text/csv", flatCsv, $"{typeSlug}_{WebUtility.UrlEncode(id)}_flat.csv");
    }

    private async ValueTask ExportMultiSheetZip(HttpContext context, DataEntityMetadata meta, string typeSlug, IReadOnlyList<object?> items, ExportOptions options)
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
                        var matchingNested = nested.FirstOrDefault(n => string.Equals(n.FieldName, field.Name, StringComparison.OrdinalIgnoreCase));
                        
                        if (headers == null && matchingNested.Headers != null && matchingNested.Headers.Length > 0)
                        {
                            headers = matchingNested.Headers;
                            childHeaders.AddRange(headers);
                        }

                        if (matchingNested.Rows != null)
                        {
                            foreach (var row in matchingNested.Rows)
                            {
                                childRows.Add(new[] { parentId }.Concat(row).ToArray());
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

    private async ValueTask ExportSingleMultiSheetZip(HttpContext context, DataEntityMetadata meta, string typeSlug, string id, object instance, ExportOptions options)
    {
        using var memoryStream = new MemoryStream();
        using (var archive = new ZipArchive(memoryStream, ZipArchiveMode.Create, leaveOpen: true))
        {
            // Add parent CSV
            var parentRows = DataScaffold.BuildViewRows(meta, instance)
                .Select(row => new[] { row.Label, row.Value })
                .ToArray();
            if (instance is BaseDataObject dataObject)
            {
                var recordId = DataScaffold.GetIdValue(dataObject) ?? string.Empty;
                parentRows = new[] { new[] { "Id", recordId } }.Concat(parentRows).ToArray();
            }
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
        var sb = new StringBuilder();
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

    private static string BuildRtfDocument(string title, string[][] rows)
    {
        var sb = new StringBuilder();
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
        
        var html = new StringBuilder();
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

    private const string ApiCsrfHeaderName = "X-Requested-With";
    private const string ApiCsrfHeaderValue = "BareMetalWeb";

    private static bool ValidateApiCsrfHeader(HttpContext context)
        => UserAuth.HasApiKeyHeader(context) ||
           string.Equals(context.Request.Headers[ApiCsrfHeaderName], ApiCsrfHeaderValue, StringComparison.Ordinal);

    private static async ValueTask<bool> HasEntityPermissionAsync(HttpContext context, DataEntityMetadata meta, CancellationToken cancellationToken = default)
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

        var userPermissions = new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        var required = permissionsNeeded.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return required.Length == 0 || required.All(userPermissions.Contains);
    }

    private static List<string[]> ParseCsvRows(string content)
    {
        var rows = new List<string[]>();
        if (string.IsNullOrEmpty(content))
            return rows;

        var current = new List<string>();
        var field = new StringBuilder();
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
        if (current.Any(value => !string.IsNullOrWhiteSpace(value)))
            rows.Add(current.ToArray());

        return rows;
    }

    private static Dictionary<string, int> BuildCsvMapping(DataEntityMetadata meta, string[] header, out int idIndex, out int passwordIndex)
    {
        var mapping = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        idIndex = -1;
        passwordIndex = -1;

        var fieldMap = new Dictionary<string, DataFieldMetadata>(StringComparer.OrdinalIgnoreCase);
        foreach (var field in meta.Fields.Where(f => (f.Create || f.Edit) && !f.ReadOnly))
        {
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

        var field = meta.Fields.FirstOrDefault(f => string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase));
        if (field == null)
            return;

        if (DataScaffold.TryConvertValue(value, field.Property.PropertyType, out var converted) && converted != null)
        {
            field.Property.SetValue(instance, converted);
            return;
        }

        var effectiveType = Nullable.GetUnderlyingType(field.Property.PropertyType) ?? field.Property.PropertyType;
        if (effectiveType == typeof(string))
        {
            field.Property.SetValue(instance, value);
        }
    }

    private void RenderSampleDataForm(HttpContext context, string? message, int addresses, int customers, int units, int products, int employees, int orders, int todos, int timeTablePlans, int lessonLogs, bool clearExisting)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Generate Sample Data");
        context.SetStringValue("html_message", string.IsNullOrWhiteSpace(message) ? string.Empty : message);

        var fields = new List<FormField>
        {
            new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken),
            new FormField(FormFieldType.Integer, "addresses", "Addresses", Required: true, Value: addresses.ToString(CultureInfo.InvariantCulture)),
            new FormField(FormFieldType.Integer, "customers", "Customers", Required: true, Value: customers.ToString(CultureInfo.InvariantCulture)),
            new FormField(FormFieldType.Integer, "units", "Units Of Measure", Required: true, Value: units.ToString(CultureInfo.InvariantCulture)),
            new FormField(FormFieldType.Integer, "products", "Products", Required: true, Value: products.ToString(CultureInfo.InvariantCulture)),
            new FormField(FormFieldType.Integer, "employees", "Employees", Required: true, Value: employees.ToString(CultureInfo.InvariantCulture)),
            new FormField(FormFieldType.Integer, "orders", "Orders", Required: true, Value: orders.ToString(CultureInfo.InvariantCulture)),
            new FormField(FormFieldType.Integer, "todos", "To-Do Items", Required: true, Value: todos.ToString(CultureInfo.InvariantCulture)),
            new FormField(FormFieldType.Integer, "timeTablePlans", "Time Table Plans", Required: true, Value: timeTablePlans.ToString(CultureInfo.InvariantCulture)),
            new FormField(FormFieldType.Integer, "lessonLogs", "Lesson Logs", Required: true, Value: lessonLogs.ToString(CultureInfo.InvariantCulture)),
            new FormField(FormFieldType.YesNo, "clearExisting", "Clear existing data", false, SelectedValue: clearExisting ? "true" : "false")
        };

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

    private static async ValueTask DeleteAllAsync<T>(CancellationToken ct = default) where T : BaseDataObject
    {
        var items = (await DataStoreProvider.Current.QueryAsync<T>(null, ct).ConfigureAwait(false)).ToList();
        foreach (var item in items)
        {
            if (item == null || item.Key == 0)
                continue;
            ct.ThrowIfCancellationRequested();
            await DataStoreProvider.Current.DeleteAsync<T>(item.Key, ct);
        }
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

    private static List<Address> GenerateAddresses(int count, HashSet<string> usedIds)
    {
        var list = new List<Address>(count);
        if (count <= 0)
            return list;

        var streets = new[] { "Maple", "Oak", "Cedar", "Pine", "Lake", "Hill", "River", "Sunset" };
        var cities = new[] { "Springfield", "Riverton", "Lakeside", "Fairview", "Oakridge" };
        var regions = new[] { "CA", "TX", "NY", "WA", "IL" };
        var rnd = Random.Shared;

        for (var i = 1; i <= count; i++)
        {
            var street = streets[rnd.Next(streets.Length)];
            var city = cities[rnd.Next(cities.Length)];
            var region = regions[rnd.Next(regions.Length)];
            var address = new Address
            {
                Label = $"Address {i}",
                Line1 = $"{rnd.Next(10, 9999)} {street} St",
                Line2 = string.Empty,
                City = city,
                Region = region,
                PostalCode = rnd.Next(10000, 99999).ToString(CultureInfo.InvariantCulture),
                Country = "US"
            };
            EnsureUniqueId(address, usedIds);
            list.Add(address);
        }

        return list;
    }

    private static List<UnitOfMeasure> GenerateUnits(int count, HashSet<string> usedIds)
    {
        var list = new List<UnitOfMeasure>(count);
        if (count <= 0)
            return list;

        var defaults = new (string Name, string Abbr)[]
        {
            ("Each", "EA"),
            ("Box", "BOX"),
            ("Kilogram", "KG"),
            ("Liter", "L"),
            ("Pack", "PK"),
            ("Hour", "HR")
        };

        var index = 1;
        foreach (var unit in defaults)
        {
            if (list.Count >= count)
                break;
            list.Add(new UnitOfMeasure
            {
                Name = unit.Name,
                Abbreviation = unit.Abbr,
                Description = string.Empty,
                IsActive = true
            });
            EnsureUniqueId(list[^1], usedIds);
        }

        while (list.Count < count)
        {
            list.Add(new UnitOfMeasure
            {
                Name = $"Unit {index}",
                Abbreviation = $"U{index}",
                Description = string.Empty,
                IsActive = true
            });
            EnsureUniqueId(list[^1], usedIds);
            index++;
        }

        return list;
    }

    private static List<Customer> GenerateCustomers(int count, List<Address> addresses, HashSet<string> usedIds)
    {
        var list = new List<Customer>(count);
        if (count <= 0)
            return list;

        var firstNames = new[] { "Alex", "Taylor", "Jordan", "Morgan", "Casey", "Riley" };
        var lastNames = new[] { "Smith", "Lee", "Patel", "Garcia", "Nguyen", "Brown" };
        var companies = new[] { "Acme Co", "Northwind", "Contoso", "Globex", "Initech" };
        var rnd = Random.Shared;

        for (var i = 0; i < count; i++)
        {
            var first = firstNames[rnd.Next(firstNames.Length)];
            var last = lastNames[rnd.Next(lastNames.Length)];
            var company = companies[rnd.Next(companies.Length)];
            var name = $"{first} {last}";
            var email = $"{first}.{last}.{i + 1}@example.com".ToLowerInvariant();
            var address = addresses.Count > 0 ? addresses[rnd.Next(addresses.Count)] : null;

            list.Add(new Customer
            {
                Name = name,
                Email = email,
                Phone = $"555-{rnd.Next(100, 999)}-{rnd.Next(1000, 9999)}",
                Company = company,
                AddressId = address?.Key.ToString() ?? string.Empty,
                IsActive = true,
                Notes = string.Empty,
                Tags = new List<string>()
            });
            EnsureUniqueId(list[^1], usedIds);
        }

        return list;
    }

    private static List<Product> GenerateProducts(int count, List<UnitOfMeasure> units, HashSet<string> usedIds)
    {
        var list = new List<Product>(count);
        if (count <= 0)
            return list;

        var names = new[] { "Widget", "Gadget", "Doohickey", "Contraption", "Gizmo" };
        var categories = new[] { "Hardware", "Supplies", "Accessories", "Tools" };
        var rnd = Random.Shared;

        for (var i = 0; i < count; i++)
        {
            var name = $"{names[rnd.Next(names.Length)]} {i + 1}";
            var unit = units.Count > 0 ? units[rnd.Next(units.Count)] : null;
            var price = Math.Round((decimal)(rnd.NextDouble() * 250 + 5), 2);
            var product = new Product
            {
                Name = name,
                Sku = $"SKU-{i + 1:0000}",
                Category = categories[rnd.Next(categories.Length)],
                UnitOfMeasureId = unit?.Key.ToString() ?? string.Empty,
                Price = price,
                InventoryCount = rnd.Next(0, 5000),
                ReorderLevel = rnd.Next(0, 200),
                LaunchDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-rnd.Next(0, 365))),
                IsActive = true,
                Description = string.Empty,
                Tags = new List<string>()
            };
            EnsureUniqueId(product, usedIds);
            list.Add(product);
        }

        return list;
    }

    private static List<Employee> GenerateEmployees(int count, HashSet<string> usedIds)
    {
        var list = new List<Employee>(count);
        if (count <= 0)
            return list;

        var firstNames = new[] { "Alice", "Bob", "Carol", "David", "Eve", "Frank", "Grace", "Henry", "Iris", "Jack" };
        var lastNames = new[] { "Anderson", "Baker", "Clarke", "Davis", "Evans", "Foster", "Green", "Harris", "Ingram", "Jones" };
        var titles = new[] { "Manager", "Senior Developer", "Developer", "Analyst", "Designer", "QA Engineer", "DevOps Engineer", "Product Owner", "Scrum Master", "Architect" };
        var departments = new[] { "Engineering", "Sales", "Marketing", "HR", "Finance", "Operations", "Support", "Legal" };
        var rnd = Random.Shared;

        for (var i = 0; i < count; i++)
        {
            var first = firstNames[rnd.Next(firstNames.Length)];
            var last = lastNames[rnd.Next(lastNames.Length)];
            var title = titles[rnd.Next(titles.Length)];
            var dept = departments[rnd.Next(departments.Length)];
            var hireDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-rnd.Next(30, 3650)));

            var employee = new Employee
            {
                Name = $"{first} {last}",
                Title = title,
                Email = $"{first.ToLowerInvariant()}.{last.ToLowerInvariant()}.{i + 1}@example.com",
                Department = dept,
                HireDate = hireDate,
                ManagerId = list.Count > 0 ? list[rnd.Next(Math.Min(list.Count, 3))].Key.ToString() : null
            };
            EnsureUniqueId(employee, usedIds);
            list.Add(employee);
        }

        return list;
    }

    private static List<Currency> GenerateSeedCurrencies(HashSet<string> usedIds)
    {
        var defaults = new (string IsoCode, string Description, string Symbol)[]
        {
            ("USD", "US Dollar", "$"),
            ("EUR", "Euro", "€"),
            ("GBP", "British Pound", "£"),
            ("JPY", "Japanese Yen", "¥"),
            ("CAD", "Canadian Dollar", "CA$")
        };

        var list = new List<Currency>(defaults.Length);
        foreach (var (isoCode, description, symbol) in defaults)
        {
            var currency = new Currency
            {
                IsoCode = isoCode,
                Description = description,
                Symbol = symbol,
                DecimalPlaces = isoCode == "JPY" ? 0 : 2,
                IsEnabled = true,
                IsBase = isoCode == "USD"
            };
            EnsureUniqueId(currency, usedIds);
            list.Add(currency);
        }

        return list;
    }

    private static List<Order> GenerateOrders(int count, List<Customer> customers, List<Product> products, List<Currency> currencies, HashSet<string> usedIds)
    {
        var list = new List<Order>(count);
        if (count <= 0 || customers.Count == 0)
            return list;

        var statuses = new[] { "Open", "Approved", "Shipped", "Closed", "Cancelled" };
        var rnd = Random.Shared;

        for (var i = 0; i < count; i++)
        {
            var customer = customers[rnd.Next(customers.Count)];
            var currency = currencies.Count > 0 ? currencies[rnd.Next(currencies.Count)] : null;
            var status = statuses[rnd.Next(statuses.Length)];
            var orderDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-rnd.Next(0, 365)));

            var order = new Order
            {
                OrderNumber = $"ORD-{i + 1:00000}",
                CustomerId = customer.Key.ToString(),
                OrderDate = orderDate,
                Status = status,
                CurrencyId = currency?.Key.ToString() ?? string.Empty,
                Notes = string.Empty,
                IsOpen = status == "Open",
                OrderRows = new List<OrderRow>()
            };

            var rowCount = rnd.Next(1, 5);
            for (var r = 0; r < rowCount && products.Count > 0; r++)
            {
                var product = products[rnd.Next(products.Count)];
                var qty = rnd.Next(1, 20);
                var price = product.Price;
                var discountPct = rnd.Next(0, 3) == 0 ? rnd.Next(5, 20) : 0;
                var subtotal = qty * price;
                order.OrderRows.Add(new OrderRow
                {
                    ProductId = product.Key.ToString(),
                    Quantity = qty,
                    UnitPrice = price,
                    DiscountPercent = discountPct,
                    Subtotal = subtotal,
                    LineTotal = Math.Round(subtotal * (1 - discountPct / 100m), 2),
                    Notes = string.Empty
                });
            }

            EnsureUniqueId(order, usedIds);
            list.Add(order);
        }

        return list;
    }

    private static List<ToDo> GenerateToDos(int count, HashSet<string> usedIds)
    {
        var list = new List<ToDo>(count);
        if (count <= 0)
            return list;

        var titles = new[] { "Review pull request", "Write unit tests", "Update documentation", "Fix bug", "Deploy to staging", "Team standup", "Code review", "Plan sprint", "Refactor module", "Performance audit" };
        var periodicities = new[] { TodoPeriodicity.OneOff, TodoPeriodicity.Daily, TodoPeriodicity.Weekly, TodoPeriodicity.Monthly };
        var rnd = Random.Shared;

        for (var i = 0; i < count; i++)
        {
            var title = $"{titles[rnd.Next(titles.Length)]} {i + 1}";
            var deadline = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(rnd.Next(-30, 90)));
            var startHour = rnd.Next(8, 18);
            var startMinute = rnd.Next(0, 4) * 15;

            list.Add(new ToDo
            {
                Title = title,
                Deadline = deadline,
                StartTime = new TimeOnly(startHour, startMinute),
                Periodicity = periodicities[rnd.Next(periodicities.Length)],
                Notes = string.Empty,
                Link = string.Empty,
                IsCompleted = rnd.Next(0, 5) == 0,
                SubItems = new List<string>()
            });
            EnsureUniqueId(list[^1], usedIds);
        }

        return list;
    }

    private static List<Subject> GenerateSeedSubjects(HashSet<string> usedIds)
    {
        var defaultSubjects = new[] { "Mathematics", "English", "Science", "History", "Geography", "Art", "Music", "Physical Education", "Computing", "Languages" };
        var list = new List<Subject>(defaultSubjects.Length);

        foreach (var name in defaultSubjects)
        {
            var subject = new Subject { Name = name };
            EnsureUniqueId(subject, usedIds);
            list.Add(subject);
        }

        return list;
    }

    private static List<TimeTablePlan> GenerateTimeTablePlans(int count, List<Subject> subjects, HashSet<string> usedIds)
    {
        var list = new List<TimeTablePlan>(count);
        if (count <= 0 || subjects.Count == 0)
            return list;

        var days = new BareMetalWeb.Data.DataObjects.DayOfWeek[]
        {
            BareMetalWeb.Data.DataObjects.DayOfWeek.Monday,
            BareMetalWeb.Data.DataObjects.DayOfWeek.Tuesday,
            BareMetalWeb.Data.DataObjects.DayOfWeek.Wednesday,
            BareMetalWeb.Data.DataObjects.DayOfWeek.Thursday,
            BareMetalWeb.Data.DataObjects.DayOfWeek.Friday
        };
        var durations = new[] { 30, 45, 60, 90 };
        var rnd = Random.Shared;

        for (var i = 0; i < count; i++)
        {
            var subject = subjects[rnd.Next(subjects.Count)];
            var day = days[rnd.Next(days.Length)];
            var startHour = rnd.Next(8, 16);
            var startMinute = rnd.Next(0, 2) * 30;

            list.Add(new TimeTablePlan
            {
                SubjectId = subject.Key.ToString(),
                Notes = string.Empty,
                Day = day,
                StartTime = new TimeOnly(startHour, startMinute),
                Minutes = durations[rnd.Next(durations.Length)]
            });
            EnsureUniqueId(list[^1], usedIds);
        }

        return list;
    }

    private static List<LessonLog> GenerateLessonLogs(int count, List<Subject> subjects, HashSet<string> usedIds)
    {
        var list = new List<LessonLog>(count);
        if (count <= 0 || subjects.Count == 0)
            return list;

        var durations = new[] { 30, 45, 60, 90 };
        var rnd = Random.Shared;

        for (var i = 0; i < count; i++)
        {
            var subject = subjects[rnd.Next(subjects.Count)];
            var date = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-rnd.Next(0, 180)));
            var startHour = rnd.Next(8, 16);
            var startMinute = rnd.Next(0, 2) * 30;

            list.Add(new LessonLog
            {
                SubjectId = subject.Key.ToString(),
                Date = date,
                StartTime = new TimeOnly(startHour, startMinute),
                Minutes = durations[rnd.Next(durations.Length)],
                Notes = string.Empty,
                Link = string.Empty
            });
            EnsureUniqueId(list[^1], usedIds);
        }

        return list;
    }

    private static void EnsureUniqueId(BaseDataObject dataObject, HashSet<string> usedIds)    {
        var id = dataObject.Key.ToString();
        if (string.IsNullOrWhiteSpace(id) || id == "0" || usedIds.Contains(id))
        {
            do
            {
                id = ((uint)Random.Shared.Next(1, int.MaxValue)).ToString();
            }
            while (usedIds.Contains(id));

            dataObject.Key = uint.Parse(id);
        }

        usedIds.Add(id);
    }

    private static async ValueTask<Dictionary<string, JsonElement>?> ReadJsonBodyAsync(HttpContext context)
    {
        if (context.Request.ContentLength.HasValue && context.Request.ContentLength.Value == 0)
            return null;

        try
        {
            using var doc = await JsonDocument.ParseAsync(context.Request.Body).ConfigureAwait(false);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return null;

            var payload = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
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

    private static async ValueTask WriteJsonResponseAsync(HttpContext context, object payload)
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

        // Fallback: serialize complex objects via reflection as JSON objects
        var valueType = value.GetType();
        if (valueType.IsClass)
        {
            writer.WriteStartObject();
            #pragma warning disable IL2075 // Child entity types are preserved via TrimmerRootAssembly
            foreach (var prop in valueType.GetProperties(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance))
            #pragma warning restore IL2075
            {
                if (!prop.CanRead || prop.GetIndexParameters().Length != 0) continue;
                writer.WritePropertyName(prop.Name);
                WriteJsonValue(writer, prop.GetValue(value));
            }
            writer.WriteEndObject();
            return;
        }

        writer.WriteStringValue(value.ToString());
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
        var fieldByLabel = meta.Fields.ToDictionary(f => f.Label, f => f, StringComparer.OrdinalIgnoreCase);
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

    private void RenderMfaResetForm(HttpContext context, string? message)
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

    private static async ValueTask<MfaChallenge?> GetMfaChallengeAsync(HttpContext context, CancellationToken cancellationToken = default)
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
        return users.Any();
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
        return users.FirstOrDefault(u => u.IsLockedOut);
    }

    private static string BuildViewSwitcher(string typeSlug, ViewType currentView, DataEntityMetadata meta)
    {
        var html = new StringBuilder();
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

    private static string BuildTimelineViewHtml(
        DataEntityMetadata meta,
        IEnumerable<BaseDataObject> allItems,
        string basePath,
        Func<DataEntityMetadata, bool>? canRenderLookupLink = null,
        string? cloneToken = null,
        string? cloneReturnUrl = null)
    {
        var html = new StringBuilder();

        // Find the first two DateOnly/DateTime fields: first is start date, second (if any) is end date
        var dateFields = meta.Fields
            .Where(f => f.FieldType == FormFieldType.DateOnly || f.FieldType == FormFieldType.DateTime)
            .Take(2)
            .ToList();

        if (dateFields.Count == 0)
            return "<p class=\"text-warning\">Timeline view requires a DateOnly or DateTime field.</p>";

        var itemsList = allItems.ToList();
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
        var minDate = ganttItems.Min(x => x.Start);
        var maxDate = ganttItems.Max(x => x.End);
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

    private static string GetDisplayValue(DataEntityMetadata meta, BaseDataObject item)
    {
        // Try common name fields first (same heuristic as DataScaffold.GetDisplayValue)
        var nameField = meta.Fields.FirstOrDefault(f =>
            string.Equals(f.Name, "Name", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(f.Name, "Title", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(f.Name, "DisplayName", StringComparison.OrdinalIgnoreCase));
        if (nameField != null)
        {
            var value = nameField.Property.GetValue(item)?.ToString();
            if (!string.IsNullOrWhiteSpace(value))
                return value;
        }

        // Fall back to first List string field
        var displayField = meta.Fields.FirstOrDefault(f => f.List && f.FieldType == FormFieldType.String);
        if (displayField != null)
        {
            var value = displayField.Property.GetValue(item)?.ToString();
            if (!string.IsNullOrWhiteSpace(value))
                return value;
        }

        // Last resort: ID
        return DataScaffold.GetIdValue(item) ?? "Unknown";
    }

    private static string FormatFieldValue(DataFieldMetadata field, object? value, Func<DataEntityMetadata, bool>? canRenderLookupLink)
    {
        if (value == null)
            return "<em class=\"text-muted\">null</em>";
        
        if (field.Lookup != null)
        {
            // For lookup fields, show the value as-is (it would be the ID)
            return WebUtility.HtmlEncode(value.ToString() ?? string.Empty);
        }
        
        return field.FieldType switch
        {
            FormFieldType.DateOnly => value is DateOnly dateOnly 
                ? WebUtility.HtmlEncode(dateOnly.ToString("yyyy-MM-dd")) 
                : WebUtility.HtmlEncode(value.ToString() ?? string.Empty),
            FormFieldType.DateTime => value is DateTime dateTime 
                ? WebUtility.HtmlEncode(dateTime.ToString("yyyy-MM-dd HH:mm:ss")) 
                : WebUtility.HtmlEncode(value.ToString() ?? string.Empty),
            FormFieldType.YesNo => value is bool boolVal 
                ? (boolVal ? "<i class=\"bi bi-check-circle text-success\"></i>" : "<i class=\"bi bi-x-circle text-danger\"></i>") 
                : WebUtility.HtmlEncode(value.ToString() ?? string.Empty),
            _ => WebUtility.HtmlEncode(value.ToString() ?? string.Empty)
        };
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

    private static string BuildSearchBox(string? currentSearchText, string actionUrl)
    {
        var safeSearchText = WebUtility.HtmlEncode(currentSearchText ?? string.Empty);
        return $@"<div class=""mb-3"">
    <form method=""get"" action=""{WebUtility.HtmlEncode(actionUrl)}"" class=""row g-2"">
        <div class=""col-auto flex-grow-1"">
            <input type=""search"" class=""form-control"" name=""q"" placeholder=""Search..."" value=""{safeSearchText}"" aria-label=""Search"" />
        </div>
        <div class=""col-auto"">
            <button type=""submit"" class=""btn btn-primary""><i class=""bi bi-search"" aria-hidden=""true""></i> Search</button>
        </div>
    </form>
</div>";
    }

    private static string BuildPageSizeSelector(int currentPageSize, string basePath, IDictionary<string, string?> queryParams)
    {
        var sizes = new[] { 10, 25, 50, 100 };
        var html = new StringBuilder();
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

    private static string BuildEnhancedPagination(int currentPage, int totalRecords, int pageSize, string basePath, IDictionary<string, string?> queryParams)
    {
        var maxPage = totalRecords == 0 ? 1 : (int)Math.Ceiling(totalRecords / (double)pageSize);
        var startRecord = totalRecords == 0 ? 0 : (currentPage - 1) * pageSize + 1;
        var endRecord = Math.Min(currentPage * pageSize, totalRecords);

        var html = new StringBuilder();
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

    private static string BuildUrlWithParam(string basePath, IDictionary<string, string?> queryParams, string key, string value, string[]? excludeParams = null)
    {
        var parts = new List<string>();
        var exclude = new HashSet<string>(excludeParams ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
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
        
        var html = new StringBuilder();
        html.Append("<thead><tr>");

        if (includeBulkSelection)
        {
            html.Append(@"<th scope=""col"" class=""bm-col-check""><input type=""checkbox"" data-bulk-select-all aria-label=""Select all"" /></th>");
        }

        if (includeActions)
        {
            html.Append(@"<th scope=""col"">Actions</th>");
        }

        foreach (var field in metadata.Fields.Where(f => f.List).OrderBy(f => f.Order))
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

    private static string BuildTableWithSortableHeaders(DataEntityMetadata metadata, IReadOnlyList<string[]> rows, string basePath, IDictionary<string, string?> queryParams, bool includeActions, bool includeBulkSelection = false)
    {
        var html = new StringBuilder();
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
        columnTitles.AddRange(metadata.Fields.Where(f => f.List).OrderBy(f => f.Order).Select(f => f.Label));
        
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

    private static string BuildBulkActionsBar(string typeSlug, string returnUrl, long totalCount, string csrfToken)
    {
        var sb = new StringBuilder();
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
        var fields = DataScaffold.BuildFormFields(meta, instance, forCreate, cspNonce: cspNonce).ToList();
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
        var sb = new StringBuilder();
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

    public async ValueTask DataCommandHandler(HttpContext context)
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

        var cmd = meta.Commands.FirstOrDefault(c => string.Equals(c.Name, commandName, StringComparison.OrdinalIgnoreCase));
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
            if (user == null || !user.Permissions.Contains(cmd.Permission, StringComparer.OrdinalIgnoreCase))
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

    public async ValueTask DataSizingHandler(HttpContext context)
    {
        await BuildPageHandler(ctx =>
        {
            ctx.SetStringValue("title", "Data & Index Sizing");

            var dataRoot = _dataRootFolder;
            var walDir   = Path.Combine(dataRoot, "wal");
            var html     = new StringBuilder();

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

                // Index / paged files in subfolders
                long indexBytes  = 0;
                foreach (var sub in new[] { "Paged", "Index" })
                {
                    var subDir = Path.Combine(entityFolder, sub);
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

            foreach (var (name, slug, schemaBytes, idMapBytes, indexBytes) in rows.OrderBy(r => r.Name, StringComparer.OrdinalIgnoreCase))
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
    public async ValueTask JobStatusHandler(HttpContext context)
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
}
