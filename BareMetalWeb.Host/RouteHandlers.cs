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
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Core.Delegates;
using BareMetalWeb.Rendering.Models;
using BareMetalWeb.Core;

namespace BareMetalWeb.Host;

public sealed class RouteHandlers : IRouteHandlers
{
    private readonly IHtmlRenderer _renderer;
    private readonly ITemplateStore _templateStore;
    private readonly bool _allowAccountCreation;
    private readonly MfaSecretProtector _mfaProtector;
    private const string MfaChallengeCookieName = "mfa_challenge_id";
    private static readonly TimeSpan MfaPendingLifetime = TimeSpan.FromMinutes(5);
    private const int MfaPendingMaxFailures = 5;
    private const int MfaChallengeMaxFailures = 6;
    private static readonly TimeSpan MfaAttemptWindow = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan MfaBaseBlockDuration = TimeSpan.FromSeconds(10);
    private static readonly ConcurrentDictionary<string, AttemptTracker> MfaAttempts = new(StringComparer.Ordinal);

    public RouteHandlers(IHtmlRenderer renderer, ITemplateStore templateStore, bool allowAccountCreation, string mfaKeyRootFolder)
    {
        _renderer = renderer;
        _templateStore = templateStore;
        _allowAccountCreation = allowAccountCreation;
        _mfaProtector = MfaSecretProtector.CreateDefault(mfaKeyRootFolder);
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
            RenderLoginForm(context, "Invalid login request.", null);
            await _renderer.RenderPage(context);
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

        var user = Users.FindByEmailOrUserName(identifier);
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
                UserId = user.Id,
                RememberMe = rememberMe,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(5),
                CreatedBy = user.UserName,
                UpdatedBy = user.UserName
            };
            await DataStoreProvider.Current.SaveAsync(challenge);
            context.SetCookie(MfaChallengeCookieName, challenge.Id, new CookieOptions
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
        await BuildPageHandler(ctx =>
        {
            var challenge = GetMfaChallenge(ctx);
            if (challenge == null)
            {
                ctx.Response.Redirect("/login");
                return ValueTask.FromResult(false);
            }

            RenderMfaChallengeForm(ctx, null);
            return ValueTask.FromResult(true);
        })(context);
    }

    public async ValueTask MfaChallengePostHandler(HttpContext context)
    {
        var challenge = GetMfaChallenge(context);
        if (challenge == null)
        {
            context.Response.Redirect("/login");
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            RenderMfaChallengeForm(context, "Invalid MFA request.");
            await _renderer.RenderPage(context);
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
            RenderMfaChallengeForm(context, "Please enter your authentication code.");
            await _renderer.RenderPage(context);
            return;
        }

        var user = Users.GetById(challenge.UserId);
        if (user == null || !user.IsActive || !user.MfaEnabled || !TryGetActiveSecret(user, out var activeSecret, out var upgraded))
        {
            RenderMfaChallengeForm(context, "MFA is not available for this account.");
            await _renderer.RenderPage(context);
            return;
        }

        if (upgraded)
            await Users.SaveAsync(user);

        var remoteIp = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (IsThrottled(BuildMfaAttemptKey("challenge:user", user.Id), MfaChallengeMaxFailures, out var retryAfter)
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
                RegisterFailure(BuildMfaAttemptKey("challenge:user", user.Id), MfaChallengeMaxFailures);
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

            RegisterSuccess(BuildMfaAttemptKey("challenge:user", user.Id));
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
                ctx.SetStringValue("message", "<p>Account creation is disabled in this environment.</p>");
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
            context.SetStringValue("message", "<p>Account creation is disabled in this environment.</p>");
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

        if (Users.FindByEmail(email) != null)
        {
            RenderRegisterForm(context, "Email is already registered.", userName, displayName, email);
            await _renderer.RenderPage(context);
            return;
        }

        if (Users.FindByUserName(userName) != null)
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
            ctx.SetStringValue("message", message);
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
            ctx.SetStringValue("message", message);
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
                ctx.SetStringValue("message", "<p>MFA is already enabled for your account.</p>");
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
        if (IsThrottled(BuildMfaAttemptKey("setup:user", user.Id), MfaPendingMaxFailures, out var setupRetry)
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

                RegisterFailure(BuildMfaAttemptKey("setup:user", user.Id), MfaPendingMaxFailures);
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
            user.MfaSecretEncrypted = _mfaProtector.EncryptSecret(currentPendingSecret, user.Id);
            user.MfaSecret = null;
            user.MfaPendingSecret = null;
            user.MfaPendingSecretEncrypted = null;
            user.MfaPendingExpiresUtc = null;
            user.MfaPendingFailedAttempts = 0;

            var backupCodes = GenerateBackupCodes(user, count: 8);
            user.MfaBackupCodeHashes = backupCodes.Hashes;
            user.MfaBackupCodesGeneratedUtc = DateTime.UtcNow;
            await Users.SaveAsync(user);

            RegisterSuccess(BuildMfaAttemptKey("setup:user", user.Id));
            RegisterSuccess(BuildMfaAttemptKey("setup:ip", setupIp));
            RegisterSuccess(BuildMfaAttemptKey("setup:secret", currentPendingSecret));

            context.SetStringValue("title", "Enable MFA");
            var backupList = string.Join(string.Empty, backupCodes.Codes.Select(codeValue => $"<li><code>{WebUtility.HtmlEncode(codeValue)}</code></li>"));
            var backupHtml = string.IsNullOrWhiteSpace(backupList)
                ? string.Empty
                : $"<div class=\"mt-3\"><p><strong>Backup codes (save these now):</strong></p><ul>{backupList}</ul><p class=\"text-warning\">These codes are shown once.</p></div>";
            context.SetStringValue("message", "<p>MFA enabled successfully.</p>" + backupHtml + "<p><a href=\"/account\">Back to account</a></p>");
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
                ctx.SetStringValue("message", "<p>MFA is not enabled for your account.</p><p><a href=\"/account\">Back to account</a></p>");
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
        context.SetStringValue("message", "<p>MFA has been reset.</p><p><a href=\"/account\">Back to account</a></p>");
        await _renderer.RenderPage(context);
    }

    public async ValueTask UsersListHandler(HttpContext context)
    {
        await BuildPageHandler(ctx =>
        {
            ctx.SetStringValue("title", "Users");

            var rows = new List<string[]>();
            foreach (var user in DataStoreProvider.Current.Query<User>(new QueryDefinition()))
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
        await BuildPageHandler(ctx =>
        {
            if (RootUserExists())
            {
                ctx.SetStringValue("title", "Setup");
                ctx.SetStringValue("message", "<p>Root user already exists.</p>");
                return;
            }

            RenderSetupForm(ctx, null, null, null);
        })(context);
    }

    public async ValueTask SetupPostHandler(HttpContext context)
    {
        if (RootUserExists())
        {
            context.SetStringValue("title", "Setup");
            context.SetStringValue("message", "<p>Root user already exists.</p>");
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
        await EnsureDefaultCurrencies(userName);
        await EnsureDefaultUnitsOfMeasure(userName);
        await EnsureDefaultAddress(userName);
        context.SetStringValue("title", "Setup");
        context.SetStringValue("message", "<p>Root user created successfully.</p>");
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
        var existing = DataStoreProvider.Current.Query<Currency>(null).ToList();
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
        var existing = DataStoreProvider.Current.Query<UnitOfMeasure>(null).ToList();
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
        var hasAddress = DataStoreProvider.Current.Query<Address>(null).Any();
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

    public async ValueTask ReloadTemplatesHandler(HttpContext context)
    {
        _templateStore.ReloadAll();
        context.SetStringValue("title", "Reload Templates");
        context.SetStringValue("message", "Templates reloaded successfully.");
        await _renderer.RenderPage(context);
    }

    private void RenderLoginForm(HttpContext context, string? message, string? emailValue)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Login");
        context.SetStringValue("message", string.IsNullOrWhiteSpace(message)
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
        context.SetStringValue("message", string.IsNullOrWhiteSpace(message)
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
        context.SetStringValue("message", string.IsNullOrWhiteSpace(message)
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

    private void RenderLogoutForm(HttpContext context, string? message)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Logout");
        context.SetStringValue("message", string.IsNullOrWhiteSpace(message)
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
        context.SetStringValue("message", info + BuildOtpClientScript(context, "/mfa"));

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

        context.SetStringValue("message", intro + payload + BuildOtpClientScript(context, "/account/mfa/setup"));
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
            user.MfaPendingSecretEncrypted = _mfaProtector.EncryptSecret(secret, user.Id);
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
            if (_mfaProtector.TryDecryptSecret(user.MfaPendingSecretEncrypted, user.Id, out var bytes))
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
            user.MfaPendingSecretEncrypted = _mfaProtector.EncryptSecret(legacy, user.Id);
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
            if (_mfaProtector.TryDecryptSecret(user.MfaSecretEncrypted, user.Id, out var bytes))
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
            user.MfaSecretEncrypted = _mfaProtector.EncryptSecret(legacy, user.Id);
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
        var action = WebUtility.HtmlEncode(formAction);
        var nonce = context.GetCspNonce();
        return $"<script src=\"/static/js/otp.js\" nonce=\"{nonce}\"></script><script nonce=\"{nonce}\">setupOtpValidation('{action}');</script>";
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
        var payload = Encoding.UTF8.GetBytes($"{user.Id}:{code}");
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
            ctx.SetStringValue("message", "<p>Manage data entities.</p>");

            var rows = DataScaffold.Entities
                .OrderBy(e => e.NavOrder)
                .ThenBy(e => e.Name)
                .Select(entity => new[]
                {
                    $"<a class=\"btn btn-sm btn-outline-info me-1\" href=\"/admin/data/{entity.Slug}\" title=\"Open\" aria-label=\"Open\"><i class=\"bi bi-search\" aria-hidden=\"true\"></i></a><a class=\"btn btn-sm btn-outline-success\" href=\"/admin/data/{entity.Slug}/import\" title=\"Import CSV\" aria-label=\"Import CSV\"><i class=\"bi bi-upload\" aria-hidden=\"true\"></i></a>",
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
            context.SetStringValue("message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var queryDictionary = ToQueryDictionary(context.Request.Query);
        var countQuery = DataScaffold.BuildQueryDefinition(queryDictionary, meta);
        var totalCount = await DataScaffold.CountAsync(meta, countQuery);
        const int pageSize = 50;
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

        var cloneToken = CsrfProtection.EnsureToken(context);
        var returnUrl = $"{context.Request.Path}{context.Request.QueryString}";
        var headers = DataScaffold.BuildListHeaders(meta, includeActions: true);
        var rows = DataScaffold.BuildListRows(
            meta,
            results,
            $"/admin/data/{typeSlug}",
            includeActions: true,
            canRenderLookupLink: m => HasEntityPermission(context, m),
            cloneToken: cloneToken,
            cloneReturnUrl: returnUrl);

        var toastHtml = BuildToastHtml(context, meta.Name);
        var startRecord = totalCount == 0 ? 0 : (page - 1) * pageSize + 1;
        var endRecord = Math.Min(page * pageSize, totalCount);

        string BuildPageUrl(int targetPage)
        {
            if (targetPage < 1)
                targetPage = 1;

            var parts = new List<string>();
            foreach (var pair in context.Request.Query)
            {
                if (string.Equals(pair.Key, "page", StringComparison.OrdinalIgnoreCase))
                    continue;

                foreach (var value in pair.Value)
                {
                    parts.Add($"{WebUtility.UrlEncode(pair.Key)}={WebUtility.UrlEncode(value)}");
                }
            }

            if (targetPage > 1)
                parts.Add($"page={targetPage}");

            var queryString = parts.Count > 0 ? "?" + string.Join("&", parts) : string.Empty;
            return $"{context.Request.Path}{queryString}";
        }

        var prevUrl = BuildPageUrl(page - 1);
        var nextUrl = BuildPageUrl(page + 1);
        var prevDisabled = page <= 1;
        var nextDisabled = endRecord >= totalCount;
        var pagerHtml = $"<div class=\"d-flex flex-wrap align-items-center justify-content-between gap-2 mb-2\">"
            + $"<div class=\"small text-muted\">Records {startRecord} to {endRecord} of {totalCount} total</div>"
            + "<div class=\"btn-group btn-group-sm\" role=\"group\" aria-label=\"Pagination\">"
            + (prevDisabled
                ? "<span class=\"btn btn-outline-secondary disabled\" aria-disabled=\"true\" title=\"Previous\"><i class=\"bi bi-arrow-left\" aria-hidden=\"true\"></i></span>"
                : $"<a class=\"btn btn-outline-secondary\" href=\"{WebUtility.HtmlEncode(prevUrl)}\" title=\"Previous\" aria-label=\"Previous\"><i class=\"bi bi-arrow-left\" aria-hidden=\"true\"></i></a>")
            + (nextDisabled
                ? "<span class=\"btn btn-outline-secondary disabled\" aria-disabled=\"true\" title=\"Next\"><i class=\"bi bi-arrow-right\" aria-hidden=\"true\"></i></span>"
                : $"<a class=\"btn btn-outline-secondary\" href=\"{WebUtility.HtmlEncode(nextUrl)}\" title=\"Next\" aria-label=\"Next\"><i class=\"bi bi-arrow-right\" aria-hidden=\"true\"></i></a>")
            + "</div></div>";
        var queryString = context.Request.QueryString.HasValue ? context.Request.QueryString.Value : string.Empty;
        var csvHtml = $"<a class=\"btn btn-sm btn-outline-success ms-2\" href=\"/admin/data/{typeSlug}/csv{WebUtility.HtmlEncode(queryString)}\" title=\"Download CSV\" aria-label=\"Download CSV\"><i class=\"bi bi-download\" aria-hidden=\"true\"></i><i class=\"bi bi-file-earmark-spreadsheet ms-1\" aria-hidden=\"true\"></i> CSV</a>";
        var htmlHtml = $"<a class=\"btn btn-sm btn-outline-primary ms-2\" href=\"/admin/data/{typeSlug}/html{WebUtility.HtmlEncode(queryString)}\" title=\"Download HTML\" aria-label=\"Download HTML\"><i class=\"bi bi-download\" aria-hidden=\"true\"></i><i class=\"bi bi-filetype-html ms-1\" aria-hidden=\"true\"></i> HTML</a>";
        var createHtml = $"<p><a class=\"btn btn-sm btn-success\" href=\"/admin/data/{typeSlug}/create\" title=\"Create {WebUtility.HtmlEncode(meta.Name)}\" aria-label=\"Create {WebUtility.HtmlEncode(meta.Name)}\"><i class=\"bi bi-plus-lg\" aria-hidden=\"true\"></i></a>{csvHtml}{htmlHtml}</p>";
        context.SetStringValue("title", $"{WebUtility.HtmlEncode(meta.Name)} List");
        context.SetStringValue("message", toastHtml + pagerHtml + createHtml);
        context.AddTable(headers.ToArray(), rows.ToArray());
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
            context.SetStringValue("message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, id);
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Not Found");
            context.SetStringValue("message", "<p>Item not found.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var rows = DataScaffold.BuildViewRowsHtml(meta, instance, m => HasEntityPermission(context, m))
            .Select(row => new[]
            {
                WebUtility.HtmlEncode(row.Label),
                row.IsHtml ? row.Value : WebUtility.HtmlEncode(row.Value)
            })
            .ToArray();

        var rtfHtml = $"<a class=\"btn btn-sm btn-outline-info ms-2\" href=\"/admin/data/{typeSlug}/{WebUtility.UrlEncode(id)}/rtf\" title=\"Download RTF\" aria-label=\"Download RTF\"><i class=\"bi bi-download\" aria-hidden=\"true\"></i><i class=\"bi bi-file-earmark-text ms-1\" aria-hidden=\"true\"></i> RTF</a>";
        var htmlHtml = $"<a class=\"btn btn-sm btn-outline-primary ms-2\" href=\"/admin/data/{typeSlug}/{WebUtility.UrlEncode(id)}/html\" title=\"Download HTML\" aria-label=\"Download HTML\"><i class=\"bi bi-download\" aria-hidden=\"true\"></i><i class=\"bi bi-filetype-html ms-1\" aria-hidden=\"true\"></i> HTML</a>";
        context.SetStringValue("title", $"{WebUtility.HtmlEncode(meta.Name)} Details");
        context.SetStringValue("message", $"<p><a class=\"btn btn-sm btn-outline-warning\" href=\"/admin/data/{typeSlug}/{WebUtility.UrlEncode(id)}/edit\" title=\"Edit\" aria-label=\"Edit\"><i class=\"bi bi-pencil\" aria-hidden=\"true\"></i></a>{rtfHtml}{htmlHtml}</p>");
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

        if (!HasEntityPermission(context, meta))
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

        if (!HasEntityPermission(context, meta))
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

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, id);
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

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, id);
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
            context.SetStringValue("message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("message", "<p>You do not have permission to access this resource.</p>");
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
        context.SetStringValue("title", $"Import CSV: {WebUtility.HtmlEncode(meta.Name)}");
        context.SetStringValue("message", help);
        context.AddFormDefinition(new FormDefinition($"/admin/data/{typeSlug}/import", "post", "Import CSV", fields));
        await _renderer.RenderPage(context);
    }

    public async ValueTask DataImportPostHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        if (meta == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Import CSV");
            context.SetStringValue("message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.SetStringValue("title", "Import CSV");
            context.SetStringValue("message", "<p>Invalid form submission.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            context.SetStringValue("title", "Import CSV");
            context.SetStringValue("message", "<p>Invalid security token. Please try again.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var file = form.Files.GetFile("csv_file");
        if (file == null || file.Length == 0)
        {
            context.SetStringValue("title", "Import CSV");
            context.SetStringValue("message", "<p>No CSV file uploaded.</p>");
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
            context.SetStringValue("message", "<p>CSV file is empty or missing headers.</p>");
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
            if (upsert && !string.IsNullOrWhiteSpace(idValue))
            {
                var existing = await DataScaffold.LoadAsync(meta, idValue!);
                if (existing is BaseDataObject existingObject)
                {
                    instance = existingObject;
                    isCreate = false;
                }
                else
                {
                    instance = meta.Handlers.Create();
                    instance.Id = idValue;
                }
            }
            else
            {
                instance = meta.Handlers.Create();
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

            ApplyAuditInfo(instance, context, isCreate);
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

        context.SetStringValue("title", $"Import CSV: {WebUtility.HtmlEncode(meta.Name)}");
        context.SetStringValue("message", summary + $"<p><a class=\"btn btn-sm btn-outline-secondary\" href=\"/admin/data/{typeSlug}\">Back to list</a></p>");
        await _renderer.RenderPage(context);
    }

    public async ValueTask DataCreateHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        if (meta == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Data");
            context.SetStringValue("message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var csrfToken = CsrfProtection.EnsureToken(context);
        var fields = DataScaffold.BuildFormFields(meta, null, forCreate: true).ToList();
        AppendUserPasswordFieldsIfNeeded(meta, fields, isCreate: true);
        fields.Insert(0, new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken));

        context.SetStringValue("title", $"Create {WebUtility.HtmlEncode(meta.Name)}");
        context.AddFormDefinition(new FormDefinition($"/admin/data/{typeSlug}/create", "post", $"Create {meta.Name}", fields));
        await _renderer.RenderPage(context);
    }

    public async ValueTask DataCreatePostHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        if (meta == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Data");
            context.SetStringValue("message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.SetStringValue("title", "Invalid Request");
            context.SetStringValue("message", "<p>Invalid form submission.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            context.SetStringValue("title", "Invalid Request");
            context.SetStringValue("message", "<p>Invalid security token. Please try again.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var instance = meta.Handlers.Create();

        var values = form.ToDictionary(k => k.Key, v => (string?)v.Value.ToString(), StringComparer.OrdinalIgnoreCase);
        var apiKeyInputs = ExtractSystemPrincipalKeys(values);
        var errors = DataScaffold.ApplyValuesFromForm(meta, instance, values, forCreate: true);
        ApplyUserPasswordIfNeeded(meta, instance, values, errors, isCreate: true);
        if (errors.Count > 0)
        {
            context.SetStringValue("title", $"Create {WebUtility.HtmlEncode(meta.Name)}");
            context.SetStringValue("message", $"<div class=\"alert alert-danger\">{string.Join("<br/>", errors.Select(WebUtility.HtmlEncode))}</div>");
            var fields = DataScaffold.BuildFormFields(meta, instance, forCreate: true).ToList();
            AppendUserPasswordFieldsIfNeeded(meta, fields, isCreate: true);
            fields.Insert(0, new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: CsrfProtection.EnsureToken(context)));
            context.AddFormDefinition(new FormDefinition($"/admin/data/{typeSlug}/create", "post", $"Create {meta.Name}", fields));
            await _renderer.RenderPage(context);
            return;
        }

        string? newApiKey = null;
        if (instance is SystemPrincipal principal)
        {
            var createdKeys = ApplySystemPrincipalKeys(principal, apiKeyInputs, isCreate: true);
            newApiKey = createdKeys.FirstOrDefault();
        }

        ApplyAuditInfo(instance, context, isCreate: true);
        await DataScaffold.SaveAsync(meta, instance);
        var newId = instance is BaseDataObject dataObject ? DataScaffold.GetIdValue(dataObject) : null;
        var keyQuery = string.IsNullOrWhiteSpace(newApiKey) ? string.Empty : $"&apikey={WebUtility.UrlEncode(newApiKey)}";
        context.Response.Redirect($"/admin/data/{typeSlug}?toast=created&id={WebUtility.UrlEncode(newId ?? string.Empty)}{keyQuery}");
    }

    public async ValueTask DataEditHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out var typeSlug, out var errorMessage);
        var id = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(id))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Data");
            context.SetStringValue("message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, id);
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Not Found");
            context.SetStringValue("message", "<p>Item not found.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var csrfToken = CsrfProtection.EnsureToken(context);
        var fields = DataScaffold.BuildFormFields(meta, instance, forCreate: false).ToList();
        AppendUserPasswordFieldsIfNeeded(meta, fields, isCreate: false);
        fields.Insert(0, new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken));

        context.SetStringValue("title", $"Edit {WebUtility.HtmlEncode(meta.Name)}");
        context.AddFormDefinition(new FormDefinition($"/admin/data/{typeSlug}/{WebUtility.UrlEncode(id)}/edit", "post", $"Save {meta.Name}", fields));
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
            context.SetStringValue("message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.SetStringValue("title", "Invalid Request");
            context.SetStringValue("message", "<p>Invalid form submission.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, id);
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            context.SetStringValue("title", "Not Found");
            context.SetStringValue("message", "<p>Item not found.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            context.SetStringValue("title", "Invalid Request");
            context.SetStringValue("message", "<p>Invalid security token. Please try again.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var values = form.ToDictionary(k => k.Key, v => (string?)v.Value.ToString(), StringComparer.OrdinalIgnoreCase);
        var apiKeyInputs = ExtractSystemPrincipalKeys(values);
        var errors = DataScaffold.ApplyValuesFromForm(meta, instance, values, forCreate: false);
        ApplyUserPasswordIfNeeded(meta, instance, values, errors, isCreate: false);
        if (errors.Count > 0)
        {
            context.SetStringValue("title", $"Edit {WebUtility.HtmlEncode(meta.Name)}");
            context.SetStringValue("message", $"<div class=\"alert alert-danger\">{string.Join("<br/>", errors.Select(WebUtility.HtmlEncode))}</div>");
            var fields = DataScaffold.BuildFormFields(meta, instance, forCreate: false).ToList();
            AppendUserPasswordFieldsIfNeeded(meta, fields, isCreate: false);
            fields.Insert(0, new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: CsrfProtection.EnsureToken(context)));
            context.AddFormDefinition(new FormDefinition($"/admin/data/{typeSlug}/{WebUtility.UrlEncode(id)}/edit", "post", $"Save {meta.Name}", fields));
            await _renderer.RenderPage(context);
            return;
        }

        if (instance is SystemPrincipal principal)
        {
            ApplySystemPrincipalKeys(principal, apiKeyInputs, isCreate: false);
        }

        ApplyAuditInfo(instance, context, isCreate: false);
        await DataScaffold.SaveAsync(meta, instance);
        context.Response.Redirect($"/admin/data/{typeSlug}?toast=updated&id={WebUtility.UrlEncode(id)}");
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
            context.SetStringValue("message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("message", "<p>You do not have permission to access this resource.</p>");
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
        context.SetStringValue("message", $"<p>Delete this {WebUtility.HtmlEncode(meta.Name)} record? This cannot be undone.</p>");
        context.AddFormDefinition(new FormDefinition($"/admin/data/{typeSlug}/{WebUtility.UrlEncode(id)}/delete", "post", $"Delete {meta.Name}", fields));
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
            context.SetStringValue("message", errorMessage ?? "Entity not found.");
            await _renderer.RenderPage(context);
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.SetStringValue("title", "Access denied");
            context.SetStringValue("message", "<p>You do not have permission to access this resource.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.SetStringValue("title", "Invalid Request");
            context.SetStringValue("message", "<p>Invalid form submission.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            context.SetStringValue("title", "Invalid Request");
            context.SetStringValue("message", "<p>Invalid security token. Please try again.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        await DataScaffold.DeleteAsync(meta, id);
        context.Response.Redirect($"/admin/data/{typeSlug}?toast=deleted&id={WebUtility.UrlEncode(id)}");
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

        if (!HasEntityPermission(context, meta))
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

        var instance = await DataScaffold.LoadAsync(meta, id);
        if (instance is not BaseDataObject source)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Item not found.");
            return;
        }

        var clone = CreateClone(meta, source);
        ApplyAuditInfo(clone, context, isCreate: true);
        await DataScaffold.SaveAsync(meta, clone);

        var newId = DataScaffold.GetIdValue(clone) ?? string.Empty;
        if (redirectToEdit)
        {
            var editUrl = $"/admin/data/{typeSlug}/{WebUtility.UrlEncode(newId)}/edit?toast=cloned&id={WebUtility.UrlEncode(newId)}";
            context.Response.Redirect(editUrl);
            return;
        }

        var returnUrl = form["returnUrl"].ToString();
        var redirectUrl = BuildCloneRedirectUrl(returnUrl, $"/admin/data/{typeSlug}", newId);
        context.Response.Redirect(redirectUrl);
    }

    private static string BuildCloneRedirectUrl(string? returnUrl, string fallbackUrl, string newId)
    {
        var safeReturnUrl = SanitizeCloneReturnUrl(returnUrl, fallbackUrl);
        var separator = safeReturnUrl.Contains('?') ? "&" : "?";
        return $"{safeReturnUrl}{separator}toast=cloned&id={WebUtility.UrlEncode(newId)}";
    }

    private static string SanitizeCloneReturnUrl(string? returnUrl, string fallbackUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
            return fallbackUrl;

        if (!returnUrl.StartsWith("/admin/data/", StringComparison.OrdinalIgnoreCase))
            return fallbackUrl;

        return returnUrl;
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
        return string.Equals(propertyName, nameof(BaseDataObject.Id), StringComparison.OrdinalIgnoreCase)
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

        var nonce = context.GetCspNonce();
        return $"<div class=\"toast-container position-fixed bottom-0 end-0 p-3 toast-z-index\">" +
             $"<div id=\"scaffold-toast\" class=\"toast text-bg-success border-0\" role=\"alert\" aria-live=\"assertive\" aria-atomic=\"true\" data-bs-delay=\"2500\">" +
             $"<div class=\"d-flex\"><div class=\"toast-body\">{message}</div>" +
             $"<button type=\"button\" class=\"btn-close btn-close-white me-2 m-auto\" data-bs-dismiss=\"toast\" aria-label=\"Close\"></button></div></div></div>" +
             $"<script src=\"/static/js/toast.js\" nonce=\"{nonce}\"></script>";
    }

    public async ValueTask DataApiListHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        if (meta == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Entity not found.");
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        var query = DataScaffold.BuildQueryDefinition(ToQueryDictionary(context.Request.Query), meta);
        var results = await DataScaffold.QueryAsync(meta, query);
        var payload = results.Cast<object>().Select(item => BuildApiModel(meta, item)).ToArray();

        await WriteJsonResponseAsync(context, payload);
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

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, id);
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

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        var payload = await ReadJsonBodyAsync(context);
        if (payload == null)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid JSON body.");
            return;
        }

        var instance = meta.Handlers.Create();

        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, payload, forCreate: true, allowMissing: false);
        if (errors.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync(string.Join(" | ", errors));
            return;
        }

        ApplyAuditInfo(instance, context, isCreate: true);
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

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        var payload = await ReadJsonBodyAsync(context);
        if (payload == null)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid JSON body.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, id);
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Item not found.");
            return;
        }

        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, payload, forCreate: false, allowMissing: false);
        if (errors.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync(string.Join(" | ", errors));
            return;
        }

        ApplyAuditInfo(instance, context, isCreate: false);
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

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        var payload = await ReadJsonBodyAsync(context);
        if (payload == null)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid JSON body.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, id);
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Item not found.");
            return;
        }

        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, payload, forCreate: false, allowMissing: true);
        if (errors.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync(string.Join(" | ", errors));
            return;
        }

        ApplyAuditInfo(instance, context, isCreate: false);
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

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        await DataScaffold.DeleteAsync(meta, id);
        context.Response.StatusCode = StatusCodes.Status204NoContent;
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
            ["throttledRequests"] = snapshot.ThrottledRequests
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
                ctx.SetStringValue("message", "<p>No log folders found.</p>");
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
            if (!selectedYear.Months.Any(entry => string.Equals(entry.Key, selectedMonthKey, StringComparison.OrdinalIgnoreCase)))
                selectedMonthKey = string.Empty;

            if (string.IsNullOrWhiteSpace(selectedMonthKey) && selectedYear.Months.Count > 0)
            {
                var latestMonth = selectedYear.Months.OrderByDescending(entry => entry.MonthDate).First();
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
                var fullPath = Path.Combine(root, date, hour, file);
                var selectedEntry = fileEntries.FirstOrDefault(entry => string.Equals(entry.Name, file, StringComparison.OrdinalIgnoreCase));
                html.Append(RenderLogFile(fullPath, file, selectedEntry.IsError));
            }
            else
            {
                html.Append("<p class=\"text-muted mb-0\">Select a log file to view.</p>");
            }
            html.Append("</div>");
            html.Append("</div>");

            ctx.SetStringValue("message", html.ToString());
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
                ctx.SetStringValue("message", $"<p class=\"text-danger\">{WebUtility.HtmlEncode(errorMessage)}</p>");
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
            ctx.SetStringValue("message", $"<p>Are you sure you want to delete logs for <strong>{WebUtility.HtmlEncode(target.Label)}</strong>?</p>");
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
            RenderSampleDataForm(ctx, "<p>Generate sample data for load and indexing tests.</p>", 100, 50, 25, 25, clearExisting: false);
        })(context);
    }

    public async ValueTask SampleDataPostHandler(HttpContext context)
    {
        if (!context.Request.HasFormContentType)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            context.SetStringValue("title", "Generate Sample Data");
            context.SetStringValue("message", "<p>Invalid form submission.</p>");
            await _renderer.RenderPage(context);
            return;
        }

        var form = await context.Request.ReadFormAsync();
        if (!CsrfProtection.ValidateFormToken(context, form))
        {
            context.SetStringValue("title", "Generate Sample Data");
            context.SetStringValue("message", "<p>Invalid security token. Please try again.</p>");
            RenderSampleDataForm(context, "<p>Invalid security token. Please try again.</p>", 100, 50, 25, 25, clearExisting: false);
            await _renderer.RenderPage(context);
            return;
        }

        var errors = new List<string>();
        var addressCount = ParseSampleCount(form, "addresses", errors);
        var customerCount = ParseSampleCount(form, "customers", errors);
        var unitCount = ParseSampleCount(form, "units", errors);
        var productCount = ParseSampleCount(form, "products", errors);
        var clearExisting = ParseSampleToggle(form, "clearExisting");

        if (customerCount > 0 && addressCount == 0)
            errors.Add("Customers require at least one address.");
        if (productCount > 0 && unitCount == 0)
            errors.Add("Products require at least one unit of measure.");

        if (errors.Count > 0)
        {
            context.SetStringValue("title", "Generate Sample Data");
            context.SetStringValue("message", $"<div class=\"alert alert-danger\">{string.Join("<br/>", errors.Select(WebUtility.HtmlEncode))}</div>");
            RenderSampleDataForm(context, $"<div class=\"alert alert-danger\">{string.Join("<br/>", errors.Select(WebUtility.HtmlEncode))}</div>", addressCount, customerCount, unitCount, productCount, clearExisting);
            await _renderer.RenderPage(context);
            return;
        }

        if (clearExisting)
        {
            await DeleteAllAsync<Customer>();
            await DeleteAllAsync<Product>();
            await DeleteAllAsync<Address>();
            await DeleteAllAsync<UnitOfMeasure>();
        }

        var usedAddressIds = new HashSet<string>(
            DataStoreProvider.Current.Query<Address>(null)
                .Select(address => address.Id),
            StringComparer.OrdinalIgnoreCase);
        var usedUnitIds = new HashSet<string>(
            DataStoreProvider.Current.Query<UnitOfMeasure>(null)
                .Select(unit => unit.Id),
            StringComparer.OrdinalIgnoreCase);
        var usedCustomerIds = new HashSet<string>(
            DataStoreProvider.Current.Query<Customer>(null)
                .Select(customer => customer.Id),
            StringComparer.OrdinalIgnoreCase);
        var usedProductIds = new HashSet<string>(
            DataStoreProvider.Current.Query<Product>(null)
                .Select(product => product.Id),
            StringComparer.OrdinalIgnoreCase);

        var addresses = GenerateAddresses(addressCount, usedAddressIds);
        var units = GenerateUnits(unitCount, usedUnitIds);
        var customers = GenerateCustomers(customerCount, addresses, usedCustomerIds);
        var products = GenerateProducts(productCount, units, usedProductIds);

        foreach (var address in addresses)
        {
            ApplyAuditInfo(address, context, isCreate: true);
            DataStoreProvider.Current.Save(address);
        }

        foreach (var unit in units)
        {
            ApplyAuditInfo(unit, context, isCreate: true);
            DataStoreProvider.Current.Save(unit);
        }

        foreach (var customer in customers)
        {
            ApplyAuditInfo(customer, context, isCreate: true);
            DataStoreProvider.Current.Save(customer);
        }

        foreach (var product in products)
        {
            ApplyAuditInfo(product, context, isCreate: true);
            DataStoreProvider.Current.Save(product);
        }

        var message = $"<div class=\"alert alert-success\">" +
                      $"Created {addresses.Count} addresses, {customers.Count} customers, {units.Count} units, {products.Count} products." +
                      "</div>";
        RenderSampleDataForm(context, message, addressCount, customerCount, unitCount, productCount, clearExisting);
        await _renderer.RenderPage(context);
    }

    private static Dictionary<string, object?> BuildApiModel(DataEntityMetadata meta, object instance)
    {
        var data = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        var id = instance is BaseDataObject dataObject ? DataScaffold.GetIdValue(dataObject) : null;
        if (!string.IsNullOrWhiteSpace(id))
            data["id"] = id;

        foreach (var field in meta.Fields.Where(f => f.View))
        {
            data[field.Name] = field.Property.GetValue(instance);
        }

        return data;
    }


    private static string GetLogRoot(HttpContext context)
    {
        var config = context.RequestServices.GetService(typeof(IConfiguration)) as IConfiguration;
        var logFolder = config?.GetValue("Logging:LogFolder", "Logs") ?? "Logs";
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
                return WebUtility.HtmlDecode(pageContext.PageMetaDataValues[i]);
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

    private static bool HasEntityPermission(HttpContext context, DataEntityMetadata meta)
    {
        var permissionsNeeded = meta.Permissions?.Trim();
        if (string.IsNullOrWhiteSpace(permissionsNeeded) || string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase))
            return true;

        var user = UserAuth.GetRequestUser(context);
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

    private static void ApplyAuditInfo(object instance, HttpContext context, bool isCreate)
    {
        if (instance is not BaseDataObject dataObject)
            return;

        var user = UserAuth.GetUser(context);
        var userName = user?.UserName ?? "system";

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

    private void RenderSampleDataForm(HttpContext context, string? message, int addresses, int customers, int units, int products, bool clearExisting)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Generate Sample Data");
        context.SetStringValue("message", string.IsNullOrWhiteSpace(message) ? string.Empty : message);

        var fields = new List<FormField>
        {
            new FormField(FormFieldType.Hidden, CsrfProtection.FormFieldName, string.Empty, Value: csrfToken),
            new FormField(FormFieldType.Integer, "addresses", "Addresses", Required: true, Value: addresses.ToString(CultureInfo.InvariantCulture)),
            new FormField(FormFieldType.Integer, "customers", "Customers", Required: true, Value: customers.ToString(CultureInfo.InvariantCulture)),
            new FormField(FormFieldType.Integer, "units", "Units Of Measure", Required: true, Value: units.ToString(CultureInfo.InvariantCulture)),
            new FormField(FormFieldType.Integer, "products", "Products", Required: true, Value: products.ToString(CultureInfo.InvariantCulture)),
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

    private static async ValueTask DeleteAllAsync<T>() where T : BaseDataObject
    {
        var items = DataStoreProvider.Current.Query<T>(null).ToList();
        foreach (var item in items)
        {
            if (item == null || string.IsNullOrWhiteSpace(item.Id))
                continue;
            await DataStoreProvider.Current.DeleteAsync<T>(item.Id);
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
                AddressId = address?.Id ?? string.Empty,
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
                UnitOfMeasureId = unit?.Id ?? string.Empty,
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

    private static void EnsureUniqueId(BaseDataObject dataObject, HashSet<string> usedIds)
    {
        var id = dataObject.Id;
        if (string.IsNullOrWhiteSpace(id) || usedIds.Contains(id))
        {
            do
            {
                id = Guid.NewGuid().ToString("N");
            }
            while (usedIds.Contains(id));

            dataObject.Id = id;
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

    private void RenderMfaResetForm(HttpContext context, string? message)
    {
        var csrfToken = CsrfProtection.EnsureToken(context);
        context.SetStringValue("title", "Reset MFA");
        context.SetStringValue("message", string.IsNullOrWhiteSpace(message)
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

    private static MfaChallenge? GetMfaChallenge(HttpContext context)
    {
        var challengeId = context.GetCookie(MfaChallengeCookieName);
        if (string.IsNullOrWhiteSpace(challengeId))
            return null;

        var challenge = DataStoreProvider.Current.Load<MfaChallenge>(challengeId);
        if (challenge == null || challenge.IsExpired())
        {
            if (challenge != null)
            {
                challenge.IsUsed = true;
                DataStoreProvider.Current.Save(challenge);
            }
            context.DeleteCookie(MfaChallengeCookieName);
            return null;
        }

        return challenge;
    }

    private static bool RootUserExists()
    {
        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = nameof(User.Permissions), Operator = QueryOperator.Contains, Value = "admin" },
                new QueryClause { Field = nameof(User.Permissions), Operator = QueryOperator.Contains, Value = "monitoring" }
            }
        };

        return DataStoreProvider.Current.Query<User>(query).Any();
    }
}
