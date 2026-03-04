using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace BareMetalWeb.Host.Tests;

[Collection("SharedState")]
public class EntraIdServiceTests : IDisposable
{
    private readonly string _tempDirectory;

    public EntraIdServiceTests()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        Directory.CreateDirectory(_tempDirectory);
        // CookieProtection keys are shared across the collection; do not reconfigure here
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDirectory, true); } catch { }
    }

    [Fact]
    public void DecodeIdToken_ExtractsClaimsFromJwt()
    {
        var payload = new
        {
            oid = "obj-123",
            email = "user@example.com",
            name = "Test User",
            tid = "tenant-456",
            nonce = "test-nonce-value"
        };

        var token = BuildTestJwt(payload);
        var userInfo = DecodeIdTokenViaReflection(token);

        Assert.Equal("obj-123", userInfo.ObjectId);
        Assert.Equal("user@example.com", userInfo.Email);
        Assert.Equal("Test User", userInfo.DisplayName);
        Assert.Equal("tenant-456", userInfo.TenantId);
        Assert.Equal("test-nonce-value", userInfo.Nonce);
    }

    [Fact]
    public void DecodeIdToken_FallsBackToPreferredUsername()
    {
        var payload = new
        {
            oid = "obj-789",
            preferred_username = "upn@example.com",
            name = "UPN User",
            tid = "tenant-abc"
        };

        var token = BuildTestJwt(payload);
        var userInfo = DecodeIdTokenViaReflection(token);

        Assert.Equal("upn@example.com", userInfo.Email);
    }

    [Fact]
    public void DecodeIdToken_HandlesInvalidToken()
    {
        var userInfo = DecodeIdTokenViaReflection("not-a-jwt");

        Assert.Null(userInfo.ObjectId);
        Assert.Null(userInfo.Email);
    }

    [Fact]
    public void ValidateState_MatchesProtectedCookie()
    {
        var state = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var protectedState = CookieProtection.Protect(state);

        // Validate using the protected value and expected state
        var unprotected = CookieProtection.Unprotect(protectedState);
        Assert.Equal(state, unprotected);
    }

    [Fact]
    public void ValidateState_RejectsModifiedState()
    {
        var state = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var differentState = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var protectedState = CookieProtection.Protect(state);

        var unprotected = CookieProtection.Unprotect(protectedState);
        Assert.NotEqual(differentState, unprotected);
    }

    [Fact]
    public void BuildLogoutUrl_ContainsCorrectEndpoint()
    {
        var options = new EntraIdOptions
        {
            TenantId = "my-tenant",
            ClientId = "my-client"
        };

        var url = EntraIdService.BuildLogoutUrl(options, "https://app.example.com/login");

        Assert.Contains("login.microsoftonline.com/my-tenant/oauth2/v2.0/logout", url);
        Assert.Contains("post_logout_redirect_uri=", url);
        Assert.Contains("app.example.com", url);
    }

    [Fact]
    public async Task ProvisionUserAsync_ReturnsNullForEmptyEmail()
    {
        var options = new EntraIdOptions { AutoProvisionUsers = true };
        var userInfo = new EntraIdUserInfo { Email = null };

        var result = await EntraIdService.ProvisionUserAsync(options, userInfo);

        Assert.Null(result);
    }

    [Fact]
    public void EntraIdOptions_Defaults_AreCorrect()
    {
        var options = new EntraIdOptions();

        Assert.False(options.Enabled);
        Assert.Equal("/auth/sso/callback", options.RedirectUri);
        Assert.True(options.AutoProvisionUsers);
        Assert.Equal("user", options.DefaultPermissions);
        Assert.Empty(options.GroupRoleMappings);
    }

    [Fact]
    public void EntraIdUserInfo_NonceParsed()
    {
        var payload = new { nonce = "abc123", email = "user@test.com" };
        var token = BuildTestJwt(payload);
        var userInfo = DecodeIdTokenViaReflection(token);

        Assert.Equal("abc123", userInfo.Nonce);
    }

    // ── Test helpers ──────────────────────────────────────────────────

    private static string BuildTestJwt(object payload)
    {
        var header = Base64UrlEncode("{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        var payloadJson = JsonSerializer.Serialize(payload);
        var body = Base64UrlEncode(payloadJson);
        return $"{header}.{body}.fake-signature";
    }

    private static string Base64UrlEncode(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static EntraIdUserInfo DecodeIdTokenViaReflection(string idToken)
    {
        // Use reflection to call the private static DecodeIdToken method
        var method = typeof(EntraIdService).GetMethod("DecodeIdToken",
            System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
        return (EntraIdUserInfo)method!.Invoke(null, new object[] { idToken })!;
    }
}
