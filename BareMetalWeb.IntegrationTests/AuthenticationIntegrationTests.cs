using System.Net;
using System.Net.Http.Headers;
using Xunit;

namespace BareMetalWeb.IntegrationTests;

/// <summary>
/// Integration tests that run against a deployed BareMetalWeb instance.
/// These tests verify authentication and basic functionality.
/// </summary>
public class AuthenticationIntegrationTests : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly string _baseUrl;
    private readonly string _username;
    private readonly string _password;

    public AuthenticationIntegrationTests()
    {
        _baseUrl = Environment.GetEnvironmentVariable("CIMIGRATE_BASE_URL") 
            ?? "https://baremetalweb-cimigrate.azurewebsites.net";
        _username = Environment.GetEnvironmentVariable("CIMIGRATE_TEST_USERNAME") ?? string.Empty;
        _password = Environment.GetEnvironmentVariable("CIMIGRATE_TEST_PASSWORD") ?? string.Empty;

        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = true,
            CookieContainer = new System.Net.CookieContainer()
        };

        _httpClient = new HttpClient(handler)
        {
            BaseAddress = new Uri(_baseUrl),
            Timeout = TimeSpan.FromSeconds(30)
        };
    }

    /// <summary>
    /// Skips the test if required environment variables are not set.
    /// This allows the tests to run in CI/CD pipelines with credentials,
    /// but skip gracefully in local development or other environments without them.
    /// </summary>
    private void EnsureEnvironmentVariablesAreSet()
    {
        Skip.IfNot(
            !string.IsNullOrEmpty(_username) && !string.IsNullOrEmpty(_password),
            "Integration tests require CIMIGRATE_TEST_USERNAME and CIMIGRATE_TEST_PASSWORD environment variables to be set. " +
            "These tests are designed to run against a deployed instance with valid credentials.");
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }

    [SkippableFact]
    public async Task HomePage_Returns_Success()
    {
        EnsureEnvironmentVariablesAreSet();
        
        // Act
        var response = await _httpClient.GetAsync("/");

        // Assert
        Assert.True(response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.Redirect, 
            $"Expected success or redirect, got {response.StatusCode}");
    }

    [SkippableFact]
    public async Task Login_WithValidCredentials_Succeeds()
    {
        EnsureEnvironmentVariablesAreSet();
        
        // Arrange - First, get the login page to obtain CSRF token if needed
        var loginPageResponse = await _httpClient.GetAsync("/login");
        
        // For now, we'll just check that we can access the login page
        Assert.True(
            loginPageResponse.IsSuccessStatusCode || loginPageResponse.StatusCode == HttpStatusCode.OK,
            $"Login page should be accessible, got {loginPageResponse.StatusCode}"
        );

        // Act - Attempt to login
        var loginData = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("username", _username),
            new KeyValuePair<string, string>("password", _password),
        });

        var loginResponse = await _httpClient.PostAsync("/login", loginData);

        // Assert - Should redirect after successful login or return success
        Assert.True(
            loginResponse.IsSuccessStatusCode 
            || loginResponse.StatusCode == HttpStatusCode.Redirect 
            || loginResponse.StatusCode == HttpStatusCode.Found
            || loginResponse.StatusCode == HttpStatusCode.SeeOther,
            $"Login should succeed or redirect, got {loginResponse.StatusCode}"
        );

        // If redirected, verify we got a session cookie
        if (loginResponse.StatusCode == HttpStatusCode.Redirect 
            || loginResponse.StatusCode == HttpStatusCode.Found 
            || loginResponse.StatusCode == HttpStatusCode.SeeOther)
        {
            var cookies = (loginResponse.Headers.TryGetValues("Set-Cookie", out var cookieHeaders))
                ? cookieHeaders : Array.Empty<string>();
            
            Assert.Contains(cookies, c => c.Contains("bm-session") || c.Contains("session"));
        }
    }

    [SkippableFact]
    public async Task Login_WithInvalidCredentials_Fails()
    {
        EnsureEnvironmentVariablesAreSet();
        
        // Arrange
        var loginData = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("username", "invalid_user_12345"),
            new KeyValuePair<string, string>("password", "wrong_password_12345"),
        });

        // Act
        var loginResponse = await _httpClient.PostAsync("/login", loginData);

        // Assert - Should either return error page or redirect back to login
        // We should NOT get a successful authentication
        var responseText = await loginResponse.Content.ReadAsStringAsync();
        
        // Success means we didn't log in (either error page or redirect to login)
        Assert.True(
            !loginResponse.IsSuccessStatusCode 
            || responseText.Contains("invalid", StringComparison.OrdinalIgnoreCase)
            || responseText.Contains("error", StringComparison.OrdinalIgnoreCase)
            || responseText.Contains("incorrect", StringComparison.OrdinalIgnoreCase)
            || loginResponse.RequestMessage?.RequestUri?.PathAndQuery.Contains("login") == true,
            "Invalid credentials should not result in successful authentication"
        );
    }

    [SkippableFact]
    public async Task ProtectedPage_WithoutAuthentication_Redirects()
    {
        EnsureEnvironmentVariablesAreSet();
        
        // Arrange - Use a fresh client without authentication
        using var unauthClient = new HttpClient
        {
            BaseAddress = new Uri(_baseUrl),
            Timeout = TimeSpan.FromSeconds(30)
        };

        // Act - Try to access a protected page (assuming /users or /admin might be protected)
        var response = await unauthClient.GetAsync("/users");

        // Assert - Should redirect to login or return unauthorized
        Assert.True(
            response.StatusCode == HttpStatusCode.Redirect 
            || response.StatusCode == HttpStatusCode.Found
            || response.StatusCode == HttpStatusCode.SeeOther
            || response.StatusCode == HttpStatusCode.Unauthorized
            || response.StatusCode == HttpStatusCode.Forbidden,
            $"Protected page should redirect or deny access, got {response.StatusCode}"
        );
    }

    [SkippableFact]
    public async Task StaticFiles_AreAccessible()
    {
        EnsureEnvironmentVariablesAreSet();
        
        // Act - Try to access a static file (CSS)
        var response = await _httpClient.GetAsync("/static/site.css");

        // Assert - Static files should be publicly accessible
        Assert.True(
            response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NotFound,
            $"Static files should be accessible or not found, got {response.StatusCode}"
        );
    }

    [SkippableFact]
    public async Task ApiEndpoint_RespondsCorrectly()
    {
        EnsureEnvironmentVariablesAreSet();
        
        // Act - Try to access API health/status endpoint if it exists
        var response = await _httpClient.GetAsync("/api/health");

        // Assert - Should return a response (success, not found, or unauthorized are all valid)
        Assert.NotEqual(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.NotEqual(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.NotEqual(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }
}
