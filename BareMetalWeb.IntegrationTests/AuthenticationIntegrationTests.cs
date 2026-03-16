// TODO: Rebuild integration test stack — these tests need to be rewritten
//       to use an in-process test host rather than hitting a deployed instance.
//       See GitHub issue #1500.

#if false // Commented out pending integration test rebuild

using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using Xunit;

namespace BareMetalWeb.IntegrationTests;

/// <summary>
/// Integration tests that run against a deployed BareMetalWeb instance.
/// These tests verify authentication and basic functionality.
/// <para>
/// For CI/CD: Set CIMIGRATE_TEST_USERNAME and CIMIGRATE_TEST_PASSWORD environment variables.
/// For local testing: Credentials are randomly generated and the setup endpoint is used if needed.
/// </para>
/// </summary>
public class AuthenticationIntegrationTests : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly string _baseUrl;
    private readonly string _username;
    private readonly string _password;
    private readonly string _email;
    private bool _setupAttempted;

    public AuthenticationIntegrationTests()
    {
        _baseUrl = Environment.GetEnvironmentVariable("CIMIGRATE_BASE_URL") 
            ?? "https://baremetalweb-cimigrate.azurewebsites.net";
        
        // For CI/CD: Use environment variables for consistent credentials across runs
        // For local: Generate random credentials (consistent within this test run)
        var envUsername = Environment.GetEnvironmentVariable("CIMIGRATE_TEST_USERNAME");
        var envPassword = Environment.GetEnvironmentVariable("CIMIGRATE_TEST_PASSWORD");
        
        if (!string.IsNullOrEmpty(envUsername) && !string.IsNullOrEmpty(envPassword))
        {
            _username = envUsername;
            _password = envPassword;
            _email = $"{envUsername}@example.com";
        }
        else
        {
            // Generate random but consistent credentials for this test run
            var guid = Guid.NewGuid().ToString("N").Substring(0, 8);
            _username = $"testuser_{guid}";
            _password = $"TestPass_{guid}_!1aA";
            _email = $"test_{guid}@example.com";
        }

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
    /// Ensures the test user exists by checking if setup is needed and creating the user if necessary.
    /// This allows tests to run against a fresh BareMetalWeb instance without manual setup.
    /// </summary>
    private async Task EnsureUserExists()
    {
        if (_setupAttempted)
            return;

        _setupAttempted = true;

        try
        {
            // Check if setup is needed by trying to access the setup page
            var setupResponse = await _httpClient.GetAsync("/setup");
            
            if (setupResponse.StatusCode == HttpStatusCode.OK)
            {
                // Setup is available, extract CSRF token and create the user
                var setupHtml = await setupResponse.Content.ReadAsStringAsync();
                var csrfToken = ExtractCsrfToken(setupHtml);
                
                if (!string.IsNullOrEmpty(csrfToken))
                {
                    var setupData = new FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string, string>("__csrf", csrfToken),
                        new KeyValuePair<string, string>("username", _username),
                        new KeyValuePair<string, string>("email", _email),
                        new KeyValuePair<string, string>("password", _password),
                    });

                    await _httpClient.PostAsync("/setup", setupData);
                    // Note: We don't check the response here as the user might already exist
                    // or the setup might succeed. Either way, we'll try to login with the credentials.
                }
            }
            // If setup is not available (e.g., returns redirect or not found), the user should already exist
        }
        catch
        {
            // If setup fails, we'll try to proceed with login anyway
            // The credentials might already exist from a previous test run
        }
    }

    /// <summary>
    /// Extracts the CSRF token from an HTML form response.
    /// </summary>
    private static string? ExtractCsrfToken(string html)
    {
        // Look for: <input type="hidden" name="__csrf" value="..." />
        var match = Regex.Match(html, @"name=[""']__csrf[""']\s+value=[""']([^""']+)[""']", RegexOptions.IgnoreCase);
        if (match.Success)
            return match.Groups[1].Value;

        // Try alternate pattern: value="..." name="__csrf"
        match = Regex.Match(html, @"value=[""']([^""']+)[""']\s+name=[""']__csrf[""']", RegexOptions.IgnoreCase);
        if (match.Success)
            return match.Groups[1].Value;

        return null;
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task HomePage_Returns_Success()
    {
        await EnsureUserExists();
        
        // Act
        var response = await _httpClient.GetAsync("/");

        // Assert
        Assert.True(response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.Redirect, 
            $"Expected success or redirect, got {response.StatusCode}");
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task Login_WithValidCredentials_Succeeds()
    {
        await EnsureUserExists();
        
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

    [Fact]
    [Trait("Category", "Integration")]
    public async Task Login_WithInvalidCredentials_Fails()
    {
        await EnsureUserExists();
        
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

    [Fact]
    [Trait("Category", "Integration")]
    public async Task ProtectedPage_WithoutAuthentication_Redirects()
    {
        await EnsureUserExists();
        
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

    [Fact]
    [Trait("Category", "Integration")]
    public async Task StaticFiles_AreAccessible()
    {
        await EnsureUserExists();
        
        // Act - Try to access a static file (CSS)
        var response = await _httpClient.GetAsync("/static/site.css");

        // Assert - Static files should be publicly accessible
        Assert.True(
            response.IsSuccessStatusCode || response.StatusCode == HttpStatusCode.NotFound,
            $"Static files should be accessible or not found, got {response.StatusCode}"
        );
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task ApiEndpoint_RespondsCorrectly()
    {
        await EnsureUserExists();
        
        // Act - Try to access API health/status endpoint if it exists
        var response = await _httpClient.GetAsync("/api/health");

        // Assert - Should return a response (success, not found, or unauthorized are all valid)
        Assert.NotEqual(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.NotEqual(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.NotEqual(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }
}

#endif
