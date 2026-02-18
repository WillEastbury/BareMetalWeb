using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Tests for BareMetalWebServer request pipeline including routing, error handling,
/// CORS, HTTPS redirect, proxy headers, menu building, and setup flow.
/// </summary>
public class BareMetalWebServerTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;
    private readonly IDataObjectStore _testStore;
    private readonly BareMetalWebServer _server;
    private readonly MockBufferedLogger _logger;
    private readonly MockHtmlRenderer _renderer;
    private readonly MockMetricsTracker _metrics;
    private readonly MockClientRequestTracker _clientRequests;
    private readonly CancellationTokenSource _cts;
    private readonly WebApplication _app;

    public BareMetalWebServerTests()
    {
        _originalStore = DataStoreProvider.Current;
        _testStore = new InMemoryDataStore();
        DataStoreProvider.Current = _testStore;

        // Create a root user to prevent setup redirects in tests
        var rootUser = CreateUser("root", new[] { "admin", "monitoring" });
        _testStore.Save(rootUser);

        _logger = new MockBufferedLogger();
        _renderer = new MockHtmlRenderer();
        _metrics = new MockMetricsTracker();
        _clientRequests = new MockClientRequestTracker();
        _cts = new CancellationTokenSource();

        // Create a minimal WebApplication for testing
        var builder = WebApplication.CreateBuilder(new string[] { });
        builder.WebHost.UseKestrel();
        _app = builder.Build();

        var notFoundPage = CreatePageInfo("Not Found", 404);
        var errorPage = CreatePageInfo("Error", 500);

        _server = new BareMetalWebServer(
            "TestApp",
            "Test Company",
            "2026",
            _app,
            _logger,
            _renderer,
            notFoundPage,
            errorPage,
            _cts,
            _metrics,
            _clientRequests);
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
        _cts.Cancel();
        _cts.Dispose();
    }

    private void EnsureStore()
    {
        DataStoreProvider.Current = _testStore;
    }

    #region Route Dispatching Tests

    [Fact]
    public async Task RequestHandler_ExactRouteMatch_ExecutesHandler()
    {
        // Arrange
        EnsureStore();
        var executed = false;
        var pageInfo = CreatePageInfo("Test Page");
        _server.RegisterRoute("GET /test", new RouteHandlerData(
            pageInfo,
            async (ctx) => { executed = true; await Task.CompletedTask; }
        ));

        var context = CreateHttpContext("GET", "/test");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.True(executed, "Route handler should have been executed");
    }

    [Fact]
    public async Task RequestHandler_PatternRouteMatch_ExecutesHandlerWithParameters()
    {
        // Arrange
        EnsureStore();
        string? capturedId = null;
        var pageInfo = CreatePageInfo("User Page");
        _server.RegisterRoute("GET /users/{id}", new RouteHandlerData(
            pageInfo,
            async (ctx) =>
            {
                var pageInfoFromContext = ctx.GetPageInfo();
                if (pageInfoFromContext != null)
                {
                    var keys = pageInfoFromContext.PageContext.PageMetaDataKeys;
                    var values = pageInfoFromContext.PageContext.PageMetaDataValues;
                    var index = Array.IndexOf(keys, "id");
                    if (index >= 0 && index < values.Length)
                        capturedId = values[index];
                }
                await Task.CompletedTask;
            }
        ));

        var context = CreateHttpContext("GET", "/users/123");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal("123", capturedId);
    }

    [Fact]
    public async Task RequestHandler_AllVerbRoute_HandlesAnyMethod()
    {
        // Arrange
        EnsureStore();
        var executedCount = 0;
        var pageInfo = CreatePageInfo("All Verbs Page");
        _server.RegisterRoute("ALL /api/resource", new RouteHandlerData(
            pageInfo,
            async (ctx) => { executedCount++; await Task.CompletedTask; }
        ));

        // Act
        await _server.RequestHandler(CreateHttpContext("GET", "/api/resource"));
        await _server.RequestHandler(CreateHttpContext("POST", "/api/resource"));
        await _server.RequestHandler(CreateHttpContext("PUT", "/api/resource"));

        // Assert
        Assert.Equal(3, executedCount);
    }

    [Fact]
    public async Task RequestHandler_MethodNotAllowed_Returns405()
    {
        // Arrange
        EnsureStore();
        // Use a pattern route to trigger method checking
        _server.RegisterRoute("GET /api/resource/{id}", new RouteHandlerData(
            CreatePageInfo("GET Only"),
            async (ctx) => await Task.CompletedTask
        ));

        var context = CreateHttpContext("POST", "/api/resource/123");

        // Act
        await _server.RequestHandler(context);

        // Assert
        if (context.Response.StatusCode != 405)
        {
            // Log any errors for debugging
            var errors = string.Join("; ", _logger.ErrorLogs);
            Assert.Fail($"Expected 405 but got {context.Response.StatusCode}. Errors: {errors}");
        }
        Assert.Equal(405, context.Response.StatusCode);
    }

    [Fact]
    public async Task RequestHandler_NoRouteMatch_Returns404()
    {
        // Arrange
        EnsureStore();
        var context = CreateHttpContext("GET", "/nonexistent");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(404, context.Response.StatusCode);
    }

    #endregion

    #region Error Handling Tests

    [Fact]
    public async Task RequestHandler_HandlerThrowsException_Returns500()
    {
        // Arrange
        EnsureStore();
        _server.RegisterRoute("GET /error", new RouteHandlerData(
            CreatePageInfo("Error Page"),
            async (ctx) =>
            {
                await Task.CompletedTask;
                throw new InvalidOperationException("Test error");
            }
        ));

        var context = CreateHttpContext("GET", "/error");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(500, context.Response.StatusCode);
        Assert.True(_logger.ErrorLogs.Any(e => e.Contains("Test error")));
        Assert.Contains("X-Error-Id", context.Response.Headers.Keys);
    }

    [Fact]
    public async Task RequestHandler_OperationCanceled_LogsDisconnection()
    {
        // Arrange
        EnsureStore();
        var cts = new CancellationTokenSource();
        cts.Cancel();

        _server.RegisterRoute("GET /cancel", new RouteHandlerData(
            CreatePageInfo("Cancel Page"),
            async (ctx) =>
            {
                await Task.CompletedTask;
                throw new OperationCanceledException("Client disconnected");
            }
        ));

        var context = CreateHttpContext("GET", "/cancel");
        context.RequestAborted = cts.Token;

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.True(_logger.InfoLogs.Any(e => e.Contains("Client disconnected") || e.Contains("disconnected")),
            $"Expected disconnection log, got: {string.Join(", ", _logger.InfoLogs)}");
    }

    #endregion

    #region CORS Tests

    [Fact]
    public async Task RequestHandler_CorsEnabled_AddsHeaders()
    {
        // Arrange
        EnsureStore();
        _server.CorsAllowedOrigins = new[] { "https://example.com" };
        _server.CorsAllowedMethods = new[] { "GET", "POST" };
        _server.CorsAllowedHeaders = new[] { "Content-Type", "Authorization" };

        var context = CreateHttpContext("GET", "/test");
        context.Request.Headers.Origin = "https://example.com";

        _server.RegisterRoute("GET /test", new RouteHandlerData(
            CreatePageInfo("Test"),
            async (ctx) => await Task.CompletedTask
        ));

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal("https://example.com", context.Response.Headers.AccessControlAllowOrigin.ToString());
        Assert.Contains("GET, POST", context.Response.Headers.AccessControlAllowMethods.ToString());
    }

    [Fact]
    public async Task RequestHandler_CorsWildcard_AllowsAnyOrigin()
    {
        // Arrange
        EnsureStore();
        _server.CorsAllowedOrigins = new[] { "*" };

        var context = CreateHttpContext("GET", "/test");
        context.Request.Headers.Origin = "https://anywhere.com";

        _server.RegisterRoute("GET /test", new RouteHandlerData(
            CreatePageInfo("Test"),
            async (ctx) => await Task.CompletedTask
        ));

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal("*", context.Response.Headers.AccessControlAllowOrigin.ToString());
    }

    [Fact]
    public async Task RequestHandler_OptionsRequest_Returns204()
    {
        // Arrange
        EnsureStore();
        _server.CorsAllowedOrigins = new[] { "https://example.com" };

        var context = CreateHttpContext("OPTIONS", "/test");
        context.Request.Headers.Origin = "https://example.com";

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(204, context.Response.StatusCode);
    }

    [Fact]
    public async Task RequestHandler_CorsOriginNotAllowed_NoHeaders()
    {
        // Arrange
        EnsureStore();
        _server.CorsAllowedOrigins = new[] { "https://allowed.com" };

        var context = CreateHttpContext("GET", "/test");
        context.Request.Headers.Origin = "https://notallowed.com";

        _server.RegisterRoute("GET /test", new RouteHandlerData(
            CreatePageInfo("Test"),
            async (ctx) => await Task.CompletedTask
        ));

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.False(context.Response.Headers.ContainsKey("Access-Control-Allow-Origin"));
    }

    #endregion

    #region HTTPS Redirect Tests

    [Fact]
    public async Task RequestHandler_HttpsRedirectModeOff_NoRedirect()
    {
        // Arrange
        EnsureStore();
        _server.HttpsRedirectMode = HttpsRedirectMode.Off;
        _server.HttpsEndpointAvailable = true;

        var context = CreateHttpContext("GET", "/test");
        context.Request.IsHttps = false;

        _server.RegisterRoute("GET /test", new RouteHandlerData(
            CreatePageInfo("Test"),
            async (ctx) => await Task.CompletedTask
        ));

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.NotEqual(301, context.Response.StatusCode);
    }

    [Fact]
    public async Task RequestHandler_HttpsRedirectModeAlways_RedirectsHttp()
    {
        // Arrange
        EnsureStore();
        _server.HttpsRedirectMode = HttpsRedirectMode.Always;
        _server.HttpsEndpointAvailable = false;

        var context = CreateHttpContext("GET", "/test");
        context.Request.IsHttps = false;
        context.Request.Host = new HostString("example.com");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(301, context.Response.StatusCode);
        Assert.True(context.Response.Headers.Location.ToString().StartsWith("https://"));
    }

    [Fact]
    public async Task RequestHandler_HttpsRedirectIfAvailable_RedirectsWhenAvailable()
    {
        // Arrange
        EnsureStore();
        _server.HttpsRedirectMode = HttpsRedirectMode.IfAvailable;
        _server.HttpsEndpointAvailable = true;

        var context = CreateHttpContext("GET", "/test");
        context.Request.IsHttps = false;
        context.Request.Host = new HostString("example.com");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(301, context.Response.StatusCode);
        Assert.True(context.Response.Headers.Location.ToString().StartsWith("https://"));
    }

    [Fact]
    public async Task RequestHandler_HttpsRedirectIfAvailable_NoRedirectWhenNotAvailable()
    {
        // Arrange
        EnsureStore();
        _server.HttpsRedirectMode = HttpsRedirectMode.IfAvailable;
        _server.HttpsEndpointAvailable = false;
        _server.TrustForwardedHeaders = false;

        var context = CreateHttpContext("GET", "/test");
        context.Request.IsHttps = false;

        _server.RegisterRoute("GET /test", new RouteHandlerData(
            CreatePageInfo("Test"),
            async (ctx) => await Task.CompletedTask
        ));

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.NotEqual(301, context.Response.StatusCode);
    }

    [Fact]
    public async Task RequestHandler_AlreadyHttps_NoRedirect()
    {
        // Arrange
        EnsureStore();
        _server.HttpsRedirectMode = HttpsRedirectMode.Always;

        var context = CreateHttpContext("GET", "/test");
        context.Request.IsHttps = true;

        _server.RegisterRoute("GET /test", new RouteHandlerData(
            CreatePageInfo("Test"),
            async (ctx) => await Task.CompletedTask
        ));

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.NotEqual(301, context.Response.StatusCode);
    }

    #endregion

    #region Proxy/Forwarded Headers Tests

    [Fact]
    public async Task RequestHandler_ForwardedProtoHttps_DetectedAsHttps()
    {
        // Arrange
        EnsureStore();
        _server.TrustForwardedHeaders = true;
        _server.HttpsRedirectMode = HttpsRedirectMode.Always;

        var context = CreateHttpContext("GET", "/test");
        context.Request.IsHttps = false;
        context.Request.Headers["X-Forwarded-Proto"] = "https";

        _server.RegisterRoute("GET /test", new RouteHandlerData(
            CreatePageInfo("Test"),
            async (ctx) => await Task.CompletedTask
        ));

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal("true", context.Response.Headers["X-BareMetal-IsHttps"].ToString());
        Assert.NotEqual(301, context.Response.StatusCode);
    }

    [Fact]
    public async Task RequestHandler_ForwardedHeaderProto_DetectedAsHttps()
    {
        // Arrange
        EnsureStore();
        _server.TrustForwardedHeaders = true;
        _server.HttpsRedirectMode = HttpsRedirectMode.Always;

        var context = CreateHttpContext("GET", "/test");
        context.Request.IsHttps = false;
        context.Request.Headers["Forwarded"] = "proto=https;host=example.com";

        _server.RegisterRoute("GET /test", new RouteHandlerData(
            CreatePageInfo("Test"),
            async (ctx) => await Task.CompletedTask
        ));

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal("true", context.Response.Headers["X-BareMetal-IsHttps"].ToString());
        Assert.NotEqual(301, context.Response.StatusCode);
    }

    [Fact]
    public async Task RequestHandler_ForwardedHeadersNotTrusted_IgnoresHeaders()
    {
        // Arrange
        EnsureStore();
        _server.TrustForwardedHeaders = false;
        _server.HttpsRedirectMode = HttpsRedirectMode.Always;
        _server.HttpsEndpointAvailable = true;

        var context = CreateHttpContext("GET", "/test");
        context.Request.IsHttps = false;
        context.Request.Headers["X-Forwarded-Proto"] = "https";

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal("false", context.Response.Headers["X-BareMetal-IsHttps"].ToString());
        Assert.Equal(301, context.Response.StatusCode);
    }

    [Fact]
    public async Task RequestHandler_HttpsRedirectWithCustomHost_UsesCustomHost()
    {
        // Arrange
        EnsureStore();
        _server.HttpsRedirectMode = HttpsRedirectMode.Always;
        _server.HttpsRedirectHost = "secure.example.com";
        _server.HttpsRedirectPort = 8443;

        var context = CreateHttpContext("GET", "/test");
        context.Request.IsHttps = false;
        context.Request.Host = new HostString("example.com");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(301, context.Response.StatusCode);
        var location = context.Response.Headers.Location.ToString();
        Assert.Contains("secure.example.com", location);
        Assert.Contains("8443", location);
    }

    #endregion

    #region Menu Building Tests

    [Fact]
    public async Task BuildAppInfoMenuOptions_NoRoutes_EmptyMenu()
    {
        // Arrange
        EnsureStore();

        // Act
        await _server.BuildAppInfoMenuOptionsAsync();

        // Assert
        Assert.Empty(_server.MenuOptionsList);
    }

    [Fact]
    public async Task BuildAppInfoMenuOptions_PublicRoute_IncludedInMenu()
    {
        // Arrange
        EnsureStore();
        var pageInfo = CreatePageInfo("Home", permissionsNeeded: "Public", showOnNavBar: true);
        _server.RegisterRoute("GET /home", new RouteHandlerData(
            pageInfo,
            async (ctx) => await Task.CompletedTask
        ));

        // Act
        await _server.BuildAppInfoMenuOptionsAsync();

        // Assert
        Assert.Single(_server.MenuOptionsList);
        Assert.Equal("/home", _server.MenuOptionsList[0].Href);
        Assert.Equal("Home", _server.MenuOptionsList[0].Label);
    }

    [Fact]
    public async Task BuildAppInfoMenuOptions_AuthenticatedRoute_ExcludedForAnonymous()
    {
        // Arrange
        EnsureStore();
        var pageInfo = CreatePageInfo("Dashboard", permissionsNeeded: "Authenticated", showOnNavBar: true);
        _server.RegisterRoute("GET /dashboard", new RouteHandlerData(
            pageInfo,
            async (ctx) => await Task.CompletedTask
        ));

        var context = CreateHttpContext("GET", "/");

        // Act
        await _server.BuildAppInfoMenuOptionsAsync(context);

        // Assert
        Assert.Empty(_server.MenuOptionsList);
    }

    [Fact]
    public async Task BuildAppInfoMenuOptions_AuthenticatedRoute_IncludedForAuthenticatedUser()
    {
        // Arrange
        EnsureStore();
        var user = CreateUser("user1", Array.Empty<string>());
        var session = CreateSession(user);
        DataStoreProvider.Current.Save(user);
        DataStoreProvider.Current.Save(session);

        var pageInfo = CreatePageInfo("Dashboard", permissionsNeeded: "Authenticated", showOnNavBar: true);
        _server.RegisterRoute("GET /dashboard", new RouteHandlerData(
            pageInfo,
            async (ctx) => await Task.CompletedTask
        ));

        var context = CreateHttpContextWithSession("GET", "/", session);

        // Act
        await _server.BuildAppInfoMenuOptionsAsync(context);

        // Assert
        Assert.NotEmpty(_server.MenuOptionsList);
        Assert.Contains(_server.MenuOptionsList, m => m.Href == "/dashboard");
    }

    [Fact]
    public async Task BuildAppInfoMenuOptions_PermissionRoute_ExcludedForUserWithoutPermission()
    {
        // Arrange
        EnsureStore();
        var user = CreateUser("user1", new[] { "viewer" });
        var session = CreateSession(user);
        DataStoreProvider.Current.Save(user);
        DataStoreProvider.Current.Save(session);

        var pageInfo = CreatePageInfo("Admin", permissionsNeeded: "admin", showOnNavBar: true);
        _server.RegisterRoute("GET /admin", new RouteHandlerData(
            pageInfo,
            async (ctx) => await Task.CompletedTask
        ));

        var context = CreateHttpContextWithSession("GET", "/", session);

        // Act
        await _server.BuildAppInfoMenuOptionsAsync(context);

        // Assert
        Assert.DoesNotContain(_server.MenuOptionsList, m => m.Href == "/admin");
    }

    [Fact]
    public async Task BuildAppInfoMenuOptions_MenuCaching_ReusesCache()
    {
        // Arrange
        EnsureStore();
        var user = CreateUser("user1", new[] { "admin" });
        var session = CreateSession(user);
        DataStoreProvider.Current.Save(user);
        DataStoreProvider.Current.Save(session);

        var pageInfo = CreatePageInfo("Admin", permissionsNeeded: "admin", showOnNavBar: true);
        _server.RegisterRoute("GET /admin", new RouteHandlerData(
            pageInfo,
            async (ctx) => await Task.CompletedTask
        ));

        var context = CreateHttpContextWithSession("GET", "/", session);

        // Act - Build menu twice
        await _server.BuildAppInfoMenuOptionsAsync(context);
        var firstBuildCount = _server.MenuOptionsList.Count;

        await _server.BuildAppInfoMenuOptionsAsync(context);
        var secondBuildCount = _server.MenuOptionsList.Count;

        // Assert
        Assert.Equal(firstBuildCount, secondBuildCount);
    }

    [Fact]
    public async Task BuildAppInfoMenuOptions_RouteAdded_InvalidatesCache()
    {
        // Arrange
        EnsureStore();
        var user = CreateUser("user1", new[] { "admin" });
        var session = CreateSession(user);
        DataStoreProvider.Current.Save(user);
        DataStoreProvider.Current.Save(session);

        var pageInfo1 = CreatePageInfo("Page1", permissionsNeeded: "admin", showOnNavBar: true);
        _server.RegisterRoute("GET /page1", new RouteHandlerData(
            pageInfo1,
            async (ctx) => await Task.CompletedTask
        ));

        var context = CreateHttpContextWithSession("GET", "/", session);

        // Act
        await _server.BuildAppInfoMenuOptionsAsync(context);
        var firstCount = _server.MenuOptionsList.Count;

        // Add another route
        var pageInfo2 = CreatePageInfo("Page2", permissionsNeeded: "admin", showOnNavBar: true);
        _server.RegisterRoute("GET /page2", new RouteHandlerData(
            pageInfo2,
            async (ctx) => await Task.CompletedTask
        ));

        await _server.BuildAppInfoMenuOptionsAsync(context);
        var secondCount = _server.MenuOptionsList.Count;

        // Assert
        Assert.True(secondCount > firstCount, "Menu should include new route");
    }

    #endregion

    #region Setup Flow Tests

    [Fact]
    public async Task RequestHandler_NoRootUser_RedirectsToSetup()
    {
        // Arrange
        EnsureStore();
        // Clear users from store to test setup redirect
        ((_testStore as InMemoryDataStore)!).Clear();

        var context = CreateHttpContext("GET", "/home");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(302, context.Response.StatusCode);
        Assert.Equal("/setup", context.Response.Headers.Location.ToString());
    }

    [Fact]
    public async Task RequestHandler_NoRootUser_AllowsSetupPage()
    {
        // Arrange
        EnsureStore();
        // Clear users from store
        ((_testStore as InMemoryDataStore)!).Clear();

        var setupExecuted = false;
        _server.RegisterRoute("GET /setup", new RouteHandlerData(
            CreatePageInfo("Setup"),
            async (ctx) => { setupExecuted = true; await Task.CompletedTask; }
        ));

        var context = CreateHttpContext("GET", "/setup");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.True(setupExecuted, "Setup page should be accessible");
        Assert.NotEqual(302, context.Response.StatusCode);
    }

    [Fact]
    public async Task RequestHandler_NoRootUser_AllowsStaticFiles()
    {
        // Arrange
        EnsureStore();
        // Clear users from store
        ((_testStore as InMemoryDataStore)!).Clear();
        _server.StaticFiles = new StaticFileConfigOptions
        {
            Enabled = true,
            RequestPathPrefix = "/static"
        };

        var context = CreateHttpContext("GET", "/static/css/site.css");

        // Act
        await _server.RequestHandler(context);

        // Assert - Should not redirect to setup (static file handler will attempt to serve)
        Assert.NotEqual(302, context.Response.StatusCode);
    }

    [Fact]
    public async Task RequestHandler_RootUserExists_NoRedirectToSetup()
    {
        // Arrange
        EnsureStore();
        var rootUser = CreateUser("root", new[] { "admin", "monitoring" });
        DataStoreProvider.Current.Save(rootUser);

        _server.RegisterRoute("GET /home", new RouteHandlerData(
            CreatePageInfo("Home"),
            async (ctx) => await Task.CompletedTask
        ));

        var context = CreateHttpContext("GET", "/home");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.NotEqual(302, context.Response.StatusCode);
    }

    #endregion

    #region Security Headers Tests

    [Fact]
    public async Task RequestHandler_AllRequests_IncludeCSP()
    {
        // Arrange
        EnsureStore();
        _server.RegisterRoute("GET /test", new RouteHandlerData(
            CreatePageInfo("Test"),
            async (ctx) => await Task.CompletedTask
        ));

        var context = CreateHttpContext("GET", "/test");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.True(context.Response.Headers.ContainsKey("Content-Security-Policy"));
        var csp = context.Response.Headers["Content-Security-Policy"].ToString();
        Assert.Contains("default-src 'self'", csp);
        Assert.Contains("https://fonts.googleapis.com", csp);
        Assert.Contains("https://fonts.gstatic.com", csp);
        Assert.Contains("nonce-", csp);
        Assert.DoesNotContain("style-src 'self' https://cdn.jsdelivr.net", csp);
        Assert.DoesNotContain("style-src 'self' https://cdnjs.cloudflare.com", csp);
        Assert.Contains("font-src 'self'", csp);
    }

    #endregion

    #region Helper Methods

    private static PageInfo CreatePageInfo(
        string title,
        int statusCode = 200,
        string? permissionsNeeded = null,
        bool showOnNavBar = false)
    {
        var template = new MockHtmlTemplate();
        var metadata = new PageMetaData(
            Template: template,
            StatusCode: statusCode,
            PermissionsNeeded: permissionsNeeded,
            ShowOnNavBar: showOnNavBar
        );

        var pageContext = new PageContext(
            PageMetaDataKeys: new[] { "title" },
            PageMetaDataValues: new[] { title }
        );

        return new PageInfo(metadata, pageContext);
    }

    private static HttpContext CreateHttpContext(string method, string path)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Request.Host = new HostString("localhost");
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static HttpContext CreateHttpContextWithSession(string method, string path, UserSession session)
    {
        var context = CreateHttpContext(method, path);
        var protectedSessionId = CookieProtection.Protect(session.Id);
        context.Request.Headers.Cookie = $"{UserAuth.SessionCookieName}={protectedSessionId}";
        return context;
    }

    private static User CreateUser(string id, string[] permissions)
    {
        return new User
        {
            Id = id,
            UserName = $"user_{id}",
            DisplayName = $"User {id}",
            Email = $"{id}@example.com",
            Permissions = permissions,
            IsActive = true
        };
    }

    private static UserSession CreateSession(User user)
    {
        return new UserSession
        {
            Id = Guid.NewGuid().ToString(),
            UserId = user.Id,
            IssuedUtc = DateTime.UtcNow,
            LastSeenUtc = DateTime.UtcNow,
            ExpiresUtc = DateTime.UtcNow.AddHours(8),
            IsRevoked = false
        };
    }

    private class MockHtmlTemplate : IHtmlTemplate
    {
        public Encoding Encoding => Encoding.UTF8;
        public string ContentTypeHeader => "text/html; charset=utf-8";
        public string Head => "<head><title>Mock</title></head>";
        public string Body => "<body>Mock</body>";
        public string Footer => "<footer>Mock</footer>";
        public string Script => "<script>/* mock */</script>";
    }

    private class MockBufferedLogger : IBufferedLogger
    {
        public List<string> InfoLogs { get; } = new();
        public List<string> ErrorLogs { get; } = new();

        public void LogInfo(string message) => InfoLogs.Add(message);
        public void LogError(string message, Exception? ex = null) =>
            ErrorLogs.Add(ex != null ? $"{message}: {ex.Message}" : message);
        public Task RunAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public void OnApplicationStopping(CancellationTokenSource cts, Task loggerTask) { }
    }

    private class MockHtmlRenderer : IHtmlRenderer
    {
        public ValueTask RenderPage(HttpContext context)
        {
            // Don't overwrite status code if already set
            if (context.Response.StatusCode == 200)
            {
                context.Response.StatusCode = context.GetPageInfo()?.PageMetaData.StatusCode ?? 200;
            }
            return ValueTask.CompletedTask;
        }

        public ValueTask RenderPage(HttpContext context, PageInfo page, IBareWebHost app)
        {
            // Don't overwrite status code if already set
            if (context.Response.StatusCode == 200)
            {
                context.Response.StatusCode = page.PageMetaData.StatusCode;
            }
            return ValueTask.CompletedTask;
        }

        public ValueTask<byte[]> RenderToBytesAsync(
            IHtmlTemplate template,
            string[] keys,
            string[] values,
            string[] appkeys,
            string[] appvalues,
            IBareWebHost app,
            string[]? tableColumnTitles = null,
            string[][]? tableRows = null,
            FormDefinition? formDefinition = null,
            TemplateLoop[]? templateLoops = null)
        {
            return ValueTask.FromResult(Encoding.UTF8.GetBytes("<html><body>Mock</body></html>"));
        }

        public ValueTask RenderToStreamAsync(
            PipeWriter writer,
            IHtmlTemplate template,
            string[] keys,
            string[] values,
            string[] appkeys,
            string[] appvalues,
            IBareWebHost app,
            string[]? tableColumnTitles = null,
            string[][]? tableRows = null,
            FormDefinition? formDefinition = null,
            TemplateLoop[]? templateLoops = null)
        {
            return ValueTask.CompletedTask;
        }
    }

    private class MockMetricsTracker : IMetricsTracker
    {
        public void RecordRequest(int statusCode, TimeSpan duration) { }
        public void RecordThrottled(TimeSpan duration) { }
        public void GetMetricTable(out string[] tableColumns, out string[][] tableRows)
        {
            tableColumns = Array.Empty<string>();
            tableRows = Array.Empty<string[]>();
        }
        public MetricsSnapshot GetSnapshot() => new MetricsSnapshot(
            0, 0, TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero,
            TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero, 0, 0, 0, 0, 0);
    }

    private class MockClientRequestTracker : IClientRequestTracker
    {
        public void RecordRequest(string ipAddress) { }
        public bool ShouldThrottle(string ipAddress, out string reason, out int? retryAfterSeconds)
        {
            reason = string.Empty;
            retryAfterSeconds = null;
            return false;
        }
        public Task RunPruningAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public void GetTopClientsTable(int count, out string[] tableColumns, out string[][] tableRows)
        {
            tableColumns = Array.Empty<string>();
            tableRows = Array.Empty<string[]>();
        }
        public void GetSuspiciousClientsTable(int count, out string[] tableColumns, out string[][] tableRows)
        {
            tableColumns = Array.Empty<string>();
            tableRows = Array.Empty<string[]>();
        }
    }

    private class InMemoryDataStore : IDataObjectStore
    {
        private readonly Dictionary<string, BaseDataObject> _store = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();

        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }

        public void Clear() => _store.Clear();

        public void Save<T>(T obj) where T : BaseDataObject
        {
            _store[obj.Id] = obj;
        }

        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Save(obj);
            return ValueTask.CompletedTask;
        }

        public T? Load<T>(string id) where T : BaseDataObject
        {
            return _store.TryGetValue(id, out var obj) ? obj as T : null;
        }

        public ValueTask<T?> LoadAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            return ValueTask.FromResult(Load<T>(id));
        }

        public IEnumerable<T> Query<T>(QueryDefinition? query = null) where T : BaseDataObject
        {
            var results = _store.Values.OfType<T>();

            if (query?.Clauses == null || query.Clauses.Count == 0)
                return results;

            foreach (var clause in query.Clauses)
            {
                results = results.Where(obj =>
                {
                    var prop = typeof(T).GetProperty(clause.Field);
                    if (prop == null) return false;

                    var value = prop.GetValue(obj);

                    if (clause.Operator == QueryOperator.Contains && value is string[] array)
                    {
                        return array.Contains(clause.Value?.ToString() ?? string.Empty);
                    }

                    return false;
                });
            }

            return results;
        }

        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            return ValueTask.FromResult(Query<T>(query));
        }

        public ValueTask<int> CountAsync<T>(QueryDefinition? query = null, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            return ValueTask.FromResult(Query<T>(query).Count());
        }

        public void Delete<T>(string id) where T : BaseDataObject
        {
            _store.Remove(id);
        }

        public ValueTask DeleteAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Delete<T>(id);
            return ValueTask.CompletedTask;
        }
    }

    #endregion
}
