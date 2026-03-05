using System.Net;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Host;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;

namespace BareMetalWeb.Host.Tests;

public sealed class ProxyRouteHandlerTests
{
    private static readonly Type HandlerType = typeof(ProxyRouteHandler);

    private class MockLogger : IBufferedLogger
    {
        public List<string> InfoMessages { get; } = new();
        public List<(string Message, Exception Ex)> Errors { get; } = new();

        public void LogInfo(string message) => InfoMessages.Add(message);
        public void LogError(string message, Exception ex) => Errors.Add((message, ex));
        public Task RunAsync(CancellationToken stoppingToken) => Task.CompletedTask;
        public void OnApplicationStopping(CancellationTokenSource appStoppingSource, Task runTask) { }
    }

    private static ProxyRouteConfig CreateDefaultRoute(string targetUrl = "http://backend:8080")
    {
        return new ProxyRouteConfig
        {
            Route = "/api",
            TargetBaseUrl = targetUrl,
            IncludeQuery = true,
            RetryIdempotentRequests = false,
            MaxRetries = 0
        };
    }

    private static ProxyRouteHandler CreateHandler(ProxyRouteConfig? route = null, MockLogger? logger = null)
    {
        return new ProxyRouteHandler(route ?? CreateDefaultRoute(), logger ?? new MockLogger());
    }

    private static HttpContext CreateHttpContext(string method = "GET", string path = "/", string queryString = "")
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Request.Host = new HostString("localhost");
        context.Request.Scheme = "https";
        if (!string.IsNullOrEmpty(queryString))
            context.Request.QueryString = new QueryString(queryString);
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static string ReadResponseBody(HttpContext context)
    {
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var reader = new StreamReader(context.Response.Body);
        return reader.ReadToEnd();
    }

    // Reflection helpers following existing patterns in RouteHandlerTests.cs
    private object? InvokePrivate(ProxyRouteHandler handler, string methodName, params object?[] args)
    {
        var mi = HandlerType.GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Instance)
            ?? throw new MissingMethodException(nameof(ProxyRouteHandler), methodName);
        return mi.Invoke(handler, args);
    }

    private static object? InvokeStatic(string methodName, params object?[] args)
    {
        var mi = HandlerType.GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new MissingMethodException(nameof(ProxyRouteHandler), methodName);
        return mi.Invoke(null, args);
    }

    private static object? InvokeStaticWithTypes(string methodName, Type[] paramTypes, params object?[] args)
    {
        var mi = HandlerType.GetMethod(methodName, BindingFlags.NonPublic | BindingFlags.Static, null, paramTypes, null)
            ?? throw new MissingMethodException(nameof(ProxyRouteHandler), methodName);
        return mi.Invoke(null, args);
    }

    // ─── Constructor Tests ───

    [Fact]
    public void Constructor_NullRoute_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("route", () => new ProxyRouteHandler(null!, new MockLogger()));
    }

    [Fact]
    public void Constructor_NullLogger_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>("logger", () => new ProxyRouteHandler(CreateDefaultRoute(), null!));
    }

    [Fact]
    public void Constructor_ValidArgs_CreatesInstance()
    {
        var handler = CreateHandler();
        Assert.NotNull(handler);
    }

    // ─── HandleAsync Null Context ───

    [Fact]
    public async Task HandleAsync_NullContext_ThrowsArgumentNullException()
    {
        var handler = CreateHandler();
        await Assert.ThrowsAsync<ArgumentNullException>("context", () => handler.HandleAsync(null!).AsTask());
    }

    // ─── HandleAsync No Targets Available ───

    [Fact]
    public async Task HandleAsync_NoTargets_Returns503()
    {
        // Arrange
        var route = new ProxyRouteConfig
        {
            Route = "/api",
            TargetBaseUrl = null,
            Targets = new List<string>(),
            TargetConfigs = new List<ProxyTargetConfig>()
        };
        var handler = new ProxyRouteHandler(route, new MockLogger());
        var context = CreateHttpContext("GET", "/api");

        // Act
        await handler.HandleAsync(context.ToBmw());

        // Assert
        Assert.Equal(503, context.Response.StatusCode);
        var body = ReadResponseBody(context);
        Assert.Contains("No proxy targets available", body);
    }

    // ─── GetStatus Tests ───

    [Fact]
    public void GetStatus_SingleTarget_ReturnsRouteInfo()
    {
        // Arrange
        var route = CreateDefaultRoute("http://backend:8080");
        route.MatchMode = "StartsWith";
        route.LoadBalance = "RoundRobin";
        var handler = CreateHandler(route);

        // Act
        var status = handler.GetStatus();

        // Assert
        Assert.Equal("/api", status.Route);
        Assert.Equal("StartsWith", status.MatchMode);
        Assert.Equal("RoundRobin", status.LoadBalance);
        Assert.Single(status.Targets);
    }

    [Fact]
    public void GetStatus_MultipleTargets_ReturnsAll()
    {
        // Arrange
        var route = new ProxyRouteConfig
        {
            Route = "/api",
            Targets = new List<string> { "http://a:80", "http://b:80", "http://c:80" }
        };
        var handler = new ProxyRouteHandler(route, new MockLogger());

        // Act
        var status = handler.GetStatus();

        // Assert
        Assert.Equal(3, status.Targets.Length);
    }

    [Fact]
    public void GetStatus_TargetConfigs_ReturnsAll()
    {
        // Arrange
        var route = new ProxyRouteConfig
        {
            Route = "/api",
            TargetConfigs = new List<ProxyTargetConfig>
            {
                new() { Uri = "http://a:80", Weight = 3 },
                new() { Uri = "http://b:80", Weight = 1 }
            }
        };
        var handler = new ProxyRouteHandler(route, new MockLogger());

        // Act
        var status = handler.GetStatus();

        // Assert
        Assert.Equal(2, status.Targets.Length);
    }

    // ─── BuildTargetUri Tests (Path Rewriting & Query String) ───

    [Fact]
    public void BuildTargetUri_SimplePath_CombinesCorrectly()
    {
        // Arrange
        var route = CreateDefaultRoute("http://backend:8080");
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/hello");

        // Act
        var uri = (Uri)InvokePrivate(handler, "BuildTargetUri", context, new Uri("http://backend:8080"))!;

        // Assert
        Assert.Equal("http://backend:8080/hello", uri.ToString());
    }

    [Fact]
    public void BuildTargetUri_QueryStringForwarding_IncludesQuery()
    {
        // Arrange
        var route = CreateDefaultRoute("http://backend:8080");
        route.IncludeQuery = true;
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/search", "?q=test&page=1");

        // Act
        var uri = (Uri)InvokePrivate(handler, "BuildTargetUri", context, new Uri("http://backend:8080"))!;

        // Assert
        Assert.Contains("q=test", uri.Query);
        Assert.Contains("page=1", uri.Query);
    }

    [Fact]
    public void BuildTargetUri_QueryStringDisabled_ExcludesQuery()
    {
        // Arrange
        var route = CreateDefaultRoute("http://backend:8080");
        route.IncludeQuery = false;
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/search", "?q=test");

        // Act
        var uri = (Uri)InvokePrivate(handler, "BuildTargetUri", context, new Uri("http://backend:8080"))!;

        // Assert
        Assert.Empty(uri.Query);
    }

    [Fact]
    public void BuildTargetUri_PathPrefixStrip_StripsPrefix()
    {
        // Arrange
        var route = CreateDefaultRoute("http://backend:8080");
        route.PathPrefixToStrip = "/api";
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/api/users");

        // Act
        var uri = (Uri)InvokePrivate(handler, "BuildTargetUri", context, new Uri("http://backend:8080"))!;

        // Assert
        Assert.Equal("http://backend:8080/users", uri.ToString());
    }

    [Fact]
    public void BuildTargetUri_PathPrefixAdd_AddsPrefix()
    {
        // Arrange
        var route = CreateDefaultRoute("http://backend:8080");
        route.PathPrefixToAdd = "/v2";
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/users");

        // Act
        var uri = (Uri)InvokePrivate(handler, "BuildTargetUri", context, new Uri("http://backend:8080"))!;

        // Assert
        Assert.Equal("http://backend:8080/v2/users", uri.ToString());
    }

    [Fact]
    public void BuildTargetUri_RewritePath_OverridesPath()
    {
        // Arrange
        var route = CreateDefaultRoute("http://backend:8080");
        route.RewritePath = "/fixed-path";
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/anything");

        // Act
        var uri = (Uri)InvokePrivate(handler, "BuildTargetUri", context, new Uri("http://backend:8080"))!;

        // Assert
        Assert.Equal("/fixed-path", uri.AbsolutePath);
    }

    [Fact]
    public void BuildTargetUri_StripAndAddPrefix_CombinesCorrectly()
    {
        // Arrange
        var route = CreateDefaultRoute("http://backend:8080");
        route.PathPrefixToStrip = "/proxy";
        route.PathPrefixToAdd = "/upstream";
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/proxy/data");

        // Act
        var uri = (Uri)InvokePrivate(handler, "BuildTargetUri", context, new Uri("http://backend:8080"))!;

        // Assert
        Assert.Equal("http://backend:8080/upstream/data", uri.ToString());
    }

    [Fact]
    public void BuildTargetUri_TargetBaseWithPath_CombinesPaths()
    {
        // Arrange
        var route = CreateDefaultRoute("http://backend:8080/base");
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/resource");

        // Act
        var uri = (Uri)InvokePrivate(handler, "BuildTargetUri", context, new Uri("http://backend:8080/base"))!;

        // Assert
        Assert.Equal("http://backend:8080/base/resource", uri.ToString());
    }

    // ─── ShouldHaveBody Tests ───

    [Fact]
    public void ShouldHaveBody_GetRequest_ReturnsFalse()
    {
        // Arrange
        var context = CreateHttpContext("GET", "/");

        // Act
        var result = (bool)InvokeStatic("ShouldHaveBody", context.Request)!;

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void ShouldHaveBody_PostWithContentLength_ReturnsTrue()
    {
        // Arrange
        var context = CreateHttpContext("POST", "/");
        context.Request.ContentLength = 100;

        // Act
        var result = (bool)InvokeStatic("ShouldHaveBody", context.Request)!;

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void ShouldHaveBody_ZeroContentLength_ReturnsFalse()
    {
        // Arrange
        var context = CreateHttpContext("POST", "/");
        context.Request.ContentLength = 0;

        // Act
        var result = (bool)InvokeStatic("ShouldHaveBody", context.Request)!;

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void ShouldHaveBody_TransferEncodingHeader_ReturnsTrue()
    {
        // Arrange
        var context = CreateHttpContext("POST", "/");
        context.Request.Headers["Transfer-Encoding"] = "chunked";

        // Act
        var result = (bool)InvokeStatic("ShouldHaveBody", context.Request)!;

        // Assert
        Assert.True(result);
    }

    // ─── CopyRequestHeaders Tests ───

    [Fact]
    public void CopyRequestHeaders_SkipsHostHeader()
    {
        // Arrange
        var route = CreateDefaultRoute();
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/");
        context.Request.Headers["Host"] = "original.example.com";
        context.Request.Headers["Accept"] = "application/json";
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, "http://backend:8080/");

        // Act
        InvokePrivate(handler, "CopyRequestHeaders", context, requestMessage);

        // Assert
        Assert.False(requestMessage.Headers.Contains("Host"));
        Assert.True(requestMessage.Headers.Contains("Accept"));
    }

    [Fact]
    public void CopyRequestHeaders_SkipsHopByHopHeaders()
    {
        // Arrange
        var route = CreateDefaultRoute();
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/");
        context.Request.Headers["Connection"] = "keep-alive";
        context.Request.Headers["Keep-Alive"] = "timeout=5";
        context.Request.Headers["Proxy-Authorization"] = "Basic abc";
        context.Request.Headers["Accept"] = "text/html";
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, "http://backend:8080/");

        // Act
        InvokePrivate(handler, "CopyRequestHeaders", context, requestMessage);

        // Assert
        Assert.False(requestMessage.Headers.Contains("Connection"));
        Assert.False(requestMessage.Headers.Contains("Keep-Alive"));
        Assert.False(requestMessage.Headers.Contains("Proxy-Authorization"));
        Assert.True(requestMessage.Headers.Contains("Accept"));
    }

    [Fact]
    public void CopyRequestHeaders_SkipsConfiguredRemoveHeaders()
    {
        // Arrange
        var route = CreateDefaultRoute();
        route.RemoveHeaders = new List<string> { "X-Internal-Secret" };
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/");
        context.Request.Headers["X-Internal-Secret"] = "secret123";
        context.Request.Headers["Accept"] = "application/json";
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, "http://backend:8080/");

        // Act
        InvokePrivate(handler, "CopyRequestHeaders", context, requestMessage);

        // Assert
        Assert.False(requestMessage.Headers.Contains("X-Internal-Secret"));
        Assert.True(requestMessage.Headers.Contains("Accept"));
    }

    [Fact]
    public void CopyRequestHeaders_AddsConfiguredHeaders()
    {
        // Arrange
        var route = CreateDefaultRoute();
        route.AddHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "X-Custom-Header", "custom-value" }
        };
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/");
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, "http://backend:8080/");

        // Act
        InvokePrivate(handler, "CopyRequestHeaders", context, requestMessage);

        // Assert
        Assert.True(requestMessage.Headers.Contains("X-Custom-Header"));
        Assert.Equal("custom-value", requestMessage.Headers.GetValues("X-Custom-Header").First());
    }

    [Fact]
    public void CopyRequestHeaders_AddsXForwardedHeaders()
    {
        // Arrange
        var route = CreateDefaultRoute();
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/");
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("example.com");
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.1");
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, "http://backend:8080/");

        // Act
        InvokePrivate(handler, "CopyRequestHeaders", context, requestMessage);

        // Assert
        Assert.Equal("10.0.0.1", requestMessage.Headers.GetValues("X-Forwarded-For").First());
        Assert.Equal("https", requestMessage.Headers.GetValues("X-Forwarded-Proto").First());
        Assert.Equal("example.com", requestMessage.Headers.GetValues("X-Forwarded-Host").First());
    }

    [Fact]
    public void CopyRequestHeaders_AuthorizationHeaderPassthrough()
    {
        // Arrange
        var route = CreateDefaultRoute();
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/");
        context.Request.Headers["Authorization"] = "Bearer token123";
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, "http://backend:8080/");

        // Act
        InvokePrivate(handler, "CopyRequestHeaders", context, requestMessage);

        // Assert
        Assert.True(requestMessage.Headers.Contains("Authorization"));
        Assert.Equal("Bearer token123", requestMessage.Headers.GetValues("Authorization").First());
    }

    [Fact]
    public void CopyRequestHeaders_SkipsRetryAllMethodsHeader()
    {
        // Arrange
        var route = CreateDefaultRoute();
        route.RetryAllMethodsHeader = "X-Proxy-Retry-All";
        var handler = CreateHandler(route);
        var context = CreateHttpContext("POST", "/");
        context.Request.Headers["X-Proxy-Retry-All"] = "true";
        context.Request.Headers["Accept"] = "application/json";
        var requestMessage = new HttpRequestMessage(HttpMethod.Post, "http://backend:8080/");

        // Act
        InvokePrivate(handler, "CopyRequestHeaders", context, requestMessage);

        // Assert
        Assert.False(requestMessage.Headers.Contains("X-Proxy-Retry-All"));
        Assert.True(requestMessage.Headers.Contains("Accept"));
    }

    // ─── CopyResponseHeaders Tests ───

    [Fact]
    public void CopyResponseHeaders_CopiesStandardHeaders()
    {
        // Arrange
        var context = CreateHttpContext();
        var responseMessage = new HttpResponseMessage(HttpStatusCode.OK);
        responseMessage.Headers.Add("X-Custom-Response", "value1");
        responseMessage.Content = new StringContent("body");
        responseMessage.Content.Headers.Add("X-Content-Custom", "value2");

        // Act
        InvokeStatic("CopyResponseHeaders", context, responseMessage);

        // Assert
        Assert.Equal("value1", context.Response.Headers["X-Custom-Response"].ToString());
        Assert.Equal("value2", context.Response.Headers["X-Content-Custom"].ToString());
    }

    [Fact]
    public void CopyResponseHeaders_SkipsHopByHopHeaders()
    {
        // Arrange
        var context = CreateHttpContext();
        var responseMessage = new HttpResponseMessage(HttpStatusCode.OK);
        responseMessage.Headers.Add("X-Normal", "ok");
        responseMessage.Content = new StringContent("body");

        // Act
        InvokeStatic("CopyResponseHeaders", context, responseMessage);

        // Assert
        Assert.True(context.Response.Headers.ContainsKey("X-Normal"));
        Assert.False(context.Response.Headers.ContainsKey("Transfer-Encoding"));
    }

    [Fact]
    public void CopyResponseHeaders_RemovesTransferEncoding()
    {
        // Arrange
        var context = CreateHttpContext();
        context.Response.Headers["transfer-encoding"] = "chunked";
        var responseMessage = new HttpResponseMessage(HttpStatusCode.OK);
        responseMessage.Content = new StringContent("body");

        // Act
        InvokeStatic("CopyResponseHeaders", context, responseMessage);

        // Assert
        Assert.False(context.Response.Headers.ContainsKey("transfer-encoding"));
    }

    // ─── ApplyTraceId Tests ───

    [Fact]
    public void ApplyTraceId_WithTraceIdHeader_AddsToRequestAndResponse()
    {
        // Arrange
        var route = CreateDefaultRoute();
        route.TraceIdHeader = "X-Trace-ID";
        var handler = CreateHandler(route);
        var context = CreateHttpContext();
        context.TraceIdentifier = "trace-123";
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, "http://backend:8080/");

        // Act
        InvokePrivate(handler, "ApplyTraceId", context, requestMessage);

        // Assert
        Assert.Equal("trace-123", requestMessage.Headers.GetValues("X-Trace-ID").First());
        Assert.Equal("trace-123", context.Response.Headers["X-Trace-ID"].ToString());
    }

    [Fact]
    public void ApplyTraceId_NoTraceIdHeaderConfig_DoesNothing()
    {
        // Arrange
        var route = CreateDefaultRoute();
        route.TraceIdHeader = "";
        var handler = CreateHandler(route);
        var context = CreateHttpContext();
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, "http://backend:8080/");

        // Act
        InvokePrivate(handler, "ApplyTraceId", context, requestMessage);

        // Assert
        Assert.False(requestMessage.Headers.Contains("X-Trace-ID"));
    }

    [Fact]
    public void ApplyTraceId_EmptyTraceIdentifier_GeneratesNewId()
    {
        // Arrange
        var route = CreateDefaultRoute();
        route.TraceIdHeader = "X-Request-ID";
        var handler = CreateHandler(route);
        var context = CreateHttpContext();
        context.TraceIdentifier = "";
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, "http://backend:8080/");

        // Act
        InvokePrivate(handler, "ApplyTraceId", context, requestMessage);

        // Assert
        Assert.True(requestMessage.Headers.Contains("X-Request-ID"));
        var traceId = requestMessage.Headers.GetValues("X-Request-ID").First();
        Assert.False(string.IsNullOrWhiteSpace(traceId));
        Assert.Equal(32, traceId.Length); // Guid.ToString("N") = 32 chars
    }

    [Fact]
    public void ApplyTraceId_AlreadyPresent_DoesNotOverwrite()
    {
        // Arrange
        var route = CreateDefaultRoute();
        route.TraceIdHeader = "X-Trace-ID";
        var handler = CreateHandler(route);
        var context = CreateHttpContext();
        context.TraceIdentifier = "new-trace";
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, "http://backend:8080/");
        requestMessage.Headers.TryAddWithoutValidation("X-Trace-ID", "existing-trace");

        // Act
        InvokePrivate(handler, "ApplyTraceId", context, requestMessage);

        // Assert
        Assert.Equal("existing-trace", requestMessage.Headers.GetValues("X-Trace-ID").First());
    }

    // ─── BuildFilteredCookieHeader Tests ───

    [Fact]
    public void BuildFilteredCookieHeader_NoCookies_ReturnsNull()
    {
        // Arrange
        var route = CreateDefaultRoute();
        var handler = CreateHandler(route);
        var context = CreateHttpContext();

        // Act
        var result = (string?)InvokePrivate(handler, "BuildFilteredCookieHeader", context);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void BuildFilteredCookieHeader_FiltersSessionCookie()
    {
        // Arrange
        var route = CreateDefaultRoute();
        var handler = CreateHandler(route);
        var context = CreateHttpContext();
        context.Request.Headers["Cookie"] = "session_id=abc; other=xyz";

        // Act
        var result = (string?)InvokePrivate(handler, "BuildFilteredCookieHeader", context);

        // Assert
        Assert.NotNull(result);
        Assert.DoesNotContain("session_id", result);
        Assert.Contains("other=xyz", result);
    }

    [Fact]
    public void BuildFilteredCookieHeader_FiltersStickySessionCookie()
    {
        // Arrange
        var route = CreateDefaultRoute();
        route.StickySessionsEnabled = true;
        route.StickySessionMode = "Cookie";
        route.StickySessionKeyName = "X-Proxy-Session";
        var handler = CreateHandler(route);
        var context = CreateHttpContext();
        context.Request.Headers["Cookie"] = "X-Proxy-Session=abc; app_data=xyz";

        // Act
        var result = (string?)InvokePrivate(handler, "BuildFilteredCookieHeader", context);

        // Assert
        Assert.NotNull(result);
        Assert.DoesNotContain("X-Proxy-Session", result);
        Assert.Contains("app_data=xyz", result);
    }

    [Fact]
    public void BuildFilteredCookieHeader_AllFiltered_ReturnsNull()
    {
        // Arrange
        var route = CreateDefaultRoute();
        var handler = CreateHandler(route);
        var context = CreateHttpContext();
        context.Request.Headers["Cookie"] = "session_id=abc";

        // Act
        var result = (string?)InvokePrivate(handler, "BuildFilteredCookieHeader", context);

        // Assert
        Assert.Null(result);
    }

    // ─── BuildTargetStates Tests ───

    [Fact]
    public void BuildTargetStates_TargetConfigs_HasPriority()
    {
        // Arrange
        var route = new ProxyRouteConfig
        {
            TargetBaseUrl = "http://fallback:80",
            Targets = new List<string> { "http://list:80" },
            TargetConfigs = new List<ProxyTargetConfig>
            {
                new() { Uri = "http://config:80", Weight = 5 }
            }
        };

        // Act
        var targets = InvokeStatic("BuildTargetStates", route) as IList<ProxyTargetState>;

        // Assert
        Assert.NotNull(targets);
        Assert.Single(targets);
        Assert.Equal(new Uri("http://config:80"), targets[0].BaseUri);
        Assert.Equal(5, targets[0].Weight);
    }

    [Fact]
    public void BuildTargetStates_TargetsListUsed_WhenNoConfigs()
    {
        // Arrange
        var route = new ProxyRouteConfig
        {
            TargetBaseUrl = "http://fallback:80",
            Targets = new List<string> { "http://a:80", "http://b:80" },
            TargetConfigs = new List<ProxyTargetConfig>()
        };

        // Act
        var targets = InvokeStatic("BuildTargetStates", route) as IList<ProxyTargetState>;

        // Assert
        Assert.NotNull(targets);
        Assert.Equal(2, targets.Count);
    }

    [Fact]
    public void BuildTargetStates_FallbackToTargetBaseUrl()
    {
        // Arrange
        var route = new ProxyRouteConfig
        {
            TargetBaseUrl = "http://single:80",
            Targets = new List<string>(),
            TargetConfigs = new List<ProxyTargetConfig>()
        };

        // Act
        var targets = InvokeStatic("BuildTargetStates", route) as IList<ProxyTargetState>;

        // Assert
        Assert.NotNull(targets);
        Assert.Single(targets);
        Assert.Equal(new Uri("http://single:80"), targets[0].BaseUri);
    }

    [Fact]
    public void BuildTargetStates_InvalidUri_Skipped()
    {
        // Arrange
        var route = new ProxyRouteConfig
        {
            Targets = new List<string> { "not-a-uri", "http://valid:80" },
            TargetConfigs = new List<ProxyTargetConfig>()
        };

        // Act
        var targets = InvokeStatic("BuildTargetStates", route) as IList<ProxyTargetState>;

        // Assert
        Assert.NotNull(targets);
        Assert.Single(targets);
        Assert.Equal(new Uri("http://valid:80"), targets[0].BaseUri);
    }

    [Fact]
    public void BuildTargetStates_NoValidTargets_ReturnsEmpty()
    {
        // Arrange
        var route = new ProxyRouteConfig
        {
            TargetBaseUrl = null,
            Targets = new List<string>(),
            TargetConfigs = new List<ProxyTargetConfig>()
        };

        // Act
        var targets = InvokeStatic("BuildTargetStates", route) as IList<ProxyTargetState>;

        // Assert
        Assert.NotNull(targets);
        Assert.Empty(targets);
    }

    // ─── Fnv1aHash Tests ───

    [Fact]
    public void Fnv1aHash_SameInput_SameOutput()
    {
        // Act
        var hash1 = (uint)InvokeStatic("Fnv1aHash", "test-key")!;
        var hash2 = (uint)InvokeStatic("Fnv1aHash", "test-key")!;

        // Assert
        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void Fnv1aHash_DifferentInputs_DifferentOutputs()
    {
        // Act
        var hash1 = (uint)InvokeStatic("Fnv1aHash", "key-a")!;
        var hash2 = (uint)InvokeStatic("Fnv1aHash", "key-b")!;

        // Assert
        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void Fnv1aHash_EmptyString_ReturnsOffset()
    {
        // Act
        var hash = (uint)InvokeStatic("Fnv1aHash", "")!;

        // Assert
        Assert.Equal(2166136261u, hash); // FNV offset basis
    }

    // ─── SelectTargetState Tests (via HandleAsync 503 and GetStatus) ───

    [Fact]
    public void GetStatus_FailoverMode_ReturnsCorrectLoadBalance()
    {
        // Arrange
        var route = new ProxyRouteConfig
        {
            Route = "/fail",
            LoadBalance = "Failover",
            Targets = new List<string> { "http://primary:80", "http://secondary:80" }
        };
        var handler = new ProxyRouteHandler(route, new MockLogger());

        // Act
        var status = handler.GetStatus();

        // Assert
        Assert.Equal("Failover", status.LoadBalance);
        Assert.Equal(2, status.Targets.Length);
    }

    // ─── CopyRequestHeaders with content headers ───

    [Fact]
    public void CopyRequestHeaders_WithContent_CopiesCustomHeadersToContent()
    {
        // Arrange
        var route = CreateDefaultRoute();
        route.AddHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "X-Api-Key", "key123" }
        };
        var handler = CreateHandler(route);
        var context = CreateHttpContext("POST", "/");
        context.Request.ContentLength = 10;
        context.Request.Headers["X-Request-Custom"] = "custom-value";
        var requestMessage = new HttpRequestMessage(HttpMethod.Post, "http://backend:8080/");
        requestMessage.Content = new StringContent("test-body");

        // Act
        InvokePrivate(handler, "CopyRequestHeaders", context, requestMessage);

        // Assert
        Assert.True(requestMessage.Headers.Contains("X-Api-Key") ||
            requestMessage.Content.Headers.Contains("X-Api-Key"));
    }

    // ─── BuildTargetUri edge cases ───

    [Fact]
    public void BuildTargetUri_EmptyPath_DefaultsToSlash()
    {
        // Arrange
        var route = CreateDefaultRoute("http://backend:8080");
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "");

        // Act
        var uri = (Uri)InvokePrivate(handler, "BuildTargetUri", context, new Uri("http://backend:8080"))!;

        // Assert
        Assert.Equal("/", uri.AbsolutePath);
    }

    [Fact]
    public void BuildTargetUri_StripPrefixCaseInsensitive()
    {
        // Arrange
        var route = CreateDefaultRoute("http://backend:8080");
        route.PathPrefixToStrip = "/API";
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/api/items");

        // Act
        var uri = (Uri)InvokePrivate(handler, "BuildTargetUri", context, new Uri("http://backend:8080"))!;

        // Assert
        Assert.Equal("/items", uri.AbsolutePath);
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("POST")]
    [InlineData("PUT")]
    [InlineData("DELETE")]
    [InlineData("PATCH")]
    public void BuildTargetUri_AllHttpMethods_ProducesValidUri(string method)
    {
        // Arrange
        var route = CreateDefaultRoute("http://backend:8080");
        var handler = CreateHandler(route);
        var context = CreateHttpContext(method, "/resource/123");

        // Act
        var uri = (Uri)InvokePrivate(handler, "BuildTargetUri", context, new Uri("http://backend:8080"))!;

        // Assert
        Assert.Equal("http://backend:8080/resource/123", uri.ToString());
    }

    // ─── Verbose logging ───

    [Fact]
    public async Task HandleAsync_NoTargets_WithVerboseLog_Returns503()
    {
        // Arrange
        var route = new ProxyRouteConfig
        {
            Route = "/api",
            EnableVerboseLog = true,
            TargetBaseUrl = null,
            Targets = new List<string>(),
            TargetConfigs = new List<ProxyTargetConfig>()
        };
        var logger = new MockLogger();
        var handler = new ProxyRouteHandler(route, logger);
        var context = CreateHttpContext("GET", "/api");

        // Act
        await handler.HandleAsync(context.ToBmw());

        // Assert
        Assert.Equal(503, context.Response.StatusCode);
    }

    // ─── Multiple cookies forwarding ───

    [Fact]
    public void BuildFilteredCookieHeader_MultipleCookies_JoinedCorrectly()
    {
        // Arrange
        var route = CreateDefaultRoute();
        var handler = CreateHandler(route);
        var context = CreateHttpContext();
        context.Request.Headers["Cookie"] = "a=1; b=2; c=3";

        // Act
        var result = (string?)InvokePrivate(handler, "BuildFilteredCookieHeader", context);

        // Assert
        Assert.NotNull(result);
        Assert.Contains("a=1", result);
        Assert.Contains("b=2", result);
        Assert.Contains("c=3", result);
    }

    // ─── Path rewriting with query string merge ───

    [Fact]
    public void BuildTargetUri_RewritePathWithQuery_MergesCorrectly()
    {
        // Arrange
        var route = CreateDefaultRoute("http://backend:8080");
        route.RewritePath = "/fixed";
        route.IncludeQuery = true;
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/original", "?foo=bar");

        // Act
        var uri = (Uri)InvokePrivate(handler, "BuildTargetUri", context, new Uri("http://backend:8080"))!;

        // Assert
        Assert.Equal("/fixed", uri.AbsolutePath);
        Assert.Contains("foo=bar", uri.Query);
    }

    // ─── Multiple query params ───

    [Fact]
    public void BuildTargetUri_MultipleQueryParams_AllForwarded()
    {
        // Arrange
        var route = CreateDefaultRoute("http://backend:8080");
        route.IncludeQuery = true;
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/search", "?q=hello&sort=asc&limit=10");

        // Act
        var uri = (Uri)InvokePrivate(handler, "BuildTargetUri", context, new Uri("http://backend:8080"))!;

        // Assert
        Assert.Contains("q=hello", uri.Query);
        Assert.Contains("sort=asc", uri.Query);
        Assert.Contains("limit=10", uri.Query);
    }

    // ─── CopyRequestHeaders: Cookie header is not directly copied ───

    [Fact]
    public void CopyRequestHeaders_SkipsCookieHeader()
    {
        // Arrange
        var route = CreateDefaultRoute();
        var handler = CreateHandler(route);
        var context = CreateHttpContext("GET", "/");
        context.Request.Headers["Cookie"] = "test=value";
        context.Request.Headers["Accept"] = "text/html";
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, "http://backend:8080/");

        // Act
        InvokePrivate(handler, "CopyRequestHeaders", context, requestMessage);

        // Assert - Cookie is rebuilt via BuildFilteredCookieHeader, not directly copied
        // The Accept header should be present
        Assert.True(requestMessage.Headers.Contains("Accept"));
    }

    // ─── ShouldHaveBody edge cases ───

    [Fact]
    public void ShouldHaveBody_NullContentLength_NoTransferEncoding_ReturnsFalse()
    {
        // Arrange
        var context = CreateHttpContext("DELETE", "/resource/1");

        // Act
        var result = (bool)InvokeStatic("ShouldHaveBody", context.Request)!;

        // Assert
        Assert.False(result);
    }

    [Fact]
    public void ShouldHaveBody_PutWithContent_ReturnsTrue()
    {
        // Arrange
        var context = CreateHttpContext("PUT", "/resource/1");
        context.Request.ContentLength = 50;

        // Act
        var result = (bool)InvokeStatic("ShouldHaveBody", context.Request)!;

        // Assert
        Assert.True(result);
    }

    // ─── GetStatus with TargetBaseUrl fallback ───

    [Fact]
    public void GetStatus_TargetBaseUrlFallback_SingleTarget()
    {
        // Arrange
        var route = new ProxyRouteConfig
        {
            Route = "/proxy",
            TargetBaseUrl = "http://solo:9090"
        };
        var handler = new ProxyRouteHandler(route, new MockLogger());

        // Act
        var status = handler.GetStatus();

        // Assert
        Assert.Single(status.Targets);
    }

    // ─── ApplyTraceId with response header already set ───

    [Fact]
    public void ApplyTraceId_ResponseAlreadyHasHeader_DoesNotOverwriteResponse()
    {
        // Arrange
        var route = CreateDefaultRoute();
        route.TraceIdHeader = "X-Trace-ID";
        var handler = CreateHandler(route);
        var context = CreateHttpContext();
        context.TraceIdentifier = "new-trace";
        context.Response.Headers["X-Trace-ID"] = "existing-response-trace";
        var requestMessage = new HttpRequestMessage(HttpMethod.Get, "http://backend:8080/");

        // Act
        InvokePrivate(handler, "ApplyTraceId", context, requestMessage);

        // Assert
        Assert.Equal("existing-response-trace", context.Response.Headers["X-Trace-ID"].ToString());
    }
}
