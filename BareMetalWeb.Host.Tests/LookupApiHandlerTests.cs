using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Data;
using BareMetalWeb.Data.DataObjects;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Tests for LookupApiHandlers endpoint behaviour via the full server pipeline.
/// </summary>
[Collection("CookieProtection")]
public class LookupApiHandlerTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;
    private readonly InMemoryDataStore _testStore;
    private readonly BareMetalWebServer _server;
    private readonly MockBufferedLogger _logger;
    private readonly MockHtmlRenderer _renderer;
    private readonly MockMetricsTracker _metrics;
    private readonly MockClientRequestTracker _clientRequests;
    private readonly CancellationTokenSource _cts;
    private readonly WebApplication _app;
    private readonly string _keyRootDirectory;
    private readonly string _testSessionId;

    public LookupApiHandlerTests()
    {
        _keyRootDirectory = Path.Combine(Path.GetTempPath(), $"bmw-lookup-tests-{Guid.NewGuid()}");
        Directory.CreateDirectory(_keyRootDirectory);
        CookieProtection.ConfigureKeyRoot(_keyRootDirectory);

        _originalStore = DataStoreProvider.Current;
        _testStore = new InMemoryDataStore();
        DataStoreProvider.Current = _testStore;

        // Create a root user with admin permissions to prevent setup redirect
        // and a user session for authenticated lookup requests
        var rootUser = new User
        {
            Id = "root",
            UserName = "admin",
            DisplayName = "Admin",
            Email = "admin@test.com",
            Permissions = new[] { "admin", "monitoring", "Products", "Customers", "Orders" },
            IsActive = true
        };
        _testStore.Save(rootUser);

        var session = new UserSession
        {
            Id = "test-session",
            UserId = rootUser.Id,
            IssuedUtc = DateTime.UtcNow,
            LastSeenUtc = DateTime.UtcNow,
            ExpiresUtc = DateTime.UtcNow.AddHours(8),
            IsRevoked = false
        };
        _testStore.Save(session);
        _testSessionId = session.Id;

        // Force UserClasses assembly to load before scanning
        _ = typeof(Product).Assembly;
        DataEntityRegistry.RegisterAllEntities();

        _logger = new MockBufferedLogger();
        _renderer = new MockHtmlRenderer();
        _metrics = new MockMetricsTracker();
        _clientRequests = new MockClientRequestTracker();
        _cts = new CancellationTokenSource();
        _app = WebApplication.Create();

        var pageInfo = CreatePageInfo("Test");
        _server = new BareMetalWebServer(
            "Test", "Test", "2025", _app, _logger, _renderer,
            pageInfo, pageInfo, _cts, _metrics, _clientRequests
        );

        // Register the lookup API routes in the correct order
        var rawPageInfo = CreatePageInfo("Public", showOnNav: false);
        _server.RegisterRoute("GET /api/_lookup/{type}/_field/{id}/{fieldName}",
            new RouteHandlerData(rawPageInfo, LookupApiHandlers.GetEntityFieldHandler));
        _server.RegisterRoute("GET /api/_lookup/{type}/_aggregate",
            new RouteHandlerData(rawPageInfo, LookupApiHandlers.AggregateEntitiesHandler));
        _server.RegisterRoute("POST /api/_lookup/{type}/_batch",
            new RouteHandlerData(rawPageInfo, LookupApiHandlers.BatchGetEntitiesHandler));
        _server.RegisterRoute("GET /api/_lookup/{type}/{id}",
            new RouteHandlerData(rawPageInfo, LookupApiHandlers.GetEntityByIdHandler));
        _server.RegisterRoute("GET /api/_lookup/{type}",
            new RouteHandlerData(rawPageInfo, LookupApiHandlers.QueryEntitiesHandler));
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
        _cts.Cancel();
        try { Directory.Delete(_keyRootDirectory, true); } catch { }
    }

    [Fact]
    public async Task GetEntityById_ReturnsEntity_WhenExists()
    {
        // Arrange
        var product = new Product { Id = "prod-1", Name = "Widget", Description = "A test widget" };
        _testStore.Save(product);

        var context = CreateHttpContext("GET", "/api/_lookup/products/prod-1");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        Assert.Equal("prod-1", json.GetProperty("id").GetString());
    }

    [Fact]
    public async Task GetEntityById_Returns404_WhenNotExists()
    {
        // Arrange
        var context = CreateHttpContext("GET", "/api/_lookup/products/nonexistent");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task GetEntityById_Returns404_ForUnknownEntityType()
    {
        // Arrange
        var context = CreateHttpContext("GET", "/api/_lookup/nonexistent-type/some-id");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task QueryEntities_ReturnsAllEntities_WhenNoFilter()
    {
        // Arrange
        _testStore.Save(new Product { Id = "prod-1", Name = "Widget" });
        _testStore.Save(new Product { Id = "prod-2", Name = "Gadget" });

        var context = CreateHttpContext("GET", "/api/_lookup/products");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        Assert.True(json.GetProperty("count").GetInt32() >= 2);
    }

    [Fact]
    public async Task GetEntityField_ReturnsFieldValue_WhenExists()
    {
        // Arrange
        var product = new Product { Id = "prod-1", Name = "Widget" };
        _testStore.Save(product);

        var context = CreateHttpContext("GET", "/api/_lookup/products/_field/prod-1/Name");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        Assert.Equal("Name", json.GetProperty("field").GetString());
        Assert.Equal("Widget", json.GetProperty("value").GetString());
    }

    [Fact]
    public async Task GetEntityField_Returns404_WhenEntityNotFound()
    {
        // Arrange
        var context = CreateHttpContext("GET", "/api/_lookup/products/_field/nonexistent/Name");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task GetEntityField_Returns404_WhenFieldNotFound()
    {
        // Arrange
        _testStore.Save(new Product { Id = "prod-1", Name = "Widget" });
        var context = CreateHttpContext("GET", "/api/_lookup/products/_field/prod-1/NonExistentField");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task AggregateEntities_Count_ReturnsCorrectCount()
    {
        // Arrange
        _testStore.Save(new Product { Id = "prod-1", Name = "Widget" });
        _testStore.Save(new Product { Id = "prod-2", Name = "Gadget" });

        var context = CreateHttpContext("GET", "/api/_lookup/products/_aggregate?fn=count");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        Assert.Equal("count", json.GetProperty("function").GetString());
        Assert.True(json.GetProperty("result").GetInt32() >= 2);
    }

    [Fact]
    public async Task AggregateEntities_Returns400_WhenNoFunction()
    {
        // Arrange
        var context = CreateHttpContext("GET", "/api/_lookup/products/_aggregate");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(400, context.Response.StatusCode);
    }

    [Fact]
    public async Task AggregateEntities_Returns400_ForUnsupportedFunction()
    {
        // Arrange
        var context = CreateHttpContext("GET", "/api/_lookup/products/_aggregate?fn=median");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(400, context.Response.StatusCode);
    }

    [Fact]
    public async Task BatchGetEntities_ReturnsMatchedEntities_WhenAllExist()
    {
        // Arrange
        _testStore.Save(new Product { Id = "prod-1", Name = "Widget" });
        _testStore.Save(new Product { Id = "prod-2", Name = "Gadget" });

        var context = CreatePostHttpContext("/api/_lookup/products/_batch", new { ids = new[] { "prod-1", "prod-2" } });

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        var results = json.GetProperty("results");
        Assert.Equal("Widget", results.GetProperty("prod-1").GetProperty("Name").GetString());
        Assert.Equal("Gadget", results.GetProperty("prod-2").GetProperty("Name").GetString());
    }

    [Fact]
    public async Task BatchGetEntities_OmitsMissingEntities_WhenSomeNotFound()
    {
        // Arrange
        _testStore.Save(new Product { Id = "prod-1", Name = "Widget" });

        var context = CreatePostHttpContext("/api/_lookup/products/_batch", new { ids = new[] { "prod-1", "nonexistent" } });

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        var results = json.GetProperty("results");
        Assert.True(results.TryGetProperty("prod-1", out _));
        Assert.False(results.TryGetProperty("nonexistent", out _));
    }

    [Fact]
    public async Task BatchGetEntities_ReturnsEmptyResults_WhenIdsArrayIsEmpty()
    {
        // Arrange
        var context = CreatePostHttpContext("/api/_lookup/products/_batch", new { ids = Array.Empty<string>() });

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        Assert.Equal(JsonValueKind.Object, json.GetProperty("results").ValueKind);
    }

    [Fact]
    public async Task BatchGetEntities_Returns400_WhenBodyMissingIdsProperty()
    {
        // Arrange
        var context = CreatePostHttpContext("/api/_lookup/products/_batch", new { something = "else" });

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(400, context.Response.StatusCode);
    }

    [Fact]
    public async Task BatchGetEntities_Returns404_ForUnknownEntityType()
    {
        // Arrange
        var context = CreatePostHttpContext("/api/_lookup/nonexistent-type/_batch", new { ids = new[] { "id-1" } });

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task BatchGetEntities_DeduplicatesIds_WhenDuplicatesPassed()
    {
        // Arrange
        _testStore.Save(new Product { Id = "prod-1", Name = "Widget" });

        var context = CreatePostHttpContext("/api/_lookup/products/_batch", new { ids = new[] { "prod-1", "prod-1", "prod-1" } });

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        var results = json.GetProperty("results");
        Assert.True(results.TryGetProperty("prod-1", out _));
    }

    #region Helpers

    private HttpContext CreateHttpContext(string method, string pathAndQuery)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;

        var uri = new Uri("http://localhost" + pathAndQuery);
        context.Request.Path = uri.AbsolutePath;
        context.Request.QueryString = new QueryString(uri.Query);
        context.Request.Host = new HostString("localhost");
        context.Response.Body = new MemoryStream();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Loopback;

        // Add session cookie for authenticated requests
        var protectedSessionId = CookieProtection.Protect(_testSessionId);
        context.Request.Headers.Cookie = $"{UserAuth.SessionCookieName}={protectedSessionId}";
        return context;
    }

    private HttpContext CreatePostHttpContext(string path, object body)
    {
        var context = CreateHttpContext("POST", path);
        var json = JsonSerializer.SerializeToUtf8Bytes(body);
        context.Request.Body = new MemoryStream(json);
        context.Request.ContentType = "application/json";
        context.Request.ContentLength = json.Length;
        return context;
    }

    private static async Task<JsonElement> ReadResponseJson(HttpContext context)
    {
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var doc = await JsonDocument.ParseAsync(context.Response.Body);
        return doc.RootElement.Clone();
    }

    private static PageInfo CreatePageInfo(string title, bool showOnNav = false)
    {
        var template = new MockHtmlTemplate();
        var meta = new PageMetaData(template, 200, "", showOnNav);
        return new PageInfo(meta, new PageContext(
            new string[0], new string[0]
        ));
    }

    private class MockHtmlTemplate : IHtmlTemplate
    {
        public Encoding Encoding => Encoding.UTF8;
        public string ContentTypeHeader => "text/html; charset=utf-8";
        public string Head => "";
        public string Body => "";
        public string Footer => "";
        public string Script => "";
    }

    private class MockBufferedLogger : IBufferedLogger
    {
        public void LogInfo(string message) { }
        public void LogError(string message, Exception? ex = null) { }
        public Task RunAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public void OnApplicationStopping(CancellationTokenSource cts, Task loggerTask) { }
    }

    private class MockHtmlRenderer : IHtmlRenderer
    {
        public ValueTask RenderPage(HttpContext context) => ValueTask.CompletedTask;
        public ValueTask RenderPage(HttpContext context, PageInfo page, IBareWebHost app) => ValueTask.CompletedTask;
        public ValueTask<byte[]> RenderToBytesAsync(IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null) => ValueTask.FromResult(Array.Empty<byte>());
        public ValueTask RenderToStreamAsync(System.IO.Pipelines.PipeWriter writer, IHtmlTemplate template, string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null, string[][]? tableRows = null, FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null) => ValueTask.CompletedTask;
    }

    private class MockMetricsTracker : IMetricsTracker
    {
        public void RecordRequest(int statusCode, TimeSpan elapsed) { }
        public void RecordThrottled(TimeSpan elapsed) { }
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

        public void Save<T>(T obj) where T : BaseDataObject
        {
            _store[typeof(T).Name + ":" + obj.Id] = obj;
        }

        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Save(obj);
            return ValueTask.CompletedTask;
        }

        public T? Load<T>(string id) where T : BaseDataObject
        {
            return _store.TryGetValue(typeof(T).Name + ":" + id, out var obj) ? obj as T : null;
        }

        public ValueTask<T?> LoadAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            return ValueTask.FromResult(Load<T>(id));
        }

        public void Delete<T>(string id) where T : BaseDataObject
        {
            _store.Remove(typeof(T).Name + ":" + id);
        }

        public ValueTask DeleteAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Delete<T>(id);
            return ValueTask.CompletedTask;
        }

        public IEnumerable<T> Query<T>(QueryDefinition? query) where T : BaseDataObject
        {
            return _store.Values.OfType<T>();
        }

        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            return ValueTask.FromResult(Query<T>(query));
        }

        public int Count<T>(QueryDefinition? query) where T : BaseDataObject
        {
            return Query<T>(query).Count();
        }

        public ValueTask<int> CountAsync<T>(QueryDefinition? query, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            return ValueTask.FromResult(Count<T>(query));
        }

        public IEnumerable<BaseDataObject> QueryByType(Type type, QueryDefinition? query)
        {
            return _store.Values.Where(v => v.GetType() == type);
        }

        public ValueTask<IEnumerable<BaseDataObject>> QueryByTypeAsync(Type type, QueryDefinition? query, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(QueryByType(type, query));
        }

        public int CountByType(Type type, QueryDefinition? query)
        {
            return QueryByType(type, query).Count();
        }

        public ValueTask<int> CountByTypeAsync(Type type, QueryDefinition? query, CancellationToken cancellationToken = default)
        {
            return ValueTask.FromResult(CountByType(type, query));
        }
    }

    #endregion
}
