using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core.Interfaces;
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
/// Tests for DataApiListHandler — verifies that the endpoint returns the
/// paginated envelope format <c>{ "items": [...], "total": N }</c> so that
/// VNext clients can implement correct multi-page navigation.
/// </summary>
[Collection("CookieProtection")]
public class DataApiListHandlerTests : IDisposable
{
    private readonly IDataObjectStore _originalStore;
    private readonly PaginatingInMemoryDataStore _testStore;
    private readonly BareMetalWebServer _server;
    private readonly string _keyRootDirectory;
    private readonly string _testSessionId;
    private readonly CancellationTokenSource _cts;
    private readonly WebApplication _app;

    public DataApiListHandlerTests()
    {
        _keyRootDirectory = Path.Combine(Path.GetTempPath(), $"bmw-dali-tests-{Guid.NewGuid()}");
        Directory.CreateDirectory(_keyRootDirectory);
        CookieProtection.ConfigureKeyRoot(_keyRootDirectory);

        _originalStore = DataStoreProvider.Current;
        _testStore = new PaginatingInMemoryDataStore();
        DataStoreProvider.Current = _testStore;

        var rootUser = new User
        {
            Id = "root",
            UserName = "admin",
            Email = "admin@test.com",
            Permissions = new[] { "admin", "Products" },
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

        _ = typeof(Product).Assembly;
        DataEntityRegistry.RegisterAllEntities();

        _cts = new CancellationTokenSource();
        _app = WebApplication.Create();

        var pageInfo = CreatePageInfo("Test");
        var rawPageInfo = CreatePageInfo("Public", showOnNav: false);
        _server = new BareMetalWebServer(
            "Test", "Test", "2025", _app, new MockBufferedLogger(),
            new MockHtmlRenderer(), pageInfo, pageInfo, _cts,
            new MockMetricsTracker(), new MockClientRequestTracker()
        );

        var handlers = new RouteHandlers(
            new MockHtmlRenderer(),
            new MockTemplateStore(),
            allowAccountCreation: true,
            mfaKeyRootFolder: _keyRootDirectory,
            auditService: new AuditService(_testStore));

        _server.RegisterRoute("GET /api/{type}", new RouteHandlerData(rawPageInfo, handlers.DataApiListHandler));
    }

    public void Dispose()
    {
        DataStoreProvider.Current = _originalStore;
        _cts.Cancel();
        try { Directory.Delete(_keyRootDirectory, true); } catch { }
    }

    [Fact]
    public async Task DataApiListHandler_ReturnsItemsAndTotalEnvelope()
    {
        // Arrange — add three products
        _testStore.Save(new Product { Id = "p1", Name = "Alpha" });
        _testStore.Save(new Product { Id = "p2", Name = "Beta" });
        _testStore.Save(new Product { Id = "p3", Name = "Gamma" });

        var context = CreateHttpContext("GET", "/api/products");

        // Act
        await _server.RequestHandler(context);

        // Assert — response is { "items": [...], "total": 3 }, not a plain array
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJsonAsync(context);
        Assert.Equal(JsonValueKind.Object, json.ValueKind);
        Assert.True(json.TryGetProperty("items", out var items), "Response should have 'items' property");
        Assert.True(json.TryGetProperty("total", out var total), "Response should have 'total' property");
        Assert.Equal(JsonValueKind.Array, items.ValueKind);
        Assert.Equal(3, total.GetInt32());
    }

    [Fact]
    public async Task DataApiListHandler_WithSkipAndTop_ItemsArePaginatedButTotalIsFullCount()
    {
        // Arrange — add 5 products
        for (var i = 1; i <= 5; i++)
            _testStore.Save(new Product { Id = $"prod-{i}", Name = $"Product {i}" });

        // Request page 2: skip=3, top=2
        var context = CreateHttpContext("GET", "/api/products?skip=3&top=2");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJsonAsync(context);
        Assert.Equal(JsonValueKind.Object, json.ValueKind);

        var total = json.GetProperty("total").GetInt32();
        var items = json.GetProperty("items");

        // total must reflect the FULL count (5), not just the items on this page (2)
        Assert.Equal(5, total);
        // items must respect the skip/top pagination
        Assert.Equal(2, items.GetArrayLength());
    }

    [Fact]
    public async Task DataApiListHandler_EmptyStore_ReturnsZeroTotalAndEmptyItems()
    {
        // Arrange — no products
        var context = CreateHttpContext("GET", "/api/products");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJsonAsync(context);
        Assert.Equal(0, json.GetProperty("total").GetInt32());
        Assert.Equal(0, json.GetProperty("items").GetArrayLength());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

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
        var protectedSessionId = CookieProtection.Protect(_testSessionId);
        context.Request.Headers.Cookie = $"{UserAuth.SessionCookieName}={protectedSessionId}";
        return context;
    }

    private static async Task<JsonElement> ReadResponseJsonAsync(HttpContext context)
    {
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var doc = await JsonDocument.ParseAsync(context.Response.Body);
        return doc.RootElement.Clone();
    }

    private static PageInfo CreatePageInfo(string title, bool showOnNav = false)
    {
        var meta = new PageMetaData(new MockHtmlTemplate(), 200, "", showOnNav);
        return new PageInfo(meta, new PageContext(Array.Empty<string>(), Array.Empty<string>()));
    }

    // ── In-memory store that respects Skip/Top for Query but not for Count ────

    /// <summary>
    /// An in-memory data store that applies Skip/Top in QueryAsync (simulating the real
    /// provider) but ignores them in CountAsync (returning the true total count).
    /// This lets us test that DataApiListHandler sends the correct total even when
    /// the items list is paginated.
    /// </summary>
    private sealed class PaginatingInMemoryDataStore : IDataObjectStore
    {
        private readonly Dictionary<string, BaseDataObject> _store = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();
        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }

        public void Save<T>(T obj) where T : BaseDataObject
            => _store[typeof(T).Name + ":" + obj.Id] = obj;

        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
        { Save(obj); return ValueTask.CompletedTask; }

        public T? Load<T>(string id) where T : BaseDataObject
            => _store.TryGetValue(typeof(T).Name + ":" + id, out var obj) ? obj as T : null;

        public ValueTask<T?> LoadAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Load<T>(id));

        public void Delete<T>(string id) where T : BaseDataObject
            => _store.Remove(typeof(T).Name + ":" + id);

        public ValueTask DeleteAsync<T>(string id, CancellationToken cancellationToken = default) where T : BaseDataObject
        { Delete<T>(id); return ValueTask.CompletedTask; }

        private IEnumerable<T> QueryAll<T>() where T : BaseDataObject
            => _store.Values.OfType<T>();

        public IEnumerable<T> Query<T>(QueryDefinition? query) where T : BaseDataObject
        {
            IEnumerable<T> all = QueryAll<T>();
            if (query?.Skip is > 0)
                all = all.Skip(query.Skip.Value);
            if (query?.Top is > 0)
                all = all.Take(query.Top.Value);
            return all;
        }

        public ValueTask<IEnumerable<T>> QueryAsync<T>(QueryDefinition? query, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(Query<T>(query));

        // Count always returns the true total — no Skip/Top applied
        public ValueTask<int> CountAsync<T>(QueryDefinition? query, CancellationToken cancellationToken = default) where T : BaseDataObject
            => ValueTask.FromResult(QueryAll<T>().Count());
    }

    // ── Mocks ─────────────────────────────────────────────────────────────────

    private sealed class MockTemplateStore : ITemplateStore
    {
        public IHtmlTemplate Get(string name) => new MockHtmlTemplate();
        public void ReloadAll() { }
    }

    private sealed class MockHtmlTemplate : IHtmlTemplate
    {
        public Encoding Encoding => Encoding.UTF8;
        public string ContentTypeHeader => "text/html; charset=utf-8";
        public string Head => "";
        public string Body => "";
        public string Footer => "";
        public string Script => "";
    }

    private sealed class MockBufferedLogger : IBufferedLogger
    {
        public void LogInfo(string message) { }
        public void LogError(string message, Exception? ex = null) { }
        public Task RunAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public void OnApplicationStopping(CancellationTokenSource cts, Task loggerTask) { }
    }

    private sealed class MockHtmlRenderer : IHtmlRenderer
    {
        public ValueTask RenderPage(HttpContext context) => ValueTask.CompletedTask;
        public ValueTask RenderPage(HttpContext context, PageInfo page, IBareWebHost app) => ValueTask.CompletedTask;
        public ValueTask<byte[]> RenderToBytesAsync(IHtmlTemplate template, string[] keys, string[] values,
            string[] appkeys, string[] appvalues, IBareWebHost app, string[]? tableColumnTitles = null,
            string[][]? tableRows = null, FormDefinition? formDefinition = null,
            TemplateLoop[]? templateLoops = null) => ValueTask.FromResult(Array.Empty<byte>());
        public ValueTask RenderToStreamAsync(System.IO.Pipelines.PipeWriter writer, IHtmlTemplate template,
            string[] keys, string[] values, string[] appkeys, string[] appvalues, IBareWebHost app,
            string[]? tableColumnTitles = null, string[][]? tableRows = null,
            FormDefinition? formDefinition = null, TemplateLoop[]? templateLoops = null) => ValueTask.CompletedTask;
    }

    private sealed class MockMetricsTracker : IMetricsTracker
    {
        public void RecordRequest(int statusCode, TimeSpan elapsed) { }
        public void RecordThrottled(TimeSpan elapsed) { }
        public void GetMetricTable(out string[] tableColumns, out string[][] tableRows)
        { tableColumns = Array.Empty<string>(); tableRows = Array.Empty<string[]>(); }
        public MetricsSnapshot GetSnapshot() => new(0, 0, TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero,
            TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero, 0, 0, 0, 0, 0);
    }

    private sealed class MockClientRequestTracker : IClientRequestTracker
    {
        public void RecordRequest(string ipAddress) { }
        public bool ShouldThrottle(string ipAddress, out string reason, out int? retryAfterSeconds)
        { reason = string.Empty; retryAfterSeconds = null; return false; }
        public Task RunPruningAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public void GetTopClientsTable(int count, out string[] tableColumns, out string[][] tableRows)
        { tableColumns = Array.Empty<string>(); tableRows = Array.Empty<string[]>(); }
        public void GetSuspiciousClientsTable(int count, out string[] tableColumns, out string[][] tableRows)
        { tableColumns = Array.Empty<string>(); tableRows = Array.Empty<string[]>(); }
    }
}
