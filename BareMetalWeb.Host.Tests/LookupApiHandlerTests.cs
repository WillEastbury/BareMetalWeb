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
[Collection("SharedState")]
public class LookupApiHandlerTests : IDisposable
{
    [DataEntity("Products", Slug = "products")]
    private class Product : BaseDataObject
    {
        [DataField(Label = "Name", Order = 1)] public string Name { get; set; } = "";
        [DataField(Label = "Description", Order = 2)] public string Description { get; set; } = "";
        [DataField(Label = "Sku", Order = 3)] public string Sku { get; set; } = "";
    }

    [DataEntity("Customers", Slug = "customers")]
    private class Customer : BaseDataObject
    {
        [DataField(Label = "Name", Order = 1)] public string Name { get; set; } = "";
        [DataField(Label = "Email", Order = 2)] public string Email { get; set; } = "";
    }

    [DataEntity("Orders", Slug = "orders")]
    private class Order : BaseDataObject
    {
        [DataField(Label = "Order Number", Order = 1)] public string OrderNumber { get; set; } = "";
        [DataField(Label = "Customer", Order = 2)]
        [DataLookup(typeof(Customer))]
        public string CustomerId { get; set; } = "";
        [DataField(Label = "Status", Order = 3)] public string Status { get; set; } = "";
    }

    private readonly IDataObjectStore _originalStore;
    private readonly InMemoryDataStore _testStore;
    private readonly BareMetalWebServer _server;
    private readonly MockBufferedLogger _logger;
    private readonly MockHtmlRenderer _renderer;
    private readonly MockMetricsTracker _metrics;
    private readonly MockClientRequestTracker _clientRequests;
    private readonly CancellationTokenSource _cts;
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
            Key = 1,
            UserName = "admin",
            DisplayName = "Admin",
            Email = "admin@test.com",
            Permissions = new[] { "admin", "monitoring", "Products", "Customers", "Orders" },
            IsActive = true
        };
        _testStore.Save(rootUser);

        var session = new UserSession
        {
            Key = 100,
            UserId = rootUser.Key.ToString(),
            IssuedUtc = DateTime.UtcNow,
            LastSeenUtc = DateTime.UtcNow,
            ExpiresUtc = DateTime.UtcNow.AddHours(8),
            IsRevoked = false
        };
        _testStore.Save(session);
        _testSessionId = session.Key.ToString();

        // Register entity types used by lookup tests
        DataScaffold.RegisterEntity<Product>();
        DataScaffold.RegisterEntity<Customer>();
        DataScaffold.RegisterEntity<Order>();
        DataScaffold.RegisterEntity<User>();

        _logger = new MockBufferedLogger();
        _renderer = new MockHtmlRenderer();
        _metrics = new MockMetricsTracker();
        _clientRequests = new MockClientRequestTracker();
        _cts = new CancellationTokenSource();

        var pageInfo = CreatePageInfo("Test");
        _server = new BareMetalWebServer(
            "Test", "Test", "2025", BmwConfig.Load("/tmp"), "/tmp", _logger, _renderer,
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
        var product = new Product { Key = 1, Name = "Widget", Description = "A test widget" };
        _testStore.Save(product);

        var context = CreateHttpContext("GET", "/api/_lookup/products/1");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        Assert.Equal("1", json.GetProperty("id").GetString());
    }

    [Fact]
    public async Task GetEntityById_Returns404_WhenNotExists()
    {
        // Arrange
        var context = CreateHttpContext("GET", "/api/_lookup/products/999");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task GetEntityById_Returns404_ForUnknownEntityType()
    {
        // Arrange
        var context = CreateHttpContext("GET", "/api/_lookup/nonexistent-type/1");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task QueryEntities_ReturnsAllEntities_WhenNoFilter()
    {
        // Arrange
        _testStore.Save(new Product { Key = 1, Name = "Widget" });
        _testStore.Save(new Product { Key = 2, Name = "Gadget" });

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
        var product = new Product { Key = 1, Name = "Widget" };
        _testStore.Save(product);

        var context = CreateHttpContext("GET", "/api/_lookup/products/_field/1/Name");

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
        var context = CreateHttpContext("GET", "/api/_lookup/products/_field/999/Name");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task GetEntityField_Returns404_WhenFieldNotFound()
    {
        // Arrange
        _testStore.Save(new Product { Key = 1, Name = "Widget" });
        var context = CreateHttpContext("GET", "/api/_lookup/products/_field/1/NonExistentField");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task AggregateEntities_Count_ReturnsCorrectCount()
    {
        // Arrange
        _testStore.Save(new Product { Key = 1, Name = "Widget" });
        _testStore.Save(new Product { Key = 2, Name = "Gadget" });

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
        _testStore.Save(new Product { Key = 1, Name = "Widget" });
        _testStore.Save(new Product { Key = 2, Name = "Gadget" });

        var context = CreatePostHttpContext("/api/_lookup/products/_batch", new { ids = new[] { "1", "2" } });

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        var results = json.GetProperty("results");
        Assert.Equal("Widget", results.GetProperty("1").GetProperty("Name").GetString());
        Assert.Equal("Gadget", results.GetProperty("2").GetProperty("Name").GetString());
    }

    [Fact]
    public async Task BatchGetEntities_OmitsMissingEntities_WhenSomeNotFound()
    {
        // Arrange
        _testStore.Save(new Product { Key = 1, Name = "Widget" });

        var context = CreatePostHttpContext("/api/_lookup/products/_batch", new { ids = new[] { "1", "999" } });

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        var results = json.GetProperty("results");
        Assert.True(results.TryGetProperty("1", out _));
        Assert.False(results.TryGetProperty("999", out _));
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
        var context = CreatePostHttpContext("/api/_lookup/nonexistent-type/_batch", new { ids = new[] { "1" } });

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task BatchGetEntities_DeduplicatesIds_WhenDuplicatesPassed()
    {
        // Arrange
        _testStore.Save(new Product { Key = 1, Name = "Widget" });

        var context = CreatePostHttpContext("/api/_lookup/products/_batch", new { ids = new[] { "1", "1", "1" } });

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        var results = json.GetProperty("results");
        Assert.True(results.TryGetProperty("1", out _));
    }

    [Fact]
    public async Task QueryEntities_IgnoresFilter_WhenFieldNotInViewableMetadata()
    {
        // Arrange — two products, filter on a field that does not exist in metadata
        _testStore.Save(new Product { Key = 1, Name = "Widget" });
        _testStore.Save(new Product { Key = 2, Name = "Gadget" });

        // ?filter=NonExistentField:value should be silently dropped, so all entities are returned
        var context = CreateHttpContext("GET", "/api/_lookup/products?filter=NonExistentField:Widget");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        // Invalid field filter is dropped; all entities (>= 2) are returned
        Assert.True(json.GetProperty("count").GetInt32() >= 2);
    }

    [Fact]
    public async Task QueryEntities_IgnoresSort_WhenFieldNotInViewableMetadata()
    {
        // Arrange
        _testStore.Save(new Product { Key = 1, Name = "Widget" });

        // ?sort=HiddenField should be silently dropped
        var context = CreateHttpContext("GET", "/api/_lookup/products?sort=HiddenField&dir=asc");

        // Act
        await _server.RequestHandler(context);

        // Assert — request succeeds; no error from invalid sort field
        Assert.Equal(200, context.Response.StatusCode);
    }

    [Fact]
    public async Task QueryEntities_IgnoresSearchField_WhenFieldNotInViewableMetadata()
    {
        // Arrange
        _testStore.Save(new Product { Key = 1, Name = "Widget" });

        // ?searchField=PasswordHash is a field that doesn't exist on Product — should be dropped
        var context = CreateHttpContext("GET", "/api/_lookup/products?search=abc&searchField=PasswordHash");

        // Act
        await _server.RequestHandler(context);

        // Assert — request still succeeds (search clause is silently dropped, no results match nothing)
        Assert.Equal(200, context.Response.StatusCode);
    }

    [Fact]
    public async Task GetEntityField_Returns404_WhenFieldIsNotViewable()
    {
        // Arrange — Product entity has no non-viewable fields by default;
        // use a non-existent field to confirm the check applies
        _testStore.Save(new Product { Key = 1, Name = "Widget" });

        var context = CreateHttpContext("GET", "/api/_lookup/products/_field/1/InternalSecretField");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task QueryEntities_Returns403_WhenFromAndViaProvided_AndRelationshipDoesNotExist()
    {
        // Arrange — 'orders' entity has CustomerId lookup to 'customers', but NOT to 'products'
        _testStore.Save(new Product { Key = 1, Name = "Widget" });

        // from=orders&via=CustomerId but target is 'products' — no such relationship
        var context = CreateHttpContext("GET", "/api/_lookup/products?from=orders&via=CustomerId");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(403, context.Response.StatusCode);
    }

    [Fact]
    public async Task QueryEntities_Returns403_WhenOnlyFromProvided_WithoutVia()
    {
        // Arrange
        _testStore.Save(new Product { Key = 1, Name = "Widget" });

        // Providing 'from' without 'via' should fail validation (incomplete relationship context)
        var context = CreateHttpContext("GET", "/api/_lookup/products?from=orders");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(403, context.Response.StatusCode);
    }

    [Fact]
    public async Task QueryEntities_Returns200_WhenFromAndViaProvided_AndRelationshipExists()
    {
        // Arrange — orders.CustomerId has a lookup to customers, so this should succeed
        var customer = new Customer { Key = 100, Name = "Acme Corp" };
        _testStore.Save(customer);

        // from=orders&via=CustomerId with target 'customers' — valid relationship
        var context = CreateHttpContext("GET", "/api/_lookup/customers?from=orders&via=CustomerId");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        Assert.True(json.GetProperty("count").GetInt32() >= 1);
    }

    

    [Fact]
    public async Task GetEntityById_WithTraverseRelationships_ExpandsLookupField()
    {
        // Arrange — Order.CustomerId is a lookup to Customer
        var customer = new Customer { Key = 100, Name = "Acme Corp", Email = "acme@example.com" };
        _testStore.Save(customer);

        var order = new Order { Key = 101, OrderNumber = "ORD-001", CustomerId = "100", Status = "Open" };
        _testStore.Save(order);

        var context = CreateHttpContext("GET", "/api/_lookup/orders/101?traverseRelationships=true");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);

        // Original FK field is still present
        Assert.Equal("100", json.GetProperty("CustomerId").GetString());

        // Expanded object added under "Customer" (Id suffix stripped)
        Assert.True(json.TryGetProperty("Customer", out var expanded), "Expected expanded 'Customer' property");
        Assert.Equal("100", expanded.GetProperty("id").GetString());
        Assert.Equal("Acme Corp", expanded.GetProperty("Name").GetString());
    }

    [Fact]
    public async Task GetEntityById_WithoutTraverseRelationships_DoesNotExpandLookupField()
    {
        // Arrange
        var customer = new Customer { Key = 200, Name = "Beta Corp", Email = "beta@example.com" };
        _testStore.Save(customer);

        var order = new Order { Key = 201, OrderNumber = "ORD-002", CustomerId = "200", Status = "Open" };
        _testStore.Save(order);

        var context = CreateHttpContext("GET", "/api/_lookup/orders/201");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);

        // FK field present but NO expanded key
        Assert.Equal("200", json.GetProperty("CustomerId").GetString());
        Assert.False(json.TryGetProperty("Customer", out _), "Should not have expanded 'Customer' without traverseRelationships=true");
    }

    [Fact]
    public async Task QueryEntities_WithTraverseRelationships_ExpandsLookupFields()
    {
        // Arrange
        var customer = new Customer { Key = 300, Name = "Gamma Ltd", Email = "gamma@example.com" };
        _testStore.Save(customer);

        var order = new Order { Key = 301, OrderNumber = "ORD-003", CustomerId = "300", Status = "Open" };
        _testStore.Save(order);

        var context = CreateHttpContext("GET", "/api/_lookup/orders?traverseRelationships=true&filter=OrderNumber:ORD-003");

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);

        var data = json.GetProperty("data");
        var first = data.EnumerateArray().First(e => e.GetProperty("OrderNumber").GetString() == "ORD-003");

        Assert.Equal("300", first.GetProperty("CustomerId").GetString());
        Assert.True(first.TryGetProperty("Customer", out var expanded), "Expected expanded 'Customer' property in query result");
        Assert.Equal("Gamma Ltd", expanded.GetProperty("Name").GetString());
    }

    [Fact]
    public async Task BatchGetEntities_WithTraverseRelationships_ExpandsLookupFields()
    {
        // Arrange
        var customer = new Customer { Key = 400, Name = "Delta Inc", Email = "delta@example.com" };
        _testStore.Save(customer);

        var order = new Order { Key = 401, OrderNumber = "ORD-004", CustomerId = "400", Status = "Open" };
        _testStore.Save(order);

        var context = CreatePostHttpContext("/api/_lookup/orders/_batch?traverseRelationships=true", new { ids = new[] { "401" } });

        // Act
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        var result = json.GetProperty("results").GetProperty("401");

        Assert.Equal("400", result.GetProperty("CustomerId").GetString());
        Assert.True(result.TryGetProperty("Customer", out var expanded), "Expected expanded 'Customer' property in batch result");
        Assert.Equal("Delta Inc", expanded.GetProperty("Name").GetString());
    }

    [Fact]
    public async Task GetEntityById_WithTraverseRelationships_ToleratesMissingRelatedEntity()
    {
        // Arrange — order references a customer that doesn't exist in the store
        var order = new Order { Key = 501, OrderNumber = "ORD-005", CustomerId = "999", Status = "Open" };
        _testStore.Save(order);

        var context = CreateHttpContext("GET", "/api/_lookup/orders/501?traverseRelationships=true");

        // Act — should not throw; missing related entity is silently skipped
        await _server.RequestHandler(context);

        // Assert
        Assert.Equal(200, context.Response.StatusCode);
        var json = await ReadResponseJson(context);
        Assert.Equal("999", json.GetProperty("CustomerId").GetString());
        Assert.False(json.TryGetProperty("Customer", out _), "No expanded key should be added when related entity is missing");
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
            TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero, 0, 0, 0, 0, 0, 0, 0, 0, TimeSpan.Zero);
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
        private readonly Dictionary<(Type, uint), BaseDataObject> _store = new();

        public IReadOnlyList<IDataProvider> Providers => Array.Empty<IDataProvider>();

        public void RegisterProvider(IDataProvider provider, bool prepend = false) { }
        public void RegisterFallbackProvider(IDataProvider provider) { }
        public void ClearProviders() { }

        public void Save<T>(T obj) where T : BaseDataObject
        {
            _store[(typeof(T), obj.Key)] = obj;
        }

        public ValueTask SaveAsync<T>(T obj, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Save(obj);
            return ValueTask.CompletedTask;
        }

        public T? Load<T>(uint key) where T : BaseDataObject
        {
            return _store.TryGetValue((typeof(T), key), out var obj) ? obj as T : null;
        }

        public ValueTask<T?> LoadAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            return ValueTask.FromResult(Load<T>(key));
        }

        public void Delete<T>(uint key) where T : BaseDataObject
        {
            _store.Remove((typeof(T), key));
        }

        public ValueTask DeleteAsync<T>(uint key, CancellationToken cancellationToken = default) where T : BaseDataObject
        {
            Delete<T>(key);
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
