using System.Text.Json;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Tests for BmwProtocolDescriptor — protocol descriptor generation,
/// opcode computation, SDK name generation, and JSON serialization.
/// </summary>
public class BmwProtocolDescriptorTests
{
    private static Dictionary<string, RouteHandlerData> BuildTestRoutes()
    {
        ushort nextId = 1;
        var routes = new Dictionary<string, RouteHandlerData>(StringComparer.Ordinal);
        void Add(string key)
        {
            var data = new RouteHandlerData(null, _ => ValueTask.CompletedTask);
            data.RouteId = nextId++;
            data.RouteKey = key;
            routes[key] = data;
        }

        Add("GET /api/orders");
        Add("POST /api/orders");
        Add("GET /api/orders/{id}");
        Add("PUT /api/orders/{id}");
        Add("DELETE /api/orders/{id}");
        Add("GET /api/users");
        Add("GET /api/users/{id}");
        Add("GET /login");
        return routes;
    }

    private static Dictionary<string, CompiledRoute> CompileRoutes(Dictionary<string, RouteHandlerData> routes)
    {
        var compiled = new Dictionary<string, CompiledRoute>(StringComparer.Ordinal);
        foreach (var kvp in routes)
            compiled[kvp.Key] = new CompiledRoute(kvp.Key);
        return compiled;
    }

    [Fact]
    public void Build_CreatesDescriptorFromRoutes()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        Assert.NotEmpty(desc.Routes);
        Assert.True(desc.Routes.Count >= 7); // 7 API routes + 1 login
    }

    [Fact]
    public void Opcodes_AreDeterministic()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        // GET /api/orders: method=0 (GET), routeOrdinal=1 → opcode = (0<<11)|1 = 1
        var listOrders = desc.RoutesByName["listOrders"];
        Assert.Equal(0, listOrders.MethodOrdinal); // GET
        Assert.Equal((0 << 11) | listOrders.RouteOrdinal, listOrders.Opcode);

        // POST /api/orders: method=3 (POST), routeOrdinal=2 → opcode = (3<<11)|2 = 6146
        var createOrders = desc.RoutesByName["createOrders"];
        Assert.Equal(3, createOrders.MethodOrdinal); // POST
        Assert.Equal((3 << 11) | createOrders.RouteOrdinal, createOrders.Opcode);
    }

    [Fact]
    public void OpcodeComputation_MatchesBinaryTransport()
    {
        // Verify opcode = (method << RouteBits) | route matches BmwBinaryTransport constants
        Assert.Equal(11, BmwBinaryTransport.RouteBits);
        int opcode = (BmwBinaryTransport.MethodPost << BmwBinaryTransport.RouteBits) | 42;
        Assert.Equal((3 << 11) | 42, opcode);
        Assert.Equal(6186, opcode);
    }

    [Fact]
    public void EntityGrouping_GroupsBySlug()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        Assert.True(desc.Entities.ContainsKey("orders"));
        Assert.True(desc.Entities.ContainsKey("users"));
        Assert.Equal(5, desc.Entities["orders"].Opcodes.Length); // GET,POST,GET/{id},PUT/{id},DELETE/{id}
        Assert.Equal(2, desc.Entities["users"].Opcodes.Length);  // GET,GET/{id}
    }

    [Fact]
    public void ParameterNames_ExtractedFromPath()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        var getOrder = desc.RoutesByName["getOrders"];
        Assert.Contains("id", getOrder.ParameterNames);
    }

    [Fact]
    public void HasPayload_TrueForWriteMethods()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        Assert.False(desc.RoutesByName["listOrders"].HasPayload);  // GET
        Assert.True(desc.RoutesByName["createOrders"].HasPayload); // POST
        Assert.True(desc.RoutesByName["updateOrders"].HasPayload); // PUT
        Assert.False(desc.RoutesByName["deleteOrders"].HasPayload); // DELETE
    }

    [Fact]
    public void ToJson_ProducesValidJson()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        string json = desc.ToJson();
        // Should parse without error
        var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal("BMW1.0", root.GetProperty("protocol").GetString());
        Assert.Equal(6, root.GetProperty("transport").GetProperty("frameSize").GetInt32());
        Assert.True(root.GetProperty("routes").GetArrayLength() > 0);
        Assert.True(root.GetProperty("entities").EnumerateObject().Any());
        Assert.True(root.GetProperty("stats").GetProperty("totalRoutes").GetInt32() > 0);
    }

    [Fact]
    public void ToJson_TransportSection_MatchesConstants()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        var doc = JsonDocument.Parse(desc.ToJson());
        var transport = doc.RootElement.GetProperty("transport");

        Assert.Equal(BmwBinaryTransport.FrameSize, transport.GetProperty("frameSize").GetInt32());
        Assert.Equal(BmwBinaryTransport.MethodBits, transport.GetProperty("methodBits").GetInt32());
        Assert.Equal(BmwBinaryTransport.RouteBits, transport.GetProperty("routeBits").GetInt32());
        Assert.Equal(BmwBinaryTransport.MaxRoutes, transport.GetProperty("maxRoutes").GetInt32());
        Assert.Equal(BmwBinaryTransport.PayloadLengthSize, transport.GetProperty("payloadLengthBytes").GetInt32());
    }

    [Fact]
    public void ToJson_RouteDescriptor_HasExpectedFields()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        var doc = JsonDocument.Parse(desc.ToJson());
        var firstRoute = doc.RootElement.GetProperty("routes")[0];

        Assert.True(firstRoute.TryGetProperty("name", out _));
        Assert.True(firstRoute.TryGetProperty("opcode", out _));
        Assert.True(firstRoute.TryGetProperty("method", out _));
        Assert.True(firstRoute.TryGetProperty("methodOrdinal", out _));
        Assert.True(firstRoute.TryGetProperty("routeOrdinal", out _));
        Assert.True(firstRoute.TryGetProperty("path", out _));
    }

    [Fact]
    public void ToJson_IsCached()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        string json1 = desc.ToJson();
        string json2 = desc.ToJson();
        Assert.Same(json1, json2); // Same reference = cached
    }

    [Fact]
    public void GenerateJsSdk_ProducesEsmModule()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        string sdk = desc.GenerateJsSdk();

        // ESM exports
        Assert.Contains("export class BMWClient", sdk);
        Assert.Contains("export {", sdk);
        Assert.Contains("import { BMWClient }", sdk); // usage comment

        // Core methods
        Assert.Contains("connect(", sdk);
        Assert.Contains("send(opcode", sdk);
        Assert.Contains("close()", sdk);
        Assert.Contains("encodeFrame", sdk);
        Assert.Contains("decodeResponse", sdk);

        // Generated route methods on prototype
        Assert.Contains("BMWClient.prototype.listOrders", sdk);
        Assert.Contains("BMWClient.prototype.getOrders", sdk);
        Assert.Contains("BMWClient.prototype.createOrders", sdk);
        Assert.Contains("BMWClient.prototype.updateOrders", sdk);
        Assert.Contains("BMWClient.prototype.deleteOrders", sdk);
        Assert.Contains("BMWClient.prototype.listUsers", sdk);
        Assert.Contains("BMWClient.prototype.getUsers", sdk);
    }

    [Fact]
    public void GenerateJsSdk_EntityClasses()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        string sdk = desc.GenerateJsSdk();
        Assert.Contains("export class Orders", sdk);
        Assert.Contains("export class Users", sdk);
        Assert.Contains("Object.assign(this, data)", sdk);
    }

    [Fact]
    public void GenerateJsSdk_InlinesOpcodes()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        string sdk = desc.GenerateJsSdk();

        // listOrders: GET(0) route=1 → opcode = (0<<11)|1 = 1
        Assert.Contains("return this.send(1, 0)", sdk);

        // createOrders: POST(3) route=2 → opcode = (3<<11)|2 = 6146
        Assert.Contains("return this.send(6146, 0, data)", sdk);
    }

    [Fact]
    public void GenerateJsSdk_IsCached()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        string sdk1 = desc.GenerateJsSdk();
        string sdk2 = desc.GenerateJsSdk();
        Assert.Same(sdk1, sdk2);
    }

    [Fact]
    public void GenerateJsSdk_RoutesLookupTable()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        string sdk = desc.GenerateJsSdk();
        // Constructor builds routes name→opcode map
        Assert.Contains("this.routes[r.name] = r.opcode", sdk);
    }

    [Fact]
    public void GenerateJsSdk_WriteMethodsAcceptData()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        string sdk = desc.GenerateJsSdk();
        // POST without ID: createOrders(data)
        Assert.Contains("prototype.createOrders = function(data)", sdk);
        // PUT with ID: updateOrders(id, data)
        Assert.Contains("prototype.updateOrders = function(id, data)", sdk);
    }

    [Fact]
    public void GenerateJsSdk_ReadMethodsNoData()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        string sdk = desc.GenerateJsSdk();
        // GET list: listOrders()
        Assert.Contains("prototype.listOrders = function()", sdk);
        // GET by ID: getOrders(id)
        Assert.Contains("prototype.getOrders = function(id)", sdk);
        // DELETE by ID: deleteOrders(id)
        Assert.Contains("prototype.deleteOrders = function(id)", sdk);
    }

    [Fact]
    public void GenerateCliReference_ProducesNodeScript()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        string cli = desc.GenerateCliReference();

        // Shebang and ESM imports
        Assert.Contains("#!/usr/bin/env node", cli);
        Assert.Contains("import { WebSocket }", cli);
        Assert.Contains("import { readFileSync }", cli);

        // Command table with opcodes
        Assert.Contains("'orders:list':", cli);
        Assert.Contains("'orders:create':", cli);
        Assert.Contains("'orders:get':", cli);
        Assert.Contains("'users:list':", cli);

        // Binary frame encoding
        Assert.Contains("encodeFrame", cli);
        Assert.Contains("encodePayload", cli);

        // WebSocket connection
        Assert.Contains("new WebSocket(host)", cli);
        Assert.Contains("BMW_HOST", cli);
    }

    [Fact]
    public void GenerateCliReference_IsCached()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        string cli1 = desc.GenerateCliReference();
        string cli2 = desc.GenerateCliReference();
        Assert.Same(cli1, cli2);
    }

    [Fact]
    public void GenerateSdkName_EntityRoutes()
    {
        Assert.Equal("listOrders", BmwProtocolDescriptor.GenerateSdkName("GET", "/api/orders", "orders"));
        Assert.Equal("getOrders", BmwProtocolDescriptor.GenerateSdkName("GET", "/api/orders/{id}", "orders"));
        Assert.Equal("createOrders", BmwProtocolDescriptor.GenerateSdkName("POST", "/api/orders", "orders"));
        Assert.Equal("updateOrders", BmwProtocolDescriptor.GenerateSdkName("PUT", "/api/orders/{id}", "orders"));
        Assert.Equal("deleteOrders", BmwProtocolDescriptor.GenerateSdkName("DELETE", "/api/orders/{id}", "orders"));
    }

    [Fact]
    public void GenerateSdkName_NonEntityRoutes()
    {
        string name = BmwProtocolDescriptor.GenerateSdkName("GET", "/login", null);
        Assert.Equal("getLogin", name);
    }

    [Fact]
    public void ToCamelCase_HandlesVariousFormats()
    {
        Assert.Equal("myEntity", BmwProtocolDescriptor.ToCamelCase("my_entity"));
        Assert.Equal("myEntity", BmwProtocolDescriptor.ToCamelCase("my-entity"));
        Assert.Equal("orders", BmwProtocolDescriptor.ToCamelCase("orders"));
        Assert.Equal("o", BmwProtocolDescriptor.ToCamelCase("O"));
    }

    [Fact]
    public void NonEntityRoutes_NotGroupedInEntities()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        // /login is not an entity route
        Assert.False(desc.Entities.ContainsKey("login"));
        // But it should still be in routes
        Assert.True(desc.RoutesByName.ContainsKey("getLogin"));
    }

    [Fact]
    public void RoutesWithRouteId0_AreExcluded()
    {
        var routes = new Dictionary<string, RouteHandlerData>(StringComparer.Ordinal);
        var data = new RouteHandlerData(null, _ => ValueTask.CompletedTask);
        data.RouteId = 0; // Not assigned
        data.RouteKey = "GET /excluded";
        routes["GET /excluded"] = data;

        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        Assert.Empty(desc.Routes);
    }
}
