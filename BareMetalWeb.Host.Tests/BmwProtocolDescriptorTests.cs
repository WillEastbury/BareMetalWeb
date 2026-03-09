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
    public void GenerateJsSdk_ProducesValidJs()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        string sdk = desc.GenerateJsSdk();
        Assert.Contains("BmwSdk", sdk);
        Assert.Contains("encodeFrame", sdk);
        Assert.Contains("connect", sdk);
        Assert.Contains("send", sdk);
        // Should contain entity methods
        Assert.Contains("orders", sdk);
        Assert.Contains("users", sdk);
    }

    [Fact]
    public void GenerateCliReference_ListsCommands()
    {
        var routes = BuildTestRoutes();
        var compiled = CompileRoutes(routes);
        var desc = BmwProtocolDescriptor.Build(routes, compiled);

        string cli = desc.GenerateCliReference();
        Assert.Contains("bmw orders", cli);
        Assert.Contains("bmw users", cli);
        Assert.Contains("opcode=", cli);
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
