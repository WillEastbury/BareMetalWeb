using System.Buffers.Binary;
using BareMetalWeb.Host;

namespace BareMetalWeb.Host.Tests;

public class BmwBinaryTransportTests
{
    // ── Frame encoding/decoding ────────────────────────────────────────────

    [Fact]
    public void EncodeFrame_GET_Route0_Id0_ProducesCorrectBytes()
    {
        var buf = new byte[6];
        BmwBinaryTransport.EncodeFrame(buf, BmwBinaryTransport.MethodGet, 0, 0);
        BmwBinaryTransport.DecodeFrame(buf, out int opcode, out uint id);
        Assert.Equal(0, opcode);
        Assert.Equal(0u, id);
    }

    [Fact]
    public void EncodeFrame_POST_Route42_Id12345_RoundTrips()
    {
        var buf = new byte[6];
        BmwBinaryTransport.EncodeFrame(buf, BmwBinaryTransport.MethodPost, 42, 12345u);
        BmwBinaryTransport.DecodeFrame(buf, out int opcode, out uint id);

        Assert.Equal(BmwBinaryTransport.MethodPost, BmwBinaryTransport.GetMethod(opcode));
        Assert.Equal(42, BmwBinaryTransport.GetRoute(opcode));
        Assert.Equal(12345u, id);
    }

    [Fact]
    public void EncodeFrame_AllMethods_RoundTrip()
    {
        for (int m = 0; m < 6; m++)
        {
            var buf = new byte[6];
            BmwBinaryTransport.EncodeFrame(buf, m, 100, 999u);
            BmwBinaryTransport.DecodeFrame(buf, out int opcode, out uint id);

            Assert.Equal(m, BmwBinaryTransport.GetMethod(opcode));
            Assert.Equal(100, BmwBinaryTransport.GetRoute(opcode));
            Assert.Equal(999u, id);
        }
    }

    [Fact]
    public void EncodeFrame_MaxRoute_RoundTrips()
    {
        var buf = new byte[6];
        int maxRoute = BmwBinaryTransport.MaxRoutes - 1; // 2047
        BmwBinaryTransport.EncodeFrame(buf, BmwBinaryTransport.MethodGet, maxRoute, uint.MaxValue);
        BmwBinaryTransport.DecodeFrame(buf, out int opcode, out uint id);

        Assert.Equal(BmwBinaryTransport.MethodGet, BmwBinaryTransport.GetMethod(opcode));
        Assert.Equal(maxRoute, BmwBinaryTransport.GetRoute(opcode));
        Assert.Equal(uint.MaxValue, id);
    }

    [Fact]
    public void DecodeFrame_ExactlySixBytes()
    {
        var buf = new byte[6];
        BmwBinaryTransport.EncodeFrame(buf, BmwBinaryTransport.MethodDelete, 7, 42u);
        // Should not throw with exactly 6 bytes
        BmwBinaryTransport.DecodeFrame(buf.AsSpan(0, 6), out int opcode, out uint id);
        Assert.Equal(7, BmwBinaryTransport.GetRoute(opcode));
        Assert.Equal(42u, id);
    }

    // ── Payload length encoding ────────────────────────────────────────────

    [Fact]
    public void PayloadLength_Zero_RoundTrips()
    {
        var buf = new byte[3];
        BmwBinaryTransport.EncodePayloadLength(buf, 0);
        Assert.Equal(0, BmwBinaryTransport.DecodePayloadLength(buf));
    }

    [Fact]
    public void PayloadLength_Max24Bit_RoundTrips()
    {
        var buf = new byte[3];
        int maxLen = (1 << 24) - 1; // 16,777,215
        BmwBinaryTransport.EncodePayloadLength(buf, maxLen);
        Assert.Equal(maxLen, BmwBinaryTransport.DecodePayloadLength(buf));
    }

    [Fact]
    public void PayloadLength_MidRange_RoundTrips()
    {
        var buf = new byte[3];
        BmwBinaryTransport.EncodePayloadLength(buf, 65535);
        Assert.Equal(65535, BmwBinaryTransport.DecodePayloadLength(buf));
    }

    // ── Method helpers ─────────────────────────────────────────────────────

    [Theory]
    [InlineData(BmwBinaryTransport.MethodGet, false)]
    [InlineData(BmwBinaryTransport.MethodHead, false)]
    [InlineData(BmwBinaryTransport.MethodDelete, false)]
    [InlineData(BmwBinaryTransport.MethodPost, true)]
    [InlineData(BmwBinaryTransport.MethodPut, true)]
    [InlineData(BmwBinaryTransport.MethodPatch, true)]
    public void IsWriteMethod_CorrectForAllMethods(int method, bool expected)
    {
        Assert.Equal(expected, BmwBinaryTransport.IsWriteMethod(method));
    }

    // ── ParseMethodOrdinal ─────────────────────────────────────────────────

    [Theory]
    [InlineData("GET /foo", BmwBinaryTransport.MethodGet)]
    [InlineData("HEAD /foo", BmwBinaryTransport.MethodHead)]
    [InlineData("DELETE /foo", BmwBinaryTransport.MethodDelete)]
    [InlineData("POST /foo", BmwBinaryTransport.MethodPost)]
    [InlineData("PUT /foo", BmwBinaryTransport.MethodPut)]
    [InlineData("PATCH /foo", BmwBinaryTransport.MethodPatch)]
    [InlineData("ALL /foo", -1)]
    [InlineData("", -1)]
    [InlineData("X", -1)]
    public void ParseMethodOrdinal_ReturnsCorrectOrdinal(string routeKey, int expected)
    {
        Assert.Equal(expected, BmwBinaryTransport.ParseMethodOrdinal(routeKey));
    }

    // ── Jump table registration ────────────────────────────────────────────

    [Fact]
    public void Register_HandlerIsAccessibleViaJumpTable()
    {
        var transport = new BmwBinaryTransport();
        bool handlerCalled = false;

        transport.Register(BmwBinaryTransport.MethodGet, 1,
            (ctx, id, payload) => { handlerCalled = true; return ValueTask.CompletedTask; },
            "GET /test");

        Assert.True(transport.RegisteredHandlerCount >= 1);
    }

    [Fact]
    public void Constructor_AllSlotsDefault404()
    {
        var transport = new BmwBinaryTransport();
        Assert.Equal(0, transport.RegisteredHandlerCount);
    }

    [Fact]
    public void RegisterEntity_RegistersFiveHandlers()
    {
        var transport = new BmwBinaryTransport();
        var noop = new BmwBinaryTransport.BinaryHandler((ctx, id, payload) => ValueTask.CompletedTask);

        transport.RegisterEntity(1, "products", noop, noop, noop, noop, noop);
        // GET, POST, PUT, PATCH, DELETE, HEAD = 6 handlers (PATCH shares with PUT handler)
        Assert.Equal(6, transport.RegisteredHandlerCount);
    }

    [Fact]
    public void GetRouteName_ReturnsRegisteredName()
    {
        var transport = new BmwBinaryTransport();
        var noop = new BmwBinaryTransport.BinaryHandler((ctx, id, payload) => ValueTask.CompletedTask);

        transport.Register(BmwBinaryTransport.MethodGet, 5, noop, "GET /products");
        Assert.Equal("GET /products", transport.GetRouteName(5));
    }

    [Fact]
    public void GetRouteName_UnregisteredRoute_ReturnsNull()
    {
        var transport = new BmwBinaryTransport();
        Assert.Null(transport.GetRouteName(999));
    }

    [Fact]
    public void GetRouteName_OutOfRange_ReturnsNull()
    {
        var transport = new BmwBinaryTransport();
        Assert.Null(transport.GetRouteName(-1));
        Assert.Null(transport.GetRouteName(BmwBinaryTransport.MaxRoutes));
    }

    // ── Opcode composition ─────────────────────────────────────────────────

    [Fact]
    public void Opcode_MethodAndRoute_AreIndependent()
    {
        // Verify method and route bits don't overlap
        for (int m = 0; m < 6; m++)
        {
            for (int r = 0; r < 10; r++)
            {
                var buf = new byte[6];
                BmwBinaryTransport.EncodeFrame(buf, m, r, 0);
                BmwBinaryTransport.DecodeFrame(buf, out int opcode, out _);

                Assert.Equal(m, BmwBinaryTransport.GetMethod(opcode));
                Assert.Equal(r, BmwBinaryTransport.GetRoute(opcode));
            }
        }
    }

    [Fact]
    public void JumpTableSize_Is16384()
    {
        Assert.Equal(16384, BmwBinaryTransport.JumpTableSize);
    }

    [Fact]
    public void FrameSize_Is6()
    {
        Assert.Equal(6, BmwBinaryTransport.FrameSize);
    }

    [Fact]
    public void MaxRoutes_Is2048()
    {
        Assert.Equal(2048, BmwBinaryTransport.MaxRoutes);
    }

    // ── Edge cases ─────────────────────────────────────────────────────────

    [Fact]
    public void EncodeFrame_EntityId_Zero_RoundTrips()
    {
        var buf = new byte[6];
        BmwBinaryTransport.EncodeFrame(buf, BmwBinaryTransport.MethodGet, 1, 0u);
        BmwBinaryTransport.DecodeFrame(buf, out _, out uint id);
        Assert.Equal(0u, id);
    }

    [Fact]
    public void EncodeFrame_EntityId_MaxUint32_RoundTrips()
    {
        var buf = new byte[6];
        BmwBinaryTransport.EncodeFrame(buf, BmwBinaryTransport.MethodGet, 1, uint.MaxValue);
        BmwBinaryTransport.DecodeFrame(buf, out _, out uint id);
        Assert.Equal(uint.MaxValue, id);
    }

    [Fact]
    public void EncodeFrame_EntityId_OneMillionRoundTrips()
    {
        var buf = new byte[6];
        BmwBinaryTransport.EncodeFrame(buf, BmwBinaryTransport.MethodPost, 500, 1_000_000u);
        BmwBinaryTransport.DecodeFrame(buf, out int opcode, out uint id);
        Assert.Equal(BmwBinaryTransport.MethodPost, BmwBinaryTransport.GetMethod(opcode));
        Assert.Equal(500, BmwBinaryTransport.GetRoute(opcode));
        Assert.Equal(1_000_000u, id);
    }

    [Fact]
    public void PayloadLength_Various_RoundTrip()
    {
        int[] testValues = [0, 1, 255, 256, 65535, 65536, 1_000_000, (1 << 24) - 1];
        foreach (var val in testValues)
        {
            var buf = new byte[3];
            BmwBinaryTransport.EncodePayloadLength(buf, val);
            Assert.Equal(val, BmwBinaryTransport.DecodePayloadLength(buf));
        }
    }

    [Fact]
    public void Register_OverwritesPreviousHandler()
    {
        var transport = new BmwBinaryTransport();
        int callCount = 0;

        transport.Register(BmwBinaryTransport.MethodGet, 1,
            (ctx, id, payload) => { callCount = 1; return ValueTask.CompletedTask; });
        transport.Register(BmwBinaryTransport.MethodGet, 1,
            (ctx, id, payload) => { callCount = 2; return ValueTask.CompletedTask; });

        // Still only 1 registered handler at that slot
        Assert.Equal(1, transport.RegisteredHandlerCount);
    }

    [Fact]
    public void MultipleMethodsSameRoute_AreIndependent()
    {
        var transport = new BmwBinaryTransport();
        var noop = new BmwBinaryTransport.BinaryHandler((ctx, id, payload) => ValueTask.CompletedTask);

        transport.Register(BmwBinaryTransport.MethodGet, 1, noop);
        transport.Register(BmwBinaryTransport.MethodPost, 1, noop);
        transport.Register(BmwBinaryTransport.MethodDelete, 1, noop);

        Assert.Equal(3, transport.RegisteredHandlerCount);
    }
}
