using System.Buffers;
using System.Buffers.Binary;
using System.IO.Pipelines;
using System.Net.WebSockets;
using System.Runtime.CompilerServices;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;

namespace BareMetalWeb.Host;

/// <summary>
/// Binary WebSocket transport for BareMetalWeb.
/// Wire format: 6-byte frames [opcode:14][id:32][reserved:2].
/// Opcode = (method &lt;&lt; 11) | route, giving 8 methods × 2048 routes = 16384 slots.
/// Write methods (POST/PUT/PATCH) carry a 3-byte content-length prefix before the payload.
/// </summary>
public sealed class BmwBinaryTransport
{
    /// <summary>Handler delegate for binary transport requests.</summary>
    public delegate ValueTask BinaryHandler(BmwContext ctx, uint entityId, Stream payload);

    // ── Constants ───────────────────────────────────────────────────────────
    public const int FrameSize = 6;
    public const int MethodBits = 3;
    public const int RouteBits = 11;
    public const int JumpTableSize = 1 << 14; // 16384 = 8 methods × 2048 routes
    public const int MaxRoutes = 1 << RouteBits; // 2048
    public const int MaxMethods = 1 << MethodBits; // 8
    public const int PayloadLengthSize = 3; // 24-bit content length for write methods

    // ── Method ordinals ────────────────────────────────────────────────────
    public const int MethodGet    = 0;
    public const int MethodHead   = 1;
    public const int MethodDelete = 2;
    public const int MethodPost   = 3;
    public const int MethodPut    = 4;
    public const int MethodPatch  = 5;

    // ── Jump table ─────────────────────────────────────────────────────────
    private readonly BinaryHandler[] _jumpTable;
    private readonly string[] _routeNames; // For diagnostics: routeOrdinal → route name

    private static readonly BinaryHandler _default404Handler = Default404Handler;

    public BmwBinaryTransport()
    {
        _jumpTable = new BinaryHandler[JumpTableSize];
        _routeNames = new string[MaxRoutes];
        Array.Fill(_jumpTable, _default404Handler);
    }

    // ── Registration ───────────────────────────────────────────────────────

    /// <summary>Register a handler for a specific (method, route) pair.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Register(int method, int route, BinaryHandler handler, string? routeName = null)
    {
        int opcode = (method << RouteBits) | route;
        _jumpTable[opcode] = handler;
        if (routeName != null && route < MaxRoutes)
            _routeNames[route] = routeName;
    }

    /// <summary>Register all standard CRUD handlers for an entity route.</summary>
    public void RegisterEntity(int route, string entitySlug,
        BinaryHandler getHandler,
        BinaryHandler listHandler,
        BinaryHandler createHandler,
        BinaryHandler updateHandler,
        BinaryHandler deleteHandler)
    {
        Register(MethodGet, route, getHandler, entitySlug);
        Register(MethodPost, route, createHandler);
        Register(MethodPut, route, updateHandler);
        Register(MethodPatch, route, updateHandler);
        Register(MethodDelete, route, deleteHandler);
        Register(MethodHead, route, listHandler);
    }

    /// <summary>
    /// Populate the jump table from existing registered routes.
    /// Maps each RouteHandlerData (with RouteId and RouteKey) into the binary dispatch table.
    /// </summary>
    public void PopulateFromRoutes(Dictionary<string, RouteHandlerData> routes, IBareWebHost app)
    {
        foreach (var kvp in routes)
        {
            var data = kvp.Value;
            if (data.RouteId == 0 || data.Handler == null)
                continue;

            int routeOrdinal = data.RouteId;
            if (routeOrdinal >= MaxRoutes)
                continue;

            int method = ParseMethodOrdinal(kvp.Key);
            if (method < 0)
                continue;

            // Wrap the existing RouteHandlerDelegate into a BinaryHandler
            var handler = data.Handler;
            Register(method, routeOrdinal, async (ctx, id, _) =>
            {
                await handler(ctx);
            }, data.RouteKey);
        }
    }

    // ── Frame decoding ─────────────────────────────────────────────────────

    /// <summary>Decode a 6-byte frame into opcode and entity ID. Zero allocations.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void DecodeFrame(ReadOnlySpan<byte> frame, out int opcode, out uint entityId)
    {
        // Bytes 0-1: opcode (14 bits) + reserved (2 bits) — big-endian uint16
        ushort raw = BinaryPrimitives.ReadUInt16BigEndian(frame);
        opcode = raw >> 2; // top 14 bits

        // Bytes 2-5: entity ID — little-endian uint32
        entityId = BinaryPrimitives.ReadUInt32LittleEndian(frame.Slice(2));
    }

    /// <summary>Encode a frame into a 6-byte buffer.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void EncodeFrame(Span<byte> buffer, int method, int route, uint entityId)
    {
        int opcode = (method << RouteBits) | route;
        BinaryPrimitives.WriteUInt16BigEndian(buffer, (ushort)(opcode << 2));
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(2), entityId);
    }

    /// <summary>Read a 24-bit content length from 3 bytes (little-endian).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int DecodePayloadLength(ReadOnlySpan<byte> bytes)
    {
        return bytes[0] | (bytes[1] << 8) | (bytes[2] << 16);
    }

    /// <summary>Write a 24-bit content length to 3 bytes (little-endian).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void EncodePayloadLength(Span<byte> buffer, int length)
    {
        buffer[0] = (byte)length;
        buffer[1] = (byte)(length >> 8);
        buffer[2] = (byte)(length >> 16);
    }

    /// <summary>Extract method ordinal from opcode.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetMethod(int opcode) => opcode >> RouteBits;

    /// <summary>Extract route ordinal from opcode.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetRoute(int opcode) => opcode & (MaxRoutes - 1);

    /// <summary>Check if a method ordinal is a write method (POST/PUT/PATCH).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool IsWriteMethod(int method) => method >= MethodPost;

    // ── WebSocket processing loop ──────────────────────────────────────────

    /// <summary>
    /// Process incoming BMW binary frames from a WebSocket connection.
    /// Runs until the client disconnects or sends a close frame.
    /// For each incoming frame the handler's output is captured via a per-frame
    /// MemoryStream and sent back as a binary WebSocket message with the same
    /// frame header so the client can correlate responses to requests.
    ///
    /// Response wire format (mirrors the request frame layout):
    /// <code>
    /// [opcode:14 | reserved:2 : uint16 BE] [entityId : uint32 LE]   ← 6-byte frame header
    /// [payloadLen : 3 bytes LE]                                       ← payload length prefix
    /// [payload bytes …]                                               ← handler output (JSON)
    /// </code>
    /// </summary>
    public async ValueTask ProcessAsync(WebSocket webSocket, BmwContext ctx, CancellationToken ct)
    {
        var receiveBuffer  = new byte[16 * 1024]; // 16 KB receive buffer (reused per loop iteration)
        var responseBuffer = new MemoryStream(4096); // capture buffer for handler output (reused per frame)

        while (webSocket.State == WebSocketState.Open && !ct.IsCancellationRequested)
        {
            var result = await webSocket.ReceiveAsync(new ArraySegment<byte>(receiveBuffer), ct);

            if (result.MessageType == WebSocketMessageType.Close)
            {
                await webSocket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null, ct);
                break;
            }

            if (result.MessageType != WebSocketMessageType.Binary)
                continue;

            // Process all complete frames in the receive buffer
            int offset   = 0;
            int received = result.Count;

            while (offset + FrameSize <= received)
            {
                var frameSpan = receiveBuffer.AsSpan(offset, FrameSize);
                DecodeFrame(frameSpan, out int opcode, out uint entityId);
                offset += FrameSize;

                int method = GetMethod(opcode);
                Stream payload = Stream.Null;

                // Write methods carry a 3-byte payload length prefix
                if (IsWriteMethod(method))
                {
                    if (offset + PayloadLengthSize > received)
                        break; // Incomplete frame — wait for more data

                    int payloadLen = DecodePayloadLength(receiveBuffer.AsSpan(offset, PayloadLengthSize));
                    offset += PayloadLengthSize;

                    if (payloadLen > 0)
                    {
                        if (offset + payloadLen > received)
                            break; // Incomplete payload — wait for more data

                        payload = new MemoryStream(receiveBuffer, offset, payloadLen, writable: false);
                        offset += payloadLen;
                    }
                }

                // ── Dispatch & capture response ──────────────────────────────────
                // Reset the capture buffer and create a fresh PipeWriter over it.
                // If the buffer has grown too large from a previous response, replace it
                // to avoid holding onto excessive memory for the lifetime of the connection.
                if (responseBuffer.Capacity > 65536)
                {
                    responseBuffer.Dispose();
                    responseBuffer = new MemoryStream(4096);
                }
                else
                {
                    responseBuffer.SetLength(0);
                }
                var captureWriter = PipeWriter.Create(responseBuffer, new StreamPipeWriterOptions(leaveOpen: true));
                var requestCtx    = ctx.CloneWithResponseBody(captureWriter);

                try
                {
                    var handler = _jumpTable[opcode];
                    await handler(requestCtx, entityId, payload);
                    await captureWriter.FlushAsync(ct);
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw; // Propagate cancellation to exit the outer loop
                }
                catch
                {
                    // Handler threw — clear any partial output; client receives empty payload
                    responseBuffer.SetLength(0);
                }
                finally
                {
                    captureWriter.Complete();
                }

                // ── Build and send response frame ────────────────────────────────
                // Layout: [6-byte frame header] [3-byte payload length] [payload bytes]
                int responseLen = (int)responseBuffer.Length;
                int totalLen    = FrameSize + PayloadLengthSize + responseLen;

                var responseBuf = ArrayPool<byte>.Shared.Rent(totalLen);
                try
                {
                    // Echo the same opcode and entityId so the client can correlate
                    EncodeFrame(responseBuf, method, GetRoute(opcode), entityId);
                    EncodePayloadLength(responseBuf.AsSpan(FrameSize), responseLen);
                    if (responseLen > 0 && responseBuffer.TryGetBuffer(out var segment))
                        segment.Array!.AsSpan(segment.Offset, responseLen)
                            .CopyTo(responseBuf.AsSpan(FrameSize + PayloadLengthSize));

                    await webSocket.SendAsync(
                        responseBuf.AsMemory(0, totalLen),
                        WebSocketMessageType.Binary,
                        endOfMessage: true,
                        ct);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(responseBuf);
                }
            }
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /// <summary>Parse HTTP method string to ordinal.</summary>
    public static int ParseMethodOrdinal(string routeKey)
    {
        if (routeKey.Length < 3) return -1;
        // Route keys are "METHOD /path" — match on first word
        return routeKey[0] switch
        {
            'G' => MethodGet,
            'H' => MethodHead,
            'D' => MethodDelete,
            'P' when routeKey[1] == 'O' => MethodPost,
            'P' when routeKey[1] == 'U' => MethodPut,
            'P' when routeKey[1] == 'A' => MethodPatch,
            _ => -1
        };
    }

    /// <summary>Get route name by ordinal for diagnostics.</summary>
    public string? GetRouteName(int route) =>
        route >= 0 && route < MaxRoutes ? _routeNames[route] : null;

    /// <summary>Get the number of registered (non-404) handlers.</summary>
    public int RegisteredHandlerCount
    {
        get
        {
            int count = 0;
            for (int i = 0; i < JumpTableSize; i++)
                if (_jumpTable[i] != _default404Handler)
                    count++;
            return count;
        }
    }

    private static ValueTask Default404Handler(BmwContext ctx, uint id, Stream payload)
    {
        ctx.StatusCode = 404;
        return ValueTask.CompletedTask;
    }
}
