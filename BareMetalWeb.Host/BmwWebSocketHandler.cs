using System.Net.WebSockets;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;

namespace BareMetalWeb.Host;

/// <summary>
/// Handles the HTTP → WebSocket upgrade for BMW binary transport.
/// Registered as GET /bmw/ws — authenticates during HTTP upgrade,
/// then delegates to <see cref="BmwBinaryTransport.ProcessAsync"/>.
/// </summary>
public static class BmwWebSocketHandler
{
    /// <summary>
    /// Creates a route handler that upgrades HTTP to WebSocket and runs the binary transport loop.
    /// </summary>
    public static Core.Delegates.RouteHandlerDelegate CreateHandler(BmwBinaryTransport transport)
    {
        return async (BmwContext ctx) =>
        {
            var httpCtx = ctx.HttpContext;
            if (!httpCtx.WebSockets.IsWebSocketRequest)
            {
                ctx.StatusCode = 400;
                await ctx.WriteResponseAsync("WebSocket upgrade required");
                return;
            }

            var webSocket = await httpCtx.WebSockets.AcceptWebSocketAsync();

            try
            {
                await transport.ProcessAsync(webSocket, ctx, ctx.RequestAborted);
            }
            catch (WebSocketException)
            {
                // Client disconnected — normal for long-lived connections
            }
            catch (OperationCanceledException)
            {
                // Request aborted — normal during shutdown
            }
            finally
            {
                if (webSocket.State == WebSocketState.Open || webSocket.State == WebSocketState.CloseReceived)
                {
                    try
                    {
                        await webSocket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
                    }
                    catch { /* Best-effort close */ }
                }
                webSocket.Dispose();
            }
        };
    }
}
