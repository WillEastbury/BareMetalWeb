using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http.Features;

namespace BareMetalWeb.Host;

/// <summary>
/// Implements <see cref="IHttpApplication{TContext}"/> so that Kestrel
/// drives the BMW request pipeline directly — no ASP.NET middleware,
/// no <c>WebApplication</c>, no <c>UseRouting</c>.
/// </summary>
/// <remarks>
/// <para>
/// The lifecycle per request is:
/// <list type="number">
///   <item>Kestrel calls <see cref="CreateContext"/> with the raw feature collection.</item>
///   <item><see cref="ProcessRequestAsync"/> dispatches through the BMW router.</item>
///   <item><see cref="DisposeContext"/> performs minimal cleanup.</item>
/// </list>
/// </para>
/// </remarks>
public sealed class BmwApplication : IHttpApplication<BmwContext>
{
    private readonly BareMetalWebServer _server;

    public BmwApplication(BareMetalWebServer server)
    {
        _server = server;
    }

    /// <summary>
    /// Called by Kestrel once per request. Resolves features and builds
    /// a <see cref="BmwContext"/> with a <c>DefaultHttpContext</c> bridge
    /// for backward-compatible handler access.
    /// </summary>
    public BmwContext CreateContext(IFeatureCollection contextFeatures)
        => BmwContext.CreateFromFeatures(contextFeatures, _server);

    /// <summary>
    /// Dispatches the request through the existing <see cref="BareMetalWebServer.RequestHandler"/>.
    /// </summary>
    public Task ProcessRequestAsync(BmwContext context)
        => _server.RequestHandler(context.HttpContext);

    /// <summary>
    /// Minimal cleanup. The <see cref="BmwContext"/> has no unmanaged resources;
    /// exceptions are already handled inside <see cref="ProcessRequestAsync"/>.
    /// </summary>
    public void DisposeContext(BmwContext context, Exception? exception)
    {
        // Nothing to dispose — BmwContext holds only managed references.
        // Kestrel handles connection/stream cleanup via the feature collection.
    }
}
