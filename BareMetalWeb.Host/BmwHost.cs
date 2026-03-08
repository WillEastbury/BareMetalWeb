using System.Runtime.InteropServices;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace BareMetalWeb.Host;

/// <summary>
/// Hosts BMW directly on Kestrel without the ASP.NET middleware pipeline.
/// Replaces <c>WebApplication.Run()</c> with a minimal hosting loop:
/// <code>
/// Socket → Kestrel → IHttpApplication&lt;BmwContext&gt; → BMW Router → PipeWriter Response
/// </code>
/// </summary>
public sealed class BmwHost : IAsyncDisposable
{
    private readonly KestrelServer _server;
    private readonly BmwApplication _application;
    private readonly IBufferedLogger _logger;
    private readonly CancellationTokenSource _cts;

    private BmwHost(KestrelServer server, BmwApplication application, IBufferedLogger logger, CancellationTokenSource cts)
    {
        _server = server;
        _application = application;
        _logger = logger;
        _cts = cts;
    }

    /// <summary>
    /// Creates a <see cref="BmwHost"/> wired to the given <see cref="BareMetalWebServer"/>.
    /// Configures Kestrel listeners from the provided options callback.
    /// </summary>
    public static BmwHost Create(
        BareMetalWebServer server,
        Action<KestrelServerOptions>? configureKestrel = null,
        ILoggerFactory? loggerFactory = null)
    {
        loggerFactory ??= LoggerFactory.Create(b => b.SetMinimumLevel(LogLevel.Warning));

        var kestrelOptions = new KestrelServerOptions();
        configureKestrel?.Invoke(kestrelOptions);

        var transportOptions = new SocketTransportOptions { NoDelay = true };
        var transportFactory = new SocketTransportFactory(
            Options.Create(transportOptions),
            loggerFactory);

        var kestrelServer = new KestrelServer(
            Options.Create(kestrelOptions),
            transportFactory,
            loggerFactory);

        var bmwApp = new BmwApplication(server);

        return new BmwHost(kestrelServer, bmwApp, server.BufferedLogger, server.cts);
    }

    /// <summary>
    /// Starts Kestrel, blocks until shutdown is requested (SIGTERM / Ctrl+C),
    /// then performs graceful shutdown.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        // Merge external cancellation with the server's own CTS
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cts.Token);

        // Handle SIGTERM / Ctrl+C
        using var sigterm = PosixSignalRegistration.Create(PosixSignal.SIGTERM, _ => _cts.Cancel());
        Console.CancelKeyPress += (_, e) => { e.Cancel = true; _cts.Cancel(); };

        await _server.StartAsync(_application, linkedCts.Token).ConfigureAwait(false);

        // Log listening addresses for diagnostics
        foreach (var address in _server.Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()?.Addresses ?? [])
            _logger.LogInfo($"Now listening on: {address}");

        _logger.LogInfo($"BmwHost started — PID {Environment.ProcessId} — direct Kestrel hosting (no ASP.NET middleware)");
        Console.WriteLine($"BmwHost started — PID {Environment.ProcessId} — direct Kestrel hosting");
        Console.WriteLine($"PORT={Environment.GetEnvironmentVariable("PORT")}");
        Console.WriteLine($"WEBSITES_PORT={Environment.GetEnvironmentVariable("WEBSITES_PORT")}");
        foreach (var address in _server.Features.Get<Microsoft.AspNetCore.Hosting.Server.Features.IServerAddressesFeature>()?.Addresses ?? [])
            Console.WriteLine($"  Listening on: {address}");

        // Block until cancellation
        try
        {
            await Task.Delay(Timeout.Infinite, linkedCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) { }

        _logger.LogInfo("BmwHost shutting down...");
        Console.WriteLine("[BMW Shutdown] Shutdown signal received — draining background services...");

        // Drain background services before stopping Kestrel
        await _application.Server.DrainBackgroundServicesAsync(TimeSpan.FromSeconds(30)).ConfigureAwait(false);

        await _server.StopAsync(CancellationToken.None).ConfigureAwait(false);
        Console.WriteLine("[BMW Shutdown] Kestrel stopped.");
        _logger.LogInfo("BmwHost stopped.");
    }

    public async ValueTask DisposeAsync()
    {
        _server.Dispose();
        await ValueTask.CompletedTask;
    }
}
