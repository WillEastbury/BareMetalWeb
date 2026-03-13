using System.Runtime.InteropServices;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using BareMetalWeb.Host;
using BareMetalWeb.Interfaces;

public static class ProgramSetup
{
    public static string GetCpuModel()
    {
        try
        {
            if (OperatingSystem.IsLinux() && File.Exists("/proc/cpuinfo"))
            {
                // Prefer "model name" (x86 full brand string) over "Model" (ARM board name)
                string? modelName = null;
                string? model = null;
                foreach (var line in File.ReadLines("/proc/cpuinfo"))
                {
                    if (line.StartsWith("model name", StringComparison.OrdinalIgnoreCase))
                    {
                        var idx = line.IndexOf(':');
                        if (idx >= 0) { modelName = line[(idx + 1)..].Trim(); break; }
                    }
                    else if (model == null && line.StartsWith("Model", StringComparison.OrdinalIgnoreCase)
                            && !line.StartsWith("model name", StringComparison.OrdinalIgnoreCase))
                    {
                        var idx = line.IndexOf(':');
                        if (idx >= 0) model = line[(idx + 1)..].Trim();
                    }
                }
                if (!string.IsNullOrEmpty(modelName)) return modelName;
                if (!string.IsNullOrEmpty(model)) return model;
            }
            else if (OperatingSystem.IsMacOS())
            {
                var psi = new System.Diagnostics.ProcessStartInfo("sysctl", "-n machdep.cpu.brand_string")
                { RedirectStandardOutput = true, UseShellExecute = false };
                using var proc = System.Diagnostics.Process.Start(psi);
                if (proc != null)
                {
                    var result = proc.StandardOutput.ReadToEnd().Trim();
                    proc.WaitForExit(1000);
                    if (!string.IsNullOrEmpty(result)) return result;
                }
            }
        }
        catch { }
        return RuntimeInformation.ProcessArchitecture.ToString();
    }
   public static string GetStorageInfo()
    {
        try
        {
            var drive = new DriveInfo(Path.GetPathRoot(Environment.CurrentDirectory) ?? "/");
            var totalGb = drive.TotalSize / (1024 * 1024 * 1024);
            var freeGb = drive.AvailableFreeSpace / (1024 * 1024 * 1024);
            return $"{freeGb} GB free / {totalGb} GB total";
        }
        catch { return "unknown"; }
    }
    public static string WriteConfigBanner()
    {
        var contentRoot = Directory.GetCurrentDirectory();
        // ── Configuration ──────────────────────────────────────────────────────
        Console.WriteLine("BMW Platform INIT");
        Console.WriteLine($"  Arch:     {RuntimeInformation.ProcessArchitecture}");
        Console.WriteLine($"  CPU:      {GetCpuModel()}");
        Console.WriteLine($"  Cores:    {Environment.ProcessorCount}");
        Console.WriteLine($"  RAM:      {GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024 * 1024)} MB");
        Console.WriteLine($"  Storage:  {GetStorageInfo()}");
        Console.WriteLine($"  OS:       {RuntimeInformation.OSDescription}");
        Console.WriteLine($"  Runtime:  {RuntimeInformation.FrameworkDescription}");
        Console.WriteLine($"  {SimdCapabilities.Current.ToLogLine()}");
        foreach (var warning in SimdCapabilities.Current.GetMismatchWarnings())
            Console.WriteLine($"  {warning}");
        Console.WriteLine($"  Content Root: {contentRoot}");
        return contentRoot;
    }
    public static Action<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions> ConfigureKestrel(BmwConfig config)
    {
        // Thread pool tuning (applied immediately — not Kestrel-specific)
        var minWorker = config.GetValue("ThreadPool.MinWorkerThreads", 0);
        var minIO = config.GetValue("ThreadPool.MinIOThreads", 0);
        if (minWorker > 0 || minIO > 0)
        {
            ThreadPool.GetMinThreads(out int currentWorker, out int currentIO);
            ThreadPool.SetMinThreads(
                minWorker > 0 ? minWorker : currentWorker,
                minIO > 0 ? minIO : currentIO);
        }

        return serverOptions =>
        {
            // Respect PORT / WEBSITES_PORT env vars (Azure App Service, containers)
            var envPort = Environment.GetEnvironmentVariable("PORT")
                       ?? Environment.GetEnvironmentVariable("WEBSITES_PORT");
            var listenPort = !string.IsNullOrEmpty(envPort) && int.TryParse(envPort, out var ep)
                ? ep
                : config.GetValue("Kestrel.Port", 5000);
            serverOptions.ListenAnyIP(listenPort);

            // HTTPS: listen on a second port when a certificate is configured
            var httpsPort = config.GetValue("Kestrel.HttpsPort", 0);
            var certPath = config.GetValue("Kestrel.CertPath", "");
            var certPassword = Environment.GetEnvironmentVariable("KESTREL_CERT_PASSWORD") ?? config.GetValue("Kestrel.CertPassword", "");
            if (httpsPort > 0 && !string.IsNullOrEmpty(certPath) && File.Exists(certPath))
            {
                var cert = string.IsNullOrEmpty(certPassword)
                    ? System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPemFile(certPath, Path.ChangeExtension(certPath, ".key"))
                    : new System.Security.Cryptography.X509Certificates.X509Certificate2(certPath, certPassword);

                // Pre-warm: build certificate context (parses chain, caches for handshakes)
                var certContext = System.Net.Security.SslStreamCertificateContext.Create(cert, additionalCertificates: null, offline: true);

                var sslOptions = new System.Net.Security.SslServerAuthenticationOptions
                {
                    ServerCertificateContext = certContext,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13,
                    AllowRenegotiation = false,
                    ClientCertificateRequired = false,
                    CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
                    CipherSuitesPolicy = new System.Net.Security.CipherSuitesPolicy([System.Net.Security.TlsCipherSuite.TLS_AES_128_GCM_SHA256]),
                    ApplicationProtocols = [System.Net.Security.SslApplicationProtocol.Http11],
                };

                // Pre-warm: loopback TLS handshake to initialize OpenSSL state machine
                WarmUpTls(sslOptions);

                serverOptions.ListenAnyIP(httpsPort, listenOptions =>
                {
                    listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1;
                    listenOptions.Use(next => new TlsConnectionMiddleware(next, sslOptions).OnConnectionAsync);
                });
                Console.WriteLine($"[BMW TLS] HTTPS configured on port {httpsPort} (direct SslStream, TLS 1.3, AES-128-GCM-SHA256, pre-warmed)");
            }

            var http2Enabled = config.GetValue("Kestrel.Http2Enabled", true);
            var http3Enabled = config.GetValue("Kestrel.Http3Enabled", false);

            serverOptions.ConfigureEndpointDefaults(listenOptions =>
            {
                if (http2Enabled && http3Enabled)
                    listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1AndHttp2AndHttp3;
                else if (http2Enabled)
                    listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1AndHttp2;
                else
                    listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1;
            });

            var maxStreams = config.GetValue("Kestrel.MaxStreamsPerConnection", 100);
            if (maxStreams > 0)
                serverOptions.Limits.Http2.MaxStreamsPerConnection = maxStreams;

            var connWindowSize = config.GetValue("Kestrel.InitialConnectionWindowSize", 131072);
            if (connWindowSize > 0)
                serverOptions.Limits.Http2.InitialConnectionWindowSize = connWindowSize;

            var streamWindowSize = config.GetValue("Kestrel.InitialStreamWindowSize", 98304);
            if (streamWindowSize > 0)
                serverOptions.Limits.Http2.InitialStreamWindowSize = streamWindowSize;

            // ── Connection limits ────────────────────────────────────────────
            // MaxConcurrentConnections: 2048 supports high-concurrency benchmarks
            // (wrk -c400) and production traffic without artificial throttling.
            // Set lower on memory-constrained deployments.
            var maxConnections = config.GetValue("Kestrel.MaxConcurrentConnections", 2048);
            if (maxConnections > 0)
                serverOptions.Limits.MaxConcurrentConnections = maxConnections;

            // Upgraded connections (WebSocket): cap below total to reserve
            // capacity for normal HTTP requests under pressure.
            var maxUpgraded = config.GetValue("Kestrel.MaxConcurrentUpgradedConnections", 512);
            if (maxUpgraded > 0)
                serverOptions.Limits.MaxConcurrentUpgradedConnections = maxUpgraded;

            // ── Timeouts ────────────────────────────────────────────────────
            // Keep-alive: 2 minutes aligns with the HTTP/2 RFC default and lets
            // multiplexed connections amortize the TLS handshake cost.
            var keepAliveSeconds = config.GetValue("Kestrel.KeepAliveTimeoutSeconds", 120);
            serverOptions.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(keepAliveSeconds);

            // Request headers: 5s is tight enough to drop slowloris-style
            // attacks while still accepting legitimate slow mobile clients.
            var headerTimeoutSeconds = config.GetValue("Kestrel.RequestHeadersTimeoutSeconds", 5);
            serverOptions.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(headerTimeoutSeconds);

            var maxBodyBytes = config.GetValue("Kestrel.MaxRequestBodySizeMB", 10);
            serverOptions.Limits.MaxRequestBodySize = (long)maxBodyBytes * 1024 * 1024;

            // Disable minimum data-rate enforcement for response bodies.
            // Prevents Kestrel from killing slow consumers (SSE, long-poll,
            // large CSV exports over mobile connections).
            serverOptions.Limits.MinResponseDataRate = null;

            // Strip the "Server: Kestrel" header — avoid leaking server identity.
            serverOptions.AddServerHeader = false;
        };
    }
    public static Action<Microsoft.AspNetCore.Server.Kestrel.Transport.Sockets.SocketTransportOptions> ConfigureSocketTransport(BmwConfig config)
    {
        return socketOptions =>
        {
            // Critical for low-latency small responses: disable Nagle at transport layer.
            socketOptions.NoDelay = config.GetValue("Kestrel.NoDelay", true);
        };
    }
    public static IBufferedLogger CreateLogger(BmwConfig config)
    {
        var folder = config.GetValue("Logging.LogFolder", "Logs");
        var levelStr = config.GetValue("Logging.MinLevel", "Info");
        var level = Enum.TryParse<BmwLogLevel>(levelStr, ignoreCase: true, out var parsed)
            ? parsed
            : BmwLogLevel.Info;
        var redactPII = config.GetValue("Logging.RedactPII", true);
        return new DiskBufferedLogger(folder, level, redactPII);
    }
    public static IDataObjectStore CreateDataStore(BmwConfig config, string contentRoot, ISchemaAwareObjectSerializer serializer, IDataQueryEvaluator queryEvaluator, IBufferedLogger logger)
    {
        var dataRoot = config.GetValue("Data.Root", Path.Combine(contentRoot, "Data"));
        MetricsTracker.DataRoot = dataRoot;

        // Detect and wipe legacy GUID-based data before opening the store
        LegacyDataWipeGuard.WipeIfLegacyDetected(dataRoot, logger);

        var dataStore = new DataObjectStore();
        DataStoreProvider.Current = dataStore;
        var provider = new WalDataProvider(
            dataRoot,
            serializer,
            queryEvaluator,
            logger);
        DataStoreProvider.PrimaryProvider = provider;
        dataStore.RegisterProvider(provider);

        return dataStore;
    }
    public static void ResetDataIfRequested(BmwConfig config, string contentRoot, string dataRoot, IBufferedLogger logger)
    {
        var resetFlagPath = Path.Combine(contentRoot, "reset-data.flag");
        var shouldReset = config.GetValue("Data.ResetOnStartup", false) || File.Exists(resetFlagPath);
        if (!shouldReset)
            return;

        var fullRoot = Path.GetFullPath(dataRoot);
        if (IsUnsafeDataRoot(fullRoot))
        {
            logger.LogError($"Refusing to reset data root '{fullRoot}'. Path is not safe.", new InvalidOperationException("Unsafe data root path."));
            return;
        }

        try
        {
            if (Directory.Exists(fullRoot))
            {
                Directory.Delete(fullRoot, recursive: true);
            }
            Directory.CreateDirectory(fullRoot);

            if (File.Exists(resetFlagPath))
            {
                File.Delete(resetFlagPath);
            }

            logger.LogInfo($"Data reset complete. Root: {fullRoot}");
        }
        catch (Exception ex)
        {
            logger.LogError($"Failed to reset data root '{fullRoot}'.", ex);
            throw;
        }
    }
    private static bool IsUnsafeDataRoot(string fullRoot)
    {
        if (string.IsNullOrWhiteSpace(fullRoot))
            return true;

        var root = Path.GetPathRoot(fullRoot);
        if (string.IsNullOrWhiteSpace(root))
            return true;

        return string.Equals(fullRoot.TrimEnd(Path.DirectorySeparatorChar), root.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);
    }

   public static IClientRequestTracker CreateClientRequestTracker(BmwConfig config, IBufferedLogger logger)
        => new ClientRequestTracker(
            logger,
            normalRpsThreshold: config.GetValue("ClientRequests.NormalRpsThreshold", 20),
            suspiciousRpsThreshold: config.GetValue("ClientRequests.SuspiciousRpsThreshold", 10),
            blockDuration: TimeSpan.FromMinutes(config.GetValue("ClientRequests.BlockDurationMinutes", 1)),
            allowList: config.GetArray("ClientRequests.AllowList"),
            denyList: config.GetArray("ClientRequests.DenyList"),
            staleThreshold: TimeSpan.FromSeconds(config.GetValue("ClientRequests.StaleThresholdSeconds", 120)),
            pruneInterval: TimeSpan.FromSeconds(config.GetValue("ClientRequests.PruneIntervalSeconds", 30)),
            maxEntries: config.GetValue("ClientRequests.MaxEntries", 100000));

    public static async ValueTask EnsureRootPermissionsAsync(IBufferedLogger logger, string[] requiredPermissions, CancellationToken cancellationToken = default)
    {
        if (requiredPermissions is null || requiredPermissions.Length == 0)
            return;

        var query = new QueryDefinition
        {
            Clauses = new List<QueryClause>
            {
                new QueryClause { Field = "Permissions", Operator = QueryOperator.Contains, Value = "admin" },
                new QueryClause { Field = "Permissions", Operator = QueryOperator.Contains, Value = "monitoring" }
            }
        };

        var usersEnumerable = await UserAuth.QueryUsersAsync(query, cancellationToken).ConfigureAwait(false);
        var users = new List<BaseDataObject>();
        foreach (var u in usersEnumerable)
        {
            users.Add(u);
        }
        foreach (var user in users)
        {
            if (user is null || !UserAuth.IsActive(user))
                continue;

            var perms = new List<string>(UserAuth.GetPermissions(user));
            var changed = false;
            foreach (var required in requiredPermissions)
            {
                if (string.IsNullOrWhiteSpace(required))
                    continue;
                bool alreadyHasPerm = false;
                foreach (var p in perms)
                {
                    if (string.Equals(p, required, StringComparison.OrdinalIgnoreCase))
                    {
                        alreadyHasPerm = true;
                        break;
                    }
                }
                if (alreadyHasPerm)
                    continue;
                perms.Add(required);
                changed = true;
            }

            if (!changed)
                continue;

            UserAuth.SetPermissions(user, perms.ToArray());
            await UserAuth.SaveUserAsync(user, cancellationToken).ConfigureAwait(false);
            logger.LogInfo($"Updated root permissions for {UserAuth.GetUserName(user) ?? user.Key.ToString()}.");
        }
    }
    public static BareMetalWebServer CreateAppInfo(
        BmwConfig config,
        string contentRoot,
        IBufferedLogger logger,
        IHtmlRenderer htmlRenderer,
        IPageInfoFactory pageInfoFactory,
        IHtmlTemplate mainTemplate,
        IMetricsTracker metrics,
        IClientRequestTracker clientRequests,
        CancellationTokenSource cts)
        => new BareMetalWebServer(
            config.GetValue("AppInfo.Name", "BareMetalWeb"),
            config.GetValue("AppInfo.Company", "BareMetalWeb Inc."),
            config.GetValue("AppInfo.Copyright", "2026"),
            config,
            contentRoot,
            logger,
            htmlRenderer,
            pageInfoFactory.TemplatedPage(mainTemplate, 404, new[] { "title", "html_message" }, new[] { "404 - Not Found", "<p>The requested page was not found.</p>" }, "", true, 6000),
            pageInfoFactory.TemplatedPage(mainTemplate, 500, new[] { "title", "html_message" }, new[] { "500 - Internal Server Error", "<p>An unexpected error occurred.</p>" }, "", true, 6000),
            cts,
            metrics: metrics,
            clientRequests: clientRequests);

    public static void ConfigureStaticFiles(BmwConfig config, BareMetalWebServer appInfo)
    {
        var staticFileConfig = new StaticFileOptionsConfig
        {
            Enabled = config.GetValue("StaticFiles.Enabled", true),
            RequestPathPrefix = config.GetValue("StaticFiles.RequestPathPrefix", "/static"),
            RootDirectory = config.GetValue("StaticFiles.RootDirectory", "wwwroot/static"),
            EnableCaching = config.GetValue("StaticFiles.EnableCaching", true),
            CacheSeconds = config.GetValue("StaticFiles.CacheSeconds", 86400),
            AddETag = config.GetValue("StaticFiles.AddETag", true),
            AddLastModified = config.GetValue("StaticFiles.AddLastModified", true),
            AllowUnknownMime = config.GetValue("StaticFiles.AllowUnknownMime", false),
            DefaultMimeType = config.GetValue("StaticFiles.DefaultMimeType", "application/octet-stream"),
        };
        var staticFileOptions = StaticFileConfigOptions.FromConfig(staticFileConfig);
        staticFileOptions.Normalize();
        appInfo.StaticFiles = staticFileOptions;
    }
    public static void ConfigureCors(BmwConfig config, BareMetalWebServer appInfo)
    {
        appInfo.CorsAllowedOrigins = config.GetArray("Cors.AllowedOrigins");
    }

    public static void ConfigureHttps(BmwConfig config, BareMetalWebServer appInfo)
    {
        var redirectModeStr = config.GetValue("Https.RedirectMode", "IfAvailable");
        appInfo.HttpsRedirectMode = Enum.TryParse<HttpsRedirectMode>(redirectModeStr, true, out var mode)
            ? mode : HttpsRedirectMode.IfAvailable;
        appInfo.TrustForwardedHeaders = config.GetValue("Https.TrustForwardedHeaders", false);
        var httpsRedirectHost = config.GetValue("Https.RedirectHost", "");
        var httpsRedirectPort = config.GetValue("Https.RedirectPort", 0);

        if (!string.IsNullOrWhiteSpace(httpsRedirectHost))
        {
            appInfo.HttpsRedirectHost = httpsRedirectHost.Trim();
        }
        if (httpsRedirectPort > 0)
        {
            appInfo.HttpsRedirectPort = httpsRedirectPort;
        }
    }
    public static void ConfigureProxyRoutes(BmwConfig config, IBareWebHost appInfo, IBufferedLogger logger, IPageInfoFactory pageInfoFactory)
    {
        // BmwConfig doesn't support complex nested object binding, so we handle
        // the legacy single-route config (Proxy.Route + Proxy.TargetBaseUrl) directly.
        var proxyRoute = config.GetValue("Proxy.Route", "");
        var proxyTarget = config.GetValue("Proxy.TargetBaseUrl", "");
        if (!string.IsNullOrWhiteSpace(proxyRoute) && !string.IsNullOrWhiteSpace(proxyTarget))
        {
            var legacyRoute = new ProxyRouteConfig
            {
                Route = proxyRoute,
                TargetBaseUrl = proxyTarget
            };
            var proxyHandler = new ProxyRouteHandler(legacyRoute, logger);
            appInfo.RegisterRoute($"ALL {proxyRoute}", new RouteHandlerData(pageInfoFactory.RawPage("Public", false), proxyHandler.HandleAsync));
        }
    }

    /// <summary>
    /// Performs a loopback TLS handshake to pre-warm OpenSSL internals, certificate chain
    /// parsing, and SslStream state machine before the first real connection arrives.
    /// </summary>
    public static void WarmUpTls(System.Net.Security.SslServerAuthenticationOptions serverOptions)
    {
        try
        {
            using var server = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
            server.Start();
            var port = ((System.Net.IPEndPoint)server.LocalEndpoint).Port;

            var clientTask = Task.Run(async () =>
            {
                using var client = new System.Net.Sockets.TcpClient();
                await client.ConnectAsync(System.Net.IPAddress.Loopback, port);
                using var sslClient = new System.Net.Security.SslStream(client.GetStream(), false,
                    (_, _, _, _) => true); // accept self-signed for warmup
                await sslClient.AuthenticateAsClientAsync(new System.Net.Security.SslClientAuthenticationOptions
                {
                    TargetHost = "warmup",
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls13,
                });
            });

            using var accepted = server.AcceptTcpClient();
            using var sslServer = new System.Net.Security.SslStream(accepted.GetStream(), false);
            sslServer.AuthenticateAsServerAsync(serverOptions).GetAwaiter().GetResult();
            clientTask.GetAwaiter().GetResult();

            server.Stop();
            Console.WriteLine("[BMW TLS] Pre-warm handshake complete");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[BMW TLS] Pre-warm skipped: {ex.Message}");
        }
    }
}
