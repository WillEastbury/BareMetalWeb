namespace BareMetalWeb.Data;

/// <summary>
/// Well-known setting IDs stored in the <see cref="AppSetting"/> object store.
/// These replace direct reads from the configuration file so settings can be
/// managed at runtime without a deployment.
/// </summary>
public static class WellKnownSettings
{
    /// <summary>The display name of the application.</summary>
    public const string AppName = "app.name";

    /// <summary>The company name shown in the application header/footer.</summary>
    public const string AppCompany = "app.company";

    /// <summary>The copyright year or statement shown in the application footer.</summary>
    public const string AppCopyright = "app.copyright";

    /// <summary>The privacy policy URL shown as a link in the application footer. Leave empty to hide the link.</summary>
    public const string AppPrivacyPolicyUrl = "app.privacyPolicyUrl";

    // ── Kestrel / transport tuning ──────────────────────────────────────

    /// <summary>Enable HTTP/2 (true/false). Default: true.</summary>
    public const string KestrelHttp2Enabled = "kestrel.http2.enabled";

    /// <summary>Enable HTTP/3 (QUIC) (true/false). Default: false.</summary>
    public const string KestrelHttp3Enabled = "kestrel.http3.enabled";

    /// <summary>Max concurrent HTTP/2 streams per connection. Default: 100.</summary>
    public const string KestrelMaxStreamsPerConnection = "kestrel.http2.maxStreamsPerConnection";

    /// <summary>HTTP/2 initial connection window size in bytes. Default: 131072.</summary>
    public const string KestrelInitialConnectionWindowSize = "kestrel.http2.initialConnectionWindowSize";

    /// <summary>HTTP/2 initial per-stream window size in bytes. Default: 98304.</summary>
    public const string KestrelInitialStreamWindowSize = "kestrel.http2.initialStreamWindowSize";

    // ── Thread pool tuning ──────────────────────────────────────────────

    /// <summary>Minimum worker threads. Default: 0 (use runtime default).</summary>
    public const string ThreadPoolMinWorkerThreads = "threadpool.minWorkerThreads";

    /// <summary>Minimum I/O completion threads. Default: 0 (use runtime default).</summary>
    public const string ThreadPoolMinIOThreads = "threadpool.minIOThreads";

    // ── GC tuning ───────────────────────────────────────────────────────

    /// <summary>Enable server GC mode (true/false). Default: true.</summary>
    public const string GCServerMode = "gc.serverMode";

    // ── Admin ────────────────────────────────────────────────────────────

    /// <summary>
    /// The secret token required to trigger the wipe-all-data operation via
    /// <c>POST /admin/wipe-data</c>. When empty or absent the endpoint returns 419.
    /// </summary>
    public const string AllowWipeData = "AllowWipeData";
}
