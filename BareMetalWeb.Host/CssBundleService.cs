using BareMetalWeb.Core;
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Runtime CSS bundle service that loads pre-built per-theme CSS files into
/// memory at application startup and serves them as single cached responses.
///
/// Theme bundles are produced either by <c>tools/download-assets.js</c> or by
/// <see cref="EnsureAssetsAsync"/>, which downloads Bootswatch theme CSS,
/// Bootstrap Icons CSS/font, and writes self-contained per-theme CSS bundles into
/// <c>wwwroot/static/css/themes/</c>.
///
/// Each bundle is served at <c>/static/css/themes/{theme}.min.css</c>.
/// Any theme in <see cref="DefaultThemes"/> that is not yet on disk is
/// fetched lazily on the first request for that theme.
/// Custom themes (see <see cref="CustomThemeDefinitions"/>) layer CSS overrides
/// on top of an existing Bootswatch base theme and are also lazily built on first request.
/// </summary>
public static class CssBundleService
{
    /// <summary>URL prefix under which all theme bundles are served.</summary>
    public const string ThemePathPrefix = "/static/css/themes/";

    private const string BootswatchVersion     = "5.3.3";
    private const string BootstrapIconsVersion = "1.11.3";
    private const string BootstrapJsVersion    = "5.3.3";

    /// <summary>
    /// All supported Bootswatch themes — matches the allowlist in <c>index.head.html</c>.
    /// All are eagerly downloaded by <see cref="EnsureAssetsAsync"/> and are also
    /// available for lazy loading on first request.
    /// </summary>
    public static readonly string[] DefaultThemes =
    {
        "cerulean", "cosmo",    "cyborg",   "darkly",  "flatly",
        "journal",  "litera",   "lumen",    "lux",     "materia",
        "minty",    "morph",    "pulse",    "quartz",  "sandstone",
        "simplex",  "sketchy",  "slate",    "solar",   "spacelab",
        "superhero","united",   "vapor",    "yeti",    "zephyr"
    };

    /// <summary>
    /// Custom, exclusive themes that layer CSS overrides on top of a Bootswatch base theme.
    /// Key = theme name; Value = (base Bootswatch theme name, CSS overrides to append).
    /// </summary>
    public static readonly IReadOnlyDictionary<string, (string BaseTheme, string CustomCss)> CustomThemeDefinitions =
        new Dictionary<string, (string, string)>(StringComparer.OrdinalIgnoreCase)
        {
            // Jigsaw: muted, sensory-friendly palette for autistic users.
            // Soft slate-blue tones, reduced contrast, no harsh colours, minimal motion.
            ["jigsaw"] = ("lumen",
                """
                /* ── Jigsaw theme — muted, sensory-friendly ── */
                body{background-color:#F6F5F1!important;color:#3D4A52!important;line-height:1.75!important}
                a{color:#5C7A8E!important}a:hover{color:#3D5E70!important}
                .navbar,.navbar-dark,.navbar-light{background-color:#3D4A52!important;border-bottom:1px solid #2E3840!important}
                .navbar .navbar-brand,.navbar-dark .navbar-brand{color:#D8E4EA!important}
                .navbar .nav-link,.navbar-dark .nav-link{color:rgba(216,228,234,.85)!important}
                .btn-primary{background-color:#6B8D9E!important;border-color:#5A7A8A!important;color:#fff!important}
                .btn-primary:hover,.btn-primary:focus{background-color:#5A7A8A!important;border-color:#4A6878!important}
                .btn-secondary{background-color:#8B9BA8!important;border-color:#7A8A96!important;color:#fff!important}
                .btn-success{background-color:#78976B!important;border-color:#6A8660!important;color:#fff!important}
                .btn-danger{background-color:#9E6B6B!important;border-color:#8A5C5C!important;color:#fff!important}
                .btn-warning{background-color:#A8985E!important;border-color:#907E50!important;color:#fff!important}
                .btn-info{background-color:#6B9EA8!important;border-color:#5A8A93!important;color:#fff!important}
                .card{border-color:#D8D5D0!important;box-shadow:none!important}
                .card-header{background-color:#EDECE8!important;border-bottom-color:#D8D5D0!important}
                .form-control:focus{border-color:#8AAAB8!important;box-shadow:0 0 0 .25rem rgba(107,141,158,.25)!important}
                .badge.bg-primary{background-color:#6B8D9E!important}
                .alert-primary{background-color:#E4ECF0!important;border-color:#B8CEDC!important;color:#2C4A58!important}
                *,*::before,*::after{transition-duration:50ms!important;animation-duration:50ms!important}
                """),

            // Rave: neon colours on a near-black background — 80s dance-floor energy.
            ["rave"] = ("cyborg",
                """
                /* ── Rave theme — neon 80s dance culture ── */
                body{background-color:#06000E!important;color:#F0E8FF!important}
                .navbar,.navbar-dark{background:linear-gradient(90deg,#1A0030,#001A30)!important;border-bottom:2px solid #FF00CC!important}
                .navbar .navbar-brand,.navbar-dark .navbar-brand{color:#FF00CC!important;text-shadow:0 0 10px #FF00CC!important}
                .navbar .nav-link,.navbar-dark .nav-link{color:#00FFFF!important}
                .navbar .nav-link:hover,.navbar-dark .nav-link:hover{color:#FF00CC!important;text-shadow:0 0 8px #FF00CC!important}
                .btn-primary{background-color:#FF00CC!important;border-color:#FF00CC!important;color:#000!important;box-shadow:0 0 12px #FF00CC,0 0 30px rgba(255,0,204,.35)!important}
                .btn-primary:hover,.btn-primary:focus{background-color:#FF33DD!important;box-shadow:0 0 18px #FF00CC,0 0 45px rgba(255,0,204,.55)!important}
                .btn-secondary{background-color:#00FFFF!important;border-color:#00FFFF!important;color:#000!important;box-shadow:0 0 10px #00FFFF!important}
                .btn-success{background-color:#00FF66!important;border-color:#00FF66!important;color:#000!important;box-shadow:0 0 10px #00FF66!important}
                .btn-warning{background-color:#FFFF00!important;border-color:#FFFF00!important;color:#000!important}
                .btn-danger{background-color:#FF0040!important;border-color:#FF0040!important;color:#fff!important;box-shadow:0 0 12px #FF0040!important}
                .card{background-color:#0D001A!important;border:1px solid #FF00CC!important;box-shadow:0 0 15px rgba(255,0,204,.2)!important}
                .card-header{background-color:#1A0030!important;color:#FF00CC!important;border-bottom:1px solid #FF00CC!important}
                h1,h2,h3{color:#FF00CC!important;text-shadow:0 0 8px rgba(255,0,204,.55)!important}
                a{color:#00FFFF!important}a:hover{color:#FF00CC!important;text-shadow:0 0 8px #FF00CC!important}
                .form-control{background-color:#0D001A!important;color:#F0E8FF!important;border-color:#FF00CC!important}
                .form-control:focus{border-color:#00FFFF!important;box-shadow:0 0 0 .25rem rgba(0,255,255,.3)!important}
                .table{color:#F0E8FF!important}
                .table>:not(caption)>*>*{background-color:transparent!important;border-color:rgba(255,0,204,.3)!important}
                .badge.bg-primary{background-color:#FF00CC!important;color:#000!important}
                """),

            // Luminescent: deep-space dark with glowing cyan and violet — everything emits light.
            ["luminescent"] = ("darkly",
                """
                /* ── Luminescent theme — glowing, illuminated ── */
                body{background-color:#04060F!important;color:#B8F0FF!important}
                .navbar,.navbar-dark{background-color:#070A18!important;border-bottom:1px solid #00F0FF!important;box-shadow:0 2px 20px rgba(0,240,255,.3)!important}
                .navbar .navbar-brand,.navbar-dark .navbar-brand{color:#00F0FF!important;text-shadow:0 0 12px #00F0FF,0 0 25px rgba(0,240,255,.5)!important}
                .navbar .nav-link,.navbar-dark .nav-link{color:#B8F0FF!important}
                .navbar .nav-link:hover,.navbar-dark .nav-link:hover{color:#00F0FF!important;text-shadow:0 0 8px #00F0FF!important}
                .btn-primary{background-color:#00C8E0!important;border-color:#00B0C8!important;color:#000!important;box-shadow:0 0 12px #00C8E0,0 0 30px rgba(0,200,224,.4)!important}
                .btn-primary:hover,.btn-primary:focus{background-color:#00E8FF!important;box-shadow:0 0 20px #00E8FF,0 0 50px rgba(0,232,255,.5)!important}
                .btn-secondary{background-color:#7B00FF!important;border-color:#6A00E0!important;color:#fff!important;box-shadow:0 0 10px #7B00FF,0 0 25px rgba(123,0,255,.4)!important}
                .btn-success{background-color:#00FF88!important;border-color:#00E07A!important;color:#000!important;box-shadow:0 0 10px #00FF88!important}
                .btn-danger{background-color:#FF3060!important;border-color:#E02050!important;color:#fff!important;box-shadow:0 0 10px #FF3060!important}
                .btn-warning{background-color:#FFD700!important;border-color:#E8C000!important;color:#000!important;box-shadow:0 0 10px #FFD700!important}
                .btn-info{background-color:#00F0FF!important;border-color:#00D0E0!important;color:#000!important;box-shadow:0 0 10px #00F0FF!important}
                .card{background-color:#080B18!important;border:1px solid rgba(0,240,255,.35)!important;box-shadow:0 0 20px rgba(0,240,255,.15),inset 0 0 30px rgba(0,240,255,.05)!important}
                .card-header{background-color:#0D1228!important;color:#00F0FF!important;border-bottom:1px solid rgba(0,240,255,.35)!important;text-shadow:0 0 8px rgba(0,240,255,.6)!important}
                h1,h2,h3{color:#00F0FF!important;text-shadow:0 0 10px rgba(0,240,255,.6),0 0 25px rgba(0,240,255,.3)!important}
                a{color:#00C8E0!important}a:hover{color:#00F0FF!important;text-shadow:0 0 8px #00F0FF!important}
                .form-control{background-color:#080B18!important;color:#B8F0FF!important;border-color:rgba(0,240,255,.4)!important}
                .form-control:focus{border-color:#00F0FF!important;box-shadow:0 0 0 .25rem rgba(0,240,255,.3),0 0 15px rgba(0,240,255,.2)!important}
                .table{color:#B8F0FF!important}
                .table>:not(caption)>*>*{background-color:transparent!important;border-color:rgba(0,240,255,.2)!important}
                .badge.bg-primary{background-color:#00C8E0!important;color:#000!important}
                """),

            // Geography: cartographic palette — parchment, stone, slate and muted earth tones.
            ["geography"] = ("sandstone",
                """
                /* ── Geography theme — beige, stone and cartographic greys ── */
                body{background-color:#F2EDD8!important;color:#3A3328!important}
                .navbar,.navbar-dark,.navbar-light{background-color:#5C5545!important;border-bottom:1px solid #3A3328!important}
                .navbar .navbar-brand,.navbar-dark .navbar-brand{color:#F2EDD8!important}
                .navbar .nav-link,.navbar-dark .nav-link{color:rgba(242,237,216,.85)!important}
                .btn-primary{background-color:#6B7A5E!important;border-color:#5A6850!important;color:#fff!important}
                .btn-primary:hover,.btn-primary:focus{background-color:#5A6850!important;border-color:#4A5842!important}
                .btn-secondary{background-color:#8A7E6A!important;border-color:#7A6E5C!important;color:#fff!important}
                .btn-success{background-color:#5E7A5A!important;border-color:#507050!important;color:#fff!important}
                .btn-danger{background-color:#8A4A3A!important;border-color:#7A3A2C!important;color:#fff!important}
                .btn-warning{background-color:#9A7A3A!important;border-color:#886A30!important;color:#fff!important}
                .btn-info{background-color:#4A6A7A!important;border-color:#3C5C6A!important;color:#fff!important}
                .card{background-color:#F8F4E8!important;border:1px solid #C8C0A8!important;box-shadow:1px 1px 4px rgba(58,51,40,.15)!important}
                .card-header{background-color:#E8E0C8!important;border-bottom-color:#C8C0A8!important;color:#3A3328!important}
                a{color:#4A6070!important}a:hover{color:#2E4050!important}
                .form-control:focus{border-color:#8A9A7A!important;box-shadow:0 0 0 .25rem rgba(107,122,94,.25)!important}
                .table{color:#3A3328!important}
                .table>:not(caption)>*>*{border-color:#C8C0A8!important}
                .table-striped>tbody>tr:nth-of-type(odd)>*{background-color:rgba(107,122,94,.07)!important}
                .badge.bg-primary{background-color:#6B7A5E!important}
                .alert-primary{background-color:#DDE5D8!important;border-color:#A8B8A0!important;color:#2A3824!important}
                """),
        };

    private sealed class BundleData
    {
        public byte[]? Bytes;
        public byte[]? BrotliBytes;
        public byte[]? GzipBytes;
        public string? ETag;
        public string LastModified = string.Empty;
    }

    // keyed by request path, e.g. "/static/css/themes/vapor.min.css"
    private static readonly ConcurrentDictionary<string, BundleData> _bundles =
        new(StringComparer.OrdinalIgnoreCase);

    // Known themes as a set for O(1) lookup during lazy loading.
    // Includes both DefaultThemes (Bootswatch) and CustomThemeDefinitions keys.
    private static readonly HashSet<string> _knownThemes = BuildKnownThemes();

    // One Lazy<Task<bool>> per theme name; ensures each theme is fetched at most once.
    private static readonly ConcurrentDictionary<string, Lazy<Task<bool>>> _lazyLoads =
        new(StringComparer.OrdinalIgnoreCase);

    // Static root set by EnsureAssetsAsync; required for lazy loading.
    private static string? _staticRoot;

    // Shared HttpClient — reused across EnsureAssetsAsync and lazy loads to avoid socket exhaustion.
    private static readonly HttpClient _http = CreateHttpClient();

    // ── Public API ────────────────────────────────────────────────────────────

    /// <summary>
    /// Ensures all required static assets exist on disk, downloading any that are
    /// missing from the CDN. Then calls <see cref="BuildBundles"/> to load them
    /// into memory.
    ///
    /// Downloads:
    /// <list type="bullet">
    ///   <item><description><c>bootstrap.bundle.min.js</c> → <c>{staticRoot}/js/</c></description></item>
    ///   <item><description><c>bootstrap-icons.woff2</c> → <c>{staticRoot}/fonts/</c></description></item>
    ///   <item><description>Per-theme CSS bundles (all <see cref="DefaultThemes"/>) → <c>{staticRoot}/css/themes/</c></description></item>
    ///   <item><description>Custom theme CSS bundles (all <see cref="CustomThemeDefinitions"/>) → <c>{staticRoot}/css/themes/</c></description></item>
    /// </list>
    ///
    /// Safe to call at startup; skips files that already exist.
    /// Also stores <paramref name="staticRoot"/> so that
    /// <see cref="TryServeAsync"/> can lazily fetch any theme not yet cached.
    /// </summary>
    public static async Task EnsureAssetsAsync(string staticRoot, Action<string>? log = null)
    {
        _staticRoot = staticRoot;

        var cssDir    = Path.Combine(staticRoot, "css");
        var jsDir     = Path.Combine(staticRoot, "js");
        var themesDir = Path.Combine(cssDir, "themes");
        var fontsDir  = Path.Combine(staticRoot, "fonts");

        Directory.CreateDirectory(themesDir);
        Directory.CreateDirectory(fontsDir);

        // 1. bootstrap.bundle.min.js
        var bootstrapJsDest = Path.Combine(jsDir, "bootstrap.bundle.min.js");
        if (!File.Exists(bootstrapJsDest))
        {
            log?.Invoke("Downloading bootstrap.bundle.min.js...");
            try
            {
                var js = await _http.GetStringAsync(
                    $"https://cdn.jsdelivr.net/npm/bootstrap@{BootstrapJsVersion}/dist/js/bootstrap.bundle.min.js")
                    .ConfigureAwait(false);
                await File.WriteAllTextAsync(bootstrapJsDest, js, Encoding.UTF8).ConfigureAwait(false);
                log?.Invoke("  Saved bootstrap.bundle.min.js");
            }
            catch (Exception ex)
            {
                log?.Invoke($"  WARNING: Failed to download bootstrap.bundle.min.js: {ex.Message}");
            }
        }

        // 2. bootstrap-icons.woff2
        var iconsWoff2Dest = Path.Combine(fontsDir, "bootstrap-icons.woff2");
        if (!File.Exists(iconsWoff2Dest))
        {
            log?.Invoke("Downloading bootstrap-icons.woff2...");
            try
            {
                var bytes = await _http.GetByteArrayAsync(
                    $"https://cdn.jsdelivr.net/npm/bootstrap-icons@{BootstrapIconsVersion}/font/fonts/bootstrap-icons.woff2")
                    .ConfigureAwait(false);
                await File.WriteAllBytesAsync(iconsWoff2Dest, bytes).ConfigureAwait(false);
                log?.Invoke("  Saved bootstrap-icons.woff2");
            }
            catch (Exception ex)
            {
                log?.Invoke($"  WARNING: Failed to download bootstrap-icons.woff2: {ex.Message}");
            }
        }

        // 3. Per-theme CSS bundles — all DefaultThemes
        string? iconsCss = null;
        foreach (var theme in DefaultThemes)
        {
            var themeDest = Path.Combine(themesDir, $"{theme}.min.css");
            if (File.Exists(themeDest))
                continue;

            // Lazily fetch bootstrap-icons CSS once (only when at least one theme is missing).
            iconsCss ??= await FetchIconsCssAsync(log).ConfigureAwait(false);

            try
            {
                log?.Invoke($"Downloading theme: {theme}...");
                var bundle = await BuildThemeBundleAsync(theme, iconsCss).ConfigureAwait(false);
                await File.WriteAllTextAsync(themeDest, bundle, Encoding.UTF8).ConfigureAwait(false);
                log?.Invoke($"  Saved theme bundle: {theme}.min.css");
            }
            catch (Exception ex)
            {
                log?.Invoke($"  WARNING: Failed to download theme {theme}: {ex.Message}");
            }
        }

        // 4. Custom exclusive themes — layer CSS overrides on top of a Bootswatch base
        foreach (var (themeName, _) in CustomThemeDefinitions)
        {
            var themeDest = Path.Combine(themesDir, $"{themeName}.min.css");
            if (File.Exists(themeDest))
                continue;

            iconsCss ??= await FetchIconsCssAsync(log).ConfigureAwait(false);

            try
            {
                log?.Invoke($"Building custom theme: {themeName}...");
                var bundle = await BuildCustomThemeBundleAsync(themeName, iconsCss).ConfigureAwait(false);
                await File.WriteAllTextAsync(themeDest, bundle, Encoding.UTF8).ConfigureAwait(false);
                log?.Invoke($"  Saved custom theme bundle: {themeName}.min.css");
            }
            catch (Exception ex)
            {
                log?.Invoke($"  WARNING: Failed to build custom theme {themeName}: {ex.Message}");
            }
        }

        // Load whatever is now on disk into the in-memory bundle cache.
        BuildBundles(cssDir);
    }

    /// <summary>
    /// Scans <paramref name="cssDirectory"/> for a <c>themes</c> sub-directory and
    /// loads every <c>*.min.css</c> file found into the in-memory bundle cache.
    /// Safe to call multiple times; existing entries are replaced.
    /// </summary>
    public static void BuildBundles(string cssDirectory)
    {
        var themesDir = Path.Combine(cssDirectory, "themes");
        if (!Directory.Exists(themesDir))
            return;

        foreach (var file in Directory.EnumerateFiles(themesDir, "*.min.css"))
        {
            try
            {
                var bytes = File.ReadAllBytes(file);
                var lastWrite = File.GetLastWriteTimeUtc(file);
                var fileName = Path.GetFileName(file); // e.g. "vapor.min.css"
                var requestPath = ThemePathPrefix + fileName; // "/static/css/themes/vapor.min.css"

                _bundles[requestPath] = new BundleData
                {
                    Bytes = bytes,
                    BrotliBytes = CompressionHelper.CompressBrotli(bytes),
                    GzipBytes = CompressionHelper.CompressGzip(bytes),
                    LastModified = lastWrite.ToString("R"),
                    ETag = $"\"{ComputeETag(bytes)}\""
                };
            }
            catch
            {
                // Best-effort: skip files that cannot be read at startup.
            }
        }
    }

    /// <summary>Returns the names of themes that have been loaded (without extension).</summary>
    public static System.Collections.Generic.IEnumerable<string> LoadedThemes()
    {
        foreach (var key in _bundles.Keys)
        {
            var name = key[(ThemePathPrefix.Length)..]; // e.g. "vapor.min.css"
            if (name.EndsWith(".min.css", StringComparison.OrdinalIgnoreCase))
                yield return name[..^".min.css".Length];
        }
    }

    /// <summary>Returns <c>true</c> if at least one theme bundle has been loaded.</summary>
    public static bool HasBundles => !_bundles.IsEmpty;

    /// <summary>
    /// Attempts to serve a CSS theme bundle for the request path.
    /// If the path matches a known theme that has not yet been cached, the theme
    /// is fetched from CDN lazily (first-hit download) before serving.
    /// Returns <c>true</c> if the path was handled (response fully written);
    /// <c>false</c> if the path is not a theme bundle path.
    /// </summary>
    public static async Task<bool> TryServeAsync(BmwContext context)
    {
        var requestPath = context.HttpRequest.Path.Value ?? string.Empty;
        if (!requestPath.StartsWith(ThemePathPrefix, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!_bundles.TryGetValue(requestPath, out var bundle))
        {
            // Attempt a lazy first-hit load if this is a known theme and we have
            // a staticRoot to save to (set by EnsureAssetsAsync).
            var themeName = TryExtractThemeName(requestPath);
            if (themeName != null && _knownThemes.Contains(themeName) && _staticRoot != null)
            {
                var lazyLoad = _lazyLoads.GetOrAdd(
                    themeName,
                    name => new Lazy<Task<bool>>(() => LazyFetchAndLoadThemeAsync(name)));

                var loaded = await lazyLoad.Value.ConfigureAwait(false);
                if (!loaded || !_bundles.TryGetValue(requestPath, out bundle))
                    return false;
            }
            else
            {
                return false;
            }
        }

        if (!HttpMethods.IsGet(context.HttpRequest.Method) && !HttpMethods.IsHead(context.HttpRequest.Method))
        {
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            return true;
        }

        if (bundle.Bytes == null)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return true;
        }

        var ifNoneMatch = context.HttpRequest.Headers.IfNoneMatch.ToString();
        if (!string.IsNullOrEmpty(ifNoneMatch) && ifNoneMatch == bundle.ETag)
        {
            context.Response.StatusCode = StatusCodes.Status304NotModified;
            return true;
        }

        context.Response.ContentType = "text/css; charset=utf-8";
        context.Response.Headers.CacheControl = "public, max-age=31536000, immutable";
        context.Response.Headers.ETag = bundle.ETag;
        context.Response.Headers.LastModified = bundle.LastModified;

        var encoding = CompressionHelper.SelectEncoding(context);
        var rawBytes = bundle.Bytes!; // confirmed non-null above
        var responseBytes = encoding switch
        {
            "br"   => bundle.BrotliBytes ?? rawBytes,
            "gzip" => bundle.GzipBytes   ?? rawBytes,
            _      => rawBytes
        };

        CompressionHelper.ApplyHeaders(context.Response, encoding);
        context.Response.ContentLength = responseBytes.Length;

        if (HttpMethods.IsGet(context.HttpRequest.Method))
            await context.Response.Body.WriteAsync(responseBytes);

        return true;
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// <summary>
    /// Downloads a single theme bundle on first request (lazy load).
    /// Uses <see cref="_staticRoot"/> to know where to persist the file.
    /// Handles both standard Bootswatch themes and custom themes from
    /// <see cref="CustomThemeDefinitions"/>.
    /// </summary>
    private static async Task<bool> LazyFetchAndLoadThemeAsync(string themeName)
    {
        if (_staticRoot == null)
            return false;

        var cssDir    = Path.Combine(_staticRoot, "css");
        var themesDir = Path.Combine(cssDir, "themes");
        var fontsDir  = Path.Combine(_staticRoot, "fonts");
        var themeDest = Path.Combine(themesDir, $"{themeName}.min.css");

        // If it was written between the TryServeAsync check and now, just reload.
        if (File.Exists(themeDest))
        {
            BuildBundles(cssDir);
            return _bundles.ContainsKey(ThemePathPrefix + $"{themeName}.min.css");
        }

        try
        {
            Directory.CreateDirectory(themesDir);
            Directory.CreateDirectory(fontsDir);

            // Ensure icons font is present.
            var iconsWoff2Dest = Path.Combine(fontsDir, "bootstrap-icons.woff2");
            if (!File.Exists(iconsWoff2Dest))
            {
                var woff2 = await _http.GetByteArrayAsync(
                    $"https://cdn.jsdelivr.net/npm/bootstrap-icons@{BootstrapIconsVersion}/font/fonts/bootstrap-icons.woff2")
                    .ConfigureAwait(false);
                await File.WriteAllBytesAsync(iconsWoff2Dest, woff2).ConfigureAwait(false);
            }

            var iconsCss = await FetchIconsCssAsync(null).ConfigureAwait(false);

            // Custom themes layer overrides on a base Bootswatch theme; standard themes
            // are downloaded directly from the Bootswatch CDN.
            string bundle;
            if (CustomThemeDefinitions.ContainsKey(themeName))
                bundle = await BuildCustomThemeBundleAsync(themeName, iconsCss).ConfigureAwait(false);
            else
                bundle = await BuildThemeBundleAsync(themeName, iconsCss).ConfigureAwait(false);

            await File.WriteAllTextAsync(themeDest, bundle, Encoding.UTF8).ConfigureAwait(false);
            BuildBundles(cssDir);
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Downloads bootstrap-icons CSS and rewrites font paths to local static paths.</summary>
    private static async Task<string> FetchIconsCssAsync(Action<string>? log)
    {
        try
        {
            log?.Invoke("Downloading bootstrap-icons CSS...");
            var raw = await _http.GetStringAsync(
                $"https://cdn.jsdelivr.net/npm/bootstrap-icons@{BootstrapIconsVersion}/font/bootstrap-icons.min.css")
                .ConfigureAwait(false);
            return Regex.Replace(raw,
                @"url\(\s*[""']?\.?/?fonts/bootstrap-icons\.woff2[^""')]*[""']?\s*\)",
                "url('/static/fonts/bootstrap-icons.woff2')",
                RegexOptions.IgnoreCase | RegexOptions.Compiled);
        }
        catch (Exception ex)
        {
            log?.Invoke($"  WARNING: Failed to download bootstrap-icons CSS: {ex.Message}");
            return string.Empty;
        }
    }

    /// <summary>
    /// Downloads a Bootswatch theme and combines it with <paramref name="iconsCss"/>
    /// into a single self-contained bundle string.
    /// </summary>
    private static async Task<string> BuildThemeBundleAsync(string themeName, string iconsCss)
    {
        var themeCss = await _http.GetStringAsync(
            $"https://cdn.jsdelivr.net/npm/bootswatch@{BootswatchVersion}/dist/{themeName}/bootstrap.min.css")
            .ConfigureAwait(false);

        // Strip Google Fonts @import — blocked by CSP (font-src 'self').
        themeCss = Regex.Replace(themeCss,
            @"@import\s+url\(\s*[""']?https://fonts\.googleapis\.com[^""')]*[""']?\s*\)\s*;?",
            string.Empty,
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        return $"/* bootstrap-icons@{BootstrapIconsVersion} */\n{iconsCss}\n\n/* bootswatch@{BootswatchVersion} theme: {themeName} */\n{themeCss}";
    }

    /// <summary>
    /// Builds a custom exclusive theme bundle by downloading a base Bootswatch theme
    /// and appending the custom CSS overrides defined in <see cref="CustomThemeDefinitions"/>.
    /// </summary>
    private static async Task<string> BuildCustomThemeBundleAsync(string themeName, string iconsCss)
    {
        var (baseTheme, customCss) = CustomThemeDefinitions[themeName];

        var baseThemeCss = await _http.GetStringAsync(
            $"https://cdn.jsdelivr.net/npm/bootswatch@{BootswatchVersion}/dist/{baseTheme}/bootstrap.min.css")
            .ConfigureAwait(false);

        // Strip Google Fonts @import — blocked by CSP (font-src 'self').
        baseThemeCss = Regex.Replace(baseThemeCss,
            @"@import\s+url\(\s*[""']?https://fonts\.googleapis\.com[^""')]*[""']?\s*\)\s*;?",
            string.Empty,
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        return $"/* bootstrap-icons@{BootstrapIconsVersion} */\n{iconsCss}\n\n/* bootswatch@{BootswatchVersion} base theme: {baseTheme} */\n{baseThemeCss}\n\n/* bmw custom theme: {themeName} */\n{customCss}";
    }

    /// <summary>
    /// Builds the complete set of known theme names, combining <see cref="DefaultThemes"/>
    /// (Bootswatch) and <see cref="CustomThemeDefinitions"/> (exclusive custom themes).
    /// </summary>
    private static HashSet<string> BuildKnownThemes()
    {
        var set = new HashSet<string>(DefaultThemes, StringComparer.OrdinalIgnoreCase);
        foreach (var key in CustomThemeDefinitions.Keys)
            set.Add(key);
        return set;
    }

    /// <summary>
    /// Extracts the theme name from a request path like
    /// <c>/static/css/themes/vapor.min.css</c> → <c>"vapor"</c>.
    /// Returns <c>null</c> if the path does not match the expected pattern.
    /// </summary>
    private static string? TryExtractThemeName(string requestPath)
    {
        if (!requestPath.StartsWith(ThemePathPrefix, StringComparison.OrdinalIgnoreCase))
            return null;
        var name = requestPath[ThemePathPrefix.Length..];
        if (!name.EndsWith(".min.css", StringComparison.OrdinalIgnoreCase))
            return null;
        return name[..^".min.css".Length];
    }

    private static string ComputeETag(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }

    private static HttpClient CreateHttpClient()
    {
        var client = new HttpClient();
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (compatible; BareMetalWeb/1.0)");
        client.Timeout = TimeSpan.FromSeconds(30);
        return client;
    }
}
