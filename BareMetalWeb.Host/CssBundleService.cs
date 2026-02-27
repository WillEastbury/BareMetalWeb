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
    private static readonly HashSet<string> _knownThemes =
        new(DefaultThemes, StringComparer.OrdinalIgnoreCase);

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
    public static async Task<bool> TryServeAsync(HttpContext context)
    {
        var requestPath = context.Request.Path.Value ?? string.Empty;
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

        if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method))
        {
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            return true;
        }

        if (bundle.Bytes == null)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return true;
        }

        var ifNoneMatch = context.Request.Headers.IfNoneMatch.ToString();
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

        if (HttpMethods.IsGet(context.Request.Method))
            await context.Response.Body.WriteAsync(responseBytes);

        return true;
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// <summary>
    /// Downloads a single theme bundle on first request (lazy load).
    /// Uses <see cref="_staticRoot"/> to know where to persist the file.
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
            var bundle   = await BuildThemeBundleAsync(themeName, iconsCss).ConfigureAwait(false);

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
                RegexOptions.IgnoreCase);
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
            RegexOptions.IgnoreCase);

        return $"/* bootstrap-icons@{BootstrapIconsVersion} */\n{iconsCss}\n\n/* bootswatch@{BootswatchVersion} theme: {themeName} */\n{themeCss}";
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
