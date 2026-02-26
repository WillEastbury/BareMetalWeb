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
/// Theme bundles are produced by the <c>tools/download-assets.js</c> script
/// which downloads Bootswatch theme CSS, Bootstrap Icons CSS, and all referenced
/// Google Font files, then writes self-contained per-theme CSS bundles into
/// <c>wwwroot/static/css/themes/</c>.
///
/// Each bundle is served at <c>/static/css/themes/{theme}.min.css</c>.
/// </summary>
public static class CssBundleService
{
    /// <summary>URL prefix under which all theme bundles are served.</summary>
    public const string ThemePathPrefix = "/static/css/themes/";

    private const string BootswatchVersion      = "5.3.3";
    private const string BootstrapIconsVersion  = "1.11.3";
    private const string BootstrapJsVersion     = "5.3.3";

    /// <summary>Themes downloaded and bundled by <see cref="EnsureAssetsAsync"/>.</summary>
    public static readonly string[] DefaultThemes =
        { "vapor", "darkly", "cyborg", "slate", "superhero", "flatly", "lux" };

    private sealed class BundleData
    {
        public byte[]? Bytes;
        public string? ETag;
        public string LastModified = string.Empty;
    }

    // keyed by request path, e.g. "/static/css/themes/vapor.min.css"
    private static readonly ConcurrentDictionary<string, BundleData> _bundles =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Ensures all required static assets exist on disk, downloading any that are missing
    /// from the CDN. Then calls <see cref="BuildBundles"/> to load them into memory.
    ///
    /// Downloads:
    /// <list type="bullet">
    ///   <item><description><c>bootstrap.bundle.min.js</c> → <c>{staticRoot}/js/</c></description></item>
    ///   <item><description><c>bootstrap-icons.woff2</c> → <c>{staticRoot}/fonts/</c></description></item>
    ///   <item><description>Per-theme CSS bundles → <c>{staticRoot}/css/themes/</c></description></item>
    /// </list>
    ///
    /// Safe to call at startup; skips files that already exist.
    /// </summary>
    public static async Task EnsureAssetsAsync(string staticRoot, Action<string>? log = null)
    {
        var cssDir    = Path.Combine(staticRoot, "css");
        var jsDir     = Path.Combine(staticRoot, "js");
        var themesDir = Path.Combine(cssDir, "themes");
        var fontsDir  = Path.Combine(staticRoot, "fonts");

        Directory.CreateDirectory(themesDir);
        Directory.CreateDirectory(fontsDir);

        using var http = new HttpClient();
        http.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (compatible; BareMetalWeb/1.0)");
        http.Timeout = TimeSpan.FromSeconds(30);

        // 1. bootstrap.bundle.min.js
        var bootstrapJsDest = Path.Combine(jsDir, "bootstrap.bundle.min.js");
        if (!File.Exists(bootstrapJsDest))
        {
            log?.Invoke("Downloading bootstrap.bundle.min.js...");
            try
            {
                var js = await http.GetStringAsync(
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
                var bytes = await http.GetByteArrayAsync(
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

        // 3. Per-theme CSS bundles
        string? iconsCss = null;
        foreach (var theme in DefaultThemes)
        {
            var themeDest = Path.Combine(themesDir, $"{theme}.min.css");
            if (File.Exists(themeDest))
                continue;

            // Lazily download bootstrap-icons CSS (only when at least one theme is missing).
            if (iconsCss == null)
            {
                try
                {
                    log?.Invoke("Downloading bootstrap-icons CSS...");
                    var raw = await http.GetStringAsync(
                        $"https://cdn.jsdelivr.net/npm/bootstrap-icons@{BootstrapIconsVersion}/font/bootstrap-icons.min.css")
                        .ConfigureAwait(false);
                    // Rewrite relative font paths to the locally-served absolute path.
                    iconsCss = Regex.Replace(raw,
                        @"url\(\s*[""']?\.?/?fonts/bootstrap-icons\.woff2[^""')]*[""']?\s*\)",
                        "url('/static/fonts/bootstrap-icons.woff2')",
                        RegexOptions.IgnoreCase);
                }
                catch (Exception ex)
                {
                    log?.Invoke($"  WARNING: Failed to download bootstrap-icons CSS: {ex.Message}");
                    iconsCss = string.Empty;
                }
            }

            try
            {
                log?.Invoke($"Downloading theme: {theme}...");
                var themeCss = await http.GetStringAsync(
                    $"https://cdn.jsdelivr.net/npm/bootswatch@{BootswatchVersion}/dist/{theme}/bootstrap.min.css")
                    .ConfigureAwait(false);

                // Strip Google Fonts @import — blocked by CSP (font-src 'self').
                themeCss = Regex.Replace(themeCss,
                    @"@import\s+url\(\s*[""']?https://fonts\.googleapis\.com[^""')]*[""']?\s*\)\s*;?",
                    string.Empty,
                    RegexOptions.IgnoreCase);

                var bundle = $"/* bootstrap-icons@{BootstrapIconsVersion} */\n{iconsCss}\n\n/* bootswatch@{BootswatchVersion} theme: {theme} */\n{themeCss}";
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

    /// <summary>
    /// Returns <c>true</c> if at least one theme bundle has been loaded.
    /// </summary>
    public static bool HasBundles => !_bundles.IsEmpty;

    private static string ComputeETag(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }

    /// <summary>
    /// Attempts to serve a CSS theme bundle if the request path matches a known
    /// bundle path.  Returns <c>true</c> if the path matched (response fully
    /// written); <c>false</c> otherwise.
    /// </summary>
    public static async Task<bool> TryServeAsync(HttpContext context)
    {
        var requestPath = context.Request.Path.Value ?? string.Empty;
        if (!requestPath.StartsWith(ThemePathPrefix, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!_bundles.TryGetValue(requestPath, out var bundle))
            return false;

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
        context.Response.Headers.CacheControl = "public, max-age=86400";
        context.Response.Headers.ETag = bundle.ETag;
        context.Response.Headers.LastModified = bundle.LastModified;
        context.Response.ContentLength = bundle.Bytes.Length;

        if (HttpMethods.IsGet(context.Request.Method))
            await context.Response.Body.WriteAsync(bundle.Bytes);

        return true;
    }
}
