using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Downloads (on first run), caches to disk, and serves per-theme CSS bundles
/// and the Bootstrap JS bundle from memory.
///
/// At startup <see cref="EnsureAssetsAsync"/> is called once.  It checks
/// whether the pre-built theme files are present on disk.  Any that are missing
/// are fetched directly from jsDelivr / Google Fonts, written to a local disk
/// cache, and loaded into memory for zero-allocation in-process serving on
/// subsequent requests.  Subsequent server restarts skip the download and load
/// straight from disk.
///
/// Theme bundles (Bootstrap Icons + Bootswatch theme + inlined Google Fonts)
/// are served at <c>/static/css/themes/{theme}.min.css</c>.
/// The Bootstrap JS bundle is saved to
/// <c>wwwroot/static/js/bootstrap.bundle.min.js</c> and served by the
/// static-file service.
/// </summary>
public static class CssBundleService
{
    // ── CDN coordinates ───────────────────────────────────────────────────────

    private const string BootswatchVersion     = "5.3.3";
    private const string BootstrapIconsVersion = "1.11.3";
    private const string BootstrapJsVersion    = "5.3.3";

    /// <summary>Themes available in the theme-selector dropdown.</summary>
    public static readonly string[] SupportedThemes =
        ["vapor", "darkly", "cyborg", "slate", "superhero", "flatly", "lux"];

    // ── Shared HTTP clients (app-lifetime singletons) ─────────────────────────
    // Static HttpClient instances are intentional here: the recommended pattern
    // for high-performance .NET is to share a single client per configuration for
    // the lifetime of the process to avoid socket exhaustion.

    private static readonly HttpClient _http = BuildHttpClient(
        "BareMetalWeb-AssetFetcher/1.0 (+https://github.com/WillEastbury/BareMetalWeb)");

    // Google Fonts only returns woff2 for modern browser user-agents
    private static readonly HttpClient _fontHttp = BuildHttpClient(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");

    private static HttpClient BuildHttpClient(string userAgent)
    {
        var client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
        return client;
    }

    // ── Pre-compiled regexes ──────────────────────────────────────────────────

    private static readonly Regex _googleFontsImportRe = new(
        @"@import\s+url\(\s*[""']?(https://fonts\.googleapis\.com[^""')]+)[""']?\s*\)\s*;?",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex _woff2UrlRe = new(
        @"url\(\s*[""']?(https://[^""')]+\.woff2[^""')*]*)[""']?\s*\)",
        RegexOptions.Compiled);

    private static readonly Regex _safeNameRe = new(
        @"[^a-zA-Z0-9.\-_]",
        RegexOptions.Compiled);

    // ── In-memory bundle cache ────────────────────────────────────────────────

    /// <summary>URL prefix under which theme bundles are served.</summary>
    public const string ThemePathPrefix = "/static/css/themes/";

    private sealed class BundleData
    {
        public byte[]? Bytes;
        public string? ETag;
        public string LastModified = string.Empty;
    }

    private static readonly ConcurrentDictionary<string, BundleData> _bundles =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary><c>true</c> when at least one theme bundle is loaded in memory.</summary>
    public static bool HasBundles => !_bundles.IsEmpty;

    /// <summary>Returns the names of themes currently loaded into memory (without extension).</summary>
    public static System.Collections.Generic.IEnumerable<string> LoadedThemes()
    {
        foreach (var key in _bundles.Keys)
        {
            var name = key[(ThemePathPrefix.Length)..];
            if (name.EndsWith(".min.css", StringComparison.OrdinalIgnoreCase))
                yield return name[..^".min.css".Length];
        }
    }

    // ── Startup entry point ───────────────────────────────────────────────────

    /// <summary>
    /// Downloads any missing CDN assets to the local disk cache, then loads all
    /// theme bundles into memory.  Idempotent — skips files that already exist
    /// on disk so subsequent restarts are instant.
    /// </summary>
    /// <param name="cssDirectory">Absolute path to <c>wwwroot/static/css</c>.</param>
    /// <param name="fontsDirectory">Absolute path to <c>wwwroot/static/fonts</c>.</param>
    /// <param name="jsDirectory">Absolute path to <c>wwwroot/static/js</c>.</param>
    /// <param name="log">Optional callback for progress / warning messages.</param>
    public static async Task EnsureAssetsAsync(
        string cssDirectory,
        string fontsDirectory,
        string jsDirectory,
        Action<string>? log = null)
    {
        var themesDir = Path.Combine(cssDirectory, "themes");
        Directory.CreateDirectory(themesDir);
        Directory.CreateDirectory(fontsDirectory);

        var missingThemes = SupportedThemes
            .Where(t => !File.Exists(Path.Combine(themesDir, $"{t}.min.css")))
            .ToArray();
        var missingJs = !File.Exists(Path.Combine(jsDirectory, "bootstrap.bundle.min.js"));

        if (missingThemes.Length > 0 || missingJs)
        {
            log?.Invoke($"[CssBundleService] Fetching CDN assets: {missingThemes.Length} theme(s), bootstrap-js={missingJs}…");

            // Bootstrap Icons CSS (shared prefix prepended to every theme bundle)
            string? iconsCss = null;
            if (missingThemes.Length > 0)
            {
                try   { iconsCss = await DownloadBootstrapIconsAsync(fontsDirectory, log); }
                catch (Exception ex) { log?.Invoke($"[CssBundleService] Warning – bootstrap-icons: {ex.Message}"); }
            }

            // Per-theme bundles
            foreach (var theme in missingThemes)
            {
                try
                {
                    await DownloadThemeBundleAsync(
                        theme,
                        Path.Combine(themesDir, $"{theme}.min.css"),
                        iconsCss ?? string.Empty,
                        fontsDirectory, log);
                    log?.Invoke($"[CssBundleService] Theme '{theme}' downloaded and cached.");
                }
                catch (Exception ex)
                {
                    log?.Invoke($"[CssBundleService] Warning – theme '{theme}': {ex.Message}");
                }
            }

            // Bootstrap JS bundle
            if (missingJs)
            {
                try
                {
                    await DownloadBootstrapJsAsync(Path.Combine(jsDirectory, "bootstrap.bundle.min.js"), log);
                    log?.Invoke("[CssBundleService] bootstrap.bundle.min.js downloaded and cached.");
                }
                catch (Exception ex)
                {
                    log?.Invoke($"[CssBundleService] Warning – bootstrap JS: {ex.Message}");
                }
            }
        }

        // Load whatever is on disk (may be partial if first-run download failed)
        BuildBundles(cssDirectory);

        if (!HasBundles)
            log?.Invoke("[CssBundleService] No theme bundles loaded — CSS requests will fall through to StaticFileService.");
    }

    /// <summary>
    /// Loads (or reloads) all <c>*.min.css</c> files from the <c>themes</c>
    /// sub-directory of <paramref name="cssDirectory"/> into the in-memory cache.
    /// </summary>
    public static void BuildBundles(string cssDirectory)
    {
        var themesDir = Path.Combine(cssDirectory, "themes");
        if (!Directory.Exists(themesDir)) return;

        foreach (var file in Directory.EnumerateFiles(themesDir, "*.min.css"))
        {
            // Skip internal intermediate files
            if (Path.GetFileName(file).StartsWith('_')) continue;
            try
            {
                var bytes     = File.ReadAllBytes(file);
                var lastWrite = File.GetLastWriteTimeUtc(file);
                var reqPath   = ThemePathPrefix + Path.GetFileName(file);

                _bundles[reqPath] = new BundleData
                {
                    Bytes        = bytes,
                    LastModified = lastWrite.ToString("R"),
                    ETag         = $"\"{ComputeETag(bytes)}\""
                };
            }
            catch { /* best-effort */ }
        }
    }

    // ── CDN download helpers ──────────────────────────────────────────────────

    private static async Task<string> DownloadBootstrapIconsAsync(
        string fontsDirectory, Action<string>? log)
    {
        var cssUrl  = $"https://cdn.jsdelivr.net/npm/bootstrap-icons@{BootstrapIconsVersion}/font/bootstrap-icons.min.css";
        var fontUrl = $"https://cdn.jsdelivr.net/npm/bootstrap-icons@{BootstrapIconsVersion}/font/fonts/bootstrap-icons.woff2";

        var css = await _http.GetStringAsync(cssUrl);

        var fontDest = Path.Combine(fontsDirectory, "bootstrap-icons.woff2");
        if (!File.Exists(fontDest))
        {
            var fontBytes = await _http.GetByteArrayAsync(fontUrl);
            await File.WriteAllBytesAsync(fontDest, fontBytes);
            log?.Invoke("[CssBundleService] Downloaded bootstrap-icons.woff2");
        }

        // Rewrite the relative ./fonts/bootstrap-icons.woff2?hash URL → local static path
        css = css.Replace("./fonts/bootstrap-icons.woff2", "/static/fonts/bootstrap-icons.woff2");
        css = css.Replace("fonts/bootstrap-icons.woff2",   "/static/fonts/bootstrap-icons.woff2");

        return css;
    }

    private static async Task DownloadThemeBundleAsync(
        string theme, string bundlePath, string iconsCss,
        string fontsDirectory, Action<string>? log)
    {
        var cssUrl = $"https://cdn.jsdelivr.net/npm/bootswatch@{BootswatchVersion}/dist/{theme}/bootstrap.min.css";
        var css    = await _http.GetStringAsync(cssUrl);

        // Replace any Google Fonts @import with inline @font-face blocks
        // Materialise matches before modifying the string
        var imports = _googleFontsImportRe.Matches(css).Cast<Match>().ToList();
        foreach (var m in imports)
        {
            try
            {
                var localFontCss = await LocaliseGoogleFontsAsync(m.Groups[1].Value, fontsDirectory, log);
                css = css.Replace(m.Value, localFontCss);
            }
            catch (Exception ex)
            {
                // Remove the broken import rather than leaving an external reference
                css = css.Replace(m.Value, $"/* Google Fonts import removed ({ex.Message}) */");
                log?.Invoke($"[CssBundleService] Warning – Google Fonts for '{theme}': {ex.Message}");
            }
        }

        var sb = new StringBuilder();
        sb.AppendLine($"/* bootstrap-icons@{BootstrapIconsVersion} — served locally */");
        sb.AppendLine(iconsCss);
        sb.AppendLine();
        sb.AppendLine($"/* bootswatch@{BootswatchVersion}/{theme} — served locally */");
        sb.Append(css);

        await File.WriteAllTextAsync(bundlePath, sb.ToString(), Encoding.UTF8);
    }

    private static async Task<string> LocaliseGoogleFontsAsync(
        string googleFontsUrl, string fontsDirectory, Action<string>? log)
    {
        // Fetch @font-face CSS — needs a modern browser UA to receive woff2 format
        var fontCss = await _fontHttp.GetStringAsync(googleFontsUrl);

        var woff2Re = _woff2UrlRe;
        var urls    = woff2Re.Matches(fontCss)
                             .Cast<Match>()
                             .Select(m => m.Groups[1].Value)
                             .Distinct(StringComparer.Ordinal)
                             .ToList();

        foreach (var woff2Url in urls)
        {
            var uri      = new Uri(woff2Url);
            var segments = uri.AbsolutePath.Trim('/').Split('/');
            var safeName = string.Join("-", segments.TakeLast(3));
            safeName     = _safeNameRe.Replace(safeName, "_");

            var localPath = Path.Combine(fontsDirectory, safeName);
            if (!File.Exists(localPath))
            {
                var fontBytes = await _http.GetByteArrayAsync(woff2Url);
                await File.WriteAllBytesAsync(localPath, fontBytes);
                log?.Invoke($"[CssBundleService] Downloaded font: {safeName}");
            }

            fontCss = fontCss.Replace(woff2Url, $"/static/fonts/{safeName}");
        }

        return fontCss;
    }

    private static async Task DownloadBootstrapJsAsync(string jsPath, Action<string>? log)
    {
        var url = $"https://cdn.jsdelivr.net/npm/bootstrap@{BootstrapJsVersion}/dist/js/bootstrap.bundle.min.js";
        var js  = await _http.GetStringAsync(url);
        await File.WriteAllTextAsync(jsPath, js, Encoding.UTF8);
    }

    // ── ETag helper ───────────────────────────────────────────────────────────

    private static string ComputeETag(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }

    // ── HTTP serving ──────────────────────────────────────────────────────────

    /// <summary>
    /// Serves a CSS theme bundle if the request path matches a known bundle.
    /// Returns <c>true</c> if the path matched (response fully written); <c>false</c> otherwise.
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

        context.Response.ContentType                = "text/css; charset=utf-8";
        context.Response.Headers.CacheControl       = "public, max-age=86400";
        context.Response.Headers.ETag               = bundle.ETag;
        context.Response.Headers.LastModified       = bundle.LastModified;
        context.Response.ContentLength              = bundle.Bytes.Length;

        if (HttpMethods.IsGet(context.Request.Method))
            await context.Response.Body.WriteAsync(bundle.Bytes);

        return true;
    }
}
