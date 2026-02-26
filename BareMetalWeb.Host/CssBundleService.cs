using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text;
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
