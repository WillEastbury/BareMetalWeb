using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Runtime JS bundle service that concatenates all static JS files into a single
/// cached bundle, served at /static/js/bundle.js to reduce round-trips.
/// The bundle is built once at application startup from the JS source files.
/// </summary>
public static class JsBundleService
{
    /// <summary>
    /// JS files to include in the bundle, in dependency order.
    /// This matches the order scripts were previously loaded in index.footer.html.
    /// </summary>
    public static readonly string[] BundleFileOrder = new[]
    {
        "theme-switcher.js",
        "timezone.js",
        "image-preview.js",
        "lookup-helper.js",
        "remote-command.js",
        "tree-view.js",
        "bmw-lookup.js",
        "calculated-fields.js",
        "bulk-operations.js",
        "form-validation.js",
        "toast.js",
        "otp.js",
        "gantt-view.js"
    };

    /// <summary>The route path at which the bundle is served.</summary>
    public const string BundlePath = "/static/js/bundle.js";

    private static byte[]? _bundleBytes;
    private static string? _eTag;
    private static string _lastModified = string.Empty;

    /// <summary>
    /// Builds and caches the JS bundle from files in <paramref name="jsDirectory"/>.
    /// Should be called once at application startup.
    /// Files listed in <see cref="BundleFileOrder"/> that do not exist are silently skipped.
    /// </summary>
    public static void BuildBundle(string jsDirectory)
    {
        var sb = new StringBuilder();
        var latestWrite = DateTime.MinValue;

        foreach (var fileName in BundleFileOrder)
        {
            var filePath = Path.Combine(jsDirectory, fileName);
            if (!File.Exists(filePath))
                continue;

            var writeTime = File.GetLastWriteTimeUtc(filePath);
            if (writeTime > latestWrite)
                latestWrite = writeTime;

            sb.Append("/* === ").Append(fileName).AppendLine(" === */");
            sb.AppendLine(File.ReadAllText(filePath, Encoding.UTF8));
        }

        _bundleBytes = Encoding.UTF8.GetBytes(sb.ToString());
        _lastModified = (latestWrite == DateTime.MinValue ? DateTime.UtcNow : latestWrite).ToString("R");
        _eTag = $"\"{ComputeETag(_bundleBytes)}\"";
    }

    private static string ComputeETag(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }

    /// <summary>
    /// Attempts to serve the JS bundle if the request path matches <see cref="BundlePath"/>.
    /// Returns <c>true</c> if the path matched (response fully written); <c>false</c> otherwise.
    /// </summary>
    public static async Task<bool> TryServeAsync(HttpContext context)
    {
        if (!context.Request.Path.Equals(BundlePath, StringComparison.OrdinalIgnoreCase))
            return false;

        if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method))
        {
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            return true;
        }

        if (_bundleBytes == null)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return true;
        }

        var ifNoneMatch = context.Request.Headers.IfNoneMatch.ToString();
        if (!string.IsNullOrEmpty(ifNoneMatch) && ifNoneMatch == _eTag)
        {
            context.Response.StatusCode = StatusCodes.Status304NotModified;
            return true;
        }

        context.Response.ContentType = "application/javascript; charset=utf-8";
        context.Response.Headers.CacheControl = "public, max-age=86400";
        context.Response.Headers.ETag = _eTag;
        context.Response.Headers.LastModified = _lastModified;
        context.Response.ContentLength = _bundleBytes.Length;

        if (HttpMethods.IsGet(context.Request.Method))
            await context.Response.Body.WriteAsync(_bundleBytes);

        return true;
    }
}
