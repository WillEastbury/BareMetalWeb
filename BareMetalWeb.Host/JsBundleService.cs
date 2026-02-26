using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Runtime JS bundle service that concatenates static JS files into cached
/// bundles served as single requests to reduce round-trips.
/// Bundles are built once at application startup from the JS source files.
/// </summary>
public static class JsBundleService
{
    /// <summary>
    /// JS files to include in the SSR bundle, in dependency order.
    /// bootstrap.bundle.min.js must be first so Bootstrap is available to all subsequent scripts.
    /// </summary>
    public static readonly string[] BundleFileOrder = new[]
    {
        "bootstrap.bundle.min.js",
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

    /// <summary>
    /// JS files to include in the VNext SPA bundle, in dependency order.
    /// bootstrap.bundle.min.js must be first so Bootstrap is available to all subsequent scripts.
    /// </summary>
    public static readonly string[] VNextBundleFileOrder = new[]
    {
        "bootstrap.bundle.min.js",
        "BareMetalRouting.js",
        "BareMetalRest.js",
        "BareMetalBind.js",
        "BareMetalTemplate.js",
        "BareMetalRendering.js",
        "theme-switcher.js",
        "vnext-app.js"
    };

    /// <summary>The route path at which the SSR bundle is served.</summary>
    public const string BundlePath = "/static/js/bundle.js";

    /// <summary>The route path at which the VNext bundle is served.</summary>
    public const string VNextBundlePath = "/static/js/vnext-bundle.js";

    private sealed class BundleData
    {
        public byte[]? Bytes;
        public string? ETag;
        public string LastModified = string.Empty;
    }

    private static readonly ConcurrentDictionary<string, BundleData> _bundles = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Builds and caches the SSR and VNext JS bundles from files in <paramref name="jsDirectory"/>.
    /// Should be called once at application startup.
    /// </summary>
    public static void BuildBundle(string jsDirectory)
    {
        BuildNamedBundle(BundlePath, BundleFileOrder, jsDirectory);
        BuildNamedBundle(VNextBundlePath, VNextBundleFileOrder, jsDirectory);
    }

    private static void BuildNamedBundle(string path, string[] fileOrder, string jsDirectory)
    {
        var sb = new StringBuilder();
        var latestWrite = DateTime.MinValue;

        foreach (var fileName in fileOrder)
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

        var bytes = Encoding.UTF8.GetBytes(sb.ToString());
        _bundles[path] = new BundleData
        {
            Bytes = bytes,
            LastModified = (latestWrite == DateTime.MinValue ? DateTime.UtcNow : latestWrite).ToString("R"),
            ETag = $"\"{ComputeETag(bytes)}\""
        };
    }

    private static string ComputeETag(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }

    /// <summary>
    /// Attempts to serve a JS bundle if the request path matches a known bundle path.
    /// Returns <c>true</c> if the path matched (response fully written); <c>false</c> otherwise.
    /// </summary>
    public static async Task<bool> TryServeAsync(HttpContext context)
    {
        var requestPath = context.Request.Path.Value ?? string.Empty;
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

        context.Response.ContentType = "application/javascript; charset=utf-8";
        context.Response.Headers.CacheControl = "public, max-age=86400";
        context.Response.Headers.ETag = bundle.ETag;
        context.Response.Headers.LastModified = bundle.LastModified;
        context.Response.ContentLength = bundle.Bytes.Length;

        if (HttpMethods.IsGet(context.Request.Method))
            await context.Response.Body.WriteAsync(bundle.Bytes);

        return true;
    }
}
