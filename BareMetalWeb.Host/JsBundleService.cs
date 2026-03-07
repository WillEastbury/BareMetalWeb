using BareMetalWeb.Core;
using System;
using System.Buffers;
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
    /// JS files to include in the legacy bundle, in dependency order.
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
        "BareMetalBinary.js",
        "BareMetalBind.js",
        "BareMetalTemplate.js",
        "BareMetalRendering.js",
        "theme-switcher.js",
        "vnext-app.js",
        "agent-panel.js"
    };

    /// <summary>The route path at which the legacy bundle is served.</summary>
    public const string BundlePath = "/static/js/bundle.js";

    /// <summary>The route path at which the VNext bundle is served.</summary>
    public const string VNextBundlePath = "/static/js/vnext-bundle.js";

    private sealed class BundleData
    {
        public byte[]? Bytes;
        public byte[]? BrotliBytes;
        public byte[]? GzipBytes;
        public string? ETag;
        public string LastModified = string.Empty;
    }

    private static readonly ConcurrentDictionary<string, BundleData> _bundles = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Characters that require special handling during minification. SIMD-accelerated via SearchValues.</summary>
    private static readonly SearchValues<char> s_jsSpecialChars = SearchValues.Create("\r\n\"'`/");

    /// <summary>
    /// Builds and caches the legacy and VNext JS bundles from files in <paramref name="jsDirectory"/>.
    /// Should be called once at application startup.
    /// </summary>
    public static void BuildBundle(string jsDirectory)
    {
        BuildNamedBundle(BundlePath, BundleFileOrder, jsDirectory);
        BuildNamedBundle(VNextBundlePath, VNextBundleFileOrder, jsDirectory);
    }

    private static void BuildNamedBundle(string path, string[] fileOrder, string jsDirectory)
    {
        var sb = new StringBuilder(16384);
        var latestWrite = DateTime.MinValue;

        foreach (var fileName in fileOrder)
        {
            var filePath = Path.Combine(jsDirectory, fileName);
            if (!File.Exists(filePath))
                continue;

            var writeTime = File.GetLastWriteTimeUtc(filePath);
            if (writeTime > latestWrite)
                latestWrite = writeTime;

            var content = File.ReadAllText(filePath, Encoding.UTF8);
            if (!fileName.EndsWith(".min.js", StringComparison.OrdinalIgnoreCase))
                content = MinifyJs(content);
            sb.Append("/* === ").Append(fileName).AppendLine(" === */");
            sb.AppendLine(content);
        }

        var bytes = Encoding.UTF8.GetBytes(sb.ToString());
        _bundles[path] = new BundleData
        {
            Bytes = bytes,
            BrotliBytes = CompressionHelper.CompressBrotli(bytes),
            GzipBytes = CompressionHelper.CompressGzip(bytes),
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
    /// Applies a simple, deterministic minification pass to JavaScript source text.
    /// <list type="bullet">
    ///   <item>Single-line comments (<c>//</c>) are stripped up to the end of the line.</item>
    ///   <item>Block comments (<c>/* … */</c>) are replaced with a single space so adjacent tokens are not merged.</item>
    ///   <item>Runs of more than one consecutive blank line are collapsed to a single newline.</item>
    ///   <item>CRLF line endings are normalised to LF.</item>
    ///   <item>Content inside string literals (single-quote, double-quote, template) is copied verbatim.</item>
    /// </list>
    /// Already-minified files (those whose name ends with <c>.min.js</c>) are passed through unchanged by the caller.
    /// </summary>
    internal static string MinifyJs(string source)
    {
        var sb = new StringBuilder(source.Length);
        var span = source.AsSpan();
        int i = 0;
        int consecutiveNewlines = 0;

        while (i < span.Length)
        {
            // SIMD fast path: bulk-copy plain text to next special character.
            // SearchValues<char> uses hardware SIMD (SSE/AVX on x64, NEON on ARM64).
            var remaining = span.Slice(i);
            int nextSpecial = remaining.IndexOfAny(s_jsSpecialChars);

            if (nextSpecial < 0)
            {
                sb.Append(remaining);
                break;
            }

            if (nextSpecial > 0)
            {
                sb.Append(remaining.Slice(0, nextSpecial));
                consecutiveNewlines = 0;
                i += nextSpecial;
            }

            char c = span[i];

            // Normalise CRLF → LF by skipping bare \r
            if (c == '\r') { i++; continue; }

            // String literals – copy verbatim so comment-like sequences inside are preserved
            if (c == '"' || c == '\'' || c == '`')
            {
                consecutiveNewlines = 0;
                char quote = c;
                sb.Append(c);
                i++;
                while (i < span.Length)
                {
                    // SIMD inner scan: find next quote, backslash, or newline
                    var litRemaining = span.Slice(i);
                    int nextLit = quote == '`'
                        ? litRemaining.IndexOfAny('\\', quote)
                        : litRemaining.IndexOfAny('\\', quote, '\n');

                    if (nextLit < 0)
                    {
                        sb.Append(litRemaining);
                        i = span.Length;
                        break;
                    }

                    if (nextLit > 0)
                    {
                        sb.Append(litRemaining.Slice(0, nextLit));
                        i += nextLit;
                    }

                    char sc = span[i];
                    if (sc == '\\' && i + 1 < span.Length)
                    {
                        sb.Append(sc);
                        i++;
                        sb.Append(span[i]);
                        i++;
                        continue;
                    }
                    sb.Append(sc);
                    i++;
                    if (sc == quote) break;
                    if (sc == '\n' && quote != '`') break;
                }
                continue;
            }

            // Line comment: skip to end of line (SIMD scan for newline)
            if (c == '/' && i + 1 < span.Length && span[i + 1] == '/')
            {
                i += 2;
                var commentRemaining = span.Slice(i);
                int nlIdx = commentRemaining.IndexOf('\n');
                i += nlIdx < 0 ? commentRemaining.Length : nlIdx;
                continue;
            }

            // Block comment: replace with one space (SIMD scan for *)
            if (c == '/' && i + 1 < span.Length && span[i + 1] == '*')
            {
                i += 2;
                while (i + 1 < span.Length)
                {
                    var blockRemaining = span.Slice(i);
                    int starIdx = blockRemaining.IndexOf('*');
                    if (starIdx < 0) { i = span.Length; break; }
                    i += starIdx;
                    if (i + 1 < span.Length && span[i + 1] == '/')
                    {
                        i += 2;
                        break;
                    }
                    i++;
                }
                sb.Append(' ');
                continue;
            }

            // Collapse runs of more than one consecutive blank line
            if (c == '\n')
            {
                consecutiveNewlines++;
                if (consecutiveNewlines <= 1) sb.Append(c);
                i++;
                continue;
            }

            // Regular slash (division/regex) — not followed by / or *
            consecutiveNewlines = 0;
            sb.Append(c);
            i++;
        }

        return sb.ToString();
    }

    /// <summary>
    /// Attempts to serve a JS bundle if the request path matches a known bundle path.
    /// Returns <c>true</c> if the path matched (response fully written); <c>false</c> otherwise.
    /// </summary>
    public static async Task<bool> TryServeAsync(BmwContext context)
    {
        var requestPath = context.HttpRequest.Path.Value ?? string.Empty;
        if (!_bundles.TryGetValue(requestPath, out var bundle))
            return false;

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

        context.Response.ContentType = "application/javascript; charset=utf-8";
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
            await context.ResponseBody.WriteAsync(responseBytes);

        return true;
    }
}
