using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Pre-compressed in-memory asset cache for static files.
/// <para>
/// At startup <see cref="Build"/> scans the static root, Brotli- and Gzip-compresses
/// every compressible file, and packs all compressed variants contiguously into a
/// <strong>single large <c>byte[]</c> backing buffer</strong>.  Each file is then
/// represented by a <see cref="CacheEntry"/> containing three
/// <see cref="ReadOnlyMemory{T}"/> slices (raw / brotli / gzip) that point directly
/// into that backing array — no per-request allocation required.
/// </para>
/// <para>
/// During request handling <see cref="TryGetEntry"/> performs an O(1) dictionary
/// lookup.  <see cref="ServeAsync"/> writes the selected variant directly to the
/// Kestrel <see cref="System.IO.Pipelines.PipeWriter"/> (zero-copy socket write
/// path), setting <c>Content-Encoding</c>, <c>Content-Length</c>, and
/// <c>Cache-Control</c> headers automatically.
/// </para>
/// <para>
/// Versioned assets (filenames that contain a content-hash pattern such as
/// <c>site.a1b2c3d4.js</c>) receive <c>Cache-Control: public,max-age=31536000,immutable</c>.
/// All other assets receive the <c>CacheSeconds</c> value from
/// <see cref="StaticFileConfigOptions"/>.
/// </para>
/// </summary>
public static class StaticAssetCache
{
    /// <summary>
    /// Represents one cached file: three <see cref="ReadOnlyMemory{T}"/> slices
    /// into the shared backing buffer plus pre-computed HTTP metadata.
    /// </summary>
    public readonly struct CacheEntry
    {
        /// <summary>Uncompressed bytes.</summary>
        public readonly ReadOnlyMemory<byte> RawBytes;
        /// <summary>Brotli-compressed bytes (empty when compression ratio was unfavourable).</summary>
        public readonly ReadOnlyMemory<byte> BrotliBytes;
        /// <summary>Gzip-compressed bytes (empty when compression ratio was unfavourable).</summary>
        public readonly ReadOnlyMemory<byte> GzipBytes;
        /// <summary>MIME content-type string (e.g. <c>"text/css; charset=utf-8"</c>).</summary>
        public readonly string ContentType;
        /// <summary>Quoted ETag derived from the SHA-256 of the raw bytes.</summary>
        public readonly string ETag;
        /// <summary>RFC 7231 date string for <c>Last-Modified</c> header.</summary>
        public readonly string LastModified;
        /// <summary>
        /// <c>true</c> when the filename contains a content-hash pattern; these assets
        /// receive <c>Cache-Control: public,max-age=31536000,immutable</c>.
        /// </summary>
        public readonly bool IsVersioned;

        internal CacheEntry(
            ReadOnlyMemory<byte> raw,
            ReadOnlyMemory<byte> brotli,
            ReadOnlyMemory<byte> gzip,
            string contentType,
            string eTag,
            string lastModified,
            bool isVersioned)
        {
            RawBytes = raw;
            BrotliBytes = brotli;
            GzipBytes = gzip;
            ContentType = contentType;
            ETag = eTag;
            LastModified = lastModified;
            IsVersioned = isVersioned;
        }

        /// <summary>
        /// Returns the best available variant for the requested encoding:
        /// Brotli → Gzip → raw, falling back to raw when a compressed variant is
        /// empty (because compression was unfavourable for this file).
        /// </summary>
        public ReadOnlyMemory<byte> SelectVariant(string? encoding) => encoding switch
        {
            "br"   => BrotliBytes.IsEmpty ? RawBytes : BrotliBytes,
            "gzip" => GzipBytes.IsEmpty   ? RawBytes : GzipBytes,
            _      => RawBytes
        };

        /// <summary>
        /// Returns the effective encoding to advertise in <c>Content-Encoding</c>.
        /// Returns <c>null</c> when the requested encoding is unavailable and raw
        /// bytes will be sent instead.
        /// </summary>
        public string? EffectiveEncoding(string? requested) => requested switch
        {
            "br"   => BrotliBytes.IsEmpty ? null : "br",
            "gzip" => GzipBytes.IsEmpty   ? null : "gzip",
            _      => null
        };
    }

    // ── State ────────────────────────────────────────────────────────────────

    // Volatile reference swap for lock-free atomic rebuild.
    private static volatile IReadOnlyDictionary<string, CacheEntry> _entries =
        new Dictionary<string, CacheEntry>(StringComparer.OrdinalIgnoreCase);

    /// <summary><c>true</c> after the first successful <see cref="Build"/> call.</summary>
    public static bool IsBuilt { get; private set; }

    /// <summary>Number of entries currently loaded into the cache.</summary>
    public static int EntryCount => _entries.Count;

    // ── Build ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Scans <paramref name="rootPath"/> recursively, Brotli- and Gzip-compresses
    /// every compressible file, and stores all variants in a single contiguous byte
    /// buffer.  The previous cache (if any) is replaced atomically so in-flight
    /// requests are never interrupted.
    /// </summary>
    /// <param name="rootPath">Absolute path to the static file root directory.</param>
    /// <param name="options">Runtime options (MIME types, compression settings, size limits).</param>
    /// <param name="log">Optional log callback for diagnostic messages.</param>
    public static void Build(string rootPath, StaticFileConfigOptions options, Action<string>? log = null)
    {
        if (!Directory.Exists(rootPath))
        {
            // Clear to empty so a missing/misconfigured root doesn't leave stale entries
            Volatile.Write(ref _entries!, new Dictionary<string, CacheEntry>(StringComparer.OrdinalIgnoreCase));
            IsBuilt = true;
            log?.Invoke($"[StaticAssetCache] Root path not found, cache cleared: {rootPath}");
            return;
        }

        // ── Pass 1: collect raw + compressed bytes into lists ─────────────

        // Temporary list of (relativePath, raw, brotli, gzip, contentType, lastModified)
        var collected = new List<(string Key, byte[] Raw, byte[] Brotli, byte[] Gzip,
            string ContentType, string LastModified, bool IsVersioned)>();

        long totalBytes = 0;

        foreach (var filePath in Directory.EnumerateFiles(rootPath, "*", SearchOption.AllDirectories))
        {
            var relativePath = Path.GetRelativePath(rootPath, filePath)
                .Replace(Path.DirectorySeparatorChar, '/');

            if (IsExcluded(relativePath))
                continue;

            // Determine MIME type; skip unknown-MIME when AllowUnknownMime is false
            if (!options.ContentTypeProvider.TryGetContentType(filePath, out var contentType))
            {
                if (!options.AllowUnknownMime)
                    continue;
                contentType = options.DefaultMimeType;
            }

            FileInfo fi;
            try { fi = new FileInfo(filePath); }
            catch { continue; }

            if (!fi.Exists)
                continue;

            // Honour the per-file maximum size guard
            var maxBytes = options.InMemoryCacheMaxFileSizeBytes;
            if (maxBytes > 0 && fi.Length > maxBytes)
            {
                log?.Invoke($"[StaticAssetCache] Skipping oversized file ({fi.Length:N0} bytes): {relativePath}");
                continue;
            }

            byte[] raw;
            try { raw = File.ReadAllBytes(filePath); }
            catch { continue; }

            var lastModified = fi.LastWriteTimeUtc.ToString("R");
            var isVersioned  = IsVersionedPath(relativePath);
            var compressible = IsCompressible(contentType, options);

            byte[] brotliData = Array.Empty<byte>();
            byte[] gzipData   = Array.Empty<byte>();

            if (compressible && raw.Length >= options.MinBytesToCompress)
            {
                var br = CompressionHelper.CompressBrotli(raw);
                var gz = CompressionHelper.CompressGzip(raw);
                // Only keep compressed variant when it actually saves bytes
                if (br.Length < raw.Length) brotliData = br;
                if (gz.Length < raw.Length) gzipData   = gz;
            }

            totalBytes += raw.Length + brotliData.Length + gzipData.Length;
            collected.Add((relativePath, raw, brotliData, gzipData, contentType, lastModified, isVersioned));
        }

        // ── Pass 2: pack into a single contiguous backing buffer ──────────

        // Guard against absurdly large allocations (> 2 GB) to avoid OOM
        if (totalBytes > int.MaxValue)
        {
            log?.Invoke($"[StaticAssetCache] Total cache size ({totalBytes:N0} bytes) exceeds Int32.MaxValue; cache not built.");
            return;
        }

        var buffer = new byte[totalBytes];
        var newEntries = new Dictionary<string, CacheEntry>(collected.Count, StringComparer.OrdinalIgnoreCase);
        int cursor = 0;

        foreach (var item in collected)
        {
            // raw slice
            item.Raw.CopyTo(buffer, cursor);
            var rawSlice = new ReadOnlyMemory<byte>(buffer, cursor, item.Raw.Length);
            cursor += item.Raw.Length;

            // brotli slice (possibly empty)
            ReadOnlyMemory<byte> brotliSlice = ReadOnlyMemory<byte>.Empty;
            if (item.Brotli.Length > 0)
            {
                item.Brotli.CopyTo(buffer, cursor);
                brotliSlice = new ReadOnlyMemory<byte>(buffer, cursor, item.Brotli.Length);
                cursor += item.Brotli.Length;
            }

            // gzip slice (possibly empty)
            ReadOnlyMemory<byte> gzipSlice = ReadOnlyMemory<byte>.Empty;
            if (item.Gzip.Length > 0)
            {
                item.Gzip.CopyTo(buffer, cursor);
                gzipSlice = new ReadOnlyMemory<byte>(buffer, cursor, item.Gzip.Length);
                cursor += item.Gzip.Length;
            }

            var etag = $"\"{ComputeETag(item.Raw)}\"";
            var entry = new CacheEntry(rawSlice, brotliSlice, gzipSlice,
                item.ContentType, etag, item.LastModified, item.IsVersioned);

            // Key: normalized relative path, always forward-slash, no leading slash
            newEntries[item.Key] = entry;
        }

        // Atomic reference swap — in-flight reads from the old dictionary continue safely
        Volatile.Write(ref _entries!, newEntries);
        IsBuilt = true;

        log?.Invoke($"[StaticAssetCache] Loaded {newEntries.Count} entries " +
                    $"({totalBytes / 1024.0 / 1024.0:F1} MB total, " +
                    $"{buffer.Length / 1024.0 / 1024.0:F1} MB buffer).");
    }

    // ── Lookup ───────────────────────────────────────────────────────────────

    /// <summary>
    /// O(1) lookup by the relative path from the static root (e.g. <c>css/site.css</c>).
    /// </summary>
    public static bool TryGetEntry(string relativePath, out CacheEntry entry)
        => _entries.TryGetValue(relativePath, out entry);

    // ── Serve ────────────────────────────────────────────────────────────────

    /// <summary>
    /// Writes a cached entry to the HTTP response using the Kestrel
    /// <see cref="System.IO.Pipelines.PipeWriter"/> (zero-copy socket-write path).
    /// Sets <c>Content-Type</c>, <c>Content-Encoding</c>, <c>Content-Length</c>,
    /// <c>ETag</c>, <c>Last-Modified</c>, and <c>Cache-Control</c> headers.
    /// Does <strong>not</strong> write a body for HEAD requests.
    /// </summary>
    /// <param name="context">Current request context.</param>
    /// <param name="entry">The cache entry to serve.</param>
    /// <param name="requestedEncoding">
    /// The encoding selected by <see cref="CompressionHelper.SelectEncoding(BmwContext)"/>
    /// (<c>"br"</c>, <c>"gzip"</c>, or <c>null</c>).
    /// </param>
    /// <param name="options">Runtime options used for cache-control values.</param>
    public static async ValueTask ServeAsync(
        BmwContext context,
        CacheEntry entry,
        string? requestedEncoding,
        StaticFileConfigOptions options)
    {
        var effectiveEncoding = entry.EffectiveEncoding(requestedEncoding);
        var variant           = entry.SelectVariant(effectiveEncoding);

        context.Response.ContentType = entry.ContentType;

        if (!string.IsNullOrEmpty(effectiveEncoding))
        {
            context.Response.Headers.ContentEncoding = effectiveEncoding;
            context.Response.Headers.Append("Vary", "Accept-Encoding");
        }

        context.Response.ContentLength = variant.Length;
        context.Response.Headers.ETag         = entry.ETag;
        context.Response.Headers.LastModified = entry.LastModified;

        if (options.EnableCaching)
        {
            context.Response.Headers.CacheControl = entry.IsVersioned
                ? "public, max-age=31536000, immutable"
                : $"public, max-age={options.CacheSeconds}";
        }
        else
        {
            context.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
        }

        context.Response.StatusCode = StatusCodes.Status200OK;

        if (!HttpMethods.IsHead(context.HttpRequest.Method))
        {
            // Zero-copy: write the ReadOnlyMemory<byte> slice directly to the
            // Kestrel PipeWriter — no intermediate buffer or Stream wrapper.
            await context.ResponseBody.WriteAsync(variant);
        }
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private static bool IsExcluded(string relativePath)
    {
        var name = Path.GetFileName(relativePath);
        return name.StartsWith('.') ||
               name.EndsWith(".key", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsCompressible(string contentType, StaticFileConfigOptions options)
    {
        foreach (var prefix in options.CompressibleContentTypePrefixes)
        {
            if (contentType.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    // Heuristic: filenames that contain 8+ consecutive hex digits are assumed to be
    // content-addressed / versioned (e.g. site.a1b2c3d4e5f6.js) and get immutable
    // Cache-Control headers.
    private static readonly System.Text.RegularExpressions.Regex s_versionedPattern =
        new(@"[a-f0-9]{8,}", System.Text.RegularExpressions.RegexOptions.IgnoreCase |
                              System.Text.RegularExpressions.RegexOptions.Compiled);

    private static bool IsVersionedPath(string relativePath)
    {
        var name = Path.GetFileNameWithoutExtension(relativePath);
        return s_versionedPattern.IsMatch(name);
    }

    private static string ComputeETag(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return Convert.ToHexString(hash)[..16].ToLowerInvariant();
    }
}
