using System;
using System.Buffers;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Host;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.FileProviders;
namespace BareMetalWeb.Host;

public static class StaticFileService
{
    private const string BytesUnit = "bytes";
    private static readonly IReadOnlyList<FileRange> EmptyRanges = Array.Empty<FileRange>();
    private static readonly TimeSpan MetadataCacheDuration = TimeSpan.FromSeconds(30);

    public static async Task<bool> TryServeAsync(HttpContext context, StaticFileConfigOptions? options)
    {
        if (options == null || !options.Enabled)
            return false;

        var requestPath = context.Request.Path.Value ?? "/";
        var prefix = string.IsNullOrWhiteSpace(options.NormalizedRequestPathPrefix)
            ? options.RequestPathPrefix
            : options.NormalizedRequestPathPrefix;

        if (!requestPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return false;

        if (requestPath.Length > prefix.Length &&
            requestPath[prefix.Length] != '/')
        {
            return false;
        }

        if (!HttpMethods.IsGet(context.Request.Method) && !HttpMethods.IsHead(context.Request.Method))
        {
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            return true;
        }

        var relativePath = requestPath[prefix.Length..].TrimStart('/');
        if (string.IsNullOrWhiteSpace(relativePath))
        {
            relativePath = string.Empty;
        }

        if (ContainsDotSegment(relativePath) || IsKeyPath(relativePath))
        {
            await WriteNotFound(context);
            return true;
        }

        var rootPath = string.IsNullOrWhiteSpace(options.RootPathFull)
            ? ResolveRootPath(options.RootDirectory)
            : options.RootPathFull;
        var fullPath = ResolveFullPath(rootPath, relativePath);
        if (fullPath == null)
        {
            await WriteNotFound(context);
            return true;
        }

        if (Directory.Exists(fullPath))
        {
            if (TryResolveDefaultFile(options, rootPath, relativePath, out var defaultPath, out var defaultRelative))
            {
                fullPath = defaultPath;
                relativePath = defaultRelative;
            }
            else if (options.EnableDirectoryBrowsing)
            {
                await WriteDirectoryListing(context, rootPath, relativePath, options);
                return true;
            }
            else
            {
                await WriteNotFound(context);
                return true;
            }
        }

        if (IsKeyPath(relativePath))
        {
            await WriteNotFound(context);
            return true;
        }

        var compressionSelection = context.Request.Headers.AcceptEncoding.Count == 0
            ? CompressionSelection.None
            : SelectCompression(context, options);
        if (compressionSelection.IsNotAcceptable)
        {
            context.Response.StatusCode = StatusCodes.Status406NotAcceptable;
            return true;
        }

        var (servePath, contentTypePath, contentEncoding, precompressed) = ResolvePrecompressedPath(fullPath, compressionSelection);
        var relativeServePath = Path.GetRelativePath(rootPath, servePath);
        var relativeContentTypePath = Path.GetRelativePath(rootPath, contentTypePath);

        if (!TryGetFileMetadata(options, servePath, relativeServePath, contentTypePath, relativeContentTypePath, out var metadata))
        {
            await WriteNotFound(context);
            return true;
        }

        var lastModifiedUtc = metadata.LastWriteTimeUtc;
        var etag = options.AddETag ? metadata.ETag : null;

        if (options.EnableCaching)
        {
            if (options.AddLastModified)
                context.Response.Headers.LastModified = lastModifiedUtc.ToString("R");

            if (options.AddETag && etag != null)
                context.Response.Headers.ETag = etag;

            var hasConditionals =
                context.Request.Headers.IfMatch.Count > 0 ||
                context.Request.Headers.IfUnmodifiedSince.Count > 0 ||
                context.Request.Headers.IfNoneMatch.Count > 0 ||
                context.Request.Headers.IfModifiedSince.Count > 0;

            if (hasConditionals && !EvaluatePreconditions(context, lastModifiedUtc, etag))
            {
                context.Response.StatusCode = StatusCodes.Status412PreconditionFailed;
                return true;
            }

            if (hasConditionals && IsNotModified(context, lastModifiedUtc, etag))
            {
                context.Response.StatusCode = StatusCodes.Status304NotModified;
                return true;
            }

            var maxAge = options.CacheSeconds <= 0 ? 0 : options.CacheSeconds;
            context.Response.Headers.CacheControl = $"public, max-age={maxAge}";
            if (options.AddExpiresHeader && maxAge > 0)
            {
                context.Response.Headers.Expires = DateTimeOffset.UtcNow.AddSeconds(maxAge).ToString("R");
            }
        }
        else
        {
            context.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
            context.Response.Headers.Pragma = "no-cache";
        }

        var contentType = metadata.ContentType;
        if (string.IsNullOrWhiteSpace(contentType))
        {
            if (!options.AllowUnknownMime)
            {
                if (options.HideUnknownMimeFiles)
                {
                    await WriteNotFound(context);
                }
                else
                {
                    context.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
                    context.Response.ContentType = "text/plain; charset=utf-8";
                    await context.Response.WriteAsync("Unsupported media type.");
                }
                return true;
            }

            contentType = options.DefaultMimeType;
        }

        context.Response.ContentType = contentType;
        context.Response.Headers.AcceptRanges = BytesUnit;
        if (!string.IsNullOrWhiteSpace(contentEncoding))
        {
            context.Response.Headers.ContentEncoding = contentEncoding;
            context.Response.Headers.Append("Vary", "Accept-Encoding");
        }

        var allowDynamicCompression = options.EnableDynamicCompression
            && !precompressed
            && string.IsNullOrWhiteSpace(contentEncoding)
            && IsCompressibleContentType(options, contentType)
            && metadata.Length >= options.MinBytesToCompress;

        RangeRequestResult rangeResult;
        IReadOnlyList<FileRange> ranges;
        if (context.Request.Headers.Range.Count == 0)
        {
            rangeResult = RangeRequestResult.NotRange;
            ranges = EmptyRanges;
        }
        else
        {
            rangeResult = TryGetRanges(context, metadata.Length, lastModifiedUtc, etag, options.MaxRanges, out var rangeList);
            ranges = rangeList;
        }
        if (precompressed && !options.AllowRangeOnPrecompressed)
        {
            rangeResult = RangeRequestResult.NotRange;
            ranges = EmptyRanges;
        }

        if (rangeResult == RangeRequestResult.Invalid)
        {
            context.Response.StatusCode = StatusCodes.Status416RangeNotSatisfiable;
            context.Response.Headers.ContentRange = $"{BytesUnit} */{metadata.Length}";
            return true;
        }

        if (rangeResult == RangeRequestResult.Single && ranges.Count == 1)
        {
            var range = ranges[0];
            context.Response.StatusCode = StatusCodes.Status206PartialContent;
            context.Response.Headers.ContentRange = $"{BytesUnit} {range.Start}-{range.End}/{metadata.Length}";
            context.Response.ContentLength = range.Length;

            if (HttpMethods.IsHead(context.Request.Method))
                return true;

            await context.Response.SendFileAsync(servePath, range.Start, range.Length);
            return true;
        }

        if (rangeResult == RangeRequestResult.Multipart && ranges.Count > 1)
        {
            var boundary = "range_" + Guid.NewGuid().ToString("N");
            context.Response.StatusCode = StatusCodes.Status206PartialContent;
            context.Response.ContentType = $"multipart/byteranges; boundary={boundary}";
            context.Response.Headers.AcceptRanges = BytesUnit;

            if (HttpMethods.IsHead(context.Request.Method))
                return true;

            await WriteMultipartRangesAsync(context, servePath, contentType, metadata.Length, boundary, ranges);
            return true;
        }

        context.Response.StatusCode = StatusCodes.Status200OK;

        if (allowDynamicCompression && compressionSelection.Kind != CompressionKind.None)
        {
            context.Response.Headers.ContentEncoding = compressionSelection.Kind == CompressionKind.Brotli ? "br" : "gzip";
            context.Response.Headers.Append("Vary", "Accept-Encoding");

            if (HttpMethods.IsHead(context.Request.Method))
                return true;

            await using var fileStream = new FileStream(servePath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan | FileOptions.Asynchronous);
            Stream compressionStream = compressionSelection.Kind == CompressionKind.Brotli
                ? new BrotliStream(context.Response.Body, CompressionLevel.Fastest, leaveOpen: true)
                : new GZipStream(context.Response.Body, CompressionLevel.Fastest, leaveOpen: true);
            await using (compressionStream)
            {
                await fileStream.CopyToAsync(compressionStream, 64 * 1024, context.RequestAborted);
            }
            return true;
        }

        context.Response.ContentLength = metadata.Length;

        if (HttpMethods.IsHead(context.Request.Method))
            return true;

        await context.Response.SendFileAsync(servePath, 0, null);
        return true;
    }

    private static bool TryGetContentType(StaticFileConfigOptions options, string fullPath, out string contentType)
    {
        var provider = options.ContentTypeProvider ?? new FileExtensionContentTypeProvider();
        if (provider.TryGetContentType(fullPath, out var mapped) && !string.IsNullOrWhiteSpace(mapped))
        {
            contentType = mapped;
            return true;
        }

        if (options.AllowUnknownMime && !string.IsNullOrWhiteSpace(options.DefaultMimeType))
        {
            contentType = options.DefaultMimeType;
            return true;
        }

        contentType = string.Empty;
        return false;
    }

    // contentTypePath can differ from fullPath when serving precompressed files (.br/.gz) but using original extension for content type.
    private static bool TryGetFileMetadata(StaticFileConfigOptions options, string fullPath, string relativeFullPath, string contentTypePath, string relativeContentTypePath, out FileMetadata metadata)
    {
        metadata = default;
        var cacheKey = BuildMetadataCacheKey(fullPath, contentTypePath);
        var now = DateTime.UtcNow;
        if (options.MetadataCache.TryGetValue(cacheKey, out FileMetadata cached) && cached.ExpiresUtc > now)
        {
            metadata = cached;
            return true;
        }

        IFileInfo? fileInfo = null;
        FileInfo? localInfo = null;
        if (options.FileProvider != null)
        {
            fileInfo = options.FileProvider.GetFileInfo(relativeFullPath);
            if (!fileInfo.Exists)
            {
                options.MetadataCache.Remove(cacheKey);
                return false;
            }
        }
        else
        {
            localInfo = new FileInfo(fullPath);
            if (!localInfo.Exists)
            {
                options.MetadataCache.Remove(cacheKey);
                return false;
            }
        }

        var lastModifiedUtc = fileInfo?.LastModified.UtcDateTime ?? localInfo!.LastWriteTimeUtc;
        var length = fileInfo?.Length ?? localInfo!.Length;

        if (!TryGetContentType(options, contentTypePath, out var contentType))
        {
            contentType = options.AllowUnknownMime ? options.DefaultMimeType : string.Empty;
        }

        metadata = new FileMetadata(
            length,
            lastModifiedUtc,
            BuildETag(lastModifiedUtc, length),
            contentType,
            now.Add(MetadataCacheDuration)
        );

        var entry = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = MetadataCacheDuration,
            Size = 1
        };

        if (options.FileProvider != null)
        {
            entry.AddExpirationToken(options.FileProvider.Watch(relativeFullPath));
            if (!string.Equals(relativeFullPath, relativeContentTypePath, StringComparison.OrdinalIgnoreCase))
            {
                entry.AddExpirationToken(options.FileProvider.Watch(relativeContentTypePath));
            }
        }

        options.MetadataCache.Set(cacheKey, metadata, entry);
        return true;
    }

    private static bool IsNotModified(HttpContext context, DateTime lastModifiedUtc, string? etag)
    {
        var ifNoneMatch = context.Request.Headers.IfNoneMatch.ToString();
        var hasIfNoneMatch = !string.IsNullOrWhiteSpace(ifNoneMatch);
        if (hasIfNoneMatch && !string.IsNullOrWhiteSpace(etag))
        {
            if (string.Equals(ifNoneMatch, "*", StringComparison.Ordinal))
                return true;

            if (TryParseEtags(ifNoneMatch, out var tags))
            {
                if (tags.Any(tag => WeakEtagEquals(tag, etag)))
                    return true;
            }
            else if (string.Equals(ifNoneMatch, etag, StringComparison.Ordinal))
            {
                return true;
            }
        }

        if (hasIfNoneMatch)
            return false;

        if (context.Request.Headers.IfModifiedSince.Count > 0)
        {
            if (DateTimeOffset.TryParse(context.Request.Headers.IfModifiedSince.ToString(), out var modifiedSince))
            {
                var lastModified = new DateTimeOffset(lastModifiedUtc);
                if (modifiedSince >= lastModified)
                    return true;
            }
        }

        return false;
    }

    private static bool EvaluatePreconditions(HttpContext context, DateTime lastModifiedUtc, string? etag)
    {
        var ifMatch = context.Request.Headers.IfMatch.ToString();
        if (!string.IsNullOrWhiteSpace(ifMatch))
        {
            if (string.Equals(ifMatch, "*", StringComparison.Ordinal))
                return true;

            if (string.IsNullOrWhiteSpace(etag))
                return false;

            if (TryParseEtags(ifMatch, out var tags))
            {
                if (!tags.Any(tag => StrongEtagEquals(tag, etag)))
                    return false;
            }
            else if (!string.Equals(ifMatch, etag, StringComparison.Ordinal))
            {
                return false;
            }
        }

        if (context.Request.Headers.IfUnmodifiedSince.Count > 0)
        {
            if (DateTimeOffset.TryParse(context.Request.Headers.IfUnmodifiedSince.ToString(), out var unmodifiedSince))
            {
                var lastModified = new DateTimeOffset(lastModifiedUtc);
                if (lastModified > unmodifiedSince)
                    return false;
            }
        }

        return true;
    }

    private static string ResolveRootPath(string rootDirectory)
    {
        var baseDir = AppContext.BaseDirectory;
        var root = Path.IsPathRooted(rootDirectory)
            ? rootDirectory
            : Path.Combine(baseDir, rootDirectory);
        return Path.GetFullPath(root);
    }

    private static string? ResolveFullPath(string rootPath, string relativePath)
    {
        var safeRelative = relativePath.Replace('/', Path.DirectorySeparatorChar);
        var combined = Path.GetFullPath(Path.Combine(rootPath, safeRelative));
        if (!combined.StartsWith(rootPath, StringComparison.OrdinalIgnoreCase))
            return null;

        return combined;
    }

    private static bool ContainsDotSegment(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath))
            return false;

        var segments = relativePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        foreach (var segment in segments)
        {
            if (IsDotName(segment))
                return true;
        }

        return false;
    }

    private static bool IsKeyPath(string relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath))
            return false;

        var trimmed = relativePath.TrimEnd('/');
        if (trimmed.Length == 0)
            return false;

        var name = Path.GetFileName(trimmed);
        return name.EndsWith(".key", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsDotName(string name)
    {
        return name.StartsWith(".", StringComparison.Ordinal);
    }

    private static bool TryResolveDefaultFile(StaticFileConfigOptions options, string rootPath, string relativePath, out string fullPath, out string resolvedRelative)
    {
        fullPath = string.Empty;
        resolvedRelative = string.Empty;

        if (options.DefaultFiles.Count == 0)
            return false;

        var basePath = string.IsNullOrWhiteSpace(relativePath)
            ? string.Empty
            : relativePath.TrimEnd('/') + Path.DirectorySeparatorChar;

        foreach (var candidate in options.DefaultFiles)
        {
            if (string.IsNullOrWhiteSpace(candidate))
                continue;

            var combined = basePath + candidate.TrimStart('/', '\\');
            var combinedFull = ResolveFullPath(rootPath, combined);
            if (combinedFull == null)
                continue;

            if (File.Exists(combinedFull))
            {
                fullPath = combinedFull;
                resolvedRelative = combined.Replace(Path.DirectorySeparatorChar, '/');
                return true;
            }
        }

        return false;
    }

    private static async Task WriteDirectoryListing(HttpContext context, string rootPath, string relativePath, StaticFileConfigOptions options)
    {
        var targetPath = ResolveFullPath(rootPath, relativePath);
        if (targetPath == null || !Directory.Exists(targetPath))
        {
            await WriteNotFound(context);
            return;
        }

        context.Response.StatusCode = StatusCodes.Status200OK;
        context.Response.ContentType = "text/html; charset=utf-8";

        var builder = new StringBuilder();
        builder.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>Index of ");
        builder.Append(WebUtility.HtmlEncode("/" + relativePath.Trim('/')));
        builder.Append("</title></head><body><h1>Index of ");
        builder.Append(WebUtility.HtmlEncode("/" + relativePath.Trim('/')));
        builder.Append("</h1><ul>");

        if (!string.IsNullOrWhiteSpace(relativePath))
        {
            builder.Append("<li><a href=\"../\">../</a></li>");
        }

        var entries = Directory.EnumerateFileSystemEntries(targetPath)
            .Select(path => new { Path = path, Name = Path.GetFileName(path) ?? string.Empty, IsDir = Directory.Exists(path) })
            .Where(entry => !string.IsNullOrWhiteSpace(entry.Name));

        entries = entries.Where(entry => !IsDotName(entry.Name));
        entries = entries.Where(entry => entry.IsDir || !entry.Name.EndsWith(".key", StringComparison.OrdinalIgnoreCase));

        if (options.DirectoryListingSortDirectoriesFirst)
        {
            entries = entries.OrderByDescending(entry => entry.IsDir).ThenBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase);
        }

        int count = 0;
        foreach (var entry in entries)
        {
            if (options.DirectoryListingMaxEntries > 0 && count >= options.DirectoryListingMaxEntries)
                break;

            if (options.DirectoryListingHideUnknownMime && !entry.IsDir)
            {
                if (!TryGetContentType(options, entry.Path, out _))
                    continue;
            }

            var displayName = entry.IsDir ? entry.Name + "/" : entry.Name;
            var href = Uri.EscapeDataString(displayName);
            builder.Append("<li><a href=\"");
            builder.Append(href);
            builder.Append("\">");
            builder.Append(WebUtility.HtmlEncode(displayName));
            builder.Append("</a></li>");
            count++;
        }

        builder.Append("</ul></body></html>");
        await context.Response.WriteAsync(builder.ToString());
    }

    private static string BuildETag(DateTime lastWriteUtc, long length)
    {
        var lastWrite = lastWriteUtc.Ticks.ToString("x");
        var size = length.ToString("x");
        return $"\"{lastWrite}-{size}\"";
    }

    private static RangeRequestResult TryGetRanges(HttpContext context, long fileLength, DateTime lastModifiedUtc, string? etag, int maxRanges, out List<FileRange> ranges)
    {
        ranges = new List<FileRange>();
        if (context.Request.Headers.Range.Count == 0)
            return RangeRequestResult.NotRange;

        var rangeHeader = context.Request.Headers.Range.ToString();
        if (string.IsNullOrWhiteSpace(rangeHeader))
            return RangeRequestResult.NotRange;

        if (!rangeHeader.StartsWith(BytesUnit + "=", StringComparison.OrdinalIgnoreCase))
            return RangeRequestResult.Invalid;

        // If-Range mismatch/outdated: ignore Range and fall back to full response.
        if (ShouldIgnoreRange(context, lastModifiedUtc, etag))
            return RangeRequestResult.NotRange;

        var raw = rangeHeader.AsSpan()[(BytesUnit.Length + 1)..];
        var index = 0;
        var length = raw.Length;

        while (index < length)
        {
            while (index < length && (raw[index] == ',' || char.IsWhiteSpace(raw[index])))
                index++;

            if (index >= length)
                break;

            var segmentStart = index;
            while (index < length && raw[index] != ',')
                index++;

            var segment = Trim(raw[segmentStart..index]);
            if (segment.Length == 0)
                return RangeRequestResult.Invalid;

            var dash = segment.IndexOf('-');
            if (dash < 0)
                return RangeRequestResult.Invalid;

            var left = Trim(segment[..dash]);
            var right = Trim(segment[(dash + 1)..]);

            if (left.Length == 0)
            {
                if (!TryParseInt64(right, out var suffixLength) || suffixLength <= 0)
                    return RangeRequestResult.Invalid;

                var start = Math.Max(0, fileLength - suffixLength);
                var end = fileLength - 1;
                ranges.Add(new FileRange(start, end));
                continue;
            }

            if (!TryParseInt64(left, out var rangeStart) || rangeStart < 0)
                return RangeRequestResult.Invalid;

            long rangeEnd;
            if (right.Length == 0)
            {
                rangeEnd = fileLength - 1;
            }
            else if (!TryParseInt64(right, out rangeEnd) || rangeEnd < rangeStart)
            {
                return RangeRequestResult.Invalid;
            }

            if (rangeStart >= fileLength)
                return RangeRequestResult.Invalid;

            rangeEnd = Math.Min(rangeEnd, fileLength - 1);
            ranges.Add(new FileRange(rangeStart, rangeEnd));
        }

        if (ranges.Count == 0)
            return RangeRequestResult.Invalid;

        ranges.Sort((a, b) => a.Start.CompareTo(b.Start));
        var merged = new List<FileRange>(ranges.Count);
        foreach (var range in ranges)
        {
            if (merged.Count == 0)
            {
                merged.Add(range);
                continue;
            }

            var last = merged[^1];
            if (range.Start <= last.End + 1)
            {
                merged[^1] = new FileRange(last.Start, Math.Max(last.End, range.End));
            }
            else
            {
                merged.Add(range);
            }
        }

        if (maxRanges > 0 && merged.Count > maxRanges)
            return RangeRequestResult.Invalid;

        ranges = merged;
        return ranges.Count == 1 ? RangeRequestResult.Single : RangeRequestResult.Multipart;
    }

    private static bool ShouldIgnoreRange(HttpContext context, DateTime lastModifiedUtc, string? etag)
    {
        var ifRange = context.Request.Headers.IfRange.ToString();
        if (string.IsNullOrWhiteSpace(ifRange))
            return false;

        if (!string.IsNullOrWhiteSpace(etag) && (StrongEtagEquals(ifRange, etag) || WeakEtagEquals(ifRange, etag)))
            return false;

        if (DateTimeOffset.TryParse(ifRange, out var ifRangeDate))
        {
            var lastModified = new DateTimeOffset(lastModifiedUtc);
            return ifRangeDate < lastModified;
        }

        return true;
    }

    private readonly record struct FileRange(long Start, long End)
    {
        public static readonly FileRange Invalid = new(-1, -1);
        public bool IsValid => Start >= 0 && End >= Start;
        public long Length => End - Start + 1;
    }

    private enum RangeRequestResult
    {
        NotRange,
        Invalid,
        Single,
        Multipart
    }

    private readonly record struct FileMetadata(
        long Length,
        DateTime LastWriteTimeUtc,
        string ETag,
        string ContentType,
        DateTime ExpiresUtc
    );

    private static CompressionSelection SelectCompression(HttpContext context, StaticFileConfigOptions options)
    {
        var header = context.Request.Headers.AcceptEncoding.ToString();
        if (string.IsNullOrWhiteSpace(header))
            return CompressionSelection.None;

        GetEncodingQualities(header, out var brQ, out var gzipQ, out var identityQ, out var starQ);

        var br = brQ > 0 ? brQ : starQ;
        var gzip = gzipQ > 0 ? gzipQ : starQ;
        var identity = identityQ > 0 ? identityQ : starQ;

        if (br <= 0 && gzip <= 0 && identity <= 0)
            return CompressionSelection.NotAcceptable;

        if (options.PreferBrotli && br >= gzip && br > 0)
            return new CompressionSelection(CompressionKind.Brotli);

        if (gzip > 0)
            return new CompressionSelection(CompressionKind.Gzip);

        if (br > 0)
            return new CompressionSelection(CompressionKind.Brotli);

        return CompressionSelection.None;
    }

    private static (string ServePath, string ContentTypePath, string? ContentEncoding, bool Precompressed) ResolvePrecompressedPath(string fullPath, CompressionSelection selection)
    {
        if (selection.Kind == CompressionKind.Brotli)
        {
            var brPath = fullPath + ".br";
            if (File.Exists(brPath))
                return (brPath, fullPath, "br", true);
        }

        if (selection.Kind == CompressionKind.Gzip)
        {
            var gzPath = fullPath + ".gz";
            if (File.Exists(gzPath))
                return (gzPath, fullPath, "gzip", true);
        }

        return (fullPath, fullPath, null, false);
    }

    private static bool IsCompressibleContentType(StaticFileConfigOptions options, string contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
            return false;

        var value = contentType.Split(';', 2)[0].Trim();
        return options.CompressibleContentTypePrefixes.Any(prefix => value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
    }

    private static void GetEncodingQualities(string header, out double brQ, out double gzipQ, out double identityQ, out double starQ)
    {
        brQ = 0;
        gzipQ = 0;
        identityQ = 0;
        starQ = 0;

        var span = header.AsSpan();
        var index = 0;

        while (index < span.Length)
        {
            while (index < span.Length && (span[index] == ',' || char.IsWhiteSpace(span[index])))
                index++;

            if (index >= span.Length)
                break;

            var tokenStart = index;
            while (index < span.Length && span[index] != ',')
                index++;

            var token = Trim(span[tokenStart..index]);
            if (token.Length == 0)
                continue;

            var semi = token.IndexOf(';');
            ReadOnlySpan<char> encoding;
            double q = 1.0;
            if (semi >= 0)
            {
                encoding = Trim(token[..semi]);
                q = ParseQuality(token[(semi + 1)..]);
            }
            else
            {
                encoding = token;
            }

            if (encoding.Length == 1 && encoding[0] == '*')
            {
                starQ = q;
                continue;
            }

            if (encoding.Equals("br".AsSpan(), StringComparison.OrdinalIgnoreCase))
                brQ = q;
            else if (encoding.Equals("gzip".AsSpan(), StringComparison.OrdinalIgnoreCase))
                gzipQ = q;
            else if (encoding.Equals("identity".AsSpan(), StringComparison.OrdinalIgnoreCase))
                identityQ = q;
        }
    }

    private static double ParseQuality(ReadOnlySpan<char> parameters)
    {
        var index = 0;
        while (index < parameters.Length)
        {
            while (index < parameters.Length && (parameters[index] == ';' || char.IsWhiteSpace(parameters[index])))
                index++;

            if (index >= parameters.Length)
                break;

            var partStart = index;
            while (index < parameters.Length && parameters[index] != ';')
                index++;

            var part = Trim(parameters[partStart..index]);
            if (part.Length >= 2 && (part[0] == 'q' || part[0] == 'Q') && part[1] == '=')
            {
                if (double.TryParse(part[2..], NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out var parsed))
                    return Math.Clamp(parsed, 0, 1);
            }
        }

        return 1.0;
    }

    private static ReadOnlySpan<char> Trim(ReadOnlySpan<char> value)
    {
        var start = 0;
        var end = value.Length - 1;
        while (start <= end && char.IsWhiteSpace(value[start]))
            start++;
        while (end >= start && char.IsWhiteSpace(value[end]))
            end--;
        return value[start..(end + 1)];
    }

    private static bool TryParseInt64(ReadOnlySpan<char> value, out long result)
    {
        result = 0;
        if (value.Length == 0)
            return false;

        for (int i = 0; i < value.Length; i++)
        {
            var c = value[i];
            if (c < '0' || c > '9')
                return false;
            result = result * 10 + (c - '0');
        }

        return true;
    }

    private static bool TryParseEtags(string header, out List<string> tags)
    {
        tags = new List<string>();
        var parts = header.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var part in parts)
        {
            var value = part.Trim();
            if (string.IsNullOrWhiteSpace(value))
                continue;

            tags.Add(value);
        }

        return tags.Count > 0;
    }

    private static bool StrongEtagEquals(string left, string right)
        => string.Equals(left, right, StringComparison.Ordinal) && !left.StartsWith("W/", StringComparison.OrdinalIgnoreCase) && !right.StartsWith("W/", StringComparison.OrdinalIgnoreCase);

    private static bool WeakEtagEquals(string left, string right)
    {
        var l = left.StartsWith("W/", StringComparison.OrdinalIgnoreCase) ? left[2..] : left;
        var r = right.StartsWith("W/", StringComparison.OrdinalIgnoreCase) ? right[2..] : right;
        return string.Equals(l, r, StringComparison.Ordinal);
    }

    private readonly record struct CompressionSelection(CompressionKind Kind, bool IsNotAcceptable = false)
    {
        public static CompressionSelection None => new(CompressionKind.None);
        public static CompressionSelection NotAcceptable => new(CompressionKind.None, true);
    }

    private enum CompressionKind
    {
        None,
        Brotli,
        Gzip
    }

    private static string BuildMetadataCacheKey(string filePath, string contentTypePath)
        => string.Equals(filePath, contentTypePath, StringComparison.OrdinalIgnoreCase)
            ? filePath
            : filePath + "|" + contentTypePath;

    private static async Task WriteMultipartRangesAsync(HttpContext context, string filePath, string contentType, long totalLength, string boundary, IReadOnlyList<FileRange> ranges)
    {
        await using var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 64 * 1024, FileOptions.SequentialScan | FileOptions.Asynchronous);
        foreach (var range in ranges)
        {
            await context.Response.WriteAsync($"--{boundary}\r\n");
            await context.Response.WriteAsync($"Content-Type: {contentType}\r\n");
            await context.Response.WriteAsync($"Content-Range: {BytesUnit} {range.Start}-{range.End}/{totalLength}\r\n\r\n");
            await CopyRangeAsync(fileStream, context.Response.Body, range.Start, range.Length, context.RequestAborted);
            await context.Response.WriteAsync("\r\n");
        }

        await context.Response.WriteAsync($"--{boundary}--\r\n");
    }

    private static async Task CopyRangeAsync(Stream source, Stream destination, long start, long length, CancellationToken cancellationToken)
    {
        source.Seek(start, SeekOrigin.Begin);
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        try
        {
            long remaining = length;
            while (remaining > 0)
            {
                var read = await source.ReadAsync(buffer.AsMemory(0, (int)Math.Min(buffer.Length, remaining)), cancellationToken);
                if (read <= 0)
                    break;

                await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                remaining -= read;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task WriteNotFound(HttpContext context)
    {
        context.Response.StatusCode = StatusCodes.Status404NotFound;
        context.Response.ContentType = "text/plain; charset=utf-8";
        await context.Response.WriteAsync("Not Found");
    }
}
