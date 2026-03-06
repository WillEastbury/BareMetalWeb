using BareMetalWeb.Core;
using BareMetalWeb.Core.Host;
using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Unit tests for <see cref="StaticAssetCache"/> — build, lookup, and
/// zero-copy-serve behaviour.
/// </summary>
[Collection("StaticAssetCache")]
public class StaticAssetCacheTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly StaticFileConfigOptions _options;

    public StaticAssetCacheTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), "bmw-sac-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempRoot);

        _options = new StaticFileConfigOptions
        {
            Enabled = true,
            RequestPathPrefix = "/static",
            RootDirectory = _tempRoot,
            EnableCaching = true,
            CacheSeconds = 3600,
            EnableInMemoryCache = true,
            InMemoryCacheMaxFileSizeBytes = 5 * 1024 * 1024,
        };
        _options.Normalize();
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempRoot))
            Directory.Delete(_tempRoot, true);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private string WriteFile(string relativePath, string content = "hello world")
    {
        var fullPath = Path.Combine(_tempRoot, relativePath.Replace('/', Path.DirectorySeparatorChar));
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        // Use no-BOM UTF-8 so ReadAllBytes returns exactly the text bytes
        File.WriteAllBytes(fullPath, Encoding.UTF8.GetBytes(content));
        return fullPath;
    }

    private static HttpContext CreateContext(string method, string path, string? acceptEncoding = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Method = method;
        ctx.Request.Path  = path;
        ctx.Response.Body = new MemoryStream();
        if (acceptEncoding != null)
            ctx.Request.Headers.AcceptEncoding = acceptEncoding;
        return ctx;
    }

    private static byte[] ReadResponseBody(HttpContext ctx)
    {
        ctx.Response.Body.Seek(0, SeekOrigin.Begin);
        using var ms = new MemoryStream();
        ctx.Response.Body.CopyTo(ms);
        return ms.ToArray();
    }

    // ── Build tests ───────────────────────────────────────────────────────────

    [Fact]
    public void Build_EmptyDirectory_SetsIsBuiltWithZeroEntries()
    {
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.True(StaticAssetCache.IsBuilt);
        Assert.Equal(0, StaticAssetCache.EntryCount);
    }

    [Fact]
    public void Build_SingleCssFile_CreatesEntry()
    {
        WriteFile("css/style.css", "body { margin: 0; }");
        StaticAssetCache.Build(_tempRoot, _options);

        Assert.True(StaticAssetCache.TryGetEntry("css/style.css", out _));
    }

    [Fact]
    public void Build_MultipleFiles_AllEntriesPresent()
    {
        WriteFile("a.css", "a {}");
        WriteFile("b.js", "var x = 1;");
        WriteFile("sub/c.css", "c {}");
        StaticAssetCache.Build(_tempRoot, _options);

        Assert.Equal(3, StaticAssetCache.EntryCount);
        Assert.True(StaticAssetCache.TryGetEntry("a.css", out _));
        Assert.True(StaticAssetCache.TryGetEntry("b.js", out _));
        Assert.True(StaticAssetCache.TryGetEntry("sub/c.css", out _));
    }

    [Fact]
    public void Build_NonExistentRoot_DoesNotThrow_EntryCountZero()
    {
        StaticAssetCache.Build(Path.Combine(_tempRoot, "nonexistent"), _options);
        Assert.Equal(0, StaticAssetCache.EntryCount);
    }

    [Fact]
    public void Build_SkipsDotFiles()
    {
        WriteFile(".hidden.css", "body {}");
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.False(StaticAssetCache.TryGetEntry(".hidden.css", out _));
    }

    [Fact]
    public void Build_SkipsKeyFiles()
    {
        WriteFile("secret.key", "my-key");
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.False(StaticAssetCache.TryGetEntry("secret.key", out _));
    }

    [Fact]
    public void Build_SkipsFilesExceedingMaxSize()
    {
        var bigContent = new string('X', 100);
        WriteFile("big.css", bigContent);

        var smallOptions = new StaticFileConfigOptions
        {
            Enabled = true,
            RequestPathPrefix = "/static",
            RootDirectory = _tempRoot,
            EnableInMemoryCache = true,
            InMemoryCacheMaxFileSizeBytes = 10  // smaller than file
        };
        smallOptions.Normalize();

        StaticAssetCache.Build(_tempRoot, smallOptions);
        Assert.False(StaticAssetCache.TryGetEntry("big.css", out _));
    }

    [Fact]
    public void Build_ZeroMaxSize_CachesAllFiles()
    {
        var bigContent = new string('X', 1_000_000);
        WriteFile("large.css", bigContent);

        var noLimitOptions = new StaticFileConfigOptions
        {
            Enabled = true,
            RequestPathPrefix = "/static",
            RootDirectory = _tempRoot,
            EnableInMemoryCache = true,
            InMemoryCacheMaxFileSizeBytes = 0  // 0 = no limit
        };
        noLimitOptions.Normalize();

        StaticAssetCache.Build(_tempRoot, noLimitOptions);
        Assert.True(StaticAssetCache.TryGetEntry("large.css", out _));
    }

    // ── Entry content tests ───────────────────────────────────────────────────

    [Fact]
    public void Entry_RawBytesMatchFileContent()
    {
        const string content = "body { color: red; }";
        WriteFile("style.css", content);
        StaticAssetCache.Build(_tempRoot, _options);

        Assert.True(StaticAssetCache.TryGetEntry("style.css", out var entry));
        var raw = Encoding.UTF8.GetString(entry.RawBytes.Span);
        Assert.Equal(content, raw);
    }

    [Fact]
    public void Entry_CompressibleFile_HasBrotliAndGzip()
    {
        // Long enough to compress smaller than raw
        WriteFile("big.css", string.Concat(Enumerable.Repeat("body { margin: 0; padding: 0; }", 200)));
        StaticAssetCache.Build(_tempRoot, _options);

        Assert.True(StaticAssetCache.TryGetEntry("big.css", out var entry));
        Assert.False(entry.BrotliBytes.IsEmpty, "Brotli variant should be present for compressible CSS");
        Assert.False(entry.GzipBytes.IsEmpty,   "Gzip variant should be present for compressible CSS");
        Assert.True(entry.BrotliBytes.Length < entry.RawBytes.Length);
        Assert.True(entry.GzipBytes.Length   < entry.RawBytes.Length);
    }

    [Fact]
    public void Entry_ETag_IsQuotedHexString()
    {
        WriteFile("style.css", "a {}");
        StaticAssetCache.Build(_tempRoot, _options);

        Assert.True(StaticAssetCache.TryGetEntry("style.css", out var entry));
        Assert.StartsWith("\"", entry.ETag);
        Assert.EndsWith("\"", entry.ETag);
    }

    [Fact]
    public void Entry_LastModified_IsRfc7231Date()
    {
        WriteFile("style.css", "a {}");
        StaticAssetCache.Build(_tempRoot, _options);

        Assert.True(StaticAssetCache.TryGetEntry("style.css", out var entry));
        Assert.True(DateTimeOffset.TryParse(entry.LastModified, out _), $"LastModified '{entry.LastModified}' should parse as RFC 7231 date");
    }

    [Fact]
    public void Entry_VersionedFile_IsVersionedTrue()
    {
        // Filename contains 8+ hex chars → versioned / immutable
        WriteFile("app.a1b2c3d4e5f6.js", "var x = 1;");
        StaticAssetCache.Build(_tempRoot, _options);

        Assert.True(StaticAssetCache.TryGetEntry("app.a1b2c3d4e5f6.js", out var entry));
        Assert.True(entry.IsVersioned);
    }

    [Fact]
    public void Entry_NonVersionedFile_IsVersionedFalse()
    {
        WriteFile("site.css", "body {}");
        StaticAssetCache.Build(_tempRoot, _options);

        Assert.True(StaticAssetCache.TryGetEntry("site.css", out var entry));
        Assert.False(entry.IsVersioned);
    }

    // ── SelectVariant / EffectiveEncoding tests ───────────────────────────────

    [Fact]
    public void SelectVariant_NullEncoding_ReturnsRaw()
    {
        WriteFile("style.css", "a {}");
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.True(StaticAssetCache.TryGetEntry("style.css", out var entry));

        Assert.Equal(entry.RawBytes, entry.SelectVariant(null));
    }

    [Fact]
    public void SelectVariant_BrEncoding_ReturnsBrotliOrRaw()
    {
        WriteFile("style.css", "a {}");
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.True(StaticAssetCache.TryGetEntry("style.css", out var entry));

        var variant = entry.SelectVariant("br");
        // If brotli is available it should be different from raw (compressed)
        if (!entry.BrotliBytes.IsEmpty)
            Assert.Equal(entry.BrotliBytes, variant);
        else
            Assert.Equal(entry.RawBytes, variant);
    }

    [Fact]
    public void EffectiveEncoding_BrUnavailable_ReturnsNull()
    {
        // A file that is too small / already compressed won't have Brotli variant
        WriteFile("font.woff2", "fake-font");  // binary, not compressible by content type
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.True(StaticAssetCache.TryGetEntry("font.woff2", out var entry));

        Assert.Null(entry.EffectiveEncoding("br"));
    }

    // ── ServeAsync tests ──────────────────────────────────────────────────────

    [Fact]
    public async Task ServeAsync_SetsStatus200AndContentType()
    {
        WriteFile("style.css", "body {}");
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.True(StaticAssetCache.TryGetEntry("style.css", out var entry));

        var ctx = CreateContext("GET", "/static/style.css");
        await StaticAssetCache.ServeAsync(ctx.ToBmw(), entry, null, _options);

        Assert.Equal(200, ctx.Response.StatusCode);
        Assert.StartsWith("text/css", ctx.Response.ContentType);
    }

    [Fact]
    public async Task ServeAsync_WritesRawBodyForGetRequest()
    {
        const string content = "body { margin: 0; }";
        WriteFile("style.css", content);
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.True(StaticAssetCache.TryGetEntry("style.css", out var entry));

        var ctx = CreateContext("GET", "/static/style.css");
        await StaticAssetCache.ServeAsync(ctx.ToBmw(), entry, null, _options);

        var body = ReadResponseBody(ctx);
        Assert.Equal(Encoding.UTF8.GetBytes(content), body);
    }

    [Fact]
    public async Task ServeAsync_HeadRequest_WritesNoBody()
    {
        WriteFile("style.css", "body {}");
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.True(StaticAssetCache.TryGetEntry("style.css", out var entry));

        var ctx = CreateContext("HEAD", "/static/style.css");
        await StaticAssetCache.ServeAsync(ctx.ToBmw(), entry, null, _options);

        Assert.Equal(0, ReadResponseBody(ctx).Length);
    }

    [Fact]
    public async Task ServeAsync_SetsContentLength()
    {
        WriteFile("style.css", "body {}");
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.True(StaticAssetCache.TryGetEntry("style.css", out var entry));

        var ctx = CreateContext("GET", "/static/style.css");
        await StaticAssetCache.ServeAsync(ctx.ToBmw(), entry, null, _options);

        Assert.Equal(entry.RawBytes.Length, ctx.Response.ContentLength);
    }

    [Fact]
    public async Task ServeAsync_SetsETagAndLastModifiedHeaders()
    {
        WriteFile("style.css", "body {}");
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.True(StaticAssetCache.TryGetEntry("style.css", out var entry));

        var ctx = CreateContext("GET", "/static/style.css");
        await StaticAssetCache.ServeAsync(ctx.ToBmw(), entry, null, _options);

        Assert.Equal(entry.ETag, ctx.Response.Headers.ETag.ToString());
        Assert.Equal(entry.LastModified, ctx.Response.Headers.LastModified.ToString());
    }

    [Fact]
    public async Task ServeAsync_VersionedAsset_SetsImmutableCacheControl()
    {
        WriteFile("app.deadbeef01234567.js", "var x = 1;");
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.True(StaticAssetCache.TryGetEntry("app.deadbeef01234567.js", out var entry));
        Assert.True(entry.IsVersioned);

        var ctx = CreateContext("GET", "/static/app.deadbeef01234567.js");
        await StaticAssetCache.ServeAsync(ctx.ToBmw(), entry, null, _options);

        Assert.Contains("immutable", ctx.Response.Headers.CacheControl.ToString());
        Assert.Contains("max-age=31536000", ctx.Response.Headers.CacheControl.ToString());
    }

    [Fact]
    public async Task ServeAsync_NonVersionedAsset_UsesCacheSeconds()
    {
        WriteFile("style.css", "body {}");
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.True(StaticAssetCache.TryGetEntry("style.css", out var entry));

        var ctx = CreateContext("GET", "/static/style.css");
        await StaticAssetCache.ServeAsync(ctx.ToBmw(), entry, null, _options);

        var cc = ctx.Response.Headers.CacheControl.ToString();
        Assert.Contains("max-age=3600", cc);
        Assert.DoesNotContain("immutable", cc);
    }

    [Fact]
    public async Task ServeAsync_BrotliRequested_SetsContentEncoding()
    {
        // Large CSS so brotli actually compresses
        WriteFile("big.css", string.Concat(Enumerable.Repeat("body { margin: 0; padding: 0; }", 200)));
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.True(StaticAssetCache.TryGetEntry("big.css", out var entry));

        if (entry.BrotliBytes.IsEmpty)
            return; // Skip if brotli unavailable for this content

        var ctx = CreateContext("GET", "/static/big.css");
        await StaticAssetCache.ServeAsync(ctx.ToBmw(), entry, "br", _options);

        Assert.Equal("br", ctx.Response.Headers.ContentEncoding.ToString());
        Assert.Equal(entry.BrotliBytes.Length, ctx.Response.ContentLength);

        // Decompress and verify round-trip
        var body = ReadResponseBody(ctx);
        using var ms = new MemoryStream(body);
        using var bs = new BrotliStream(ms, CompressionMode.Decompress);
        using var decoded = new MemoryStream();
        bs.CopyTo(decoded);
        Assert.Equal(entry.RawBytes.ToArray(), decoded.ToArray());
    }

    [Fact]
    public async Task ServeAsync_GzipRequested_SetsContentEncoding()
    {
        WriteFile("big.css", string.Concat(Enumerable.Repeat("body { margin: 0; padding: 0; }", 200)));
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.True(StaticAssetCache.TryGetEntry("big.css", out var entry));

        if (entry.GzipBytes.IsEmpty)
            return; // Skip if gzip unavailable

        var ctx = CreateContext("GET", "/static/big.css");
        await StaticAssetCache.ServeAsync(ctx.ToBmw(), entry, "gzip", _options);

        Assert.Equal("gzip", ctx.Response.Headers.ContentEncoding.ToString());
        Assert.Equal(entry.GzipBytes.Length, ctx.Response.ContentLength);
    }

    // ── StaticFileService integration ─────────────────────────────────────────

    [Fact]
    public async Task StaticFileService_UsesCacheWhenBuilt()
    {
        const string content = "body { color: blue; }";
        WriteFile("site.css", content);
        StaticAssetCache.Build(_tempRoot, _options);

        var ctx = CreateContext("GET", "/static/site.css");
        var served = await StaticFileService.TryServeAsync(ctx.ToBmw(), _options);

        Assert.True(served);
        Assert.Equal(200, ctx.Response.StatusCode);
        var body = ReadResponseBody(ctx);
        Assert.Equal(Encoding.UTF8.GetBytes(content), body);
    }

    [Fact]
    public async Task StaticFileService_Returns304_WhenETagMatches()
    {
        WriteFile("site.css", "body {}");
        StaticAssetCache.Build(_tempRoot, _options);
        Assert.True(StaticAssetCache.TryGetEntry("site.css", out var entry));

        var ctx = CreateContext("GET", "/static/site.css");
        ctx.Request.Headers.IfNoneMatch = entry.ETag;
        var served = await StaticFileService.TryServeAsync(ctx.ToBmw(), _options);

        Assert.True(served);
        Assert.Equal(304, ctx.Response.StatusCode);
    }
}
