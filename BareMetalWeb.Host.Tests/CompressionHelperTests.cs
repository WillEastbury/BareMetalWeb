using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Host;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace BareMetalWeb.Host.Tests;

public class CompressionHelperTests
{
    // ── SelectEncoding ─────────────────────────────────────────────────────────

    [Fact]
    public void SelectEncoding_NullHeader_ReturnsNull()
    {
        Assert.Null(CompressionHelper.SelectEncoding((string?)null));
    }

    [Fact]
    public void SelectEncoding_EmptyHeader_ReturnsNull()
    {
        Assert.Null(CompressionHelper.SelectEncoding(string.Empty));
    }

    [Fact]
    public void SelectEncoding_BrotliOnly_ReturnsBr()
    {
        Assert.Equal("br", CompressionHelper.SelectEncoding("br"));
    }

    [Fact]
    public void SelectEncoding_GzipOnly_ReturnsGzip()
    {
        Assert.Equal("gzip", CompressionHelper.SelectEncoding("gzip"));
    }

    [Fact]
    public void SelectEncoding_BothBrotliAndGzip_PrefersBrotli()
    {
        Assert.Equal("br", CompressionHelper.SelectEncoding("gzip, br"));
    }

    [Fact]
    public void SelectEncoding_BrotliWithLowerQuality_PrefersGzip()
    {
        // br;q=0.5 vs gzip;q=0.9 → gzip should win
        Assert.Equal("gzip", CompressionHelper.SelectEncoding("br;q=0.5, gzip;q=0.9"));
    }

    [Fact]
    public void SelectEncoding_StarEncoding_ReturnsBr()
    {
        // '*' means any encoding is accepted; we should prefer br
        Assert.Equal("br", CompressionHelper.SelectEncoding("*"));
    }

    [Fact]
    public void SelectEncoding_IdentityOnly_ReturnsNull()
    {
        Assert.Null(CompressionHelper.SelectEncoding("identity"));
    }

    [Fact]
    public void SelectEncoding_DeflateOnly_ReturnsNull()
    {
        Assert.Null(CompressionHelper.SelectEncoding("deflate"));
    }

    [Fact]
    public void SelectEncoding_ZeroQualityBr_DoesNotSelectBr()
    {
        Assert.Equal("gzip", CompressionHelper.SelectEncoding("br;q=0, gzip"));
    }

    // ── CompressBrotli / CompressGzip round-trips ──────────────────────────────

    [Fact]
    public void CompressBrotli_RoundTrips()
    {
        var original = Encoding.UTF8.GetBytes("Hello, World! This is a test of brotli compression.");
        var compressed = CompressionHelper.CompressBrotli(original);
        Assert.NotEmpty(compressed);

        using var ms = new MemoryStream(compressed);
        using var bs = new BrotliStream(ms, CompressionMode.Decompress);
        using var result = new MemoryStream();
        bs.CopyTo(result);
        Assert.Equal(original, result.ToArray());
    }

    [Fact]
    public void CompressGzip_RoundTrips()
    {
        var original = Encoding.UTF8.GetBytes("Hello, World! This is a test of gzip compression.");
        var compressed = CompressionHelper.CompressGzip(original);
        Assert.NotEmpty(compressed);

        using var ms = new MemoryStream(compressed);
        using var gz = new GZipStream(ms, CompressionMode.Decompress);
        using var result = new MemoryStream();
        gz.CopyTo(result);
        Assert.Equal(original, result.ToArray());
    }

    [Fact]
    public void Compress_NullEncoding_ReturnsOriginal()
    {
        var data = Encoding.UTF8.GetBytes("test data");
        Assert.Same(data, CompressionHelper.Compress(data, null));
    }

    [Fact]
    public void Compress_BrEncoding_CompressesBrotli()
    {
        var data = Encoding.UTF8.GetBytes(new string('a', 200));
        var compressed = CompressionHelper.Compress(data, "br");
        Assert.True(compressed.Length < data.Length, "Brotli should compress repetitive data");
    }

    [Fact]
    public void Compress_GzipEncoding_CompressesGzip()
    {
        var data = Encoding.UTF8.GetBytes(new string('a', 200));
        var compressed = CompressionHelper.Compress(data, "gzip");
        Assert.True(compressed.Length < data.Length, "GZip should compress repetitive data");
    }
}

[Collection("JsBundleService")]
public class JsBundleServiceCompressionTests : IDisposable
{
    private readonly string _tempDir;

    public JsBundleServiceCompressionTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "bmw-jscmp-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
        File.WriteAllText(Path.Combine(_tempDir, "theme-switcher.js"),
            new string('x', 500), Encoding.UTF8);
        JsBundleService.BuildBundle(_tempDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private static HttpContext CreateContext(string method, string path, string? acceptEncoding = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        if (acceptEncoding != null)
            context.Request.Headers.AcceptEncoding = acceptEncoding;
        return context;
    }

    [Fact]
    public async Task TryServeAsync_WithBrotliAcceptEncoding_SetsBrContentEncoding()
    {
        var context = CreateContext("GET", JsBundleService.BundlePath, "br");
        await JsBundleService.TryServeAsync(context.ToBmw());

        Assert.Equal("br", context.Response.Headers.ContentEncoding.ToString());
        Assert.Contains("Accept-Encoding", context.Response.Headers.Vary.ToString());
    }

    [Fact]
    public async Task TryServeAsync_WithGzipAcceptEncoding_SetsGzipContentEncoding()
    {
        var context = CreateContext("GET", JsBundleService.BundlePath, "gzip");
        await JsBundleService.TryServeAsync(context.ToBmw());

        Assert.Equal("gzip", context.Response.Headers.ContentEncoding.ToString());
        Assert.Contains("Accept-Encoding", context.Response.Headers.Vary.ToString());
    }

    [Fact]
    public async Task TryServeAsync_WithNoAcceptEncoding_NoContentEncodingHeader()
    {
        var context = CreateContext("GET", JsBundleService.BundlePath);
        await JsBundleService.TryServeAsync(context.ToBmw());

        Assert.Empty(context.Response.Headers.ContentEncoding.ToString());
    }

    [Fact]
    public async Task TryServeAsync_WithBrotliAcceptEncoding_BodyIsDecompressibleBrotli()
    {
        var context = CreateContext("GET", JsBundleService.BundlePath, "br");
        await JsBundleService.TryServeAsync(context.ToBmw());

        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var bs = new BrotliStream(context.Response.Body, CompressionMode.Decompress);
        using var result = new MemoryStream();
        bs.CopyTo(result);
        Assert.True(result.Length > 0);
    }
}

[Collection("CssBundleService")]
public class CssBundleServiceCompressionTests : IDisposable
{
    private readonly string _tempRoot;

    public CssBundleServiceCompressionTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), "bmw-csscmp-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(Path.Combine(_tempRoot, "css", "themes"));
        File.WriteAllText(
            Path.Combine(_tempRoot, "css", "themes", "vapor.min.css"),
            new string('a', 500), Encoding.UTF8);
        CssBundleService.BuildBundles(Path.Combine(_tempRoot, "css"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempRoot))
            Directory.Delete(_tempRoot, true);
    }

    private static HttpContext CreateContext(string method, string path, string? acceptEncoding = null)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        if (acceptEncoding != null)
            context.Request.Headers.AcceptEncoding = acceptEncoding;
        return context;
    }

    [Fact]
    public async Task TryServeAsync_WithBrotliAcceptEncoding_SetsBrContentEncoding()
    {
        var context = CreateContext("GET", CssBundleService.ThemePathPrefix + "vapor.min.css", "br");
        await CssBundleService.TryServeAsync(context.ToBmw());

        Assert.Equal("br", context.Response.Headers.ContentEncoding.ToString());
        Assert.Contains("Accept-Encoding", context.Response.Headers.Vary.ToString());
    }

    [Fact]
    public async Task TryServeAsync_WithGzipAcceptEncoding_SetsGzipContentEncoding()
    {
        var context = CreateContext("GET", CssBundleService.ThemePathPrefix + "vapor.min.css", "gzip");
        await CssBundleService.TryServeAsync(context.ToBmw());

        Assert.Equal("gzip", context.Response.Headers.ContentEncoding.ToString());
        Assert.Contains("Accept-Encoding", context.Response.Headers.Vary.ToString());
    }

    [Fact]
    public async Task TryServeAsync_WithNoAcceptEncoding_NoContentEncodingHeader()
    {
        var context = CreateContext("GET", CssBundleService.ThemePathPrefix + "vapor.min.css");
        await CssBundleService.TryServeAsync(context.ToBmw());

        Assert.Empty(context.Response.Headers.ContentEncoding.ToString());
    }
}
