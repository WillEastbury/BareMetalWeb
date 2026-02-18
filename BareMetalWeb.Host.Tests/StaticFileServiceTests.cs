using System;
using System.IO;
using System.Threading.Tasks;
using BareMetalWeb.Core.Host;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace BareMetalWeb.Host.Tests;

public class StaticFileServiceTests : IDisposable
{
    private readonly string _testRootPath;
    private readonly StaticFileConfigOptions _options;

    public StaticFileServiceTests()
    {
        // Create a temporary directory for test files
        _testRootPath = Path.Combine(Path.GetTempPath(), "StaticFileServiceTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_testRootPath);

        // Create test files
        CreateTestFile("test.css", "body { color: red; }");
        CreateTestFile("test.js", "console.log('hello');");
        CreateTestFile("test.txt", "Hello, World!");
        CreateTestFile("test.html", "<html><body>Test</body></html>");
        CreateTestFile("test.json", "{\"key\": \"value\"}");
        CreateTestFile("test.png", new byte[] { 0x89, 0x50, 0x4E, 0x47 }); // PNG header
        CreateTestFile("test.jpg", new byte[] { 0xFF, 0xD8, 0xFF }); // JPEG header
        CreateTestFile("test.unknown", "unknown content");
        CreateTestFile("test.key", "secret key"); // Should be blocked

        // Create subdirectory with files
        Directory.CreateDirectory(Path.Combine(_testRootPath, "subdir"));
        CreateTestFile("subdir/nested.css", "div { margin: 0; }");

        // Create .dotfile (should be rejected via ContainsDotSegment)
        CreateTestFile(".hidden", "hidden content");

        // Setup options
        _options = new StaticFileConfigOptions
        {
            Enabled = true,
            RequestPathPrefix = "/static",
            RootDirectory = _testRootPath,
            EnableCaching = true,
            CacheSeconds = 3600,
            AddETag = true,
            AddLastModified = true,
            AllowUnknownMime = false,
            HideUnknownMimeFiles = false,
            DefaultMimeType = "application/octet-stream"
        };
        _options.Normalize();
    }

    public void Dispose()
    {
        // Clean up test directory
        if (Directory.Exists(_testRootPath))
        {
            try
            {
                Directory.Delete(_testRootPath, recursive: true);
            }
            catch
            {
                // Best effort cleanup
            }
        }
    }

    private void CreateTestFile(string relativePath, string content)
    {
        var fullPath = Path.Combine(_testRootPath, relativePath);
        File.WriteAllText(fullPath, content);
    }

    private void CreateTestFile(string relativePath, byte[] content)
    {
        var fullPath = Path.Combine(_testRootPath, relativePath);
        File.WriteAllBytes(fullPath, content);
    }

    private static DefaultHttpContext CreateHttpContext(string path, string method = "GET")
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Request.Method = method;
        context.Response.Body = new MemoryStream();
        return context;
    }

    [Fact]
    public async Task TryServeAsync_CssFile_ServesWithCorrectContentType()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.css");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.StartsWith("text/css", context.Response.ContentType);
    }

    [Fact]
    public async Task TryServeAsync_JsFile_ServesWithCorrectContentType()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.js");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.Equal("application/javascript", context.Response.ContentType);
    }

    [Fact]
    public async Task TryServeAsync_PngImage_ServesWithCorrectContentType()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.png");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.Equal("image/png", context.Response.ContentType);
    }

    [Fact]
    public async Task TryServeAsync_JpegImage_ServesWithCorrectContentType()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.jpg");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.Equal("image/jpeg", context.Response.ContentType);
    }

    [Fact]
    public async Task TryServeAsync_HtmlFile_ServesWithCorrectContentType()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.html");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.StartsWith("text/html", context.Response.ContentType);
    }

    [Fact]
    public async Task TryServeAsync_JsonFile_ServesWithCorrectContentType()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.json");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.StartsWith("application/json", context.Response.ContentType);
    }

    [Fact]
    public async Task TryServeAsync_MissingFile_Returns404()
    {
        // Arrange
        var context = CreateHttpContext("/static/nonexistent.css");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_DirectoryTraversalAttempt_Returns404()
    {
        // Arrange
        var context = CreateHttpContext("/static/../../../etc/passwd");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_DotSegmentInPath_Returns404()
    {
        // Arrange
        var context = CreateHttpContext("/static/.hidden");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_KeyFile_Returns404()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.key");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_WithCaching_AddsCacheHeaders()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.css");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.True(context.Response.Headers.ContainsKey("Cache-Control"));
        Assert.Contains("max-age=3600", context.Response.Headers.CacheControl.ToString());
    }

    [Fact]
    public async Task TryServeAsync_WithCaching_AddsETag()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.css");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.True(context.Response.Headers.ContainsKey("ETag"));
        Assert.NotEmpty(context.Response.Headers.ETag.ToString());
    }

    [Fact]
    public async Task TryServeAsync_WithCaching_AddsLastModified()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.css");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.True(context.Response.Headers.ContainsKey("Last-Modified"));
    }

    [Fact]
    public async Task TryServeAsync_WithoutCaching_AddsNoCacheHeaders()
    {
        // Arrange
        _options.EnableCaching = false;
        var context = CreateHttpContext("/static/test.css");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.Contains("no-cache", context.Response.Headers.CacheControl.ToString());
    }

    [Fact]
    public async Task TryServeAsync_HeadRequest_ReturnsHeadersOnly()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.css", "HEAD");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.True(context.Response.Headers.ContainsKey("Content-Type"));
        // Response body should not be written for HEAD request
        Assert.Equal(0, context.Response.Body.Length);
    }

    [Fact]
    public async Task TryServeAsync_PostRequest_Returns405()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.css", "POST");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(405, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_PutRequest_Returns405()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.css", "PUT");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(405, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_DeleteRequest_Returns405()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.css", "DELETE");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(405, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_UnknownMimeType_Returns415WhenNotAllowed()
    {
        // Arrange
        _options.AllowUnknownMime = false;
        _options.HideUnknownMimeFiles = false;
        var context = CreateHttpContext("/static/test.unknown");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(415, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_UnknownMimeType_Returns404WhenHidden()
    {
        // Arrange
        _options.AllowUnknownMime = false;
        _options.HideUnknownMimeFiles = true;
        var context = CreateHttpContext("/static/test.unknown");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_UnknownMimeType_ServesWithDefaultWhenAllowed()
    {
        // Arrange
        _options.AllowUnknownMime = true;
        _options.DefaultMimeType = "application/octet-stream";
        var context = CreateHttpContext("/static/test.unknown");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.Equal("application/octet-stream", context.Response.ContentType);
    }

    [Fact]
    public async Task TryServeAsync_NestedFile_ServesCorrectly()
    {
        // Arrange
        var context = CreateHttpContext("/static/subdir/nested.css");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.StartsWith("text/css", context.Response.ContentType);
    }

    [Fact]
    public async Task TryServeAsync_WrongPrefix_ReturnsFalse()
    {
        // Arrange
        var context = CreateHttpContext("/other/test.css");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task TryServeAsync_DisabledService_ReturnsFalse()
    {
        // Arrange
        _options.Enabled = false;
        var context = CreateHttpContext("/static/test.css");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task TryServeAsync_NullOptions_ReturnsFalse()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.css");

        // Act
        var result = await StaticFileService.TryServeAsync(context, null);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task TryServeAsync_IfNoneMatch_Returns304WhenMatches()
    {
        // Arrange - First request to get ETag
        var context1 = CreateHttpContext("/static/test.css");
        await StaticFileService.TryServeAsync(context1, _options);
        var etag = context1.Response.Headers.ETag.ToString();

        // Act - Second request with If-None-Match
        var context2 = CreateHttpContext("/static/test.css");
        context2.Request.Headers.IfNoneMatch = etag;
        var result = await StaticFileService.TryServeAsync(context2, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(304, context2.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_IfModifiedSince_Returns304WhenNotModified()
    {
        // Arrange - First request to get Last-Modified
        var context1 = CreateHttpContext("/static/test.css");
        await StaticFileService.TryServeAsync(context1, _options);
        var lastModified = context1.Response.Headers.LastModified.ToString();
        
        // Parse and add 1 second to ensure it's after the last modified time
        var lastModifiedDate = DateTimeOffset.Parse(lastModified);
        var futureDate = lastModifiedDate.AddSeconds(1);

        // Act - Second request with If-Modified-Since set to future date
        var context2 = CreateHttpContext("/static/test.css");
        context2.Request.Headers.IfModifiedSince = futureDate.ToString("R");
        var result = await StaticFileService.TryServeAsync(context2, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(304, context2.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_AcceptRanges_AddsHeader()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.css");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.Equal("bytes", context.Response.Headers.AcceptRanges.ToString());
    }

    [Fact]
    public async Task TryServeAsync_RangeRequest_Returns206()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.css");
        context.Request.Headers.Range = "bytes=0-10";

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(206, context.Response.StatusCode);
        Assert.True(context.Response.Headers.ContainsKey("Content-Range"));
    }

    [Fact]
    public async Task TryServeAsync_InvalidRangeRequest_Returns416()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.css");
        context.Request.Headers.Range = "bytes=9999-10000"; // Beyond file size

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(416, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_ContentLength_SetCorrectly()
    {
        // Arrange
        var context = CreateHttpContext("/static/test.css");

        // Act
        var result = await StaticFileService.TryServeAsync(context, _options);

        // Assert
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        Assert.True(context.Response.ContentLength > 0);
    }
}
