using System;
using System.IO;
using System.Threading.Tasks;
using BareMetalWeb.Core.Host;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace BareMetalWeb.Host.Tests;

public class StaticFileServiceTests : IDisposable
{
    private readonly string _tempDir;
    private readonly StaticFileConfigOptions _options;

    public StaticFileServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "bmw-sftest-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);

        _options = new StaticFileConfigOptions
        {
            Enabled = true,
            RequestPathPrefix = "/static",
            RootDirectory = _tempDir,
            EnableCaching = false,
        };
        _options.Normalize();
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempDir))
            Directory.Delete(_tempDir, true);
    }

    private HttpContext CreateContext(string method, string path)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        return context;
    }

    private void CreateFile(string relativePath, string content = "hello")
    {
        var fullPath = Path.Combine(_tempDir, relativePath.Replace('/', Path.DirectorySeparatorChar));
        var dir = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(dir))
            Directory.CreateDirectory(dir);
        File.WriteAllText(fullPath, content);
    }

    [Fact]
    public async Task TryServeAsync_NullOptions_ReturnsFalse()
    {
        var context = CreateContext("GET", "/static/test.css");
        var result = await StaticFileService.TryServeAsync(context, null);
        Assert.False(result);
    }

    [Fact]
    public async Task TryServeAsync_Disabled_ReturnsFalse()
    {
        _options.Enabled = false;
        var context = CreateContext("GET", "/static/test.css");
        var result = await StaticFileService.TryServeAsync(context, _options);
        Assert.False(result);
    }

    [Fact]
    public async Task TryServeAsync_WrongPrefix_ReturnsFalse()
    {
        var context = CreateContext("GET", "/assets/test.css");
        var result = await StaticFileService.TryServeAsync(context, _options);
        Assert.False(result);
    }

    [Fact]
    public async Task TryServeAsync_PostMethod_Returns405()
    {
        var context = CreateContext("POST", "/static/test.css");
        var result = await StaticFileService.TryServeAsync(context, _options);
        Assert.True(result);
        Assert.Equal(405, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_ExistingFile_Returns200()
    {
        CreateFile("style.css", "body { color: red; }");
        var context = CreateContext("GET", "/static/style.css");
        var result = await StaticFileService.TryServeAsync(context, _options);
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_ExistingFile_SetsContentType()
    {
        CreateFile("app.js", "console.log('hi');");
        var context = CreateContext("GET", "/static/app.js");
        await StaticFileService.TryServeAsync(context, _options);
        Assert.Equal("application/javascript", context.Response.ContentType);
    }

    [Fact]
    public async Task TryServeAsync_MissingFile_Returns404()
    {
        var context = CreateContext("GET", "/static/nonexistent.css");
        var result = await StaticFileService.TryServeAsync(context, _options);
        Assert.True(result);
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_DotSegment_Returns404()
    {
        CreateFile("secret.txt", "secret");
        var context = CreateContext("GET", "/static/../secret.txt");
        var result = await StaticFileService.TryServeAsync(context, _options);
        Assert.True(result);
        Assert.Equal(404, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_HeadMethod_ReturnsNoBody()
    {
        CreateFile("head.txt", "content");
        var context = CreateContext("HEAD", "/static/head.txt");
        var result = await StaticFileService.TryServeAsync(context, _options);
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        Assert.Equal(0, context.Response.Body.Length);
    }

    [Fact]
    public async Task TryServeAsync_HtmlFile_SetsHtmlContentType()
    {
        CreateFile("page.html", "<h1>Hello</h1>");
        var context = CreateContext("GET", "/static/page.html");
        await StaticFileService.TryServeAsync(context, _options);
        Assert.StartsWith("text/html", context.Response.ContentType);
    }

    [Fact]
    public async Task TryServeAsync_SubDirectory_ServesFile()
    {
        CreateFile("css/main.css", "body{}");
        var context = CreateContext("GET", "/static/css/main.css");
        var result = await StaticFileService.TryServeAsync(context, _options);
        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_KeysDirectory_Returns404()
    {
        CreateFile(".keys/secret.key", "key");
        var context = CreateContext("GET", "/static/.keys/secret.key");
        var result = await StaticFileService.TryServeAsync(context, _options);
        Assert.True(result);
        Assert.Equal(404, context.Response.StatusCode);
    }
}
