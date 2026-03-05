using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using BareMetalWeb.Host;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace BareMetalWeb.Host.Tests;

[Collection("JsBundleService")]
public class JsBundleServiceTests : IDisposable
{
    private readonly string _tempDir;

    public JsBundleServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "bmw-bundle-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
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

    private void WriteJsFile(string fileName, string content)
        => File.WriteAllText(Path.Combine(_tempDir, fileName), content, Encoding.UTF8);

    private string ReadResponseBody(HttpContext context)
    {
        context.Response.Body.Seek(0, SeekOrigin.Begin);
        return new StreamReader(context.Response.Body, Encoding.UTF8).ReadToEnd();
    }

    [Fact]
    public async Task BuildBundle_ConcatenatesFilesInOrder()
    {
        WriteJsFile("theme-switcher.js", "/* theme */");
        WriteJsFile("timezone.js", "/* tz */");

        JsBundleService.BuildBundle(_tempDir);

        var context = CreateContext("GET", JsBundleService.BundlePath);
        await JsBundleService.TryServeAsync(context);

        var body = ReadResponseBody(context);
        var themeIdx = body.IndexOf("theme-switcher.js", StringComparison.Ordinal);
        var tzIdx = body.IndexOf("timezone.js", StringComparison.Ordinal);
        Assert.True(themeIdx >= 0, "theme-switcher.js should appear in bundle");
        Assert.True(tzIdx >= 0, "timezone.js should appear in bundle");
        Assert.True(themeIdx < tzIdx, "theme-switcher.js should appear before timezone.js");
    }

    [Fact]
    public void BuildBundle_SkipsMissingFiles()
    {
        // Only write one of the expected files
        WriteJsFile("theme-switcher.js", "var x=1;");

        // Should not throw even though other files are missing
        JsBundleService.BuildBundle(_tempDir);
    }

    [Fact]
    public async Task TryServeAsync_NonBundlePath_ReturnsFalse()
    {
        JsBundleService.BuildBundle(_tempDir);

        var context = CreateContext("GET", "/static/js/theme-switcher.js");
        var result = await JsBundleService.TryServeAsync(context);

        Assert.False(result);
    }

    [Fact]
    public async Task TryServeAsync_BundlePath_ReturnsTrue()
    {
        WriteJsFile("theme-switcher.js", "var x=1;");
        JsBundleService.BuildBundle(_tempDir);

        var context = CreateContext("GET", JsBundleService.BundlePath);
        var result = await JsBundleService.TryServeAsync(context);

        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_SetsCorrectContentType()
    {
        WriteJsFile("theme-switcher.js", "var x=1;");
        JsBundleService.BuildBundle(_tempDir);

        var context = CreateContext("GET", JsBundleService.BundlePath);
        await JsBundleService.TryServeAsync(context);

        Assert.Equal("application/javascript; charset=utf-8", context.Response.ContentType);
    }

    [Fact]
    public async Task TryServeAsync_SetsETagHeader()
    {
        WriteJsFile("theme-switcher.js", "var x=1;");
        JsBundleService.BuildBundle(_tempDir);

        var context = CreateContext("GET", JsBundleService.BundlePath);
        await JsBundleService.TryServeAsync(context);

        Assert.False(string.IsNullOrEmpty(context.Response.Headers.ETag.ToString()));
    }

    [Fact]
    public async Task TryServeAsync_Returns304_WhenETagMatches()
    {
        WriteJsFile("theme-switcher.js", "var x=1;");
        JsBundleService.BuildBundle(_tempDir);

        // First request to get the ETag
        var first = CreateContext("GET", JsBundleService.BundlePath);
        await JsBundleService.TryServeAsync(first);
        var etag = first.Response.Headers.ETag.ToString();

        // Second request with matching ETag
        var context = CreateContext("GET", JsBundleService.BundlePath);
        context.Request.Headers.IfNoneMatch = etag;
        var result = await JsBundleService.TryServeAsync(context);

        Assert.True(result);
        Assert.Equal(304, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_PostMethod_Returns405()
    {
        WriteJsFile("theme-switcher.js", "var x=1;");
        JsBundleService.BuildBundle(_tempDir);

        var context = CreateContext("POST", JsBundleService.BundlePath);
        var result = await JsBundleService.TryServeAsync(context);

        Assert.True(result);
        Assert.Equal(405, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_HeadMethod_ReturnsNoBody()
    {
        WriteJsFile("theme-switcher.js", "var x=1;");
        JsBundleService.BuildBundle(_tempDir);

        var context = CreateContext("HEAD", JsBundleService.BundlePath);
        await JsBundleService.TryServeAsync(context);

        Assert.Equal(200, context.Response.StatusCode);
        Assert.Equal(0, context.Response.Body.Length);
    }

    [Fact]
    public async Task TryServeAsync_SetsCacheControlHeader()
    {
        WriteJsFile("theme-switcher.js", "var x=1;");
        JsBundleService.BuildBundle(_tempDir);

        var context = CreateContext("GET", JsBundleService.BundlePath);
        await JsBundleService.TryServeAsync(context);

        Assert.Contains("public", context.Response.Headers.CacheControl.ToString());
        Assert.Contains("max-age=31536000", context.Response.Headers.CacheControl.ToString());
        Assert.Contains("immutable", context.Response.Headers.CacheControl.ToString());
    }

    [Fact]
    public async Task TryServeAsync_BundleContainsFileContent()
    {
        WriteJsFile("theme-switcher.js", "function myThemeFunc(){}");
        JsBundleService.BuildBundle(_tempDir);

        var context = CreateContext("GET", JsBundleService.BundlePath);
        await JsBundleService.TryServeAsync(context);

        var body = ReadResponseBody(context);
        Assert.Contains("myThemeFunc", body);
    }

    [Fact]
    public void BundleFileOrder_ContainsExpectedFiles()
    {
        Assert.Contains("bootstrap.bundle.min.js", JsBundleService.BundleFileOrder);
        Assert.Contains("theme-switcher.js", JsBundleService.BundleFileOrder);
        Assert.Contains("timezone.js", JsBundleService.BundleFileOrder);
        Assert.Contains("bmw-lookup.js", JsBundleService.BundleFileOrder);
        Assert.Contains("toast.js", JsBundleService.BundleFileOrder);
        Assert.Contains("otp.js", JsBundleService.BundleFileOrder);
    }

    [Fact]
    public void BundleFileOrder_BootstrapIsFirst()
    {
        Assert.Equal("bootstrap.bundle.min.js", JsBundleService.BundleFileOrder[0]);
    }

    [Fact]
    public void VNextBundleFileOrder_BootstrapIsFirst()
    {
        Assert.Equal("bootstrap.bundle.min.js", JsBundleService.VNextBundleFileOrder[0]);
    }

    [Fact]
    public async Task BuildBundle_BootstrapIsIncludedWhenPresent()
    {
        WriteJsFile("bootstrap.bundle.min.js", "/* bootstrap bundle */");
        WriteJsFile("theme-switcher.js", "/* theme */");

        JsBundleService.BuildBundle(_tempDir);

        var context = CreateContext("GET", JsBundleService.BundlePath);
        await JsBundleService.TryServeAsync(context);

        var body = ReadResponseBody(context);
        Assert.Contains("bootstrap bundle", body);
        // Bootstrap should appear before theme-switcher
        var bootstrapIdx = body.IndexOf("bootstrap bundle", StringComparison.Ordinal);
        var themeIdx = body.IndexOf("theme-switcher.js", StringComparison.Ordinal);
        Assert.True(bootstrapIdx < themeIdx, "bootstrap.bundle.min.js should appear before theme-switcher.js");
    }

    // ── MinifyJs unit tests ────────────────────────────────────────────────────

    [Fact]
    public void MinifyJs_RemovesLineComments()
    {
        var result = JsBundleService.MinifyJs("var x = 1; // this is a comment\nvar y = 2;");
        Assert.DoesNotContain("this is a comment", result);
        Assert.Contains("var x = 1;", result);
        Assert.Contains("var y = 2;", result);
    }

    [Fact]
    public void MinifyJs_RemovesBlockComments()
    {
        var result = JsBundleService.MinifyJs("var x = /* block comment */ 1;");
        Assert.DoesNotContain("block comment", result);
        Assert.Contains("var x =", result);
        Assert.Contains("1;", result);
    }

    [Fact]
    public void MinifyJs_BlockComment_ReplacedWithSpace_PreventsMerge()
    {
        // "return/* comment */true" must not become "returntrue"
        var result = JsBundleService.MinifyJs("return/* comment */true;");
        Assert.Contains("return true;", result);
    }

    [Fact]
    public void MinifyJs_CollapsesExcessiveBlankLines()
    {
        var result = JsBundleService.MinifyJs("var x = 1;\n\n\n\nvar y = 2;");
        Assert.DoesNotContain("\n\n", result);
        Assert.Contains("var x = 1;", result);
        Assert.Contains("var y = 2;", result);
    }

    [Fact]
    public void MinifyJs_PreservesDoubleQuoteStringWithCommentSyntax()
    {
        var result = JsBundleService.MinifyJs("var url = \"http://example.com\"; // comment");
        Assert.Contains("http://example.com", result);
        Assert.DoesNotContain("// comment", result);
    }

    [Fact]
    public void MinifyJs_PreservesSingleQuoteStringWithBlockComment()
    {
        var result = JsBundleService.MinifyJs("var s = '/* not a comment */';");
        Assert.Contains("/* not a comment */", result);
    }

    [Fact]
    public void MinifyJs_PreservesTemplateLiteralWithCommentSyntax()
    {
        var result = JsBundleService.MinifyJs("var t = `// not a comment`;");
        Assert.Contains("// not a comment", result);
    }

    [Fact]
    public void MinifyJs_NormalisesCarriageReturns()
    {
        var result = JsBundleService.MinifyJs("var x = 1;\r\nvar y = 2;");
        Assert.DoesNotContain('\r', result);
        Assert.Contains("var x = 1;", result);
        Assert.Contains("var y = 2;", result);
    }

    [Fact]
    public void MinifyJs_SingleBlankLine_IsPreserved()
    {
        var result = JsBundleService.MinifyJs("var x = 1;\n\nvar y = 2;");
        // One blank line (two newlines) is acceptable – only *excessive* runs are collapsed
        Assert.Contains("var x = 1;", result);
        Assert.Contains("var y = 2;", result);
    }

    [Fact]
    public async Task BuildBundle_MinifiesNonMinFiles()
    {
        WriteJsFile("theme-switcher.js", "var x = 1; // comment to strip\nvar y = 2;");
        JsBundleService.BuildBundle(_tempDir);

        var context = CreateContext("GET", JsBundleService.BundlePath);
        await JsBundleService.TryServeAsync(context);

        var body = ReadResponseBody(context);
        Assert.DoesNotContain("comment to strip", body);
        Assert.Contains("var x = 1;", body);
    }

    [Fact]
    public async Task BuildBundle_DoesNotMinifyMinFiles()
    {
        WriteJsFile("bootstrap.bundle.min.js", "/* preserved comment */ var b=1;");
        JsBundleService.BuildBundle(_tempDir);

        var context = CreateContext("GET", JsBundleService.BundlePath);
        await JsBundleService.TryServeAsync(context);

        var body = ReadResponseBody(context);
        Assert.Contains("preserved comment", body);
    }
}
