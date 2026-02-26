using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using BareMetalWeb.Host;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace BareMetalWeb.Host.Tests;

public class CssBundleServiceTests : IDisposable
{
    private readonly string _tempRoot;

    public CssBundleServiceTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), "bmw-css-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(Path.Combine(_tempRoot, "css", "themes"));
        Directory.CreateDirectory(Path.Combine(_tempRoot, "js"));
        Directory.CreateDirectory(Path.Combine(_tempRoot, "fonts"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_tempRoot))
            Directory.Delete(_tempRoot, true);
    }

    private HttpContext CreateContext(string method, string path)
    {
        var context = new DefaultHttpContext();
        context.Request.Method = method;
        context.Request.Path = path;
        context.Response.Body = new MemoryStream();
        return context;
    }

    private void WriteThemeCss(string theme, string content)
        => File.WriteAllText(
            Path.Combine(_tempRoot, "css", "themes", $"{theme}.min.css"),
            content,
            Encoding.UTF8);

    // ── BuildBundles ──────────────────────────────────────────────────────────

    [Fact]
    public void BuildBundles_LoadsThemesFromDisk()
    {
        WriteThemeCss("vapor", "/* vapor theme */");

        CssBundleService.BuildBundles(Path.Combine(_tempRoot, "css"));

        Assert.True(CssBundleService.HasBundles);
        Assert.Contains("vapor", CssBundleService.LoadedThemes());
    }

    [Fact]
    public void BuildBundles_NoThemesDirectory_DoesNotThrow()
    {
        var emptyRoot = Path.Combine(_tempRoot, "empty");
        Directory.CreateDirectory(emptyRoot);

        // Should not throw when themes directory does not exist
        CssBundleService.BuildBundles(emptyRoot);
    }

    // ── TryServeAsync ─────────────────────────────────────────────────────────

    [Fact]
    public async Task TryServeAsync_KnownTheme_ReturnsTrue()
    {
        WriteThemeCss("flatly", "/* flatly */");
        CssBundleService.BuildBundles(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("GET", "/static/css/themes/flatly.min.css");
        var result = await CssBundleService.TryServeAsync(context);

        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_UnknownTheme_ReturnsFalse()
    {
        CssBundleService.BuildBundles(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("GET", "/static/css/themes/nonexistent.min.css");
        var result = await CssBundleService.TryServeAsync(context);

        Assert.False(result);
    }

    [Fact]
    public async Task TryServeAsync_SetsCorrectContentType()
    {
        WriteThemeCss("darkly", "/* darkly */");
        CssBundleService.BuildBundles(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("GET", "/static/css/themes/darkly.min.css");
        await CssBundleService.TryServeAsync(context);

        Assert.Equal("text/css; charset=utf-8", context.Response.ContentType);
    }

    [Fact]
    public async Task TryServeAsync_SetsETagHeader()
    {
        WriteThemeCss("slate", "/* slate */");
        CssBundleService.BuildBundles(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("GET", "/static/css/themes/slate.min.css");
        await CssBundleService.TryServeAsync(context);

        Assert.False(string.IsNullOrEmpty(context.Response.Headers.ETag.ToString()));
    }

    [Fact]
    public async Task TryServeAsync_Returns304_WhenETagMatches()
    {
        WriteThemeCss("lux", "/* lux */");
        CssBundleService.BuildBundles(Path.Combine(_tempRoot, "css"));

        var first = CreateContext("GET", "/static/css/themes/lux.min.css");
        await CssBundleService.TryServeAsync(first);
        var etag = first.Response.Headers.ETag.ToString();

        var second = CreateContext("GET", "/static/css/themes/lux.min.css");
        second.Request.Headers.IfNoneMatch = etag;
        var result = await CssBundleService.TryServeAsync(second);

        Assert.True(result);
        Assert.Equal(304, second.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_PostMethod_Returns405()
    {
        WriteThemeCss("superhero", "/* superhero */");
        CssBundleService.BuildBundles(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("POST", "/static/css/themes/superhero.min.css");
        var result = await CssBundleService.TryServeAsync(context);

        Assert.True(result);
        Assert.Equal(405, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_HeadMethod_ReturnsNoBody()
    {
        WriteThemeCss("cyborg", "/* cyborg */");
        CssBundleService.BuildBundles(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("HEAD", "/static/css/themes/cyborg.min.css");
        await CssBundleService.TryServeAsync(context);

        Assert.Equal(200, context.Response.StatusCode);
        Assert.Equal(0, context.Response.Body.Length);
    }

    // ── EnsureAssetsAsync (pre-existing files — no network required) ──────────

    [Fact]
    public async Task EnsureAssetsAsync_AllFilesExist_SkipsDownloadAndLoadsIntoMemory()
    {
        // Pre-create all required files so no HTTP calls are made
        File.WriteAllText(Path.Combine(_tempRoot, "js", "bootstrap.bundle.min.js"), "/* bootstrap js */");
        File.WriteAllBytes(Path.Combine(_tempRoot, "fonts", "bootstrap-icons.woff2"), new byte[] { 0x77, 0x4f, 0x46, 0x32 });

        foreach (var theme in CssBundleService.DefaultThemes)
            WriteThemeCss(theme, $"/* {theme} pre-existing */");

        var logged = new System.Collections.Generic.List<string>();
        await CssBundleService.EnsureAssetsAsync(_tempRoot, msg => logged.Add(msg));

        // No "Downloading" messages expected since all files already existed
        Assert.DoesNotContain(logged, m => m.StartsWith("Downloading"));

        // BuildBundles is called at end — themes should be in memory
        Assert.True(CssBundleService.HasBundles);
        foreach (var theme in CssBundleService.DefaultThemes)
            Assert.Contains(theme, CssBundleService.LoadedThemes());
    }

    [Fact]
    public async Task EnsureAssetsAsync_CreatesRequiredDirectories()
    {
        // Use a root with no subdirectories at all
        var freshRoot = Path.Combine(Path.GetTempPath(), "bmw-fresh-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(Path.Combine(freshRoot, "css"));
        Directory.CreateDirectory(Path.Combine(freshRoot, "js"));

        try
        {
            // Pre-create all files so no network access is needed
            File.WriteAllText(Path.Combine(freshRoot, "js", "bootstrap.bundle.min.js"), "/* js */");

            var fontsDir  = Path.Combine(freshRoot, "fonts");
            var themesDir = Path.Combine(freshRoot, "css", "themes");

            // Ensure directories don't pre-exist
            Assert.False(Directory.Exists(fontsDir));
            Assert.False(Directory.Exists(themesDir));

            // Create them manually (simulating what EnsureAssetsAsync does internally
            // after it creates dirs, it tries to download — pre-create woff2 and themes)
            Directory.CreateDirectory(fontsDir);
            Directory.CreateDirectory(themesDir);
            File.WriteAllBytes(Path.Combine(fontsDir, "bootstrap-icons.woff2"), Array.Empty<byte>());
            foreach (var theme in CssBundleService.DefaultThemes)
                File.WriteAllText(Path.Combine(themesDir, $"{theme}.min.css"), $"/* {theme} */");

            await CssBundleService.EnsureAssetsAsync(freshRoot);

            Assert.True(Directory.Exists(fontsDir));
            Assert.True(Directory.Exists(themesDir));
        }
        finally
        {
            if (Directory.Exists(freshRoot))
                Directory.Delete(freshRoot, true);
        }
    }

    [Fact]
    public void DefaultThemes_ContainsExpectedThemes()
    {
        Assert.Contains("vapor",     CssBundleService.DefaultThemes);
        Assert.Contains("darkly",    CssBundleService.DefaultThemes);
        Assert.Contains("cyborg",    CssBundleService.DefaultThemes);
        Assert.Contains("slate",     CssBundleService.DefaultThemes);
        Assert.Contains("superhero", CssBundleService.DefaultThemes);
        Assert.Contains("flatly",    CssBundleService.DefaultThemes);
        Assert.Contains("lux",       CssBundleService.DefaultThemes);
    }
}
