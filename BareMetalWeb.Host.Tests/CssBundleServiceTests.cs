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

    // ── DefaultThemes coverage ────────────────────────────────────────────────

    [Fact]
    public void DefaultThemes_Contains25Themes()
    {
        Assert.Equal(25, CssBundleService.DefaultThemes.Length);
    }

    [Theory]
    [InlineData("cerulean")]
    [InlineData("cosmo")]
    [InlineData("cyborg")]
    [InlineData("darkly")]
    [InlineData("flatly")]
    [InlineData("journal")]
    [InlineData("litera")]
    [InlineData("lumen")]
    [InlineData("lux")]
    [InlineData("materia")]
    [InlineData("minty")]
    [InlineData("morph")]
    [InlineData("pulse")]
    [InlineData("quartz")]
    [InlineData("sandstone")]
    [InlineData("simplex")]
    [InlineData("sketchy")]
    [InlineData("slate")]
    [InlineData("solar")]
    [InlineData("spacelab")]
    [InlineData("superhero")]
    [InlineData("united")]
    [InlineData("vapor")]
    [InlineData("yeti")]
    [InlineData("zephyr")]
    public void DefaultThemes_ContainsTheme(string theme)
    {
        Assert.Contains(theme, CssBundleService.DefaultThemes);
    }

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

    [Fact]
    public void BuildBundles_MultipleThemes_AllLoaded()
    {
        foreach (var theme in new[] { "darkly", "flatly", "slate" })
            WriteThemeCss(theme, $"/* {theme} */");

        CssBundleService.BuildBundles(Path.Combine(_tempRoot, "css"));

        var loaded = CssBundleService.LoadedThemes();
        Assert.Contains("darkly",  loaded);
        Assert.Contains("flatly",  loaded);
        Assert.Contains("slate",   loaded);
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
    public async Task TryServeAsync_UnknownPath_ReturnsFalse()
    {
        var context = CreateContext("GET", "/static/js/bundle.js");
        var result = await CssBundleService.TryServeAsync(context);

        Assert.False(result);
    }

    [Fact]
    public async Task TryServeAsync_UnknownThemeName_ReturnsFalse()
    {
        // A path with a theme name that is NOT in DefaultThemes (and never will be)
        // must always return false, regardless of what other tests have done.
        var context = CreateContext("GET", "/static/css/themes/nonexistent-xyz-abc.min.css");
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

    [Fact]
    public async Task TryServeAsync_SetsCacheControlHeader()
    {
        WriteThemeCss("minty", "/* minty */");
        CssBundleService.BuildBundles(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("GET", "/static/css/themes/minty.min.css");
        await CssBundleService.TryServeAsync(context);

        Assert.Contains("public", context.Response.Headers.CacheControl.ToString());
        Assert.Contains("max-age=31536000", context.Response.Headers.CacheControl.ToString());
        Assert.Contains("immutable", context.Response.Headers.CacheControl.ToString());
    }

    // ── EnsureAssetsAsync (pre-existing files — no network required) ──────────

    [Fact]
    public async Task EnsureAssetsAsync_AllFilesExist_SkipsDownloadAndLoadsIntoMemory()
    {
        // Pre-create all required files so no HTTP calls are made.
        File.WriteAllText(Path.Combine(_tempRoot, "js", "bootstrap.bundle.min.js"), "/* bootstrap js */");
        File.WriteAllBytes(Path.Combine(_tempRoot, "fonts", "bootstrap-icons.woff2"), new byte[] { 0x77, 0x4f, 0x46, 0x32 });

        foreach (var theme in CssBundleService.DefaultThemes)
            WriteThemeCss(theme, $"/* {theme} pre-existing */");

        var logged = new System.Collections.Generic.List<string>();
        await CssBundleService.EnsureAssetsAsync(_tempRoot, msg => logged.Add(msg));

        // No "Downloading" messages expected since all files already existed.
        Assert.DoesNotContain(logged, m => m.StartsWith("Downloading"));

        // BuildBundles is called at end — all 25 themes should be in memory.
        Assert.True(CssBundleService.HasBundles);
        foreach (var theme in CssBundleService.DefaultThemes)
            Assert.Contains(theme, CssBundleService.LoadedThemes());
    }

    [Fact]
    public async Task EnsureAssetsAsync_CreatesRequiredDirectories()
    {
        // Use a root that has css/ and js/ but NOT themes/ or fonts/.
        var freshRoot = Path.Combine(Path.GetTempPath(), "bmw-fresh-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(Path.Combine(freshRoot, "css"));
        Directory.CreateDirectory(Path.Combine(freshRoot, "js"));

        try
        {
            var fontsDir  = Path.Combine(freshRoot, "fonts");
            var themesDir = Path.Combine(freshRoot, "css", "themes");

            Assert.False(Directory.Exists(fontsDir));
            Assert.False(Directory.Exists(themesDir));

            // Pre-create files to avoid real network calls inside EnsureAssetsAsync.
            File.WriteAllText(Path.Combine(freshRoot, "js", "bootstrap.bundle.min.js"), "/* js */");
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
    public async Task EnsureAssetsAsync_SetsStaticRootForLazyLoading()
    {
        // Pre-create all files so no network is needed.
        File.WriteAllText(Path.Combine(_tempRoot, "js", "bootstrap.bundle.min.js"), "/* js */");
        File.WriteAllBytes(Path.Combine(_tempRoot, "fonts", "bootstrap-icons.woff2"), Array.Empty<byte>());
        foreach (var theme in CssBundleService.DefaultThemes)
            WriteThemeCss(theme, $"/* {theme} */");

        await CssBundleService.EnsureAssetsAsync(_tempRoot);

        // After EnsureAssetsAsync, all DefaultThemes must be served from cache.
        foreach (var theme in CssBundleService.DefaultThemes)
        {
            var context = CreateContext("GET", $"/static/css/themes/{theme}.min.css");
            var result = await CssBundleService.TryServeAsync(context);
            Assert.True(result, $"Theme '{theme}' should be served after EnsureAssetsAsync");
            Assert.Equal(200, context.Response.StatusCode);
        }
    }
}
