using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Host;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace BareMetalWeb.Host.Tests;

[Collection("CssBundleService")]
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
    public void DefaultThemes_Contains10Themes()
    {
        Assert.Equal(10, CssBundleService.DefaultThemes.Length);
    }

    [Theory]
    [InlineData("light")]
    [InlineData("dark")]
    [InlineData("colourful")]
    [InlineData("muted")]
    [InlineData("highviz")]
    [InlineData("ocean")]
    [InlineData("forest")]
    [InlineData("sunset")]
    [InlineData("midnight")]
    [InlineData("rose")]
    public void DefaultThemes_ContainsTheme(string theme)
    {
        Assert.Contains(theme, CssBundleService.DefaultThemes);
    }

    // ── DiscoverThemes ──────────────────────────────────────────────────────────

    [Fact]
    public void BuildBundles_LoadsThemesFromDisk()
    {
        WriteThemeCss("light", "/* light theme */");

        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        Assert.True(CssBundleService.HasBundles);
        Assert.Contains("light", CssBundleService.LoadedThemes());
    }

    [Fact]
    public void BuildBundles_NoThemesDirectory_DoesNotThrow()
    {
        var emptyRoot = Path.Combine(_tempRoot, "empty");
        Directory.CreateDirectory(emptyRoot);

        // Should not throw when themes directory does not exist
        CssBundleService.DiscoverThemes(emptyRoot);
    }

    [Fact]
    public void BuildBundles_MultipleThemes_AllLoaded()
    {
        foreach (var theme in new[] { "light", "dark", "muted" })
            WriteThemeCss(theme, $"/* {theme} */");

        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        var loaded = CssBundleService.LoadedThemes();
        Assert.Contains("light",  loaded);
        Assert.Contains("dark",   loaded);
        Assert.Contains("muted",  loaded);
    }

    // ── TryServeAsync ─────────────────────────────────────────────────────────

    [Fact]
    public async Task TryServeAsync_KnownTheme_ReturnsTrue()
    {
        WriteThemeCss("light", "/* light */");
        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("GET", "/static/css/themes/light.min.css");
        var result = await CssBundleService.TryServeAsync(context.ToBmw());

        Assert.True(result);
        Assert.Equal(200, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_UnknownPath_ReturnsFalse()
    {
        var context = CreateContext("GET", "/static/js/bundle.js");
        var result = await CssBundleService.TryServeAsync(context.ToBmw());

        Assert.False(result);
    }

    [Fact]
    public async Task TryServeAsync_UnknownThemeName_ReturnsFalse()
    {
        // A path with a theme name that is NOT in DefaultThemes (and never will be)
        // must always return false, regardless of what other tests have done.
        var context = CreateContext("GET", "/static/css/themes/nonexistent-xyz-abc.min.css");
        var result = await CssBundleService.TryServeAsync(context.ToBmw());

        Assert.False(result);
    }

    [Fact]
    public async Task TryServeAsync_SetsCorrectContentType()
    {
        WriteThemeCss("dark", "/* dark */");
        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("GET", "/static/css/themes/dark.min.css");
        await CssBundleService.TryServeAsync(context.ToBmw());

        Assert.Equal("text/css; charset=utf-8", context.Response.ContentType);
    }

    [Fact]
    public async Task TryServeAsync_SetsETagHeader()
    {
        WriteThemeCss("muted", "/* muted */");
        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("GET", "/static/css/themes/muted.min.css");
        await CssBundleService.TryServeAsync(context.ToBmw());

        Assert.False(string.IsNullOrEmpty(context.Response.Headers.ETag.ToString()));
    }

    [Fact]
    public async Task TryServeAsync_Returns304_WhenETagMatches()
    {
        WriteThemeCss("colourful", "/* colourful */");
        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        var first = CreateContext("GET", "/static/css/themes/colourful.min.css");
        await CssBundleService.TryServeAsync(first.ToBmw());
        var etag = first.Response.Headers.ETag.ToString();

        var second = CreateContext("GET", "/static/css/themes/colourful.min.css");
        second.Request.Headers.IfNoneMatch = etag;
        var result = await CssBundleService.TryServeAsync(second.ToBmw());

        Assert.True(result);
        Assert.Equal(304, second.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_PostMethod_Returns405()
    {
        WriteThemeCss("highviz", "/* highviz */");
        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("POST", "/static/css/themes/highviz.min.css");
        var result = await CssBundleService.TryServeAsync(context.ToBmw());

        Assert.True(result);
        Assert.Equal(405, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_HeadMethod_ReturnsNoBody()
    {
        WriteThemeCss("dark", "/* dark */");
        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("HEAD", "/static/css/themes/dark.min.css");
        await CssBundleService.TryServeAsync(context.ToBmw());

        Assert.Equal(200, context.Response.StatusCode);
        Assert.Equal(0, context.Response.Body.Length);
    }

    [Fact]
    public async Task TryServeAsync_SetsCacheControlHeader()
    {
        WriteThemeCss("light", "/* light */");
        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("GET", "/static/css/themes/light.min.css");
        await CssBundleService.TryServeAsync(context.ToBmw());

        Assert.Contains("public", context.Response.Headers.CacheControl.ToString());
        Assert.Contains("max-age=31536000", context.Response.Headers.CacheControl.ToString());
        Assert.Contains("immutable", context.Response.Headers.CacheControl.ToString());
    }

    // ── LoadAssets (pre-existing files — no network required) ───────────

    [Fact]
    public void LoadAssets_AllFilesExist_LoadsIntoMemory()
    {
        // Pre-create all required theme files on disk.
        foreach (var theme in CssBundleService.DefaultThemes)
            WriteThemeCss(theme, $"/* {theme} pre-existing */");

        CssBundleService.LoadAssets(_tempRoot);

        // BuildBundles is called — all 5 themes should be in memory.
        Assert.True(CssBundleService.HasBundles);
        foreach (var theme in CssBundleService.DefaultThemes)
            Assert.Contains(theme, CssBundleService.LoadedThemes());
    }

    [Fact]
    public void LoadAssets_EmptyThemesDir_DoesNotThrow()
    {
        // Use a fresh root with no theme files — LoadAssets should not throw.
        var freshRoot = Path.Combine(Path.GetTempPath(), "bmw-empty-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(Path.Combine(freshRoot, "css", "themes"));
        try
        {
            // Should complete without throwing even when no theme files exist.
            CssBundleService.LoadAssets(freshRoot);
        }
        finally
        {
            if (Directory.Exists(freshRoot)) Directory.Delete(freshRoot, true);
        }
    }

    [Fact]
    public async Task LoadAssets_LoadsThemesAndServesFromCache()
    {
        // Pre-create all files so they can be served.
        foreach (var theme in CssBundleService.DefaultThemes)
            WriteThemeCss(theme, $"/* {theme} */");

        CssBundleService.LoadAssets(_tempRoot);

        // After LoadAssets, all DefaultThemes must be served from cache.
        foreach (var theme in CssBundleService.DefaultThemes)
        {
            var context = CreateContext("GET", $"/static/css/themes/{theme}.min.css");
            var result = await CssBundleService.TryServeAsync(context.ToBmw());
            Assert.True(result, $"Theme '{theme}' should be served after LoadAssets");
            Assert.Equal(200, context.Response.StatusCode);
        }
    }
}
