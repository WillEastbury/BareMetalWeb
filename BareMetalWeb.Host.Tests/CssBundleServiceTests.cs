using BareMetalWeb.Core;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
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

    // ── CustomThemeDefinitions coverage ──────────────────────────────────────

    [Fact]
    public void CustomThemeDefinitions_Contains4Themes()
    {
        Assert.Equal(4, CssBundleService.CustomThemeDefinitions.Count);
    }

    [Theory]
    [InlineData("jigsaw")]
    [InlineData("rave")]
    [InlineData("luminescent")]
    [InlineData("geography")]
    public void CustomThemeDefinitions_ContainsTheme(string theme)
    {
        Assert.True(CssBundleService.CustomThemeDefinitions.ContainsKey(theme),
            $"CustomThemeDefinitions should contain '{theme}'");
    }

    [Theory]
    [InlineData("jigsaw", "lumen")]
    [InlineData("rave", "cyborg")]
    [InlineData("luminescent", "darkly")]
    [InlineData("geography", "sandstone")]
    public void CustomThemeDefinitions_HasCorrectBaseTheme(string theme, string expectedBase)
    {
        var (baseTheme, _) = CssBundleService.CustomThemeDefinitions[theme];
        Assert.Equal(expectedBase, baseTheme);
    }

    [Theory]
    [InlineData("jigsaw")]
    [InlineData("rave")]
    [InlineData("luminescent")]
    [InlineData("geography")]
    public void CustomThemeDefinitions_HasNonEmptyCustomCss(string theme)
    {
        var (_, customCss) = CssBundleService.CustomThemeDefinitions[theme];
        Assert.False(string.IsNullOrWhiteSpace(customCss),
            $"Custom CSS for '{theme}' should not be empty");
    }

    // ── DiscoverThemes ──────────────────────────────────────────────────────────

    [Fact]
    public void BuildBundles_LoadsThemesFromDisk()
    {
        WriteThemeCss("vapor", "/* vapor theme */");

        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        Assert.True(CssBundleService.HasBundles);
        Assert.Contains("vapor", CssBundleService.LoadedThemes());
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
        foreach (var theme in new[] { "darkly", "flatly", "slate" })
            WriteThemeCss(theme, $"/* {theme} */");

        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

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
        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("GET", "/static/css/themes/flatly.min.css");
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
        WriteThemeCss("darkly", "/* darkly */");
        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("GET", "/static/css/themes/darkly.min.css");
        await CssBundleService.TryServeAsync(context.ToBmw());

        Assert.Equal("text/css; charset=utf-8", context.Response.ContentType);
    }

    [Fact]
    public async Task TryServeAsync_SetsETagHeader()
    {
        WriteThemeCss("slate", "/* slate */");
        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("GET", "/static/css/themes/slate.min.css");
        await CssBundleService.TryServeAsync(context.ToBmw());

        Assert.False(string.IsNullOrEmpty(context.Response.Headers.ETag.ToString()));
    }

    [Fact]
    public async Task TryServeAsync_Returns304_WhenETagMatches()
    {
        WriteThemeCss("lux", "/* lux */");
        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        var first = CreateContext("GET", "/static/css/themes/lux.min.css");
        await CssBundleService.TryServeAsync(first.ToBmw());
        var etag = first.Response.Headers.ETag.ToString();

        var second = CreateContext("GET", "/static/css/themes/lux.min.css");
        second.Request.Headers.IfNoneMatch = etag;
        var result = await CssBundleService.TryServeAsync(second.ToBmw());

        Assert.True(result);
        Assert.Equal(304, second.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_PostMethod_Returns405()
    {
        WriteThemeCss("superhero", "/* superhero */");
        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("POST", "/static/css/themes/superhero.min.css");
        var result = await CssBundleService.TryServeAsync(context.ToBmw());

        Assert.True(result);
        Assert.Equal(405, context.Response.StatusCode);
    }

    [Fact]
    public async Task TryServeAsync_HeadMethod_ReturnsNoBody()
    {
        WriteThemeCss("cyborg", "/* cyborg */");
        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("HEAD", "/static/css/themes/cyborg.min.css");
        await CssBundleService.TryServeAsync(context.ToBmw());

        Assert.Equal(200, context.Response.StatusCode);
        Assert.Equal(0, context.Response.Body.Length);
    }

    [Fact]
    public async Task TryServeAsync_SetsCacheControlHeader()
    {
        WriteThemeCss("minty", "/* minty */");
        CssBundleService.DiscoverThemes(Path.Combine(_tempRoot, "css"));

        var context = CreateContext("GET", "/static/css/themes/minty.min.css");
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

        // Also pre-create custom theme files.
        foreach (var theme in CssBundleService.CustomThemeDefinitions.Keys)
            WriteThemeCss(theme, $"/* {theme} pre-existing */");

        CssBundleService.LoadAssets(_tempRoot);

        // BuildBundles is called — all 25 themes should be in memory.
        Assert.True(CssBundleService.HasBundles);
        foreach (var theme in CssBundleService.DefaultThemes)
            Assert.Contains(theme, CssBundleService.LoadedThemes());

        // All custom themes should also be in memory.
        foreach (var theme in CssBundleService.CustomThemeDefinitions.Keys)
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
        foreach (var theme in CssBundleService.CustomThemeDefinitions.Keys)
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

        // All custom themes must also be served from cache.
        foreach (var theme in CssBundleService.CustomThemeDefinitions.Keys)
        {
            var context = CreateContext("GET", $"/static/css/themes/{theme}.min.css");
            var result = await CssBundleService.TryServeAsync(context.ToBmw());
            Assert.True(result, $"Custom theme '{theme}' should be served after LoadAssets");
            Assert.Equal(200, context.Response.StatusCode);
        }
    }
}
