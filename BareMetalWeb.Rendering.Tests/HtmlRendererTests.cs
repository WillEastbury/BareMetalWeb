using System.IO;
using System.IO.Compression;
using System.Text;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Core.Host;
using BareMetalWeb.Host;
using BareMetalWeb.Interfaces;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Interfaces;
using BareMetalWeb.Rendering.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace BareMetalWeb.Rendering.Tests;

#region Stubs

internal sealed class StubHtmlTemplate : IHtmlTemplate
{
    public Encoding Encoding { get; set; } = Encoding.UTF8;
    public string ContentTypeHeader { get; set; } = "text/html; charset=utf-8";
    public string Head { get; set; } = "";
    public string Body { get; set; } = "";
    public string Footer { get; set; } = "";
    public string Script { get; set; } = "";
}

internal sealed class StubFragmentRenderer : IHtmlFragmentRenderer
{
    public byte[] DocTypeAndHeadStart { get; set; } = Encoding.UTF8.GetBytes("<!DOCTYPE html><html><head><meta charset='");
    public byte[] HeadEndAndBodyStart { get; set; } = Encoding.UTF8.GetBytes("</head><body>");
    public byte[] BodyEndAndHtmlEnd { get; set; } = Encoding.UTF8.GetBytes("</body></html>");
    public byte[] ScriptTagStart { get; set; } = Encoding.UTF8.GetBytes("<script>");
    public byte[] ScriptTagEnd { get; set; } = Encoding.UTF8.GetBytes("</script>");

    public byte[] LastRenderMenuLeftResult { get; set; } = Encoding.UTF8.GetBytes("<nav>left</nav>");
    public byte[] LastRenderMenuRightResult { get; set; } = Encoding.UTF8.GetBytes("<nav>right</nav>");
    public byte[] LastRenderTableResult { get; set; } = Encoding.UTF8.GetBytes("<table>rendered</table>");
    public byte[] LastRenderFormResult { get; set; } = Encoding.UTF8.GetBytes("<form>rendered</form>");

    public byte[] RenderMenuOptions(List<IMenuOption> options, bool rightAligned)
        => rightAligned ? LastRenderMenuRightResult : LastRenderMenuLeftResult;

    public byte[] RenderTable(string[] columnTitles, string[][] rows)
        => LastRenderTableResult;

    public byte[] RenderForm(FormDefinition definition)
        => LastRenderFormResult;
}

internal sealed class StubMenuOption : IMenuOption
{
    public string Href { get; set; } = "/";
    public string Label { get; set; } = "Home";
    public bool ShowOnNavBar { get; set; } = true;
    public string PermissionsNeeded { get; set; } = "";
    public bool RightAligned { get; set; }
    public bool HighlightAsButton { get; set; }
    public bool RequiresAnonymous { get; set; }
    public bool RequiresLoggedIn { get; set; }
    public string[] RequiredPermissions { get; set; } = Array.Empty<string>();
    public string? ColorClass { get; set; }
    public string? Group { get; set; }
}

internal sealed class StubBareWebHost : IBareWebHost
{
    public static string[] appMetaDataKeys { get; set; } = Array.Empty<string>();

    public WebApplication app { get; set; } = null!;
    public IBufferedLogger BufferedLogger => null!;
    public IMetricsTracker Metrics { get; set; } = null!;
    public IClientRequestTracker ClientRequests => null!;
    public IHtmlRenderer HtmlRenderer => null!;
    public Dictionary<string, RouteHandlerData> routes { get; set; } = new();
    public string AppName { get; set; } = "TestApp";
    public string CompanyDescription { get; set; } = "";
    public string CopyrightYear { get; set; } = "2024";
    public string PrivacyPolicyUrl { get; set; } = "";
    public string[] AppMetaDataKeys { get; } = Array.Empty<string>();
    public string[] AppMetaDataValues { get; set; } = Array.Empty<string>();
    public List<IMenuOption> MenuOptionsList { get; set; } = new();
    public PageInfo NotFoundPageInfo => null!;
    public PageInfo ErrorPageInfo => null!;
    public CancellationTokenSource cts { get; } = new();
    public string[] CorsAllowedOrigins { get; set; } = Array.Empty<string>();
    public string[] CorsAllowedMethods { get; set; } = Array.Empty<string>();
    public string[] CorsAllowedHeaders { get; set; } = Array.Empty<string>();
    public StaticFileConfigOptions StaticFiles { get; set; } = new();
    public HttpsRedirectMode HttpsRedirectMode { get; set; }
    public bool TrustForwardedHeaders { get; set; }
    public bool HttpsEndpointAvailable { get; set; }
    public string? HttpsRedirectHost { get; set; }
    public int? HttpsRedirectPort { get; set; }
    public bool ShowHostDiagnostics { get; set; } = false;

    public ValueTask BuildAppInfoMenuOptionsAsync(HttpContext? context = null, CancellationToken cancellationToken = default)
        => ValueTask.CompletedTask;

    public void RegisterRoute(string path, RouteHandlerData routeHandler) { }
    public Task RenderForbidden(HttpContext context) => Task.CompletedTask;
    public Task RequestHandler(HttpContext context) => Task.CompletedTask;
    public Task WireUpRequestHandlingAndLoggerAsyncLifetime() => Task.CompletedTask;
}

#endregion

public class HtmlRendererTests
{
    private readonly StubFragmentRenderer _fragments = new();
    private readonly StubBareWebHost _app = new();
    private readonly HtmlRenderer _renderer;

    public HtmlRendererTests()
    {
        _renderer = new HtmlRenderer(_fragments);
    }

    private async Task<string> RenderAsync(
        StubHtmlTemplate template,
        string[]? keys = null,
        string[]? values = null,
        string[]? appkeys = null,
        string[]? appvalues = null,
        string[]? tableColumnTitles = null,
        string[][]? tableRows = null,
        FormDefinition? formDefinition = null,
        TemplateLoop[]? templateLoops = null)
    {
        var result = await _renderer.RenderToBytesAsync(
            template,
            keys ?? Array.Empty<string>(),
            values ?? Array.Empty<string>(),
            appkeys ?? Array.Empty<string>(),
            appvalues ?? Array.Empty<string>(),
            _app,
            tableColumnTitles,
            tableRows,
            formDefinition,
            templateLoops);
        return Encoding.UTF8.GetString(result);
    }

    [Fact]
    public async Task RenderToBytesAsync_TokenSubstitution_ReplacesPageKeysInBody()
    {
        var template = new StubHtmlTemplate { Body = "Hello {{name}}!" };
        var html = await RenderAsync(template, keys: new[] { "name" }, values: new[] { "World" });
        Assert.Contains("Hello World!", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_AppMetadataSubstitution_ReplacesAppKeys()
    {
        var template = new StubHtmlTemplate { Body = "App: {{AppName}}, Year: {{CopyrightYear}}" };
        var html = await RenderAsync(template,
            appkeys: new[] { "AppName", "CopyrightYear" },
            appvalues: new[] { "MyApp", "2024" });
        Assert.Contains("App: MyApp, Year: 2024", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_UnknownTokens_RemovedFromOutput()
    {
        var template = new StubHtmlTemplate { Body = "Before{{unknown}}After" };
        var html = await RenderAsync(template);
        Assert.Contains("BeforeAfter", html);
        Assert.DoesNotContain("{{unknown}}", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_EmptyTemplate_ProducesMinimalOutput()
    {
        var template = new StubHtmlTemplate();
        var html = await RenderAsync(template);
        Assert.Contains("<!DOCTYPE html>", html);
        Assert.Contains("</head><body>", html);
        Assert.Contains("</body></html>", html);
        Assert.DoesNotContain("<script>", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_ScriptNonEmpty_WrappedInScriptTags()
    {
        var template = new StubHtmlTemplate { Script = "alert('hi');" };
        var html = await RenderAsync(template);
        Assert.Contains("<script>alert('hi');</script>", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_ScriptEmpty_NoScriptTags()
    {
        var template = new StubHtmlTemplate { Script = "" };
        var html = await RenderAsync(template);
        Assert.DoesNotContain("<script>", html);
        Assert.DoesNotContain("</script>", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_TemplateLoop_IteratesItems()
    {
        var template = new StubHtmlTemplate { Body = "{{Loop%%items}}{{name}},{{EndLoop%%items}}" };
        var loops = new[]
        {
            new TemplateLoop("items", new List<IReadOnlyDictionary<string, string>>
            {
                new Dictionary<string, string> { ["name"] = "Alice" },
                new Dictionary<string, string> { ["name"] = "Bob" },
                new Dictionary<string, string> { ["name"] = "Carol" }
            })
        };
        var html = await RenderAsync(template, templateLoops: loops);
        Assert.Contains("Alice,Bob,Carol,", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_NestedLoopVariables_ProvideScopedKeyValues()
    {
        var template = new StubHtmlTemplate { Body = "{{Loop%%rows}}[{{id}}:{{val}}]{{EndLoop%%rows}}" };
        var loops = new[]
        {
            new TemplateLoop("rows", new List<IReadOnlyDictionary<string, string>>
            {
                new Dictionary<string, string> { ["id"] = "1", ["val"] = "a" },
                new Dictionary<string, string> { ["id"] = "2", ["val"] = "b" }
            })
        };
        var html = await RenderAsync(template, templateLoops: loops);
        Assert.Contains("[1:a][2:b]", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_ForLoop_ProducesSequence()
    {
        var template = new StubHtmlTemplate { Body = "{{For%%i|1|3|1}}{{i}}{{EndFor%%i}}" };
        var html = await RenderAsync(template);
        Assert.Contains("123", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_ForLoopDecrement_ProducesReverseSequence()
    {
        var template = new StubHtmlTemplate { Body = "{{For%%i|3|1|-1}}{{i}}{{EndFor%%i}}" };
        var html = await RenderAsync(template);
        Assert.Contains("321", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_TableInjection_ReplacesTableToken()
    {
        var template = new StubHtmlTemplate { Body = "Data:{{table}}" };
        var html = await RenderAsync(template,
            tableColumnTitles: new[] { "Col1" },
            tableRows: new[] { new[] { "Val1" } });
        Assert.Contains("Data:<table>rendered</table>", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_FormInjection_ReplacesFormToken()
    {
        var template = new StubHtmlTemplate { Body = "Form:{{form}}" };
        var formDef = new FormDefinition("action", "POST", "Submit", new List<FormField>());
        var html = await RenderAsync(template, formDefinition: formDef);
        Assert.Contains("Form:<form>rendered</form>", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_MenuInjection_ReplacesLinkTokens()
    {
        var template = new StubHtmlTemplate { Body = "L:{{links_left}} R:{{links_right}}" };
        var html = await RenderAsync(template);
        Assert.Contains("L:<nav>left</nav>", html);
        Assert.Contains("R:<nav>right</nav>", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_PageKeysPrecedeAppKeys_PageValueWins()
    {
        var template = new StubHtmlTemplate { Body = "{{title}}" };
        var html = await RenderAsync(template,
            keys: new[] { "title" }, values: new[] { "PageTitle" },
            appkeys: new[] { "title" }, appvalues: new[] { "AppTitle" });
        Assert.Contains("PageTitle", html);
        Assert.DoesNotContain("AppTitle", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_MultipleTokensInSameSection_AllReplaced()
    {
        var template = new StubHtmlTemplate { Body = "{{greeting}} {{name}}, welcome to {{place}}!" };
        var html = await RenderAsync(template,
            keys: new[] { "greeting", "name", "place" },
            values: new[] { "Hello", "User", "Earth" });
        Assert.Contains("Hello User, welcome to Earth!", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_TokenInHead_IsSubstituted()
    {
        var template = new StubHtmlTemplate { Head = "<title>{{pageTitle}}</title>" };
        var html = await RenderAsync(template,
            keys: new[] { "pageTitle" }, values: new[] { "My Page" });
        Assert.Contains("<title>My Page</title>", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_TokenInFooter_IsSubstituted()
    {
        var template = new StubHtmlTemplate { Footer = "<footer>{{copyright}}</footer>" };
        var html = await RenderAsync(template,
            keys: new[] { "copyright" }, values: new[] { "2024 Corp" });
        Assert.Contains("<footer>2024 Corp</footer>", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_Encoding_OutputIsValidUtf8()
    {
        var template = new StubHtmlTemplate { Body = "Héllo Wörld — ñ" };
        var bytes = await _renderer.RenderToBytesAsync(
            template,
            Array.Empty<string>(), Array.Empty<string>(),
            Array.Empty<string>(), Array.Empty<string>(),
            _app);
        var decoded = Encoding.UTF8.GetString(bytes);
        Assert.Contains("Héllo Wörld — ñ", decoded);
    }

    [Fact]
    public async Task RenderToBytesAsync_EmptyLoop_ProducesNoLoopBody()
    {
        var template = new StubHtmlTemplate { Body = "before{{Loop%%empty}}X{{EndLoop%%empty}}after" };
        var loops = new[] { new TemplateLoop("empty", new List<IReadOnlyDictionary<string, string>>()) };
        var html = await RenderAsync(template, templateLoops: loops);
        Assert.Contains("beforeafter", html);
        Assert.DoesNotContain("X", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_MissingLoopKey_LoopBodyOmitted()
    {
        var template = new StubHtmlTemplate { Body = "before{{Loop%%missing}}X{{EndLoop%%missing}}after" };
        var html = await RenderAsync(template);
        Assert.Contains("beforeafter", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_TokenInScript_Substituted()
    {
        var template = new StubHtmlTemplate { Script = "var x = '{{val}}';" };
        var html = await RenderAsync(template, keys: new[] { "val" }, values: new[] { "test" });
        Assert.Contains("var x = 'test';", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_ForLoopInBody_WithStep2()
    {
        var template = new StubHtmlTemplate { Body = "{{For%%n|0|6|2}}{{n}},{{EndFor%%n}}" };
        var html = await RenderAsync(template);
        Assert.Contains("0,2,4,6,", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_HtmlSpecialCharsInValue_AreEncoded()
    {
        // Defense-in-depth: values with HTML special chars must be encoded
        var template = new StubHtmlTemplate { Body = "{{title}}" };
        var html = await RenderAsync(template,
            keys: new[] { "title" }, values: new[] { "<script>alert('xss')</script>" });
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_HtmlPrefixedKey_WritesRawHtml()
    {
        // Keys with "html_" prefix should bypass encoding (intentional raw HTML)
        var template = new StubHtmlTemplate { Body = "{{html_message}}" };
        var html = await RenderAsync(template,
            keys: new[] { "html_message" }, values: new[] { "<p>Hello <strong>World</strong></p>" });
        Assert.Contains("<p>Hello <strong>World</strong></p>", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_AppMetaHtmlSpecialChars_AreEncoded()
    {
        // App metadata values with special chars must also be encoded
        var template = new StubHtmlTemplate { Body = "{{AppName}}" };
        var html = await RenderAsync(template,
            appkeys: new[] { "AppName" }, appvalues: new[] { "Acme & Co. <Ltd>" });
        Assert.Contains("Acme &amp; Co. &lt;Ltd&gt;", html);
    }

    [Fact]
    public async Task RenderToBytesAsync_LoopItemHtmlSpecialChars_AreEncoded()
    {
        // Loop scoped values with special chars must be encoded
        var template = new StubHtmlTemplate { Body = "{{Loop%%rows}}{{name}}{{EndLoop%%rows}}" };
        var loops = new[]
        {
            new TemplateLoop("rows", new List<IReadOnlyDictionary<string, string>>
            {
                new Dictionary<string, string> { ["name"] = "<Evil>" }
            })
        };
        var html = await RenderAsync(template, templateLoops: loops);
        Assert.DoesNotContain("<Evil>", html);
        Assert.Contains("&lt;Evil&gt;", html);
    }
}

public class HtmlRendererCompressionTests
{
    private readonly StubFragmentRenderer _fragments = new();
    private readonly StubBareWebHost _app = new();
    private readonly HtmlRenderer _renderer;

    public HtmlRendererCompressionTests()
    {
        _renderer = new HtmlRenderer(_fragments);
    }

    private static PageInfo MakePageInfo(string bodyContent = "Hello World")
    {
        var template = new StubHtmlTemplate { Body = bodyContent };
        var meta = new PageMetaData(template, 200);
        var ctx = new PageContext(Array.Empty<string>(), Array.Empty<string>());
        return new PageInfo(meta, ctx);
    }

    private static DefaultHttpContext CreateHttpContext(string? acceptEncoding = null)
    {
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        if (acceptEncoding != null)
            context.Request.Headers.AcceptEncoding = acceptEncoding;
        return context;
    }

    [Fact]
    public async Task RenderPage_WithBrotliAcceptEncoding_SetsBrContentEncoding()
    {
        var context = CreateHttpContext("br");
        await _renderer.RenderPage(context, MakePageInfo(), _app);

        Assert.Equal("br", context.Response.Headers.ContentEncoding.ToString());
        Assert.Contains("Accept-Encoding", context.Response.Headers.Vary.ToString());
    }

    [Fact]
    public async Task RenderPage_WithGzipAcceptEncoding_SetsGzipContentEncoding()
    {
        var context = CreateHttpContext("gzip");
        await _renderer.RenderPage(context, MakePageInfo(), _app);

        Assert.Equal("gzip", context.Response.Headers.ContentEncoding.ToString());
        Assert.Contains("Accept-Encoding", context.Response.Headers.Vary.ToString());
    }

    [Fact]
    public async Task RenderPage_WithNoAcceptEncoding_NoContentEncodingHeader()
    {
        var context = CreateHttpContext();
        await _renderer.RenderPage(context, MakePageInfo(), _app);

        Assert.Empty(context.Response.Headers.ContentEncoding.ToString());
    }

    [Fact]
    public async Task RenderPage_WithBrotliAcceptEncoding_BodyIsDecompressibleBrotli()
    {
        var context = CreateHttpContext("br");
        await _renderer.RenderPage(context, MakePageInfo("Test content for brotli"), _app);

        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var bs = new BrotliStream(context.Response.Body, CompressionMode.Decompress);
        using var result = new MemoryStream();
        bs.CopyTo(result);
        var html = Encoding.UTF8.GetString(result.ToArray());
        Assert.Contains("Test content for brotli", html);
    }

    [Fact]
    public async Task RenderPage_WithGzipAcceptEncoding_BodyIsDecompressibleGzip()
    {
        var context = CreateHttpContext("gzip");
        await _renderer.RenderPage(context, MakePageInfo("Test content for gzip"), _app);

        context.Response.Body.Seek(0, SeekOrigin.Begin);
        using var gz = new GZipStream(context.Response.Body, CompressionMode.Decompress);
        using var result = new MemoryStream();
        gz.CopyTo(result);
        var html = Encoding.UTF8.GetString(result.ToArray());
        Assert.Contains("Test content for gzip", html);
    }
}

public class DiagnosticBannerTests
{
    private static StubBareWebHost CreateHost(bool showHostDiagnostics)
    {
        var host = new StubBareWebHost { ShowHostDiagnostics = showHostDiagnostics };
        return host;
    }

    private static HttpContext CreateContext(string? showhst = null, string? xForwardedHost = null)
    {
        var ctx = new DefaultHttpContext();
        if (showhst != null)
            ctx.Request.QueryString = new QueryString($"?showhst={showhst}");
        if (xForwardedHost != null)
            ctx.Request.Headers["X-Forwarded-Host"] = xForwardedHost;
        ctx.Request.Host = new HostString("localhost");
        return ctx;
    }

    [Fact]
    public void ShouldShowDiagnosticBanner_AppSettingFalse_ReturnsFalse()
    {
        var host = CreateHost(false);
        var context = CreateContext("true");
        Assert.False(HtmlRenderer.ShouldShowDiagnosticBanner(context, host));
    }

    [Fact]
    public void ShouldShowDiagnosticBanner_QsParamMissing_ReturnsFalse()
    {
        var host = CreateHost(true);
        var context = CreateContext(showhst: null);
        Assert.False(HtmlRenderer.ShouldShowDiagnosticBanner(context, host));
    }

    [Fact]
    public void ShouldShowDiagnosticBanner_QsParamFalse_ReturnsFalse()
    {
        var host = CreateHost(true);
        var context = CreateContext("false");
        Assert.False(HtmlRenderer.ShouldShowDiagnosticBanner(context, host));
    }

    [Fact]
    public void ShouldShowDiagnosticBanner_BothTrue_ReturnsTrue()
    {
        var host = CreateHost(true);
        var context = CreateContext("true");
        Assert.True(HtmlRenderer.ShouldShowDiagnosticBanner(context, host));
    }

    [Fact]
    public void ShouldShowDiagnosticBanner_QsParamCaseInsensitive_ReturnsTrue()
    {
        var host = CreateHost(true);
        var context = CreateContext("True");
        Assert.True(HtmlRenderer.ShouldShowDiagnosticBanner(context, host));
    }

    [Fact]
    public void InjectBeforeBodyEnd_InjectsBeforeClosingBodyTag()
    {
        var source = Encoding.UTF8.GetBytes("<html><body><p>content</p></body></html>");
        var insert = Encoding.UTF8.GetBytes("<div>banner</div>");
        var result = Encoding.UTF8.GetString(HtmlRenderer.InjectBeforeBodyEnd(source, insert));
        Assert.Equal("<html><body><p>content</p><div>banner</div></body></html>", result);
    }

    [Fact]
    public void InjectBeforeBodyEnd_NoBodyTag_AppendsAtEnd()
    {
        var source = Encoding.UTF8.GetBytes("<html><p>no body tag</p></html>");
        var insert = Encoding.UTF8.GetBytes("<div>banner</div>");
        var result = Encoding.UTF8.GetString(HtmlRenderer.InjectBeforeBodyEnd(source, insert));
        Assert.Equal("<html><p>no body tag</p></html><div>banner</div>", result);
    }

    [Fact]
    public void BuildDiagnosticBannerHtml_UsesXForwardedHostWhenPresent()
    {
        var host = CreateHost(true);
        host.Metrics = new StubMetricsTracker();
        var context = CreateContext("true", "proxy.example.com");
        var html = HtmlRenderer.BuildDiagnosticBannerHtml(context, host, 1024);
        Assert.Contains("proxy.example.com", html);
        Assert.Contains("bm-diag-banner", html);
    }

    [Fact]
    public void BuildDiagnosticBannerHtml_FallsBackToRequestHostWhenNoForwardedHeader()
    {
        var host = CreateHost(true);
        host.Metrics = new StubMetricsTracker();
        var context = CreateContext("true");
        var html = HtmlRenderer.BuildDiagnosticBannerHtml(context, host, 512);
        Assert.Contains("localhost", html);
        Assert.Contains("512", html);
    }
}

internal sealed class StubMetricsTracker : IMetricsTracker
{
    public void RecordRequest(int statusCode, TimeSpan elapsed) { }
    public void RecordThrottled(TimeSpan elapsed) { }
    public void GetMetricTable(out string[] tableColumns, out string[][] tableRows)
    {
        tableColumns = Array.Empty<string>();
        tableRows = Array.Empty<string[]>();
    }
    public MetricsSnapshot GetSnapshot() => new MetricsSnapshot(
        0, 0, TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero, TimeSpan.FromMilliseconds(1.5),
        TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero, 0, 0, 0, 0, 0, 0, 0, 0, TimeSpan.Zero);
}
