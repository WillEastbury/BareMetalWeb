using System;
using System.Buffers;
using System.IO;
using System.IO.Pipelines;
using System.Text;
using BareMetalWeb.Rendering;
using BareMetalWeb.Rendering.Interfaces;
using BareMetalWeb.Interfaces;
using BenchmarkDotNet.Attributes;

namespace BareMetalWeb.Benchmarks;

/// <summary>
/// Benchmarks comparing three HTML render strategies:
///   1. Original — re-parses templates via PipeWriter streaming (multiple GetSpan/Advance)
///   2. Arena    — re-parses templates into ArrayBufferWriter (single contiguous buffer)
///   3. Compiled — pre-parsed RenderPlan, writes directly to PipeWriter (zero-copy streaming)
///
/// All three produce identical HTML output.
/// </summary>
[MemoryDiagnoser]
[ShortRunJob]
public class HtmlRenderBenchmarks
{
    private HtmlRenderer _renderer = null!;
    private IHtmlTemplate _template = null!;
    private string[] _pageKeys = null!;
    private string[] _pageValues = null!;
    private string[] _appKeys = null!;
    private string[] _appValues = null!;

    [GlobalSetup]
    public void Setup()
    {
        var fragmentStore = new StubFragmentStore();
        var fragments = new HtmlFragmentRenderer(fragmentStore);
        _renderer = new HtmlRenderer(fragments);

        _template = new HtmlTemplate(
            head: "<title>{{page_title}}</title><meta name=\"description\" content=\"{{description}}\"><link rel=\"stylesheet\" href=\"{{theme_css_url}}\">",
            body: "<h1>{{page_title}}</h1><p>{{content}}</p><div>{{html_sidebar}}</div><nav>{{links_left}}</nav><aside>{{links_right}}</aside>",
            footer: "<footer>&copy; {{copyright_year}} {{company_name}}</footer>",
            script: "console.log('{{csp_nonce}}');"
        );

        _pageKeys = new[] { "page_title", "description", "theme_css_url", "content", "html_sidebar", "copyright_year", "company_name", "csp_nonce" };
        _pageValues = new[] { "Dashboard", "Main dashboard view", "/static/css/themes/vapor.min.css", "Welcome to BareMetalWeb", "<ul><li>Link 1</li><li>Link 2</li></ul>", "2026", "Contoso Ltd", "abc123" };
        _appKeys = new[] { "app_name", "app_version" };
        _appValues = new[] { "BareMetalWeb", "1.0.0" };
    }

    [Benchmark(Baseline = true)]
    public async Task<int> Original_PipeWriter()
    {
        var ms = new MemoryStream();
        var pw = PipeWriter.Create(ms);
        await _renderer.RenderToStreamAsync(pw, _template, _pageKeys, _pageValues, _appKeys, _appValues, new StubApp());
        await pw.CompleteAsync();
        return (int)ms.Length;
    }

    [Benchmark]
    public async Task<int> Arena_SingleBuffer()
    {
        var output = await _renderer.RenderToBytesArenaAsync(_template, _pageKeys, _pageValues, _appKeys, _appValues, new StubApp());
        return output.Length;
    }

    [Benchmark]
    public async Task<int> Compiled_ZeroCopy()
    {
        var ms = new MemoryStream();
        var pw = PipeWriter.Create(ms);
        await _renderer.RenderToStreamCompiledAsync(pw, _template, _pageKeys, _pageValues, _appKeys, _appValues, new StubApp());
        await pw.CompleteAsync();
        return (int)ms.Length;
    }

    [Benchmark]
    public async Task<int> Compiled_Buffered()
    {
        var output = await _renderer.RenderToBytesCompiledAsync(_template, _pageKeys, _pageValues, _appKeys, _appValues, new StubApp());
        return output.Length;
    }

    // ── Minimal stubs ──────────────────────────────────────────────────

    private sealed class StubFragmentStore : IHtmlFragmentStore
    {
        public string ReturnTemplateFragment(string key) => key switch
        {
            "DocTypeAndHeadStart" => "<!DOCTYPE html><html><head><meta charset='",
            "HeadEndAndBodyStart" => "</head><body>",
            "BodyEndAndHtmlEnd" => "</body></html>",
            "ScriptTagStart" => "<script>",
            "ScriptTagEnd" => "</script>",
            "MenuOption" => "<a href=\"{{href}}\" class=\"{{class}}\">{{label}}</a>",
            _ => $"<!-- {key} -->"
        };

        public string ZeroAllocationReplaceCopy(string template, string[] keys, string[] values)
        {
            var result = template;
            for (int i = 0; i < keys.Length; i++)
                result = result.Replace(keys[i], values[i]);
            return result;
        }

        public byte[] ZeroAllocationReplaceCopyAndEncode(string template, string[] keys, string[] values)
            => Encoding.UTF8.GetBytes(ZeroAllocationReplaceCopy(template, keys, values));

        public void ZeroAllocationReplaceCopyAndWrite(string template, IBufferWriter<byte> writer, string[] keys, string[] values)
        {
            var bytes = ZeroAllocationReplaceCopyAndEncode(template, keys, values);
            var span = writer.GetSpan(bytes.Length);
            bytes.CopyTo(span);
            writer.Advance(bytes.Length);
        }
    }

    private sealed class StubApp : BareMetalWeb.Core.Host.IBareWebHost
    {
        public string[] AppMetaDataKeys { get; } = Array.Empty<string>();
        public string[] AppMetaDataValues { get; set; } = Array.Empty<string>();
        public List<BareMetalWeb.Core.Interfaces.IMenuOption> MenuOptionsList { get; set; } = new();
        public string AppName { get; set; } = "Bench";
        public string CompanyDescription { get; set; } = "";
        public string CopyrightYear { get; set; } = "2026";
        public string PrivacyPolicyUrl { get; set; } = "";
        public static string[] appMetaDataKeys { get; set; } = Array.Empty<string>();
        public Microsoft.AspNetCore.Builder.WebApplication app { get; set; } = null!;
        public BareMetalWeb.Core.Interfaces.IBufferedLogger BufferedLogger => null!;
        public BareMetalWeb.Core.Interfaces.IMetricsTracker Metrics { get; set; } = null!;
        public BareMetalWeb.Core.Interfaces.IClientRequestTracker ClientRequests => null!;
        public BareMetalWeb.Core.Interfaces.IHtmlRenderer HtmlRenderer => null!;
        public Dictionary<string, BareMetalWeb.Host.RouteHandlerData> routes { get; set; } = new();
        public BareMetalWeb.Core.PageInfo NotFoundPageInfo => null!;
        public BareMetalWeb.Core.PageInfo ErrorPageInfo => null!;
        public CancellationTokenSource cts { get; } = new();
        public string[] CorsAllowedOrigins { get; set; } = Array.Empty<string>();
        public string[] CorsAllowedMethods { get; set; } = Array.Empty<string>();
        public string[] CorsAllowedHeaders { get; set; } = Array.Empty<string>();
        public BareMetalWeb.Core.Host.StaticFileConfigOptions StaticFiles { get; set; } = new();
        public BareMetalWeb.Core.HttpsRedirectMode HttpsRedirectMode { get; set; }
        public bool TrustForwardedHeaders { get; set; }
        public bool HttpsEndpointAvailable { get; set; }
        public string? HttpsRedirectHost { get; set; }
        public int? HttpsRedirectPort { get; set; }
        public BareMetalWeb.Core.BmwConfig Configuration { get; set; } = BareMetalWeb.Core.BmwConfig.Load("/tmp");
        public string ContentRootPath { get; set; } = "/tmp";
        public bool ShowHostDiagnostics { get; set; } = false;
        public System.Threading.Tasks.ValueTask BuildAppInfoMenuOptionsAsync(BareMetalWeb.Core.BmwContext? context = null, CancellationToken cancellationToken = default) => ValueTask.CompletedTask;
        public void RegisterRoute(string path, BareMetalWeb.Host.RouteHandlerData routeHandler) { }
        public Task RenderForbidden(BareMetalWeb.Core.BmwContext context) => Task.CompletedTask;
        public Task RequestHandler(BareMetalWeb.Core.BmwContext context) => Task.CompletedTask;
        public Task WireUpRequestHandlingAndLoggerAsyncLifetime() => Task.CompletedTask;
    }
}
