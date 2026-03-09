using System.IO;
using System.IO.Pipelines;
using System.Text;
using BareMetalWeb.Rendering;
using Xunit;

namespace BareMetalWeb.Rendering.Tests;

public class SingleSpanRendererTests
{
    private static string Render(string template, string[] pageKeys, string[] pageValues,
        string[]? appKeys = null, string[]? appValues = null)
    {
        var plan = TemplatePlanCompiler.Compile(template);
        var ms = new MemoryStream();
        var writer = PipeWriter.Create(ms);

        SingleSpanRenderer.RenderAsync(writer, plan, pageKeys, pageValues,
            appKeys ?? Array.Empty<string>(), appValues ?? Array.Empty<string>())
            .AsTask().GetAwaiter().GetResult();
        writer.Complete();

        return Encoding.UTF8.GetString(ms.ToArray());
    }

    [Fact]
    public void Render_SimpleSubstitution_MatchesExpected()
    {
        var result = Render("Hello {{name}}!",
            new[] { "name" }, new[] { "World" });
        Assert.Equal("Hello World!", result);
    }

    [Fact]
    public void Render_MultipleTokens_AllReplaced()
    {
        var result = Render("{{a}} {{b}} {{c}}",
            new[] { "a", "b", "c" },
            new[] { "X", "Y", "Z" });
        Assert.Equal("X Y Z", result);
    }

    [Fact]
    public void Render_PageKeysPrecedeAppKeys()
    {
        var result = Render("{{k}}",
            new[] { "k" }, new[] { "page" },
            new[] { "k" }, new[] { "app" });
        Assert.Equal("page", result);
    }

    [Fact]
    public void Render_HtmlEncoding_SpecialChars()
    {
        var result = Render("{{v}}",
            new[] { "v" }, new[] { "<b>A & B</b>" });
        Assert.DoesNotContain("<b>", result);
        Assert.Contains("&lt;b&gt;", result);
        Assert.Contains("&amp;", result);
    }

    [Fact]
    public void Render_RawHtml_NotEncoded()
    {
        var result = Render("{{html_x}}",
            new[] { "html_x" }, new[] { "<p>raw</p>" });
        Assert.Contains("<p>raw</p>", result);
    }

    [Fact]
    public void Render_UnknownToken_ProducesEmpty()
    {
        var result = Render("A{{missing}}B",
            Array.Empty<string>(), Array.Empty<string>());
        Assert.Equal("AB", result);
    }

    [Fact]
    public void Render_PureStatic_ExactOutput()
    {
        var result = Render("<div>Static</div>",
            Array.Empty<string>(), Array.Empty<string>());
        Assert.Equal("<div>Static</div>", result);
    }

    [Fact]
    public void Render_Utf8Values_Preserved()
    {
        var result = Render("{{v}}",
            new[] { "v" }, new[] { "Héllo — ñ" });
        Assert.Contains("Héllo — ñ", result);
    }

    [Fact]
    public void Render_RepeatedKey_BothResolved()
    {
        var result = Render("{{x}} and {{x}}",
            new[] { "x" }, new[] { "val" });
        Assert.Equal("val and val", result);
    }

    [Fact]
    public void Render_QuotesAndApostrophes_Encoded()
    {
        var result = Render("{{v}}",
            new[] { "v" }, new[] { "He said \"hi\" it's ok" });
        Assert.Contains("&quot;hi&quot;", result);
        Assert.Contains("&#39;", result);
    }

    [Fact]
    public void Render_LargeTemplate_AllTokensResolved()
    {
        var sb = new StringBuilder();
        var keys = new string[50];
        var values = new string[50];
        for (int i = 0; i < 50; i++)
        {
            sb.Append($"[{{{{k{i}}}}}]");
            keys[i] = $"k{i}";
            values[i] = $"v{i}";
        }

        var result = Render(sb.ToString(), keys, values);
        for (int i = 0; i < 50; i++)
            Assert.Contains($"[v{i}]", result);
    }

    [Fact]
    public void EstimateTotalSize_IncludesStaticAndDynamicBytes()
    {
        var plan = TemplatePlanCompiler.Compile("AB{{x}}CD");
        var resolved = new string?[] { "Hello" };
        int estimate = SingleSpanRenderer.EstimateTotalSize(plan, resolved);
        // Static: 4 bytes, Dynamic: "Hello" → 5 chars max * some factor
        Assert.True(estimate >= 9); // at minimum 4 + 5
    }

    [Fact]
    public void RenderToSpan_ProducesCorrectBytes()
    {
        var plan = TemplatePlanCompiler.Compile("Hi {{name}}!");
        var resolved = new string?[] { "BMW" };
        var buffer = new byte[256];
        int written = SingleSpanRenderer.RenderToSpan(plan, resolved, buffer);
        Assert.Equal("Hi BMW!", Encoding.UTF8.GetString(buffer, 0, written));
    }

    [Fact]
    public async Task RenderAsync_WithResolvedValues_SingleFlush()
    {
        var plan = TemplatePlanCompiler.Compile("A {{x}} B");
        var resolved = new string?[] { "val" };

        var ms = new MemoryStream();
        var instrumented = new InstrumentedPipeWriter(PipeWriter.Create(ms));

        await SingleSpanRenderer.RenderAsync(instrumented, plan, resolved);
        instrumented.Complete();

        // Single-span: exactly 1 GetSpan, 1 Advance, 1 Flush
        Assert.Equal(1, instrumented.GetSpanCount);
        Assert.Equal(1, instrumented.AdvanceCount);
        Assert.Equal(1, instrumented.FlushCount);
        Assert.Equal("A val B", Encoding.UTF8.GetString(ms.ToArray()));
    }

    [Fact]
    public async Task RenderAsync_VsMultiWrite_FewerPipeWriterCalls()
    {
        var template = "<div>{{a}}</div><span>{{b}}</span><p>{{c}}</p>";
        var plan = TemplatePlanCompiler.Compile(template);
        var pageKeys = new[] { "a", "b", "c" };
        var pageValues = new[] { "X", "Y", "Z" };

        // Multi-write approach
        var ms1 = new MemoryStream();
        var iw1 = new InstrumentedPipeWriter(PipeWriter.Create(ms1));
        TemplatePlanExecutor.Execute(iw1, plan, pageKeys, pageValues,
            Array.Empty<string>(), Array.Empty<string>());
        await iw1.FlushAsync();
        iw1.Complete();

        // Single-span approach
        var ms2 = new MemoryStream();
        var iw2 = new InstrumentedPipeWriter(PipeWriter.Create(ms2));
        await SingleSpanRenderer.RenderAsync(iw2, plan, pageKeys, pageValues,
            Array.Empty<string>(), Array.Empty<string>());
        iw2.Complete();

        // Both produce same output
        Assert.Equal(
            Encoding.UTF8.GetString(ms1.ToArray()),
            Encoding.UTF8.GetString(ms2.ToArray()));

        // Single-span uses fewer PipeWriter calls
        Assert.True(iw2.GetSpanCount < iw1.GetSpanCount,
            $"SingleSpan GetSpan ({iw2.GetSpanCount}) should be less than multi-write ({iw1.GetSpanCount})");
    }
}
