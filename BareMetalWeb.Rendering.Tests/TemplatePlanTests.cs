using System.IO;
using System.IO.Pipelines;
using System.Text;
using BareMetalWeb.Rendering;
using Xunit;

namespace BareMetalWeb.Rendering.Tests;

public class TemplatePlanCompilerTests
{
    [Fact]
    public void Compile_EmptyTemplate_ReturnsEmptyPlan()
    {
        var plan = TemplatePlanCompiler.Compile("");
        Assert.Empty(plan.Segments);
        Assert.Empty(plan.FieldKeys);
        Assert.Equal(0, plan.StaticByteCount);
    }

    [Fact]
    public void Compile_NullTemplate_ReturnsEmptyPlan()
    {
        var plan = TemplatePlanCompiler.Compile(null!);
        Assert.Empty(plan.Segments);
    }

    [Fact]
    public void Compile_PureStaticTemplate_SingleSegment()
    {
        var plan = TemplatePlanCompiler.Compile("<div>Hello World</div>");
        Assert.Single(plan.Segments);
        Assert.True(plan.Segments[0].IsStatic);
        Assert.Equal("<div>Hello World</div>", Encoding.UTF8.GetString(plan.Segments[0].Fragment.Span));
        Assert.Empty(plan.FieldKeys);
    }

    [Fact]
    public void Compile_SingleToken_ThreeSegments()
    {
        var plan = TemplatePlanCompiler.Compile("Hello {{name}}!");
        Assert.Equal(3, plan.Segments.Length);

        // Static "Hello "
        Assert.True(plan.Segments[0].IsStatic);
        Assert.Equal("Hello ", Encoding.UTF8.GetString(plan.Segments[0].Fragment.Span));

        // Dynamic {{name}}
        Assert.False(plan.Segments[1].IsStatic);
        Assert.Equal(0, plan.Segments[1].FieldIndex);
        Assert.False(plan.Segments[1].IsRawHtml);

        // Static "!"
        Assert.True(plan.Segments[2].IsStatic);
        Assert.Equal("!", Encoding.UTF8.GetString(plan.Segments[2].Fragment.Span));

        Assert.Single(plan.FieldKeys);
        Assert.Equal("name", plan.FieldKeys[0]);
    }

    [Fact]
    public void Compile_MultipleTokens_CorrectFieldIndices()
    {
        var plan = TemplatePlanCompiler.Compile("{{a}} and {{b}} and {{a}}");

        // Fields: a(0), b(1) — "a" reused with same index
        Assert.Equal(2, plan.FieldKeys.Length);
        Assert.Equal("a", plan.FieldKeys[0]);
        Assert.Equal("b", plan.FieldKeys[1]);

        // Segments: static(" and "), dynamic(a), static(" and "), dynamic(b), static(" and "), dynamic(a)
        // Actually: dynamic(a), static(" and "), dynamic(b), static(" and "), dynamic(a)
        Assert.Equal(5, plan.Segments.Length);
        Assert.Equal(0, plan.Segments[0].FieldIndex); // a
        Assert.True(plan.Segments[1].IsStatic);        // " and "
        Assert.Equal(1, plan.Segments[2].FieldIndex); // b
        Assert.True(plan.Segments[3].IsStatic);        // " and "
        Assert.Equal(0, plan.Segments[4].FieldIndex); // a again
    }

    [Fact]
    public void Compile_HtmlPrefixKey_MarkedAsRawHtml()
    {
        var plan = TemplatePlanCompiler.Compile("{{html_content}}");
        Assert.Single(plan.Segments);
        Assert.True(plan.Segments[0].IsRawHtml);
        Assert.Equal("html_content", plan.FieldKeys[0]);
    }

    [Fact]
    public void Compile_NonHtmlPrefixKey_NotMarkedAsRawHtml()
    {
        var plan = TemplatePlanCompiler.Compile("{{title}}");
        Assert.False(plan.Segments[0].IsRawHtml);
    }

    [Fact]
    public void Compile_MalformedToken_NoClosingBraces_EmitsLiteral()
    {
        var plan = TemplatePlanCompiler.Compile("Hello {{broken");
        // Should produce: static("Hello "), static("{{broken")
        Assert.Equal(2, plan.Segments.Length);
        Assert.True(plan.Segments[0].IsStatic);
        Assert.True(plan.Segments[1].IsStatic);
        Assert.Contains("{{broken", Encoding.UTF8.GetString(plan.Segments[1].Fragment.Span));
    }

    [Fact]
    public void Compile_StaticByteCount_SumsFragmentLengths()
    {
        var plan = TemplatePlanCompiler.Compile("AB{{x}}CD");
        // "AB" (2 bytes) + "CD" (2 bytes) = 4
        Assert.Equal(4, plan.StaticByteCount);
    }

    [Fact]
    public void Compile_AdjacentTokens_NoDuplicateStatic()
    {
        var plan = TemplatePlanCompiler.Compile("{{a}}{{b}}");
        Assert.Equal(2, plan.Segments.Length);
        Assert.False(plan.Segments[0].IsStatic);
        Assert.False(plan.Segments[1].IsStatic);
    }

    [Fact]
    public void Compile_Utf8StaticContent_PreEncoded()
    {
        var plan = TemplatePlanCompiler.Compile("Héllo Wörld");
        Assert.Single(plan.Segments);
        Assert.True(plan.Segments[0].IsStatic);
        Assert.Equal("Héllo Wörld", Encoding.UTF8.GetString(plan.Segments[0].Fragment.Span));
    }
}

public class TemplatePlanExecutorTests
{
    private static string Execute(string template, string[] pageKeys, string[] pageValues,
        string[]? appKeys = null, string[]? appValues = null)
    {
        var plan = TemplatePlanCompiler.Compile(template);
        var ms = new MemoryStream();
        var writer = PipeWriter.Create(ms);

        TemplatePlanExecutor.Execute(writer, plan, pageKeys, pageValues,
            appKeys ?? Array.Empty<string>(), appValues ?? Array.Empty<string>());
        writer.Complete();

        return Encoding.UTF8.GetString(ms.ToArray());
    }

    [Fact]
    public void Execute_TokenSubstitution_ReplacesPageKeys()
    {
        var result = Execute("Hello {{name}}!",
            new[] { "name" }, new[] { "World" });
        Assert.Equal("Hello World!", result);
    }

    [Fact]
    public void Execute_MultipleTokens_AllReplaced()
    {
        var result = Execute("{{greeting}} {{name}}, welcome to {{place}}!",
            new[] { "greeting", "name", "place" },
            new[] { "Hello", "User", "Earth" });
        Assert.Equal("Hello User, welcome to Earth!", result);
    }

    [Fact]
    public void Execute_AppKeys_UsedWhenPageKeyMissing()
    {
        var result = Execute("{{title}}",
            Array.Empty<string>(), Array.Empty<string>(),
            new[] { "title" }, new[] { "AppTitle" });
        Assert.Equal("AppTitle", result);
    }

    [Fact]
    public void Execute_PageKeysPrecedeAppKeys()
    {
        var result = Execute("{{title}}",
            new[] { "title" }, new[] { "PageTitle" },
            new[] { "title" }, new[] { "AppTitle" });
        Assert.Equal("PageTitle", result);
    }

    [Fact]
    public void Execute_UnknownToken_ProducesEmptyOutput()
    {
        var result = Execute("Before{{unknown}}After",
            Array.Empty<string>(), Array.Empty<string>());
        Assert.Equal("BeforeAfter", result);
    }

    [Fact]
    public void Execute_HtmlSpecialChars_AreEncoded()
    {
        var result = Execute("{{title}}",
            new[] { "title" }, new[] { "<script>alert('xss')</script>" });
        Assert.DoesNotContain("<script>", result);
        Assert.Contains("&lt;script&gt;", result);
    }

    [Fact]
    public void Execute_HtmlPrefixKey_WritesRawHtml()
    {
        var result = Execute("{{html_content}}",
            new[] { "html_content" }, new[] { "<p>Hello <strong>World</strong></p>" });
        Assert.Contains("<p>Hello <strong>World</strong></p>", result);
    }

    [Fact]
    public void Execute_PureStaticTemplate_ProducesExactOutput()
    {
        var result = Execute("<div>Hello</div>",
            Array.Empty<string>(), Array.Empty<string>());
        Assert.Equal("<div>Hello</div>", result);
    }

    [Fact]
    public void Execute_RepeatedKey_BothInstancesResolved()
    {
        var result = Execute("{{x}} and {{x}}",
            new[] { "x" }, new[] { "val" });
        Assert.Equal("val and val", result);
    }

    [Fact]
    public void Execute_Ampersand_EncodedCorrectly()
    {
        var result = Execute("{{v}}",
            new[] { "v" }, new[] { "A & B" });
        Assert.Equal("A &amp; B", result);
    }

    [Fact]
    public void Execute_QuotesAndApostrophes_EncodedCorrectly()
    {
        var result = Execute("{{v}}",
            new[] { "v" }, new[] { "He said \"hello\" and it's fine" });
        Assert.Contains("&quot;hello&quot;", result);
        Assert.Contains("&#39;", result);
    }

    [Fact]
    public void Execute_Utf8Values_PreservedCorrectly()
    {
        var result = Execute("{{name}}",
            new[] { "name" }, new[] { "Héllo Wörld — ñ" });
        Assert.Contains("Héllo Wörld — ñ", result);
    }

    [Fact]
    public void ExecuteWithResolvedValues_DirectExecution()
    {
        var plan = TemplatePlanCompiler.Compile("{{a}}-{{b}}");
        var ms = new MemoryStream();
        var writer = PipeWriter.Create(ms);

        TemplatePlanExecutor.ExecuteWithResolvedValues(writer, plan, new[] { "X", "Y" });
        writer.Complete();

        Assert.Equal("X-Y", Encoding.UTF8.GetString(ms.ToArray()));
    }

    [Fact]
    public void Execute_EmptyStringValue_ProducesNoOutput()
    {
        var result = Execute("A{{v}}B",
            new[] { "v" }, new[] { "" });
        // Empty string for HTML-encoded still produces nothing
        Assert.Equal("AB", result);
    }

    [Fact]
    public void Execute_LargeTemplate_AllSegmentsProcessed()
    {
        // Build a template with 50 tokens
        var sb = new System.Text.StringBuilder();
        var keys = new string[50];
        var values = new string[50];
        for (int i = 0; i < 50; i++)
        {
            sb.Append($"[{{{{k{i}}}}}]");
            keys[i] = $"k{i}";
            values[i] = $"v{i}";
        }

        var result = Execute(sb.ToString(), keys, values);
        for (int i = 0; i < 50; i++)
        {
            Assert.Contains($"[v{i}]", result);
        }
    }
}
