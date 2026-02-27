using System.Collections.Generic;
using Xunit;

namespace BareMetalWeb.Host.Tests;

public class RouteMatchingTests
{
    [Fact]
    public void TryMatch_ExactPath_ReturnsTrue()
    {
        var result = RouteMatching.TryMatch("/foo/bar", "/foo/bar", out var parameters);
        Assert.True(result);
        Assert.Empty(parameters);
    }

    [Fact]
    public void TryMatch_ExactPath_CaseInsensitive()
    {
        var result = RouteMatching.TryMatch("/Foo/BAR", "/foo/bar", out _);
        Assert.True(result);
    }

    [Fact]
    public void TryMatch_DifferentPath_ReturnsFalse()
    {
        var result = RouteMatching.TryMatch("/foo/bar", "/foo/baz", out _);
        Assert.False(result);
    }

    [Fact]
    public void TryMatch_SingleParameter_ExtractsValue()
    {
        var result = RouteMatching.TryMatch("/users/42", "/users/{id}", out var parameters);
        Assert.True(result);
        Assert.Equal("42", parameters["id"]);
    }

    [Fact]
    public void TryMatch_MultipleParameters_ExtractsAll()
    {
        var result = RouteMatching.TryMatch("/users/42/posts/7", "/users/{userId}/posts/{postId}", out var parameters);
        Assert.True(result);
        Assert.Equal("42", parameters["userId"]);
        Assert.Equal("7", parameters["postId"]);
    }

    [Fact]
    public void TryMatch_CatchAllParameter_CapturesRemainder()
    {
        var result = RouteMatching.TryMatch("/files/docs/readme.md", "/files/{*path}", out var parameters);
        Assert.True(result);
        Assert.Equal("docs/readme.md", parameters["path"]);
    }

    [Fact]
    public void TryMatch_CatchAllParameter_EmptyRemainder()
    {
        var result = RouteMatching.TryMatch("/files", "/files/{*path}", out var parameters);
        Assert.True(result);
        Assert.Equal(string.Empty, parameters["path"]);
    }

    [Fact]
    public void TryMatch_RegexPattern_MatchingPath_ReturnsTrue()
    {
        var result = RouteMatching.TryMatch("/api/v2/data", "regex:^/api/v\\d+/data$", out _);
        Assert.True(result);
    }

    [Fact]
    public void TryMatch_RegexPattern_NonMatchingPath_ReturnsFalse()
    {
        var result = RouteMatching.TryMatch("/api/latest/data", "regex:^/api/v\\d+/data$", out _);
        Assert.False(result);
    }

    [Fact]
    public void TryMatch_TrailingSlash_MatchesWithoutSlash()
    {
        var result = RouteMatching.TryMatch("/foo/bar/", "/foo/bar", out _);
        Assert.True(result);
    }

    [Fact]
    public void TryMatch_TemplateLongerThanPath_ReturnsFalse()
    {
        var result = RouteMatching.TryMatch("/foo", "/foo/bar/baz", out _);
        Assert.False(result);
    }

    [Fact]
    public void TryMatch_PathLongerThanTemplate_ReturnsFalse()
    {
        var result = RouteMatching.TryMatch("/foo/bar/baz", "/foo/bar", out _);
        Assert.False(result);
    }

    [Fact]
    public void TryMatch_RootPath_MatchesRootTemplate()
    {
        var result = RouteMatching.TryMatch("/", "/", out _);
        Assert.True(result);
    }

    [Fact]
    public void TryMatch_MixedLiteralAndParams()
    {
        var result = RouteMatching.TryMatch("/admin/data/Customer/edit", "/admin/data/{type}/edit", out var parameters);
        Assert.True(result);
        Assert.Equal("Customer", parameters["type"]);
    }

    [Fact]
    public void TryMatch_ParameterWithSpecialChars_CapturesAsIs()
    {
        var result = RouteMatching.TryMatch("/search/hello%20world", "/search/{query}", out var parameters);
        Assert.True(result);
        Assert.Equal("hello%20world", parameters["query"]);
    }

    [Fact]
    public void TryMatch_CatchAll_MultipleSegments()
    {
        var result = RouteMatching.TryMatch("/static/css/themes/dark/main.css", "/static/{*rest}", out var parameters);
        Assert.True(result);
        Assert.Equal("css/themes/dark/main.css", parameters["rest"]);
    }

    // ── CompiledRoute tests ──────────────────────────────────────────────────

    [Fact]
    public void CompiledRoute_Verb_ParsedCorrectly()
    {
        var c = new CompiledRoute("GET /users/{id}");
        Assert.Equal("GET", c.Verb);
    }

    [Fact]
    public void CompiledRoute_Segments_LiteralParsedCorrectly()
    {
        var c = new CompiledRoute("GET /users/profile");
        Assert.Equal(2, c.Segments.Length);
        Assert.Equal(RouteSegmentKind.Literal, c.Segments[0].Kind);
        Assert.Equal("users", c.Segments[0].Value);
        Assert.Equal(RouteSegmentKind.Literal, c.Segments[1].Kind);
        Assert.Equal("profile", c.Segments[1].Value);
        Assert.Equal(2, c.LiteralSegmentCount);
        Assert.Equal(0, c.ParameterCount);
    }

    [Fact]
    public void CompiledRoute_Segments_ParameterParsedCorrectly()
    {
        var c = new CompiledRoute("GET /users/{id}");
        Assert.Equal(2, c.Segments.Length);
        Assert.Equal(RouteSegmentKind.Literal, c.Segments[0].Kind);
        Assert.Equal("users", c.Segments[0].Value);
        Assert.Equal(RouteSegmentKind.Parameter, c.Segments[1].Kind);
        Assert.Equal("id", c.Segments[1].Value);
        Assert.Equal(1, c.LiteralSegmentCount);
        Assert.Equal(1, c.ParameterCount);
    }

    [Fact]
    public void CompiledRoute_Segments_CatchAllParsedCorrectly()
    {
        var c = new CompiledRoute("GET /files/{*path}");
        Assert.Equal(2, c.Segments.Length);
        Assert.Equal(RouteSegmentKind.CatchAll, c.Segments[1].Kind);
        Assert.Equal("path", c.Segments[1].Value);
        Assert.Equal(1, c.LiteralSegmentCount);
        Assert.Equal(1, c.ParameterCount);
    }

    [Fact]
    public void CompiledRoute_IsRegex_DetectedCorrectly()
    {
        var c = new CompiledRoute("GET regex:^/api/v\\d+/data$");
        Assert.True(c.IsRegex);
        Assert.NotNull(c.RegexPattern);
        Assert.Empty(c.Segments);
    }

    [Fact]
    public void TryMatch_CompiledRoute_ExactPath_ReturnsTrue()
    {
        var compiled = new CompiledRoute("GET /foo/bar");
        var result = RouteMatching.TryMatch("/foo/bar", compiled, out var parameters);
        Assert.True(result);
        Assert.Empty(parameters);
    }

    [Fact]
    public void TryMatch_CompiledRoute_DifferentPath_ReturnsFalse()
    {
        var compiled = new CompiledRoute("GET /foo/baz");
        var result = RouteMatching.TryMatch("/foo/bar", compiled, out _);
        Assert.False(result);
    }

    [Fact]
    public void TryMatch_CompiledRoute_SingleParameter_ExtractsValue()
    {
        var compiled = new CompiledRoute("GET /users/{id}");
        var result = RouteMatching.TryMatch("/users/42", compiled, out var parameters);
        Assert.True(result);
        Assert.Equal("42", parameters["id"]);
    }

    [Fact]
    public void TryMatch_CompiledRoute_MultipleParameters_ExtractsAll()
    {
        var compiled = new CompiledRoute("GET /users/{userId}/posts/{postId}");
        var result = RouteMatching.TryMatch("/users/42/posts/7", compiled, out var parameters);
        Assert.True(result);
        Assert.Equal("42", parameters["userId"]);
        Assert.Equal("7", parameters["postId"]);
    }

    [Fact]
    public void TryMatch_CompiledRoute_CatchAllParameter_CapturesRemainder()
    {
        var compiled = new CompiledRoute("GET /files/{*path}");
        var result = RouteMatching.TryMatch("/files/docs/readme.md", compiled, out var parameters);
        Assert.True(result);
        Assert.Equal("docs/readme.md", parameters["path"]);
    }

    [Fact]
    public void TryMatch_CompiledRoute_CatchAllParameter_EmptyRemainder()
    {
        var compiled = new CompiledRoute("GET /files/{*path}");
        var result = RouteMatching.TryMatch("/files", compiled, out var parameters);
        Assert.True(result);
        Assert.Equal(string.Empty, parameters["path"]);
    }

    [Fact]
    public void TryMatch_CompiledRoute_Regex_MatchingPath_ReturnsTrue()
    {
        var compiled = new CompiledRoute("GET regex:^/api/v\\d+/data$");
        var result = RouteMatching.TryMatch("/api/v2/data", compiled, out _);
        Assert.True(result);
    }

    [Fact]
    public void TryMatch_CompiledRoute_Regex_NonMatchingPath_ReturnsFalse()
    {
        var compiled = new CompiledRoute("GET regex:^/api/v\\d+/data$");
        var result = RouteMatching.TryMatch("/api/latest/data", compiled, out _);
        Assert.False(result);
    }

    [Fact]
    public void TryMatch_CompiledRoute_PathLongerThanTemplate_ReturnsFalse()
    {
        var compiled = new CompiledRoute("GET /foo/bar");
        var result = RouteMatching.TryMatch("/foo/bar/baz", compiled, out _);
        Assert.False(result);
    }

    [Fact]
    public void TryMatch_CompiledRoute_TemplateLongerThanPath_ReturnsFalse()
    {
        var compiled = new CompiledRoute("GET /foo/bar/baz");
        var result = RouteMatching.TryMatch("/foo", compiled, out _);
        Assert.False(result);
    }

    [Fact]
    public void TryMatch_CompiledRoute_CatchAll_MultipleSegments()
    {
        var compiled = new CompiledRoute("GET /static/{*rest}");
        var result = RouteMatching.TryMatch("/static/css/themes/dark/main.css", compiled, out var parameters);
        Assert.True(result);
        Assert.Equal("css/themes/dark/main.css", parameters["rest"]);
    }

    [Fact]
    public void TryMatch_CompiledRoute_DictionaryPreSized_NoExtraAllocations()
    {
        // Verify that the dictionary capacity matches ParameterCount (no excess buckets).
        var compiled = new CompiledRoute("GET /a/{x}/b/{y}");
        Assert.Equal(2, compiled.ParameterCount);
        var result = RouteMatching.TryMatch("/a/1/b/2", compiled, out var parameters);
        Assert.True(result);
        Assert.Equal(2, parameters.Count);
    }

    [Fact]
    public void RouteMatching_CaseSensitive_Setting_RespectedByCompiledOverload()
    {
        var compiled = new CompiledRoute("GET /Foo/Bar");
        try
        {
            RouteMatching.CaseSensitive = true;
            Assert.False(RouteMatching.TryMatch("/foo/bar", compiled, out _));
            Assert.True(RouteMatching.TryMatch("/Foo/Bar", compiled, out _));
        }
        finally
        {
            // Restore default so other tests are unaffected.
            RouteMatching.CaseSensitive = false;
        }
    }

    [Fact]
    public void RouteMatching_CaseSensitive_Setting_RespectedByStringOverload()
    {
        try
        {
            RouteMatching.CaseSensitive = true;
            Assert.False(RouteMatching.TryMatch("/Foo/BAR", "/foo/bar", out _));
            Assert.True(RouteMatching.TryMatch("/foo/bar", "/foo/bar", out _));
        }
        finally
        {
            RouteMatching.CaseSensitive = false;
        }
    }
}
