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
}
