using System;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Tests for ReadQueryParam (allocation-free query string parsing)
/// used by HydrateRouteParamsFromQuery during numeric route dispatch.
/// </summary>
public class NumericDispatchTests
{
    [Fact]
    public void ReadQueryParam_ReturnsValue_WhenKeyExists()
    {
        var result = BareMetalWebServer.ReadQueryParam("?type=users&id=42".AsSpan(), "type".AsSpan());
        Assert.Equal("users", result.ToString());
    }

    [Fact]
    public void ReadQueryParam_ReturnsValue_ForSecondParam()
    {
        var result = BareMetalWebServer.ReadQueryParam("?type=users&id=42".AsSpan(), "id".AsSpan());
        Assert.Equal("42", result.ToString());
    }

    [Fact]
    public void ReadQueryParam_ReturnsEmpty_WhenKeyMissing()
    {
        var result = BareMetalWebServer.ReadQueryParam("?type=users&id=42".AsSpan(), "name".AsSpan());
        Assert.True(result.IsEmpty);
    }

    [Fact]
    public void ReadQueryParam_ReturnsEmpty_WhenQueryEmpty()
    {
        var result = BareMetalWebServer.ReadQueryParam(ReadOnlySpan<char>.Empty, "type".AsSpan());
        Assert.True(result.IsEmpty);
    }

    [Fact]
    public void ReadQueryParam_HandlesNoLeadingQuestionMark()
    {
        var result = BareMetalWebServer.ReadQueryParam("type=orders&id=7".AsSpan(), "type".AsSpan());
        Assert.Equal("orders", result.ToString());
    }

    [Fact]
    public void ReadQueryParam_ReturnsFirstMatch_WhenDuplicateKeys()
    {
        var result = BareMetalWebServer.ReadQueryParam("?x=1&x=2".AsSpan(), "x".AsSpan());
        Assert.Equal("1", result.ToString());
    }

    [Fact]
    public void ReadQueryParam_HandlesEmptyValue()
    {
        var result = BareMetalWebServer.ReadQueryParam("?key=".AsSpan(), "key".AsSpan());
        Assert.Equal("", result.ToString());
    }

    [Fact]
    public void ReadQueryParam_DoesNotPartialMatchKeys()
    {
        // "type" should not match "typeId"
        var result = BareMetalWebServer.ReadQueryParam("?typeId=foo".AsSpan(), "type".AsSpan());
        Assert.True(result.IsEmpty);
    }

    [Fact]
    public void ReadQueryParam_HandlesTrailingAmpersand()
    {
        var result = BareMetalWebServer.ReadQueryParam("?id=99&".AsSpan(), "id".AsSpan());
        Assert.Equal("99", result.ToString());
    }

    [Fact]
    public void ReadQueryParam_SingleParam()
    {
        var result = BareMetalWebServer.ReadQueryParam("?field=Name".AsSpan(), "field".AsSpan());
        Assert.Equal("Name", result.ToString());
    }

    [Fact]
    public void ReadQueryParam_MultipleParams_Command()
    {
        var result = BareMetalWebServer.ReadQueryParam(
            "?type=users&id=5&command=SendEmail".AsSpan(), "command".AsSpan());
        Assert.Equal("SendEmail", result.ToString());
    }
}
