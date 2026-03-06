using System;
using BareMetalWeb.Core;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace BareMetalWeb.Host.Tests;

public class CsrfProtectionTests
{
    [Fact]
    public void EnsureToken_CreatesTokenAndSetsCookie()
    {
        var context = new DefaultHttpContext();
        var token = CsrfProtection.EnsureToken(context.ToBmw());

        Assert.False(string.IsNullOrWhiteSpace(token));
    }

    [Fact]
    public void EnsureToken_ReturnsSameTokenOnSecondCall()
    {
        var context = new DefaultHttpContext();
        // Simulate a cookie already present
        context.Request.Headers["Cookie"] = "csrf_token=existing-token-value";

        var token = CsrfProtection.EnsureToken(context.ToBmw());
        Assert.Equal("existing-token-value", token);
    }

    [Fact]
    public void ValidateApiToken_ReturnsTrue_WhenHeaderMatchesCookie()
    {
        var context = new DefaultHttpContext();
        var tokenValue = "test-csrf-token-abc123";
        context.Request.Headers["Cookie"] = $"csrf_token={tokenValue}";
        context.Request.Headers[CsrfProtection.ApiTokenHeaderName] = tokenValue;

        Assert.True(CsrfProtection.ValidateApiToken(context.ToBmw()));
    }

    [Fact]
    public void ValidateApiToken_ReturnsFalse_WhenHeaderMissing()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["Cookie"] = "csrf_token=test-token";

        Assert.False(CsrfProtection.ValidateApiToken(context.ToBmw()));
    }

    [Fact]
    public void ValidateApiToken_ReturnsFalse_WhenCookieMissing()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers[CsrfProtection.ApiTokenHeaderName] = "test-token";

        Assert.False(CsrfProtection.ValidateApiToken(context.ToBmw()));
    }

    [Fact]
    public void ValidateApiToken_ReturnsFalse_WhenTokensMismatch()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["Cookie"] = "csrf_token=token-one";
        context.Request.Headers[CsrfProtection.ApiTokenHeaderName] = "token-two";

        Assert.False(CsrfProtection.ValidateApiToken(context.ToBmw()));
    }

    [Fact]
    public void ValidateApiToken_ReturnsFalse_WhenBothEmpty()
    {
        var context = new DefaultHttpContext();
        Assert.False(CsrfProtection.ValidateApiToken(context.ToBmw()));
    }

    [Fact]
    public void ValidateApiToken_ThrowsOnNullContext()
    {
        Assert.Throws<ArgumentNullException>(() => CsrfProtection.ValidateApiToken(null!));
    }

    [Fact]
    public void ValidateApiToken_ReturnsTrue_WhenApiKeyHeaderPresent()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["ApiKey"] = "some-raw-api-key";

        // No CSRF cookie or token set — should still pass because API key bypasses CSRF
        Assert.True(CsrfProtection.ValidateApiToken(context.ToBmw()));
    }

    [Fact]
    public void ValidateApiToken_ReturnsTrue_WhenAuthorizationApiKeyHeaderPresent()
    {
        var context = new DefaultHttpContext();
        context.Request.Headers["Authorization"] = "ApiKey some-raw-api-key";

        // No CSRF cookie or token set — should still pass because API key bypasses CSRF
        Assert.True(CsrfProtection.ValidateApiToken(context.ToBmw()));
    }
}
