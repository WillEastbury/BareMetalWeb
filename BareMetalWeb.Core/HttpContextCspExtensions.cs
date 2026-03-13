using System;
using System.Security.Cryptography;
using BareMetalWeb.Core;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Connection-level feature carrying a pre-generated CSP nonce.
/// Set once per connection, read by every request on that connection.
/// </summary>
public interface IConnectionNonceFeature
{
    string Nonce { get; }
}

public static class HttpContextCspExtensions
{
    private const string CspNonceKey = "BareMetalWeb.CspNonce";

    /// <summary>
    /// Generates and stores a CSP nonce for the current request.
    /// </summary>
    public static string GenerateCspNonce(this HttpContext context)
    {
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        context.Items[CspNonceKey] = nonce;
        return nonce;
    }

    /// <summary>
    /// Gets the CSP nonce for the current request, or generates one if it doesn't exist.
    /// </summary>
    public static string GetCspNonce(this HttpContext context)
    {
        if (context.Items.TryGetValue(CspNonceKey, out var value) && value is string nonce)
            return nonce;

        // Try connection-level nonce (one RNG call per connection, not per request)
        var connNonce = context.Features.Get<IConnectionNonceFeature>();
        if (connNonce != null)
        {
            context.Items[CspNonceKey] = connNonce.Nonce;
            return connNonce.Nonce;
        }
        
        return GenerateCspNonce(context);
    }

    // ── BmwContext overloads (use BmwContext.CspNonce directly) ────────

    public static string GenerateCspNonce(this BmwContext context)
    {
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        context.CspNonce = nonce;
        return nonce;
    }

    public static string GetCspNonce(this BmwContext context)
    {
        if (context.CspNonce is string existing)
            return existing;

        // Try connection-level nonce (one RNG call per connection, not per request)
        var connNonce = context.Features?.Get<IConnectionNonceFeature>();
        if (connNonce != null)
        {
            context.CspNonce = connNonce.Nonce;
            return connNonce.Nonce;
        }

        return GenerateCspNonce(context);
    }
}
