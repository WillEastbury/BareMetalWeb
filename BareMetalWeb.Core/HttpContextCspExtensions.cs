using Microsoft.AspNetCore.Http;
using System;
using System.Security.Cryptography;

namespace BareMetalWeb.Host;

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
        
        return GenerateCspNonce(context);
    }
}
