using System;
using System.IO;
using System.IO.Compression;
using System.Globalization;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Shared helpers for selecting and applying response compression (Brotli / Gzip).
/// Accessible from both BareMetalWeb.Host and BareMetalWeb.Rendering.
/// </summary>
public static class CompressionHelper
{
    /// <summary>
    /// Selects the preferred response encoding from the <c>Accept-Encoding</c> header,
    /// preferring Brotli over Gzip.
    /// Returns <c>"br"</c>, <c>"gzip"</c>, or <c>null</c> if no compression is
    /// accepted or the header is absent.
    /// </summary>
    public static string? SelectEncoding(string? acceptEncodingHeader)
    {
        if (string.IsNullOrWhiteSpace(acceptEncodingHeader))
            return null;

        double brQ = 0, gzQ = 0, starQ = 0;

        foreach (var token in acceptEncodingHeader.Split(','))
        {
            var p = token.Trim().AsSpan();
            var semiIdx = p.IndexOf(';');
            var enc = (semiIdx < 0 ? p : p[..semiIdx]).Trim();
            double q = 1.0;

            if (semiIdx >= 0)
            {
                var param = p[(semiIdx + 1)..].Trim();
                if (param.StartsWith("q=".AsSpan(), StringComparison.OrdinalIgnoreCase))
                {
                    if (double.TryParse(param[2..], NumberStyles.AllowDecimalPoint,
                            CultureInfo.InvariantCulture, out var qv))
                        q = Math.Clamp(qv, 0.0, 1.0);
                }
            }

            if (enc.Equals("br".AsSpan(), StringComparison.OrdinalIgnoreCase))
                brQ = Math.Max(brQ, q);
            else if (enc.Equals("gzip".AsSpan(), StringComparison.OrdinalIgnoreCase))
                gzQ = Math.Max(gzQ, q);
            else if (enc.Length == 1 && enc[0] == '*')
                starQ = Math.Max(starQ, q);
        }

        var effectiveBr = brQ > 0 ? brQ : starQ;
        var effectiveGz = gzQ > 0 ? gzQ : starQ;

        if (effectiveBr >= effectiveGz && effectiveBr > 0)
            return "br";
        if (effectiveGz > 0)
            return "gzip";
        return null;
    }

    /// <summary>
    /// Selects the preferred response encoding from the request's <c>Accept-Encoding</c>
    /// header. Returns <c>"br"</c>, <c>"gzip"</c>, or <c>null</c>.
    /// </summary>
    public static string? SelectEncoding(HttpContext context)
        => SelectEncoding(context.Request.Headers.AcceptEncoding.ToString());

    /// <summary>Compresses <paramref name="data"/> using Brotli at Optimal level.</summary>
    public static byte[] CompressBrotli(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var bs = new BrotliStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            bs.Write(data, 0, data.Length);
        return ms.ToArray();
    }

    /// <summary>Compresses <paramref name="data"/> using GZip at Optimal level.</summary>
    public static byte[] CompressGzip(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
            gz.Write(data, 0, data.Length);
        return ms.ToArray();
    }

    /// <summary>
    /// Applies the <paramref name="encoding"/> to <paramref name="data"/>.
    /// Returns the original <paramref name="data"/> unchanged when
    /// <paramref name="encoding"/> is <c>null</c>.
    /// </summary>
    public static byte[] Compress(byte[] data, string? encoding)
        => encoding switch
        {
            "br"   => CompressBrotli(data),
            "gzip" => CompressGzip(data),
            _      => data
        };

    /// <summary>
    /// Applies compression headers (<c>Content-Encoding</c> and <c>Vary</c>) to
    /// the response when <paramref name="encoding"/> is non-null.
    /// </summary>
    public static void ApplyHeaders(HttpResponse response, string? encoding)
    {
        if (string.IsNullOrEmpty(encoding))
            return;

        response.Headers.ContentEncoding = encoding;
        response.Headers.Append("Vary", "Accept-Encoding");
    }
}
