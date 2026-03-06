namespace BareMetalWeb.Core;

/// <summary>
/// Parsed request data extracted once from the Kestrel request feature.
/// Stored as strings (not spans) so the struct can live on the heap inside
/// <see cref="BmwContext"/>. The values reference the same interned/pooled
/// strings that Kestrel already provides — no extra allocations.
/// </summary>
public readonly struct BmwRequest
{
    /// <summary>HTTP method in uppercase (GET, POST, PUT, DELETE, etc.).</summary>
    public readonly string Method;

    /// <summary>Request path (e.g. "/api/users/42"). Normalised by Kestrel.</summary>
    public readonly string Path;

    /// <summary>Raw query string including the leading '?' (e.g. "?page=1&amp;size=10"), or empty.</summary>
    public readonly string QueryString;

    /// <summary>
    /// Pre-computed route key in the form "METHOD /path" used for jump-table lookup.
    /// Computed once at context creation time.
    /// </summary>
    public readonly string RouteKey;

    public BmwRequest(string method, string path, string queryString)
    {
        Method = method;
        Path = path;
        QueryString = queryString;
        RouteKey = string.Concat(method, " ", path);
    }
}
