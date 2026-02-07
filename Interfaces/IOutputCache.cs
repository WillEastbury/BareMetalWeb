using System;

namespace BareMetalWeb.Interfaces;

public interface IOutputCache
{
    bool TryGet(string path, out CachedResponse response);
    void Store(string path, byte[] body, string contentType, int statusCode, int expiry = 30);

    public record CachedResponse(byte[] Body, string ContentType, int StatusCode, DateTime Expires);
}
