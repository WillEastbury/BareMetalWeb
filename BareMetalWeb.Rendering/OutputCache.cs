using System.Collections.Concurrent;
using BareMetalWeb.Core.Interfaces;

namespace BareMetalWeb.Rendering;

public class OutputCache : IOutputCache
{
    private readonly ConcurrentDictionary<string, IOutputCache.CachedResponse> _cache = new();
    private readonly TimeSpan _defaultExpiry = TimeSpan.FromSeconds(30);

    public bool TryGet(string path, out IOutputCache.CachedResponse response) => _cache.TryGetValue(path, out response!) && response.Expires > DateTime.UtcNow;

    public void Store(string path, byte[] body, string contentType, int statusCode, int expiry = 30)
    {
        _cache[path] = new IOutputCache.CachedResponse
        (
            body,
            contentType,
            statusCode,
            DateTime.UtcNow.Add(TimeSpan.FromSeconds(expiry))
        );
        PruneExpired();
    }

    private void PruneExpired()
    {
        var now = DateTime.UtcNow;
        // ConcurrentDictionary enumeration is safe under concurrent modification (no exceptions,
        // no corruption). Missed or extra entries are acceptable for best-effort pruning.
        foreach (var kv in _cache)
        {
            if (kv.Value.Expires <= now)
                _cache.TryRemove(kv.Key, out _);
        }
    }
}
