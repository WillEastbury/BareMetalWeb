using System.Runtime.CompilerServices;

namespace BareMetalWeb.Host;

/// <summary>
/// O(1) dispatch table indexed by numeric route ID. Clients request <c>/&lt;routeId&gt;</c>
/// and the server resolves the handler via a single array lookup — no string comparison,
/// no hash table, no dictionary. AOT-safe, zero-allocation on the hot path.
/// </summary>
public sealed class NumericRouteTable
{
    private RouteEntry[] _entries = Array.Empty<RouteEntry>();
    private int _count;

    /// <summary>Number of registered routes.</summary>
    public int Count => _count;

    /// <summary>
    /// Assigns a numeric route ID to each route in <paramref name="routes"/>.
    /// IDs are sequential starting from 0. The order is deterministic (sorted by key).
    /// </summary>
    public void Build(Dictionary<string, RouteHandlerData> routes)
    {
        // Sort keys for deterministic ID assignment across restarts
        var keys = new List<string>(routes.Keys);
        keys.Sort(StringComparer.Ordinal);

        _entries = new RouteEntry[keys.Count];
        _count = keys.Count;

        for (int i = 0; i < keys.Count; i++)
        {
            var key = keys[i];
            var data = routes[key];
            _entries[i] = new RouteEntry
            {
                RouteKey = key,
                Handler = data
            };
        }
    }

    /// <summary>
    /// O(1) lookup by numeric route ID. Returns false if out of range.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryLookup(int routeId, out RouteHandlerData data)
    {
        if ((uint)routeId < (uint)_count)
        {
            data = _entries[routeId].Handler;
            return true;
        }
        data = default;
        return false;
    }

    /// <summary>
    /// Returns the route key (e.g. "GET /login") for a given numeric route ID.
    /// </summary>
    public string? GetRouteKey(int routeId)
    {
        if ((uint)routeId < (uint)_count)
            return _entries[routeId].RouteKey;
        return null;
    }

    /// <summary>
    /// Returns all route entries for metadata export.
    /// </summary>
    public ReadOnlySpan<RouteEntry> GetAllEntries() => _entries.AsSpan(0, _count);

    /// <summary>
    /// Parses a numeric route ID from the path span. The path must start with a digit
    /// character. Parsing stops at the first non-digit ('/', '?', ' ', or end of span).
    /// Returns -1 if the path does not start with a digit.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int ParseRouteId(ReadOnlySpan<char> pathAfterSlash)
    {
        if (pathAfterSlash.IsEmpty)
            return -1;

        char first = pathAfterSlash[0];
        if ((uint)(first - '0') > 9)
            return -1;

        // Branchless ASCII digit loop
        int value = first - '0';
        int i = 1;
        while (i < pathAfterSlash.Length)
        {
            uint d = (uint)(pathAfterSlash[i] - '0');
            if (d > 9) break;
            value = value * 10 + (int)d;
            i++;
        }

        return value;
    }

    public struct RouteEntry
    {
        public string RouteKey;
        public RouteHandlerData Handler;
    }
}
