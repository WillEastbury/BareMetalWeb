using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Host;

/// <summary>
/// A hash-indexed dispatch table for exact-match route lookup in O(1).
/// Routes with parameters (e.g. <c>/api/{type}/{id}</c>) are not eligible
/// and fall through to the pattern-matching path.
/// </summary>
/// <remarks>
/// <para>
/// The table uses open addressing with linear probing. Slot count is the
/// next power-of-two ≥ 2× the route count, giving a load factor ≤ 0.5
/// for fast probing. Collisions are resolved at startup; at runtime a
/// single hash + mask + equality check is the fast path.
/// </para>
/// <para>
/// Rebuilt whenever routes change (tracked via a version counter).
/// The rebuild is cheap — typically &lt;150 routes.
/// </para>
/// </remarks>
public sealed class RouteJumpTable
{
    private struct Slot
    {
        public uint Hash;
        public string Key;          // "GET /login" — the exact route key
        public RouteHandlerData Data;
        public bool Occupied;
    }

    private Slot[] _slots = Array.Empty<Slot>();
    private uint _mask;
    private int _count;
    private int _version;

    /// <summary>Number of exact-match routes in the jump table.</summary>
    public int Count => _count;

    /// <summary>
    /// Rebuild the jump table from the current route dictionary.
    /// Only includes routes that have no parameter segments (exact-match only).
    /// </summary>
    public void Build(Dictionary<string, RouteHandlerData> routes, Dictionary<string, CompiledRoute> compiledRoutes, IBufferedLogger logger)
    {
        // Collect exact-match routes (no parameters, no regex, no catch-all)
        var exactRoutes = new List<(string Key, RouteHandlerData Data, uint Hash)>();
        foreach (var kvp in routes)
        {
            if (compiledRoutes.TryGetValue(kvp.Key, out var compiled))
            {
                if (compiled.IsRegex || compiled.ParameterCount > 0)
                    continue; // Skip parameterised/regex routes
            }

            uint hash = RouteHash.Hash(kvp.Key);
            exactRoutes.Add((kvp.Key, kvp.Value, hash));
        }

        if (exactRoutes.Count == 0)
        {
            _slots = Array.Empty<Slot>();
            _mask = 0;
            _count = 0;
            _version++;
            return;
        }

        // Table size = next power-of-two ≥ 2× route count (load factor ≤ 0.5)
        int tableSize = NextPowerOfTwo(exactRoutes.Count * 2);
        uint mask = (uint)(tableSize - 1);
        var slots = new Slot[tableSize];

        // Insert with linear probing; detect collisions at build time
        for (int i = 0; i < exactRoutes.Count; i++)
        {
            var (key, data, hash) = exactRoutes[i];
            uint idx = hash & mask;

            int probes = 0;
            while (slots[idx].Occupied)
            {
                if (slots[idx].Hash == hash && string.Equals(slots[idx].Key, key, StringComparison.Ordinal))
                {
                    // Duplicate route key — overwrite (same as dictionary behaviour)
                    break;
                }
                idx = (idx + 1) & mask;
                probes++;
                if (probes >= tableSize)
                    throw new InvalidOperationException($"Route jump table full — this should never happen (table size {tableSize}, routes {exactRoutes.Count})");
            }

            slots[idx] = new Slot
            {
                Hash = hash,
                Key = key,
                Data = data,
                Occupied = true
            };
        }

        _slots = slots;
        _mask = mask;
        _count = exactRoutes.Count;
        _version++;

        logger.LogInfo($"Route jump table built: {exactRoutes.Count} exact routes in {tableSize}-slot table (load factor {(double)exactRoutes.Count / tableSize:P0})");
    }

    /// <summary>
    /// Look up an exact-match route by its pre-computed hash and key string.
    /// Returns true if found; the handler data is written to <paramref name="data"/>.
    /// </summary>
    public bool TryLookup(uint hash, string routeKey, out RouteHandlerData data)
    {
        var slots = _slots;
        if (slots.Length == 0)
        {
            data = default;
            return false;
        }

        uint mask = _mask;
        uint idx = hash & mask;

        // Linear probing — average 1-2 probes at ≤50% load factor
        while (true)
        {
            ref var slot = ref slots[idx];
            if (!slot.Occupied)
            {
                data = default;
                return false;
            }
            if (slot.Hash == hash && string.Equals(slot.Key, routeKey, StringComparison.Ordinal))
            {
                data = slot.Data;
                return true;
            }
            idx = (idx + 1) & mask;
        }
    }

    /// <summary>
    /// Convenience overload that hashes the key inline.
    /// </summary>
    public bool TryLookup(string routeKey, out RouteHandlerData data)
        => TryLookup(RouteHash.Hash(routeKey), routeKey, out data);

    private static int NextPowerOfTwo(int v)
    {
        v--;
        v |= v >> 1;
        v |= v >> 2;
        v |= v >> 4;
        v |= v >> 8;
        v |= v >> 16;
        return v + 1;
    }
}
