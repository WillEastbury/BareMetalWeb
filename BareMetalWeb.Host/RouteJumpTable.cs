using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Host;

/// <summary>
/// A perfect-hash dispatch table for exact-match route lookup in O(1) with
/// zero collision probing. Routes with parameters (e.g. <c>/api/{type}/{id}</c>)
/// are not eligible and fall through to the pattern-matching path.
/// </summary>
/// <remarks>
/// <para>
/// At build time the table searches for an FNV-1a seed that maps every
/// exact-match route key to a unique slot (a minimal-collision perfect hash).
/// The table starts at 4× the route count and adaptively doubles up to 16×
/// if the seed search doesn't converge within 100k attempts per size.
/// </para>
/// <para>
/// At runtime, lookup is a single seeded hash, a bitwise mask, and one
/// ordinal string comparison — no probing loop, no dictionary overhead.
/// </para>
/// <para>
/// Rebuilt whenever routes change (tracked via a version counter).
/// </para>
/// </remarks>
public sealed class RouteJumpTable
{
    private struct Slot
    {
        public string Key;          // "GET /login" — null means empty slot
        public RouteHandlerData Data;
    }

    private Slot[] _slots = Array.Empty<Slot>();
    private uint _seed;
    private uint _mask;
    private int _count;
    private int _version;

    /// <summary>Number of exact-match routes in the table.</summary>
    public int Count => _count;

    /// <summary>The perfect-hash seed found at build time.</summary>
    public uint Seed => _seed;

    /// <summary>
    /// Rebuild the table from the current route dictionary.
    /// Finds an FNV-1a seed that gives every exact-match route a unique slot.
    /// Adaptively grows the table when the birthday-problem makes a collision-free
    /// seed unlikely at the current size.
    /// </summary>
    public void Build(Dictionary<string, RouteHandlerData> routes, Dictionary<string, CompiledRoute> compiledRoutes, IBufferedLogger logger)
    {
        // Collect exact-match routes (no parameters, no regex, no catch-all)
        var exactRoutes = new List<(string Key, RouteHandlerData Data)>();
        foreach (var kvp in routes)
        {
            if (compiledRoutes.TryGetValue(kvp.Key, out var compiled))
            {
                if (compiled.IsRegex || compiled.ParameterCount > 0)
                    continue;
            }

            exactRoutes.Add((kvp.Key, kvp.Value));
        }

        if (exactRoutes.Count == 0)
        {
            _slots = Array.Empty<Slot>();
            _mask = 0;
            _seed = 0;
            _count = 0;
            _version++;
            return;
        }

        // Adaptively grow the table when the seed search doesn't converge.
        // Start at 4× route count (birthday-problem sweet spot for <200 routes),
        // doubling up to 16× if needed. Each size gets 100k seed attempts.
        const int maxMultiplier = 16;
        const uint maxSeedAttempts = 100_000;

        int multiplier = 4;
        uint seed = 0;
        int tableSize = 0;
        uint mask = 0;
        bool found = false;

        while (multiplier <= maxMultiplier)
        {
            tableSize = NextPowerOfTwo(exactRoutes.Count * multiplier);
            mask = (uint)(tableSize - 1);
            var occupied = new bool[tableSize];

            for (seed = 0; seed < maxSeedAttempts; seed++)
            {
                bool collision = false;
                Array.Clear(occupied);

                for (int i = 0; i < exactRoutes.Count; i++)
                {
                    uint idx = RouteHash.Hash(exactRoutes[i].Key, seed) & mask;
                    if (occupied[idx])
                    {
                        collision = true;
                        break;
                    }
                    occupied[idx] = true;
                }

                if (!collision)
                {
                    found = true;
                    break;
                }
            }

            if (found)
                break;

            logger.LogInfo(
                $"Perfect hash: no seed found for {exactRoutes.Count} routes in " +
                $"{tableSize}-slot table ({multiplier}×), expanding to {multiplier * 2}×");
            multiplier *= 2;
        }

        if (!found)
            throw new InvalidOperationException(
                $"Could not find a perfect hash seed for {exactRoutes.Count} routes " +
                $"in {tableSize}-slot table after {maxMultiplier}× expansion.");

        // Populate the table using the winning seed
        var slots = new Slot[tableSize];
        for (int i = 0; i < exactRoutes.Count; i++)
        {
            uint idx = RouteHash.Hash(exactRoutes[i].Key, seed) & mask;
            slots[idx] = new Slot
            {
                Key = exactRoutes[i].Key,
                Data = exactRoutes[i].Data
            };
        }

        _slots = slots;
        _seed = seed;
        _mask = mask;
        _count = exactRoutes.Count;
        _version++;

        logger.LogInfo(
            $"Perfect route table built: {exactRoutes.Count} exact routes in " +
            $"{tableSize}-slot table, seed={seed} (load factor {(double)exactRoutes.Count / tableSize:P0})");
    }

    /// <summary>
    /// Look up an exact-match route by its key string.
    /// Returns true if found; the handler data is written to <paramref name="data"/>.
    /// Single hash + single comparison — no probing.
    /// </summary>
    public bool TryLookup(string routeKey, out RouteHandlerData data)
    {
        var slots = _slots;
        if (slots.Length == 0)
        {
            data = default;
            return false;
        }

        uint idx = RouteHash.Hash(routeKey, _seed) & _mask;
        ref var slot = ref slots[idx];

        if (slot.Key != null && string.Equals(slot.Key, routeKey, StringComparison.Ordinal))
        {
            data = slot.Data;
            return true;
        }

        data = default;
        return false;
    }

    /// <summary>
    /// Look up an exact-match route using a pre-computed hash and key.
    /// The hash must have been computed with <see cref="RouteHash.Hash(string, uint)"/>
    /// using the same seed as this table.
    /// </summary>
    public bool TryLookup(uint hash, string routeKey, out RouteHandlerData data)
    {
        var slots = _slots;
        if (slots.Length == 0)
        {
            data = default;
            return false;
        }

        uint idx = hash & _mask;
        ref var slot = ref slots[idx];

        if (slot.Key != null && string.Equals(slot.Key, routeKey, StringComparison.Ordinal))
        {
            data = slot.Data;
            return true;
        }

        data = default;
        return false;
    }

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
