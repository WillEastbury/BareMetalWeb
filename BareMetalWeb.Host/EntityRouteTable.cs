using System.Runtime.CompilerServices;
using BareMetalWeb.Data;

namespace BareMetalWeb.Host;

/// <summary>
/// Open-addressed hash table that maps entity slug spans to pre-interned slug
/// strings. Built once at startup from <c>DataScaffold.Entities</c>; lookups
/// are allocation-free (single FNV-1a hash + linear probe on ReadOnlySpan&lt;char&gt;).
/// </summary>
/// <remarks>
/// <para>
/// The table uses 4× the entity count (rounded to next power-of-two) to keep
/// probe chains short. Linear probing is cache-friendly for the small table
/// sizes typical here (≤ 256 entities → ≤ 1024 slots).
/// </para>
/// <para>
/// All comparisons are case-insensitive (OrdinalIgnoreCase) to match the
/// DataScaffold.EntitiesBySlug dictionary behaviour.
/// </para>
/// </remarks>
public sealed class EntityRouteTable
{
    private struct Slot
    {
        /// <summary>Pre-interned entity slug (null = empty slot).</summary>
        public string? Slug;
        /// <summary>Compiled entity ordinal from RuntimeSnapshot (-1 = unresolved).</summary>
        public int EntityOrdinal;
    }

    private Slot[] _slots = Array.Empty<Slot>();
    private uint _mask;
    private int _count;

    /// <summary>Number of entities in the table.</summary>
    public int Count => _count;

    /// <summary>
    /// Build the table from a set of entity slugs.
    /// Each slug is stored as-is (pre-interned) for zero-allocation comparison.
    /// </summary>
    public void Build(IReadOnlyList<string> slugs)
    {
        if (slugs.Count == 0)
        {
            _slots = Array.Empty<Slot>();
            _mask = 0;
            _count = 0;
            return;
        }

        int tableSize = NextPowerOfTwo(slugs.Count * 4);
        uint mask = (uint)(tableSize - 1);
        var slots = new Slot[tableSize];

        for (int i = 0; i < slugs.Count; i++)
        {
            var slug = slugs[i];
            uint idx = HashSlug(slug.AsSpan()) & mask;

            // Linear probe to find empty slot
            while (slots[idx].Slug != null)
                idx = (idx + 1) & mask;

            slots[idx].Slug = slug;

            // Resolve compiled ordinal from RuntimeSnapshot (if available)
            var snapshot = RuntimeSnapshot.Current;
            slots[idx].EntityOrdinal = snapshot?.Entities.TryResolveSlug(slug, out int eid) == true ? eid : -1;
        }

        _slots = slots;
        _mask = mask;
        _count = slugs.Count;
    }

    /// <summary>
    /// Resolve an entity slug span to its pre-interned string and compiled ordinal.
    /// Returns true if the entity is known; <paramref name="resolvedSlug"/>
    /// is the canonical slug string (no allocation), <paramref name="entityOrdinal"/>
    /// is the RuntimeSnapshot EntityId (-1 if snapshot was not available at build time).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryResolve(ReadOnlySpan<char> slug, out string resolvedSlug, out int entityOrdinal)
    {
        var slots = _slots;
        if (slots.Length == 0) { resolvedSlug = null!; entityOrdinal = -1; return false; }

        uint idx = HashSlug(slug) & _mask;

        // Linear probe — max _count probes before guaranteed miss
        for (int probe = 0; probe <= _count; probe++)
        {
            ref var slot = ref slots[idx];
            if (slot.Slug == null) { resolvedSlug = null!; entityOrdinal = -1; return false; }
            if (slug.Equals(slot.Slug.AsSpan(), StringComparison.OrdinalIgnoreCase))
            {
                resolvedSlug = slot.Slug;
                entityOrdinal = slot.EntityOrdinal;
                return true;
            }
            idx = (idx + 1) & _mask;
        }

        resolvedSlug = null!;
        entityOrdinal = -1;
        return false;
    }

    /// <summary>FNV-1a hash over a char span (case-insensitive via ASCII lowering).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint HashSlug(ReadOnlySpan<char> slug)
    {
        uint hash = 2166136261u;
        for (int i = 0; i < slug.Length; i++)
        {
            // ASCII-lowercase for case-insensitive hashing
            uint c = slug[i];
            if (c >= 'A' && c <= 'Z') c |= 0x20;
            hash ^= c;
            hash *= 16777619u;
        }
        return hash;
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
