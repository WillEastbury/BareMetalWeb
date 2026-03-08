using System.Runtime.CompilerServices;

namespace BareMetalWeb.Host;

/// <summary>
/// FNV-1a hash for route keys. Deterministic, extremely fast, and operates
/// on <see cref="ReadOnlySpan{T}"/> to avoid allocations.
/// </summary>
/// <remarks>
/// <para>
/// FNV-1a is chosen over xxHash for simplicity — the input sizes (short route
/// strings) don't benefit from SIMD acceleration, and FNV-1a has excellent
/// distribution for string keys.
/// </para>
/// <para>
/// The seeded overloads (<see cref="Hash(string, uint)"/>) mix a seed into the
/// offset basis, allowing the perfect-hash builder to try different hash
/// functions without changing the algorithm.
/// </para>
/// </remarks>
public static class RouteHash
{
    private const uint FnvOffsetBasis = 2166136261u;
    private const uint FnvPrime = 16777619u;

    /// <summary>Compute FNV-1a hash of a route key string.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint Hash(string key)
    {
        uint hash = FnvOffsetBasis;
        for (int i = 0; i < key.Length; i++)
        {
            hash ^= key[i];
            hash *= FnvPrime;
        }
        return hash;
    }

    /// <summary>Compute FNV-1a hash of a route key span.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint Hash(ReadOnlySpan<char> key)
    {
        uint hash = FnvOffsetBasis;
        for (int i = 0; i < key.Length; i++)
        {
            hash ^= key[i];
            hash *= FnvPrime;
        }
        return hash;
    }

    /// <summary>
    /// Compute a seeded FNV-1a hash. The seed is XORed into the offset basis,
    /// producing a different hash function per seed value. Used by the
    /// perfect-hash builder to search for a collision-free mapping.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint Hash(string key, uint seed)
    {
        uint hash = FnvOffsetBasis ^ seed;
        for (int i = 0; i < key.Length; i++)
        {
            hash ^= key[i];
            hash *= FnvPrime;
        }
        return hash;
    }

    /// <summary>Seeded FNV-1a hash over a span.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint Hash(ReadOnlySpan<char> key, uint seed)
    {
        uint hash = FnvOffsetBasis ^ seed;
        for (int i = 0; i < key.Length; i++)
        {
            hash ^= key[i];
            hash *= FnvPrime;
        }
        return hash;
    }

    /// <summary>
    /// Seeded FNV-1a hash over two concatenated strings without allocating.
    /// Produces the same result as <c>Hash(string.Concat(prefix, suffix), seed)</c>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint Hash(string prefix, string suffix, uint seed)
    {
        uint hash = FnvOffsetBasis ^ seed;
        for (int i = 0; i < prefix.Length; i++)
        {
            hash ^= prefix[i];
            hash *= FnvPrime;
        }
        for (int i = 0; i < suffix.Length; i++)
        {
            hash ^= suffix[i];
            hash *= FnvPrime;
        }
        return hash;
    }
}
