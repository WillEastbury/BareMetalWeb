using System.Runtime.CompilerServices;

namespace BareMetalWeb.Host;

/// <summary>
/// FNV-1a hash for route keys. Deterministic, extremely fast, and operates
/// on <see cref="ReadOnlySpan{T}"/> to avoid allocations.
/// </summary>
/// <remarks>
/// FNV-1a is chosen over xxHash for simplicity — the input sizes (short route
/// strings) don't benefit from SIMD acceleration, and FNV-1a has excellent
/// distribution for string keys.
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
}
