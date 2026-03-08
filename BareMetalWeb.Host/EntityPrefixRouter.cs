using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace BareMetalWeb.Host;

/// <summary>
/// Entity route descriptor: maps a canonical name to a contiguous ordinal.
/// </summary>
public readonly struct EntityRoute
{
    public readonly string Name;
    public readonly int Ordinal;

    public EntityRoute(string name, int ordinal)
    {
        Name = name;
        Ordinal = ordinal;
    }
}

/// <summary>
/// O(1) entity router using word-based prefix comparison.
/// Resolves entity names from request path segments using 64-bit word loads
/// and branchless arithmetic over <see cref="ReadOnlySpan{Byte}"/>.
/// </summary>
/// <remarks>
/// <para>
/// At startup, entities are assigned contiguous ordinals and grouped by
/// their first ASCII character into a 26-slot dispatch table. Each entry
/// stores a precomputed <c>ulong</c> containing the first 8 lowercase
/// bytes, enabling single-instruction comparison for most entity names.
/// </para>
/// <para>
/// Hot path: 1 byte read (first char) → 1 array index → 1 word load +
/// XOR + length check. No hashing, no dictionary lookups, no allocations.
/// Slugs ≤ 8 bytes resolve with a single <c>ulong</c> comparison.
/// </para>
/// </remarks>
public sealed class EntityPrefixRouter
{
    /// <summary>Pre-computed byte literal for an entity name.</summary>
    private readonly struct ByteLiteral
    {
        public readonly byte[] Bytes;     // UTF-8 lowercase
        public readonly string Name;      // Pre-interned canonical name
        public readonly int Ordinal;
        public readonly int Length;        // Cached byte length
        public readonly ulong PrefixWord; // First min(8, Length) bytes as LE ulong

        public ByteLiteral(byte[] bytes, string name, int ordinal)
        {
            Bytes = bytes;
            Name = name;
            Ordinal = ordinal;
            Length = bytes.Length;
            PrefixWord = PackWord(bytes);
        }
    }

    private ByteLiteral[][] _buckets = Array.Empty<ByteLiteral[]>();
    private EntityRoute[] _routes = Array.Empty<EntityRoute>();
    private int _count;

    /// <summary>Number of registered entities.</summary>
    public int Count => _count;

    /// <summary>Registered entity routes.</summary>
    public IReadOnlyList<EntityRoute> Routes => _routes;

    /// <summary>
    /// Build the prefix dispatch tree from a set of entity routes.
    /// Entities are grouped by first ASCII character; within each group,
    /// sorted by length descending for longest-first matching.
    /// Precomputes 64-bit prefix words for word-based comparison.
    /// </summary>
    public void Build(IReadOnlyList<EntityRoute> routes)
    {
        _count = routes.Count;
        _routes = routes.ToArray();

        if (routes.Count == 0)
        {
            _buckets = new ByteLiteral[26][];
            for (int i = 0; i < 26; i++) _buckets[i] = Array.Empty<ByteLiteral>();
            return;
        }

        var groups = new List<ByteLiteral>[26];

        for (int i = 0; i < routes.Count; i++)
        {
            var route = routes[i];
            byte[] bytes = Encoding.UTF8.GetBytes(route.Name.ToLowerInvariant());
            if (bytes.Length == 0) continue;

            int bucket = AsciiLower(bytes[0]) - 'a';
            if ((uint)bucket >= 26) continue;

            groups[bucket] ??= new List<ByteLiteral>();
            groups[bucket].Add(new ByteLiteral(bytes, route.Name, route.Ordinal));
        }

        _buckets = new ByteLiteral[26][];
        for (int b = 0; b < 26; b++)
        {
            if (groups[b] is { Count: > 0 } list)
            {
                list.Sort((a, x) => x.Length.CompareTo(a.Length));
                _buckets[b] = list.ToArray();
            }
            else
            {
                _buckets[b] = Array.Empty<ByteLiteral>();
            }
        }
    }

    /// <summary>
    /// Build from simple slug list, assigning contiguous ordinals 0..N-1.
    /// </summary>
    public void Build(IReadOnlyList<string> slugs)
    {
        var routes = new EntityRoute[slugs.Count];
        for (int i = 0; i < slugs.Count; i++)
            routes[i] = new EntityRoute(slugs[i], i);
        Build(routes);
    }

    /// <summary>
    /// Resolve an entity slug (UTF-8 bytes) to its canonical name and ordinal.
    /// Uses 64-bit word comparison: slugs ≤ 8 bytes resolve with a single
    /// ulong XOR; longer slugs check the first 8 bytes then fall back to
    /// SequenceEqual for the tail. Zero allocations, zero branches in the
    /// common case.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryResolve(ReadOnlySpan<byte> entitySlug, out string resolvedName, out int ordinal)
    {
        if (entitySlug.IsEmpty || _buckets.Length == 0)
        {
            resolvedName = null!;
            ordinal = -1;
            return false;
        }

        if (entitySlug.Length > 128)
        {
            resolvedName = null!;
            ordinal = -1;
            return false;
        }

        // Pre-lowercase once using branchless masking
        Span<byte> lowered = stackalloc byte[entitySlug.Length];
        AsciiLowerSpan(entitySlug, lowered);

        int bucket = lowered[0] - 'a';
        if ((uint)bucket >= 26)
        {
            resolvedName = null!;
            ordinal = -1;
            return false;
        }

        int slugLen = lowered.Length;
        ulong slugWord = PackWord(lowered);
        var entries = _buckets[bucket];

        for (int i = 0; i < entries.Length; i++)
        {
            ref readonly var entry = ref entries[i];

            // Branchless: XOR the prefix words and OR with the length
            // difference. If the combined value is zero, the first 8
            // bytes and the length both match.
            ulong diff = slugWord ^ entry.PrefixWord;
            ulong combined = diff | (uint)(slugLen ^ entry.Length);

            if (combined != 0)
                continue;

            // For slugs ≤ 8 bytes, the word comparison is the full match.
            // For longer slugs, verify the tail beyond byte 8.
            if (slugLen > 8 && !lowered.Slice(8).SequenceEqual(entry.Bytes.AsSpan(8)))
                continue;

            resolvedName = entry.Name;
            ordinal = entry.Ordinal;
            return true;
        }

        resolvedName = null!;
        ordinal = -1;
        return false;
    }

    /// <summary>
    /// Resolve an entity slug (char span) to its canonical name and ordinal.
    /// Encodes to UTF-8 on the stack for byte-level comparison.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryResolve(ReadOnlySpan<char> entitySlug, out string resolvedName, out int ordinal)
    {
        Span<byte> buf = stackalloc byte[128];
        if (entitySlug.Length > 42)
        {
            resolvedName = null!;
            ordinal = -1;
            return false;
        }
        int written = Encoding.UTF8.GetBytes(entitySlug, buf);
        return TryResolve(buf[..written], out resolvedName, out ordinal);
    }

    /// <summary>
    /// Parse entity name from a full UTF-8 path and resolve its ordinal.
    /// Uses SWAR (SIMD Within A Register) to scan for '/' separators
    /// 8 bytes at a time instead of byte-by-byte.
    /// </summary>
    public bool TryParseAndResolve(
        ReadOnlySpan<byte> path,
        ReadOnlySpan<byte> prefix,
        out string resolvedName,
        out int ordinal,
        out ReadOnlySpan<byte> remainder)
    {
        resolvedName = null!;
        ordinal = -1;
        remainder = default;

        if (!path.StartsWith(prefix))
            return false;

        var afterPrefix = path[prefix.Length..];

        int slash = FindSlash(afterPrefix);
        ReadOnlySpan<byte> entitySlug;

        if (slash < 0)
        {
            entitySlug = afterPrefix;
            remainder = ReadOnlySpan<byte>.Empty;
        }
        else
        {
            entitySlug = afterPrefix[..slash];
            remainder = afterPrefix[(slash + 1)..];
        }

        return TryResolve(entitySlug, out resolvedName, out ordinal);
    }

    // ── Word packing ─────────────────────────────────────────────

    /// <summary>
    /// Pack the first min(8, length) bytes of a span into a little-endian
    /// ulong, zero-padding the high bytes for short spans. Uses an
    /// unaligned 64-bit load when the span is ≥ 8 bytes.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong PackWord(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length >= 8)
            return Unsafe.ReadUnaligned<ulong>(ref MemoryMarshal.GetReference(bytes));

        // Short span: pack byte-by-byte (branchless shift chain)
        ulong word = 0;
        for (int i = 0; i < bytes.Length; i++)
            word |= (ulong)bytes[i] << (i * 8);
        return word;
    }

    // ── SWAR slash scanner (#1301) ───────────────────────────────

    /// <summary>
    /// Find the index of the first '/' byte using SWAR (SIMD Within A
    /// Register). Scans 8 bytes per iteration using the standard
    /// byte-detection trick: XOR with the target byte, then detect zero
    /// bytes via <c>(x - 0x01…01) &amp; ~x &amp; 0x80…80</c>.
    /// Falls back to scalar scanning for the &lt; 8 byte tail.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static int FindSlash(ReadOnlySpan<byte> span)
    {
        const ulong broadcast = 0x2F2F2F2F_2F2F2F2FUL; // '/' in every byte lane
        const ulong lo = 0x01010101_01010101UL;
        const ulong hi = 0x80808080_80808080UL;

        ref byte start = ref MemoryMarshal.GetReference(span);
        int i = 0;

        // 8-byte SWAR scan
        while (i + 8 <= span.Length)
        {
            ulong word = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref start, i));
            ulong x = word ^ broadcast;
            ulong mask = (x - lo) & ~x & hi;
            if (mask != 0)
                return i + (BitOperations.TrailingZeroCount(mask) >> 3);
            i += 8;
        }

        // Scalar tail
        for (; i < span.Length; i++)
        {
            if (Unsafe.Add(ref start, i) == (byte)'/')
                return i;
        }

        return -1;
    }

    // ── Matching helpers (retained for external callers / tests) ──

    /// <summary>
    /// Fast exact byte comparison using <see cref="MemoryExtensions.SequenceEqual{T}"/>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool Match(ReadOnlySpan<byte> span, ReadOnlySpan<byte> literal)
        => span.SequenceEqual(literal);

    /// <summary>
    /// Overload accepting a string literal — encodes to UTF-8 on the stack
    /// and delegates to the byte comparison.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool Match(ReadOnlySpan<byte> span, string literal)
    {
        if (literal.Length > 42) return false;
        Span<byte> buf = stackalloc byte[128];
        int len = Encoding.UTF8.GetBytes(literal.AsSpan(), buf);
        return span.SequenceEqual(buf[..len]);
    }

    /// <summary>
    /// ASCII case-insensitive byte comparison (scalar fallback).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool MatchIgnoreAsciiCase(ReadOnlySpan<byte> span, ReadOnlySpan<byte> loweredLiteral)
    {
        if (span.Length != loweredLiteral.Length) return false;

        for (int i = 0; i < span.Length; i++)
        {
            if (AsciiLower(span[i]) != loweredLiteral[i])
                return false;
        }
        return true;
    }

    // ── Branchless ASCII lowering ────────────────────────────────

    /// <summary>
    /// Branchless ASCII lowercase using arithmetic masking.
    /// NativeAOT ARM64: SUB / SUB / ASR / AND / ORR — zero branches.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte AsciiLower(byte b)
    {
        uint diff = (uint)(b - 'A');
        uint mask = (uint)((int)(diff - 26) >> 31) & 0x20;
        return (byte)(b | mask);
    }

    /// <summary>
    /// Bulk-lowercase a span using the branchless mask.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void AsciiLowerSpan(ReadOnlySpan<byte> src, Span<byte> dst)
    {
        for (int i = 0; i < src.Length; i++)
            dst[i] = AsciiLower(src[i]);
    }
}
