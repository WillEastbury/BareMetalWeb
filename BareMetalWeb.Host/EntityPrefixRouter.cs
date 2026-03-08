using System.Diagnostics;
using System.Runtime.CompilerServices;
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
/// O(1) entity router using Redis-style prefix parsing.
/// Resolves entity names from request path segments using branch-friendly
/// prefix comparisons over <see cref="ReadOnlySpan{Byte}"/>.
/// </summary>
/// <remarks>
/// <para>
/// At startup, entities are assigned contiguous ordinals and grouped by
/// their first ASCII character into a 26-slot dispatch table. Within each
/// bucket, entries are sorted by length descending (longest first) to ensure
/// deterministic resolution of shared prefixes (e.g. "customerGroup" before
/// "customer").
/// </para>
/// <para>
/// The hot path performs: 1 byte read (first char) → 1 array index →
/// 1–2 <see cref="MemoryExtensions.SequenceEqual{T}(ReadOnlySpan{T}, ReadOnlySpan{T})"/>
/// comparisons. No hashing, no dictionary lookups, no string allocations.
/// </para>
/// </remarks>
public sealed class EntityPrefixRouter
{
    /// <summary>Pre-computed byte literal for an entity name.</summary>
    private readonly struct ByteLiteral
    {
        public readonly byte[] Bytes; // UTF-8 lowercase
        public readonly string Name;  // Pre-interned canonical name
        public readonly int Ordinal;

        public ByteLiteral(byte[] bytes, string name, int ordinal)
        {
            Bytes = bytes;
            Name = name;
            Ordinal = ordinal;
        }
    }

    private ByteLiteral[][] _buckets = Array.Empty<ByteLiteral[]>();
    private EntityRoute[] _routes = Array.Empty<EntityRoute>();
    private int _count;

    // Metrics (thread-safe via Interlocked)
    private long _dispatchTicks;
    private long _dispatchCount;
    private long _matchAttempts;

    /// <summary>Number of registered entities.</summary>
    public int Count => _count;

    /// <summary>Registered entity routes.</summary>
    public IReadOnlyList<EntityRoute> Routes => _routes;

    /// <summary>Total dispatch operations recorded.</summary>
    public long DispatchCount => Volatile.Read(ref _dispatchCount);

    /// <summary>Total entity_match_attempts across all dispatches.</summary>
    public long MatchAttempts => Volatile.Read(ref _matchAttempts);

    /// <summary>Average entity_dispatch_time in nanoseconds.</summary>
    public double AverageDispatchNs
    {
        get
        {
            long count = Volatile.Read(ref _dispatchCount);
            if (count == 0) return 0;
            double ticks = Volatile.Read(ref _dispatchTicks);
            return ticks / count / Stopwatch.Frequency * 1_000_000_000;
        }
    }

    /// <summary>
    /// Build the prefix dispatch tree from a set of entity routes.
    /// Entities are grouped by first ASCII character; within each group,
    /// sorted by name length descending for longest-first matching.
    /// </summary>
    public void Build(IReadOnlyList<EntityRoute> routes)
    {
        _count = routes.Count;
        _routes = routes.ToArray();
        ResetMetrics();

        if (routes.Count == 0)
        {
            _buckets = new ByteLiteral[26][];
            for (int i = 0; i < 26; i++) _buckets[i] = Array.Empty<ByteLiteral>();
            return;
        }

        // Group by first character (ASCII-lowered) → bucket index
        var groups = new List<ByteLiteral>[26];

        for (int i = 0; i < routes.Count; i++)
        {
            var route = routes[i];
            byte[] bytes = Encoding.UTF8.GetBytes(route.Name.ToLowerInvariant());
            if (bytes.Length == 0) continue;

            int bucket = AsciiLower(bytes[0]) - 'a';
            if ((uint)bucket >= 26) continue; // non-alpha first char — skip

            groups[bucket] ??= new List<ByteLiteral>();
            groups[bucket].Add(new ByteLiteral(bytes, route.Name, route.Ordinal));
        }

        // Build dispatch table with longest-first ordering
        _buckets = new ByteLiteral[26][];
        for (int b = 0; b < 26; b++)
        {
            if (groups[b] is { Count: > 0 } list)
            {
                list.Sort((a, x) => x.Bytes.Length.CompareTo(a.Bytes.Length));
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
    /// O(1) bucket lookup + 1–2 comparisons per bucket. Case-insensitive.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryResolve(ReadOnlySpan<byte> entitySlug, out string resolvedName, out int ordinal)
    {
        long start = Stopwatch.GetTimestamp();

        if (entitySlug.IsEmpty || _buckets.Length == 0)
        {
            resolvedName = null!;
            ordinal = -1;
            return false;
        }

        int bucket = AsciiLower(entitySlug[0]) - 'a';
        if ((uint)bucket >= 26)
        {
            resolvedName = null!;
            ordinal = -1;
            RecordDispatch(start, 0);
            return false;
        }

        var entries = _buckets[bucket];
        int attempts = 0;

        for (int i = 0; i < entries.Length; i++)
        {
            attempts++;
            ref readonly var entry = ref entries[i];

            if (MatchIgnoreAsciiCase(entitySlug, entry.Bytes))
            {
                resolvedName = entry.Name;
                ordinal = entry.Ordinal;
                RecordDispatch(start, attempts);
                return true;
            }
        }

        resolvedName = null!;
        ordinal = -1;
        RecordDispatch(start, attempts);
        return false;
    }

    /// <summary>
    /// Resolve an entity slug (char span) to its canonical name and ordinal.
    /// Encodes to UTF-8 on the stack for byte-level comparison.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryResolve(ReadOnlySpan<char> entitySlug, out string resolvedName, out int ordinal)
    {
        // Stack-encode up to 128 chars (covers any realistic entity name)
        Span<byte> buf = stackalloc byte[128];
        int written = Encoding.UTF8.GetBytes(entitySlug, buf);
        return TryResolve(buf[..written], out resolvedName, out ordinal);
    }

    /// <summary>
    /// Parse entity name from a full UTF-8 path and resolve its ordinal.
    /// </summary>
    /// <param name="path">Full request path bytes (e.g. <c>/ui/customer/123</c>).</param>
    /// <param name="prefix">Path prefix to strip (e.g. <c>/ui/</c>).</param>
    /// <param name="resolvedName">Canonical entity name on success.</param>
    /// <param name="ordinal">Entity ordinal on success, -1 on failure.</param>
    /// <param name="remainder">Path remainder after the entity segment.</param>
    /// <returns><c>true</c> if the entity was resolved.</returns>
    /// <example>
    /// <code>
    /// // Input:  /ui/customer/123
    /// // Prefix: /ui/
    /// // Result: resolvedName="customer", ordinal=0, remainder="123"
    /// </code>
    /// </example>
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

        // Extract entity segment (up to next '/' or end)
        int slash = afterPrefix.IndexOf((byte)'/');
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

    /// <summary>
    /// Fast exact byte comparison using <see cref="MemoryExtensions.SequenceEqual{T}"/>.
    /// For case-sensitive entity matching against pre-computed byte literals.
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
        Span<byte> buf = stackalloc byte[128];
        int len = Encoding.UTF8.GetBytes(literal.AsSpan(), buf);
        return span.SequenceEqual(buf[..len]);
    }

    /// <summary>
    /// ASCII case-insensitive byte comparison.
    /// Pre-computed literals are stored lowercase; this lowers each input byte
    /// inline. Branches are predictable (single ASCII range check per byte).
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

    /// <summary>Reset dispatch metrics to zero.</summary>
    public void ResetMetrics()
    {
        Interlocked.Exchange(ref _dispatchTicks, 0);
        Interlocked.Exchange(ref _dispatchCount, 0);
        Interlocked.Exchange(ref _matchAttempts, 0);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte AsciiLower(byte b) => (b >= (byte)'A' && b <= (byte)'Z') ? (byte)(b | 0x20) : b;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void RecordDispatch(long startTimestamp, int attempts)
    {
        long elapsed = Stopwatch.GetTimestamp() - startTimestamp;
        Interlocked.Add(ref _dispatchTicks, elapsed);
        Interlocked.Increment(ref _dispatchCount);
        Interlocked.Add(ref _matchAttempts, attempts);
    }
}
