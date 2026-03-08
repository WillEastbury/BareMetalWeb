using System.Collections.Concurrent;
using System.Threading;

namespace BareMetalWeb.Host;

/// <summary>
/// Per-identity sliding-window rate limiter for API endpoints.
/// Tracks separate read (GET) and write (POST/PUT/PATCH/DELETE) budgets per minute.
/// Lock-free hot path using Interlocked operations.
/// </summary>
internal sealed class ApiRateLimiter
{
    private readonly ConcurrentDictionary<string, ApiBucket> _buckets = new(StringComparer.Ordinal);
    private readonly int _readLimitPerMinute;
    private readonly int _writeLimitPerMinute;
    private long _lastPruneTicks = DateTime.UtcNow.Ticks;

    public ApiRateLimiter(int readLimitPerMinute = 300, int writeLimitPerMinute = 60)
    {
        _readLimitPerMinute = readLimitPerMinute;
        _writeLimitPerMinute = writeLimitPerMinute;
    }

    /// <summary>
    /// Attempt to acquire a request slot. Returns true if allowed, false if rate-limited.
    /// </summary>
    public bool TryAcquire(string identity, bool isWrite, out int retryAfterSeconds)
    {
        PruneIfNeeded();

        var bucket = _buckets.GetOrAdd(identity, static _ => new ApiBucket());
        int limit = isWrite ? _writeLimitPerMinute : _readLimitPerMinute;
        return bucket.TryAcquire(limit, isWrite, out retryAfterSeconds);
    }

    /// <summary>Evict stale buckets every 2 minutes to bound memory.</summary>
    private void PruneIfNeeded()
    {
        var nowTicks = DateTime.UtcNow.Ticks;
        var lastPrune = Interlocked.Read(ref _lastPruneTicks);
        if (nowTicks - lastPrune < TimeSpan.TicksPerMinute * 2)
            return;

        if (Interlocked.CompareExchange(ref _lastPruneTicks, nowTicks, lastPrune) != lastPrune)
            return;

        var threshold = nowTicks - TimeSpan.TicksPerMinute * 3;
        foreach (var kvp in _buckets)
        {
            if (Interlocked.Read(ref kvp.Value.LastAccessTicks) < threshold)
                _buckets.TryRemove(kvp.Key, out _);
        }
    }

    private sealed class ApiBucket
    {
        private long _readCount;
        private long _writeCount;
        private long _windowStartTicks;
        internal long LastAccessTicks;

        public ApiBucket()
        {
            var now = DateTime.UtcNow.Ticks;
            _windowStartTicks = now;
            LastAccessTicks = now;
        }

        public bool TryAcquire(int limit, bool isWrite, out int retryAfterSeconds)
        {
            var nowTicks = DateTime.UtcNow.Ticks;
            Interlocked.Exchange(ref LastAccessTicks, nowTicks);

            // Reset window if expired
            var windowStart = Interlocked.Read(ref _windowStartTicks);
            if (nowTicks - windowStart > TimeSpan.TicksPerMinute)
            {
                // CAS to avoid multiple threads resetting concurrently
                if (Interlocked.CompareExchange(ref _windowStartTicks, nowTicks, windowStart) == windowStart)
                {
                    Interlocked.Exchange(ref _readCount, 0);
                    Interlocked.Exchange(ref _writeCount, 0);
                }
            }

            long count;
            if (isWrite)
                count = Interlocked.Increment(ref _writeCount);
            else
                count = Interlocked.Increment(ref _readCount);

            if (count <= limit)
            {
                retryAfterSeconds = 0;
                return true;
            }

            // Over limit — compute retry-after from remaining window time
            var remaining = TimeSpan.FromTicks(
                Interlocked.Read(ref _windowStartTicks) + TimeSpan.TicksPerMinute - nowTicks);
            retryAfterSeconds = Math.Max(1, (int)Math.Ceiling(remaining.TotalSeconds));

            // Roll back the increment so we don't inflate the counter
            if (isWrite)
                Interlocked.Decrement(ref _writeCount);
            else
                Interlocked.Decrement(ref _readCount);

            return false;
        }
    }
}
