using System.Buffers;

namespace BareMetalWeb.Core;

/// <summary>
/// Aggregates first-write/flush timing stages captured in <see cref="BmwContext"/>.
/// Keeps a recent rolling window for operational metrics endpoints.
/// </summary>
public static class ResponseTimingMetrics
{
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
    private static readonly object s_lock = new();
    private static readonly Queue<ResponseTimingSample> s_samples = new();

    public static void Record(double parseToFirstMs, double firstToFlushStartMs, double flushAwaitMs, double firstToFlushMs)
    {
        var now = DateTime.UtcNow;
        lock (s_lock)
        {
            s_samples.Enqueue(new ResponseTimingSample(
                now,
                MsToTicks(parseToFirstMs),
                MsToTicks(firstToFlushStartMs),
                MsToTicks(flushAwaitMs),
                MsToTicks(firstToFlushMs)));
            Prune(now);
        }
    }

    public static ResponseTimingSnapshot GetSnapshot()
    {
        lock (s_lock)
        {
            Prune(DateTime.UtcNow);
            if (s_samples.Count == 0)
                return ResponseTimingSnapshot.Empty;

            var samples = s_samples.ToArray();
            return new ResponseTimingSnapshot(
                samples.Length,
                Compute(samples, static s => s.ParseToFirstTicks),
                Compute(samples, static s => s.FirstToFlushStartTicks),
                Compute(samples, static s => s.FlushAwaitTicks),
                Compute(samples, static s => s.FirstToFlushTicks));
        }
    }

    private static void Prune(DateTime now)
    {
        var cutoff = now - Window;
        while (s_samples.Count > 0 && s_samples.Peek().TimestampUtc < cutoff)
            s_samples.Dequeue();
    }

    private static TimingMetric Compute(ResponseTimingSample[] samples, Func<ResponseTimingSample, long> selector)
    {
        var pool = ArrayPool<long>.Shared;
        var ticks = pool.Rent(samples.Length);
        try
        {
            long total = 0;
            long max = 0;
            for (int i = 0; i < samples.Length; i++)
            {
                var t = selector(samples[i]);
                ticks[i] = t;
                total += t;
                if (t > max) max = t;
            }

            Array.Sort(ticks, 0, samples.Length);
            var p95 = PercentileTicks(ticks, samples.Length, 0.95);
            return new TimingMetric(
                TimeSpan.FromTicks(total / samples.Length),
                TimeSpan.FromTicks(p95),
                TimeSpan.FromTicks(max));
        }
        finally
        {
            pool.Return(ticks);
        }
    }

    private static long PercentileTicks(long[] sortedTicks, int count, double percentile)
    {
        var position = percentile * count;
        var index = (int)Math.Ceiling(position) - 1;
        if (index < 0) index = 0;
        if (index >= count) index = count - 1;
        return sortedTicks[index];
    }

    private static long MsToTicks(double ms)
    {
        if (ms <= 0) return 0;
        return (long)Math.Round(TimeSpan.TicksPerMillisecond * ms);
    }

    private readonly record struct ResponseTimingSample(
        DateTime TimestampUtc,
        long ParseToFirstTicks,
        long FirstToFlushStartTicks,
        long FlushAwaitTicks,
        long FirstToFlushTicks);
}

public readonly record struct TimingMetric(TimeSpan Average, TimeSpan P95, TimeSpan Max);

public readonly record struct ResponseTimingSnapshot(
    int SampleCount,
    TimingMetric ParseToFirst,
    TimingMetric FirstToFlushStart,
    TimingMetric FlushAwait,
    TimingMetric FirstToFlush)
{
    public static readonly ResponseTimingSnapshot Empty = new(
        0,
        new TimingMetric(TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero),
        new TimingMetric(TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero),
        new TimingMetric(TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero),
        new TimingMetric(TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero));
}
