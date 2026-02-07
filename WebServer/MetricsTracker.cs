using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;

using BareMetalWeb.Interfaces;

namespace BareMetalWeb.WebServer;

public sealed class MetricsTracker : IMetricsTracker
{
    private static readonly TimeSpan RecentWindow = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan RecentShortWindow = TimeSpan.FromSeconds(10);

    private long _totalRequests;
    private long _errorRequests;
    private long _totalElapsedTicks;
    private long _requests2xx;
    private long _requests4xx;
    private long _requests5xx;
    private long _requestsOther;
    private long _throttledRequests;

    private readonly object _recentLock = new();
    private readonly Queue<ResponseSample> _recentSamples = new();

    public void RecordRequest(int statusCode, TimeSpan elapsed)
    {
        Interlocked.Increment(ref _totalRequests);

        if (statusCode >= 200 && statusCode <= 299)
            Interlocked.Increment(ref _requests2xx);
        else if (statusCode >= 400 && statusCode <= 499)
            Interlocked.Increment(ref _requests4xx);
        else if (statusCode >= 500 && statusCode <= 599)
            Interlocked.Increment(ref _requests5xx);
        else
            Interlocked.Increment(ref _requestsOther);

        if (statusCode >= 500)
            Interlocked.Increment(ref _errorRequests);

        Interlocked.Add(ref _totalElapsedTicks, elapsed.Ticks);

        var nowUtc = DateTime.UtcNow;
        lock (_recentLock)
        {
            _recentSamples.Enqueue(new ResponseSample(nowUtc, elapsed.Ticks));
            PruneOldSamples(nowUtc);
        }
    }

    public void RecordThrottled(TimeSpan elapsed)
    {
        Interlocked.Increment(ref _throttledRequests);
        RecordRequest(429, elapsed);
    }

    public MetricsSnapshot GetSnapshot()
    {
        var total = Interlocked.Read(ref _totalRequests);
        var errors = Interlocked.Read(ref _errorRequests);
        var ticks = Interlocked.Read(ref _totalElapsedTicks);
        var average = total == 0 ? TimeSpan.Zero : TimeSpan.FromTicks(ticks / total);

        long requests2xx = Interlocked.Read(ref _requests2xx);
        long requests4xx = Interlocked.Read(ref _requests4xx);
        long requests5xx = Interlocked.Read(ref _requests5xx);
        long requestsOther = Interlocked.Read(ref _requestsOther);
        long throttled = Interlocked.Read(ref _throttledRequests);

        ResponseSample[] recentSamples;
        DateTime nowUtc = DateTime.UtcNow;
        lock (_recentLock)
        {
            PruneOldSamples(nowUtc);
            recentSamples = _recentSamples.ToArray();
        }

        var recentMetrics = ComputeRecentMetrics(recentSamples);
        var recent10s = ComputeRecentMetrics(FilterRecentSamples(recentSamples, nowUtc - RecentShortWindow));

        return new MetricsSnapshot(
            total,
            errors,
            average,
            recentMetrics.Minimum,
            recentMetrics.Maximum,
            recentMetrics.Average,
            recentMetrics.P95,
            recentMetrics.P99,
            recent10s.Average,
            requests2xx,
            requests4xx,
            requests5xx,
            requestsOther,
            throttled
        );
    }

    private void PruneOldSamples(DateTime nowUtc)
    {
        var cutoff = nowUtc - RecentWindow;
        while (_recentSamples.Count > 0 && _recentSamples.Peek().TimestampUtc < cutoff)
        {
            _recentSamples.Dequeue();
        }
    }

    private static RecentMetrics ComputeRecentMetrics(ResponseSample[] samples)
    {
        if (samples.Length == 0)
            return new RecentMetrics(TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero, TimeSpan.Zero);

        var ticks = new long[samples.Length];
        long totalTicks = 0;
        long minTicks = long.MaxValue;
        long maxTicks = long.MinValue;

        for (int i = 0; i < samples.Length; i++)
        {
            var t = samples[i].ElapsedTicks;
            ticks[i] = t;
            totalTicks += t;
            if (t < minTicks) minTicks = t;
            if (t > maxTicks) maxTicks = t;
        }

        Array.Sort(ticks);
        var p95 = PercentileTicks(ticks, 0.95);
        var p99 = PercentileTicks(ticks, 0.99);

        var avgTicks = totalTicks / samples.Length;
        return new RecentMetrics(
            TimeSpan.FromTicks(minTicks),
            TimeSpan.FromTicks(maxTicks),
            TimeSpan.FromTicks(avgTicks),
            TimeSpan.FromTicks(p95),
            TimeSpan.FromTicks(p99)
        );
    }

    private static ResponseSample[] FilterRecentSamples(ResponseSample[] samples, DateTime cutoffUtc)
    {
        if (samples.Length == 0)
            return Array.Empty<ResponseSample>();

        var list = new List<ResponseSample>(samples.Length);
        for (int i = 0; i < samples.Length; i++)
        {
            if (samples[i].TimestampUtc >= cutoffUtc)
                list.Add(samples[i]);
        }

        return list.Count == samples.Length ? samples : list.ToArray();
    }

    private static long PercentileTicks(long[] sortedTicks, double percentile)
    {
        if (sortedTicks.Length == 0)
            return 0;

        var position = percentile * sortedTicks.Length;
        var index = (int)Math.Ceiling(position) - 1;
        if (index < 0) index = 0;
        if (index >= sortedTicks.Length) index = sortedTicks.Length - 1;
        return sortedTicks[index];
    }

    private readonly record struct ResponseSample(DateTime TimestampUtc, long ElapsedTicks);
    private readonly record struct RecentMetrics(TimeSpan Minimum, TimeSpan Maximum, TimeSpan Average, TimeSpan P95, TimeSpan P99);
    public void GetMetricTable(out string[] tableColumns, out string[][] tableRows)
    {
        var snapshot = GetSnapshot();
        tableColumns = ["Metric", "Value"];
        tableRows =
        [
            new[] { "Total Requests", snapshot.TotalRequests.ToString() },
            new[] { "Errored Requests (5xx)", snapshot.ErrorRequests.ToString() },
            new[] { "Average Response Time (All Time)", $"{snapshot.AverageResponseTime.TotalMilliseconds:F2} ms" },
            new[] { "Minimum Response Time (Last 5m)", $"{snapshot.RecentMinimumResponseTime.TotalMilliseconds:F2} ms" },
            new[] { "Maximum Response Time (Last 5m)", $"{snapshot.RecentMaximumResponseTime.TotalMilliseconds:F2} ms" },
            new[] { "Average Response Time (Last 5m)", $"{snapshot.RecentAverageResponseTime.TotalMilliseconds:F2} ms" },
            new[] { "95th Percentile Response Time (Last 5m)", $"{snapshot.RecentP95ResponseTime.TotalMilliseconds:F2} ms" },
            new[] { "99th Percentile Response Time (Last 5m)", $"{snapshot.RecentP99ResponseTime.TotalMilliseconds:F2} ms" },
            new[] { "Average Response Time (Last 10s)", $"{snapshot.Recent10sAverageResponseTime.TotalMilliseconds:F2} ms" },
            new[] { "Pages Served 2xx", snapshot.Requests2xx.ToString() },
            new[] { "Pages Served 4xx", snapshot.Requests4xx.ToString() },
            new[] { "Pages Served 5xx", snapshot.Requests5xx.ToString() },
            new[] { "Pages Served Other", snapshot.RequestsOther.ToString() },
            new[] { "Pages Throttled (429)", snapshot.ThrottledRequests.ToString() }
        ];
    }
}

public readonly record struct MetricsSnapshot(
    long TotalRequests,
    long ErrorRequests,
    TimeSpan AverageResponseTime,
    TimeSpan RecentMinimumResponseTime,
    TimeSpan RecentMaximumResponseTime,
    TimeSpan RecentAverageResponseTime,
    TimeSpan RecentP95ResponseTime,
    TimeSpan RecentP99ResponseTime,
    TimeSpan Recent10sAverageResponseTime,
    long Requests2xx,
    long Requests4xx,
    long Requests5xx,
    long RequestsOther,
    long ThrottledRequests
);
