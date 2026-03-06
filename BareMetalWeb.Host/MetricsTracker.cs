using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using BareMetalWeb.Interfaces;
#if NET7_0_OR_GREATER
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
#endif

namespace BareMetalWeb.Host;

public sealed class MetricsTracker : IMetricsTracker, IDisposable
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
    private readonly Process _currentProcess = Process.GetCurrentProcess();

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

        _currentProcess.Refresh();

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
            throttled,
            _currentProcess.Id,
            _currentProcess.WorkingSet64,
            _currentProcess.VirtualMemorySize64,
            DateTime.UtcNow - _currentProcess.StartTime.ToUniversalTime()
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

        // Rent a buffer from ArrayPool to avoid allocating a new long[] on every snapshot call.
        var pool = ArrayPool<long>.Shared;
        long[] ticks = pool.Rent(samples.Length);
        try
        {
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

            Array.Sort(ticks, 0, samples.Length);
            var p95 = PercentileTicks(ticks, samples.Length, 0.95);
            var p99 = PercentileTicks(ticks, samples.Length, 0.99);

            var avgTicks = totalTicks / samples.Length;
            return new RecentMetrics(
                TimeSpan.FromTicks(minTicks),
                TimeSpan.FromTicks(maxTicks),
                TimeSpan.FromTicks(avgTicks),
                TimeSpan.FromTicks(p95),
                TimeSpan.FromTicks(p99)
            );
        }
        finally
        {
            pool.Return(ticks);
        }
    }

    private static ResponseSample[] FilterRecentSamples(ResponseSample[] samples, DateTime cutoffUtc)
    {
        if (samples.Length == 0)
            return Array.Empty<ResponseSample>();

        // Count matches first so the output array is exactly sized (avoids List<T> overhead).
        int matchCount = 0;
        for (int i = 0; i < samples.Length; i++)
        {
            if (samples[i].TimestampUtc >= cutoffUtc)
                matchCount++;
        }

        if (matchCount == samples.Length) return samples;
        if (matchCount == 0) return Array.Empty<ResponseSample>();

        var result = new ResponseSample[matchCount];
        int j = 0;
        for (int i = 0; i < samples.Length; i++)
        {
            if (samples[i].TimestampUtc >= cutoffUtc)
                result[j++] = samples[i];
        }
        return result;
    }

    private static long PercentileTicks(long[] sortedTicks, int count, double percentile)
    {
        if (count == 0)
            return 0;

        var position = percentile * count;
        var index = (int)Math.Ceiling(position) - 1;
        if (index < 0) index = 0;
        if (index >= count) index = count - 1;
        return sortedTicks[index];
    }

    public void Dispose() => _currentProcess.Dispose();

    private readonly record struct ResponseSample(DateTime TimestampUtc, long ElapsedTicks);
    private readonly record struct RecentMetrics(TimeSpan Minimum, TimeSpan Maximum, TimeSpan Average, TimeSpan P95, TimeSpan P99);
    public void GetMetricTable(out string[] tableColumns, out string[][] tableRows)
    {
        var snapshot = GetSnapshot();
        tableColumns = ["Metric", "Value"];
        tableRows =
        [
            new[] { "📊 REQUEST STATISTICS", "" },
            new[] { "Total Requests", snapshot.TotalRequests.ToString("N0") },
            new[] { "Errored Requests (5xx)", snapshot.ErrorRequests.ToString("N0") },

            new[] { "⏱️ RESPONSE TIMES", "" },
            new[] { "Average (All Time)", $"{snapshot.AverageResponseTime.TotalMilliseconds:F2} ms" },
            new[] { "Minimum (Last 5m)", $"{snapshot.RecentMinimumResponseTime.TotalMilliseconds:F2} ms" },
            new[] { "Maximum (Last 5m)", $"{snapshot.RecentMaximumResponseTime.TotalMilliseconds:F2} ms" },
            new[] { "Average (Last 5m)", $"{snapshot.RecentAverageResponseTime.TotalMilliseconds:F2} ms" },
            new[] { "P95 (Last 5m)", $"{snapshot.RecentP95ResponseTime.TotalMilliseconds:F2} ms" },
            new[] { "P99 (Last 5m)", $"{snapshot.RecentP99ResponseTime.TotalMilliseconds:F2} ms" },
            new[] { "Average (Last 10s)", $"{snapshot.Recent10sAverageResponseTime.TotalMilliseconds:F2} ms" },

            new[] { "📈 STATUS CODES", "" },
            new[] { "2xx Success", snapshot.Requests2xx.ToString("N0") },
            new[] { "4xx Client Error", snapshot.Requests4xx.ToString("N0") },
            new[] { "5xx Server Error", snapshot.Requests5xx.ToString("N0") },
            new[] { "Other", snapshot.RequestsOther.ToString("N0") },
            new[] { "429 Throttled", snapshot.ThrottledRequests.ToString("N0") },

            new[] { "💻 MEMORY & PROCESS", "" },
            new[] { "Process ID (PID)", snapshot.ProcessId.ToString() },
            new[] { "Uptime", FormatUptime(snapshot.ProcessUptime) },
            new[] { "Working Set", FormatSizeBytes(snapshot.WorkingSet64) },
            new[] { "Virtual Memory", FormatSizeBytes(snapshot.VirtualMemorySize64) },

            new[] { "🖥️ ENVIRONMENT", "" },
            new[] { "Operating System", RuntimeInformation.OSDescription },
            new[] { "OS Architecture", RuntimeInformation.OSArchitecture.ToString() },
            new[] { "Process Architecture", RuntimeInformation.ProcessArchitecture.ToString() },
            new[] { "Processor Count", Environment.ProcessorCount.ToString() },
            new[] { "CPU", GetCpuModel() },
            new[] { ".NET Runtime", RuntimeInformation.FrameworkDescription },
            new[] { "Data Location", DataRoot ?? "(default)" },

            new[] { "⚡ SIMD & VECTOR", "" },
            new[] { "SIMD Vector Width", $"{System.Numerics.Vector<float>.Count * 4 * 8}-bit ({System.Numerics.Vector<float>.Count} floats)" },

            new[] { "🚀 ACTIVE ACCELERATION PATHS", "" },
            new[] { "Vector Distance (ANN)", DataLayerCapabilities.VectorDistancePath },
            new[] { "CRC-32C Checksum", DataLayerCapabilities.Crc32CPath },
            new[] { "Key Comparison", DataLayerCapabilities.KeyComparisonPath },

            new[] { "🔧 AVAILABLE CPU FEATURES", "" },
            .. GetSimdFeatureRows()
        ];
    }

    /// <summary>Data root directory — set once at startup from configuration.</summary>
    public static string? DataRoot { get; set; }

    private static string FormatUptime(TimeSpan uptime)
    {
        if (uptime.TotalDays >= 1)
            return $"{(int)uptime.TotalDays}d {uptime.Hours:D2}h {uptime.Minutes:D2}m {uptime.Seconds:D2}s";
        if (uptime.TotalHours >= 1)
            return $"{uptime.Hours:D2}h {uptime.Minutes:D2}m {uptime.Seconds:D2}s";
        return $"{uptime.Minutes:D2}m {uptime.Seconds:D2}s";
    }

    private static string FormatSizeBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double size = bytes;
        int unitIndex = 0;
        while (size >= 1024 && unitIndex < units.Length - 1)
        {
            size /= 1024;
            unitIndex++;
        }
        return unitIndex == 0
            ? $"{size:N0} {units[unitIndex]}"
            : $"{size:N2} {units[unitIndex]}";
    }

    private static string GetCpuModel()
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) && File.Exists("/proc/cpuinfo"))
            {
                foreach (var line in File.ReadLines("/proc/cpuinfo"))
                {
                    if (line.StartsWith("model name", StringComparison.OrdinalIgnoreCase) ||
                        line.StartsWith("Model", StringComparison.OrdinalIgnoreCase) ||
                        line.StartsWith("Hardware", StringComparison.OrdinalIgnoreCase))
                    {
                        var colonIdx = line.IndexOf(':');
                        if (colonIdx >= 0)
                            return line[(colonIdx + 1)..].Trim();
                    }
                }
            }
        }
        catch { /* /proc/cpuinfo not readable */ }

        return RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.Arm64 => "ARM (AArch64)",
            Architecture.Arm => "ARM (32-bit)",
            Architecture.X64 => "x86-64",
            Architecture.X86 => "x86",
            _ => RuntimeInformation.ProcessArchitecture.ToString()
        };
    }

    private static string[][] GetSimdFeatureRows()
    {
        var features = new List<string[]>();
#if NET7_0_OR_GREATER
        if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
        {
            features.Add(new[] { "ARM AdvSimd (NEON)", AdvSimd.IsSupported ? "✓" : "✗" });
            features.Add(new[] { "ARM AdvSimd.Arm64", AdvSimd.Arm64.IsSupported ? "✓" : "✗" });
            features.Add(new[] { "ARM Aes", System.Runtime.Intrinsics.Arm.Aes.IsSupported ? "✓" : "✗" });
            features.Add(new[] { "ARM Crc32", Crc32.IsSupported ? "✓" : "✗" });
            features.Add(new[] { "ARM Crc32.Arm64", Crc32.Arm64.IsSupported ? "✓" : "✗" });
            features.Add(new[] { "ARM Dp", Dp.IsSupported ? "✓" : "✗" });
            features.Add(new[] { "ARM Sha256", Sha256.IsSupported ? "✓" : "✗" });
        }
        else
        {
            features.Add(new[] { "x86 SSE2", Sse2.IsSupported ? "✓" : "✗" });
            features.Add(new[] { "x86 SSE4.2", Sse42.IsSupported ? "✓" : "✗" });
            features.Add(new[] { "x86 AVX", Avx.IsSupported ? "✓" : "✗" });
            features.Add(new[] { "x86 AVX2", Avx2.IsSupported ? "✓" : "✗" });
            features.Add(new[] { "x86 AVX-512F", Avx512F.IsSupported ? "✓" : "✗" });
            features.Add(new[] { "x86 FMA", Fma.IsSupported ? "✓" : "✗" });
            features.Add(new[] { "x86 BMI1", Bmi1.IsSupported ? "✓" : "✗" });
            features.Add(new[] { "x86 BMI2", Bmi2.IsSupported ? "✓" : "✗" });
            features.Add(new[] { "x86 POPCNT", Popcnt.IsSupported ? "✓" : "✗" });
            features.Add(new[] { "x86 LZCNT", Lzcnt.IsSupported ? "✓" : "✗" });
        }
#endif
        return features.ToArray();
    }
}
