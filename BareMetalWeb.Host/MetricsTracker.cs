using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;

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
    private long _requestsInFlight;

    private long _routeDispatchTicks;
    private long _routeDispatchCount;
    private long _walReadTicks;
    private long _walReadCount;
    private long _uiRenderTicks;
    private long _uiRenderCount;
    private long _serializationTicks;
    private long _serializationCount;
    private long _gcPauseTicks;
    private long _gcPauseCount;

    // ── Last-observed (this call) ticks — written with Volatile ──
    private long _routeDispatchLastTicks;
    private long _walReadLastTicks;
    private long _uiRenderLastTicks;
    private long _serializationLastTicks;

    private readonly object _recentLock = new();
    private readonly Queue<ResponseSample> _recentSamples = new();
    // ── Rolling 5-minute windows per subsystem (guarded by _recentLock) ──
    // Running totals kept alongside each queue so ComputeSubsystemRecent is O(1) with no iteration.
    private readonly Queue<SubsystemSample> _recentRouteDispatch = new();
    private long _recentRouteDispatchTotalTicks;
    private readonly Queue<SubsystemSample> _recentWalRead = new();
    private long _recentWalReadTotalTicks;
    private readonly Queue<SubsystemSample> _recentUiRender = new();
    private long _recentUiRenderTotalTicks;
    private readonly Queue<SubsystemSample> _recentSerialization = new();
    private long _recentSerializationTotalTicks;
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

    public void RecordRouteDispatch(TimeSpan elapsed)
    {
        Interlocked.Increment(ref _routeDispatchCount);
        Interlocked.Add(ref _routeDispatchTicks, elapsed.Ticks);
        Volatile.Write(ref _routeDispatchLastTicks, elapsed.Ticks);
        var now = DateTime.UtcNow;
        lock (_recentLock)
        {
            _recentRouteDispatch.Enqueue(new SubsystemSample(now, elapsed.Ticks));
            _recentRouteDispatchTotalTicks += elapsed.Ticks;
            PruneQueue(_recentRouteDispatch, ref _recentRouteDispatchTotalTicks, now - RecentWindow);
        }
    }

    public void RecordWalRead(TimeSpan elapsed)
    {
        Interlocked.Increment(ref _walReadCount);
        Interlocked.Add(ref _walReadTicks, elapsed.Ticks);
        Volatile.Write(ref _walReadLastTicks, elapsed.Ticks);
        var now = DateTime.UtcNow;
        lock (_recentLock)
        {
            _recentWalRead.Enqueue(new SubsystemSample(now, elapsed.Ticks));
            _recentWalReadTotalTicks += elapsed.Ticks;
            PruneQueue(_recentWalRead, ref _recentWalReadTotalTicks, now - RecentWindow);
        }
    }

    public void RecordUiRender(TimeSpan elapsed)
    {
        Interlocked.Increment(ref _uiRenderCount);
        Interlocked.Add(ref _uiRenderTicks, elapsed.Ticks);
        Volatile.Write(ref _uiRenderLastTicks, elapsed.Ticks);
        var now = DateTime.UtcNow;
        lock (_recentLock)
        {
            _recentUiRender.Enqueue(new SubsystemSample(now, elapsed.Ticks));
            _recentUiRenderTotalTicks += elapsed.Ticks;
            PruneQueue(_recentUiRender, ref _recentUiRenderTotalTicks, now - RecentWindow);
        }
    }

    public void RecordSerialization(TimeSpan elapsed)
    {
        Interlocked.Increment(ref _serializationCount);
        Interlocked.Add(ref _serializationTicks, elapsed.Ticks);
        Volatile.Write(ref _serializationLastTicks, elapsed.Ticks);
        var now = DateTime.UtcNow;
        lock (_recentLock)
        {
            _recentSerialization.Enqueue(new SubsystemSample(now, elapsed.Ticks));
            _recentSerializationTotalTicks += elapsed.Ticks;
            PruneQueue(_recentSerialization, ref _recentSerializationTotalTicks, now - RecentWindow);
        }
    }

    public void RecordGcPause(TimeSpan elapsed)
    {
        Interlocked.Increment(ref _gcPauseCount);
        Interlocked.Add(ref _gcPauseTicks, elapsed.Ticks);
    }

    public void EnterRequest() => Interlocked.Increment(ref _requestsInFlight);
    public void LeaveRequest() => Interlocked.Decrement(ref _requestsInFlight);

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
        long rdRecentCount, wrRecentCount, uiRecentCount, serRecentCount;
        TimeSpan rdRecentAvg, wrRecentAvg, uiRecentAvg, serRecentAvg;
        lock (_recentLock)
        {
            PruneOldSamples(nowUtc);
            recentSamples = _recentSamples.ToArray();
            rdRecentCount = _recentRouteDispatch.Count;
            rdRecentAvg = rdRecentCount == 0 ? TimeSpan.Zero : TimeSpan.FromTicks(_recentRouteDispatchTotalTicks / rdRecentCount);
            wrRecentCount = _recentWalRead.Count;
            wrRecentAvg = wrRecentCount == 0 ? TimeSpan.Zero : TimeSpan.FromTicks(_recentWalReadTotalTicks / wrRecentCount);
            uiRecentCount = _recentUiRender.Count;
            uiRecentAvg = uiRecentCount == 0 ? TimeSpan.Zero : TimeSpan.FromTicks(_recentUiRenderTotalTicks / uiRecentCount);
            serRecentCount = _recentSerialization.Count;
            serRecentAvg = serRecentCount == 0 ? TimeSpan.Zero : TimeSpan.FromTicks(_recentSerializationTotalTicks / serRecentCount);
        }

        var recentMetrics = ComputeRecentMetrics(recentSamples);
        var recent10s = ComputeRecentMetrics(FilterRecentSamples(recentSamples, nowUtc - RecentShortWindow));

        var routeDispatchCount = Interlocked.Read(ref _routeDispatchCount);
        var routeDispatchAvg = routeDispatchCount == 0 ? TimeSpan.Zero : TimeSpan.FromTicks(Interlocked.Read(ref _routeDispatchTicks) / routeDispatchCount);
        var walReadCount = Interlocked.Read(ref _walReadCount);
        var walReadAvg = walReadCount == 0 ? TimeSpan.Zero : TimeSpan.FromTicks(Interlocked.Read(ref _walReadTicks) / walReadCount);
        var uiRenderCount = Interlocked.Read(ref _uiRenderCount);
        var uiRenderAvg = uiRenderCount == 0 ? TimeSpan.Zero : TimeSpan.FromTicks(Interlocked.Read(ref _uiRenderTicks) / uiRenderCount);
        var serializationCount = Interlocked.Read(ref _serializationCount);
        var serializationAvg = serializationCount == 0 ? TimeSpan.Zero : TimeSpan.FromTicks(Interlocked.Read(ref _serializationTicks) / serializationCount);
        var rdLast = TimeSpan.FromTicks(Volatile.Read(ref _routeDispatchLastTicks));
        var wrLast = TimeSpan.FromTicks(Volatile.Read(ref _walReadLastTicks));
        var uiLast = TimeSpan.FromTicks(Volatile.Read(ref _uiRenderLastTicks));
        var serLast = TimeSpan.FromTicks(Volatile.Read(ref _serializationLastTicks));
        var gcGen0 = GC.CollectionCount(0);
        var gcGen1 = GC.CollectionCount(1);
        var gcGen2 = GC.CollectionCount(2);
        var gcAllocated = GC.GetTotalAllocatedBytes(precise: false);

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
            Interlocked.Read(ref _requestsInFlight),
            _currentProcess.Id,
            _currentProcess.WorkingSet64,
            _currentProcess.VirtualMemorySize64,
            DateTime.UtcNow - _currentProcess.StartTime.ToUniversalTime(),
            routeDispatchCount, routeDispatchAvg,
            walReadCount, walReadAvg,
            uiRenderCount, uiRenderAvg,
            serializationCount, serializationAvg,
            rdRecentCount, rdRecentAvg,
            wrRecentCount, wrRecentAvg,
            uiRecentCount, uiRecentAvg,
            serRecentCount, serRecentAvg,
            rdLast, wrLast, uiLast, serLast,
            gcGen0, gcGen1, gcGen2, gcAllocated
        );
    }

    private void PruneOldSamples(DateTime nowUtc)
    {
        var cutoff = nowUtc - RecentWindow;
        while (_recentSamples.Count > 0 && _recentSamples.Peek().TimestampUtc < cutoff)
            _recentSamples.Dequeue();
        PruneQueue(_recentRouteDispatch, ref _recentRouteDispatchTotalTicks, cutoff);
        PruneQueue(_recentWalRead, ref _recentWalReadTotalTicks, cutoff);
        PruneQueue(_recentUiRender, ref _recentUiRenderTotalTicks, cutoff);
        PruneQueue(_recentSerialization, ref _recentSerializationTotalTicks, cutoff);
    }

    private static void PruneQueue(Queue<SubsystemSample> queue, ref long runningTotal, DateTime cutoff)
    {
        while (queue.Count > 0 && queue.Peek().TimestampUtc < cutoff)
            runningTotal -= queue.Dequeue().ElapsedTicks;
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
    private readonly record struct SubsystemSample(DateTime TimestampUtc, long ElapsedTicks);
    private readonly record struct RecentMetrics(TimeSpan Minimum, TimeSpan Maximum, TimeSpan Average, TimeSpan P95, TimeSpan P99);
    public void GetMetricTable(out string[] tableColumns, out string[][] tableRows)
    {
        var snapshot = GetSnapshot();
        var responseTiming = ResponseTimingMetrics.GetSnapshot();
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
            new[] { "🔬 RESPONSE WRITE STAGES (Last 5m)", "" },
            new[] { "Samples", responseTiming.SampleCount.ToString("N0") },
            new[] { "Parse→First Write (avg/p95/max)", $"{responseTiming.ParseToFirst.Average.TotalMilliseconds:F3} / {responseTiming.ParseToFirst.P95.TotalMilliseconds:F3} / {responseTiming.ParseToFirst.Max.TotalMilliseconds:F3} ms" },
            new[] { "First Write→Flush Start (avg/p95/max)", $"{responseTiming.FirstToFlushStart.Average.TotalMilliseconds:F3} / {responseTiming.FirstToFlushStart.P95.TotalMilliseconds:F3} / {responseTiming.FirstToFlushStart.Max.TotalMilliseconds:F3} ms" },
            new[] { "Flush Await (avg/p95/max)", $"{responseTiming.FlushAwait.Average.TotalMilliseconds:F3} / {responseTiming.FlushAwait.P95.TotalMilliseconds:F3} / {responseTiming.FlushAwait.Max.TotalMilliseconds:F3} ms" },
            new[] { "First Write→Flush Complete (avg/p95/max)", $"{responseTiming.FirstToFlush.Average.TotalMilliseconds:F3} / {responseTiming.FirstToFlush.P95.TotalMilliseconds:F3} / {responseTiming.FirstToFlush.Max.TotalMilliseconds:F3} ms" },

            new[] { "📈 STATUS CODES", "" },
            new[] { "2xx Success", snapshot.Requests2xx.ToString("N0") },
            new[] { "4xx Client Error", snapshot.Requests4xx.ToString("N0") },
            new[] { "5xx Server Error", snapshot.Requests5xx.ToString("N0") },
            new[] { "Other", snapshot.RequestsOther.ToString("N0") },
            new[] { "429 Throttled", snapshot.ThrottledRequests.ToString("N0") },

            new[] { "⏰ SUBSYSTEM TIMERS", "" },
            new[] { "Route Dispatch (since start)", $"{snapshot.RouteDispatchAverage.TotalMicroseconds:F1} µs ({snapshot.RouteDispatchCount:N0} calls)" },
            new[] { "Route Dispatch (last 5m)", $"{snapshot.RouteDispatchRecentAverage.TotalMicroseconds:F1} µs ({snapshot.RouteDispatchRecentCount:N0} calls)" },
            new[] { "Route Dispatch (last call)", $"{snapshot.RouteDispatchLast.TotalMicroseconds:F1} µs" },
            new[] { "WAL Read (since start)", $"{snapshot.WalReadAverage.TotalMicroseconds:F1} µs ({snapshot.WalReadCount:N0} calls)" },
            new[] { "WAL Read (last 5m)", $"{snapshot.WalReadRecentAverage.TotalMicroseconds:F1} µs ({snapshot.WalReadRecentCount:N0} calls)" },
            new[] { "WAL Read (last call)", $"{snapshot.WalReadLast.TotalMicroseconds:F1} µs" },
            new[] { "UI Render (since start)", $"{snapshot.UiRenderAverage.TotalMilliseconds:F2} ms ({snapshot.UiRenderCount:N0} calls)" },
            new[] { "UI Render (last 5m)", $"{snapshot.UiRenderRecentAverage.TotalMilliseconds:F2} ms ({snapshot.UiRenderRecentCount:N0} calls)" },
            new[] { "UI Render (last call)", $"{snapshot.UiRenderLast.TotalMilliseconds:F2} ms" },
            new[] { "Serialization (since start)", $"{snapshot.SerializationAverage.TotalMicroseconds:F1} µs ({snapshot.SerializationCount:N0} calls)" },
            new[] { "Serialization (last 5m)", $"{snapshot.SerializationRecentAverage.TotalMicroseconds:F1} µs ({snapshot.SerializationRecentCount:N0} calls)" },
            new[] { "Serialization (last call)", $"{snapshot.SerializationLast.TotalMicroseconds:F1} µs" },

            new[] { "🗑️ GC STATISTICS", "" },
            new[] { "Gen0 Collections", snapshot.GcGen0Collections.ToString("N0") },
            new[] { "Gen1 Collections", snapshot.GcGen1Collections.ToString("N0") },
            new[] { "Gen2 Collections", snapshot.GcGen2Collections.ToString("N0") },
            new[] { "Total Allocated", FormatSizeBytes(snapshot.GcTotalAllocatedBytes) },

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
            new[] { "SIMD Vector Width", $"{SimdCapabilities.Current.VectorBitWidth}-bit ({SimdCapabilities.Current.FloatVectorWidth} floats)" },

            new[] { "🚀 ACTIVE ACCELERATION PATHS", "" },
            new[] { "Vector Distance (ANN)", DataLayerCapabilities.VectorDistancePath },
            new[] { "CRC-32C Checksum", DataLayerCapabilities.Crc32CPath },
            new[] { "Key Comparison", DataLayerCapabilities.KeyComparisonPath },

            new[] { "🔧 AVAILABLE CPU FEATURES", "" },
            .. GetSimdFeatureRows(),

            .. GetClusterRows()
        ];
    }

    private static string[][] GetClusterRows()
    {
        var state = ClusterState;
        if (state == null)
            return [];

        var snapshot = state.GetSnapshot();
        var roleLabel = snapshot.Role == BareMetalWeb.Data.ClusterRole.Leader
            ? "👑 Leader"
            : "🔄 Follower";
        var leaseLabel = snapshot.IsLeaseValid ? "✓ Valid" : "✗ Expired";

        return
        [
            new[] { "🏆 CLUSTER / LEASE", "" },
            new[] { "Instance Name", snapshot.InstanceId },
            new[] { "Role", roleLabel },
            new[] { "Lease Valid", leaseLabel },
            new[] { "Epoch", snapshot.Epoch.ToString("N0") },
            new[] { "Last LSN", snapshot.LastLsn.ToString("N0") },
        ];
    }

    /// <summary>Data root directory — set once at startup from configuration.</summary>
    public static string? DataRoot { get; set; }

    /// <summary>Cluster state reference — set once at startup. Null on single-instance deployments.</summary>
    public static BareMetalWeb.Data.ClusterState? ClusterState { get; set; }

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
        var caps = SimdCapabilities.Current;
        var features = new List<string[]>();
        if (RuntimeInformation.ProcessArchitecture == Architecture.Arm64)
        {
            features.Add(new[] { "ARM AdvSimd (NEON)", caps.AdvSimd ? "✓" : "✗" });
            features.Add(new[] { "ARM AdvSimd.Arm64", caps.AdvSimdArm64 ? "✓" : "✗" });
            features.Add(new[] { "ARM Aes", caps.ArmAes ? "✓" : "✗" });
            features.Add(new[] { "ARM Crc32", caps.ArmCrc32 ? "✓" : "✗" });
            features.Add(new[] { "ARM Crc32.Arm64", caps.ArmCrc32Arm64 ? "✓" : "✗" });
            features.Add(new[] { "ARM Dp", caps.ArmDp ? "✓" : "✗" });
            features.Add(new[] { "ARM Sha256", caps.ArmSha256 ? "✓" : "✗" });
        }
        else
        {
            features.Add(new[] { "x86 SSE2", caps.Sse2 ? "✓" : "✗" });
            features.Add(new[] { "x86 SSE4.2", caps.Sse42 ? "✓" : "✗" });
            features.Add(new[] { "x86 AVX", caps.Avx ? "✓" : "✗" });
            features.Add(new[] { "x86 AVX2", caps.Avx2 ? "✓" : "✗" });
            features.Add(new[] { "x86 AVX-512F", caps.Avx512F ? "✓" : "✗" });
            features.Add(new[] { "x86 FMA", caps.Fma ? "✓" : "✗" });
            features.Add(new[] { "x86 BMI1", caps.Bmi1 ? "✓" : "✗" });
            features.Add(new[] { "x86 BMI2", caps.Bmi2 ? "✓" : "✗" });
            features.Add(new[] { "x86 POPCNT", caps.Popcnt ? "✓" : "✗" });
            features.Add(new[] { "x86 LZCNT", caps.Lzcnt ? "✓" : "✗" });
            foreach (var warning in caps.GetMismatchWarnings())
                features.Add(new[] { "⚠ Config mismatch", warning });
        }
        return features.ToArray();
    }

    /// <summary>
    /// Renders metrics as grouped Bootstrap cards, each containing a compact sub-table.
    /// One card per logical group instead of one row per metric.
    /// </summary>
    public string GetMetricGroupsHtml()
    {
        GetMetricTable(out _, out string[][] allRows);

        var sb = new System.Text.StringBuilder(4096);
        sb.Append("<div class=\"row g-3\">");

        string? currentGroup = null;
        var groupRows = new List<string[]>();

        for (int i = 0; i <= allRows.Length; i++)
        {
            bool isHeader = i < allRows.Length && allRows[i].Length >= 2 && allRows[i][1] == "";
            bool isEnd = i == allRows.Length;

            if ((isHeader || isEnd) && currentGroup != null && groupRows.Count > 0)
            {
                sb.Append("<div class=\"col-12 col-lg-6\">");
                sb.Append("<div class=\"card shadow-sm h-100\">");
                sb.Append("<div class=\"card-header fw-semibold\">");
                sb.Append(System.Net.WebUtility.HtmlEncode(currentGroup));
                sb.Append("</div>");
                sb.Append("<div class=\"card-body p-0\">");
                sb.Append("<table class=\"table table-sm table-striped align-middle mb-0\">");
                sb.Append("<tbody>");
                foreach (var row in groupRows)
                {
                    sb.Append("<tr><td class=\"ps-3\">");
                    sb.Append(System.Net.WebUtility.HtmlEncode(row[0]));
                    sb.Append("</td><td class=\"text-end pe-3 text-nowrap\">");
                    sb.Append(System.Net.WebUtility.HtmlEncode(row[1]));
                    sb.Append("</td></tr>");
                }
                sb.Append("</tbody></table>");
                sb.Append("</div></div></div>");
                groupRows.Clear();
            }

            if (isHeader)
                currentGroup = allRows[i][0];
            else if (!isEnd)
                groupRows.Add(allRows[i]);
        }

        sb.Append("</div>");
        return sb.ToString();
    }
}
