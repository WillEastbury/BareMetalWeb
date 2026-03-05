using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace BareMetalWeb.Host.Tests;

public class MetricsTrackerTests
{
    [Fact]
    public void GetSnapshot_NoRequests_ReturnsZeroes()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(0, snapshot.TotalRequests);
        Assert.Equal(0, snapshot.ErrorRequests);
        Assert.Equal(TimeSpan.Zero, snapshot.AverageResponseTime);
        Assert.Equal(0, snapshot.Requests2xx);
        Assert.Equal(0, snapshot.Requests4xx);
        Assert.Equal(0, snapshot.Requests5xx);
        Assert.Equal(0, snapshot.RequestsOther);
        Assert.Equal(0, snapshot.ThrottledRequests);
    }

    [Fact]
    public void RecordRequest_SingleRequest_IncrementsTotal()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(50));
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(1, snapshot.TotalRequests);
    }

    [Fact]
    public void RecordRequest_MultipleRequests_CountsCorrectly()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(10));
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(20));
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(30));
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(3, snapshot.TotalRequests);
    }

    [Fact]
    public void RecordRequest_AverageResponseTime_ComputedCorrectly()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(100));
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(200));
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(TimeSpan.FromMilliseconds(150), snapshot.AverageResponseTime);
    }

    [Fact]
    public void RecordRequest_2xxStatusCodes_Tracked()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(1));
        tracker.RecordRequest(201, TimeSpan.FromMilliseconds(1));
        tracker.RecordRequest(204, TimeSpan.FromMilliseconds(1));
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(3, snapshot.Requests2xx);
        Assert.Equal(0, snapshot.ErrorRequests);
    }

    [Fact]
    public void RecordRequest_4xxStatusCodes_Tracked()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordRequest(400, TimeSpan.FromMilliseconds(1));
        tracker.RecordRequest(404, TimeSpan.FromMilliseconds(1));
        tracker.RecordRequest(499, TimeSpan.FromMilliseconds(1));
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(3, snapshot.Requests4xx);
        Assert.Equal(0, snapshot.ErrorRequests);
    }

    [Fact]
    public void RecordRequest_5xxStatusCodes_TrackedAsErrors()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordRequest(500, TimeSpan.FromMilliseconds(1));
        tracker.RecordRequest(502, TimeSpan.FromMilliseconds(1));
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(2, snapshot.Requests5xx);
        Assert.Equal(2, snapshot.ErrorRequests);
    }

    [Fact]
    public void RecordRequest_OtherStatusCodes_Tracked()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordRequest(100, TimeSpan.FromMilliseconds(1));
        tracker.RecordRequest(301, TimeSpan.FromMilliseconds(1));
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(2, snapshot.RequestsOther);
    }

    [Fact]
    public void RecordRequest_MixedStatusCodes_CategorizedCorrectly()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(1));
        tracker.RecordRequest(404, TimeSpan.FromMilliseconds(1));
        tracker.RecordRequest(500, TimeSpan.FromMilliseconds(1));
        tracker.RecordRequest(301, TimeSpan.FromMilliseconds(1));
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(4, snapshot.TotalRequests);
        Assert.Equal(1, snapshot.Requests2xx);
        Assert.Equal(1, snapshot.Requests4xx);
        Assert.Equal(1, snapshot.Requests5xx);
        Assert.Equal(1, snapshot.RequestsOther);
        Assert.Equal(1, snapshot.ErrorRequests);
    }

    [Fact]
    public void RecordThrottled_IncrementsThrottledAndTotal()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordThrottled(TimeSpan.FromMilliseconds(5));
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(1, snapshot.ThrottledRequests);
        Assert.Equal(1, snapshot.TotalRequests);
        Assert.Equal(1, snapshot.Requests4xx);
    }

    [Fact]
    public void RecordThrottled_MultipleThrottles_CountsCorrectly()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordThrottled(TimeSpan.FromMilliseconds(1));
        tracker.RecordThrottled(TimeSpan.FromMilliseconds(2));
        tracker.RecordThrottled(TimeSpan.FromMilliseconds(3));
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(3, snapshot.ThrottledRequests);
        Assert.Equal(3, snapshot.TotalRequests);
    }

    [Fact]
    public void GetSnapshot_RecentMetrics_ReflectRecentRequests()
    {
        // Arrange
        var tracker = new MetricsTracker();
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(10));
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(30));

        // Act
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(TimeSpan.FromMilliseconds(10), snapshot.RecentMinimumResponseTime);
        Assert.Equal(TimeSpan.FromMilliseconds(30), snapshot.RecentMaximumResponseTime);
        Assert.Equal(TimeSpan.FromMilliseconds(20), snapshot.RecentAverageResponseTime);
    }

    [Fact]
    public void GetSnapshot_SingleRequest_PercentilesEqualElapsed()
    {
        // Arrange
        var tracker = new MetricsTracker();
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(42));

        // Act
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(TimeSpan.FromMilliseconds(42), snapshot.RecentP95ResponseTime);
        Assert.Equal(TimeSpan.FromMilliseconds(42), snapshot.RecentP99ResponseTime);
    }

    [Fact]
    public void GetSnapshot_Recent10sAverage_ReflectsRecentRequests()
    {
        // Arrange
        var tracker = new MetricsTracker();
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(50));
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(150));

        // Act
        var snapshot = tracker.GetSnapshot();

        // Assert – both requests were just recorded so within the 10s window
        Assert.Equal(TimeSpan.FromMilliseconds(100), snapshot.Recent10sAverageResponseTime);
    }

    [Fact]
    public void GetSnapshot_CalledMultipleTimes_ReturnsCumulativeData()
    {
        // Arrange
        var tracker = new MetricsTracker();
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(10));
        var snapshot1 = tracker.GetSnapshot();

        // Act
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(30));
        var snapshot2 = tracker.GetSnapshot();

        // Assert
        Assert.Equal(1, snapshot1.TotalRequests);
        Assert.Equal(2, snapshot2.TotalRequests);
    }

    [Fact]
    public async Task ConcurrentRecording_AllRequestsCounted()
    {
        // Arrange
        var tracker = new MetricsTracker();
        int requestsPerThread = 100;
        int threadCount = 10;

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(_ =>
            Task.Run(() =>
            {
                for (int i = 0; i < requestsPerThread; i++)
                    tracker.RecordRequest(200, TimeSpan.FromMilliseconds(1));
            })).ToArray();
        await Task.WhenAll(tasks);
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(requestsPerThread * threadCount, snapshot.TotalRequests);
        Assert.Equal(requestsPerThread * threadCount, snapshot.Requests2xx);
    }

    [Fact]
    public async Task ConcurrentRecording_MixedStatusCodes_CountsCorrectly()
    {
        // Arrange
        var tracker = new MetricsTracker();
        int iterations = 50;

        // Act
        var task2xx = Task.Run(() =>
        {
            for (int i = 0; i < iterations; i++)
                tracker.RecordRequest(200, TimeSpan.FromMilliseconds(1));
        });
        var task4xx = Task.Run(() =>
        {
            for (int i = 0; i < iterations; i++)
                tracker.RecordRequest(404, TimeSpan.FromMilliseconds(1));
        });
        var task5xx = Task.Run(() =>
        {
            for (int i = 0; i < iterations; i++)
                tracker.RecordRequest(500, TimeSpan.FromMilliseconds(1));
        });
        var taskThrottled = Task.Run(() =>
        {
            for (int i = 0; i < iterations; i++)
                tracker.RecordThrottled(TimeSpan.FromMilliseconds(1));
        });
        await Task.WhenAll(task2xx, task4xx, task5xx, taskThrottled);
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(4 * iterations, snapshot.TotalRequests);
        Assert.Equal(iterations, snapshot.Requests2xx);
        Assert.Equal(iterations * 2, snapshot.Requests4xx); // 404 + 429 from throttled
        Assert.Equal(iterations, snapshot.Requests5xx);
        Assert.Equal(iterations, snapshot.ThrottledRequests);
    }

    [Fact]
    public void GetMetricTable_ReturnsCorrectStructure()
    {
        // Arrange
        var tracker = new MetricsTracker();
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(25));

        // Act
        tracker.GetMetricTable(out var columns, out var rows);

        // Assert
        Assert.Equal(2, columns.Length);
        Assert.Equal("Metric", columns[0]);
        Assert.Equal("Value", columns[1]);
        Assert.True(rows.Length >= 19, $"Expected at least 19 metric rows (got {rows.Length})");
    }

    [Fact]
    public void GetMetricTable_ContainsExpectedMetricNames()
    {
        // Arrange
        var tracker = new MetricsTracker();
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(10));
        tracker.RecordRequest(500, TimeSpan.FromMilliseconds(20));

        // Act
        tracker.GetMetricTable(out _, out var rows);
        var metricNames = rows.Select(r => r[0]).ToArray();

        // Assert
        Assert.Contains("Total Requests", metricNames);
        Assert.Contains("Errored Requests (5xx)", metricNames);
        Assert.Contains("Pages Served 2xx", metricNames);
        Assert.Contains("Pages Served 4xx", metricNames);
        Assert.Contains("Pages Served 5xx", metricNames);
        Assert.Contains("Pages Throttled (429)", metricNames);
        Assert.Contains("---- MEMORY STATS ----", metricNames);
        Assert.Contains("Process ID (PID)", metricNames);
        Assert.Contains("Working Set (bytes)", metricNames);
        Assert.Contains("Virtual Memory Size (bytes)", metricNames);
        Assert.Contains("---- CPU / SIMD ----", metricNames);
        Assert.Contains("Architecture", metricNames);
        Assert.Contains("Runtime", metricNames);
        Assert.Contains("SIMD Vector Width", metricNames);
    }

    [Fact]
    public void GetMetricTable_ValuesMatchSnapshot()
    {
        // Arrange
        var tracker = new MetricsTracker();
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(10));
        tracker.RecordRequest(500, TimeSpan.FromMilliseconds(20));

        // Act
        tracker.GetMetricTable(out _, out var rows);
        var metricDict = rows.ToDictionary(r => r[0], r => r[1]);

        // Assert
        Assert.Equal("2", metricDict["Total Requests"]);
        Assert.Equal("1", metricDict["Errored Requests (5xx)"]);
        Assert.Equal("1", metricDict["Pages Served 2xx"]);
        Assert.Equal("1", metricDict["Pages Served 5xx"]);
    }

    [Fact]
    public void RecordRequest_BoundaryStatusCodes_CategorizedCorrectly()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(1)); // low end 2xx
        tracker.RecordRequest(299, TimeSpan.FromMilliseconds(1)); // high end 2xx
        tracker.RecordRequest(400, TimeSpan.FromMilliseconds(1)); // low end 4xx
        tracker.RecordRequest(499, TimeSpan.FromMilliseconds(1)); // high end 4xx
        tracker.RecordRequest(500, TimeSpan.FromMilliseconds(1)); // low end 5xx
        tracker.RecordRequest(599, TimeSpan.FromMilliseconds(1)); // high end 5xx
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(2, snapshot.Requests2xx);
        Assert.Equal(2, snapshot.Requests4xx);
        Assert.Equal(2, snapshot.Requests5xx);
        Assert.Equal(0, snapshot.RequestsOther);
        Assert.Equal(2, snapshot.ErrorRequests);
    }

    [Fact]
    public void GetSnapshot_P95P99_DistributedRequests()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Record 100 requests with increasing elapsed times (1ms to 100ms)
        for (int i = 1; i <= 100; i++)
            tracker.RecordRequest(200, TimeSpan.FromMilliseconds(i));

        // Act
        var snapshot = tracker.GetSnapshot();

        // Assert – p95 should be the 95th value (95ms), p99 should be the 99th value (99ms)
        Assert.Equal(TimeSpan.FromMilliseconds(95), snapshot.RecentP95ResponseTime);
        Assert.Equal(TimeSpan.FromMilliseconds(99), snapshot.RecentP99ResponseTime);
    }

    [Fact]
    public async Task ConcurrentRecording_SnapshotDuringWrites_DoesNotThrow()
    {
        // Arrange
        var tracker = new MetricsTracker();
        var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));

        // Act & Assert – no exceptions during concurrent reads and writes
        var writeTask = Task.Run(() =>
        {
            while (!cts.Token.IsCancellationRequested)
                tracker.RecordRequest(200, TimeSpan.FromMilliseconds(1));
        });
        var readTask = Task.Run(() =>
        {
            while (!cts.Token.IsCancellationRequested)
            {
                var s = tracker.GetSnapshot();
                Assert.True(s.TotalRequests >= 0);
            }
        });

        await Task.WhenAll(writeTask, readTask);
    }

    [Fact]
    public void RecordRequest_TimingAccumulation_TotalElapsedTracked()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(100));
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(300));
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(200));
        var snapshot = tracker.GetSnapshot();

        // Assert – average = (100+300+200)/3 = 200ms
        Assert.Equal(TimeSpan.FromMilliseconds(200), snapshot.AverageResponseTime);
        Assert.Equal(3, snapshot.TotalRequests);
    }

    [Fact]
    public void GetSnapshot_NoRequests_RecentMetricsAreZero()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(TimeSpan.Zero, snapshot.RecentMinimumResponseTime);
        Assert.Equal(TimeSpan.Zero, snapshot.RecentMaximumResponseTime);
        Assert.Equal(TimeSpan.Zero, snapshot.RecentAverageResponseTime);
        Assert.Equal(TimeSpan.Zero, snapshot.RecentP95ResponseTime);
        Assert.Equal(TimeSpan.Zero, snapshot.RecentP99ResponseTime);
        Assert.Equal(TimeSpan.Zero, snapshot.Recent10sAverageResponseTime);
    }

    [Fact]
    public void GetSnapshot_SnapshotIsImmutable_NotAffectedByLaterRecords()
    {
        // Arrange
        var tracker = new MetricsTracker();
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(10));

        // Act
        var snapshot1 = tracker.GetSnapshot();
        tracker.RecordRequest(500, TimeSpan.FromMilliseconds(90));
        var snapshot2 = tracker.GetSnapshot();

        // Assert – first snapshot unaffected
        Assert.Equal(1, snapshot1.TotalRequests);
        Assert.Equal(0, snapshot1.ErrorRequests);
        Assert.Equal(2, snapshot2.TotalRequests);
        Assert.Equal(1, snapshot2.ErrorRequests);
    }

    [Fact]
    public void RecordThrottled_ContributesToTiming()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordThrottled(TimeSpan.FromMilliseconds(100));
        tracker.RecordThrottled(TimeSpan.FromMilliseconds(200));
        var snapshot = tracker.GetSnapshot();

        // Assert – average = (100+200)/2 = 150ms
        Assert.Equal(TimeSpan.FromMilliseconds(150), snapshot.AverageResponseTime);
        Assert.Equal(2, snapshot.ThrottledRequests);
    }

    [Fact]
    public void RecordRequest_4xxNotCountedAsErrors()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordRequest(400, TimeSpan.FromMilliseconds(1));
        tracker.RecordRequest(404, TimeSpan.FromMilliseconds(1));
        tracker.RecordRequest(429, TimeSpan.FromMilliseconds(1));
        var snapshot = tracker.GetSnapshot();

        // Assert – 4xx are not errors
        Assert.Equal(3, snapshot.Requests4xx);
        Assert.Equal(0, snapshot.ErrorRequests);
    }

    [Fact]
    public void GetSnapshot_P95P99_IdenticalValues_ReturnsSameValue()
    {
        // Arrange
        var tracker = new MetricsTracker();
        for (int i = 0; i < 20; i++)
            tracker.RecordRequest(200, TimeSpan.FromMilliseconds(50));

        // Act
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(TimeSpan.FromMilliseconds(50), snapshot.RecentP95ResponseTime);
        Assert.Equal(TimeSpan.FromMilliseconds(50), snapshot.RecentP99ResponseTime);
        Assert.Equal(TimeSpan.FromMilliseconds(50), snapshot.RecentMinimumResponseTime);
        Assert.Equal(TimeSpan.FromMilliseconds(50), snapshot.RecentMaximumResponseTime);
    }

    [Fact]
    public void GetMetricTable_NoRequests_ReturnsZeroValues()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.GetMetricTable(out var columns, out var rows);
        var metricDict = rows.ToDictionary(r => r[0], r => r[1]);

        // Assert
        Assert.Equal(2, columns.Length);
        Assert.True(rows.Length >= 19, $"Expected at least 19 metric rows (got {rows.Length})");
        Assert.Equal("0", metricDict["Total Requests"]);
        Assert.Equal("0", metricDict["Errored Requests (5xx)"]);
        Assert.Equal("0", metricDict["Pages Served 2xx"]);
        Assert.Equal("0", metricDict["Pages Served 5xx"]);
        Assert.Equal("0", metricDict["Pages Throttled (429)"]);
    }

    [Fact]
    public async Task ConcurrentRecording_ThrottledRequests_CountsCorrectly()
    {
        // Arrange
        var tracker = new MetricsTracker();
        int requestsPerThread = 100;
        int threadCount = 5;

        // Act
        var tasks = Enumerable.Range(0, threadCount).Select(_ =>
            Task.Run(() =>
            {
                for (int i = 0; i < requestsPerThread; i++)
                    tracker.RecordThrottled(TimeSpan.FromMilliseconds(1));
            })).ToArray();
        await Task.WhenAll(tasks);
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(requestsPerThread * threadCount, snapshot.ThrottledRequests);
        Assert.Equal(requestsPerThread * threadCount, snapshot.TotalRequests);
        Assert.Equal(requestsPerThread * threadCount, snapshot.Requests4xx);
    }

    [Fact]
    public void RecordRequest_StatusCodeJustOutsideRanges_CategorizedAsOther()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordRequest(199, TimeSpan.FromMilliseconds(1)); // below 2xx
        tracker.RecordRequest(300, TimeSpan.FromMilliseconds(1)); // between 2xx and 4xx
        tracker.RecordRequest(399, TimeSpan.FromMilliseconds(1)); // between 3xx and 4xx
        tracker.RecordRequest(600, TimeSpan.FromMilliseconds(1)); // above 5xx
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(0, snapshot.Requests2xx);
        Assert.Equal(0, snapshot.Requests4xx);
        Assert.Equal(0, snapshot.Requests5xx);
        Assert.Equal(4, snapshot.RequestsOther);
    }

    [Fact]
    public void GetSnapshot_AccuracyAfterManyRequests_MatchesExpectedCounts()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        for (int i = 0; i < 50; i++) tracker.RecordRequest(200, TimeSpan.FromMilliseconds(2));
        for (int i = 0; i < 30; i++) tracker.RecordRequest(404, TimeSpan.FromMilliseconds(3));
        for (int i = 0; i < 10; i++) tracker.RecordRequest(500, TimeSpan.FromMilliseconds(5));
        for (int i = 0; i < 5; i++) tracker.RecordThrottled(TimeSpan.FromMilliseconds(1));
        for (int i = 0; i < 5; i++) tracker.RecordRequest(302, TimeSpan.FromMilliseconds(1));
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(100, snapshot.TotalRequests);
        Assert.Equal(50, snapshot.Requests2xx);
        Assert.Equal(35, snapshot.Requests4xx); // 30 direct + 5 throttled (429)
        Assert.Equal(10, snapshot.Requests5xx);
        Assert.Equal(5, snapshot.RequestsOther);
        Assert.Equal(10, snapshot.ErrorRequests); // only 5xx
        Assert.Equal(5, snapshot.ThrottledRequests);
    }

    [Fact]
    public void GetSnapshot_RecentMetrics_MinMaxCorrectWithVariedTimes()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(5));
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(100));
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(50));
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(1));
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(TimeSpan.FromMilliseconds(1), snapshot.RecentMinimumResponseTime);
        Assert.Equal(TimeSpan.FromMilliseconds(100), snapshot.RecentMaximumResponseTime);
    }

    [Fact]
    public void GetMetricTable_AllResponseTimeMetrics_FormattedCorrectly()
    {
        // Arrange
        var tracker = new MetricsTracker();
        tracker.RecordRequest(200, TimeSpan.FromMilliseconds(25));

        // Act
        tracker.GetMetricTable(out _, out var rows);
        var metricDict = rows.ToDictionary(r => r[0], r => r[1]);

        // Assert – response time values should end with " ms"
        Assert.EndsWith("ms", metricDict["Average Response Time (All Time)"]);
        Assert.EndsWith("ms", metricDict["Minimum Response Time (Last 5m)"]);
        Assert.EndsWith("ms", metricDict["Maximum Response Time (Last 5m)"]);
        Assert.EndsWith("ms", metricDict["Average Response Time (Last 5m)"]);
        Assert.EndsWith("ms", metricDict["95th Percentile Response Time (Last 5m)"]);
        Assert.EndsWith("ms", metricDict["99th Percentile Response Time (Last 5m)"]);
        Assert.EndsWith("ms", metricDict["Average Response Time (Last 10s)"]);
    }

    [Fact]
    public void RecordRequest_LargeElapsedTime_TrackedCorrectly()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordRequest(200, TimeSpan.FromSeconds(30));
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(TimeSpan.FromSeconds(30), snapshot.AverageResponseTime);
        Assert.Equal(TimeSpan.FromSeconds(30), snapshot.RecentMaximumResponseTime);
    }

    [Fact]
    public void RecordRequest_ZeroElapsedTime_TrackedCorrectly()
    {
        // Arrange
        var tracker = new MetricsTracker();

        // Act
        tracker.RecordRequest(200, TimeSpan.Zero);
        var snapshot = tracker.GetSnapshot();

        // Assert
        Assert.Equal(1, snapshot.TotalRequests);
        Assert.Equal(TimeSpan.Zero, snapshot.AverageResponseTime);
    }
}
