using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.ControlPlane;
using BareMetalWeb.Core;
using Xunit;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Unit tests for the observability telemetry streaming pipeline:
///   • TelemetryBuffer (disk-backed offline queue)
///   • ControlPlaneService.ComputeBackoff (exponential back-off with jitter)
///   • ControlPlaneService.GetHealth (health visibility)
///   • DiskBufferedLogger.ErrorHook (error forwarding)
/// </summary>
public class ControlPlaneObservabilityTests : IDisposable
{
    private readonly string _tempDir;

    public ControlPlaneObservabilityTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"bmw_cp_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch { /* best-effort */ }
    }

    // ── TelemetryBuffer ──────────────────────────────────────────────────────

    [Fact]
    public void TelemetryBuffer_EnqueueAndDequeue_RoundTrips()
    {
        var buf = new TelemetryBuffer(_tempDir, maxRecords: 10);

        buf.TryEnqueue("{\"a\":1}");
        buf.TryEnqueue("{\"b\":2}");

        Assert.Equal(2, buf.QueueDepth);
        Assert.True(buf.TryDequeue(out var first));
        Assert.Equal("{\"a\":1}", first);
        Assert.Equal(1, buf.QueueDepth);
    }

    [Fact]
    public void TelemetryBuffer_WhenFull_DropsOldestAndCountsDrops()
    {
        var buf = new TelemetryBuffer(_tempDir, maxRecords: 3);

        buf.TryEnqueue("A");
        buf.TryEnqueue("B");
        buf.TryEnqueue("C");
        // Adding a 4th should evict "A" and increment DroppedCount
        buf.TryEnqueue("D");

        Assert.Equal(1, buf.DroppedCount);
        Assert.Equal(3, buf.QueueDepth);

        // First item should now be "B" (oldest remaining)
        buf.TryDequeue(out var item);
        Assert.Equal("B", item);
    }

    [Fact]
    public void TelemetryBuffer_TryDequeue_ReturnsFalseWhenEmpty()
    {
        var buf = new TelemetryBuffer(_tempDir, maxRecords: 10);
        Assert.False(buf.TryDequeue(out _));
    }

    [Fact]
    public void TelemetryBuffer_PersistCurrentState_WritesFile()
    {
        var buf = new TelemetryBuffer(_tempDir, maxRecords: 10);
        buf.TryEnqueue("line1");
        buf.TryEnqueue("line2");
        buf.PersistCurrentState();

        var filePath = Path.Combine(_tempDir, "telemetry_pending.ndjson");
        Assert.True(File.Exists(filePath));
        var lines = File.ReadAllLines(filePath);
        Assert.Contains("line1", lines);
        Assert.Contains("line2", lines);
    }

    [Fact]
    public void TelemetryBuffer_PersistCurrentState_DeletesFileWhenEmpty()
    {
        var buf = new TelemetryBuffer(_tempDir, maxRecords: 10);
        buf.TryEnqueue("item");
        buf.PersistCurrentState(); // writes file

        buf.TryDequeue(out _);     // drain queue
        buf.PersistCurrentState(); // should delete file

        var filePath = Path.Combine(_tempDir, "telemetry_pending.ndjson");
        Assert.False(File.Exists(filePath));
    }

    [Fact]
    public void TelemetryBuffer_LoadFromDisk_RestoresPendingRecords()
    {
        // Arrange: write records to disk directly
        var filePath = Path.Combine(_tempDir, "telemetry_pending.ndjson");
        File.WriteAllLines(filePath, new[] { "rec1", "rec2", "rec3" });

        // Act: create a new buffer instance which should load from disk
        var buf = new TelemetryBuffer(_tempDir, maxRecords: 100);

        // Assert
        Assert.Equal(3, buf.QueueDepth);
        buf.TryDequeue(out var r1); Assert.Equal("rec1", r1);
        buf.TryDequeue(out var r2); Assert.Equal("rec2", r2);
        buf.TryDequeue(out var r3); Assert.Equal("rec3", r3);
    }

    [Fact]
    public void TelemetryBuffer_LoadFromDisk_RespectsMaxRecords()
    {
        // Write more records than the limit
        var filePath = Path.Combine(_tempDir, "telemetry_pending.ndjson");
        var lines = new string[20];
        for (int i = 0; i < 20; i++) lines[i] = $"item{i}";
        File.WriteAllLines(filePath, lines);

        var buf = new TelemetryBuffer(_tempDir, maxRecords: 5);

        Assert.Equal(5, buf.QueueDepth);
        // Excess records beyond limit should be counted as dropped
        Assert.Equal(15, buf.DroppedCount);
    }

    // ── RecordEnvelopeExtensions ─────────────────────────────────────────────

    [Fact]
    public void RecordEnvelope_PrependAndParse_RoundTrips()
    {
        const string entityType = "TelemetrySnapshot";
        const string json = "{\"instanceId\":\"host1\"}";

        var envelope = json.PrependEntityType(entityType);
        Assert.True(envelope.TryParseEntityRecord(out var parsedType, out var parsedJson, out var attempt));
        Assert.Equal(entityType, parsedType);
        Assert.Equal(json, parsedJson);
        Assert.Equal(0, attempt);
    }

    [Fact]
    public void RecordEnvelope_IncrementAttempt_IncrementsCounter()
    {
        const string json = "{\"x\":1}";
        var envelope = json.PrependEntityType("ErrorEvent");
        envelope.TryParseEntityRecord(out _, out _, out var attempt0);
        Assert.Equal(0, attempt0);

        var envelope2 = envelope.IncrementAttempt(0);
        envelope2.TryParseEntityRecord(out _, out var sameJson, out var attempt1);
        Assert.Equal(1, attempt1);
        Assert.Equal(json, sameJson);
    }

    [Fact]
    public void RecordEnvelope_TryParse_ReturnsFalseForMalformedRecord()
    {
        Assert.False("notypejustjson".TryParseEntityRecord(out _, out _, out _));
        Assert.False(string.Empty.TryParseEntityRecord(out _, out _, out _));
    }

    [Fact]
    public void RecordEnvelope_TryParse_LegacyFormatWithoutAttemptField()
    {
        // Legacy format written by old code: entityType\x1Fjson (no attempt field)
        const char sep = '\x1F';
        var legacy = string.Concat("InstanceHeartbeat", sep, "{\"id\":\"x\"}");
        Assert.True(legacy.TryParseEntityRecord(out var et, out var js, out var att));
        Assert.Equal("InstanceHeartbeat", et);
        Assert.Equal("{\"id\":\"x\"}", js);
        Assert.Equal(0, att); // defaults to 0
    }

    // ── ControlPlaneService.ComputeBackoff ───────────────────────────────────

    [Fact]
    public void ComputeBackoff_FirstFailure_ReturnsAtLeastMinimum()
    {
        var delay = ControlPlaneService.ComputeBackoff(1);
        Assert.True(delay >= TimeSpan.FromSeconds(5),
            $"Expected >= 5s but got {delay.TotalSeconds:F1}s");
    }

    [Fact]
    public void ComputeBackoff_HighFailureCount_CapsAtMaximum()
    {
        // 20 failures should still be <= max (5 minutes) + 20% jitter
        for (int i = 0; i < 5; i++) // run multiple times to exercise jitter range
        {
            var delay = ControlPlaneService.ComputeBackoff(20);
            // Even with +20% jitter on 5 min cap the result should stay reasonable
            Assert.True(delay <= TimeSpan.FromMinutes(7),
                $"Back-off too large: {delay.TotalSeconds:F1}s");
        }
    }

    [Fact]
    public void ComputeBackoff_GrowsExponentially()
    {
        // The median (no jitter) should grow: failure 1 < failure 2 < failure 4
        // We can't check the exact value because of jitter, but many samples should show growth.
        double sum1 = 0, sum4 = 0;
        for (int i = 0; i < 50; i++)
        {
            sum1 += ControlPlaneService.ComputeBackoff(1).TotalSeconds;
            sum4 += ControlPlaneService.ComputeBackoff(4).TotalSeconds;
        }
        Assert.True(sum4 > sum1, "Expected higher back-off for more failures");
    }

    // ── DiskBufferedLogger.ErrorHook ─────────────────────────────────────────

    [Fact]
    public void DiskBufferedLogger_ErrorHook_InvokedOnError()
    {
        var logDir = Path.Combine(_tempDir, "logs");
        var logger = new DiskBufferedLogger(logDir);

        string? capturedLevel = null;
        string? capturedMessage = null;
        logger.ErrorHook = (level, msg, exType, stack, path, method, status, rid) =>
        {
            capturedLevel = level;
            capturedMessage = msg;
        };

        logger.Log(BmwLogLevel.Error, "Something went wrong", correlationId: "rid-1");

        Assert.Equal("ERROR", capturedLevel);
        Assert.Equal("Something went wrong", capturedMessage);
    }

    [Fact]
    public void DiskBufferedLogger_ErrorHook_InvokedOnFatal()
    {
        var logDir = Path.Combine(_tempDir, "logs");
        var logger = new DiskBufferedLogger(logDir);

        string? capturedLevel = null;
        logger.ErrorHook = (level, msg, exType, stack, path, method, status, rid) =>
            capturedLevel = level;

        logger.Log(BmwLogLevel.Fatal, "Fatal error!");

        Assert.Equal("FATAL", capturedLevel);
    }

    [Fact]
    public void DiskBufferedLogger_ErrorHook_NotInvokedForInfoLevel()
    {
        var logDir = Path.Combine(_tempDir, "logs");
        var logger = new DiskBufferedLogger(logDir);

        bool hookCalled = false;
        logger.ErrorHook = (_, _, _, _, _, _, _, _) => hookCalled = true;

        logger.Log(BmwLogLevel.Info, "Just info");

        Assert.False(hookCalled);
    }

    [Fact]
    public void DiskBufferedLogger_ErrorHook_LogError_InvokedWithExceptionDetails()
    {
        var logDir = Path.Combine(_tempDir, "logs");
        var logger = new DiskBufferedLogger(logDir);

        string? capturedExType = null;
        string? capturedStack = null;
        logger.ErrorHook = (level, msg, exType, stack, path, method, status, rid) =>
        {
            capturedExType = exType;
            capturedStack = stack;
        };

        var ex = new InvalidOperationException("test exception");
        logger.LogError("Unhandled exception", ex, correlationId: null);

        Assert.Equal("InvalidOperationException", capturedExType);
        Assert.NotNull(capturedStack);
    }

    [Fact]
    public void DiskBufferedLogger_ErrorHook_PassesPathAndMethodFromFields()
    {
        var logDir = Path.Combine(_tempDir, "logs");
        var logger = new DiskBufferedLogger(logDir);

        string? capturedPath = null;
        string? capturedMethod = null;
        int capturedStatus = 0;
        logger.ErrorHook = (level, msg, exType, stack, path, method, status, rid) =>
        {
            capturedPath = path;
            capturedMethod = method;
            capturedStatus = status;
        };

        logger.Log(BmwLogLevel.Error, "Not found", "rid-42",
            new BareMetalWeb.Core.Interfaces.LogFields
            {
                Path = "/api/orders",
                Method = "GET",
                StatusCode = 500,
            });

        Assert.Equal("/api/orders", capturedPath);
        Assert.Equal("GET", capturedMethod);
        Assert.Equal(500, capturedStatus);
    }

    // ── ObservabilityHealth ──────────────────────────────────────────────────

    [Fact]
    public void ObservabilityHealth_DefaultValues_AreExpected()
    {
        var health = new ObservabilityHealth();
        Assert.Equal(0, health.PendingQueueDepth);
        Assert.Equal(0L, health.DroppedCount);
        Assert.Equal(0L, health.RetryCount);
        Assert.Null(health.LastSuccessfulSendUtc);
        Assert.False(health.IsOnline);
    }
}
