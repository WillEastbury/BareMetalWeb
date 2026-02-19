using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace BareMetalWeb.Host.Tests;

public class DiskBufferedLoggerTests : IDisposable
{
    private readonly string _tempDir;

    public DiskBufferedLoggerTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"bmw_log_{Guid.NewGuid().ToString("N")[..8]}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
                Directory.Delete(_tempDir, recursive: true);
        }
        catch
        {
            // Best-effort cleanup
        }
    }

    // ── Buffering & flushing ──────────────────────────────────────────

    [Fact]
    public async Task LogInfo_BuffersMessages_FlushWritesToDisk()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);
        logger.LogInfo("Hello from test");

        using var cts = new CancellationTokenSource();

        // Act – run one flush cycle then cancel
        cts.CancelAfter(TimeSpan.FromMilliseconds(500));
        try { await logger.RunAsync(cts.Token); }
        catch (OperationCanceledException) { }

        // Assert
        var logFiles = Directory.GetFiles(_tempDir, "info_*.log", SearchOption.AllDirectories);
        Assert.NotEmpty(logFiles);

        var content = await File.ReadAllTextAsync(logFiles[0]);
        Assert.Contains("Hello from test", content);
        Assert.Contains("INFO |", content);
    }

    [Fact]
    public async Task RunAsync_FinalFlush_WritesShutdownMessage()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);
        logger.LogInfo("before shutdown");

        using var cts = new CancellationTokenSource();
        cts.Cancel(); // cancel immediately so RunAsync does final flush

        // Act
        await logger.RunAsync(cts.Token);

        // Assert
        var logFiles = Directory.GetFiles(_tempDir, "info_*.log", SearchOption.AllDirectories);
        Assert.NotEmpty(logFiles);

        var content = await File.ReadAllTextAsync(logFiles[0]);
        Assert.Contains("Clean shutdown completed", content);
        Assert.Contains("before shutdown", content);
    }

    [Fact]
    public async Task LogError_WritesErrorFileToDisk()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);

        // Act
        logger.LogError("Something broke", new InvalidOperationException("boom"));

        // Give fire-and-forget task time to complete
        await Task.Delay(500);

        // Assert
        var errorFiles = Directory.GetFiles(_tempDir, "error_*.log", SearchOption.AllDirectories);
        Assert.NotEmpty(errorFiles);

        var content = await File.ReadAllTextAsync(errorFiles[0]);
        Assert.Contains("ERROR |", content);
        Assert.Contains("Something broke", content);
        Assert.Contains("boom", content);
    }

    // ── File rotation (date-based log files) ─────────────────────────

    [Fact]
    public async Task LogFiles_UseTimestampBasedPath()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);
        logger.LogInfo("rotation check");

        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(500));
        try { await logger.RunAsync(cts.Token); }
        catch (OperationCanceledException) { }

        // Assert – directory structure is {dayStamp}/{hourStamp}/info_{minuteStamp}.log
        var nowUtc = DateTime.UtcNow;
        var dayDir = nowUtc.ToString("yyyyMMdd");
        var hourDir = nowUtc.ToString("HH");

        var expectedDir = Path.Combine(_tempDir, dayDir, hourDir);
        Assert.True(Directory.Exists(expectedDir), $"Expected directory {expectedDir} to exist");

        var logFiles = Directory.GetFiles(expectedDir, "info_*.log");
        Assert.NotEmpty(logFiles);

        var fileName = Path.GetFileName(logFiles[0]);
        Assert.StartsWith("info_", fileName);
        Assert.EndsWith(".log", fileName);
    }

    [Fact]
    public async Task ErrorLogFiles_UseTimestampBasedPath()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);
        logger.LogError("err", new Exception("test"));

        await Task.Delay(500);

        // Assert
        var errorFiles = Directory.GetFiles(_tempDir, "error_*.log", SearchOption.AllDirectories);
        Assert.NotEmpty(errorFiles);

        var fileName = Path.GetFileName(errorFiles[0]);
        Assert.StartsWith("error_", fileName);
        Assert.EndsWith(".log", fileName);
    }

    // ── Concurrent write safety ──────────────────────────────────────

    [Fact]
    public async Task LogInfo_ConcurrentWrites_AllMessagesBuffered()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);
        const int threadCount = 20;
        const int messagesPerThread = 50;

        // Act – write from many threads concurrently
        var tasks = Enumerable.Range(0, threadCount).Select(t =>
            Task.Run(() =>
            {
                for (int i = 0; i < messagesPerThread; i++)
                    logger.LogInfo($"thread-{t}-msg-{i}");
            }));
        await Task.WhenAll(tasks);

        // Flush
        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(500));
        try { await logger.RunAsync(cts.Token); }
        catch (OperationCanceledException) { }

        // Assert – total may be capped at MaxBufferSize (1000)
        var logFiles = Directory.GetFiles(_tempDir, "info_*.log", SearchOption.AllDirectories);
        Assert.NotEmpty(logFiles);

        var allLines = logFiles
            .SelectMany(f => File.ReadAllLines(f))
            .Where(l => l.Contains("thread-"))
            .ToList();

        // 20 * 50 = 1000 exactly at buffer capacity
        Assert.True(allLines.Count > 0, "Expected logged messages on disk");
        Assert.True(allLines.Count <= threadCount * messagesPerThread + 10, "Unexpected extra lines");
    }

    // ── Buffer overflow handling ─────────────────────────────────────

    [Fact]
    public async Task LogInfo_ExceedsMaxBufferSize_OldestMessagesDropped()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);

        // Act – fill buffer past capacity (MaxBufferSize = 1000)
        for (int i = 0; i < 1100; i++)
            logger.LogInfo($"msg-{i:D4}");

        // Flush
        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(500));
        try { await logger.RunAsync(cts.Token); }
        catch (OperationCanceledException) { }

        // Assert
        var logFiles = Directory.GetFiles(_tempDir, "info_*.log", SearchOption.AllDirectories);
        var content = string.Join(Environment.NewLine, logFiles.SelectMany(f => File.ReadAllLines(f)));

        // Oldest messages (0-99) should have been dequeued
        Assert.DoesNotContain("msg-0000", content);
        Assert.DoesNotContain("msg-0099", content);

        // Newest messages should be present
        Assert.Contains("msg-1099", content);
        Assert.Contains("msg-1050", content);
    }

    [Fact]
    public void LogInfo_AtExactCapacity_DoesNotThrow()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);

        // Act & Assert – should not throw
        for (int i = 0; i < 1000; i++)
            logger.LogInfo($"msg-{i}");
    }

    // ── Log level filtering ──────────────────────────────────────────

    [Fact]
    public async Task LogInfo_WritesToInfoFile_NotErrorFile()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);
        logger.LogInfo("info only");

        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(500));
        try { await logger.RunAsync(cts.Token); }
        catch (OperationCanceledException) { }

        // Assert
        var infoFiles = Directory.GetFiles(_tempDir, "info_*.log", SearchOption.AllDirectories);
        var errorFiles = Directory.GetFiles(_tempDir, "error_*.log", SearchOption.AllDirectories);

        Assert.NotEmpty(infoFiles);
        Assert.Empty(errorFiles);

        var content = await File.ReadAllTextAsync(infoFiles[0]);
        Assert.Contains("INFO |", content);
        Assert.DoesNotContain("ERROR |", content);
    }

    [Fact]
    public async Task LogError_WritesToErrorFile_NotInfoFile()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);
        logger.LogError("error only", new Exception("fail"));

        await Task.Delay(500);

        // Assert
        var errorFiles = Directory.GetFiles(_tempDir, "error_*.log", SearchOption.AllDirectories);
        Assert.NotEmpty(errorFiles);

        var content = await File.ReadAllTextAsync(errorFiles[0]);
        Assert.Contains("ERROR |", content);
    }

    [Fact]
    public async Task LogError_IncludesExceptionDetails()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);
        var ex = new InvalidOperationException("inner detail");

        // Act
        logger.LogError("outer message", ex);
        await Task.Delay(500);

        // Assert
        var errorFiles = Directory.GetFiles(_tempDir, "error_*.log", SearchOption.AllDirectories);
        Assert.NotEmpty(errorFiles);

        var content = await File.ReadAllTextAsync(errorFiles[0]);
        Assert.Contains("outer message", content);
        Assert.Contains("inner detail", content);
        Assert.Contains("InvalidOperationException", content);
    }

    // ── File I/O error resilience ────────────────────────────────────

    [Fact]
    public async Task LogError_WhenDiskFails_DoesNotThrow()
    {
        // Arrange – use an invalid path that will cause I/O failure
        var invalidPath = Path.Combine(_tempDir, new string('x', 300), "impossibly_long");
        var logger = new DiskBufferedLogger(invalidPath);

        // Capture Console.Error so the expected "Failed to log" message doesn't pollute CI output
        var originalError = Console.Error;
        using var captured = new StringWriter();
        Console.SetError(captured);
        try
        {
            // Act & Assert – fire-and-forget error logging must never throw
            var exception = Record.Exception(() =>
                logger.LogError("should not throw", new Exception("test")));

            Assert.Null(exception);

            // Wait for the fire-and-forget async task to complete
            await Task.Delay(500);
        }
        finally
        {
            Console.SetError(originalError);
        }
    }

    [Fact]
    public async Task RunAsync_WhenFlushFails_ContinuesRunning()
    {
        // Arrange – start with a valid path, log a message
        var logger = new DiskBufferedLogger(_tempDir);
        logger.LogInfo("message before failure");

        // Act – even if we cancel quickly, the logger should not throw unhandled
        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(300));

        var exception = await Record.ExceptionAsync(async () =>
        {
            try { await logger.RunAsync(cts.Token); }
            catch (OperationCanceledException) { }
        });

        Assert.Null(exception);
    }

    [Fact]
    public async Task OnApplicationStopping_FlushesRemainingLogs()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);
        logger.LogInfo("final message");

        // Use a pre-cancelled token so RunAsync skips the while-loop
        // and proceeds directly to the final shutdown flush.
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // Act
        await logger.RunAsync(cts.Token);

        // Assert
        var logFiles = Directory.GetFiles(_tempDir, "info_*.log", SearchOption.AllDirectories);
        Assert.NotEmpty(logFiles);

        var content = string.Join(Environment.NewLine, logFiles.SelectMany(f => File.ReadAllLines(f)));
        Assert.Contains("final message", content);
        Assert.Contains("Clean shutdown completed", content);
    }

    // ── Empty buffer flush ───────────────────────────────────────────

    [Fact]
    public async Task RunAsync_EmptyBuffer_StillWritesShutdownMessage()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);

        // Act – run briefly with nothing buffered
        using var cts = new CancellationTokenSource();
        cts.CancelAfter(TimeSpan.FromMilliseconds(100));
        await logger.RunAsync(cts.Token);

        // Assert – final shutdown flush always runs, writing the shutdown marker
        var infoFiles = Directory.GetFiles(_tempDir, "info_*.log", SearchOption.AllDirectories);
        Assert.Single(infoFiles);
        var content = await File.ReadAllTextAsync(infoFiles[0]);
        Assert.Contains("Clean shutdown completed", content);
    }

    // ── Shutdown flush with empty buffer ─────────────────────────────

    [Fact]
    public async Task RunAsync_ShutdownFlush_EmptyBuffer_WritesShutdownMessage()
    {
        // Arrange – no messages buffered, but pre-cancelled token triggers shutdown flush
        var logger = new DiskBufferedLogger(_tempDir);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // Act
        await logger.RunAsync(cts.Token);

        // Assert – shutdown flush writes even when buffer is empty
        var infoFiles = Directory.GetFiles(_tempDir, "info_*.log", SearchOption.AllDirectories);
        Assert.NotEmpty(infoFiles);

        var content = await File.ReadAllTextAsync(infoFiles[0]);
        Assert.Contains("Clean shutdown completed", content);
    }

    // ── Buffer cleared after flush ───────────────────────────────────

    [Fact]
    public async Task FlushOnce_ClearsBuffer_SecondFlushDoesNotDuplicate()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);
        logger.LogInfo("first-batch");

        // Act – first flush cycle
        using var cts1 = new CancellationTokenSource();
        cts1.CancelAfter(TimeSpan.FromMilliseconds(500));
        try { await logger.RunAsync(cts1.Token); }
        catch (OperationCanceledException) { }

        var firstFiles = Directory.GetFiles(_tempDir, "info_*.log", SearchOption.AllDirectories);
        var firstContent = string.Join(Environment.NewLine, firstFiles.SelectMany(f => File.ReadAllLines(f)));
        var firstBatchCount = firstContent.Split("first-batch").Length - 1;

        // Second flush with no new messages
        using var cts2 = new CancellationTokenSource();
        cts2.CancelAfter(TimeSpan.FromMilliseconds(500));
        try { await logger.RunAsync(cts2.Token); }
        catch (OperationCanceledException) { }

        // Assert – "first-batch" should not appear again
        var allFiles = Directory.GetFiles(_tempDir, "info_*.log", SearchOption.AllDirectories);
        var allContent = string.Join(Environment.NewLine, allFiles.SelectMany(f => File.ReadAllLines(f)));
        var totalBatchCount = allContent.Split("first-batch").Length - 1;

        Assert.Equal(firstBatchCount, totalBatchCount);
    }

    // ── Multiple flush cycles accumulate ─────────────────────────────

    [Fact]
    public async Task MultipleFlushed_AccumulateContent()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);

        // First batch
        logger.LogInfo("batch-one");
        using var cts1 = new CancellationTokenSource();
        cts1.CancelAfter(TimeSpan.FromMilliseconds(500));
        try { await logger.RunAsync(cts1.Token); }
        catch (OperationCanceledException) { }

        // Second batch
        logger.LogInfo("batch-two");
        using var cts2 = new CancellationTokenSource();
        cts2.CancelAfter(TimeSpan.FromMilliseconds(500));
        try { await logger.RunAsync(cts2.Token); }
        catch (OperationCanceledException) { }

        // Assert
        var allFiles = Directory.GetFiles(_tempDir, "info_*.log", SearchOption.AllDirectories);
        var allContent = string.Join(Environment.NewLine, allFiles.SelectMany(f => File.ReadAllLines(f)));
        Assert.Contains("batch-one", allContent);
        Assert.Contains("batch-two", allContent);
    }

    // ── Message format validation ────────────────────────────────────

    [Fact]
    public async Task LogInfo_MessageFormat_ContainsIso8601Timestamp()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);
        logger.LogInfo("format-check");

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // Act
        await logger.RunAsync(cts.Token);

        // Assert – each line should match "INFO | <ISO 8601> | <message>"
        var logFiles = Directory.GetFiles(_tempDir, "info_*.log", SearchOption.AllDirectories);
        var lines = logFiles.SelectMany(f => File.ReadAllLines(f))
            .Where(l => l.Contains("format-check"))
            .ToList();

        Assert.Single(lines);
        var parts = lines[0].Split(" | ");
        Assert.Equal(3, parts.Length);
        Assert.Equal("INFO", parts[0]);
        Assert.True(DateTimeOffset.TryParse(parts[1], out _), "Timestamp should be valid ISO 8601");
    }

    [Fact]
    public async Task LogError_MessageFormat_ContainsExceptionAndTimestamp()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);
        var ex = new ArgumentException("bad arg");

        // Act
        logger.LogError("format-err", ex);
        await Task.Delay(500);

        // Assert
        var errorFiles = Directory.GetFiles(_tempDir, "error_*.log", SearchOption.AllDirectories);
        Assert.NotEmpty(errorFiles);

        var content = await File.ReadAllTextAsync(errorFiles[0]);
        Assert.StartsWith("ERROR |", content);
        Assert.Contains("format-err", content);
        Assert.Contains("ArgumentException", content);
        Assert.Contains("bad arg", content);
    }

    // ── Concurrent error writes ──────────────────────────────────────

    [Fact]
    public async Task LogError_ConcurrentWrites_DoesNotThrow()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);

        // Act – fire many errors concurrently
        var tasks = Enumerable.Range(0, 20).Select(i =>
            Task.Run(() =>
                logger.LogError($"concurrent-err-{i}", new Exception($"err-{i}"))));
        await Task.WhenAll(tasks);

        // Give fire-and-forget tasks time to complete
        await Task.Delay(1000);

        // Assert – at least some error files exist and no exceptions thrown
        var errorFiles = Directory.GetFiles(_tempDir, "error_*.log", SearchOption.AllDirectories);
        Assert.NotEmpty(errorFiles);
    }

    // ── OnApplicationStopping handles error gracefully ───────────────

    [Fact]
    public void OnApplicationStopping_WhenRunAsyncThrows_DoesNotThrow()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);
        logger.LogInfo("pre-stop msg");

        using var cts = new CancellationTokenSource();
        var runTask = logger.RunAsync(cts.Token);

        // Act & Assert – should not throw even though cancellation causes TaskCanceledException
        var exception = Record.Exception(() => logger.OnApplicationStopping(cts, runTask));
        Assert.Null(exception);
    }

    // ── Buffer overflow drops oldest, keeps newest ───────────────────

    [Fact]
    public async Task LogInfo_OverflowByOne_DropsExactlyOldest()
    {
        // Arrange
        var logger = new DiskBufferedLogger(_tempDir);

        // Fill to capacity + 1
        for (int i = 0; i < 1001; i++)
            logger.LogInfo($"overflow-{i:D4}");

        // Flush
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await logger.RunAsync(cts.Token);

        // Assert
        var logFiles = Directory.GetFiles(_tempDir, "info_*.log", SearchOption.AllDirectories);
        var content = string.Join(Environment.NewLine, logFiles.SelectMany(f => File.ReadAllLines(f)));

        // First message should be dropped
        Assert.DoesNotContain("overflow-0000", content);
        // Second message should be present (it's now the oldest)
        Assert.Contains("overflow-0001", content);
        // Last message should be present
        Assert.Contains("overflow-1000", content);
    }

    // ── Log folder path handling ─────────────────────────────────────

    [Fact]
    public async Task Constructor_EmptyLogFolder_UsesBaseDirectory()
    {
        // Arrange – empty string logFolder falls back to AppContext.BaseDirectory
        var logger = new DiskBufferedLogger("");
        logger.LogInfo("fallback-test");

        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // Act
        await logger.RunAsync(cts.Token);

        // Assert – log files should exist under AppContext.BaseDirectory
        var nowUtc = DateTime.UtcNow;
        var expectedDir = Path.Combine(AppContext.BaseDirectory, nowUtc.ToString("yyyyMMdd"), nowUtc.ToString("HH"));
        Assert.True(Directory.Exists(expectedDir), $"Expected directory {expectedDir} to exist");

        // Cleanup
        try { Directory.Delete(Path.Combine(AppContext.BaseDirectory, nowUtc.ToString("yyyyMMdd")), recursive: true); }
        catch { }
    }
}
