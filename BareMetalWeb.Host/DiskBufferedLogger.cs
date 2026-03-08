using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Host;

public sealed class DiskBufferedLogger : IBufferedLogger
{
    // SECURITY: Audit log files are written as plaintext and may contain PII (user names, entity IDs,
    // operation details, error messages). No log redaction or encryption-at-rest is applied. Consider
    // implementing log field redaction middleware for sensitive patterns (passwords, tokens, PII) and
    // encrypting log files on disk for compliance. See issue #1201.
    private readonly string _logFolder;
    private readonly object _lock = new();
    private DateTime? _lastInfoMinuteUtc;

    private readonly Queue<string> _buffer = new();
    private const int MaxBufferSize = 1000;
    private const int LogRetentionDays = 30;
    private DateTime _lastCleanupUtc = DateTime.MinValue;

    public DiskBufferedLogger(string logFolder)
    {
        _logFolder = logFolder;
    }

    public void LogInfo(string message)
    {
        lock (_lock)
        {
            if (_buffer.Count >= MaxBufferSize)
                _buffer.Dequeue();

            _buffer.Enqueue(
                $"INFO | {DateTime.UtcNow:O} | {message}");
        }
    }

    public void LogError(string message, Exception ex)
    {
        // Deliberately NOT sharing the lock
        // Errors must not block info logging
        // Fire-and-forget async to avoid blocking caller while still using async backoff
        _ = LogErrorAsync(message, ex);
    }

    private async Task LogErrorAsync(string message, Exception ex)
    {
        try
        {
            var nowUtc = DateTime.UtcNow;
            await AppendTextSharedAsync(
                GetLogFilePath(nowUtc, "error"),
                $"ERROR | {nowUtc:O} | {message}{Environment.NewLine}{ex}{Environment.NewLine}").ConfigureAwait(false);
        }
        catch (Exception secondEx)
        {
            // Last line of defence: logging must never throw, BUT - we should at least know it failed
            // While this is not ideal to log to the console for performance terms, logging failures are rare and likely indicate a serious issue
            // So we should at least do SOMETHING
            Console.Error.WriteLine($"Failed to log {ex.ToString()} || because of error: {secondEx}");  
        }
    }
    [DebuggerNonUserCode] // Prevent stepping into this method during debugging as it will drive you insane 
    // If diagnosing why your logging is not working, remove this attribute
    public async Task RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await FlushOnceAsync(CancellationToken.None);
                await Task.Delay(200, cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Expected during shutdown — fall through to final flush
        }

        // Final flush on shutdown — always runs even after cancellation
        await FlushOnceAsync(CancellationToken.None, isShutdown: true);
    }

    /// <summary>
    /// #1246: Delete log directories older than <see cref="LogRetentionDays"/> days.
    /// Runs at most once per day to avoid repeated directory scans.
    /// </summary>
    private void CleanupOldLogs()
    {
        var now = DateTime.UtcNow;
        if ((now - _lastCleanupUtc).TotalHours < 24) return;
        _lastCleanupUtc = now;

        var baseDirectory = string.IsNullOrWhiteSpace(_logFolder)
            ? AppContext.BaseDirectory
            : _logFolder;
        if (!Path.IsPathRooted(baseDirectory))
            baseDirectory = Path.Combine(AppContext.BaseDirectory, baseDirectory);

        if (!Directory.Exists(baseDirectory)) return;

        try
        {
            var cutoff = now.AddDays(-LogRetentionDays).ToString("yyyyMMdd");
            foreach (var dayDir in Directory.EnumerateDirectories(baseDirectory))
            {
                var dirName = Path.GetFileName(dayDir);
                if (dirName.Length == 8 && string.CompareOrdinal(dirName, cutoff) < 0)
                {
                    try { Directory.Delete(dayDir, recursive: true); }
                    catch { /* best-effort cleanup */ }
                }
            }
        }
        catch { /* don't let cleanup failures affect logging */ }
    }

    public void OnApplicationStopping(CancellationTokenSource cts, Task loggerTask)
    {
        Console.WriteLine("Application stopping: flushing logs...");
        this.LogInfo("Application stopping: flushing logs...");
        cts.Cancel();

        try
        {
            loggerTask.GetAwaiter().GetResult();
            Console.WriteLine("Log flush complete. Exiting.");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(
                $"Error during log flush on shutdown:{Environment.NewLine}{ex}");
        }
    }

    [DebuggerNonUserCode] // Prevent stepping into this method during debugging as it will drive you insane 
    // If diagnosing why your logging is not working, remove this attribute
    private async Task FlushOnceAsync(CancellationToken token, bool isShutdown = false)
    {
        string[] batch;

        lock (_lock)
        {
            if (_buffer.Count == 0 && !isShutdown)
                return;

            batch = _buffer.ToArray();
            _buffer.Clear();
        }

        var nowUtc = DateTime.UtcNow;
        var currentMinuteUtc = TruncateToMinuteUtc(nowUtc);
        var previousMinuteUtc = _lastInfoMinuteUtc;
        _lastInfoMinuteUtc = currentMinuteUtc;

        if (!isShutdown && previousMinuteUtc.HasValue && previousMinuteUtc.Value != currentMinuteUtc)
        {
            var segmentLine = $"INFO | {nowUtc:O} | Log segment complete; cycling to next segment.";
            await AppendLinesSharedAsync(
                GetLogFilePath(previousMinuteUtc.Value, "info"),
                new[] { segmentLine },
                token).ConfigureAwait(false);
        }

        var lines = new List<string>(batch.Length + 1);
        if (batch.Length > 0)
            lines.AddRange(batch);

        if (isShutdown)
        {
            lines.Add($"INFO | {nowUtc:O} | Clean shutdown completed.");
        }

        await AppendLinesSharedAsync(GetLogFilePath(nowUtc, "info"), lines, token).ConfigureAwait(false);

        CleanupOldLogs();
    }

    private static DateTime TruncateToMinuteUtc(DateTime utcNow)
    {
        var ticks = utcNow.Ticks - (utcNow.Ticks % TimeSpan.TicksPerMinute);
        return new DateTime(ticks, DateTimeKind.Utc);
    }

    private string GetLogFilePath(DateTime utcNow, string category)
    {
        var minuteStamp = utcNow.ToString("yyyyMMdd_HHmm");
        var dayStamp = utcNow.ToString("yyyyMMdd");
        var hourStamp = utcNow.ToString("HH");

        var baseDirectory = string.IsNullOrWhiteSpace(_logFolder)
            ? AppContext.BaseDirectory
            : _logFolder;

        if (!Path.IsPathRooted(baseDirectory))
        {
            baseDirectory = Path.Combine(AppContext.BaseDirectory, baseDirectory);
        }

        var targetDirectory = Path.Combine(baseDirectory, dayStamp, hourStamp);
        Directory.CreateDirectory(targetDirectory);

        var fileName = $"{category}_{minuteStamp}.log";
        return Path.Combine(targetDirectory, fileName);
    }

    private static async Task AppendTextSharedAsync(string path, string content)
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                // Encrypt log content at rest when BMW_WAL_ENCRYPTION_KEY is configured
                if (BareMetalWeb.Data.EncryptedFileIO.IsEnabled())
                {
                    var plainBytes = System.Text.Encoding.UTF8.GetBytes(content);
                    var encrypted = BareMetalWeb.Data.EncryptedFileIO.Encrypt(plainBytes, "auditlog");
                    var line = Convert.ToBase64String(encrypted);
                    using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite, 4096, useAsync: true);
                    using var writer = new StreamWriter(stream);
                    await writer.WriteLineAsync(line).ConfigureAwait(false);
                }
                else
                {
                    using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite, 4096, useAsync: true);
                    using var writer = new StreamWriter(stream);
                    await writer.WriteAsync(content).ConfigureAwait(false);
                }
                return;
            }
            catch (IOException) when (attempt < 2)
            {
                await Task.Delay(10 * (attempt + 1)).ConfigureAwait(false);
            }
        }
    }

    private static async Task AppendLinesSharedAsync(string path, IReadOnlyCollection<string> lines, CancellationToken token)
    {
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                using var stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite, 4096, useAsync: true);
                using var writer = new StreamWriter(stream);

                // Encrypt each log line at rest when BMW_WAL_ENCRYPTION_KEY is configured
                bool encrypt = BareMetalWeb.Data.EncryptedFileIO.IsEnabled();
                foreach (var line in lines)
                {
                    if (encrypt)
                    {
                        var plainBytes = System.Text.Encoding.UTF8.GetBytes(line);
                        var encrypted = BareMetalWeb.Data.EncryptedFileIO.Encrypt(plainBytes, "auditlog");
                        await writer.WriteLineAsync(Convert.ToBase64String(encrypted)).ConfigureAwait(false);
                    }
                    else
                    {
                        await writer.WriteLineAsync(line).ConfigureAwait(false);
                    }
                }
                return;
            }
            catch (IOException) when (attempt < 2)
            {
                await Task.Delay(10 * (attempt + 1), token).ConfigureAwait(false);
            }
        }
    }
}
