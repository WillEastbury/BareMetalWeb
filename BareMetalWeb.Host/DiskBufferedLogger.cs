using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Host;

public sealed class DiskBufferedLogger : IBufferedLogger
{
    // SECURITY: PII redaction is applied when RedactPII is enabled (#1272).
    // Log encryption-at-rest is available when BMW_WAL_ENCRYPTION_KEY is configured.
    private readonly string _logFolder;
    private readonly object _lock = new();
    private DateTime? _lastInfoMinuteUtc;

    private readonly Queue<string> _buffer = new();
    private const int MaxBufferSize = 1000;
    private const int LogRetentionDays = 30;
    private DateTime _lastCleanupUtc = DateTime.MinValue;

    /// <summary>The minimum log level. Entries below this are suppressed with zero allocation.</summary>
    public BmwLogLevel MinimumLevel { get; set; }

    /// <summary>When true, PII patterns (emails, IPs, tokens) are redacted before writing to disk.</summary>
    public bool RedactPII { get; set; }

    private static readonly string[] s_levelLabels = { "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "OFF" };

    public DiskBufferedLogger(string logFolder, BmwLogLevel minimumLevel = BmwLogLevel.Info, bool redactPII = false)
    {
        _logFolder = logFolder;
        MinimumLevel = minimumLevel;
        RedactPII = redactPII;
    }

    /// <summary>
    /// Optional hook invoked whenever an ERROR or FATAL entry is logged.
    /// Wire this up at startup to forward error events to the control-plane
    /// telemetry pipeline without coupling the logger to that subsystem.
    /// Signature: (level, message, exceptionType?, stackTrace?, path?, method?, statusCode, correlationId?)
    /// </summary>
    public Action<string, string, string?, string?, string?, string?, int, string?>? ErrorHook { get; set; }

    /// <summary>Returns true if the given level would be logged. Use as a guard to avoid allocations.</summary>
    public bool IsEnabled(BmwLogLevel level) => level >= MinimumLevel;

    // ── Legacy interface (backward-compatible) ─────────────────────────────

    public void LogInfo(string message)
    {
        Log(BmwLogLevel.Info, message, correlationId: null);
    }

    public void LogError(string message, Exception ex)
    {
        LogError(message, ex, correlationId: null);
    }

    // ── Structured logging (#1256) ─────────────────────────────────────────

    public void Log(BmwLogLevel level, string message, string? correlationId = null)
    {
        if (level < MinimumLevel) return;

        var entry = FormatJsonEntry(level, message, correlationId, fields: null, ex: null);

        if (level >= BmwLogLevel.Error)
        {
            _ = LogErrorRawAsync(entry, level);
            ErrorHook?.Invoke(s_levelLabels[(int)level], message, null, null, null, null, 0, correlationId);
            return;
        }

        lock (_lock)
        {
            if (_buffer.Count >= MaxBufferSize)
                _buffer.Dequeue();
            _buffer.Enqueue(entry);
        }
    }

    public void LogError(string message, Exception ex, string? correlationId)
    {
        if (BmwLogLevel.Error < MinimumLevel) return;
        var entry = FormatJsonEntry(BmwLogLevel.Error, message, correlationId, fields: null, ex);
        _ = LogErrorRawAsync(entry, BmwLogLevel.Error);
        ErrorHook?.Invoke("ERROR", message, ex.GetType().Name, ex.ToString(), null, null, 0, correlationId);
    }

    public void Log(BmwLogLevel level, string message, string? correlationId, LogFields? fields)
    {
        if (level < MinimumLevel) return;

        var entry = FormatJsonEntry(level, message, correlationId, fields, ex: null);

        if (level >= BmwLogLevel.Error)
        {
            _ = LogErrorRawAsync(entry, level);
            ErrorHook?.Invoke(s_levelLabels[(int)level], message, null, null,
                fields?.Path, fields?.Method, fields?.StatusCode ?? 0, correlationId);
            return;
        }

        lock (_lock)
        {
            if (_buffer.Count >= MaxBufferSize)
                _buffer.Dequeue();
            _buffer.Enqueue(entry);
        }
    }

    // ── JSON formatting ────────────────────────────────────────────────────

    private string FormatJsonEntry(BmwLogLevel level, string message, string? correlationId, LogFields? fields, Exception? ex)
    {
        bool redact = RedactPII;

        using var ms = new MemoryStream(256);
        using (var w = new Utf8JsonWriter(ms, new JsonWriterOptions { SkipValidation = true }))
        {
            w.WriteStartObject();
            w.WriteString("ts", DateTime.UtcNow.ToString("O"));
            w.WriteString("level", s_levelLabels[(int)level]);
            if (correlationId != null)
                w.WriteString("rid", correlationId);
            w.WriteString("msg", redact ? LogRedactor.RedactFreeText(message) : message);

            if (fields != null)
            {
                if (fields.Method != null) w.WriteString("method", fields.Method);
                if (fields.Path != null) w.WriteString("path", fields.Path);
                if (fields.StatusCode.HasValue) w.WriteNumber("status", fields.StatusCode.Value);
                if (fields.DurationMs.HasValue) w.WriteNumber("ms", Math.Round(fields.DurationMs.Value, 2));
                if (fields.UserId != null) w.WriteString("uid", fields.UserId);
                if (fields.SourceIp != null) w.WriteString("ip", redact ? LogRedactor.RedactIp(fields.SourceIp) : fields.SourceIp);
                if (fields.Detail != null) w.WriteString("detail", redact ? LogRedactor.RedactFreeText(fields.Detail) : fields.Detail);
            }

            if (ex != null)
            {
                w.WriteString("error", ex.GetType().Name);
                w.WriteString("stack", redact ? LogRedactor.RedactFreeText(ex.ToString()) : ex.ToString());
            }

            w.WriteEndObject();
        }
        return Encoding.UTF8.GetString(ms.ToArray());
    }

    // ── Error logging (async, non-blocking) ────────────────────────────────

    private async Task LogErrorRawAsync(string jsonEntry, BmwLogLevel level)
    {
        try
        {
            var nowUtc = DateTime.UtcNow;
            var category = level >= BmwLogLevel.Fatal ? "fatal" : "error";
            await AppendTextSharedAsync(
                GetLogFilePath(nowUtc, category),
                jsonEntry + Environment.NewLine).ConfigureAwait(false);
        }
        catch (Exception secondEx)
        {
            Console.Error.WriteLine($"Failed to log error: {secondEx}");
        }
    }

    [DebuggerNonUserCode]
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

    [DebuggerNonUserCode]
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
            var segmentLine = FormatJsonEntry(BmwLogLevel.Info, "Log segment complete; cycling to next segment.", null, null, null);
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
            lines.Add(FormatJsonEntry(BmwLogLevel.Info, "Clean shutdown completed.", null, null, null));
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
