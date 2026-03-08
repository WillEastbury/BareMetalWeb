namespace BareMetalWeb.Core.Interfaces;

public interface IBufferedLogger
{
    void LogInfo(string message);
    void LogError(string message, Exception ex);
    Task RunAsync(CancellationToken cancellationToken);
    void OnApplicationStopping(CancellationTokenSource cts, Task loggerTask);

    // ── Structured logging extensions (#1256) ──────────────────────────────

    /// <summary>Log at the specified level with an optional correlation ID.</summary>
    void Log(BmwLogLevel level, string message, string? correlationId = null) => LogInfo(message);

    /// <summary>Log an error with an optional correlation ID.</summary>
    void LogError(string message, Exception ex, string? correlationId = null) => LogError(message, ex);

    /// <summary>Log a structured entry with typed fields.</summary>
    void Log(BmwLogLevel level, string message, string? correlationId, LogFields? fields) => LogInfo(message);

    /// <summary>Returns true if the given level would be logged (for zero-alloc guard checks).</summary>
    bool IsEnabled(BmwLogLevel level) => true;

    /// <summary>The current minimum log level.</summary>
    BmwLogLevel MinimumLevel => BmwLogLevel.Info;
}

/// <summary>
/// Typed fields for structured log entries. Callers populate only the
/// fields relevant to their context — unpopulated fields are omitted
/// from the JSON output.
/// </summary>
public sealed class LogFields
{
    public string? Method { get; init; }
    public string? Path { get; init; }
    public int? StatusCode { get; init; }
    public double? DurationMs { get; init; }
    public string? UserId { get; init; }
    public string? SourceIp { get; init; }
    public string? Detail { get; init; }
}
