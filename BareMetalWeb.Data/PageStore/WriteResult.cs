namespace BareMetalWeb.Data.PageStore;

/// <summary>
/// Result of a write operation.
/// </summary>
public sealed class WriteResult
{
    public WriteResult(bool success, long newVersion, string? errorMessage = null)
    {
        Success = success;
        NewVersion = newVersion;
        ErrorMessage = errorMessage;
    }

    /// <summary>
    /// Whether the write succeeded.
    /// </summary>
    public bool Success { get; }

    /// <summary>
    /// The new version of the page after the write.
    /// </summary>
    public long NewVersion { get; }

    /// <summary>
    /// Error message if the write failed.
    /// </summary>
    public string? ErrorMessage { get; }

    public static WriteResult SuccessResult(long newVersion) => new WriteResult(true, newVersion);
    
    public static WriteResult FailureResult(string errorMessage) => new WriteResult(false, 0, errorMessage);
    
    public static WriteResult VersionMismatch(long currentVersion, long expectedVersion) 
        => new WriteResult(false, currentVersion, $"Version mismatch: expected {expectedVersion}, current {currentVersion}");
}
