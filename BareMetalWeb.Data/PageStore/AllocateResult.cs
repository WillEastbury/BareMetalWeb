namespace BareMetalWeb.Data.PageStore;

/// <summary>
/// Result of a page allocation operation.
/// </summary>
public sealed class AllocateResult
{
    public AllocateResult(bool success, long pageId, long version, string? errorMessage = null)
    {
        Success = success;
        PageId = pageId;
        Version = version;
        ErrorMessage = errorMessage;
    }

    /// <summary>
    /// Whether the allocation succeeded.
    /// </summary>
    public bool Success { get; }

    /// <summary>
    /// The allocated page ID.
    /// </summary>
    public long PageId { get; }

    /// <summary>
    /// The initial version of the page.
    /// </summary>
    public long Version { get; }

    /// <summary>
    /// Error message if the allocation failed.
    /// </summary>
    public string? ErrorMessage { get; }

    public static AllocateResult SuccessResult(long pageId, long version) => new AllocateResult(true, pageId, version);
    
    public static AllocateResult FailureResult(string errorMessage) => new AllocateResult(false, 0, 0, errorMessage);
}
