namespace BareMetalWeb.Data.PageStore;

/// <summary>
/// Represents a single write operation to be queued and processed by an extent writer.
/// </summary>
public sealed class WriteCommand
{
    public WriteCommand(long pageId, byte[] data, long? expectedVersion, TaskCompletionSource<WriteResult> completion)
    {
        PageId = pageId;
        Data = data ?? throw new ArgumentNullException(nameof(data));
        ExpectedVersion = expectedVersion;
        Completion = completion ?? throw new ArgumentNullException(nameof(completion));
    }

    /// <summary>
    /// The page ID to write to.
    /// </summary>
    public long PageId { get; }

    /// <summary>
    /// The data to write.
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Expected version for optimistic concurrency control. Null means no version check.
    /// </summary>
    public long? ExpectedVersion { get; }

    /// <summary>
    /// Completion source to signal when the write is done.
    /// </summary>
    public TaskCompletionSource<WriteResult> Completion { get; }
}
