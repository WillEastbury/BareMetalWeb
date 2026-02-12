namespace BareMetalWeb.Data.PageStore;

/// <summary>
/// Metadata for a single page in the page store.
/// </summary>
public readonly struct PageMetadata
{
    public PageMetadata(long pageId, long version, int size, bool exists)
    {
        PageId = pageId;
        Version = version;
        Size = size;
        Exists = exists;
    }

    /// <summary>
    /// Unique identifier for the page.
    /// </summary>
    public long PageId { get; }

    /// <summary>
    /// Monotonic version/LSN for optimistic concurrency control.
    /// </summary>
    public long Version { get; }

    /// <summary>
    /// Size of the page data in bytes.
    /// </summary>
    public int Size { get; }

    /// <summary>
    /// Whether the page exists and is not deleted.
    /// </summary>
    public bool Exists { get; }
}
