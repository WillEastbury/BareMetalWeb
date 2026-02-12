namespace BareMetalWeb.Data.PageStore;

/// <summary>
/// Represents a page allocation request.
/// </summary>
public sealed class AllocateCommand
{
    public AllocateCommand(byte[] data, TaskCompletionSource<AllocateResult> completion)
    {
        Data = data ?? throw new ArgumentNullException(nameof(data));
        Completion = completion ?? throw new ArgumentNullException(nameof(completion));
    }

    /// <summary>
    /// The initial data to write to the new page.
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Completion source to signal when the allocation is done.
    /// </summary>
    public TaskCompletionSource<AllocateResult> Completion { get; }
}
