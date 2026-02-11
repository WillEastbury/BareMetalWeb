namespace BareMetalWeb.Core.Interfaces;

public interface IPagedFile : IDisposable
{
    int PageSize { get; }
    long Length { get; }
    long PageCount { get; }
    bool CanWrite { get; }

    int ReadPage(long pageIndex, Span<byte> buffer);
    ValueTask<int> ReadPageAsync(long pageIndex, Memory<byte> buffer, CancellationToken cancellationToken = default);

    void WritePage(long pageIndex, ReadOnlySpan<byte> data);
    ValueTask WritePageAsync(long pageIndex, ReadOnlyMemory<byte> data, CancellationToken cancellationToken = default);

    void Flush();
    ValueTask FlushAsync(CancellationToken cancellationToken = default);
}
