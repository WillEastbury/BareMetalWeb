namespace BareMetalWeb.Core.Interfaces;

public interface IPagedFile : IDisposable
{
    int PageSize { get; }
    long Length { get; }
    long PageCount { get; }
    bool CanWrite { get; }

    int ReadPage(long pageIndex, Span<byte> buffer);
    void WritePage(long pageIndex, ReadOnlySpan<byte> data);
    void Flush();
}
