using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.MemoryMappedFiles;
using BareMetalWeb.Core.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// Read-only <see cref="IPagedFile"/> implementation backed by a <see cref="MemoryMappedFile"/>.
/// Used for index file loading where random-access page reads benefit from the OS page cache
/// without per-read FileStream seek overhead.
/// <para>
/// Parses the same header format as <see cref="LocalPagedFile"/>:
/// page 0 = header (magic, version, pageSize, mapPageCount, dataStartPage),
/// pages 1..N = allocation map, pages N+1.. = data pages.
/// </para>
/// </summary>
internal sealed class MappedPagedFile : IPagedFile
{
    private const uint HeaderMagic = 0x50414745; // 'PAGE'
    private const int HeaderVersion = 1;
    private const int HeaderMagicOffset = 0;
    private const int HeaderVersionOffset = 4;
    private const int HeaderPageSizeOffset = 8;
    private const int HeaderMapPageCountOffset = 12;
    private const int HeaderDataStartOffset = 16;

    private readonly MemoryMappedFile _mmf;
    private readonly MemoryMappedViewAccessor _accessor;
    private int _pageSize;
    private int _dataStartPage;
    private readonly long _fileLength;
    private volatile bool _disposed;

    public MappedPagedFile(string filePath, int expectedPageSize)
    {
        var fi = new FileInfo(filePath);
        _fileLength = fi.Length;
        if (_fileLength == 0)
            throw new InvalidOperationException("Cannot map empty paged file.");

        _mmf = MemoryMappedFile.CreateFromFile(filePath, FileMode.Open, null, 0,
            MemoryMappedFileAccess.Read);
        _accessor = _mmf.CreateViewAccessor(0, _fileLength, MemoryMappedFileAccess.Read);

        try
        {
            ReadAndValidateHeader(expectedPageSize);
        }
        catch
        {
            _accessor.Dispose();
            _mmf.Dispose();
            throw;
        }
    }

    public int PageSize => _pageSize;

    public long Length => _fileLength;

    public long PageCount
    {
        get
        {
            var totalPages = (_fileLength + _pageSize - 1) / _pageSize;
            return Math.Max(0, totalPages - _dataStartPage);
        }
    }

    public bool CanWrite => false;

    /// <summary>
    /// Reads a data page from the memory-mapped file into the caller's buffer.
    /// Returns the number of bytes read (may be less than page size near end of file).
    /// </summary>
    public unsafe int ReadPage(long pageIndex, Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (buffer.Length < _pageSize)
            throw new ArgumentException("Buffer must be at least one page in size.", nameof(buffer));

        long offset = (pageIndex + _dataStartPage) * (long)_pageSize;
        if (offset >= _fileLength)
            return 0;

        int available = (int)Math.Min(_pageSize, _fileLength - offset);
        if (available <= 0) return 0;

        byte* ptr = null;
        _accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
        try
        {
            new ReadOnlySpan<byte>(ptr + _accessor.PointerOffset + offset, available)
                .CopyTo(buffer);
            return available;
        }
        finally
        {
            _accessor.SafeMemoryMappedViewHandle.ReleasePointer();
        }
    }

    public void WritePage(long pageIndex, ReadOnlySpan<byte> data)
        => throw new NotSupportedException("MappedPagedFile is read-only.");

    public void Flush() { /* no-op for read-only mapping */ }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _accessor.Dispose();
        _mmf.Dispose();
    }

    private unsafe void ReadAndValidateHeader(int expectedPageSize)
    {
        if (_fileLength < 20) // minimum header: magic(4)+ver(4)+pageSize(4)+mapCount(4)+dataStart(4)
            throw new InvalidOperationException("Paged file too small for header.");

        byte* ptr = null;
        _accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
        try
        {
            var header = new ReadOnlySpan<byte>(ptr + _accessor.PointerOffset, Math.Min(20, (int)_fileLength));

            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(header.Slice(HeaderMagicOffset, 4));
            if (magic != HeaderMagic)
                throw new InvalidOperationException("Paged file header magic mismatch.");

            int version = BinaryPrimitives.ReadInt32LittleEndian(header.Slice(HeaderVersionOffset, 4));
            if (version != HeaderVersion)
                throw new InvalidOperationException("Paged file header version mismatch.");

            int pageSize = BinaryPrimitives.ReadInt32LittleEndian(header.Slice(HeaderPageSizeOffset, 4));
            if (pageSize != expectedPageSize)
                throw new InvalidOperationException("Paged file page size mismatch.");

            int mapPageCount = BinaryPrimitives.ReadInt32LittleEndian(header.Slice(HeaderMapPageCountOffset, 4));
            if (mapPageCount <= 0)
                throw new InvalidOperationException("Paged file map page count invalid.");

            int dataStartPage = BinaryPrimitives.ReadInt32LittleEndian(header.Slice(HeaderDataStartOffset, 4));
            if (dataStartPage <= 0)
                throw new InvalidOperationException("Paged file data start invalid.");

            _pageSize = pageSize;
            _dataStartPage = dataStartPage;
        }
        finally
        {
            _accessor.SafeMemoryMappedViewHandle.ReleasePointer();
        }
    }
}
