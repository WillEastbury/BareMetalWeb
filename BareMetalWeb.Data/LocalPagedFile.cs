using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Core.Interfaces;

namespace BareMetalWeb.Data;

/// <summary>
/// File-backed implementation of <see cref="IPagedFile"/> used by
/// <see cref="WalDataProvider"/> for secondary index paged storage.
/// </summary>
internal sealed class LocalPagedFile : IPagedFile
{
    private const uint HeaderMagic = 0x50414745; // 'PAGE'
    private const int HeaderVersion = 1;
    private const int HeaderMagicOffset = 0;
    private const int HeaderVersionOffset = 4;
    private const int HeaderPageSizeOffset = 8;
    private const int HeaderMapPageCountOffset = 12;
    private const int HeaderDataStartOffset = 16;

    private readonly FileStream _stream;
    private readonly int _pageSize;
    private int _mapPageCount;
    private int _dataStartPage;
    private byte[] _mapBytes;
    private readonly byte[] _pageCache;
    private bool _mapDirty;
    private bool _cacheDirty;
    private long _cachedPageIndex = -1;

    public LocalPagedFile(FileStream stream, int pageSize)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        if (pageSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(pageSize), "Page size must be greater than zero.");

        _pageSize = pageSize;
        _mapPageCount = 1;
        _dataStartPage = 1 + _mapPageCount;
        _mapBytes = ArrayPool<byte>.Shared.Rent(_pageSize * _mapPageCount);
        _pageCache = ArrayPool<byte>.Shared.Rent(_pageSize);
        Array.Clear(_mapBytes, 0, _pageSize * _mapPageCount);

        try
        {
            InitializeOrLoad();
        }
        catch
        {
            ArrayPool<byte>.Shared.Return(_mapBytes);
            ArrayPool<byte>.Shared.Return(_pageCache);
            throw;
        }
    }

    public int PageSize => _pageSize;

    public long Length => _stream.Length;

    public long PageCount
    {
        get
        {
            var totalPages = (_stream.Length + _pageSize - 1) / _pageSize;
            return Math.Max(0, totalPages - _dataStartPage);
        }
    }

    public bool CanWrite => _stream.CanWrite;

    public int ReadPage(long pageIndex, Span<byte> buffer)
    {
        if (buffer.Length < _pageSize)
            throw new ArgumentException("Buffer must be at least one page in size.", nameof(buffer));

        var bytesRead = EnsureCacheLoaded(pageIndex);
        if (bytesRead == 0)
            return 0;

        _pageCache.AsSpan(0, bytesRead).CopyTo(buffer);
        return bytesRead;
    }

    public void WritePage(long pageIndex, ReadOnlySpan<byte> data)
    {
        EnsureWritable();
        if (data.Length != _pageSize)
            throw new ArgumentException("Data must be exactly one page in size.", nameof(data));

        EnsureCacheForWrite(pageIndex);
        data.CopyTo(_pageCache.AsSpan(0, _pageSize));
        _cacheDirty = true;
        MarkPageAllocated(pageIndex);
    }

    public void Flush()
    {
        FlushCache();
        FlushMap();
        _stream.Flush();
    }

    public void Dispose()
    {
        try
        {
            Flush();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(_mapBytes);
            ArrayPool<byte>.Shared.Return(_pageCache);
            _stream.Dispose();
        }
    }

    private void InitializeOrLoad()
    {
        if (_stream.Length == 0)
        {
            if (!_stream.CanWrite)
                throw new InvalidOperationException("Cannot initialize a read-only paged file.");

            WriteHeader();
            WriteMapPages();
            _stream.Flush();
            return;
        }

        ReadHeader();
        EnsureMapBufferSize();
        ReadMapPages();
    }

    private void WriteHeader()
    {
        var buffer = ArrayPool<byte>.Shared.Rent(_pageSize);
        try
        {
            Array.Clear(buffer, 0, _pageSize);
            var span = buffer.AsSpan(0, _pageSize);
            BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(HeaderMagicOffset, 4), HeaderMagic);
            BinaryPrimitives.WriteInt32LittleEndian(span.Slice(HeaderVersionOffset, 4), HeaderVersion);
            BinaryPrimitives.WriteInt32LittleEndian(span.Slice(HeaderPageSizeOffset, 4), _pageSize);
            BinaryPrimitives.WriteInt32LittleEndian(span.Slice(HeaderMapPageCountOffset, 4), _mapPageCount);
            BinaryPrimitives.WriteInt32LittleEndian(span.Slice(HeaderDataStartOffset, 4), _dataStartPage);
            _stream.Seek(0, SeekOrigin.Begin);
            _stream.Write(span);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private void ReadHeader()
    {
        var buffer = ArrayPool<byte>.Shared.Rent(_pageSize);
        try
        {
            var span = buffer.AsSpan(0, _pageSize);
            _stream.Seek(0, SeekOrigin.Begin);
            ReadExact(span);

            var magic = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(HeaderMagicOffset, 4));
            if (magic != HeaderMagic)
                throw new InvalidOperationException("Paged file header magic mismatch.");

            var version = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(HeaderVersionOffset, 4));
            if (version != HeaderVersion)
                throw new InvalidOperationException("Paged file header version mismatch.");

            var pageSize = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(HeaderPageSizeOffset, 4));
            if (pageSize != _pageSize)
                throw new InvalidOperationException("Paged file page size mismatch.");

            var mapPageCount = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(HeaderMapPageCountOffset, 4));
            if (mapPageCount <= 0)
                throw new InvalidOperationException("Paged file map page count invalid.");

            var dataStartPage = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(HeaderDataStartOffset, 4));
            if (dataStartPage <= 0)
                throw new InvalidOperationException("Paged file data start invalid.");

            _mapPageCount = mapPageCount;
            _dataStartPage = dataStartPage;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private void WriteMapPages()
    {
        _stream.Seek(_pageSize, SeekOrigin.Begin);
        _stream.Write(_mapBytes, 0, _pageSize * _mapPageCount);
        _mapDirty = false;
    }

    private void ReadMapPages()
    {
        _stream.Seek(_pageSize, SeekOrigin.Begin);
        var length = _pageSize * _mapPageCount;
        var bytesRead = ReadExact(_mapBytes.AsSpan(0, length));
        if (bytesRead < length)
            Array.Clear(_mapBytes, bytesRead, length - bytesRead);
    }

    private int EnsureCacheLoaded(long pageIndex)
    {
        if (_cachedPageIndex == pageIndex)
            return _cacheDirty ? _pageSize : GetCachedBytesAvailable(pageIndex);

        FlushCache();
        _cachedPageIndex = pageIndex;
        _cacheDirty = false;
        return ReadPageIntoCache(pageIndex);
    }

    private void EnsureCacheForWrite(long pageIndex)
    {
        if (_cachedPageIndex == pageIndex)
            return;

        FlushCache();
        _cachedPageIndex = pageIndex;
        _cacheDirty = false;
    }

    private int ReadPageIntoCache(long pageIndex)
    {
        var offset = GetOffset(pageIndex);
        if (offset >= _stream.Length)
        {
            Array.Clear(_pageCache, 0, _pageSize);
            return 0;
        }

        _stream.Seek(offset, SeekOrigin.Begin);
        var bytesRead = ReadExact(_pageCache.AsSpan(0, _pageSize));
        if (bytesRead < _pageSize)
            Array.Clear(_pageCache, bytesRead, _pageSize - bytesRead);
        return bytesRead;
    }

    private void FlushCache()
    {
        if (!_cacheDirty || _cachedPageIndex < 0)
            return;

        WriteCacheToDisk();
    }

    private void WriteCacheToDisk()
    {
        var offset = GetOffset(_cachedPageIndex);
        _stream.Seek(offset, SeekOrigin.Begin);
        _stream.Write(_pageCache, 0, _pageSize);
        _cacheDirty = false;
    }

    private void FlushMap()
    {
        if (!_mapDirty)
            return;

        WriteMapPages();
    }

    private void MarkPageAllocated(long pageIndex)
    {
        EnsureMapCapacity(pageIndex);
        var mapCapacity = (long)_mapPageCount * _pageSize * 8;
        if (pageIndex >= mapCapacity)
            throw new InvalidOperationException("Page index exceeds map capacity.");

        var bitIndex = pageIndex;
        var byteIndex = bitIndex / 8;
        if (byteIndex > int.MaxValue)
            throw new InvalidOperationException("Page index exceeds supported map size.");

        var byteIndexInt = (int)byteIndex;
        var bitOffset = (int)(bitIndex % 8);
        var mask = (byte)(1 << bitOffset);
        if ((_mapBytes[byteIndexInt] & mask) == 0)
        {
            _mapBytes[byteIndexInt] |= mask;
            _mapDirty = true;
        }
    }

    private int ReadExact(Span<byte> buffer)
    {
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = _stream.Read(buffer.Slice(totalRead));
            if (read == 0)
                break;
            totalRead += read;
        }
        return totalRead;
    }

    private int GetCachedBytesAvailable(long pageIndex)
    {
        var remaining = _stream.Length - GetOffset(pageIndex);
        if (remaining <= 0)
            return 0;

        var available = Math.Min((long)_pageSize, remaining);
        return (int)available;
    }

    private long GetOffset(long pageIndex)
    {
        if (pageIndex < 0)
            throw new ArgumentOutOfRangeException(nameof(pageIndex), "Page index cannot be negative.");
        if (pageIndex > long.MaxValue / _pageSize)
            throw new ArgumentOutOfRangeException(nameof(pageIndex), "Page index is too large.");

        return (pageIndex + _dataStartPage) * (long)_pageSize;
    }

    private void EnsureMapBufferSize()
    {
        var requiredLength = _pageSize * _mapPageCount;
        if (_mapBytes.Length >= requiredLength)
            return;

        var newBuffer = ArrayPool<byte>.Shared.Rent(requiredLength);
        Array.Copy(_mapBytes, newBuffer, Math.Min(_mapBytes.Length, requiredLength));
        ArrayPool<byte>.Shared.Return(_mapBytes);
        _mapBytes = newBuffer;
    }

    private void EnsureMapCapacity(long pageIndex)
    {
        var requiredBytes = (pageIndex / 8) + 1;
        var requiredMapPagesLong = (requiredBytes + _pageSize - 1) / _pageSize;
        if (requiredMapPagesLong > int.MaxValue)
            throw new InvalidOperationException("Paged file map exceeds supported size.");

        var requiredMapPages = (int)requiredMapPagesLong;
        if (requiredMapPages <= _mapPageCount)
            return;

        GrowMapPages(requiredMapPages);
    }

    private void GrowMapPages(int newMapPageCount)
    {
        if (newMapPageCount <= _mapPageCount)
            return;

        EnsureWritable();
        FlushCache();

        var deltaPages = newMapPageCount - _mapPageCount;
        var oldDataStartOffset = (long)_dataStartPage * _pageSize;
        var dataLength = Math.Max(0, _stream.Length - oldDataStartOffset);
        var shiftBytes = (long)deltaPages * _pageSize;

        if (dataLength > 0)
            ShiftDataForward(oldDataStartOffset, dataLength, shiftBytes);

        _mapPageCount = newMapPageCount;
        _dataStartPage = 1 + _mapPageCount;
        _cachedPageIndex = -1;
        _cacheDirty = false;
        Array.Clear(_pageCache, 0, _pageCache.Length);

        var requiredLength = _pageSize * _mapPageCount;
        var newBuffer = ArrayPool<byte>.Shared.Rent(requiredLength);
        Array.Copy(_mapBytes, newBuffer, _pageSize * (_mapPageCount - deltaPages));
        Array.Clear(newBuffer, _pageSize * (_mapPageCount - deltaPages), _pageSize * deltaPages);
        ArrayPool<byte>.Shared.Return(_mapBytes);
        _mapBytes = newBuffer;
        _mapDirty = true;

        WriteHeader();
        WriteMapPages();
    }

    private void ShiftDataForward(long oldDataStartOffset, long dataLength, long shiftBytes)
    {
        var newLength = _stream.Length + shiftBytes;
        _stream.SetLength(newLength);

        var buffer = ArrayPool<byte>.Shared.Rent(1024 * 1024);
        try
        {
            var remaining = dataLength;
            var readPos = oldDataStartOffset + dataLength;

            while (remaining > 0)
            {
                var chunk = (int)Math.Min(buffer.Length, remaining);
                readPos -= chunk;
                _stream.Seek(readPos, SeekOrigin.Begin);
                var bytesRead = ReadExact(buffer.AsSpan(0, chunk));
                _stream.Seek(readPos + shiftBytes, SeekOrigin.Begin);
                _stream.Write(buffer, 0, bytesRead);
                remaining -= bytesRead;
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private void EnsureWritable()
    {
        if (!_stream.CanWrite)
            throw new InvalidOperationException("Paged file is not writable.");
    }
}
