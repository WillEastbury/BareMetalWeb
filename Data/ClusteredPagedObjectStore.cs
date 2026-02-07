using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Text;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Data;

public sealed class ClusteredPagedObjectStore
{
    private const string DataFileName = "clustered";
    private const int DefaultPageSize = 16384;
    private const uint HeaderMagic = 0x31504C43; // "CLP1"
    private const int HeaderVersion = 1;
    private const int HeaderMagicOffset = 0;
    private const int HeaderVersionOffset = 4;
    private const int HeaderPageSizeOffset = 8;
    private const int HeaderLastPageOffset = 16;
    private const int HeaderRecordCountOffset = 24;
    private const byte PageKindData = (byte)'D';
    private const byte PageKindOverflow = (byte)'O';
    private const byte PageKindOverflowCont = (byte)'C';
    private const byte PageKindDeleted = (byte)'X';
    private const int PageHeaderSize = 16;
    private const int OverflowHeaderSize = 16;
    private const int OverflowContinuationHeaderSize = 1;
    private const int SlotSize = 8;
    private const int RecordHeaderSize = 16;
    private const byte CompressionNone = 0;
    private const byte CompressionBrotli = 1;
    private const byte SlotFlagDeleted = 1;

    private readonly IDataProvider _provider;
    private readonly string _entityName;
    private readonly int _pageSize;
    private readonly IBufferedLogger? _logger;

    public ClusteredPagedObjectStore(IDataProvider provider, string entityName, int pageSize = DefaultPageSize, IBufferedLogger? logger = null)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _entityName = entityName ?? throw new ArgumentNullException(nameof(entityName));
        if (pageSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(pageSize), "Page size must be greater than zero.");

        _pageSize = pageSize;
        _logger = logger;
    }

    public string Write(string id, ReadOnlySpan<byte> payload)
    {
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("Id cannot be empty.", nameof(id));

        var idBytes = Encoding.UTF8.GetBytes(id);
        var compressed = CompressPayload(payload, out var compressionKind, out var uncompressedLength);
        var recordLength = RecordHeaderSize + idBytes.Length + compressed.Length;
        if (recordLength + SlotSize > _pageSize - PageHeaderSize)
            return WriteOverflow(idBytes, compressed, compressionKind, uncompressedLength);

        using var pagedFile = _provider.OpenPagedFile(_entityName, DataFileName, _pageSize, FileAccess.ReadWrite);
        var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
        try
        {
            var header = ReadHeader(pagedFile, buffer);
            var targetPage = header.LastPageIndex <= 0 ? 1 : header.LastPageIndex;
            if (!TryWriteRecordToPage(pagedFile, buffer, targetPage, idBytes, compressed, compressionKind, uncompressedLength, out var slotIndex))
            {
                targetPage = header.LastPageIndex + 1;
                WriteEmptyPage(pagedFile, buffer, targetPage);
                if (!TryWriteRecordToPage(pagedFile, buffer, targetPage, idBytes, compressed, compressionKind, uncompressedLength, out slotIndex))
                    throw new InvalidOperationException("Failed to write clustered record to a new page.");

                header.LastPageIndex = targetPage;
            }

            header.RecordCount++;
            WriteHeader(pagedFile, buffer, header);
            pagedFile.Flush();
            return FormatLocation(targetPage, slotIndex);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public byte[]? Read(string location)
    {
        if (!TryParseLocationInternal(location, out var isOverflow, out var pageIndex, out var slotIndex, out var pageCount))
            return null;

        if (isOverflow)
            return ReadOverflow(pageIndex, pageCount);

        using var pagedFile = _provider.OpenPagedFile(_entityName, DataFileName, _pageSize, FileAccess.Read);
        if (pagedFile.PageCount <= pageIndex)
            return null;

        var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
        try
        {
            var bytesRead = pagedFile.ReadPage(pageIndex, buffer);
            if (bytesRead == 0)
                return null;

            var span = buffer.AsSpan(0, pagedFile.PageSize);
            if (span[0] != PageKindData)
                return null;

            if (!TryReadSlot(span, slotIndex, out var offset, out var length, out var flags))
                return null;
            if ((flags & SlotFlagDeleted) != 0)
                return null;

            if (offset + length > pagedFile.PageSize)
                return null;

            var recordSpan = span.Slice(offset, length);
            if (!TryReadRecord(recordSpan, out var payload, out var compressionKind, out var uncompressedLength))
                return null;

            return DecompressPayload(payload, compressionKind, uncompressedLength);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public bool Delete(string location)
    {
        if (!TryParseLocationInternal(location, out var isOverflow, out var pageIndex, out var slotIndex, out var pageCount))
            return false;

        if (isOverflow)
            return DeleteOverflow(pageIndex, pageCount);

        using var pagedFile = _provider.OpenPagedFile(_entityName, DataFileName, _pageSize, FileAccess.ReadWrite);
        if (pagedFile.PageCount <= pageIndex)
            return false;

        var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
        try
        {
            var bytesRead = pagedFile.ReadPage(pageIndex, buffer);
            if (bytesRead == 0)
                return false;

            var span = buffer.AsSpan(0, pagedFile.PageSize);
            if (span[0] != PageKindData)
                return false;

            if (!TryReadSlot(span, slotIndex, out var offset, out var length, out var flags))
                return false;
            if ((flags & SlotFlagDeleted) != 0)
                return false;

            WriteSlot(span, slotIndex, offset, length, (byte)(flags | SlotFlagDeleted));
            pagedFile.WritePage(pageIndex, span);
            pagedFile.Flush();
            return true;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public bool Exists()
    {
        return _provider.PagedFileExists(_entityName, DataFileName);
    }

    public Dictionary<string, string> Compact(IReadOnlyDictionary<string, string> liveLocations)
    {
        if (liveLocations == null || liveLocations.Count == 0)
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var payloads = new List<(string Id, byte[] Payload)>(liveLocations.Count);
        foreach (var entry in liveLocations)
        {
            var bytes = Read(entry.Value);
            if (bytes != null)
                payloads.Add((entry.Key, bytes));
        }

        if (_provider.PagedFileExists(_entityName, DataFileName))
            _provider.DeletePagedFileAsync(_entityName, DataFileName).AsTask().GetAwaiter().GetResult();

        var newMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in payloads)
        {
            var location = Write(entry.Id, entry.Payload);
            newMap[entry.Id] = location;
        }

        _logger?.LogInfo($"Clustered compaction complete for {_entityName}. Records={newMap.Count}.");
        return newMap;
    }

    private static byte[] CompressPayload(ReadOnlySpan<byte> payload, out byte compressionKind, out int uncompressedLength)
    {
        uncompressedLength = payload.Length;
        if (payload.Length == 0)
        {
            compressionKind = CompressionNone;
            return Array.Empty<byte>();
        }

        using var output = new MemoryStream();
        using (var brotli = new BrotliStream(output, CompressionLevel.Fastest, leaveOpen: true))
        {
            brotli.Write(payload);
        }

        var compressed = output.ToArray();
        if (compressed.Length >= payload.Length)
        {
            compressionKind = CompressionNone;
            return payload.ToArray();
        }

        compressionKind = CompressionBrotli;
        return compressed;
    }

    private static byte[] DecompressPayload(ReadOnlySpan<byte> payload, byte compressionKind, int uncompressedLength)
    {
        if (compressionKind == CompressionNone)
            return payload.ToArray();

        using var input = new MemoryStream(payload.ToArray());
        using var brotli = new BrotliStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream(uncompressedLength > 0 ? uncompressedLength : 0);
        brotli.CopyTo(output);
        return output.ToArray();
    }

    private static string FormatLocation(long pageIndex, ushort slotIndex)
    {
        return string.Concat(pageIndex.ToString(), ":", slotIndex.ToString());
    }

    private static string FormatOverflowLocation(long pageIndex, int pageCount)
    {
        return string.Concat("o:", pageIndex.ToString(), ":", pageCount.ToString());
    }

    public static bool TryParseLocation(string value, out long pageIndex, out ushort slotIndex)
    {
        pageIndex = 0;
        slotIndex = 0;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        if (value.StartsWith("o:", StringComparison.OrdinalIgnoreCase))
            return false;

        var parts = value.Split(':');
        if (parts.Length != 2)
            return false;

        if (!long.TryParse(parts[0], out pageIndex))
            return false;
        if (!ushort.TryParse(parts[1], out slotIndex))
            return false;

        return pageIndex > 0;
    }

    private static bool TryParseLocationInternal(string value, out bool isOverflow, out long pageIndex, out ushort slotIndex, out int pageCount)
    {
        isOverflow = false;
        pageIndex = 0;
        slotIndex = 0;
        pageCount = 0;

        if (string.IsNullOrWhiteSpace(value))
            return false;

        if (value.StartsWith("o:", StringComparison.OrdinalIgnoreCase))
        {
            var parts = value.Split(':');
            if (parts.Length != 3)
                return false;
            if (!long.TryParse(parts[1], out pageIndex))
                return false;
            if (!int.TryParse(parts[2], out pageCount))
                return false;
            if (pageIndex <= 0 || pageCount <= 0)
                return false;

            isOverflow = true;
            return true;
        }

        var standardParts = value.Split(':');
        if (standardParts.Length != 2)
            return false;

        if (!long.TryParse(standardParts[0], out pageIndex))
            return false;
        if (!ushort.TryParse(standardParts[1], out slotIndex))
            return false;
        if (pageIndex <= 0)
            return false;

        pageCount = 1;
        return true;
    }

    private bool TryWriteRecordToPage(IPagedFile pagedFile, byte[] buffer, long pageIndex, byte[] idBytes, byte[] payloadBytes, byte compressionKind, int uncompressedLength, out ushort slotIndex)
    {
        slotIndex = 0;
        var span = buffer.AsSpan(0, pagedFile.PageSize);
        span.Clear();

        if (pagedFile.PageCount > pageIndex)
        {
            var bytesRead = pagedFile.ReadPage(pageIndex, buffer);
            if (bytesRead == 0)
                span.Clear();
        }

        if (span[0] != PageKindData)
            InitializePage(span);

        ReadPageHeader(span, out var slotCount, out var freeStart, out var freeEnd);
        var recordLength = RecordHeaderSize + idBytes.Length + payloadBytes.Length;
        var newFreeEnd = (ushort)(freeEnd - SlotSize);
        if (freeStart + recordLength > newFreeEnd)
            return false;

        var recordOffset = freeStart;
        WriteRecord(span.Slice(recordOffset, recordLength), idBytes, payloadBytes, compressionKind, uncompressedLength);

        slotIndex = slotCount;
        WriteSlot(span, slotIndex, recordOffset, (ushort)recordLength, 0);

        slotCount++;
        freeStart = (ushort)(freeStart + recordLength);
        freeEnd = newFreeEnd;
        WritePageHeader(span, slotCount, freeStart, freeEnd);

        pagedFile.WritePage(pageIndex, span);
        return true;
    }

    private static void WriteRecord(Span<byte> destination, byte[] idBytes, byte[] payloadBytes, byte compressionKind, int uncompressedLength)
    {
        destination.Clear();
        destination[0] = 0;
        destination[1] = compressionKind;
        BinaryPrimitives.WriteUInt16LittleEndian(destination.Slice(2, 2), (ushort)idBytes.Length);
        BinaryPrimitives.WriteInt32LittleEndian(destination.Slice(4, 4), payloadBytes.Length);
        BinaryPrimitives.WriteInt32LittleEndian(destination.Slice(8, 4), uncompressedLength);
        BinaryPrimitives.WriteInt32LittleEndian(destination.Slice(12, 4), 0);

        idBytes.CopyTo(destination.Slice(RecordHeaderSize, idBytes.Length));
        payloadBytes.CopyTo(destination.Slice(RecordHeaderSize + idBytes.Length, payloadBytes.Length));
    }

    private static bool TryReadRecord(ReadOnlySpan<byte> recordSpan, out ReadOnlySpan<byte> payload, out byte compressionKind, out int uncompressedLength)
    {
        payload = ReadOnlySpan<byte>.Empty;
        compressionKind = CompressionNone;
        uncompressedLength = 0;
        if (recordSpan.Length < RecordHeaderSize)
            return false;

        compressionKind = recordSpan[1];
        var idLength = BinaryPrimitives.ReadUInt16LittleEndian(recordSpan.Slice(2, 2));
        var payloadLength = BinaryPrimitives.ReadInt32LittleEndian(recordSpan.Slice(4, 4));
        uncompressedLength = BinaryPrimitives.ReadInt32LittleEndian(recordSpan.Slice(8, 4));

        var totalLength = RecordHeaderSize + idLength + payloadLength;
        if (payloadLength < 0 || totalLength > recordSpan.Length)
            return false;

        payload = recordSpan.Slice(RecordHeaderSize + idLength, payloadLength);
        return true;
    }

    private string WriteOverflow(byte[] idBytes, byte[] payloadBytes, byte compressionKind, int uncompressedLength)
    {
        var totalPayloadBytes = idBytes.Length + payloadBytes.Length;
        var firstCapacity = _pageSize - OverflowHeaderSize;
        var remaining = Math.Max(0, totalPayloadBytes - firstCapacity);
        var contCapacity = _pageSize - OverflowContinuationHeaderSize;
        var pageCount = 1 + (remaining == 0 ? 0 : (remaining + contCapacity - 1) / contCapacity);

        using var pagedFile = _provider.OpenPagedFile(_entityName, DataFileName, _pageSize, FileAccess.ReadWrite);
        var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
        try
        {
            var header = ReadHeader(pagedFile, buffer);
            var startPage = header.LastPageIndex <= 0 ? 1 : header.LastPageIndex + 1;

            var idOffset = 0;
            var payloadOffset = 0;
            var bytesRemaining = totalPayloadBytes;

            for (var pageIndex = 0; pageIndex < pageCount; pageIndex++)
            {
                var span = buffer.AsSpan(0, pagedFile.PageSize);
                span.Clear();

                if (pageIndex == 0)
                {
                    span[0] = PageKindOverflow;
                    span[1] = compressionKind;
                    BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(2, 2), (ushort)idBytes.Length);
                    BinaryPrimitives.WriteInt32LittleEndian(span.Slice(4, 4), payloadBytes.Length);
                    BinaryPrimitives.WriteInt32LittleEndian(span.Slice(8, 4), uncompressedLength);
                    BinaryPrimitives.WriteInt32LittleEndian(span.Slice(12, 4), pageCount);

                    var capacity = _pageSize - OverflowHeaderSize;
                    var toCopy = Math.Min(capacity, bytesRemaining);
                    CopyPayloadSlice(span.Slice(OverflowHeaderSize, toCopy), idBytes, payloadBytes, ref idOffset, ref payloadOffset, toCopy);
                    bytesRemaining -= toCopy;
                }
                else
                {
                    span[0] = PageKindOverflowCont;
                    var capacity = _pageSize - OverflowContinuationHeaderSize;
                    var toCopy = Math.Min(capacity, bytesRemaining);
                    CopyPayloadSlice(span.Slice(OverflowContinuationHeaderSize, toCopy), idBytes, payloadBytes, ref idOffset, ref payloadOffset, toCopy);
                    bytesRemaining -= toCopy;
                }

                pagedFile.WritePage(startPage + pageIndex, span);
            }

            header.LastPageIndex = startPage + pageCount - 1;
            header.RecordCount++;
            WriteHeader(pagedFile, buffer, header);
            pagedFile.Flush();
            return FormatOverflowLocation(startPage, pageCount);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private byte[]? ReadOverflow(long pageIndex, int pageCount)
    {
        using var pagedFile = _provider.OpenPagedFile(_entityName, DataFileName, _pageSize, FileAccess.Read);
        if (pagedFile.PageCount <= pageIndex)
            return null;

        var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
        try
        {
            var bytesRead = pagedFile.ReadPage(pageIndex, buffer);
            if (bytesRead == 0)
                return null;

            var span = buffer.AsSpan(0, pagedFile.PageSize);
            if (span[0] != PageKindOverflow)
                return null;

            var compressionKind = span[1];
            var idLength = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2, 2));
            var payloadLength = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(4, 4));
            var uncompressedLength = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(8, 4));
            var recordedPageCount = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(12, 4));
            if (payloadLength < 0 || recordedPageCount != pageCount)
                return null;

            var totalPayloadBytes = idLength + payloadLength;
            var combined = new byte[totalPayloadBytes];
            var copied = 0;

            var firstCapacity = _pageSize - OverflowHeaderSize;
            var firstCopy = Math.Min(firstCapacity, totalPayloadBytes);
            if (firstCopy > 0)
            {
                span.Slice(OverflowHeaderSize, firstCopy).CopyTo(combined.AsSpan(0, firstCopy));
                copied = firstCopy;
            }

            for (var i = 1; i < pageCount; i++)
            {
                var read = pagedFile.ReadPage(pageIndex + i, buffer);
                if (read == 0)
                    return null;

                var nextSpan = buffer.AsSpan(0, pagedFile.PageSize);
                if (nextSpan[0] != PageKindOverflowCont)
                    return null;

                var remaining = totalPayloadBytes - copied;
                var capacity = _pageSize - OverflowContinuationHeaderSize;
                var toCopy = Math.Min(capacity, remaining);
                if (toCopy > 0)
                {
                    nextSpan.Slice(OverflowContinuationHeaderSize, toCopy).CopyTo(combined.AsSpan(copied, toCopy));
                    copied += toCopy;
                }
            }

            if (copied != totalPayloadBytes)
                return null;

            var payloadSpan = combined.AsSpan(idLength, payloadLength);
            return DecompressPayload(payloadSpan, compressionKind, uncompressedLength);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private bool DeleteOverflow(long pageIndex, int pageCount)
    {
        using var pagedFile = _provider.OpenPagedFile(_entityName, DataFileName, _pageSize, FileAccess.ReadWrite);
        if (pagedFile.PageCount <= pageIndex)
            return false;

        var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
        try
        {
            for (var i = 0; i < pageCount; i++)
            {
                var bytesRead = pagedFile.ReadPage(pageIndex + i, buffer);
                if (bytesRead == 0)
                    continue;

                var span = buffer.AsSpan(0, pagedFile.PageSize);
                span[0] = PageKindDeleted;
                pagedFile.WritePage(pageIndex + i, span);
            }

            pagedFile.Flush();
            return true;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static void CopyPayloadSlice(Span<byte> destination, byte[] idBytes, byte[] payloadBytes, ref int idOffset, ref int payloadOffset, int length)
    {
        var remaining = length;
        var destOffset = 0;
        if (idOffset < idBytes.Length)
        {
            var take = Math.Min(remaining, idBytes.Length - idOffset);
            idBytes.AsSpan(idOffset, take).CopyTo(destination.Slice(destOffset, take));
            idOffset += take;
            destOffset += take;
            remaining -= take;
        }

        if (remaining > 0)
        {
            var take = Math.Min(remaining, payloadBytes.Length - payloadOffset);
            payloadBytes.AsSpan(payloadOffset, take).CopyTo(destination.Slice(destOffset, take));
            payloadOffset += take;
        }
    }

    private static void WriteEmptyPage(IPagedFile pagedFile, byte[] buffer, long pageIndex)
    {
        var span = buffer.AsSpan(0, pagedFile.PageSize);
        span.Clear();
        InitializePage(span);
        pagedFile.WritePage(pageIndex, span);
    }

    private static void InitializePage(Span<byte> span)
    {
        span.Clear();
        span[0] = PageKindData;
        span[1] = 0;
        WritePageHeader(span, 0, PageHeaderSize, (ushort)span.Length);
    }

    private static void ReadPageHeader(ReadOnlySpan<byte> span, out ushort slotCount, out ushort freeStart, out ushort freeEnd)
    {
        slotCount = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(2, 2));
        freeStart = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(4, 2));
        freeEnd = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(6, 2));
        if (freeStart == 0 || freeEnd == 0)
        {
            slotCount = 0;
            freeStart = PageHeaderSize;
            freeEnd = (ushort)span.Length;
        }
    }

    private static void WritePageHeader(Span<byte> span, ushort slotCount, ushort freeStart, ushort freeEnd)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(2, 2), slotCount);
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(4, 2), freeStart);
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(6, 2), freeEnd);
    }

    private static void WriteSlot(Span<byte> span, ushort slotIndex, ushort offset, ushort length, byte flags)
    {
        var slotOffset = span.Length - ((slotIndex + 1) * SlotSize);
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(slotOffset, 2), offset);
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(slotOffset + 2, 2), length);
        span[slotOffset + 4] = flags;
        span[slotOffset + 5] = 0;
        BinaryPrimitives.WriteUInt16LittleEndian(span.Slice(slotOffset + 6, 2), 0);
    }

    private static bool TryReadSlot(ReadOnlySpan<byte> span, ushort slotIndex, out ushort offset, out ushort length, out byte flags)
    {
        offset = 0;
        length = 0;
        flags = 0;

        var slotOffset = span.Length - ((slotIndex + 1) * SlotSize);
        if (slotOffset < PageHeaderSize)
            return false;

        offset = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(slotOffset, 2));
        length = BinaryPrimitives.ReadUInt16LittleEndian(span.Slice(slotOffset + 2, 2));
        flags = span[slotOffset + 4];
        return length > 0;
    }

    private ClusteredHeader ReadHeader(IPagedFile pagedFile, byte[] buffer)
    {
        if (pagedFile.PageCount == 0)
        {
            var header = new ClusteredHeader(0, 0);
            WriteHeader(pagedFile, buffer, header);
            return header;
        }

        var bytesRead = pagedFile.ReadPage(0, buffer);
        if (bytesRead == 0)
        {
            var header = new ClusteredHeader(0, 0);
            WriteHeader(pagedFile, buffer, header);
            return header;
        }

        var span = buffer.AsSpan(0, pagedFile.PageSize);
        var magic = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(HeaderMagicOffset, 4));
        if (magic != HeaderMagic)
            throw new InvalidOperationException("Clustered file header magic mismatch.");

        var version = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(HeaderVersionOffset, 4));
        if (version != HeaderVersion)
            throw new InvalidOperationException("Clustered file header version mismatch.");

        var pageSize = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(HeaderPageSizeOffset, 4));
        if (pageSize != pagedFile.PageSize)
            throw new InvalidOperationException("Clustered file page size mismatch.");

        var lastPage = BinaryPrimitives.ReadInt64LittleEndian(span.Slice(HeaderLastPageOffset, 8));
        var recordCount = BinaryPrimitives.ReadInt64LittleEndian(span.Slice(HeaderRecordCountOffset, 8));
        return new ClusteredHeader(lastPage, recordCount);
    }

    private void WriteHeader(IPagedFile pagedFile, byte[] buffer, ClusteredHeader header)
    {
        var span = buffer.AsSpan(0, pagedFile.PageSize);
        span.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(HeaderMagicOffset, 4), HeaderMagic);
        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(HeaderVersionOffset, 4), HeaderVersion);
        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(HeaderPageSizeOffset, 4), pagedFile.PageSize);
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(HeaderLastPageOffset, 8), header.LastPageIndex);
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(HeaderRecordCountOffset, 8), header.RecordCount);
        pagedFile.WritePage(0, span);
    }

    private struct ClusteredHeader
    {
        public ClusteredHeader(long lastPageIndex, long recordCount)
        {
            LastPageIndex = lastPageIndex;
            RecordCount = recordCount;
        }

        public long LastPageIndex { get; set; }
        public long RecordCount { get; set; }
    }
}
