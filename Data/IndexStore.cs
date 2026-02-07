using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;
using BareMetalWeb.Interfaces;

namespace BareMetalWeb.Data;

public sealed class IndexStore
{
    private const string SnapshotHeader = "v2";
    private const int DefaultPageSize = 4096;
    private const int PageLengthPrefixSize = 4;
    private const int HeaderPageCount = 2;
    private const int PageKindSize = 1;
    private const int PageHeaderSize = PageKindSize + PageLengthPrefixSize;
    private const byte PageKindSnapshot = (byte)'S';
    private const byte PageKindLog = (byte)'L';
    private const uint IndexMagic = 0x32445849; // "IDX2"
    private const int IndexHeaderVersion = 2;
    private const int IndexMagicOffset = 0;
    private const int IndexVersionOffset = 4;
    private const int IndexPageSizeOffset = 8;
    private const int IndexSnapshotCountOffset = 12;
    private const int IndexLogCountOffset = 20;
    private const int IndexSequenceOffset = 28;
    private const int IndexChecksumOffset = 36;
    private const string RegistryFileName = "index.registry";
    private readonly IDataProvider _provider;
    private readonly IBufferedLogger? _logger;
    public IndexStore(IDataProvider provider, IBufferedLogger? logger = null)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _logger = logger;
    }
    public void AppendEntry(string entityName, string fieldName, string key, string id, char op, bool normalizeKey = true, long? expiresAtUtcTicks = null)
    {
        if (string.IsNullOrWhiteSpace(entityName))
            throw new ArgumentException("Entity name cannot be empty.", nameof(entityName));
        if (string.IsNullOrWhiteSpace(fieldName))
            throw new ArgumentException("Field name cannot be empty.", nameof(fieldName));
        if (string.IsNullOrWhiteSpace(id))
            throw new ArgumentException("Id cannot be empty.", nameof(id));
        if (op != 'A' && op != 'D')
            throw new ArgumentException("Op must be 'A' or 'D'.", nameof(op));

        var normalizedKey = normalizeKey ? NormalizeKey(key) : key ?? string.Empty;
        using var lockHandle = _provider.AcquireIndexLock(entityName, fieldName);
        TrackIndex(entityName, fieldName);

        var line = FormatEntry(DateTime.UtcNow.Ticks, op, normalizedKey, id, expiresAtUtcTicks);
        AppendPagedLine(entityName, fieldName, line);
    }
    public void AppendEntry(string entityName, string fieldName, string key, string id, char op, DateTime? expiresAtUtc, bool normalizeKey = true)
    {
        AppendEntry(entityName, fieldName, key, id, op, normalizeKey, expiresAtUtc?.Ticks);
    }
    public Dictionary<string, HashSet<string>> ReadIndex(string entityName, string fieldName, bool normalizeKey = true)
    {
        var map = new Dictionary<string, Dictionary<string, long>>(StringComparer.OrdinalIgnoreCase);
        if (!_provider.PagedFileExists(entityName, GetPagedFileName(fieldName)))
            return new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

        var nowTicks = DateTime.UtcNow.Ticks;

        using var pagedFile = _provider.OpenPagedFile(entityName, GetPagedFileName(fieldName), DefaultPageSize, FileAccess.Read);
        var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
        try
        {
            var header = ReadIndexHeader(pagedFile, buffer);
            ApplySnapshotPages(pagedFile, buffer, map, header.SnapshotPageCount, nowTicks);
            ApplyLogPages(pagedFile, buffer, map, header.SnapshotPageCount, header.LogPageCount, normalizeKey, nowTicks);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return BuildIdMap(map, nowTicks);
    }
    public Dictionary<string, string> ReadLatestValueIndex(string entityName, string fieldName, bool normalizeKey = true)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!_provider.PagedFileExists(entityName, GetPagedFileName(fieldName)))
            return map;

        var nowTicks = DateTime.UtcNow.Ticks;

        using var pagedFile = _provider.OpenPagedFile(entityName, GetPagedFileName(fieldName), DefaultPageSize, FileAccess.Read);
        var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
        try
        {
            var header = ReadIndexHeader(pagedFile, buffer);
            ApplySnapshotPagesLatest(pagedFile, buffer, map, header.SnapshotPageCount, nowTicks);
            ApplyLogPagesLatest(pagedFile, buffer, map, header.SnapshotPageCount, header.LogPageCount, normalizeKey, nowTicks);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        return map;
    }
    public bool TryGetLatestValue(string entityName, string fieldName, string key, out string value, bool normalizeKey = true)
    {
        value = string.Empty;
        if (string.IsNullOrWhiteSpace(key))
            return false;
        if (!_provider.PagedFileExists(entityName, GetPagedFileName(fieldName)))
            return false;

        var nowTicks = DateTime.UtcNow.Ticks;
        var normalizedKey = normalizeKey ? NormalizeKey(key) : key;
        string? current = null;

        using var pagedFile = _provider.OpenPagedFile(entityName, GetPagedFileName(fieldName), DefaultPageSize, FileAccess.Read);
        var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
        try
        {
            var header = ReadIndexHeader(pagedFile, buffer);
            ForEachPagedLine(pagedFile, buffer, HeaderPageCount, header.SnapshotPageCount, PageKindSnapshot, line =>
            {
                if (string.IsNullOrWhiteSpace(line))
                    return;
                if (string.Equals(line.Trim(), SnapshotHeader, StringComparison.OrdinalIgnoreCase))
                    return;

                if (!TryParseSnapshotLine(line, out var entryKey, out var entryValue, out var expiresAtUtcTicks))
                    return;
                if (IsExpired(expiresAtUtcTicks, nowTicks))
                    return;
                if (!string.Equals(entryKey, normalizedKey, StringComparison.OrdinalIgnoreCase))
                    return;

                current = entryValue;
            });

            var logStartPage = HeaderPageCount + header.SnapshotPageCount;
            ForEachPagedLine(pagedFile, buffer, logStartPage, header.LogPageCount, PageKindLog, line =>
            {
                if (string.IsNullOrWhiteSpace(line))
                    return;

                if (!TryParseEntry(line, out var op, out var entryKey, out var entryValue, out var expiresAtUtcTicks))
                    return;
                if (!string.Equals(entryKey, normalizedKey, StringComparison.OrdinalIgnoreCase))
                    return;

                if (op == 'D')
                {
                    current = null;
                    return;
                }

                if (IsExpired(expiresAtUtcTicks, nowTicks))
                    return;

                current = entryValue;
            });
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }

        if (string.IsNullOrWhiteSpace(current))
            return false;

        value = current;
        return true;
    }
    public void BuildSnapshot(string entityName, string fieldName, bool normalizeKey = true)
    {
        using var lockHandle = _provider.AcquireIndexLock(entityName, fieldName);
        TrackIndex(entityName, fieldName);
        var pagedFileName = GetPagedFileName(fieldName);
        if (!_provider.PagedFileExists(entityName, pagedFileName))
            return;

        IndexHeader header;
        using (var pagedFile = _provider.OpenPagedFile(entityName, pagedFileName, DefaultPageSize, FileAccess.Read))
        {
            var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
            try
            {
                header = ReadIndexHeader(pagedFile, buffer);
                if (header.LogPageCount == 0)
                    return;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        var map = new Dictionary<string, Dictionary<string, long>>(StringComparer.OrdinalIgnoreCase);
        var nowTicks = DateTime.UtcNow.Ticks;
        using (var pagedFile = _provider.OpenPagedFile(entityName, pagedFileName, DefaultPageSize, FileAccess.Read))
        {
            var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
            try
            {
                ApplySnapshotPages(pagedFile, buffer, map, header.SnapshotPageCount, nowTicks);
                ApplyLogPages(pagedFile, buffer, map, header.SnapshotPageCount, header.LogPageCount, normalizeKey, nowTicks);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        WriteSnapshotPaged(entityName, fieldName, map, nowTicks);
    }
    private void WriteSnapshotPaged(string entityName, string fieldName, Dictionary<string, Dictionary<string, long>> map, long nowTicks)
    {
        var pagedFileName = GetPagedFileName(fieldName);
        if (_provider.PagedFileExists(entityName, pagedFileName))
            _provider.DeletePagedFileAsync(entityName, pagedFileName).AsTask().GetAwaiter().GetResult();

        using var pagedFile = _provider.OpenPagedFile(entityName, pagedFileName, DefaultPageSize, FileAccess.ReadWrite);
        var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
        try
        {
            long pageIndex = HeaderPageCount;
            WritePagedLine(pagedFile, buffer, pageIndex++, PageKindSnapshot, SnapshotHeader);
            foreach (var pair in map)
            {
                foreach (var id in pair.Value)
                {
                    if (IsExpired(id.Value, nowTicks))
                        continue;

                    WritePagedLine(pagedFile, buffer, pageIndex++, PageKindSnapshot, FormatSnapshotLine(pair.Key, id.Key, id.Value));
                }
            }

            pagedFile.Flush();

            var snapshotPageCount = pageIndex - HeaderPageCount;
            WriteIndexHeader(pagedFile, buffer, snapshotPageCount, 0, previousSequence: -1);
            pagedFile.Flush();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
    private void AppendPagedLine(string entityName, string fieldName, string line)
    {
        var pagedFileName = GetPagedFileName(fieldName);
        using var pagedFile = _provider.OpenPagedFile(entityName, pagedFileName, DefaultPageSize, FileAccess.ReadWrite);
        var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
        try
        {
            var header = ReadIndexHeader(pagedFile, buffer);
            var pageIndex = HeaderPageCount + header.SnapshotPageCount + header.LogPageCount;
            WritePagedLine(pagedFile, buffer, pageIndex, PageKindLog, line);
            pagedFile.Flush();
            WriteIndexHeader(pagedFile, buffer, header.SnapshotPageCount, header.LogPageCount + 1, header.Sequence);
            pagedFile.Flush();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
    private static void WritePagedLine(IPagedFile pagedFile, byte[] buffer, long pageIndex, byte kind, string line)
    {
        var span = buffer.AsSpan(0, pagedFile.PageSize);
        span.Clear();

        var byteCount = Encoding.UTF8.GetByteCount(line);
        if (byteCount > pagedFile.PageSize - PageHeaderSize)
            throw new InvalidOperationException("Index entry exceeds paged file page size.");

        span[0] = kind;
        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(PageKindSize, PageLengthPrefixSize), byteCount);
        Encoding.UTF8.GetBytes(line, span.Slice(PageHeaderSize, byteCount));
        pagedFile.WritePage(pageIndex, span);
    }
    private static void ApplySnapshotPages(IPagedFile pagedFile, byte[] buffer, Dictionary<string, Dictionary<string, long>> map, long snapshotPageCount, long nowTicks)
    {
        ForEachPagedLine(pagedFile, buffer, HeaderPageCount, snapshotPageCount, PageKindSnapshot, line =>
        {
            if (string.IsNullOrWhiteSpace(line))
                return;
            if (string.Equals(line.Trim(), SnapshotHeader, StringComparison.OrdinalIgnoreCase))
                return;

            if (TryParseSnapshotLine(line, out var key, out var id, out var expiresAtUtcTicks))
            {
                if (IsExpired(expiresAtUtcTicks, nowTicks))
                    return;

                AddEntry(map, key, id, expiresAtUtcTicks);
            }
        });
    }
    private static void ApplySnapshotPagesLatest(IPagedFile pagedFile, byte[] buffer, Dictionary<string, string> map, long snapshotPageCount, long nowTicks)
    {
        ForEachPagedLine(pagedFile, buffer, HeaderPageCount, snapshotPageCount, PageKindSnapshot, line =>
        {
            if (string.IsNullOrWhiteSpace(line))
                return;
            if (string.Equals(line.Trim(), SnapshotHeader, StringComparison.OrdinalIgnoreCase))
                return;

            if (!TryParseSnapshotLine(line, out var key, out var id, out var expiresAtUtcTicks))
                return;
            if (IsExpired(expiresAtUtcTicks, nowTicks))
                return;

            map[key] = id;
        });
    }
    private static void ApplyLogPages(IPagedFile pagedFile, byte[] buffer, Dictionary<string, Dictionary<string, long>> map, long snapshotPageCount, long logPageCount, bool normalizeKey, long nowTicks)
    {
        var logStartPage = HeaderPageCount + snapshotPageCount;
        ForEachPagedLine(pagedFile, buffer, logStartPage, logPageCount, PageKindLog, line =>
        {
            if (string.IsNullOrWhiteSpace(line))
                return;

            if (!TryParseEntry(line, out var op, out var key, out var id, out var expiresAtUtcTicks))
                return;

            var normalizedKey = normalizeKey ? NormalizeKey(key) : key;
            if (op == 'A')
            {
                if (IsExpired(expiresAtUtcTicks, nowTicks))
                    return;

                AddEntry(map, normalizedKey, id, expiresAtUtcTicks);
            }
            else if (op == 'D')
                RemoveEntry(map, normalizedKey, id);
        });
    }
    private static void ApplyLogPagesLatest(IPagedFile pagedFile, byte[] buffer, Dictionary<string, string> map, long snapshotPageCount, long logPageCount, bool normalizeKey, long nowTicks)
    {
        var logStartPage = HeaderPageCount + snapshotPageCount;
        ForEachPagedLine(pagedFile, buffer, logStartPage, logPageCount, PageKindLog, line =>
        {
            if (string.IsNullOrWhiteSpace(line))
                return;

            if (!TryParseEntry(line, out var op, out var key, out var id, out var expiresAtUtcTicks))
                return;

            var normalizedKey = normalizeKey ? NormalizeKey(key) : key;
            if (op == 'D')
            {
                map.Remove(normalizedKey);
                return;
            }

            if (IsExpired(expiresAtUtcTicks, nowTicks))
                return;

            map[normalizedKey] = id;
        });
    }
    private static void ForEachPagedLine(IPagedFile pagedFile, byte[] buffer, long startPage, long pageCount, byte expectedKind, Action<string> handler)
    {
        if (pageCount <= 0)
            return;

        var endPage = startPage + pageCount;
        for (long pageIndex = startPage; pageIndex < endPage; pageIndex++)
        {
            var bytesRead = pagedFile.ReadPage(pageIndex, buffer);
            if (bytesRead == 0)
                continue;

            var span = buffer.AsSpan(0, pagedFile.PageSize);
            if (span[0] != expectedKind)
                continue;

            var length = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(PageKindSize, PageLengthPrefixSize));
            if (length <= 0 || length > pagedFile.PageSize - PageHeaderSize)
                continue;

            var line = Encoding.UTF8.GetString(span.Slice(PageHeaderSize, length));
            handler(line);
        }
    }
    private static string GetPagedFileName(string fieldName)
    {
        return $"{fieldName}_index";
    }
    private static IndexHeader ReadIndexHeader(IPagedFile pagedFile, byte[] buffer)
    {
        var headerA = TryReadIndexHeaderPage(pagedFile, buffer, 0, out var validA);
        var headerB = TryReadIndexHeaderPage(pagedFile, buffer, 1, out var validB);

        if (validA && validB)
            return headerA.Sequence >= headerB.Sequence ? headerA : headerB;
        if (validA)
            return headerA;
        if (validB)
            return headerB;

        var recovered = RecoverHeaderByScan(pagedFile, buffer);
        if (pagedFile.CanWrite)
            WriteIndexHeader(pagedFile, buffer, recovered.SnapshotPageCount, recovered.LogPageCount, recovered.Sequence);

        return recovered;
    }
    private static void WriteIndexHeader(IPagedFile pagedFile, byte[] buffer, long snapshotPageCount, long logPageCount, long previousSequence)
    {
        var nextSequence = previousSequence + 1;
        var pageIndex = nextSequence % HeaderPageCount;
        var span = buffer.AsSpan(0, pagedFile.PageSize);
        span.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(IndexMagicOffset, 4), IndexMagic);
        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(IndexVersionOffset, 4), IndexHeaderVersion);
        BinaryPrimitives.WriteInt32LittleEndian(span.Slice(IndexPageSizeOffset, 4), pagedFile.PageSize);
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(IndexSnapshotCountOffset, 8), snapshotPageCount);
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(IndexLogCountOffset, 8), logPageCount);
        BinaryPrimitives.WriteInt64LittleEndian(span.Slice(IndexSequenceOffset, 8), nextSequence);
        var checksum = ComputeHeaderChecksum(span.Slice(0, IndexChecksumOffset));
        BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(IndexChecksumOffset, 4), checksum);
        pagedFile.WritePage(pageIndex, span);
    }
    private readonly struct IndexHeader
    {
        public IndexHeader(long snapshotPageCount, long logPageCount, long sequence)
        {
            SnapshotPageCount = snapshotPageCount;
            LogPageCount = logPageCount;
            Sequence = sequence;
        }

        public long SnapshotPageCount { get; }
        public long LogPageCount { get; }
        public long Sequence { get; }
    }
    public sealed class IndexLease : IDisposable
    {
        public IndexLease(string entityName, string fieldName, IDisposable handle)
        {
            EntityName = entityName;
            FieldName = fieldName;
            _handle = handle ?? throw new ArgumentNullException(nameof(handle));
        }

        public string EntityName { get; }
        public string FieldName { get; }
        private readonly IDisposable _handle;

        public void Dispose()
        {
            _handle.Dispose();
        }
    }
    public static IReadOnlyList<IndexLease> RecoverTrackedIndexes(IDataProvider provider, IBufferedLogger? logger = null)
    {
        if (provider == null)
            throw new ArgumentNullException(nameof(provider));

        var total = 0;
        var locked = 0;
        var skipped = 0;
        var leases = new List<IndexLease>();
        foreach (var entry in ReadRegistryEntries(provider))
        {
            total++;
            if (!TryAcquireIndexLock(provider, entry.EntityName, entry.FieldName, out var handle))
            {
                skipped++;
                continue;
            }

            try
            {
                var pagedFileName = GetPagedFileName(entry.FieldName);
                if (provider.PagedFileExists(entry.EntityName, pagedFileName))
                {
                    using var pagedFile = provider.OpenPagedFile(entry.EntityName, pagedFileName, DefaultPageSize, FileAccess.ReadWrite);
                    var buffer = ArrayPool<byte>.Shared.Rent(pagedFile.PageSize);
                    try
                    {
                        _ = ReadIndexHeader(pagedFile, buffer);
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(buffer);
                    }
                }

                locked++;
                leases.Add(new IndexLease(entry.EntityName, entry.FieldName, handle));
            }
            catch (Exception ex)
            {
                logger?.LogError($"Failed to recover index {entry.EntityName}.{entry.FieldName}.", ex);
                handle.Dispose();
                throw;
            }
        }

        logger?.LogInfo($"Index recovery scanned={total}, locked={locked}, skipped={skipped}.");

        return leases;
    }
    private static bool TryAcquireIndexLock(IDataProvider provider, string entityName, string fieldName, out IDisposable handle)
    {
        handle = null!;
        try
        {
            handle = provider.AcquireIndexLock(entityName, fieldName);
            return true;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }
    private static IndexHeader TryReadIndexHeaderPage(IPagedFile pagedFile, byte[] buffer, long pageIndex, out bool valid)
    {
        valid = false;
        if (pagedFile.PageCount <= pageIndex)
            return new IndexHeader(0, 0, 0);

        var bytesRead = pagedFile.ReadPage(pageIndex, buffer);
        if (bytesRead == 0)
            return new IndexHeader(0, 0, 0);

        var span = buffer.AsSpan(0, pagedFile.PageSize);
        var magic = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(IndexMagicOffset, 4));
        if (magic != IndexMagic)
            return new IndexHeader(0, 0, 0);

        var version = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(IndexVersionOffset, 4));
        if (version != IndexHeaderVersion)
            return new IndexHeader(0, 0, 0);

        var pageSize = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(IndexPageSizeOffset, 4));
        if (pageSize != pagedFile.PageSize)
            return new IndexHeader(0, 0, 0);

        var checksum = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(IndexChecksumOffset, 4));
        var computed = ComputeHeaderChecksum(span.Slice(0, IndexChecksumOffset));
        if (checksum != computed)
            return new IndexHeader(0, 0, 0);

        var snapshotPageCount = BinaryPrimitives.ReadInt64LittleEndian(span.Slice(IndexSnapshotCountOffset, 8));
        var logPageCount = BinaryPrimitives.ReadInt64LittleEndian(span.Slice(IndexLogCountOffset, 8));
        var sequence = BinaryPrimitives.ReadInt64LittleEndian(span.Slice(IndexSequenceOffset, 8));
        valid = true;
        return new IndexHeader(snapshotPageCount, logPageCount, sequence);
    }
    private static IndexHeader RecoverHeaderByScan(IPagedFile pagedFile, byte[] buffer)
    {
        var snapshotPageCount = 0L;
        var logPageCount = 0L;
        var startPage = HeaderPageCount;
        for (long pageIndex = startPage; pageIndex < pagedFile.PageCount; pageIndex++)
        {
            var bytesRead = pagedFile.ReadPage(pageIndex, buffer);
            if (bytesRead == 0)
                continue;

            var span = buffer.AsSpan(0, pagedFile.PageSize);
            var kind = span[0];
            var length = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(PageKindSize, PageLengthPrefixSize));
            if (length <= 0 || length > pagedFile.PageSize - PageHeaderSize)
                continue;

            if (kind == PageKindSnapshot)
                snapshotPageCount++;
            else if (kind == PageKindLog)
                logPageCount++;
        }

        var sequence = pagedFile.PageCount == 0 ? -1 : 0;
        return new IndexHeader(snapshotPageCount, logPageCount, sequence);
    }
    private static uint ComputeHeaderChecksum(ReadOnlySpan<byte> span)
    {
        const uint fnvOffset = 2166136261;
        const uint fnvPrime = 16777619;
        var hash = fnvOffset;
        for (var i = 0; i < span.Length; i++)
        {
            hash ^= span[i];
            hash *= fnvPrime;
        }
        return hash;
    }
    private void TrackIndex(string entityName, string fieldName)
    {
        var registryPath = GetRegistryPath();
        Directory.CreateDirectory(Path.GetDirectoryName(registryPath) ?? _provider.IndexRootPath);

        var entry = FormatRegistryEntry(entityName, fieldName);
        var lockPath = registryPath + ".lock";
        var encoding = new UTF8Encoding(false);

        using var lockStream = new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        using var stream = new FileStream(registryPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite);
        using (var reader = new StreamReader(stream, encoding, detectEncodingFromByteOrderMarks: false, bufferSize: 1024, leaveOpen: true))
        {
            while (!reader.EndOfStream)
            {
                var line = reader.ReadLine();
                if (string.IsNullOrWhiteSpace(line))
                    continue;
                if (string.Equals(line, entry, StringComparison.Ordinal))
                    return;
            }
        }

        stream.Seek(0, SeekOrigin.End);
        using var writer = new StreamWriter(stream, encoding, bufferSize: 1024, leaveOpen: true);
        writer.WriteLine(entry);
        _logger?.LogInfo($"Tracked index {entityName}.{fieldName}.");
    }
    private string GetRegistryPath()
    {
        return Path.Combine(_provider.IndexRootPath, _provider.IndexFolderName, RegistryFileName);
    }
    private static IEnumerable<(string EntityName, string FieldName)> ReadRegistryEntries(IDataProvider provider)
    {
        var path = Path.Combine(provider.IndexRootPath, provider.IndexFolderName, RegistryFileName);
        if (!File.Exists(path))
            yield break;

        var encoding = new UTF8Encoding(false);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream, encoding, detectEncodingFromByteOrderMarks: false);
        while (!reader.EndOfStream)
        {
            var line = reader.ReadLine();
            if (string.IsNullOrWhiteSpace(line))
                continue;

            if (TryParseRegistryEntry(line, out var entityName, out var fieldName))
                yield return (entityName, fieldName);
        }
    }
    private static string FormatRegistryEntry(string entityName, string fieldName)
    {
        return string.Join('|', Encode(entityName), Encode(fieldName));
    }
    private static bool TryParseRegistryEntry(string line, out string entityName, out string fieldName)
    {
        entityName = string.Empty;
        fieldName = string.Empty;

        var parts = line.Split('|');
        if (parts.Length != 2)
            return false;

        entityName = Decode(parts[0]);
        fieldName = Decode(parts[1]);
        return !string.IsNullOrWhiteSpace(entityName) && !string.IsNullOrWhiteSpace(fieldName);
    }
    public static string ComposeCompositeKey(params string[] parts)
    {
        if (parts == null || parts.Length == 0)
            return string.Empty;

        var builder = new StringBuilder(parts.Length * 8);
        for (var i = 0; i < parts.Length; i++)
        {
            var part = parts[i] ?? string.Empty;
            if (i > 0)
                builder.Append('|');
            builder.Append(part.Length);
            builder.Append(':');
            builder.Append(part);
        }

        return builder.ToString();
    }
    public static bool TrySplitCompositeKey(string compositeKey, out string[] parts)
    {
        parts = Array.Empty<string>();
        if (string.IsNullOrEmpty(compositeKey))
            return false;

        var list = new List<string>();
        var index = 0;
        while (index < compositeKey.Length)
        {
            var lengthEnd = compositeKey.IndexOf(':', index);
            if (lengthEnd < 0)
                return false;

            if (!int.TryParse(compositeKey.AsSpan(index, lengthEnd - index), out var partLength) || partLength < 0)
                return false;

            var partStart = lengthEnd + 1;
            if (partStart + partLength > compositeKey.Length)
                return false;

            list.Add(compositeKey.Substring(partStart, partLength));
            index = partStart + partLength;
            if (index == compositeKey.Length)
                break;
            if (compositeKey[index] != '|')
                return false;
            index++;
        }

        parts = list.ToArray();
        return parts.Length > 0;
    }
    private static void AddEntry(Dictionary<string, Dictionary<string, long>> map, string key, string id, long expiresAtUtcTicks)
    {
        if (!map.TryGetValue(key, out var set))
        {
            set = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
            map[key] = set;
        }
        set[id] = expiresAtUtcTicks;
    }
    private static void RemoveEntry(Dictionary<string, Dictionary<string, long>> map, string key, string id)
    {
        if (!map.TryGetValue(key, out var set))
            return;
        set.Remove(id);
        if (set.Count == 0)
            map.Remove(key);
    }
    private static string FormatEntry(long ticks, char op, string key, string id, long? expiresAtUtcTicks)
    {
        return expiresAtUtcTicks.HasValue && expiresAtUtcTicks.Value > 0
            ? string.Join('|',
                ticks.ToString(),
                op,
                Encode(key),
                Encode(id),
                expiresAtUtcTicks.Value.ToString())
            : string.Join('|',
                ticks.ToString(),
                op,
                Encode(key),
                Encode(id));
    }
    private static string FormatSnapshotLine(string key, string id, long expiresAtUtcTicks)
    {
        return expiresAtUtcTicks > 0
            ? string.Join('|', Encode(key), Encode(id), expiresAtUtcTicks.ToString())
            : string.Join('|', Encode(key), Encode(id));
    }
    private static bool TryParseEntry(string line, out char op, out string key, out string id, out long expiresAtUtcTicks)
    {
        op = '\0';
        key = string.Empty;
        id = string.Empty;
        expiresAtUtcTicks = 0;

        var parts = line.Split('|');
        if (parts.Length < 4 || parts.Length > 5)
            return false;

        if (parts[1].Length != 1)
            return false;

        op = parts[1][0];
        key = Decode(parts[2]);
        id = Decode(parts[3]);
        if (parts.Length == 5)
            long.TryParse(parts[4], out expiresAtUtcTicks);
        return true;
    }
    private static bool TryParseSnapshotLine(string line, out string key, out string id, out long expiresAtUtcTicks)
    {
        key = string.Empty;
        id = string.Empty;
        expiresAtUtcTicks = 0;

        var parts = line.Split('|');
        if (parts.Length < 2 || parts.Length > 3)
            return false;

        key = Decode(parts[0]);
        id = Decode(parts[1]);
        if (parts.Length == 3)
            long.TryParse(parts[2], out expiresAtUtcTicks);
        return true;
    }
    private static string Encode(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
        return Convert.ToBase64String(bytes);
    }
    private static string Decode(string value)
    {
        try
        {
            var bytes = Convert.FromBase64String(value);
            return Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return string.Empty;
        }
    }
    private static string NormalizeKey(string key)
    {
        return (key ?? string.Empty).Trim().ToLowerInvariant();
    }
    private static Dictionary<string, HashSet<string>> BuildIdMap(Dictionary<string, Dictionary<string, long>> map, long nowTicks)
    {
        var result = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in map)
        {
            HashSet<string>? set = null;
            foreach (var idEntry in pair.Value)
            {
                if (IsExpired(idEntry.Value, nowTicks))
                    continue;

                set ??= new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                set.Add(idEntry.Key);
            }

            if (set != null && set.Count > 0)
                result[pair.Key] = set;
        }

        return result;
    }
    private static bool IsExpired(long expiresAtUtcTicks, long nowTicks)
    {
        return expiresAtUtcTicks > 0 && expiresAtUtcTicks <= nowTicks;
    }
}
