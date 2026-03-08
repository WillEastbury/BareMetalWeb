using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Threading;

namespace BareMetalWeb.Data;

/// <summary>
/// Thread-safe cache of memory-mapped WAL segment files for zero-overhead reads.
/// Mapped segments remain open until evicted (compaction) or the cache is disposed.
/// Falls back gracefully: callers should handle null returns and ObjectDisposedException.
/// </summary>
internal sealed class MappedSegmentCache : IDisposable
{
    private readonly string _directory;
    private readonly ConcurrentDictionary<uint, Lazy<MappedSegment?>> _cache = new();
    private volatile bool _disposed;

    public MappedSegmentCache(string directory)
    {
        _directory = directory ?? throw new ArgumentNullException(nameof(directory));
    }

    /// <summary>
    /// Gets or creates a memory-mapped view of the specified WAL segment.
    /// Returns <c>null</c> if the segment file does not exist or cannot be mapped.
    /// Thread-safe: concurrent callers for the same segment share a single mapping.
    /// </summary>
    public MappedSegment? GetOrCreate(uint segmentId)
    {
        if (_disposed) return null;

        var lazy = _cache.GetOrAdd(segmentId, static (id, dir) => new Lazy<MappedSegment?>(() =>
        {
            string path = Path.Combine(dir, WalConstants.SegmentFileName(id));
            try
            {
                if (!File.Exists(path)) return null;
                var fi = new FileInfo(path);
                if (fi.Length == 0) return null;
                return new MappedSegment(path, fi.Length);
            }
            catch (IOException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
        }), _directory);

        try { return lazy.Value; }
        catch { return null; }
    }

    /// <summary>
    /// Evicts and disposes a cached segment mapping.
    /// Call after compaction replaces the segment file so subsequent reads map the new file.
    /// </summary>
    public void Evict(uint segmentId)
    {
        if (_cache.TryRemove(segmentId, out var lazy) && lazy.IsValueCreated)
        {
            try { lazy.Value?.Dispose(); }
            catch { /* best-effort cleanup */ }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        // Snapshot keys then remove+dispose each — avoids double-dispose with concurrent Evict
        foreach (var kvp in _cache)
        {
            if (_cache.TryRemove(kvp.Key, out var lazy) && lazy.IsValueCreated)
            {
                try { lazy.Value?.Dispose(); }
                catch { /* best-effort cleanup */ }
            }
        }
    }
}

/// <summary>
/// Read-only memory-mapped view of a single WAL segment file.
/// Provides fast record reads via the OS page cache without FileStream open/close overhead.
/// Uses unsafe pointer access for zero-copy reads from the mapped region.
/// <para>
/// Thread-safety: concurrent reads are safe. <see cref="Dispose"/> uses a reader-count
/// gate so in-flight reads complete before the mapping is released. Once disposed,
/// new reads throw <see cref="ObjectDisposedException"/>.
/// </para>
/// </summary>
internal sealed class MappedSegment : IDisposable
{
    private readonly MemoryMappedFile _mmf;
    private readonly MemoryMappedViewAccessor _accessor;
    private readonly long _length;

    // Reader-count gate: >= 0 means active readers; -1 means disposed.
    // EnterRead increments; LeaveRead decrements; Dispose spins until 0 then sets -1.
    private int _readerCount;
    private const int Disposed = -1;

    public MappedSegment(string filePath, long fileLength)
    {
        _length = fileLength;
        _mmf = MemoryMappedFile.CreateFromFile(filePath, FileMode.Open, null, 0,
            MemoryMappedFileAccess.Read);
        _accessor = _mmf.CreateViewAccessor(0, _length, MemoryMappedFileAccess.Read);
    }

    public long Length => _length;

    /// <summary>
    /// Reads bytes from the mapped segment into the destination buffer.
    /// Returns the number of bytes actually read (may be less than destination.Length
    /// if the offset is near the end of the file).
    /// Throws <see cref="ObjectDisposedException"/> if the segment has been disposed.
    /// </summary>
    public unsafe int Read(long offset, Span<byte> destination)
    {
        if (!TryEnterRead())
            throw new ObjectDisposedException(nameof(MappedSegment));
        try
        {
            if (offset < 0 || offset >= _length) return 0;

            int available = (int)Math.Min(destination.Length, _length - offset);
            if (available <= 0) return 0;

            byte* ptr = null;
            _accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
            try
            {
                new ReadOnlySpan<byte>(ptr + _accessor.PointerOffset + offset, available)
                    .CopyTo(destination);
                return available;
            }
            finally
            {
                _accessor.SafeMemoryMappedViewHandle.ReleasePointer();
            }
        }
        finally
        {
            LeaveRead();
        }
    }

    /// <summary>
    /// Reads a complete WAL record at <paramref name="offset32"/> into a pooled buffer.
    /// Validates the record header magic and type before allocating.
    /// Returns <c>null</c> if the offset is out of range or the header is invalid.
    /// <para>
    /// <b>Caller must return the buffer to <see cref="ArrayPool{T}.Shared"/>.</b>
    /// </para>
    /// Throws <see cref="ObjectDisposedException"/> if the segment has been disposed.
    /// </summary>
    public unsafe byte[]? ReadRecord(uint offset32, out int totalBytes)
    {
        totalBytes = 0;

        if (!TryEnterRead())
            throw new ObjectDisposedException(nameof(MappedSegment));
        try
        {
            if (offset32 + WalConstants.RecordHeaderBytes > _length) return null;

            byte* ptr = null;
            _accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref ptr);
            try
            {
                byte* basePtr = ptr + _accessor.PointerOffset;

                // Read and validate record header without allocating
                var headerSpan = new ReadOnlySpan<byte>(basePtr + offset32,
                    WalConstants.RecordHeaderBytes);

                if (BinaryPrimitives.ReadUInt32LittleEndian(headerSpan) != WalConstants.RecordMagic)
                    return null;

                uint totalBytesU = BinaryPrimitives.ReadUInt32LittleEndian(headerSpan.Slice(8));
                long minSize = WalConstants.RecordHeaderBytes + WalConstants.RecordTrailerBytes;
                if (totalBytesU < minSize || offset32 + (long)totalBytesU > _length)
                    return null;

                // Guard against int overflow — records > 2 GiB are corrupt
                if (totalBytesU > int.MaxValue) return null;

                totalBytes = (int)totalBytesU;

                // Copy full record into pooled buffer for CRC verification (needs mutable span)
                var buffer = ArrayPool<byte>.Shared.Rent(totalBytes);
                new ReadOnlySpan<byte>(basePtr + offset32, totalBytes)
                    .CopyTo(buffer.AsSpan(0, totalBytes));
                return buffer;
            }
            finally
            {
                _accessor.SafeMemoryMappedViewHandle.ReleasePointer();
            }
        }
        finally
        {
            LeaveRead();
        }
    }

    public void Dispose()
    {
        // Spin until all readers have drained, then atomically set Disposed.
        // This ensures no AcquirePointer call is in flight when we tear down the mapping.
        var spin = new SpinWait();
        while (true)
        {
            int current = Volatile.Read(ref _readerCount);
            if (current == Disposed) return; // already disposed
            if (current == 0 && Interlocked.CompareExchange(ref _readerCount, Disposed, 0) == 0)
                break;
            spin.SpinOnce();
        }

        _accessor.Dispose();
        _mmf.Dispose();
    }

    /// <summary>
    /// Atomically increments the reader count. Returns <c>false</c> if disposed.
    /// </summary>
    private bool TryEnterRead()
    {
        while (true)
        {
            int current = Volatile.Read(ref _readerCount);
            if (current == Disposed) return false;
            if (Interlocked.CompareExchange(ref _readerCount, current + 1, current) == current)
                return true;
        }
    }

    private void LeaveRead()
    {
        Interlocked.Decrement(ref _readerCount);
    }
}
