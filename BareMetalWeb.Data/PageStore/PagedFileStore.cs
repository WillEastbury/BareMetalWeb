using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Threading.Channels;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data.Interfaces;

namespace BareMetalWeb.Data.PageStore;

/// <summary>
/// A page-addressable storage engine with deterministic write ordering, 
/// no locks for normal page writes, and optimistic concurrency control.
/// Uses extent-based partitioning with single-writer queues per extent.
/// </summary>
public sealed class PagedFileStore : IDisposable
{
    private const string PageStoreFileName = "pagestore";
    private const int DefaultPageSize = 4096;
    private const int DefaultExtentSizeBytes = 64 * 1024 * 1024; // 64 MB
    private const int DefaultQueueCapacity = 1000;
    private const int PageHeaderSize = 32;
    private const uint PageMagic = 0x50475354; // 'PGST'
    
    // Page header offsets
    private const int HeaderMagicOffset = 0;
    private const int HeaderVersionOffset = 4;
    private const int HeaderSizeOffset = 12;
    private const int HeaderFlagsOffset = 16;
    
    // Page flags
    private const byte PageFlagActive = 0x01;
    private const byte PageFlagDeleted = 0x02;
    
    private readonly IDataProvider _provider;
    private readonly string _storeName;
    private readonly int _pageSize;
    private readonly int _extentSizeBytes;
    private readonly int _pagesPerExtent;
    private readonly int _queueCapacity;
    private readonly IBufferedLogger? _logger;
    
    private readonly ConcurrentDictionary<int, ExtentWriter> _extentWriters = new();
    private readonly ConcurrentDictionary<long, PageMetadata> _metadataCache = new();
    private long _nextPageId = 1;
    private long _globalSequence = 0;
    private readonly object _allocationLock = new object();
    private readonly CancellationTokenSource _shutdownCts = new CancellationTokenSource();
    private bool _disposed;

    public PagedFileStore(
        IDataProvider provider, 
        string storeName, 
        int pageSize = DefaultPageSize,
        int extentSizeBytes = DefaultExtentSizeBytes,
        int queueCapacity = DefaultQueueCapacity,
        IBufferedLogger? logger = null)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
        _storeName = storeName ?? throw new ArgumentNullException(nameof(storeName));
        _pageSize = pageSize;
        _extentSizeBytes = extentSizeBytes;
        _pagesPerExtent = extentSizeBytes / pageSize;
        _queueCapacity = queueCapacity;
        _logger = logger;

        Initialize();
    }

    /// <summary>
    /// Read a page and return its data and metadata.
    /// </summary>
    public async Task<(byte[]? data, PageMetadata metadata)> ReadPageAsync(long pageId, CancellationToken cancellationToken = default)
    {
        if (pageId <= 0)
            return (null, new PageMetadata(pageId, 0, 0, false));

        // Try cache first
        if (_metadataCache.TryGetValue(pageId, out var cached) && cached.Exists)
        {
            var data = await ReadPageDataAsync(pageId, cached.Size, cancellationToken);
            return (data, cached);
        }

        // Read from disk
        var (diskData, metadata) = await ReadPageFromDiskAsync(pageId, cancellationToken);
        if (metadata.Exists)
        {
            _metadataCache[pageId] = metadata;
        }

        return (diskData, metadata);
    }

    /// <summary>
    /// Get page metadata without reading the full page data.
    /// </summary>
    public Task<PageMetadata> HeadPageAsync(long pageId, CancellationToken cancellationToken = default)
    {
        if (pageId <= 0)
            return Task.FromResult(new PageMetadata(pageId, 0, 0, false));

        if (_metadataCache.TryGetValue(pageId, out var cached))
            return Task.FromResult(cached);

        return HeadPageFromDiskAsync(pageId, cancellationToken);
    }

    /// <summary>
    /// Allocate a new page and write initial data.
    /// </summary>
    public async Task<AllocateResult> AddPageAsync(byte[] data, CancellationToken cancellationToken = default)
    {
        if (data == null || data.Length == 0)
            return AllocateResult.FailureResult("Data cannot be null or empty");

        if (data.Length > _pageSize - PageHeaderSize)
            return AllocateResult.FailureResult($"Data size {data.Length} exceeds page capacity {_pageSize - PageHeaderSize}");

        long pageId;
        int extentId;
        
        lock (_allocationLock)
        {
            pageId = _nextPageId++;
            extentId = GetExtentId(pageId);
        }

        var writer = GetOrCreateExtentWriter(extentId);
        var completion = new TaskCompletionSource<AllocateResult>();
        var cmd = new AllocateCommand(data, completion);

        if (!writer.TryEnqueueAllocate(pageId, cmd))
        {
            return AllocateResult.FailureResult("Queue full - backpressure limit reached");
        }

        return await completion.Task;
    }

    /// <summary>
    /// Write/overwrite an existing page with optional version check.
    /// </summary>
    public async Task<WriteResult> WritePageAsync(long pageId, byte[] data, long? expectedVersion = null, CancellationToken cancellationToken = default)
    {
        if (pageId <= 0)
            return WriteResult.FailureResult("Invalid page ID");

        if (data == null || data.Length == 0)
            return WriteResult.FailureResult("Data cannot be null or empty");

        if (data.Length > _pageSize - PageHeaderSize)
            return WriteResult.FailureResult($"Data size {data.Length} exceeds page capacity {_pageSize - PageHeaderSize}");

        var extentId = GetExtentId(pageId);
        var writer = GetOrCreateExtentWriter(extentId);
        var completion = new TaskCompletionSource<WriteResult>();
        var cmd = new WriteCommand(pageId, data, expectedVersion, completion);

        if (!writer.TryEnqueueWrite(cmd))
        {
            return WriteResult.FailureResult("Queue full - backpressure limit reached");
        }

        return await completion.Task;
    }

    private void Initialize()
    {
        // Load existing metadata if the store exists
        if (_provider.PagedFileExists(_storeName, PageStoreFileName))
        {
            LoadExistingMetadata();
        }
    }

    private void LoadExistingMetadata()
    {
        try
        {
            using var pagedFile = _provider.OpenPagedFile(_storeName, PageStoreFileName, _pageSize, FileAccess.Read);
            var buffer = ArrayPool<byte>.Shared.Rent(_pageSize);
            try
            {
                var maxPageId = 0L;
                for (long i = 0; i < pagedFile.PageCount; i++)
                {
                    var bytesRead = pagedFile.ReadPage(i, buffer);
                    if (bytesRead == 0) continue;

                    var span = buffer.AsSpan(0, _pageSize);
                    var magic = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(HeaderMagicOffset, 4));
                    if (magic != PageMagic) continue;

                    var version = BinaryPrimitives.ReadInt64LittleEndian(span.Slice(HeaderVersionOffset, 8));
                    var size = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(HeaderSizeOffset, 4));
                    var flags = span[HeaderFlagsOffset];
                    var exists = (flags & PageFlagActive) != 0 && (flags & PageFlagDeleted) == 0;

                    var pageId = i + 1;
                    var metadata = new PageMetadata(pageId, version, size, exists);
                    _metadataCache[pageId] = metadata;

                    if (pageId > maxPageId)
                        maxPageId = pageId;
                    
                    if (version > _globalSequence)
                        _globalSequence = version;
                }

                _nextPageId = maxPageId + 1;
                _logger?.LogInfo($"Loaded page store '{_storeName}': {_metadataCache.Count} pages, next ID {_nextPageId}");
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Failed to load metadata for page store '{_storeName}'", ex);
        }
    }

    private int GetExtentId(long pageId)
    {
        return (int)((pageId - 1) / _pagesPerExtent);
    }

    private ExtentWriter GetOrCreateExtentWriter(int extentId)
    {
        return _extentWriters.GetOrAdd(extentId, id => 
            new ExtentWriter(id, this, _queueCapacity, _shutdownCts.Token, _logger));
    }

    private async Task<byte[]?> ReadPageDataAsync(long pageId, int size, CancellationToken cancellationToken)
    {
        try
        {
            using var pagedFile = _provider.OpenPagedFile(_storeName, PageStoreFileName, _pageSize, FileAccess.Read);
            var physicalIndex = pageId - 1;
            
            if (physicalIndex >= pagedFile.PageCount)
                return null;

            var buffer = ArrayPool<byte>.Shared.Rent(_pageSize);
            try
            {
                var bytesRead = await pagedFile.ReadPageAsync(physicalIndex, buffer, cancellationToken);
                if (bytesRead == 0) return null;

                var span = buffer.AsSpan(0, _pageSize);
                var dataSpan = span.Slice(PageHeaderSize, Math.Min(size, _pageSize - PageHeaderSize));
                return dataSpan.ToArray();
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Failed to read page {pageId}", ex);
            return null;
        }
    }

    private async Task<(byte[]? data, PageMetadata metadata)> ReadPageFromDiskAsync(long pageId, CancellationToken cancellationToken)
    {
        try
        {
            using var pagedFile = _provider.OpenPagedFile(_storeName, PageStoreFileName, _pageSize, FileAccess.Read);
            var physicalIndex = pageId - 1;
            
            if (physicalIndex >= pagedFile.PageCount)
                return (null, new PageMetadata(pageId, 0, 0, false));

            var buffer = ArrayPool<byte>.Shared.Rent(_pageSize);
            try
            {
                var bytesRead = await pagedFile.ReadPageAsync(physicalIndex, buffer, cancellationToken);
                if (bytesRead == 0)
                    return (null, new PageMetadata(pageId, 0, 0, false));

                var span = buffer.AsSpan(0, _pageSize);
                var magic = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(HeaderMagicOffset, 4));
                if (magic != PageMagic)
                    return (null, new PageMetadata(pageId, 0, 0, false));

                var version = BinaryPrimitives.ReadInt64LittleEndian(span.Slice(HeaderVersionOffset, 8));
                var size = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(HeaderSizeOffset, 4));
                var flags = span[HeaderFlagsOffset];
                var exists = (flags & PageFlagActive) != 0 && (flags & PageFlagDeleted) == 0;

                var metadata = new PageMetadata(pageId, version, size, exists);
                if (!exists)
                    return (null, metadata);

                var dataSpan = span.Slice(PageHeaderSize, Math.Min(size, _pageSize - PageHeaderSize));
                return (dataSpan.ToArray(), metadata);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Failed to read page {pageId}", ex);
            return (null, new PageMetadata(pageId, 0, 0, false));
        }
    }

    private async Task<PageMetadata> HeadPageFromDiskAsync(long pageId, CancellationToken cancellationToken)
    {
        try
        {
            using var pagedFile = _provider.OpenPagedFile(_storeName, PageStoreFileName, _pageSize, FileAccess.Read);
            var physicalIndex = pageId - 1;
            
            if (physicalIndex >= pagedFile.PageCount)
                return new PageMetadata(pageId, 0, 0, false);

            var buffer = ArrayPool<byte>.Shared.Rent(_pageSize);
            try
            {
                var bytesRead = await pagedFile.ReadPageAsync(physicalIndex, buffer, cancellationToken);
                if (bytesRead == 0)
                    return new PageMetadata(pageId, 0, 0, false);

                var span = buffer.AsSpan(0, _pageSize);
                var magic = BinaryPrimitives.ReadUInt32LittleEndian(span.Slice(HeaderMagicOffset, 4));
                if (magic != PageMagic)
                    return new PageMetadata(pageId, 0, 0, false);

                var version = BinaryPrimitives.ReadInt64LittleEndian(span.Slice(HeaderVersionOffset, 8));
                var size = BinaryPrimitives.ReadInt32LittleEndian(span.Slice(HeaderSizeOffset, 4));
                var flags = span[HeaderFlagsOffset];
                var exists = (flags & PageFlagActive) != 0 && (flags & PageFlagDeleted) == 0;

                var metadata = new PageMetadata(pageId, version, size, exists);
                _metadataCache[pageId] = metadata;
                return metadata;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError($"Failed to head page {pageId}", ex);
            return new PageMetadata(pageId, 0, 0, false);
        }
    }

    private long GetNextSequence()
    {
        return Interlocked.Increment(ref _globalSequence);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _shutdownCts.Cancel();
        
        foreach (var writer in _extentWriters.Values)
        {
            writer.Dispose();
        }
        
        _extentWriters.Clear();
        _shutdownCts.Dispose();
    }

    /// <summary>
    /// Single-writer loop for an extent. Processes writes serially in FIFO order.
    /// </summary>
    private sealed class ExtentWriter : IDisposable
    {
        private readonly int _extentId;
        private readonly PagedFileStore _store;
        private readonly Channel<object> _commandQueue;
        private readonly Task _writerTask;
        private readonly CancellationToken _shutdownToken;
        private readonly IBufferedLogger? _logger;
        private bool _disposed;

        public ExtentWriter(int extentId, PagedFileStore store, int queueCapacity, CancellationToken shutdownToken, IBufferedLogger? logger)
        {
            _extentId = extentId;
            _store = store;
            _shutdownToken = shutdownToken;
            _logger = logger;

            var options = new BoundedChannelOptions(queueCapacity)
            {
                FullMode = BoundedChannelFullMode.DropWrite
            };
            _commandQueue = Channel.CreateBounded<object>(options);
            _writerTask = Task.Run(WriterLoop, shutdownToken);
        }

        public bool TryEnqueueWrite(WriteCommand cmd)
        {
            return _commandQueue.Writer.TryWrite(cmd);
        }

        public bool TryEnqueueAllocate(long pageId, AllocateCommand cmd)
        {
            return _commandQueue.Writer.TryWrite((pageId, cmd));
        }

        private async Task WriterLoop()
        {
            try
            {
                await foreach (var command in _commandQueue.Reader.ReadAllAsync(_shutdownToken))
                {
                    try
                    {
                        if (command is WriteCommand writeCmd)
                        {
                            await ProcessWriteCommand(writeCmd);
                        }
                        else if (command is ValueTuple<long, AllocateCommand> allocateTuple)
                        {
                            await ProcessAllocateCommand(allocateTuple.Item1, allocateTuple.Item2);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger?.LogError($"Extent {_extentId} writer error", ex);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                // Normal shutdown
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Extent {_extentId} writer loop failed", ex);
            }
        }

        private async Task ProcessWriteCommand(WriteCommand cmd)
        {
            try
            {
                // Get current metadata
                var currentMetadata = await _store.HeadPageAsync(cmd.PageId, _shutdownToken);

                // Optimistic concurrency check
                if (cmd.ExpectedVersion.HasValue)
                {
                    if (!currentMetadata.Exists)
                    {
                        cmd.Completion.SetResult(WriteResult.FailureResult("Page does not exist"));
                        return;
                    }

                    if (currentMetadata.Version != cmd.ExpectedVersion.Value)
                    {
                        cmd.Completion.SetResult(WriteResult.VersionMismatch(currentMetadata.Version, cmd.ExpectedVersion.Value));
                        return;
                    }
                }

                // Bump version
                var newVersion = _store.GetNextSequence();

                // Write page
                await WritePageToDisk(cmd.PageId, cmd.Data, newVersion);

                // Update cache
                var newMetadata = new PageMetadata(cmd.PageId, newVersion, cmd.Data.Length, true);
                _store._metadataCache[cmd.PageId] = newMetadata;

                cmd.Completion.SetResult(WriteResult.SuccessResult(newVersion));
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Failed to process write command for page {cmd.PageId}", ex);
                cmd.Completion.SetResult(WriteResult.FailureResult(ex.Message));
            }
        }

        private async Task ProcessAllocateCommand(long pageId, AllocateCommand cmd)
        {
            try
            {
                // Allocate new version
                var newVersion = _store.GetNextSequence();

                // Write page
                await WritePageToDisk(pageId, cmd.Data, newVersion);

                // Update cache
                var newMetadata = new PageMetadata(pageId, newVersion, cmd.Data.Length, true);
                _store._metadataCache[pageId] = newMetadata;

                cmd.Completion.SetResult(AllocateResult.SuccessResult(pageId, newVersion));
            }
            catch (Exception ex)
            {
                _logger?.LogError($"Failed to process allocate command for page {pageId}", ex);
                cmd.Completion.SetResult(AllocateResult.FailureResult(ex.Message));
            }
        }

        private async Task WritePageToDisk(long pageId, byte[] data, long version)
        {
            using var pagedFile = _store._provider.OpenPagedFile(_store._storeName, PageStoreFileName, _store._pageSize, FileAccess.ReadWrite);
            var buffer = ArrayPool<byte>.Shared.Rent(_store._pageSize);
            try
            {
                var span = buffer.AsSpan(0, _store._pageSize);
                span.Clear();

                // Write header
                BinaryPrimitives.WriteUInt32LittleEndian(span.Slice(HeaderMagicOffset, 4), PageMagic);
                BinaryPrimitives.WriteInt64LittleEndian(span.Slice(HeaderVersionOffset, 8), version);
                BinaryPrimitives.WriteInt32LittleEndian(span.Slice(HeaderSizeOffset, 4), data.Length);
                span[HeaderFlagsOffset] = PageFlagActive;

                // Write data
                data.CopyTo(span.Slice(PageHeaderSize));

                // Write page (physical index is pageId - 1)
                var physicalIndex = pageId - 1;
                await pagedFile.WritePageAsync(physicalIndex, buffer.AsMemory(0, _store._pageSize), _shutdownToken);
                await pagedFile.FlushAsync(_shutdownToken);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;

            _commandQueue.Writer.Complete();
            try
            {
                _writerTask.Wait(TimeSpan.FromSeconds(5));
            }
            catch
            {
                // Best effort
            }
        }
    }
}
