using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Threading;
using System.Threading.Tasks;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Host.Tests;

/// <summary>
/// Tests for <see cref="WalStreamWriter"/> binary length-prefixed WAL streaming.
/// </summary>
public class WalStreamWriterTests : IDisposable
{
    private readonly string _tempDir;
    private readonly WalStore _walStore;
    private readonly WalDataProvider _walProvider;

    public WalStreamWriterTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "bmw_walstream_" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);

        _walProvider = new WalDataProvider(_tempDir);
        _walStore = _walProvider.WalStore;
    }

    public void Dispose()
    {
        _walProvider.Dispose();
        try { Directory.Delete(_tempDir, true); } catch { }
    }

    [Fact]
    public async Task StreamAllAsync_EmptyStore_WritesZeroCount()
    {
        var pipe = new Pipe();
        var count = await WalStreamWriter.StreamAllAsync(pipe.Writer, _walProvider, CancellationToken.None);
        await pipe.Writer.CompleteAsync();

        Assert.Equal(0, count);

        var result = await pipe.Reader.ReadAsync();
        var buffer = result.Buffer;
        Assert.True(buffer.Length >= 4);

        var countBytes = new byte[4];
        buffer.Slice(0, 4).CopyTo(countBytes);
        var recordCount = BinaryPrimitives.ReadUInt32LittleEndian(countBytes);
        Assert.Equal(0u, recordCount);

        pipe.Reader.AdvanceTo(buffer.End);
        await pipe.Reader.CompleteAsync();
    }

    [Fact]
    public async Task StreamAllAsync_WithRecords_WritesCorrectFraming()
    {
        // Commit some WAL records
        var tableId = 1u;
        var key1 = _walStore.AllocateKey(tableId);
        var key2 = _walStore.AllocateKey(tableId);
        var payload1 = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var payload2 = new byte[] { 0xAA, 0xBB, 0xCC };

        await _walStore.CommitAsync(new[]
        {
            WalOp.Upsert(key1, payload1),
            WalOp.Upsert(key2, payload2),
        });

        var pipe = new Pipe();
        var count = await WalStreamWriter.StreamAllAsync(pipe.Writer, _walProvider, CancellationToken.None);
        await pipe.Writer.CompleteAsync();

        Assert.Equal(2, count);

        // Read all output
        var result = await pipe.Reader.ReadAsync();
        var buffer = result.Buffer;
        var bytes = buffer.ToArray();
        pipe.Reader.AdvanceTo(buffer.End);
        await pipe.Reader.CompleteAsync();

        // Verify framing: [count:4] [len1:4] [data1:N] [len2:4] [data2:N]
        int offset = 0;
        var recordCount = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
        offset += 4;
        Assert.Equal(2u, recordCount);

        // Record 1
        var len1 = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
        offset += 4;
        Assert.True(len1 > 0);
        offset += (int)len1;

        // Record 2
        var len2 = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(offset, 4));
        offset += 4;
        Assert.True(len2 > 0);
        offset += (int)len2;

        // All bytes consumed
        Assert.Equal(bytes.Length, offset);
    }

    [Fact]
    public async Task StreamEntityAsync_UnknownEntity_WritesZeroCount()
    {
        var pipe = new Pipe();
        var count = await WalStreamWriter.StreamEntityAsync(
            pipe.Writer, _walProvider, "nonexistent", CancellationToken.None);
        await pipe.Writer.CompleteAsync();

        Assert.Equal(0, count);

        var result = await pipe.Reader.ReadAsync();
        var buffer = result.Buffer;
        var bytes = new byte[4];
        buffer.Slice(0, 4).CopyTo(bytes);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(bytes));

        pipe.Reader.AdvanceTo(buffer.End);
        await pipe.Reader.CompleteAsync();
    }

    [Fact]
    public async Task StreamAllAsync_Cancellation_ThrowsWhenCancelled()
    {
        // Pre-cancelled token should throw immediately
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        // Commit a record so there's data to iterate
        var key = _walStore.AllocateKey(1u);
        await _walStore.CommitAsync(new[] { WalOp.Upsert(key, new byte[] { 1, 2 }) });

        var pipe = new Pipe();
        try
        {
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await WalStreamWriter.StreamAllAsync(pipe.Writer, _walProvider, cts.Token));
        }
        finally
        {
            await pipe.Writer.CompleteAsync();
            await pipe.Reader.CompleteAsync();
        }
    }

    [Fact]
    public async Task StreamAllAsync_LargePayload_FramesCorrectly()
    {
        // 4KB payload (compressible text to avoid Brotli expansion)
        var payload = new byte[4096];
        Array.Fill<byte>(payload, 0x41); // 'A' repeated — highly compressible
        var key = _walStore.AllocateKey(1u);
        await _walStore.CommitAsync(new[] { WalOp.Upsert(key, payload) });

        var pipe = new Pipe(new PipeOptions(useSynchronizationContext: false));
        var count = await WalStreamWriter.StreamAllAsync(pipe.Writer, _walProvider, CancellationToken.None);
        await pipe.Writer.CompleteAsync();

        Assert.Equal(1, count);

        // Read all output
        var ms = new MemoryStream();
        while (true)
        {
            var result = await pipe.Reader.ReadAsync();
            foreach (var seg in result.Buffer)
                ms.Write(seg.Span);
            pipe.Reader.AdvanceTo(result.Buffer.End);
            if (result.IsCompleted) break;
        }
        await pipe.Reader.CompleteAsync();
        var bytes = ms.ToArray();

        // Count header
        var recordCount = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0, 4));
        Assert.Equal(1u, recordCount);

        // Length prefix
        var len = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(4, 4));
        Assert.True(len > 0);

        // Total = 4 (count) + 4 (len) + len (payload)
        Assert.Equal(8 + (int)len, bytes.Length);
    }
}
