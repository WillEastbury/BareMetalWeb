using System.IO;
using System.IO.Pipelines;
using System.Text;
using BareMetalWeb.Rendering;
using Xunit;

namespace BareMetalWeb.Rendering.Tests;

public class RenderInstrumentationTests
{
    private static PipeWriter CreatePipeWriter(MemoryStream? ms = null)
        => PipeWriter.Create(ms ?? new MemoryStream());

    [Fact]
    public void InstrumentedPipeWriter_CountsGetSpanCalls()
    {
        var ms = new MemoryStream();
        var iw = new InstrumentedPipeWriter(PipeWriter.Create(ms));

        var span = iw.GetSpan(16);
        "Hello"u8.CopyTo(span);
        iw.Advance(5);

        span = iw.GetSpan(16);
        " World"u8.CopyTo(span);
        iw.Advance(6);

        Assert.Equal(2, iw.GetSpanCount);
        Assert.Equal(2, iw.AdvanceCount);
    }

    [Fact]
    public async Task InstrumentedPipeWriter_CountsFlushCalls()
    {
        var ms = new MemoryStream();
        var iw = new InstrumentedPipeWriter(PipeWriter.Create(ms));

        var span = iw.GetSpan(4);
        "OK"u8.CopyTo(span);
        iw.Advance(2);
        await iw.FlushAsync();
        await iw.FlushAsync();

        Assert.Equal(2, iw.FlushCount);
    }

    [Fact]
    public void InstrumentedPipeWriter_TracksFragmentCopies()
    {
        var iw = new InstrumentedPipeWriter(PipeWriter.Create(new MemoryStream()));
        iw.IncrementFragmentCopy();
        iw.IncrementFragmentCopy();
        iw.IncrementFragmentCopy();
        Assert.Equal(3, iw.FragmentCopyCount);
    }

    [Fact]
    public void InstrumentedPipeWriter_Reset_ClearsAllCounters()
    {
        var iw = new InstrumentedPipeWriter(PipeWriter.Create(new MemoryStream()));
        _ = iw.GetSpan(4);
        iw.Advance(0);
        iw.IncrementFragmentCopy();
        iw.Reset();

        Assert.Equal(0, iw.GetSpanCount);
        Assert.Equal(0, iw.AdvanceCount);
        Assert.Equal(0, iw.FragmentCopyCount);
    }

    [Fact]
    public async Task InstrumentedPipeWriter_Snapshot_CapturesMetrics()
    {
        var iw = new InstrumentedPipeWriter(PipeWriter.Create(new MemoryStream()));
        _ = iw.GetSpan(4);
        iw.Advance(0);
        await iw.FlushAsync();
        iw.IncrementFragmentCopy();
        iw.IncrementFragmentCopy();

        var snap = iw.Snapshot(TimeSpan.FromMicroseconds(42), 1024);
        Assert.Equal(42, snap.RenderTime.TotalMicroseconds, 1);
        Assert.Equal(1, snap.FlushCount);
        Assert.Equal(1, snap.GetSpanCount);
        Assert.Equal(2, snap.FragmentCopyCount);
        Assert.Equal(1024, snap.AllocationBytes);
    }

    [Fact]
    public async Task InstrumentedPipeWriter_WritesDataCorrectly()
    {
        var ms = new MemoryStream();
        var iw = new InstrumentedPipeWriter(PipeWriter.Create(ms));

        var span = iw.GetSpan(16);
        "Hello BMW"u8.CopyTo(span);
        iw.Advance(9);
        await iw.FlushAsync();
        iw.Complete();

        Assert.Equal("Hello BMW", Encoding.UTF8.GetString(ms.ToArray()));
    }

    [Fact]
    public async Task RenderBenchmark_MeasureAsync_ReturnsPositiveMetrics()
    {
        var ms = new MemoryStream();
        var writer = PipeWriter.Create(ms);

        var result = await RenderBenchmark.MeasureAsync(writer, async iw =>
        {
            var s = iw.GetSpan(32);
            "<div>test</div>"u8.CopyTo(s);
            iw.Advance(15);
            iw.IncrementFragmentCopy();
            await iw.FlushAsync();
        });

        Assert.True(result.RenderTime.TotalMicroseconds > 0);
        Assert.Equal(1, result.FlushCount);
        Assert.Equal(1, result.GetSpanCount);
        Assert.Equal(1, result.FragmentCopyCount);
    }

    [Fact]
    public async Task RenderBenchmark_BenchmarkAsync_AveragesOverIterations()
    {
        var result = await RenderBenchmark.BenchmarkAsync(
            () => PipeWriter.Create(new MemoryStream()),
            async iw =>
            {
                var s = iw.GetSpan(8);
                "OK"u8.CopyTo(s);
                iw.Advance(2);
                iw.IncrementFragmentCopy();
                await iw.FlushAsync();
            },
            iterations: 10);

        Assert.True(result.RenderTime.TotalMicroseconds > 0);
        Assert.Equal(1, result.FlushCount);
        Assert.Equal(1, result.GetSpanCount);
        Assert.Equal(1, result.FragmentCopyCount);
    }

    [Fact]
    public void RenderInstrumentation_ToString_ContainsAllMetrics()
    {
        var ri = new RenderInstrumentation
        {
            RenderTime = TimeSpan.FromMicroseconds(123.4),
            FlushCount = 2,
            GetSpanCount = 10,
            FragmentCopyCount = 5,
            AllocationBytes = 2048
        };

        var s = ri.ToString();
        Assert.Contains("123.4", s);
        Assert.Contains("Flushes: 2", s);
        Assert.Contains("GetSpan: 10", s);
        Assert.Contains("Copies: 5", s);
        Assert.Contains("2048", s);
    }
}
