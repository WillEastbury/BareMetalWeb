using System.Buffers;
using System.Diagnostics;
using System.IO.Pipelines;

namespace BareMetalWeb.Rendering;

/// <summary>
/// Captures per-render metrics: total render time, PipeWriter flush/GetSpan counts,
/// fragment copy count, and allocation delta.
/// </summary>
public sealed class RenderInstrumentation
{
    public TimeSpan RenderTime { get; set; }
    public int FlushCount { get; set; }
    public int GetSpanCount { get; set; }
    public int FragmentCopyCount { get; set; }
    public long AllocationBytes { get; set; }

    public override string ToString() =>
        $"Render: {RenderTime.TotalMicroseconds:F1}µs | Flushes: {FlushCount} | GetSpan: {GetSpanCount} | Copies: {FragmentCopyCount} | Alloc: {AllocationBytes}B";
}

/// <summary>
/// Wraps a <see cref="PipeWriter"/> to count GetSpan, Advance, and FlushAsync calls
/// without adding allocation overhead to the hot path.
/// </summary>
public sealed class InstrumentedPipeWriter : PipeWriter
{
    private readonly PipeWriter _inner;
    private int _getSpanCount;
    private int _advanceCount;
    private int _flushCount;
    private int _fragmentCopyCount;

    public int GetSpanCount => _getSpanCount;
    public int AdvanceCount => _advanceCount;
    public int FlushCount => _flushCount;
    public int FragmentCopyCount => _fragmentCopyCount;

    public InstrumentedPipeWriter(PipeWriter inner)
    {
        _inner = inner;
    }

    public void IncrementFragmentCopy() => _fragmentCopyCount++;

    public override void Advance(int bytes)
    {
        _advanceCount++;
        _inner.Advance(bytes);
    }

    public override Memory<byte> GetMemory(int sizeHint = 0) => _inner.GetMemory(sizeHint);

    public override Span<byte> GetSpan(int sizeHint = 0)
    {
        _getSpanCount++;
        return _inner.GetSpan(sizeHint);
    }

    public override void CancelPendingFlush() => _inner.CancelPendingFlush();

    public override void Complete(Exception? exception = null) => _inner.Complete(exception);

    public override ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default)
    {
        _flushCount++;
        return _inner.FlushAsync(cancellationToken);
    }

    /// <summary>Snapshot current counters into a <see cref="RenderInstrumentation"/>.</summary>
    public RenderInstrumentation Snapshot(TimeSpan elapsed, long allocDelta) => new()
    {
        RenderTime = elapsed,
        FlushCount = _flushCount,
        GetSpanCount = _getSpanCount,
        FragmentCopyCount = _fragmentCopyCount,
        AllocationBytes = allocDelta
    };

    public void Reset()
    {
        _getSpanCount = 0;
        _advanceCount = 0;
        _flushCount = 0;
        _fragmentCopyCount = 0;
    }
}

/// <summary>
/// Runs a render delegate under instrumentation, capturing allocation delta and timing.
/// </summary>
public static class RenderBenchmark
{
    /// <summary>
    /// Measures a single render invocation, returning instrumentation data.
    /// </summary>
    public static async ValueTask<RenderInstrumentation> MeasureAsync(
        PipeWriter rawWriter,
        Func<InstrumentedPipeWriter, ValueTask> renderAction)
    {
        var instrumented = new InstrumentedPipeWriter(rawWriter);
        long allocBefore = GC.GetAllocatedBytesForCurrentThread();
        long startTs = Stopwatch.GetTimestamp();

        await renderAction(instrumented);

        var elapsed = Stopwatch.GetElapsedTime(startTs);
        long allocDelta = GC.GetAllocatedBytesForCurrentThread() - allocBefore;
        return instrumented.Snapshot(elapsed, allocDelta);
    }

    /// <summary>
    /// Runs <paramref name="iterations"/> of a render, returning average instrumentation.
    /// </summary>
    public static async ValueTask<RenderInstrumentation> BenchmarkAsync(
        Func<PipeWriter> writerFactory,
        Func<InstrumentedPipeWriter, ValueTask> renderAction,
        int iterations = 100)
    {
        // Warm-up
        for (int i = 0; i < 5; i++)
        {
            var w = new InstrumentedPipeWriter(writerFactory());
            await renderAction(w);
            await w.CompleteAsync();
        }

        long totalFlushes = 0, totalGetSpan = 0, totalCopies = 0, totalAlloc = 0;
        double totalUs = 0;

        for (int i = 0; i < iterations; i++)
        {
            var w = writerFactory();
            var result = await MeasureAsync(w, renderAction);
            await w.CompleteAsync();

            totalFlushes += result.FlushCount;
            totalGetSpan += result.GetSpanCount;
            totalCopies += result.FragmentCopyCount;
            totalAlloc += result.AllocationBytes;
            totalUs += result.RenderTime.TotalMicroseconds;
        }

        return new RenderInstrumentation
        {
            RenderTime = TimeSpan.FromMicroseconds(totalUs / iterations),
            FlushCount = (int)(totalFlushes / iterations),
            GetSpanCount = (int)(totalGetSpan / iterations),
            FragmentCopyCount = (int)(totalCopies / iterations),
            AllocationBytes = totalAlloc / iterations
        };
    }
}
