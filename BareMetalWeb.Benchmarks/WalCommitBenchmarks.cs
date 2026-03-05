using System;
using System.IO;
using System.Text;
using BareMetalWeb.Data;
using BenchmarkDotNet.Attributes;

namespace BareMetalWeb.Benchmarks;

/// <summary>
/// Measures WAL commit throughput: how many records per second the WAL can
/// durably commit under various batch sizes.
///
/// Each benchmark iteration calls <see cref="WalStore.CommitAsync"/> once and
/// waits for the result. BenchmarkDotNet reports the mean latency; the
/// inverse gives commits/second.  Multiply by the batch size to get
/// records/second written per commit.
///
/// Typical single-commit path (one op):
///   serialize → CRC32C → fsync → head-map update
/// </summary>
[MemoryDiagnoser]
[ShortRunJob]
public class WalCommitBenchmarks : IDisposable
{
    private string _dir = null!;
    private WalStore _store = null!;

    // Pre-built payloads to exclude serialisation cost from the measurement.
    private static readonly byte[] SmallPayload  = Encoding.UTF8.GetBytes(new string('A', 128));
    private static readonly byte[] MediumPayload = Encoding.UTF8.GetBytes(new string('B', 512));

    // Monotonic key counter shared across benchmark methods; ensures every
    // commit targets a unique key so head-map merges don't skew the read path.
    // Use long (supported by Interlocked.Increment); cast to ulong before use.
    private long _keyCounter;

    // Pre-allocated op arrays to avoid per-iteration heap pressure.
    private WalOp[] _batch10  = null!;
    private WalOp[] _batch100 = null!;

    [GlobalSetup]
    public void Setup()
    {
        _dir = Path.Combine(Path.GetTempPath(), $"bmw_wal_bench_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_dir);
        _store = new WalStore(_dir);
        _keyCounter = 1;
        _batch10    = new WalOp[10];
        _batch100   = new WalOp[100];
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        _store.Dispose();
        if (Directory.Exists(_dir))
            Directory.Delete(_dir, recursive: true);
    }

    // ── Single-op commits (baseline: 1 record per fsync) ─────────────────────

    /// <summary>
    /// Commits a single small-payload op (~128 bytes uncompressed).
    /// Represents the minimum overhead per durable record.
    /// </summary>
    [Benchmark(Baseline = true, Description = "1 op / 128 B payload")]
    public void CommitSingleSmall()
    {
        ulong key = (ulong)System.Threading.Interlocked.Increment(ref _keyCounter);
        var ops = new[] { WalOp.Upsert(key, SmallPayload) };
        _store.CommitAsync(ops).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Commits a single medium-payload op (~512 bytes uncompressed).
    /// </summary>
    [Benchmark(Description = "1 op / 512 B payload")]
    public void CommitSingleMedium()
    {
        ulong key = (ulong)System.Threading.Interlocked.Increment(ref _keyCounter);
        var ops = new[] { WalOp.Upsert(key, MediumPayload) };
        _store.CommitAsync(ops).GetAwaiter().GetResult();
    }

    // ── Batch commits (N records per fsync) ───────────────────────────────────

    /// <summary>
    /// Commits 10 ops in a single atomic batch.
    /// Amortises the fsync cost over 10 records.
    /// </summary>
    [Benchmark(Description = "10 ops / 128 B each")]
    public void CommitBatch10()
    {
        for (int i = 0; i < _batch10.Length; i++)
        {
            ulong key = (ulong)System.Threading.Interlocked.Increment(ref _keyCounter);
            _batch10[i] = WalOp.Upsert(key, SmallPayload);
        }
        _store.CommitAsync(_batch10).GetAwaiter().GetResult();
    }

    /// <summary>
    /// Commits 100 ops in a single atomic batch.
    /// Shows how well the WAL amortises the per-fsync cost at larger batch sizes.
    /// </summary>
    [Benchmark(Description = "100 ops / 128 B each")]
    public void CommitBatch100()
    {
        for (int i = 0; i < _batch100.Length; i++)
        {
            ulong key = (ulong)System.Threading.Interlocked.Increment(ref _keyCounter);
            _batch100[i] = WalOp.Upsert(key, SmallPayload);
        }
        _store.CommitAsync(_batch100).GetAwaiter().GetResult();
    }

    public void Dispose() => Cleanup();
}
