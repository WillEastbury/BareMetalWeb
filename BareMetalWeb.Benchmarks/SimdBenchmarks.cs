using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Diagnosers;
using BareMetalWeb.Benchmarks.Simd;

namespace BareMetalWeb.Benchmarks;

/// <summary>
/// BenchmarkDotNet suite for the SIMD acceleration spike.
///
/// Compares Scalar vs Vector&lt;T&gt; vs AVX2 for:
///   – Column scans (int and long columns)
///   – Column copy (int, long, byte)
///   – Delta encoding compression
///   – Bitmask filter generation
///
/// <b>Run command (Release build required):</b>
/// <code>
///   dotnet run --project BareMetalWeb.Benchmarks --configuration Release
/// </code>
///
/// The dataset is 100 % deterministic (seeded with a fixed value) so results
/// are fully reproducible.
/// </summary>
[ShortRunJob]
[MemoryDiagnoser]
[HardwareCounters(
    HardwareCounter.BranchMispredictions,
    HardwareCounter.CacheMisses)]
public class SimdBenchmarks
{
    // ── Parameters ───────────────────────────────────────────────────────

    /// <summary>Number of rows in the test column. Parameterised: 1K / 10K / 1M.</summary>
    [Params(1_000, 10_000, 1_000_000)]
    public int Rows { get; set; }

    // ── Test data ────────────────────────────────────────────────────────

    private int[]  _intColumn   = null!;
    private long[] _longColumn  = null!;
    private byte[] _byteColumn  = null!;
    private short[] _shortColumn = null!;

    private int[]  _intDest     = null!;
    private long[] _longDest    = null!;
    private byte[] _byteDest    = null!;

    private int[]  _deltaOutput = null!;
    private int[]  _decodeOutput = null!;

    /// <summary>Target value present in ~10 % of rows (realistic selectivity).</summary>
    private const int ScanTarget = 42;

    [GlobalSetup]
    public void Setup()
    {
        // Deterministic data — no random allocations during the benchmark run itself
        _intColumn    = GenerateIntColumn(Rows, seed: 12345, target: ScanTarget, hitRate: 10);
        _longColumn   = GenerateLongColumn(Rows, seed: 12345);
        _byteColumn   = GenerateByteColumn(Rows, seed: 12345);
        _shortColumn  = GenerateShortColumn(Rows, seed: 12345);

        _intDest      = new int[Rows];
        _longDest     = new long[Rows];
        _byteDest     = new byte[Rows];

        _deltaOutput  = new int[Rows];
        _decodeOutput = new int[Rows];

        // Log CPU capabilities once during setup
        ColumnScan.LogCapabilities(msg => Console.WriteLine($"[CPU] {msg}"));
    }

    // ── Column Scan benchmarks ───────────────────────────────────────────

    /// <summary>Baseline: scalar int column scan.</summary>
    [Benchmark(Baseline = true, Description = "Scan int – Scalar")]
    [BenchmarkCategory("ColumnScan")]
    public List<int> ColumnScan_Int_Scalar() =>
        ColumnScan.ScanScalar(_intColumn, ScanTarget);

    /// <summary>Portable SIMD int column scan.</summary>
    [Benchmark(Description = "Scan int – Vector<T>")]
    [BenchmarkCategory("ColumnScan")]
    public List<int> ColumnScan_Int_Vector() =>
        ColumnScan.ScanVector(_intColumn, ScanTarget);

    /// <summary>AVX2 int column scan.</summary>
    [Benchmark(Description = "Scan int – AVX2")]
    [BenchmarkCategory("ColumnScan")]
    public List<int> ColumnScan_Int_Avx2() =>
        ColumnScan.ScanAvx2(_intColumn, ScanTarget);

    /// <summary>Scalar long column scan.</summary>
    [Benchmark(Description = "Scan long – Scalar")]
    [BenchmarkCategory("ColumnScan")]
    public List<int> ColumnScan_Long_Scalar() =>
        ColumnScan.ScanScalar(_longColumn, 42L);

    /// <summary>AVX2 long column scan.</summary>
    [Benchmark(Description = "Scan long – AVX2")]
    [BenchmarkCategory("ColumnScan")]
    public List<int> ColumnScan_Long_Avx2() =>
        ColumnScan.ScanAvx2(_longColumn, 42L);

    // ── Bitmask filter benchmarks ────────────────────────────────────────

    /// <summary>Returns a ulong[] bitmask — cheaper composition downstream.</summary>
    [Benchmark(Description = "Bitmask filter – int")]
    [BenchmarkCategory("BitmaskFilter")]
    public ulong[] BitmaskFilter_Int() =>
        ColumnScan.ScanToBitmask(_intColumn, ScanTarget);

    // ── Column Copy benchmarks ───────────────────────────────────────────

    /// <summary>Scalar int column copy.</summary>
    [Benchmark(Description = "Copy int – Scalar")]
    [BenchmarkCategory("ColumnCopy")]
    public void ColumnCopy_Int_Scalar() =>
        ColumnCopy.CopyScalar(_intColumn, _intDest);

    /// <summary>Portable Vector&lt;int&gt; copy.</summary>
    [Benchmark(Description = "Copy int – Vector<T>")]
    [BenchmarkCategory("ColumnCopy")]
    public void ColumnCopy_Int_Vector() =>
        ColumnCopy.CopyVector<int>(_intColumn, _intDest);

    /// <summary>AVX2 int copy (32 bytes per instruction).</summary>
    [Benchmark(Description = "Copy int – AVX2")]
    [BenchmarkCategory("ColumnCopy")]
    public void ColumnCopy_Int_Avx2() =>
        ColumnCopy.CopyAvx2(_intColumn, _intDest);

    /// <summary>Scalar long copy.</summary>
    [Benchmark(Description = "Copy long – Scalar")]
    [BenchmarkCategory("ColumnCopy")]
    public void ColumnCopy_Long_Scalar() =>
        ColumnCopy.CopyScalar(_longColumn, _longDest);

    /// <summary>AVX2 long copy.</summary>
    [Benchmark(Description = "Copy long – AVX2")]
    [BenchmarkCategory("ColumnCopy")]
    public void ColumnCopy_Long_Avx2() =>
        ColumnCopy.CopyAvx2(_longColumn, _longDest);

    /// <summary>Scalar byte copy.</summary>
    [Benchmark(Description = "Copy byte – Scalar")]
    [BenchmarkCategory("ColumnCopy")]
    public void ColumnCopy_Byte_Scalar() =>
        ColumnCopy.CopyScalar(_byteColumn, _byteDest);

    /// <summary>AVX2 byte copy (maximum bandwidth utilization).</summary>
    [Benchmark(Description = "Copy byte – AVX2")]
    [BenchmarkCategory("ColumnCopy")]
    public void ColumnCopy_Byte_Avx2() =>
        ColumnCopy.CopyAvx2(_byteColumn, _byteDest);

    // ── Delta encoding benchmarks ────────────────────────────────────────

    /// <summary>Scalar delta encode.</summary>
    [Benchmark(Description = "DeltaEncode – Scalar")]
    [BenchmarkCategory("Compression")]
    public void DeltaEncode_Scalar() =>
        Compression.DeltaEncodeScalar(_intColumn, _deltaOutput);

    /// <summary>Portable Vector&lt;int&gt; delta encode.</summary>
    [Benchmark(Description = "DeltaEncode – Vector<T>")]
    [BenchmarkCategory("Compression")]
    public void DeltaEncode_Vector() =>
        Compression.DeltaEncodeVector(_intColumn, _deltaOutput);

    /// <summary>AVX2 delta encode.</summary>
    [Benchmark(Description = "DeltaEncode – AVX2")]
    [BenchmarkCategory("Compression")]
    public void DeltaEncode_Avx2() =>
        Compression.DeltaEncodeAvx2(_intColumn, _deltaOutput);

    /// <summary>Scalar delta decode (prefix sum).</summary>
    [Benchmark(Description = "DeltaDecode – Scalar")]
    [BenchmarkCategory("Compression")]
    public void DeltaDecode_Scalar()
    {
        Compression.DeltaEncodeScalar(_intColumn, _deltaOutput);
        Compression.DeltaDecodeScalar(_deltaOutput, _decodeOutput);
    }

    /// <summary>AVX2 delta decode.</summary>
    [Benchmark(Description = "DeltaDecode – AVX2")]
    [BenchmarkCategory("Compression")]
    public void DeltaDecode_Avx2()
    {
        Compression.DeltaEncodeAvx2(_intColumn, _deltaOutput);
        Compression.DeltaDecodeAvx2(_deltaOutput, _decodeOutput);
    }

    /// <summary>Zero counting after delta encode (AVX2 vs scalar).</summary>
    [Benchmark(Description = "ZeroCount – Scalar")]
    [BenchmarkCategory("Compression")]
    public int ZeroCount_Scalar()
    {
        Compression.DeltaEncodeScalar(_intColumn, _deltaOutput);
        return Compression.CountZerosScalar(_deltaOutput);
    }

    /// <summary>Zero counting after delta encode using AVX2.</summary>
    [Benchmark(Description = "ZeroCount – AVX2")]
    [BenchmarkCategory("Compression")]
    public int ZeroCount_Avx2()
    {
        Compression.DeltaEncodeAvx2(_intColumn, _deltaOutput);
        return Compression.CountZerosAvx2(_deltaOutput);
    }

    // ── Data generators ──────────────────────────────────────────────────

    private static int[] GenerateIntColumn(int rows, int seed, int target, int hitRate)
    {
        var data = new int[rows];
        int next = seed;
        for (int i = 0; i < rows; i++)
        {
            next = next * 1664525 + 1013904223; // LCG
            data[i] = (i % hitRate == 0) ? target : (Math.Abs(next) % 1000) + 1;
        }
        return data;
    }

    private static long[] GenerateLongColumn(int rows, int seed)
    {
        var data = new long[rows];
        long next = seed;
        for (int i = 0; i < rows; i++)
        {
            next = next * 6364136223846793005L + 1442695040888963407L; // Knuth LCG
            data[i] = Math.Abs(next % 1_000_000L);
        }
        return data;
    }

    private static byte[] GenerateByteColumn(int rows, int seed)
    {
        var data = new byte[rows];
        int next = seed;
        for (int i = 0; i < rows; i++)
        {
            next = next * 1664525 + 1013904223;
            data[i] = (byte)(next & 0xFF);
        }
        return data;
    }

    private static short[] GenerateShortColumn(int rows, int seed)
    {
        var data = new short[rows];
        int next = seed;
        for (int i = 0; i < rows; i++)
        {
            next = next * 1664525 + 1013904223;
            data[i] = (short)(Math.Abs(next) % 32768);
        }
        return data;
    }
}
