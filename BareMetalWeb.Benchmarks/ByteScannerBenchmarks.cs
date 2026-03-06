using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using BareMetalWeb.Data;

namespace BareMetalWeb.Benchmarks;

/// <summary>
/// Measures <see cref="SimdByteScanner.FindByte"/> performance across three implementations:
/// <list type="bullet">
///   <item>Scalar — plain loop, one byte per iteration (baseline)</item>
///   <item>Span.IndexOf — .NET runtime vectorised search via SearchValues / SSE2</item>
///   <item>SimdByteScanner — explicit AVX2 / ARM AdvSimd / portable Vector&lt;byte&gt;</item>
/// </list>
///
/// <para><b>Run command (Release build required):</b></para>
/// <code>
///   dotnet run --project BareMetalWeb.Benchmarks --configuration Release -- --filter *ByteScanner*
/// </code>
///
/// <para>Expected output on AVX2 hardware (approximate):</para>
/// <code>
///   | Method                  |    Size | Mean      | Ratio |
///   |------------------------ |-------- |---------- |------ |
///   | Scalar_FindByte         | 1048576 | ~300 µs   |  1.00 |
///   | SpanIndexOf_FindByte    | 1048576 | ~80  µs   |  0.27 |
///   | Simd_FindByte_NoMatch   | 1048576 | ~60  µs   |  0.20 |
///   | Simd_FindByte_MatchEnd  | 1048576 | ~60  µs   |  0.20 |
///   | Simd_FindByte_MatchMid  | 1048576 | ~30  µs   |  0.10 |
/// </code>
/// </summary>
[SimpleJob(RuntimeMoniker.Net90)]
[MemoryDiagnoser]
public class ByteScannerBenchmarks
{
    /// <summary>Buffer size in bytes. Parameterised to show scaling.</summary>
    [Params(1_024, 65_536, 1_048_576)]
    public int Size { get; set; }

    private byte[] _noMatch     = null!; // target never present
    private byte[] _matchEnd    = null!; // target only at the last byte
    private byte[] _matchMid    = null!; // target at the exact midpoint

    private const byte Target = 0x7B; // ASCII '{' — common template-scanning target

    [GlobalSetup]
    public void Setup()
    {
        // Fill with 0x01 so Target (0x7B) never appears by default.
        _noMatch  = new byte[Size];
        Array.Fill(_noMatch, (byte)0x01);

        _matchEnd = new byte[Size];
        Array.Fill(_matchEnd, (byte)0x01);
        _matchEnd[Size - 1] = Target;      // force a full scan before the hit

        _matchMid = new byte[Size];
        Array.Fill(_matchMid, (byte)0x01);
        _matchMid[Size / 2] = Target;      // hit at midpoint — half the work

        Console.WriteLine($"[CPU] {SimdByteScanner.ActivePath}");
    }

    // ─── Scalar baseline ─────────────────────────────────────────────────────

    /// <summary>
    /// Plain loop — one byte comparison per iteration.
    /// Serves as the timing baseline (Ratio = 1.00).
    /// </summary>
    [Benchmark(Baseline = true, Description = "Scalar – no match")]
    public int Scalar_FindByte_NoMatch()
    {
        ReadOnlySpan<byte> data = _noMatch;
        for (int i = 0; i < data.Length; i++)
            if (data[i] == Target) return i;
        return -1;
    }

    // ─── .NET runtime built-in (SSE2 / NEON) ─────────────────────────────────

    /// <summary>
    /// <c>MemoryExtensions.IndexOf(byte)</c> — the .NET runtime selects an
    /// SSE2 or NEON vector path; serves as the managed-runtime reference point.
    /// </summary>
    [Benchmark(Description = "Span.IndexOf – no match")]
    public int SpanIndexOf_FindByte_NoMatch()
        => ((ReadOnlySpan<byte>)_noMatch).IndexOf(Target);

    [Benchmark(Description = "Span.IndexOf – match at end")]
    public int SpanIndexOf_FindByte_MatchEnd()
        => ((ReadOnlySpan<byte>)_matchEnd).IndexOf(Target);

    [Benchmark(Description = "Span.IndexOf – match at mid")]
    public int SpanIndexOf_FindByte_MatchMid()
        => ((ReadOnlySpan<byte>)_matchMid).IndexOf(Target);

    // ─── SimdByteScanner (AVX2 / AdvSimd / Vector<byte>) ─────────────────────

    /// <summary>No-match scan — must traverse the entire buffer.</summary>
    [Benchmark(Description = "SimdByteScanner – no match")]
    public int Simd_FindByte_NoMatch()
        => SimdByteScanner.FindByte(_noMatch, Target);

    /// <summary>Match at the last byte — exercises the complete SIMD loop plus tail.</summary>
    [Benchmark(Description = "SimdByteScanner – match at end")]
    public int Simd_FindByte_MatchEnd()
        => SimdByteScanner.FindByte(_matchEnd, Target);

    /// <summary>Match at the midpoint — shows early-exit SIMD behaviour.</summary>
    [Benchmark(Description = "SimdByteScanner – match at mid")]
    public int Simd_FindByte_MatchMid()
        => SimdByteScanner.FindByte(_matchMid, Target);
}
