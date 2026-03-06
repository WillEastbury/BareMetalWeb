using System;
using System.Numerics;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Unit tests for <see cref="BitmaskFilterPipeline"/>.
///
/// Test structure:
///   1. EvaluateFilter — correctness of the three-predicate compound filter.
///   2. BuildMask helpers — each type/operator combination.
///   3. CollectMatchingRows — bit-enumeration helper.
///   4. Edge cases — empty spans, all-match, no-match, non-multiple-of-64 sizes.
///   5. Large dataset — validate against a reference scalar loop at 1 M rows.
///   6. DataLayerCapabilities — BitmaskFilterPipelinePath is reported.
/// </summary>
public sealed class BitmaskFilterPipelineTests
{
    // ── 1. EvaluateFilter ─────────────────────────────────────────────────────

    [Fact]
    public void EvaluateFilter_AllMatch_ReturnsAllIndices()
    {
        const int n = 64;
        var age    = new int   [n]; age.AsSpan().Fill(31);      // all > 30
        var score  = new double[n]; score.AsSpan().Fill(0.0);   // all < 90
        var active = new byte  [n]; active.AsSpan().Fill(1);    // all == 1

        var output = new int[n];
        int count = BitmaskFilterPipeline.EvaluateFilter(age, score, active, output);

        Assert.Equal(n, count);
        for (int i = 0; i < n; i++)
            Assert.Equal(i, output[i]);
    }

    [Fact]
    public void EvaluateFilter_NoneMatch_ReturnsZero()
    {
        const int n = 64;
        var age    = new int   [n]; age.AsSpan().Fill(20);      // none > 30
        var score  = new double[n]; score.AsSpan().Fill(0.0);
        var active = new byte  [n]; active.AsSpan().Fill(1);

        var output = new int[n];
        int count = BitmaskFilterPipeline.EvaluateFilter(age, score, active, output);

        Assert.Equal(0, count);
    }

    [Fact]
    public void EvaluateFilter_AgePredicateFails_ExcludesRow()
    {
        const int n = 4;
        int[]    age    = [31, 20, 35, 40];  // row 1 fails (20 <= 30)
        double[] score  = [0, 0, 0, 0];
        byte[]   active = [1, 1, 1, 1];

        var output = new int[n];
        int count = BitmaskFilterPipeline.EvaluateFilter(age, score, active, output);

        Assert.Equal(3, count);
        Assert.Equal(0, output[0]);
        Assert.Equal(2, output[1]);
        Assert.Equal(3, output[2]);
    }

    [Fact]
    public void EvaluateFilter_ScorePredicateFails_ExcludesRow()
    {
        const int n = 4;
        int[]    age    = [31, 31, 31, 31];
        double[] score  = [0, 90.0, 0, 100.0];   // rows 1,3 fail (>= 90)
        byte[]   active = [1, 1, 1, 1];

        var output = new int[n];
        int count = BitmaskFilterPipeline.EvaluateFilter(age, score, active, output);

        Assert.Equal(2, count);
        Assert.Equal(0, output[0]);
        Assert.Equal(2, output[1]);
    }

    [Fact]
    public void EvaluateFilter_ActivePredicateFails_ExcludesRow()
    {
        const int n = 4;
        int[]    age    = [31, 31, 31, 31];
        double[] score  = [0, 0, 0, 0];
        byte[]   active = [1, 0, 1, 0];   // rows 1,3 fail (== 0)

        var output = new int[n];
        int count = BitmaskFilterPipeline.EvaluateFilter(age, score, active, output);

        Assert.Equal(2, count);
        Assert.Equal(0, output[0]);
        Assert.Equal(2, output[1]);
    }

    [Fact]
    public void EvaluateFilter_MultiBlock_SpansBlockBoundary()
    {
        // 130 rows so we cover at least 3 blocks (64 + 64 + 2)
        const int n = 130;
        var age    = new int   [n];
        var score  = new double[n];
        var active = new byte  [n];

        // Make every odd row match all predicates
        for (int i = 0; i < n; i++)
        {
            bool match = (i % 2 == 1);
            age   [i] = match ? 31    : 20;
            score [i] = match ? 0.0   : 99.0;
            active[i] = match ? (byte)1 : (byte)0;
        }

        var output = new int[n];
        int count = BitmaskFilterPipeline.EvaluateFilter(age, score, active, output);

        Assert.Equal(65, count);   // rows 1,3,5,...,129 → 65 odd rows
        for (int i = 0; i < count; i++)
            Assert.True(output[i] % 2 == 1, $"output[{i}] = {output[i]} should be odd");
    }

    [Fact]
    public void EvaluateFilter_EmptyInput_ReturnsZero()
    {
        var output = new int[0];
        int count = BitmaskFilterPipeline.EvaluateFilter(
            ReadOnlySpan<int>.Empty,
            ReadOnlySpan<double>.Empty,
            ReadOnlySpan<byte>.Empty,
            output);
        Assert.Equal(0, count);
    }

    [Fact]
    public void EvaluateFilter_SingleRow_Match()
    {
        int[]    age    = [50];
        double[] score  = [45.0];
        byte[]   active = [1];

        var output = new int[1];
        int count = BitmaskFilterPipeline.EvaluateFilter(age, score, active, output);
        Assert.Equal(1, count);
        Assert.Equal(0, output[0]);
    }

    [Fact]
    public void EvaluateFilter_SingleRow_NoMatch()
    {
        int[]    age    = [10];
        double[] score  = [45.0];
        byte[]   active = [1];

        var output = new int[1];
        int count = BitmaskFilterPipeline.EvaluateFilter(age, score, active, output);
        Assert.Equal(0, count);
    }

    // ── 2. BuildMask helpers ──────────────────────────────────────────────────

    [Fact]
    public void BuildMaskGreaterThan_Int_SetsCorrectBits()
    {
        int[] col = [10, 31, 5, 100, 30];   // indices 1, 3 are > 30
        ulong mask = BitmaskFilterPipeline.BuildMaskGreaterThan(col, 0, col.Length, 30);
        Assert.Equal(0b01010UL, mask);   // bits 1 and 3
    }

    [Fact]
    public void BuildMaskGreaterThan_Long_SetsCorrectBits()
    {
        long[] col = [0L, 1000L, 500L, 2000L];   // indices 1, 3 are > 999
        ulong mask = BitmaskFilterPipeline.BuildMaskGreaterThan(col, 0, col.Length, 999L);
        Assert.Equal(0b1010UL, mask);
    }

    [Fact]
    public void BuildMaskGreaterThan_Double_SetsCorrectBits()
    {
        double[] col = [1.0, 90.1, 0.5, 200.0];   // indices 1, 3 are > 90.0
        ulong mask = BitmaskFilterPipeline.BuildMaskGreaterThan(col, 0, col.Length, 90.0);
        Assert.Equal(0b1010UL, mask);
    }

    [Fact]
    public void BuildMaskLessThan_Double_SetsCorrectBits()
    {
        double[] col = [89.9, 90.0, 100.0, 0.0];   // indices 0, 3 are < 90.0
        ulong mask = BitmaskFilterPipeline.BuildMaskLessThan(col, 0, col.Length, 90.0);
        Assert.Equal(0b1001UL, mask);
    }

    [Fact]
    public void BuildMaskLessThan_Int_SetsCorrectBits()
    {
        int[] col = [5, 30, 31, 1];   // indices 0, 3 are < 10
        ulong mask = BitmaskFilterPipeline.BuildMaskLessThan(col, 0, col.Length, 10);
        Assert.Equal(0b1001UL, mask);
    }

    [Fact]
    public void BuildMaskLessThan_Float_SetsCorrectBits()
    {
        float[] col = [1.0f, 5.0f, 10.0f, 3.0f];   // indices 0, 1, 3 are < 5.5
        ulong mask = BitmaskFilterPipeline.BuildMaskLessThan(col, 0, col.Length, 5.5f);
        Assert.Equal(0b1011UL, mask);
    }

    [Fact]
    public void BuildMaskEquals_Byte_SetsCorrectBits()
    {
        byte[] col = [1, 0, 1, 1, 0];   // indices 0, 2, 3 are == 1
        ulong mask = BitmaskFilterPipeline.BuildMaskEquals(col, 0, col.Length, (byte)1);
        Assert.Equal(0b01101UL, mask);
    }

    [Fact]
    public void BuildMaskEquals_Int_SetsCorrectBits()
    {
        int[] col = [5, 3, 5, 0, 5];   // indices 0, 2, 4 are == 5
        ulong mask = BitmaskFilterPipeline.BuildMaskEquals(col, 0, col.Length, 5);
        Assert.Equal(0b10101UL, mask);
    }

    [Fact]
    public void BuildMaskGreaterThanOrEqual_Int_SetsCorrectBits()
    {
        int[] col = [30, 31, 29, 30];   // indices 0, 1, 3 are >= 30
        ulong mask = BitmaskFilterPipeline.BuildMaskGreaterThanOrEqual(col, 0, col.Length, 30);
        Assert.Equal(0b1011UL, mask);
    }

    [Fact]
    public void BuildMaskLessThanOrEqual_Double_SetsCorrectBits()
    {
        double[] col = [10.0, 10.1, 9.9, 10.0];   // indices 0, 2, 3 are <= 10.0
        ulong mask = BitmaskFilterPipeline.BuildMaskLessThanOrEqual(col, 0, col.Length, 10.0);
        Assert.Equal(0b1101UL, mask);
    }

    [Fact]
    public void BuildMaskLessThanOrEqual_Int_SetsCorrectBits()
    {
        int[] col = [5, 6, 4, 5];   // indices 0, 2, 3 are <= 5
        ulong mask = BitmaskFilterPipeline.BuildMaskLessThanOrEqual(col, 0, col.Length, 5);
        Assert.Equal(0b1101UL, mask);
    }

    [Fact]
    public void BuildMask_BaseIndexOffset_ScansCorrectSlice()
    {
        // 10-element array, but scan only elements 4..7 (blockLen=4, baseIndex=4)
        int[] col = [99, 99, 99, 99, 31, 20, 35, 40, 99, 99];   // [4]=31,[5]=20,[6]=35,[7]=40
        ulong mask = BitmaskFilterPipeline.BuildMaskGreaterThan(col, 4, 4, 30);
        // Local bits: bit0=col[4]>30=true, bit1=col[5]>30=false, bit2=col[6]>30=true, bit3=col[7]>30=true
        Assert.Equal(0b1101UL, mask);
    }

    [Fact]
    public void BuildMask_AllMatch_AllBitsSet()
    {
        int[] col = [100, 200, 300, 400];
        ulong mask = BitmaskFilterPipeline.BuildMaskGreaterThan(col, 0, col.Length, 0);
        Assert.Equal(0b1111UL, mask);
    }

    [Fact]
    public void BuildMask_NoneMatch_ZeroMask()
    {
        int[] col = [1, 2, 3, 4];
        ulong mask = BitmaskFilterPipeline.BuildMaskGreaterThan(col, 0, col.Length, 100);
        Assert.Equal(0UL, mask);
    }

    // ── 3. CollectMatchingRows ─────────────────────────────────────────────────

    [Fact]
    public void CollectMatchingRows_SingleBit_WritesCorrectIndex()
    {
        ulong combined = 0b0100UL;   // bit 2 set
        var output = new int[4];
        int written = BitmaskFilterPipeline.CollectMatchingRows(combined, baseIndex: 64, output, writeAt: 0);
        Assert.Equal(1, written);
        Assert.Equal(64 + 2, output[0]);
    }

    [Fact]
    public void CollectMatchingRows_MultipleBits_WritesAllIndices()
    {
        ulong combined = 0b10101UL;   // bits 0, 2, 4 set
        var output = new int[8];
        int written = BitmaskFilterPipeline.CollectMatchingRows(combined, baseIndex: 0, output, writeAt: 0);
        Assert.Equal(3, written);
        Assert.Equal(0, output[0]);
        Assert.Equal(2, output[1]);
        Assert.Equal(4, output[2]);
    }

    [Fact]
    public void CollectMatchingRows_ZeroCombined_WritesNothing()
    {
        var output = new int[4];
        int written = BitmaskFilterPipeline.CollectMatchingRows(0UL, baseIndex: 0, output, writeAt: 0);
        Assert.Equal(0, written);
    }

    [Fact]
    public void CollectMatchingRows_AppendsToPreviousWriteAt()
    {
        ulong combined = 0b11UL;   // bits 0,1
        var output = new int[8];
        output[0] = 999;   // pre-existing value at slot 0
        int written = BitmaskFilterPipeline.CollectMatchingRows(combined, baseIndex: 10, output, writeAt: 1);
        Assert.Equal(3, written);          // started at 1, added 2
        Assert.Equal(999, output[0]);      // slot 0 untouched
        Assert.Equal(10, output[1]);
        Assert.Equal(11, output[2]);
    }

    // ── 4. Edge cases ─────────────────────────────────────────────────────────

    [Fact]
    public void EvaluateFilter_ExactlyOneFull64Block()
    {
        const int n = 64;
        var age    = Enumerable.Range(0, n).ToArray();   // 0..63
        var score  = Enumerable.Range(0, n).Select(_ => 50.0).ToArray();
        var active = Enumerable.Range(0, n).Select(_ => (byte)1).ToArray();

        var output = new int[n];
        int count = BitmaskFilterPipeline.EvaluateFilter(age, score, active, output);

        // Only rows where age > 30: indices 31..63 = 33 rows
        Assert.Equal(33, count);
        for (int i = 0; i < count; i++)
            Assert.True(output[i] > 30);
    }

    [Fact]
    public void EvaluateFilter_NotMultipleOf64_HandlesRemainder()
    {
        const int n = 100;
        var age    = new int   [n]; age.AsSpan().Fill(31);
        var score  = new double[n]; score.AsSpan().Fill(0.0);
        var active = new byte  [n]; active.AsSpan().Fill(1);

        var output = new int[n];
        int count = BitmaskFilterPipeline.EvaluateFilter(age, score, active, output);
        Assert.Equal(n, count);
    }

    // ── 5. Large dataset correctness against reference scalar loop ─────────────

    [Fact]
    public void EvaluateFilter_1MRows_MatchesScalarReference()
    {
        const int n = 1_000_000;
        var rng    = new Random(42);
        var age    = new int   [n];
        var score  = new double[n];
        var active = new byte  [n];

        for (int i = 0; i < n; i++)
        {
            age   [i] = rng.Next(0, 100);
            score [i] = rng.NextDouble() * 100.0;
            active[i] = (byte)(rng.Next(0, 2));
        }

        // Reference: scalar branch-per-row loop
        var scalarResult = new List<int>(n / 4);
        for (int i = 0; i < n; i++)
            if (age[i] > 30 && score[i] < 90.0 && active[i] == 1)
                scalarResult.Add(i);

        // Bitmask pipeline
        var output = new int[n];
        int count = BitmaskFilterPipeline.EvaluateFilter(age, score, active, output);

        Assert.Equal(scalarResult.Count, count);
        for (int i = 0; i < count; i++)
            Assert.Equal(scalarResult[i], output[i]);
    }

    // ── 6. DataLayerCapabilities integration ──────────────────────────────────

    [Fact]
    public void DataLayerCapabilities_BitmaskFilterPipelinePath_IsNonEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(DataLayerCapabilities.BitmaskFilterPipelinePath));
    }

    [Fact]
    public void DataLayerCapabilities_Describe_ContainsBitmaskFilter()
    {
        string desc = DataLayerCapabilities.Describe();
        Assert.Contains("Bitmask filter", desc, StringComparison.OrdinalIgnoreCase);
    }
}
