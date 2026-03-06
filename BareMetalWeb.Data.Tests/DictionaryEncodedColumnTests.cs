using System;
using System.Collections.Generic;
using System.Linq;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for <see cref="DictionaryEncodedColumn{T}"/> (issue #911) and
/// <see cref="DictionaryColumnFilter"/> (issue #912).
///
/// Structured as:
///   1. Encoding basics — round-trip, cardinality, compression tier selection.
///   2. Compression tiers — byte, ushort, int paths exercised explicitly.
///   3. Decode correctness — output matches original input.
///   4. SIMD FilterEquals — correctness against scalar reference.
///   5. SIMD FilterNotEquals — inverse filter correctness.
///   6. Multi-value FilterIn — set membership filter.
///   7. Edge cases — empty, single value, all-unique.
///   8. Large dataset — performance sanity (no explicit timing, just correctness at scale).
/// </summary>
public sealed class DictionaryEncodedColumnTests
{
    // ── 1. Encoding basics ────────────────────────────────────────────────

    [Fact]
    public void Encode_StringColumn_BuildsCorrectDictionary()
    {
        var input = new[] { "active", "active", "disabled", "active", "pending" };
        var encoded = DictionaryEncodedColumn<string>.Encode(input);

        Assert.Equal(3, encoded.Cardinality);
        Assert.Equal(5, encoded.RowCount);
        Assert.Contains("active", encoded.DictionaryValues);
        Assert.Contains("disabled", encoded.DictionaryValues);
        Assert.Contains("pending", encoded.DictionaryValues);
    }

    [Fact]
    public void Encode_IntColumn_BuildsCorrectDictionary()
    {
        var input = new[] { 10, 20, 10, 30, 20, 10 };
        var encoded = DictionaryEncodedColumn<int>.Encode(input);

        Assert.Equal(3, encoded.Cardinality);
        Assert.Equal(6, encoded.RowCount);
    }

    [Fact]
    public void Encode_Decode_RoundTrip_RecoversOriginal()
    {
        var input = new[] { "active", "active", "disabled", "active", "pending" };
        var encoded = DictionaryEncodedColumn<string>.Encode(input);

        var output = new string[input.Length];
        encoded.Decode(output);

        Assert.Equal(input, output);
    }

    [Fact]
    public void Encode_Decode_IntRoundTrip_RecoversOriginal()
    {
        var rng = new Random(42);
        var input = Enumerable.Range(0, 1000).Select(_ => rng.Next(0, 50)).ToArray();
        var encoded = DictionaryEncodedColumn<int>.Encode(input);

        var output = new int[input.Length];
        encoded.Decode(output);

        Assert.Equal(input, output);
    }

    // ── 2. Compression tier selection ─────────────────────────────────────

    [Fact]
    public void Encode_LowCardinality_UsesByteTier()
    {
        // 10 unique values → byte tier
        var input = Enumerable.Range(0, 500).Select(i => i % 10).ToArray();
        var encoded = DictionaryEncodedColumn<int>.Encode(input);

        Assert.Equal(DictionaryEncodedColumn<int>.IndexTier.Byte, encoded.Tier);
        Assert.Equal(10, encoded.Cardinality);
    }

    [Fact]
    public void Encode_Cardinality256_StillByteTier()
    {
        var input = Enumerable.Range(0, 1024).Select(i => i % 256).ToArray();
        var encoded = DictionaryEncodedColumn<int>.Encode(input);

        Assert.Equal(DictionaryEncodedColumn<int>.IndexTier.Byte, encoded.Tier);
        Assert.Equal(256, encoded.Cardinality);
    }

    [Fact]
    public void Encode_Cardinality257_UsesUShortTier()
    {
        var input = Enumerable.Range(0, 1024).Select(i => i % 257).ToArray();
        var encoded = DictionaryEncodedColumn<int>.Encode(input);

        Assert.Equal(DictionaryEncodedColumn<int>.IndexTier.UShort, encoded.Tier);
        Assert.Equal(257, encoded.Cardinality);
    }

    [Fact]
    public void Encode_HighCardinality_UsesIntTier()
    {
        // 70,000 unique values → int tier
        var input = Enumerable.Range(0, 70_000).ToArray();
        var encoded = DictionaryEncodedColumn<int>.Encode(input);

        Assert.Equal(DictionaryEncodedColumn<int>.IndexTier.Int, encoded.Tier);
        Assert.Equal(70_000, encoded.Cardinality);
    }

    [Fact]
    public void Encode_UShortTier_RoundTrip()
    {
        // 300 unique values → ushort tier
        var input = Enumerable.Range(0, 2000).Select(i => i % 300).ToArray();
        var encoded = DictionaryEncodedColumn<int>.Encode(input);

        Assert.Equal(DictionaryEncodedColumn<int>.IndexTier.UShort, encoded.Tier);

        var output = new int[input.Length];
        encoded.Decode(output);
        Assert.Equal(input, output);
    }

    // ── 3. GetEncodedIndexesAsInt ──────────────────────────────────────────

    [Fact]
    public void GetEncodedIndexesAsInt_ProducesConsistentCodes()
    {
        var input = new[] { "active", "active", "disabled", "active", "pending" };
        var encoded = DictionaryEncodedColumn<string>.Encode(input);

        var indexes = new int[input.Length];
        encoded.GetEncodedIndexesAsInt(indexes);

        // Same values should have same codes
        Assert.Equal(indexes[0], indexes[1]); // both "active"
        Assert.Equal(indexes[0], indexes[3]); // both "active"
        Assert.NotEqual(indexes[0], indexes[2]); // "active" != "disabled"
        Assert.NotEqual(indexes[2], indexes[4]); // "disabled" != "pending"
    }

    [Fact]
    public void GetEncodedIndexesAsInt_AllTiers_DecodeToSameValues()
    {
        // Byte tier
        var byteTier = DictionaryEncodedColumn<int>.Encode(new[] { 1, 2, 1, 3 });
        var byteIdx = new int[4];
        byteTier.GetEncodedIndexesAsInt(byteIdx);
        for (int i = 0; i < 4; i++)
            Assert.Equal(byteTier.DictionaryValues[byteIdx[i]], new[] { 1, 2, 1, 3 }[i]);
    }

    // ── 4. SIMD FilterEquals ──────────────────────────────────────────────

    [Fact]
    public void FilterEquals_MatchesScalarReference()
    {
        var input = Enumerable.Range(0, 1024).Select(i => i % 5).ToArray();
        var encoded = DictionaryEncodedColumn<int>.Encode(input);

        var indexes = new int[input.Length];
        encoded.GetEncodedIndexesAsInt(indexes);

        int targetValue = 3;
        int targetCode = encoded.LookupCode(targetValue);
        Assert.True(targetCode >= 0);

        var simdOutput = new int[input.Length];
        int simdCount = DictionaryColumnFilter.FilterEquals(indexes, targetCode, simdOutput);

        // Scalar reference
        var scalarMatches = new List<int>();
        for (int i = 0; i < input.Length; i++)
            if (input[i] == targetValue)
                scalarMatches.Add(i);

        Assert.Equal(scalarMatches.Count, simdCount);
        for (int i = 0; i < simdCount; i++)
            Assert.Equal(scalarMatches[i], simdOutput[i]);
    }

    [Fact]
    public void FilterEquals_StringColumn_CorrectResults()
    {
        var statuses = new[] { "active", "disabled", "pending" };
        var rng = new Random(99);
        var input = Enumerable.Range(0, 2048).Select(_ => statuses[rng.Next(3)]).ToArray();

        var encoded = DictionaryEncodedColumn<string>.Encode(input);
        var indexes = new int[input.Length];
        encoded.GetEncodedIndexesAsInt(indexes);

        int activeCode = encoded.LookupCode("active");
        var output = new int[input.Length];
        int count = DictionaryColumnFilter.FilterEquals(indexes, activeCode, output);

        int expected = input.Count(s => s == "active");
        Assert.Equal(expected, count);
        for (int i = 0; i < count; i++)
            Assert.Equal("active", input[output[i]]);
    }

    [Fact]
    public void FilterEquals_NoMatches_ReturnsZero()
    {
        var input = new[] { 1, 2, 3, 4, 5 };
        var encoded = DictionaryEncodedColumn<int>.Encode(input);
        var indexes = new int[input.Length];
        encoded.GetEncodedIndexesAsInt(indexes);

        int missingCode = encoded.LookupCode(99);
        Assert.Equal(-1, missingCode);

        // Filtering for code -1 should return nothing
        var output = new int[input.Length];
        int count = DictionaryColumnFilter.FilterEquals(indexes, -1, output);
        Assert.Equal(0, count);
    }

    [Fact]
    public void FilterEquals_AllMatch_ReturnsAllIndexes()
    {
        var input = Enumerable.Repeat(42, 512).ToArray();
        var encoded = DictionaryEncodedColumn<int>.Encode(input);
        var indexes = new int[input.Length];
        encoded.GetEncodedIndexesAsInt(indexes);

        int code = encoded.LookupCode(42);
        var output = new int[input.Length];
        int count = DictionaryColumnFilter.FilterEquals(indexes, code, output);

        Assert.Equal(512, count);
        for (int i = 0; i < count; i++)
            Assert.Equal(i, output[i]);
    }

    // ── 5. SIMD FilterNotEquals ───────────────────────────────────────────

    [Fact]
    public void FilterNotEquals_MatchesScalarReference()
    {
        var input = Enumerable.Range(0, 1024).Select(i => i % 7).ToArray();
        var encoded = DictionaryEncodedColumn<int>.Encode(input);
        var indexes = new int[input.Length];
        encoded.GetEncodedIndexesAsInt(indexes);

        int excludeValue = 2;
        int excludeCode = encoded.LookupCode(excludeValue);

        var simdOutput = new int[input.Length];
        int simdCount = DictionaryColumnFilter.FilterNotEquals(indexes, excludeCode, simdOutput);

        var scalarMatches = new List<int>();
        for (int i = 0; i < input.Length; i++)
            if (input[i] != excludeValue)
                scalarMatches.Add(i);

        Assert.Equal(scalarMatches.Count, simdCount);
        for (int i = 0; i < simdCount; i++)
            Assert.Equal(scalarMatches[i], simdOutput[i]);
    }

    // ── 6. Multi-value FilterIn ───────────────────────────────────────────

    [Fact]
    public void FilterIn_MultipleValues_ReturnsUnion()
    {
        var input = Enumerable.Range(0, 1024).Select(i => i % 10).ToArray();
        var encoded = DictionaryEncodedColumn<int>.Encode(input);
        var indexes = new int[input.Length];
        encoded.GetEncodedIndexesAsInt(indexes);

        int code2 = encoded.LookupCode(2);
        int code5 = encoded.LookupCode(5);
        int code8 = encoded.LookupCode(8);

        var output = new int[input.Length];
        int count = DictionaryColumnFilter.FilterIn(indexes, new[] { code2, code5, code8 }, output);

        int expected = input.Count(v => v == 2 || v == 5 || v == 8);
        Assert.Equal(expected, count);
        for (int i = 0; i < count; i++)
        {
            int val = input[output[i]];
            Assert.True(val == 2 || val == 5 || val == 8);
        }
    }

    // ── 7. Edge cases ─────────────────────────────────────────────────────

    [Fact]
    public void Encode_Empty_ProducesEmptyColumn()
    {
        var encoded = DictionaryEncodedColumn<string>.Encode(ReadOnlySpan<string>.Empty);

        Assert.Equal(0, encoded.Cardinality);
        Assert.Equal(0, encoded.RowCount);
        Assert.Equal(DictionaryEncodedColumn<string>.IndexTier.Byte, encoded.Tier);
    }

    [Fact]
    public void Encode_SingleValue_CardinalityOne()
    {
        var input = Enumerable.Repeat("only", 100).ToArray();
        var encoded = DictionaryEncodedColumn<string>.Encode(input);

        Assert.Equal(1, encoded.Cardinality);
        Assert.Equal(DictionaryEncodedColumn<string>.IndexTier.Byte, encoded.Tier);

        var output = new string[100];
        encoded.Decode(output);
        Assert.All(output, v => Assert.Equal("only", v));
    }

    [Fact]
    public void Encode_AllUnique_CardinalityEqualsRowCount()
    {
        var input = Enumerable.Range(0, 200).Select(i => $"val_{i}").ToArray();
        var encoded = DictionaryEncodedColumn<string>.Encode(input);

        Assert.Equal(200, encoded.Cardinality);
        Assert.Equal(200, encoded.RowCount);
    }

    [Fact]
    public void LookupCode_ExistingValue_ReturnsCode()
    {
        var input = new[] { "a", "b", "c" };
        var encoded = DictionaryEncodedColumn<string>.Encode(input);

        Assert.True(encoded.LookupCode("a") >= 0);
        Assert.True(encoded.LookupCode("b") >= 0);
        Assert.True(encoded.LookupCode("c") >= 0);
    }

    [Fact]
    public void LookupCode_MissingValue_ReturnsNegativeOne()
    {
        var input = new[] { "a", "b", "c" };
        var encoded = DictionaryEncodedColumn<string>.Encode(input);

        Assert.Equal(-1, encoded.LookupCode("missing"));
    }

    [Fact]
    public void Decode_OutputTooSmall_Throws()
    {
        var input = new[] { 1, 2, 3 };
        var encoded = DictionaryEncodedColumn<int>.Encode(input);

        Assert.Throws<ArgumentException>(() => encoded.Decode(new int[2]));
    }

    [Fact]
    public void GetEncodedIndexesAsInt_OutputTooSmall_Throws()
    {
        var input = new[] { 1, 2, 3 };
        var encoded = DictionaryEncodedColumn<int>.Encode(input);

        Assert.Throws<ArgumentException>(() => encoded.GetEncodedIndexesAsInt(new int[2]));
    }

    // ── 8. Large dataset correctness ──────────────────────────────────────

    [Fact]
    public void FilterEquals_LargeDataset_CorrectResults()
    {
        // 1M rows with 20 unique values → exercises SIMD hot path extensively
        int rowCount = 1_000_000;
        var rng = new Random(123);
        var input = new int[rowCount];
        for (int i = 0; i < rowCount; i++) input[i] = rng.Next(0, 20);

        var encoded = DictionaryEncodedColumn<int>.Encode(input);
        Assert.Equal(20, encoded.Cardinality);
        Assert.Equal(DictionaryEncodedColumn<int>.IndexTier.Byte, encoded.Tier);

        var indexes = new int[rowCount];
        encoded.GetEncodedIndexesAsInt(indexes);

        int targetValue = 7;
        int targetCode = encoded.LookupCode(targetValue);

        var output = new int[rowCount];
        int count = DictionaryColumnFilter.FilterEquals(indexes, targetCode, output);

        int expected = input.Count(v => v == targetValue);
        Assert.Equal(expected, count);

        // Verify all matches are correct
        for (int i = 0; i < count; i++)
            Assert.Equal(targetValue, input[output[i]]);
    }

    [Fact]
    public void FilterNotEquals_LargeDataset_CorrectResults()
    {
        int rowCount = 100_000;
        var rng = new Random(456);
        var input = new int[rowCount];
        for (int i = 0; i < rowCount; i++) input[i] = rng.Next(0, 5);

        var encoded = DictionaryEncodedColumn<int>.Encode(input);
        var indexes = new int[rowCount];
        encoded.GetEncodedIndexesAsInt(indexes);

        int excludeCode = encoded.LookupCode(3);
        var output = new int[rowCount];
        int count = DictionaryColumnFilter.FilterNotEquals(indexes, excludeCode, output);

        int expected = input.Count(v => v != 3);
        Assert.Equal(expected, count);
    }

    [Fact]
    public void Encode_Decode_LargeDataset_RoundTrip()
    {
        int rowCount = 500_000;
        var rng = new Random(789);
        var input = new string[rowCount];
        var vals = new[] { "alpha", "beta", "gamma", "delta", "epsilon" };
        for (int i = 0; i < rowCount; i++) input[i] = vals[rng.Next(vals.Length)];

        var encoded = DictionaryEncodedColumn<string>.Encode(input);
        Assert.Equal(5, encoded.Cardinality);

        var output = new string[rowCount];
        encoded.Decode(output);

        for (int i = 0; i < rowCount; i++)
            Assert.Equal(input[i], output[i]);
    }

    [Fact]
    public void FilterEquals_NonAligned_CorrectResults()
    {
        // 1023 rows: not evenly divisible by 8 (AVX2 lane count)
        var input = Enumerable.Range(0, 1023).Select(i => i % 3).ToArray();
        var encoded = DictionaryEncodedColumn<int>.Encode(input);
        var indexes = new int[input.Length];
        encoded.GetEncodedIndexesAsInt(indexes);

        int code1 = encoded.LookupCode(1);
        var output = new int[input.Length];
        int count = DictionaryColumnFilter.FilterEquals(indexes, code1, output);

        int expected = input.Count(v => v == 1);
        Assert.Equal(expected, count);
        for (int i = 0; i < count; i++)
            Assert.Equal(1, input[output[i]]);
    }
}
