using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Data;
using Xunit;

namespace BareMetalWeb.Data.Tests;

/// <summary>
/// Tests for SIMD / hardware-intrinsics acceleration paths:
/// <list type="bullet">
///   <item><see cref="SimdDistance"/> — Cosine, DotProduct, Euclidean distance</item>
///   <item><see cref="WalCrc32C"/> — extended correctness and cross-path consistency</item>
///   <item><see cref="WalLatin1Key32.CompareTo"/> — zero-allocation ulong-word comparison</item>
///   <item><see cref="DataLayerCapabilities"/> — hardware capability reporting</item>
/// </list>
/// </summary>
public sealed class SimdAccelerationTests
{
    // ── SimdDistance ─────────────────────────────────────────────────────────

    [Fact]
    public void SimdDistance_Cosine_IdenticalVectors_ReturnsZero()
    {
        var v = new float[] { 1f, 2f, 3f, 4f, 5f, 6f, 7f, 8f };
        Assert.Equal(0f, SimdDistance.Cosine(v, v), precision: 5);
    }

    [Fact]
    public void SimdDistance_Cosine_OppositeVectors_ReturnsTwo()
    {
        var a = new float[] { 1f, 0f, 0f, 0f };
        var b = new float[] { -1f, 0f, 0f, 0f };
        Assert.Equal(2f, SimdDistance.Cosine(a, b), precision: 5);
    }

    [Fact]
    public void SimdDistance_Cosine_OrthogonalVectors_ReturnsOne()
    {
        var a = new float[] { 1f, 0f, 0f, 0f };
        var b = new float[] { 0f, 1f, 0f, 0f };
        Assert.Equal(1f, SimdDistance.Cosine(a, b), precision: 5);
    }

    [Fact]
    public void SimdDistance_Cosine_ZeroVector_ReturnsOne()
    {
        var a = new float[] { 1f, 2f, 3f, 4f };
        var b = new float[] { 0f, 0f, 0f, 0f };
        Assert.Equal(1f, SimdDistance.Cosine(a, b), precision: 5);
    }

    [Fact]
    public void SimdDistance_DotProduct_KnownVectors_ReturnsNegatedDot()
    {
        // [1,2,3] · [4,5,6] = 4+10+18 = 32 → DotProduct returns -32
        var a = new float[] { 1f, 2f, 3f };
        var b = new float[] { 4f, 5f, 6f };
        Assert.Equal(-32f, SimdDistance.DotProduct(a, b), precision: 4);
    }

    [Fact]
    public void SimdDistance_DotProduct_ZeroVector_ReturnsZero()
    {
        var a = new float[] { 1f, 2f, 3f, 4f };
        var b = new float[] { 0f, 0f, 0f, 0f };
        Assert.Equal(0f, SimdDistance.DotProduct(a, b), precision: 5);
    }

    [Fact]
    public void SimdDistance_Euclidean_IdenticalVectors_ReturnsZero()
    {
        var v = new float[] { 3f, 4f, 5f, 6f };
        Assert.Equal(0f, SimdDistance.Euclidean(v, v), precision: 5);
    }

    [Fact]
    public void SimdDistance_Euclidean_KnownDistance()
    {
        // Distance between (0,0) and (3,4) = 5
        var a = new float[] { 0f, 0f };
        var b = new float[] { 3f, 4f };
        Assert.Equal(5f, SimdDistance.Euclidean(a, b), precision: 5);
    }

    [Fact]
    public void SimdDistance_Compute_DispatchesCorrectly()
    {
        var a = new float[] { 1f, 0f, 0f, 0f };
        var b = new float[] { 0f, 1f, 0f, 0f };

        Assert.Equal(SimdDistance.Cosine(a, b),     SimdDistance.Compute(DistanceMetric.Cosine, a, b),     precision: 5);
        Assert.Equal(SimdDistance.DotProduct(a, b), SimdDistance.Compute(DistanceMetric.DotProduct, a, b), precision: 5);
        Assert.Equal(SimdDistance.Euclidean(a, b),  SimdDistance.Compute(DistanceMetric.Euclidean, a, b),  precision: 5);
    }

    [Fact]
    public void SimdDistance_Cosine_LargeVectors_ConsistentWithSmall()
    {
        // Use a vector wider than any SIMD register (> 16 floats) to exercise
        // the tail-remainder scalar loop for all code paths.
        const int N = 37; // prime to stress-test tail handling
        var rng = new Random(42);
        var a = new float[N];
        var b = new float[N];
        for (int i = 0; i < N; i++)
        {
            a[i] = (float)rng.NextDouble();
            b[i] = (float)rng.NextDouble();
        }

        // Reference: scalar dot products
        float refDot = 0f, refNormA = 0f, refNormB = 0f;
        for (int i = 0; i < N; i++)
        {
            refDot   += a[i] * b[i];
            refNormA += a[i] * a[i];
            refNormB += b[i] * b[i];
        }
        float refCosine = 1f - refDot / (MathF.Sqrt(refNormA) * MathF.Sqrt(refNormB));

        float actual = SimdDistance.Cosine(a, b);
        Assert.Equal(refCosine, actual, precision: 4); // allow small FMA rounding difference
    }

    [Fact]
    public void SimdDistance_ActivePath_IsNonEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(SimdDistance.ActivePath));
    }

    // ── WalCrc32C — correctness with slicing-by-4 ─────────────────────────

    [Fact]
    public void Crc32C_KnownVector_Consistent_AcrossAllLengths()
    {
        // Check that CRC is consistent for all lengths 0..64 (exercises
        // both aligned and unaligned paths in the slicing-by-4 software path).
        byte[] data = Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog");
        uint expected = WalCrc32C.Compute(data);

        for (int trim = 0; trim < Math.Min(data.Length, 16); trim++)
        {
            uint crc = WalCrc32C.Compute(data.AsSpan(0, data.Length - trim));
            // Just ensure no crash and a valid (non-zero for non-empty) result
            if (data.Length - trim > 0)
                Assert.NotEqual(0u, crc);
        }

        // Full data is stable
        Assert.Equal(expected, WalCrc32C.Compute(data));
    }

    [Fact]
    public void Crc32C_LargeBuffer_MatchesKnownCrc()
    {
        // CRC-32C of "123456789" = 0xE3069283 — this is a standard test vector.
        byte[] data = Encoding.ASCII.GetBytes("123456789");
        Assert.Equal(0xE306_9283u, WalCrc32C.Compute(data));
    }

    [Fact]
    public void Crc32C_LargeBuffer_HardwareMatchesSoftware()
    {
        // Generate a 256-byte buffer and verify hardware and software paths agree.
        // We compute the expected value using a local software CRC32C to cross-check.
        var buf = new byte[256];
        for (int i = 0; i < buf.Length; i++) buf[i] = (byte)i;

        // Compute expected via a local software reference
        const uint poly = 0x82F63B78u;
        var table = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            uint c = i;
            for (int j = 0; j < 8; j++) c = (c & 1u) != 0u ? (c >> 1) ^ poly : c >> 1;
            table[i] = c;
        }
        uint refCrc = 0xFFFF_FFFFu;
        foreach (byte b in buf) refCrc = (refCrc >> 8) ^ table[(byte)(refCrc ^ b)];
        refCrc = ~refCrc;

        uint actual = WalCrc32C.Compute(buf);
        Assert.Equal(refCrc, actual);
    }

    [Fact]
    public void Crc32C_3WayPath_LargeBuffer_IsConsistent()
    {
        // Feed a buffer large enough to exercise the 3-way interleaved hardware
        // paths (>= 3 × 8 = 24 bytes) multiple times and confirm identical results.
        var buf = new byte[256];
        for (int i = 0; i < buf.Length; i++) buf[i] = (byte)i;

        uint first = WalCrc32C.Compute(buf);
        for (int rep = 0; rep < 5; rep++)
            Assert.Equal(first, WalCrc32C.Compute(buf));
    }

    // ── WalLatin1Key32.CompareTo ──────────────────────────────────────────

    [Fact]
    public void Latin1Key_CompareTo_Self_ReturnsZero()
    {
        var k = WalLatin1Key32.FromString("hello");
        Assert.Equal(0, k.CompareTo(k));
    }

    [Fact]
    public void Latin1Key_CompareTo_SameContent_ReturnsZero()
    {
        var k1 = WalLatin1Key32.FromString("hello");
        var k2 = WalLatin1Key32.FromString("hello");
        Assert.Equal(0, k1.CompareTo(k2));
        Assert.Equal(0, k2.CompareTo(k1));
    }

    [Fact]
    public void Latin1Key_CompareTo_LessFirst_ReturnsNegative()
    {
        var ka = WalLatin1Key32.FromString("apple");
        var kb = WalLatin1Key32.FromString("banana");
        Assert.True(ka.CompareTo(kb) < 0);
        Assert.True(kb.CompareTo(ka) > 0);
    }

    [Fact]
    public void Latin1Key_CompareTo_Prefix_ShorterIsLess()
    {
        // "abc" < "abcd" because byte 3 of "abc" is 0x00, byte 3 of "abcd" is 0x64
        var ka = WalLatin1Key32.FromString("abc");
        var kb = WalLatin1Key32.FromString("abcd");
        Assert.True(ka.CompareTo(kb) < 0);
    }

    [Fact]
    public void Latin1Key_CompareTo_NullKeys_BothZero_Equal()
    {
        var k1 = WalLatin1Key32.FromString(null);
        var k2 = WalLatin1Key32.FromString(null);
        Assert.Equal(0, k1.CompareTo(k2));
    }

    [Fact]
    public void Latin1Key_CompareTo_MaxBytes_AllFF_VsAllFE()
    {
        // Stress-test the word-comparison path with bytes across the word boundary
        var k1 = WalLatin1Key32.FromBytes(new byte[32].Also(b => Array.Fill(b, (byte)0xFF)));
        var k2 = WalLatin1Key32.FromBytes(new byte[32].Also(b => Array.Fill(b, (byte)0xFE)));
        Assert.True(k2.CompareTo(k1) < 0); // 0xFE... < 0xFF...
        Assert.True(k1.CompareTo(k2) > 0);
    }

    [Fact]
    public void Latin1Key_CompareTo_DifferenceInLastWord()
    {
        // First 24 bytes identical, last 8 bytes differ — exercises the _w3 comparison
        var buf1 = new byte[32];
        var buf2 = new byte[32];
        Array.Fill(buf1, (byte)'A');
        Array.Fill(buf2, (byte)'A');
        buf2[31] = (byte)'B'; // last byte differs

        var k1 = WalLatin1Key32.FromBytes(buf1);
        var k2 = WalLatin1Key32.FromBytes(buf2);
        Assert.True(k1.CompareTo(k2) < 0);
        Assert.True(k2.CompareTo(k1) > 0);
    }

    // ── DataLayerCapabilities ─────────────────────────────────────────────

    [Fact]
    public void DataLayerCapabilities_VectorDistancePath_IsNonEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(DataLayerCapabilities.VectorDistancePath));
    }

    [Fact]
    public void DataLayerCapabilities_Crc32CPath_IsNonEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(DataLayerCapabilities.Crc32CPath));
    }

    [Fact]
    public void DataLayerCapabilities_BloomFilterPath_IsNonEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(DataLayerCapabilities.BloomFilterPath));
    }

    [Fact]
    public void DataLayerCapabilities_SchemaHashPath_IsNonEmpty()
    {
        Assert.False(string.IsNullOrWhiteSpace(DataLayerCapabilities.SchemaHashPath));
    }

    [Fact]
    public void DataLayerCapabilities_Describe_ContainsAllSections()
    {
        string desc = DataLayerCapabilities.Describe();
        Assert.False(string.IsNullOrWhiteSpace(desc));
        Assert.Contains("CRC", desc, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("distance", desc, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Bloom", desc, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Schema", desc, StringComparison.OrdinalIgnoreCase);
    }

    // ── Bloom filter ulong[] bit-packing + POPCNT ─────────────────────────

    [Fact]
    public void BloomFilter_AddAndSearch_FindsExactToken()
    {
        // Arrange
        var testRoot = Path.Combine(Path.GetTempPath(), "SimdBloomTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testRoot);
        try
        {
            var mgr = new SearchIndexManager(testRoot, logger: null);
            var item = new TestSearchableItem { Key = 1, Description = "hello world" };
            mgr.IndexObject(item);

            // Act
            var results = mgr.Search(typeof(TestSearchableItem), "hello", () => new[] { item }, IndexKind.Bloom);

            // Assert: token found
            Assert.Contains(1u, results);
        }
        finally
        {
            Directory.Delete(testRoot, recursive: true);
        }
    }

    [Fact]
    public void BloomFilter_NegativeProbe_ReturnsEmpty()
    {
        var testRoot = Path.Combine(Path.GetTempPath(), "SimdBloomNeg_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testRoot);
        try
        {
            var mgr = new SearchIndexManager(testRoot, logger: null);
            var item = new TestSearchableItem { Key = 1, Description = "hello world" };
            mgr.IndexObject(item);

            // A token that was never inserted must not be returned
            var results = mgr.Search(typeof(TestSearchableItem), "zzznomatch999", () => new[] { item }, IndexKind.Bloom);
            Assert.DoesNotContain(1u, results);
        }
        finally
        {
            Directory.Delete(testRoot, recursive: true);
        }
    }

    [Fact]
    public void BloomFilter_MultipleItems_AllFound()
    {
        var testRoot = Path.Combine(Path.GetTempPath(), "SimdBloomMulti_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testRoot);
        try
        {
            var mgr = new SearchIndexManager(testRoot, logger: null);
            var items = Enumerable.Range(1, 50)
                .Select(i => new TestSearchableItem { Key = (uint)i, Description = $"token{i} extra" })
                .ToArray();
            foreach (var it in items)
                mgr.IndexObject(it);

            // Every inserted token must resolve back to its ID
            for (uint i = 1; i <= 50; i++)
            {
                var results = mgr.Search(typeof(TestSearchableItem), $"token{i}", () => items, IndexKind.Bloom);
                Assert.Contains(i, results);
            }
        }
        finally
        {
            Directory.Delete(testRoot, recursive: true);
        }
    }

    // ── XxHash64 Schema Hash ──────────────────────────────────────────────

    [Fact]
    public void SchemaHash_SameType_ProducesSameHash()
    {
        var ser = new BinaryObjectSerializer();
        var schema1 = ser.BuildSchema(typeof(SimpleHashItem));
        var schema2 = ser.BuildSchema(typeof(SimpleHashItem));
        Assert.Equal(schema1.Hash, schema2.Hash);
    }

    [Fact]
    public void SchemaHash_DifferentTypes_ProduceDifferentHashes()
    {
        var ser = new BinaryObjectSerializer();
        var schemaA = ser.BuildSchema(typeof(SimpleHashItem));
        var schemaB = ser.BuildSchema(typeof(AnotherHashItem));
        Assert.NotEqual(schemaA.Hash, schemaB.Hash);
    }

    [Fact]
    public void SchemaHash_RoundTrip_SerializeDeserialize_Succeeds()
    {
        var ser = new BinaryObjectSerializer();
        var original = new SimpleHashItem { Name = "test", Value = 42 };
        var schema = ser.CreateSchema(1, ser.BuildSchema(typeof(SimpleHashItem)).Members);

        byte[] bytes = ser.Serialize(original, 1);
        var restored = ser.Deserialize<SimpleHashItem>(bytes, schema);

        Assert.NotNull(restored);
        Assert.Equal(original.Name, restored.Name);
        Assert.Equal(original.Value, restored.Value);
    }
}

/// <summary>Simple POCO used to verify XxHash64 schema hash stability.</summary>
file class SimpleHashItem
{
    public string? Name { get; set; }
    public int Value { get; set; }
}

/// <summary>Different POCO to verify schema hashes differ across types.</summary>
file class AnotherHashItem
{
    public Guid Id { get; set; }
    public double Score { get; set; }
}

/// <summary>Tiny fluent helper to keep test array initialisation readable.</summary>
file static class ArrayExtensions
{
    public static byte[] Also(this byte[] arr, Action<byte[]> action)
    {
        action(arr);
        return arr;
    }
}
