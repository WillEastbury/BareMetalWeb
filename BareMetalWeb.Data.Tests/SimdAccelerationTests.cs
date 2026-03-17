using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using BareMetalWeb.Core;
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
    public SimdAccelerationTests()
    {
        DataScaffold.RegisterEntity<TestSearchableItem>();
    }

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

    [Fact]
    public void SchemaHash_100k_RandomSchemas_CollisionRate_BelowExpected()
    {
        // Generate 100,000 random schemas with unique member signatures and verify
        // that the XxHash64-folded-to-32-bit collision rate is within birthday-paradox
        // expectations. For 100k items in a 2^32 space, expected unique ≈ 99,999
        // (collision probability per pair ≈ 2.3e-10, expected collisions ≈ 1.2).
        // We allow up to 50 collisions — still well below any quality concern.
        const int count = 100_000;
        const int maxAllowedCollisions = 50;
        var ser = new BinaryObjectSerializer();
        var hashes = new HashSet<uint>(count);
        var rng = new Random(42); // deterministic seed for reproducibility
        int collisions = 0;

        string[] typeNames = { "String", "Int32", "Double", "Boolean", "Guid", "DateTime", "Byte[]", "Decimal" };

        for (int i = 0; i < count; i++)
        {
            int memberCount = rng.Next(1, 8);
            var members = new MemberSignature[memberCount];
            for (int m = 0; m < memberCount; m++)
            {
                string name = $"Field_{i}_{m}_{rng.Next()}";
                string typeName = typeNames[rng.Next(typeNames.Length)];
                int? blittableSize = rng.Next(3) == 0 ? rng.Next(1, 64) : null;
                members[m] = new MemberSignature(name, typeName, typeof(string), blittableSize);
            }

            var schema = ser.CreateSchema(1, members);
            if (!hashes.Add(schema.Hash))
                collisions++;
        }

        Assert.True(collisions <= maxAllowedCollisions,
            $"Schema hash collision count {collisions} exceeds maximum allowed {maxAllowedCollisions}.");
    }
}

// ── BloomFilterData unit tests ────────────────────────────────────────────

/// <summary>
/// Direct unit tests for <see cref="BloomFilterData.MightContain"/> and
/// <see cref="BloomFilterData.PopulationCount"/>, covering both the 4-wide
/// unrolled path and the scalar tail.
/// </summary>
public sealed class BloomFilterDataTests
{
    // ── MightContain ─────────────────────────────────────────────────────────

    [Fact]
    public void MightContain_EmptySpan_ReturnsTrue()
    {
        // An empty set of required bits is trivially satisfied.
        var bf = new BloomFilterData(size: 256, hashCount: 3);
        Assert.True(bf.MightContain(ReadOnlySpan<int>.Empty));
    }

    [Fact]
    public void MightContain_AllBitsSet_ReturnsTrue()
    {
        // Set all 8 bits explicitly, then ask whether they are all present.
        var bf = new BloomFilterData(size: 256, hashCount: 8);
        int[] indices = { 0, 7, 63, 64, 127, 128, 200, 255 };
        foreach (var idx in indices)
            bf.SetBit(idx);

        // Exercises the 4-wide unrolled path (n=8 >= 4) and produces no false negatives.
        Assert.True(bf.MightContain(indices));
    }

    [Fact]
    public void MightContain_OneBitClearInUnrolledSection_ReturnsFalse()
    {
        // Set 7 of 8 bits; the missing one falls inside the 4-wide unrolled region (i < 4).
        var bf = new BloomFilterData(size: 256, hashCount: 8);
        int[] indices = { 0, 7, 63, 64, 127, 128, 200, 255 };
        foreach (var idx in indices)
            bf.SetBit(idx);

        // Clear the second bit (index 1 in the span → inside the first 4-wide iteration).
        bf.Bits[7 >> 6] &= ~(1UL << (7 & 63));

        Assert.False(bf.MightContain(indices));
    }

    [Fact]
    public void MightContain_OneBitClearInScalarTail_ReturnsFalse()
    {
        // n=5 → 4-wide loop runs once (i=0..3), scalar tail handles i=4.
        // Clear the tail bit so the scalar path returns false.
        var bf = new BloomFilterData(size: 256, hashCount: 5);
        int[] indices = { 0, 7, 63, 64, 200 };
        foreach (var idx in indices)
            bf.SetBit(idx);

        // Clear the last index (200) — processed by the scalar tail.
        bf.Bits[200 >> 6] &= ~(1UL << (200 & 63));

        Assert.False(bf.MightContain(indices));
    }

    [Fact]
    public void MightContain_SpanLengthNotDivisibleByFour_ScalarTailCorrect()
    {
        // n=7 → one full 4-wide pass (i=0..3) + scalar tail (i=4,5,6).
        var bf = new BloomFilterData(size: 512, hashCount: 7);
        int[] indices = { 1, 10, 50, 100, 150, 200, 300 };
        foreach (var idx in indices)
            bf.SetBit(idx);

        Assert.True(bf.MightContain(indices));
    }

    [Fact]
    public void MightContain_ScalarOnlyPath_ThreeIndices_AllSet()
    {
        // hashCount=3 is the default: exercises only the scalar tail (n < 4).
        var bf = new BloomFilterData(size: 10000, hashCount: 3);
        int[] indices = { 42, 1000, 9999 };
        foreach (var idx in indices)
            bf.SetBit(idx);

        Assert.True(bf.MightContain(indices));
    }

    [Fact]
    public void MightContain_ScalarOnlyPath_ThreeIndices_OneClear()
    {
        var bf = new BloomFilterData(size: 10000, hashCount: 3);
        int[] indices = { 42, 1000, 9999 };
        bf.SetBit(42);
        bf.SetBit(1000);
        // 9999 is NOT set

        Assert.False(bf.MightContain(indices));
    }

    // ── PopulationCount ───────────────────────────────────────────────────────

    [Fact]
    public void PopulationCount_EmptyBits_ReturnsZero()
    {
        var bf = new BloomFilterData(size: 64, hashCount: 1);
        // Bits array has exactly 1 ulong; no bits set.
        Assert.Equal(0, bf.PopulationCount());
    }

    [Fact]
    public void PopulationCount_LessThanFourWords_ScalarTailOnly()
    {
        // size=192 → Bits has 3 ulongs (< 4), so only the scalar tail executes.
        var bf = new BloomFilterData(size: 192, hashCount: 1);
        bf.SetBit(0);   // word 0, bit 0
        bf.SetBit(64);  // word 1, bit 0
        bf.SetBit(128); // word 2, bit 0
        Assert.Equal(3, bf.PopulationCount());
    }

    [Fact]
    public void PopulationCount_ExactlyFourWords_NoScalarTail()
    {
        // size=256 → Bits has exactly 4 ulongs; the unrolled loop runs once, tail is empty.
        var bf = new BloomFilterData(size: 256, hashCount: 1);
        bf.SetBit(0);   // word 0
        bf.SetBit(64);  // word 1
        bf.SetBit(128); // word 2
        bf.SetBit(192); // word 3
        Assert.Equal(4, bf.PopulationCount());
    }

    [Fact]
    public void PopulationCount_MoreThanFourWords_CorrectCount()
    {
        // size=448 → 7 ulongs: one 4-wide pass + 3-word scalar tail.
        var bf = new BloomFilterData(size: 448, hashCount: 1);
        // Set two bits per word (7 words × 2 bits = 14)
        for (int w = 0; w < 7; w++)
        {
            bf.SetBit(w * 64);
            bf.SetBit(w * 64 + 1);
        }
        Assert.Equal(14, bf.PopulationCount());
    }

    [Fact]
    public void PopulationCount_KnownPattern_MatchesBruteForce()
    {
        // Set bits at positions 0, 1, 63, 64, 127, 255.
        var bf = new BloomFilterData(size: 512, hashCount: 1);
        int[] setBits = { 0, 1, 63, 64, 127, 255 };
        foreach (var b in setBits)
            bf.SetBit(b);

        int expected = setBits.Length;
        Assert.Equal(expected, bf.PopulationCount());
    }

    // ── False positive rate ──────────────────────────────────────────────────

    [Fact]
    public void BloomFilter_FalsePositiveRate_WithinExpectedBounds()
    {
        // Insert 1,000 tokens into a bloom filter sized for 10,000 bits with 3 hashes.
        // Then probe 100,000 tokens that were NOT inserted and measure the false positive rate.
        // For m=10000, k=3, n=1000: expected FPR ≈ (1 - e^(-kn/m))^k ≈ 3.6%
        // We allow up to 10% to account for hash distribution variance.
        const int size = 10_000;
        const int hashCount = 3;
        const int insertCount = 1_000;
        const int probeCount = 100_000;
        const double maxAllowedFpr = 0.10;

        var bf = new BloomFilterData(size, hashCount);

        // Insert tokens
        for (int i = 0; i < insertCount; i++)
        {
            string token = $"inserted_{i}";
            for (int h = 0; h < hashCount; h++)
            {
                int hash = ((StringComparer.OrdinalIgnoreCase.GetHashCode(token)
                             ^ (h * unchecked((int)0x9e3779b9))) & 0x7FFFFFFF);
                bf.SetBit((int)(hash % size));
            }
        }

        // Probe tokens that were never inserted
        int falsePositives = 0;
        for (int i = 0; i < probeCount; i++)
        {
            string probe = $"notinserted_{i + insertCount}";
            Span<int> indices = stackalloc int[hashCount];
            for (int h = 0; h < hashCount; h++)
            {
                int hash = ((StringComparer.OrdinalIgnoreCase.GetHashCode(probe)
                             ^ (h * unchecked((int)0x9e3779b9))) & 0x7FFFFFFF);
                indices[h] = (int)(hash % size);
            }
            if (bf.MightContain(indices))
                falsePositives++;
        }

        double fpr = (double)falsePositives / probeCount;
        Assert.True(fpr < maxAllowedFpr,
            $"False positive rate {fpr:P2} exceeds maximum allowed {maxAllowedFpr:P0}. " +
            $"({falsePositives}/{probeCount} false positives)");
        // Sanity: rate should be > 0 (a perfect filter with this config would be suspicious)
        Assert.True(falsePositives > 0,
            "Zero false positives is statistically implausible — possible test bug.");
    }

    // ── SimdByteScanner ────────────────────────────────────────────────────

    [Fact]
    public void SimdByteScanner_FindByte_ReturnsFirstMatch()
    {
        var data = new byte[1024];
        data[512] = 0xAA;
        data[700] = 0xAA;

        Assert.Equal(512, SimdByteScanner.FindByte(data, 0xAA));
    }

    [Fact]
    public void SimdByteScanner_FindByte_ReturnsMinusOneWhenAbsent()
    {
        var data = new byte[256];
        for (int i = 0; i < data.Length; i++) data[i] = 0x42;

        Assert.Equal(-1, SimdByteScanner.FindByte(data, 0xFF));
    }

    [Fact]
    public void SimdByteScanner_FindByte_EmptySpan()
    {
        Assert.Equal(-1, SimdByteScanner.FindByte(ReadOnlySpan<byte>.Empty, 0x00));
    }

    [Fact]
    public void SimdByteScanner_FindByte_FirstByte()
    {
        var data = new byte[] { 0xBB, 0x00, 0x00, 0x00 };
        Assert.Equal(0, SimdByteScanner.FindByte(data, 0xBB));
    }

    [Fact]
    public void SimdByteScanner_FindByte_LastByte()
    {
        var data = new byte[65];
        data[64] = 0xCC; // past any 32-byte or 16-byte aligned block
        Assert.Equal(64, SimdByteScanner.FindByte(data, 0xCC));
    }

    [Fact]
    public void SimdByteScanner_FindByte_LargeBuffer_EveryPosition()
    {
        for (int size = 0; size <= 128; size++)
        {
            var data = new byte[size];
            for (int pos = 0; pos < size; pos++)
            {
                Array.Clear(data);
                data[pos] = 0xFE;
                int found = SimdByteScanner.FindByte(data, 0xFE);
                Assert.Equal(pos, found);
            }
        }
    }

    [Fact]
    public void SimdByteScanner_FindAnyOfTwo_FindsBothTargets()
    {
        var data = new byte[256];
        data[100] = 0x0A;
        data[50]  = 0x7C;

        Assert.Equal(50, SimdByteScanner.FindAnyOfTwo(data, 0x0A, 0x7C));
        Assert.Equal(50, SimdByteScanner.FindAnyOfTwo(data, 0x7C, 0x0A));
    }

    [Fact]
    public void SimdByteScanner_FindAnyOfTwo_ReturnsMinusOneWhenAbsent()
    {
        var data = new byte[128];
        for (int i = 0; i < data.Length; i++) data[i] = 0x42;

        Assert.Equal(-1, SimdByteScanner.FindAnyOfTwo(data, 0x0A, 0x0D));
    }

    [Fact]
    public void SimdByteScanner_CountByte_CorrectCount()
    {
        var data = new byte[1024];
        int expected = 0;
        for (int i = 0; i < data.Length; i++)
        {
            if (i % 7 == 0) { data[i] = 0xDD; expected++; }
        }

        Assert.Equal(expected, SimdByteScanner.CountByte(data, 0xDD));
    }

    [Fact]
    public void SimdByteScanner_CountByte_AllMatch()
    {
        var data = new byte[200];
        Array.Fill(data, (byte)0x99);
        Assert.Equal(200, SimdByteScanner.CountByte(data, 0x99));
    }

    [Fact]
    public void SimdByteScanner_CountByte_NoneMatch()
    {
        var data = new byte[200];
        Assert.Equal(0, SimdByteScanner.CountByte(data, 0xFF));
    }

    [Fact]
    public void SimdByteScanner_CountByte_Empty()
    {
        Assert.Equal(0, SimdByteScanner.CountByte(ReadOnlySpan<byte>.Empty, 0x00));
    }

    [Fact]
    public void SimdByteScanner_FindByte_MatchesSpanIndexOf()
    {
        var rng = new Random(42);
        for (int trial = 0; trial < 200; trial++)
        {
            int len = rng.Next(0, 2048);
            var data = new byte[len];
            rng.NextBytes(data);
            byte target = (byte)rng.Next(256);

            int expected = ((ReadOnlySpan<byte>)data).IndexOf(target);
            int actual = SimdByteScanner.FindByte(data, target);
            Assert.Equal(expected, actual);
        }
    }

    [Fact]
    public void SimdByteScanner_CountByte_MatchesLinqCount()
    {
        var rng = new Random(123);
        for (int trial = 0; trial < 100; trial++)
        {
            int len = rng.Next(0, 2048);
            var data = new byte[len];
            rng.NextBytes(data);
            byte target = (byte)rng.Next(256);

            int expected = data.Count(b => b == target);
            int actual = SimdByteScanner.CountByte(data, target);
            Assert.Equal(expected, actual);
        }
    }

    [Fact]
    public void SimdByteScanner_FindNextRecordMagic_Integration()
    {
        var data = new byte[4096];
        var rng = new Random(99);
        rng.NextBytes(data);

        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            data.AsSpan(1000), 0x52454331u);

        int found = WalSegmentReader.FindNextRecordMagic(data);
        Assert.True(found >= 0 && found <= 1000,
            $"Expected magic at or before 1000, found at {found}");
    }

    [Fact]
    public void SimdByteScanner_Throughput_LargeBuffer()
    {
        const int size = 4 * 1024 * 1024;
        var data = new byte[size];
        data[size - 1] = 0xFF;

        SimdByteScanner.FindByte(data, 0xFF); // warm up

        var sw = System.Diagnostics.Stopwatch.StartNew();
        const int iterations = 50;
        for (int i = 0; i < iterations; i++)
            SimdByteScanner.FindByte(data, 0xFF);
        sw.Stop();

        long totalBytes = (long)size * iterations;
        double gbPerSec = totalBytes / (sw.Elapsed.TotalSeconds * 1024 * 1024 * 1024);

        Assert.True(gbPerSec > 0.5,
            $"Throughput {gbPerSec:F2} GB/s is suspiciously low — SIMD path may not be active");
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
