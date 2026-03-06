using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace BareMetalWeb.Data;

/// <summary>
/// SIMD-accelerated filtering over dictionary-encoded integer index columns.
///
/// <para>Filters compare encoded dictionary indexes (small ints) instead of full values,
/// enabling tens of millions of rows per second throughput.</para>
///
/// <para>Pipeline tiers:
///   1. <b>AVX2</b> — 8 × int32 per cycle via <c>Avx2.CompareEqual</c> + <c>Avx2.MoveMask</c>
///   2. <b>Portable SIMD</b> — <c>Vector&lt;int&gt;</c> fallback (width auto-detected)
///   3. <b>Scalar</b> — branchless loop for platforms without hardware SIMD
/// </para>
/// </summary>
public static class DictionaryColumnFilter
{
    /// <summary>
    /// Scans <paramref name="encodedColumn"/> for entries equal to <paramref name="dictionaryIndex"/>
    /// and writes matching row positions into <paramref name="outputIndexes"/>.
    /// Returns the number of matches written.
    ///
    /// <para>Uses AVX2 when available (8 ints per cycle), then falls back to portable
    /// <c>Vector&lt;int&gt;</c>, then scalar loop.</para>
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int FilterEquals(
        ReadOnlySpan<int> encodedColumn,
        int dictionaryIndex,
        Span<int> outputIndexes)
    {
        if (Avx2.IsSupported)
            return FilterEqualsAvx2(encodedColumn, dictionaryIndex, outputIndexes);

        if (Vector.IsHardwareAccelerated && Vector<int>.Count >= 4)
            return FilterEqualsVector(encodedColumn, dictionaryIndex, outputIndexes);

        return FilterEqualsScalar(encodedColumn, dictionaryIndex, outputIndexes);
    }

    /// <summary>
    /// Scans for entries NOT equal to <paramref name="dictionaryIndex"/>.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int FilterNotEquals(
        ReadOnlySpan<int> encodedColumn,
        int dictionaryIndex,
        Span<int> outputIndexes)
    {
        if (Avx2.IsSupported)
            return FilterNotEqualsAvx2(encodedColumn, dictionaryIndex, outputIndexes);

        if (Vector.IsHardwareAccelerated && Vector<int>.Count >= 4)
            return FilterNotEqualsVector(encodedColumn, dictionaryIndex, outputIndexes);

        return FilterNotEqualsScalar(encodedColumn, dictionaryIndex, outputIndexes);
    }

    /// <summary>
    /// Multi-value IN filter: matches rows whose encoded index is in <paramref name="dictionaryIndexes"/>.
    /// </summary>
    public static int FilterIn(
        ReadOnlySpan<int> encodedColumn,
        ReadOnlySpan<int> dictionaryIndexes,
        Span<int> outputIndexes)
    {
        // Build a fast lookup set; for small cardinalities a bitmask is ideal.
        int maxIdx = 0;
        for (int i = 0; i < dictionaryIndexes.Length; i++)
            if (dictionaryIndexes[i] > maxIdx) maxIdx = dictionaryIndexes[i];

        // Use a bit-set for cardinalities that fit in a ulong or small ulong[].
        int words = (maxIdx >> 6) + 1;
        Span<ulong> bitSet = words <= 16 ? stackalloc ulong[words] : new ulong[words];
        bitSet.Clear();
        for (int i = 0; i < dictionaryIndexes.Length; i++)
        {
            int idx = dictionaryIndexes[i];
            bitSet[idx >> 6] |= 1UL << (idx & 63);
        }

        int count = 0;
        for (int i = 0; i < encodedColumn.Length; i++)
        {
            int code = encodedColumn[i];
            int word = code >> 6;
            if (word < bitSet.Length && (bitSet[word] & (1UL << (code & 63))) != 0)
                outputIndexes[count++] = i;
        }
        return count;
    }

    // ── AVX2 path: 8 × int32 per iteration ─────────────────────────────────

    private static unsafe int FilterEqualsAvx2(
        ReadOnlySpan<int> encodedColumn,
        int dictionaryIndex,
        Span<int> outputIndexes)
    {
        int n = encodedColumn.Length;
        int count = 0;

        // Broadcast the target dictionary index into all 8 lanes of a 256-bit register.
        Vector256<int> target = Vector256.Create(dictionaryIndex);

        int i = 0;
        fixed (int* pCol = encodedColumn)
        {
            // Process 8 ints per iteration using AVX2.
            for (; i <= n - 8; i += 8)
            {
                // Load 8 encoded indexes from column.
                Vector256<int> chunk = Avx.LoadVector256(pCol + i);

                // Compare each lane: produces -1 (all bits set) on match, 0 otherwise.
                Vector256<int> cmp = Avx2.CompareEqual(chunk, target);

                // Extract the top bit of each 32-bit lane into an 8-bit mask.
                int mask = Avx2.MoveMask(cmp.AsByte());

                // Each matching 32-bit lane contributes 4 set bits (0xF) in the byte mask.
                // Walk set bits in 4-bit strides.
                while (mask != 0)
                {
                    int bit = BitOperations.TrailingZeroCount(mask);
                    int lane = bit >> 2; // each lane is 4 bytes wide
                    outputIndexes[count++] = i + lane;
                    mask &= ~(0xF << (lane << 2)); // clear all 4 bits for this lane
                }
            }
        }

        // Scalar tail for remaining elements.
        for (; i < n; i++)
            if (encodedColumn[i] == dictionaryIndex)
                outputIndexes[count++] = i;

        return count;
    }

    private static unsafe int FilterNotEqualsAvx2(
        ReadOnlySpan<int> encodedColumn,
        int dictionaryIndex,
        Span<int> outputIndexes)
    {
        int n = encodedColumn.Length;
        int count = 0;
        Vector256<int> target = Vector256.Create(dictionaryIndex);

        int i = 0;
        fixed (int* pCol = encodedColumn)
        {
            for (; i <= n - 8; i += 8)
            {
                Vector256<int> chunk = Avx.LoadVector256(pCol + i);
                // Invert equals to get not-equals.
                Vector256<int> cmp = Avx2.AndNot(
                    Avx2.CompareEqual(chunk, target),
                    Vector256.Create(-1));
                int mask = Avx2.MoveMask(cmp.AsByte());

                while (mask != 0)
                {
                    int bit = BitOperations.TrailingZeroCount(mask);
                    int lane = bit >> 2;
                    outputIndexes[count++] = i + lane;
                    mask &= ~(0xF << (lane << 2));
                }
            }
        }

        for (; i < n; i++)
            if (encodedColumn[i] != dictionaryIndex)
                outputIndexes[count++] = i;

        return count;
    }

    // ── Portable Vector<int> path ──────────────────────────────────────────

    private static int FilterEqualsVector(
        ReadOnlySpan<int> encodedColumn,
        int dictionaryIndex,
        Span<int> outputIndexes)
    {
        int n = encodedColumn.Length;
        int count = 0;
        int vLen = Vector<int>.Count;
        var targetVec = new Vector<int>(dictionaryIndex);

        int[] temp = new int[n];
        encodedColumn.CopyTo(temp);

        int i = 0;
        for (; i <= n - vLen; i += vLen)
        {
            var chunk = new Vector<int>(temp, i);
            var cmp = Vector.Equals(chunk, targetVec);

            for (int j = 0; j < vLen; j++)
                if (cmp[j] != 0)
                    outputIndexes[count++] = i + j;
        }

        for (; i < n; i++)
            if (encodedColumn[i] == dictionaryIndex)
                outputIndexes[count++] = i;

        return count;
    }

    private static int FilterNotEqualsVector(
        ReadOnlySpan<int> encodedColumn,
        int dictionaryIndex,
        Span<int> outputIndexes)
    {
        int n = encodedColumn.Length;
        int count = 0;
        int vLen = Vector<int>.Count;
        var targetVec = new Vector<int>(dictionaryIndex);

        int[] temp = new int[n];
        encodedColumn.CopyTo(temp);

        int i = 0;
        for (; i <= n - vLen; i += vLen)
        {
            var chunk = new Vector<int>(temp, i);
            var cmp = Vector.OnesComplement(Vector.Equals(chunk, targetVec));

            for (int j = 0; j < vLen; j++)
                if (cmp[j] != 0)
                    outputIndexes[count++] = i + j;
        }

        for (; i < n; i++)
            if (encodedColumn[i] != dictionaryIndex)
                outputIndexes[count++] = i;

        return count;
    }

    // ── Scalar fallback ────────────────────────────────────────────────────

    private static int FilterEqualsScalar(
        ReadOnlySpan<int> encodedColumn,
        int dictionaryIndex,
        Span<int> outputIndexes)
    {
        int count = 0;
        for (int i = 0; i < encodedColumn.Length; i++)
            if (encodedColumn[i] == dictionaryIndex)
                outputIndexes[count++] = i;
        return count;
    }

    private static int FilterNotEqualsScalar(
        ReadOnlySpan<int> encodedColumn,
        int dictionaryIndex,
        Span<int> outputIndexes)
    {
        int count = 0;
        for (int i = 0; i < encodedColumn.Length; i++)
            if (encodedColumn[i] != dictionaryIndex)
                outputIndexes[count++] = i;
        return count;
    }
}
