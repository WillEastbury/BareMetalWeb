using System.Numerics;
using System.Runtime.CompilerServices;

namespace BareMetalWeb.Data;

/// <summary>
/// Branchless predicate evaluation pipeline for raw columnar data using 64-bit bitmasks.
///
/// <para>
/// <b>Why bitmask pipelines outperform branch-heavy loops:</b><br/>
/// A naïve per-row loop evaluates each predicate with a conditional branch, stalling the
/// CPU pipeline when the branch predictor guesses incorrectly (typically 5–20 mispredictions
/// per 1,000 rows for mixed-selectivity data). This pipeline avoids that penalty by
/// processing 64 rows per iteration: all predicates are evaluated unconditionally using
/// comparison operators that the JIT compiles to branchless SETG / SETL / SETE instructions
/// (x86) or CSET / CSEL (ARM64). The combined bitmask is examined once per 64-row block,
/// and matching indices are extracted via <see cref="BitOperations.TrailingZeroCount"/> — a
/// single-cycle instruction — plus the clear-lowest-set-bit trick
/// (<c>combined &amp;= combined - 1</c>).
/// </para>
///
/// <para>
/// <b>CPU cache behaviour:</b><br/>
/// Column arrays are laid out as contiguous sequences in memory. Sweeping multiple
/// single-type arrays in forward order lets the hardware prefetcher stay well ahead of the
/// loop, avoiding cache misses. A branch-heavy row-object scan, by contrast, chases object
/// references through heap memory — each object access can incur a cache miss.
/// </para>
///
/// <para>
/// <b>SIMD upgrade path:</b><br/>
/// Each <c>BuildMask*</c> helper uses a scalar loop that the JIT can auto-vectorise or
/// that can be manually replaced with a <see cref="System.Numerics.Vector{T}"/> sweep or
/// AVX-512 <c>_mm512_cmpgt_epi32_mask</c> intrinsic. The outer block-of-64 aggregation
/// logic and the bit-enumeration loop are unchanged regardless of how masks are generated.
/// </para>
///
/// <para>
/// <b>Allocation policy:</b> all methods are allocation-free. The caller provides the
/// output buffer; no <c>new</c> expressions appear in any hot path.
/// </para>
/// </summary>
public static class BitmaskFilterPipeline
{
    // ── Primary EvaluateFilter method (as specified by the issue) ─────────────────

    /// <summary>
    /// Evaluates the compound filter <c>(age &gt; 30) AND (score &lt; 90) AND (active == 1)</c>
    /// without per-row branching.
    ///
    /// <para><b>Processing model (all allocation-free):</b></para>
    /// <list type="number">
    ///   <item>Rows are processed in blocks of up to 64.</item>
    ///   <item>
    ///     For each block, three 64-bit masks are produced — one per predicate — where bit
    ///     <c>k</c> is set when row <c>baseIndex+k</c> satisfies the predicate:
    ///     <code>
    ///     ulong maskAge    = BuildMaskGreaterThan(age,    baseIndex, blockLen, 30);
    ///     ulong maskScore  = BuildMaskLessThan   (score,  baseIndex, blockLen, 90.0);
    ///     ulong maskActive = BuildMaskEquals     (active, baseIndex, blockLen, (byte)1);
    ///     </code>
    ///   </item>
    ///   <item>
    ///     The three masks are intersected via bitwise AND:
    ///     <code>ulong combined = maskAge &amp; maskScore &amp; maskActive;</code>
    ///   </item>
    ///   <item>
    ///     Matching row indices are collected by iterating set bits:
    ///     <code>
    ///     while (combined != 0)
    ///     {
    ///         int offset = BitOperations.TrailingZeroCount(combined);
    ///         outputIndexes[count++] = baseIndex + offset;
    ///         combined &amp;= combined - 1;   // clear lowest set bit
    ///     }
    ///     </code>
    ///   </item>
    /// </list>
    ///
    /// <example>
    /// Filtering 1 million rows with zero heap allocations:
    /// <code>
    /// // Prepare column data (flat arrays — columnar layout)
    /// int[]    age    = new int   [1_000_000];
    /// double[] score  = new double[1_000_000];
    /// byte[]   active = new byte  [1_000_000];
    /// // ... populate columns ...
    ///
    /// // Allocate worst-case output buffer (or use stackalloc for small result sets)
    /// int[] outputBuffer = new int[1_000_000];
    ///
    /// int matchCount = BitmaskFilterPipeline.EvaluateFilter(
    ///     age, score, active, outputBuffer);
    ///
    /// // matchCount matching row indices are now in outputBuffer[0..matchCount)
    /// ReadOnlySpan&lt;int&gt; matches = outputBuffer.AsSpan(0, matchCount);
    /// </code>
    /// </example>
    /// </summary>
    /// <param name="age">Read-only span of integer ages (one element per row).</param>
    /// <param name="score">Read-only span of double scores (one element per row).</param>
    /// <param name="active">Read-only span of byte active flags (one element per row).</param>
    /// <param name="outputIndexes">
    ///   Caller-allocated output span.  Must contain at least <c>age.Length</c> elements to
    ///   handle the worst-case where every row matches.
    /// </param>
    /// <returns>Number of matching row indices written into <paramref name="outputIndexes"/>.</returns>
    public static int EvaluateFilter(
        ReadOnlySpan<int>    age,
        ReadOnlySpan<double> score,
        ReadOnlySpan<byte>   active,
        Span<int>            outputIndexes)
    {
        int n     = age.Length;
        int count = 0;

        // Process in blocks of 64 rows so each block maps to a single 64-bit mask word.
        for (int baseIndex = 0; baseIndex < n; baseIndex += 64)
        {
            int blockLen = Math.Min(64, n - baseIndex);

            // ── Step 1: build a 64-bit mask for each predicate ──────────────────────
            //
            // BuildMask* sweeps the current block and sets bit k when row
            // (baseIndex + k) satisfies the predicate.  The comparisons compile
            // to branchless SETG / SETL / SETE (x86) or CSET (ARM64) instructions
            // — no branch misprediction penalty even for low-selectivity data.

            ulong maskAge    = BuildMaskGreaterThan(age,    baseIndex, blockLen, 30);
            ulong maskScore  = BuildMaskLessThan(score,     baseIndex, blockLen, 90.0);
            ulong maskActive = BuildMaskEquals(active,      baseIndex, blockLen, (byte)1);

            // ── Step 2: intersect all predicates via bitwise AND ─────────────────────
            //
            // A bit survives the AND only when ALL three predicates are satisfied.
            ulong combined = maskAge & maskScore & maskActive;

            // Fast-path: skip the bit-enumeration loop when no rows match.
            if (combined == 0) continue;

            // ── Step 3: enumerate matching rows using branchless bit tricks ──────────
            //
            // TrailingZeroCount returns the index of the lowest set bit in O(1).
            // Clearing the lowest set bit (combined & (combined - 1)) advances to
            // the next match without scanning zero bits, so this loop fires exactly
            // once per matching row — no wasted iterations.

            while (combined != 0)
            {
                int offset = BitOperations.TrailingZeroCount(combined);
                outputIndexes[count++] = baseIndex + offset;
                combined &= combined - 1;   // clear lowest set bit → next match
            }
        }

        return count;
    }

    // ── Mask-building helpers ─────────────────────────────────────────────────────

    /// <summary>
    /// Builds a 64-bit bitmask for the predicate <c>column[i] &gt; target</c>.
    ///
    /// <para>
    /// Bit <c>k</c> (0-based, <c>k &lt; <paramref name="blockLen"/></c>) is set when
    /// <c>column[<paramref name="baseIndex"/> + k] &gt; <paramref name="target"/></c>.
    /// </para>
    ///
    /// <para>
    /// The inner loop is intentionally scalar: modern JITs (RyuJIT / NativeAOT) emit
    /// a branchless SETG or SBB sequence for the ternary.  When AVX-512 support is
    /// available this can be replaced with a single <c>_mm512_cmpgt_epi32_mask</c>
    /// call to produce the 16-bit (or 64-bit with AVX-512BW) mask directly in hardware.
    /// </para>
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong BuildMaskGreaterThan(ReadOnlySpan<int> column, int baseIndex, int blockLen, int target)
    {
        ulong mask = 0;
        for (int k = 0; k < blockLen; k++)
            mask |= (column[baseIndex + k] > target ? 1UL : 0UL) << k;
        return mask;
    }

    /// <summary>
    /// Builds a 64-bit bitmask for the predicate <c>column[i] &gt; target</c> over a
    /// <see cref="long"/> column.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong BuildMaskGreaterThan(ReadOnlySpan<long> column, int baseIndex, int blockLen, long target)
    {
        ulong mask = 0;
        for (int k = 0; k < blockLen; k++)
            mask |= (column[baseIndex + k] > target ? 1UL : 0UL) << k;
        return mask;
    }

    /// <summary>
    /// Builds a 64-bit bitmask for the predicate <c>column[i] &gt; target</c> over a
    /// <see cref="double"/> column.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong BuildMaskGreaterThan(ReadOnlySpan<double> column, int baseIndex, int blockLen, double target)
    {
        ulong mask = 0;
        for (int k = 0; k < blockLen; k++)
            mask |= (column[baseIndex + k] > target ? 1UL : 0UL) << k;
        return mask;
    }

    /// <summary>
    /// Builds a 64-bit bitmask for the predicate <c>column[i] &lt; target</c> over a
    /// <see cref="double"/> column.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong BuildMaskLessThan(ReadOnlySpan<double> column, int baseIndex, int blockLen, double target)
    {
        ulong mask = 0;
        for (int k = 0; k < blockLen; k++)
            mask |= (column[baseIndex + k] < target ? 1UL : 0UL) << k;
        return mask;
    }

    /// <summary>
    /// Builds a 64-bit bitmask for the predicate <c>column[i] &lt; target</c> over an
    /// <see cref="int"/> column.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong BuildMaskLessThan(ReadOnlySpan<int> column, int baseIndex, int blockLen, int target)
    {
        ulong mask = 0;
        for (int k = 0; k < blockLen; k++)
            mask |= (column[baseIndex + k] < target ? 1UL : 0UL) << k;
        return mask;
    }

    /// <summary>
    /// Builds a 64-bit bitmask for the predicate <c>column[i] &lt; target</c> over a
    /// <see cref="float"/> column.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong BuildMaskLessThan(ReadOnlySpan<float> column, int baseIndex, int blockLen, float target)
    {
        ulong mask = 0;
        for (int k = 0; k < blockLen; k++)
            mask |= (column[baseIndex + k] < target ? 1UL : 0UL) << k;
        return mask;
    }

    /// <summary>
    /// Builds a 64-bit bitmask for the predicate <c>column[i] == target</c> over a
    /// <see cref="byte"/> column.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong BuildMaskEquals(ReadOnlySpan<byte> column, int baseIndex, int blockLen, byte target)
    {
        ulong mask = 0;
        for (int k = 0; k < blockLen; k++)
            mask |= (column[baseIndex + k] == target ? 1UL : 0UL) << k;
        return mask;
    }

    /// <summary>
    /// Builds a 64-bit bitmask for the predicate <c>column[i] == target</c> over an
    /// <see cref="int"/> column.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong BuildMaskEquals(ReadOnlySpan<int> column, int baseIndex, int blockLen, int target)
    {
        ulong mask = 0;
        for (int k = 0; k < blockLen; k++)
            mask |= (column[baseIndex + k] == target ? 1UL : 0UL) << k;
        return mask;
    }

    /// <summary>
    /// Builds a 64-bit bitmask for the predicate <c>column[i] &gt;= target</c> over an
    /// <see cref="int"/> column.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong BuildMaskGreaterThanOrEqual(ReadOnlySpan<int> column, int baseIndex, int blockLen, int target)
    {
        ulong mask = 0;
        for (int k = 0; k < blockLen; k++)
            mask |= (column[baseIndex + k] >= target ? 1UL : 0UL) << k;
        return mask;
    }

    /// <summary>
    /// Builds a 64-bit bitmask for the predicate <c>column[i] &lt;= target</c> over a
    /// <see cref="double"/> column.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong BuildMaskLessThanOrEqual(ReadOnlySpan<double> column, int baseIndex, int blockLen, double target)
    {
        ulong mask = 0;
        for (int k = 0; k < blockLen; k++)
            mask |= (column[baseIndex + k] <= target ? 1UL : 0UL) << k;
        return mask;
    }

    /// <summary>
    /// Builds a 64-bit bitmask for the predicate <c>column[i] &lt;= target</c> over an
    /// <see cref="int"/> column.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong BuildMaskLessThanOrEqual(ReadOnlySpan<int> column, int baseIndex, int blockLen, int target)
    {
        ulong mask = 0;
        for (int k = 0; k < blockLen; k++)
            mask |= (column[baseIndex + k] <= target ? 1UL : 0UL) << k;
        return mask;
    }

    // ── Set-bit enumeration helper ────────────────────────────────────────────────

    /// <summary>
    /// Collects the absolute row indices of all set bits in <paramref name="combined"/>
    /// into <paramref name="outputIndexes"/>, starting at write position
    /// <paramref name="writeAt"/>.
    ///
    /// <para>
    /// Each bit position <c>k</c> in <paramref name="combined"/> corresponds to row
    /// <c><paramref name="baseIndex"/> + k</c>.  The method uses
    /// <see cref="BitOperations.TrailingZeroCount"/> to find each set bit in O(1) and
    /// the clear-lowest-set-bit trick (<c>combined &amp;= combined - 1</c>) to advance
    /// to the next match without scanning zero bits.
    /// </para>
    /// </summary>
    /// <returns>Updated write position after appending all matching indices.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int CollectMatchingRows(ulong combined, int baseIndex, Span<int> outputIndexes, int writeAt)
    {
        while (combined != 0)
        {
            int offset = BitOperations.TrailingZeroCount(combined);
            outputIndexes[writeAt++] = baseIndex + offset;
            combined &= combined - 1;   // clear lowest set bit → advance to next match
        }
        return writeAt;
    }
}
