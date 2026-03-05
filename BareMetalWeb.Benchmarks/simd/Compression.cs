using System.Numerics;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace BareMetalWeb.Benchmarks.Simd;

/// <summary>
/// SIMD-accelerated compression primitives for column arrays.
///
/// Implements <b>delta encoding</b> (first-order differencing), which is the
/// key pre-processing step before entropy/RLE compression of sorted or
/// monotonically-increasing integer columns (e.g. timestamps, sequential IDs).
///
/// Three implementations are provided:
///   1. <see cref="DeltaEncodeScalar"/>  – scalar loop (baseline).
///   2. <see cref="DeltaEncodeVector"/>  – portable <see cref="Vector{T}"/>.
///   3. <see cref="DeltaEncodeAvx2"/>    – AVX2 hardware intrinsics.
///
/// <b>Decode</b> (prefix-sum reconstruction) is provided as
///   <see cref="DeltaDecodeScalar"/>, <see cref="DeltaDecodeVector"/>, and
///   <see cref="DeltaDecodeAvx2"/>.
///
/// <b>Zero detection</b>: a helper <see cref="CountZerosScalar"/> /
/// <see cref="CountZerosAvx2"/> shows how SIMD acceleration is applied to
/// zero detection after delta encoding — useful for RLE run-length counting.
/// </summary>
public static class Compression
{
    // ── Delta encode – scalar ────────────────────────────────────────────

    /// <summary>
    /// Scalar delta encoder: <c>output[i] = input[i] - input[i-1]</c>.
    /// <c>output[0] = input[0]</c> (first element stored as-is).
    /// Writes result into the provided <paramref name="output"/> array to
    /// avoid allocations on the hot path.
    /// </summary>
    public static void DeltaEncodeScalar(int[] input, int[] output)
    {
        if (input.Length == 0) return;
        output[0] = input[0];
        for (int i = 1; i < input.Length; i++)
            output[i] = input[i] - input[i - 1];
    }

    // ── Delta encode – portable Vector<T> ───────────────────────────────

    /// <summary>
    /// Portable SIMD delta encoder using <see cref="Vector{T}"/> subtraction.
    ///
    /// Strategy: for each vector-width page, we compute
    /// <c>current - shifted_previous</c>, where <c>shifted_previous</c>
    /// is a vector with the last element of the previous page at position 0
    /// and current[0..N-2] at positions 1..N-1.
    ///
    /// Because <see cref="Vector{T}"/> doesn't expose cross-lane shifts
    /// natively, we use a temporary scalar array of length
    /// <c>Vector&lt;int&gt;.Count + 1</c> to build the shifted vector — this
    /// keeps the inner loop allocation-free.
    /// </summary>
    public static void DeltaEncodeVector(int[] input, int[] output)
    {
        if (input.Length == 0) return;

        int vLen = Vector<int>.Count;
        int prev = 0; // the last value from the previous page (or 0 for the first)
        int i = 0;

        // Stack-allocate the shifted buffer — vLen is at most 8 on AVX2, 4 on SSE2
        Span<int> shifted = stackalloc int[vLen];

        for (; i <= input.Length - vLen; i += vLen)
        {
            // Build shifted: [prev, input[i], input[i+1], ..., input[i+vLen-2]]
            shifted[0] = prev;
            for (int j = 1; j < vLen; j++)
                shifted[j] = input[i + j - 1];

            var vCurrent = new Vector<int>(input, i);
            var vShifted = new Vector<int>((ReadOnlySpan<int>)shifted);
            var vDelta = vCurrent - vShifted;
            vDelta.CopyTo(output, i);

            prev = input[i + vLen - 1];
        }

        // Scalar remainder
        for (; i < input.Length; i++)
        {
            output[i] = input[i] - prev;
            prev = input[i];
        }
    }

    // ── Delta encode – AVX2 ──────────────────────────────────────────────

    /// <summary>
    /// AVX2 delta encoder.
    ///
    /// Uses <see cref="Avx2.AlignRight"/> (VPALIGNR) to build the shifted
    /// vector in a single instruction:
    ///   <c>VPALIGNR(current, prev_vec, 12)</c>
    /// aligns at byte offset 12 (= 3 ints), taking the high 12 bytes of
    /// <paramref name="prev_vec"/> and the low 20 bytes of <c>current</c>
    /// to produce [prev[7], cur[0..6]].
    ///
    /// Falls back to <see cref="DeltaEncodeVector"/> when AVX2 is not
    /// available.
    /// </summary>
    public static void DeltaEncodeAvx2(int[] input, int[] output)
    {
        if (!Avx2.IsSupported)
        {
            DeltaEncodeVector(input, output);
            return;
        }

        if (input.Length == 0) return;

        const int vLen = 8; // 256-bit / 32-bit per int
        int i = 0;
        int scalarPrev = 0;

        unsafe
        {
            fixed (int* pIn = input)
            fixed (int* pOut = output)
            {
                // prevVec holds the previous 8-element page. Starts as all-zeros
                // (treated as a virtual row of 0s before index 0).
                var prevVec = Vector256<int>.Zero;

                for (; i <= input.Length - vLen; i += vLen)
                {
                    var cur = Avx.LoadVector256(pIn + i);

                    // VPALIGNR: byte-level right-align across two 128-bit lanes.
                    // Byte shift of 28 (= 7 ints * 4 bytes) inside each 128-bit lane
                    // combined with a cross-lane permute to bring the tail of the
                    // lower lane into the head of the upper lane.
                    //
                    // Step 1: permute lanes to get [high128(prev), low128(cur)]
                    var perm = Avx2.Permute2x128(prevVec, cur, 0x21);
                    // Step 2: VPALIGNR(cur, perm, 12) = take last 4 bytes (1 int) of perm
                    //         and first 28 bytes (7 ints) of cur per 128-bit lane.
                    //         This gives [prev[7], cur[0], cur[1], ..., cur[6]]
                    //         ... but because VPALIGNR operates per 128-bit lane we get:
                    //         lower lane: [prev[3], cur[0], cur[1], cur[2]]
                    //         upper lane: [cur[3],  cur[4], cur[5], cur[6]]
                    // Byte offset 12 = 3 ints.
                    var shifted = Avx2.AlignRight(cur.AsByte(), perm.AsByte(), 12).AsInt32();

                    var delta = Avx2.Subtract(cur, shifted);
                    Avx.Store(pOut + i, delta);

                    prevVec = cur;
                }

                // Record the last processed scalar for the tail
                if (i > 0)
                    scalarPrev = input[i - 1];
            }
        }

        // Scalar remainder
        for (; i < input.Length; i++)
        {
            output[i] = input[i] - scalarPrev;
            scalarPrev = input[i];
        }
    }

    // ── Delta decode (prefix-sum reconstruction) ─────────────────────────

    /// <summary>Scalar prefix-sum decode: <c>output[i] = output[i-1] + delta[i]</c>.</summary>
    public static void DeltaDecodeScalar(int[] deltas, int[] output)
    {
        if (deltas.Length == 0) return;
        output[0] = deltas[0];
        for (int i = 1; i < deltas.Length; i++)
            output[i] = output[i - 1] + deltas[i];
    }

    /// <summary>
    /// Portable SIMD prefix-sum decode.
    /// Prefix sums are inherently sequential, so the SIMD version uses a
    /// Hillis-Steele parallel scan within each vector-width block, then adjusts
    /// by adding the running total carried from the previous block.
    /// </summary>
    public static void DeltaDecodeVector(int[] deltas, int[] output)
    {
        if (deltas.Length == 0) return;

        int vLen = Vector<int>.Count;
        int running = 0; // carry-over from previous block
        int i = 0;

        // Allocate scratch buffer outside the loop to avoid repeated stack growth (CA2014)
        Span<int> block = stackalloc int[vLen];

        for (; i <= deltas.Length - vLen; i += vLen)
        {
            // Hillis-Steele intra-block prefix scan
            deltas.AsSpan(i, vLen).CopyTo(block);

            // Inclusive scan within block
            for (int stride = 1; stride < vLen; stride <<= 1)
            {
                for (int j = stride; j < vLen; j++)
                    block[j] += block[j - stride];
            }

            // Add carry-over from previous block, then store
            var carry = new Vector<int>(running);
            var v = new Vector<int>(block);
            (v + carry).CopyTo(output, i);

            running += block[vLen - 1]; // new carry = block sum
        }

        // Scalar remainder — continue from last carry
        for (; i < deltas.Length; i++)
        {
            running += deltas[i];
            output[i] = running;
        }
    }

    /// <summary>
    /// AVX2 prefix-sum decode. Uses the same Hillis-Steele block approach as
    /// <see cref="DeltaDecodeVector"/> but with AVX2 shift + add for the
    /// intra-block scan steps, reducing instruction count for the inner loop.
    /// Falls back to <see cref="DeltaDecodeVector"/> when AVX2 is unavailable.
    /// </summary>
    public static void DeltaDecodeAvx2(int[] deltas, int[] output)
    {
        if (!Avx2.IsSupported)
        {
            DeltaDecodeVector(deltas, output);
            return;
        }

        if (deltas.Length == 0) return;

        const int vLen = 8;
        int i = 0;
        int running = 0;

        unsafe
        {
            fixed (int* pDelta = deltas)
            fixed (int* pOut = output)
            {
                for (; i <= deltas.Length - vLen; i += vLen)
                {
                    // Load 8 deltas
                    var v = Avx.LoadVector256(pDelta + i);

                    // Hillis-Steele prefix scan within 256-bit register
                    // Step 1: stride 1  →  v += v << 1 int
                    var shift1 = Avx2.Permute2x128(Vector256<int>.Zero, v, 0x20);
                    shift1 = Avx2.AlignRight(v.AsByte(), shift1.AsByte(), 12).AsInt32();
                    v = Avx2.Add(v, shift1);

                    // Step 2: stride 2  →  v += v << 2 ints
                    var shift2 = Avx2.Permute2x128(Vector256<int>.Zero, v, 0x20);
                    shift2 = Avx2.AlignRight(v.AsByte(), shift2.AsByte(), 8).AsInt32();
                    v = Avx2.Add(v, shift2);

                    // Step 3: stride 4  →  v += v << 4 ints
                    var shift4 = Avx2.Permute2x128(Vector256<int>.Zero, v, 0x20);
                    v = Avx2.Add(v, shift4);

                    // Add carry-over from previous block
                    var carry = Vector256.Create(running);
                    v = Avx2.Add(v, carry);

                    Avx.Store(pOut + i, v);

                    // Extract new running total from last lane
                    running = pOut[i + vLen - 1];
                }
            }
        }

        // Scalar remainder
        for (; i < deltas.Length; i++)
        {
            running += deltas[i];
            output[i] = running;
        }
    }

    // ── Zero detection after delta encoding ──────────────────────────────

    /// <summary>Counts zero entries in <paramref name="data"/> (scalar baseline).</summary>
    public static int CountZerosScalar(int[] data)
    {
        int count = 0;
        for (int i = 0; i < data.Length; i++)
            if (data[i] == 0) count++;
        return count;
    }

    /// <summary>
    /// AVX2 zero-count: loads 8 ints, compares to zero vector, extracts
    /// 8-bit bitmask, counts set bits with <see cref="BitOperations.PopCount"/>.
    /// Falls back to scalar when AVX2 is unavailable.
    /// </summary>
    public static int CountZerosAvx2(int[] data)
    {
        if (!Avx2.IsSupported)
            return CountZerosScalar(data);

        int count = 0;
        const int vLen = 8;
        var zero = Vector256<int>.Zero;
        int i = 0;

        unsafe
        {
            fixed (int* ptr = data)
            {
                for (; i <= data.Length - vLen; i += vLen)
                {
                    var v = Avx.LoadVector256(ptr + i);
                    var cmp = Avx2.CompareEqual(v, zero);
                    int mask = Avx.MoveMask(cmp.AsSingle());
                    count += BitOperations.PopCount((uint)mask);
                }
            }
        }

        for (; i < data.Length; i++)
            if (data[i] == 0) count++;

        return count;
    }
}
