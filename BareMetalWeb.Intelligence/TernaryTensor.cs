using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// SIMD-accelerated ternary tensor operations for BitNet b1.58 inference.
/// Weights are packed as signed bytes (-1, 0, +1). All arithmetic is integer-only.
/// </summary>
public static class TernaryTensor
{
    /// <summary>
    /// Ternary matrix-vector multiply: output = weights · input.
    /// Weights are ternary (-1, 0, +1) stored as sbyte.
    /// Input and output are int32 (quantised activations).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void MatVecMultiply(
        ReadOnlySpan<sbyte> weights,
        ReadOnlySpan<int> input,
        Span<int> output,
        int rows,
        int cols)
    {
        if (weights.Length < rows * cols)
            ThrowArgumentOutOfRange(nameof(weights), weights.Length, rows * cols);
        if (input.Length < cols)
            ThrowArgumentOutOfRange(nameof(input), input.Length, cols);
        if (output.Length < rows)
            ThrowArgumentOutOfRange(nameof(output), output.Length, rows);

        for (int r = 0; r < rows; r++)
        {
            ReadOnlySpan<sbyte> rowWeights = weights.Slice(r * cols, cols);
            output[r] = DotProductTernary(rowWeights, input);
        }
    }

    /// <summary>
    /// Ternary dot product: sum of w[i] * x[i] where w[i] ∈ {-1, 0, +1}.
    /// SIMD accelerated — processes 8 elements per iteration on 256-bit,
    /// 4 elements on 128-bit, falls back to scalar.
    /// </summary>
    public static int DotProductTernary(ReadOnlySpan<sbyte> weights, ReadOnlySpan<int> input)
    {
        int length = Math.Min(weights.Length, input.Length);
        int sum = 0;
        int i = 0;

        if (Vector256.IsHardwareAccelerated && length >= 8)
        {
            sum = DotProductVector256(weights, input, length, ref i);
        }
        else if (Vector128.IsHardwareAccelerated && length >= 4)
        {
            sum = DotProductVector128(weights, input, length, ref i);
        }

        // Scalar tail
        for (; i < length; i++)
        {
            int w = weights[i];
            // Branchless ternary: w is -1, 0, or +1, so w * x is just add/sub/skip
            sum += w * input[i];
        }

        return sum;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int DotProductVector256(
        ReadOnlySpan<sbyte> weights, ReadOnlySpan<int> input, int length, ref int i)
    {
        Vector256<int> acc = Vector256<int>.Zero;
        ref readonly int inputRef = ref MemoryMarshal.GetReference(input);

        for (; i + 8 <= length; i += 8)
        {
            // Widen 8 ternary weights from sbyte to int32
            Vector256<int> w = WidenToInt32_256(weights, i);
            Vector256<int> x = Vector256.LoadUnsafe(in inputRef, (nuint)i);

            acc = Vector256.Add(acc, Vector256.Multiply(w, x));
        }

        return Vector256.Sum(acc);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int DotProductVector128(
        ReadOnlySpan<sbyte> weights, ReadOnlySpan<int> input, int length, ref int i)
    {
        Vector128<int> acc = Vector128<int>.Zero;
        ref readonly int inputRef = ref MemoryMarshal.GetReference(input);

        for (; i + 4 <= length; i += 4)
        {
            Vector128<int> w = WidenToInt32_128(weights, i);
            Vector128<int> x = Vector128.LoadUnsafe(in inputRef, (nuint)i);

            acc = Vector128.Add(acc, Vector128.Multiply(w, x));
        }

        return Vector128.Sum(acc);
    }

    /// <summary>
    /// RMS normalisation (integer approximation).
    /// Computes: output[i] = (input[i] * scale) / rms
    /// where rms = sqrt(mean(input[i]^2))
    /// </summary>
    public static void RmsNormalize(ReadOnlySpan<int> input, Span<int> output, int scale = 1024)
    {
        if (input.Length != output.Length)
            ThrowArgumentOutOfRange(nameof(output), output.Length, input.Length);

        long sumSquares = 0;
        for (int i = 0; i < input.Length; i++)
        {
            long v = input[i];
            sumSquares += v * v;
        }

        // Integer sqrt approximation: rms = isqrt(sumSquares / n)
        long meanSquare = sumSquares / Math.Max(1, input.Length);
        int rms = (int)Math.Max(1, IntegerSqrt(meanSquare));

        for (int i = 0; i < input.Length; i++)
        {
            output[i] = (int)((long)input[i] * scale / rms);
        }
    }

    /// <summary>
    /// Softmax over integer logits, returning indices sorted by descending probability.
    /// Returns top-k indices. Uses fixed-point arithmetic to avoid float.
    /// </summary>
    public static void TopK(ReadOnlySpan<int> logits, Span<int> topIndices, int k)
    {
        k = Math.Min(k, Math.Min(logits.Length, topIndices.Length));

        // Simple selection: find top-k by iterating k times
        Span<bool> used = stackalloc bool[logits.Length < 1024 ? logits.Length : 0];
        bool useHeap = logits.Length >= 1024;
        bool[]? usedArray = useHeap ? new bool[logits.Length] : null;
        Span<bool> usedSpan = useHeap ? usedArray.AsSpan() : used;

        for (int pick = 0; pick < k; pick++)
        {
            int bestIdx = -1;
            int bestVal = int.MinValue;
            for (int j = 0; j < logits.Length; j++)
            {
                if (!usedSpan[j] && logits[j] > bestVal)
                {
                    bestVal = logits[j];
                    bestIdx = j;
                }
            }
            if (bestIdx < 0) break;
            topIndices[pick] = bestIdx;
            usedSpan[bestIdx] = true;
        }
    }

    /// <summary>
    /// Element-wise add: output = a + b.
    /// </summary>
    public static void Add(ReadOnlySpan<int> a, ReadOnlySpan<int> b, Span<int> output)
    {
        int len = Math.Min(a.Length, Math.Min(b.Length, output.Length));
        int i = 0;

        if (Vector256.IsHardwareAccelerated)
        {
            ref readonly int aRef = ref MemoryMarshal.GetReference(a);
            ref readonly int bRef = ref MemoryMarshal.GetReference(b);
            ref int oRef = ref MemoryMarshal.GetReference(output);

            for (; i + 8 <= len; i += 8)
            {
                var va = Vector256.LoadUnsafe(in aRef, (nuint)i);
                var vb = Vector256.LoadUnsafe(in bRef, (nuint)i);
                Vector256.Add(va, vb).StoreUnsafe(ref oRef, (nuint)i);
            }
        }

        for (; i < len; i++)
            output[i] = a[i] + b[i];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<int> WidenToInt32_256(ReadOnlySpan<sbyte> source, int offset)
    {
        // Load 8 sbyte values and widen to 8 int32 values
        return Vector256.Create(
            (int)source[offset],     (int)source[offset + 1],
            (int)source[offset + 2], (int)source[offset + 3],
            (int)source[offset + 4], (int)source[offset + 5],
            (int)source[offset + 6], (int)source[offset + 7]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<int> WidenToInt32_128(ReadOnlySpan<sbyte> source, int offset)
    {
        return Vector128.Create(
            (int)source[offset],     (int)source[offset + 1],
            (int)source[offset + 2], (int)source[offset + 3]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static long IntegerSqrt(long n)
    {
        if (n <= 0) return 0;
        long x = (long)Math.Sqrt((double)n);
        // Newton's method correction for integer precision
        while (x * x > n) x--;
        while ((x + 1) * (x + 1) <= n) x++;
        return x;
    }

    private static void ThrowArgumentOutOfRange(string param, int actual, int required)
    {
        throw new ArgumentOutOfRangeException(param,
            $"Buffer length {actual} is less than required {required}");
    }
}
