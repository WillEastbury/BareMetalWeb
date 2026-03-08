using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// 2-bit packed ternary weight matrix stored in native (unmanaged) memory.
///   1. 2-bit packing — 4 weights per byte (4× vs sbyte[])
///   2. Native memory — weights live outside the GC heap (zero GC pressure)
///   3. Zero-skip — packed 0x00 = 4+ zero weights, skipped in dot product
///   4. 32-byte row alignment — rows start on AVX2/cache-line boundaries
///   5. AVX2 vectorised dot product — 16 weights per iteration
///   6. Prefetch — hides memory latency for large matrices
///
/// Encoding: -1 → 0b11, 0 → 0b00, +1 → 0b01 (2 bits per weight)
/// Branchless decode: weight = (e &amp; 1) * (1 - (e &amp; 2))
/// </summary>
public sealed unsafe class NativeTernaryMatrix : IDisposable
{
    private const int RowAlignment = 32; // AVX2 register width in bytes

    private byte* _data;
    private readonly int _rows;
    private readonly int _cols;
    private readonly int _packedRowBytes;   // logical packed width = ceil(cols / 4)
    private readonly int _rowStrideBytes;   // aligned width = AlignUp(packedRowBytes, 32)
    private readonly long _totalBytes;
    private MatrixStats _stats;
    private bool _disposed;

    public int Rows => _rows;
    public int Cols => _cols;
    /// <summary>Logical packed bytes per row (ceil(cols / 4)).</summary>
    public int PackedRowBytes => _packedRowBytes;
    /// <summary>Aligned stride per row (multiple of 32 bytes).</summary>
    public int RowStrideBytes => _rowStrideBytes;
    public long BytesAllocated => _totalBytes;
    public bool IsDisposed => _disposed;
    /// <summary>Sparsity and packing statistics computed during Pack().</summary>
    public MatrixStats Stats => _stats;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static int AlignUp(int value, int alignment)
    {
        return (value + alignment - 1) & ~(alignment - 1);
    }

    private NativeTernaryMatrix(int rows, int cols)
    {
        _rows = rows;
        _cols = cols;
        _packedRowBytes = (cols + 3) >> 2;
        _rowStrideBytes = AlignUp(_packedRowBytes, RowAlignment);
        _totalBytes = (long)rows * _rowStrideBytes;
        _data = (byte*)NativeMemory.AllocZeroed((nuint)_totalBytes);
    }

    /// <summary>
    /// Pack an sbyte[] ternary weight matrix into 2-bit native memory.
    /// Weights must be in {-1, 0, +1}. Layout is row-major, rows 32-byte aligned.
    /// Computes MatrixStats during packing.
    /// </summary>
    public static NativeTernaryMatrix Pack(ReadOnlySpan<sbyte> weights, int rows, int cols)
    {
        if (weights.Length < rows * cols)
            throw new ArgumentException($"Weight buffer {weights.Length} < required {rows * cols}");

        var matrix = new NativeTernaryMatrix(rows, cols);

        for (int r = 0; r < rows; r++)
        {
            int srcRow = r * cols;
            long dstRow = (long)r * matrix._rowStrideBytes;

            int c = 0;
            int byteIdx = 0;
            for (; c + 3 < cols; c += 4, byteIdx++)
            {
                int i = srcRow + c;
                byte packed = (byte)(
                    (weights[i] & 3) |
                    ((weights[i + 1] & 3) << 2) |
                    ((weights[i + 2] & 3) << 4) |
                    ((weights[i + 3] & 3) << 6));
                matrix._data[dstRow + byteIdx] = packed;
            }

            // Tail (0-3 remaining weights) — padding stays zero from AllocZeroed
            if (c < cols)
            {
                byte packed = 0;
                for (int k = 0; c + k < cols; k++)
                    packed |= (byte)((weights[srcRow + c + k] & 3) << (k * 2));
                matrix._data[dstRow + byteIdx] = packed;
            }
        }

        // Compute sparsity stats over logical region
        int totalLogicalBytes = rows * matrix._packedRowBytes;
        int zeroByteCount = 0;
        for (int r = 0; r < rows; r++)
        {
            byte* rowPtr = matrix._data + (long)r * matrix._rowStrideBytes;
            for (int b = 0; b < matrix._packedRowBytes; b++)
            {
                if (rowPtr[b] == 0) zeroByteCount++;
            }
        }

        matrix._stats = new MatrixStats(
            LogicalWeights: rows * cols,
            PackedBytes: totalLogicalBytes,
            ZeroByteCount: zeroByteCount,
            ZeroByteRatio: totalLogicalBytes > 0
                ? (float)zeroByteCount / totalLogicalBytes
                : 0f);

        return matrix;
    }

    /// <summary>
    /// Dot product of matrix row with an input vector.
    /// Dispatches to AVX2 (16 weights/iter) or scalar (4 weights/iter).
    /// Both paths use prefetching and zero-skip acceleration.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int DotProductRow(int row, ReadOnlySpan<int> input)
    {
        if ((uint)row >= (uint)_rows)
            ThrowRowOutOfRange(row);

        byte* rowPtr = _data + (long)row * _rowStrideBytes;
        int fullBytes = _cols >> 2;
        int tailWeights = _cols & 3;

        ref readonly int inputRef = ref MemoryMarshal.GetReference(input);

        int sum;
        int col;

        if (Vector256.IsHardwareAccelerated && fullBytes >= 4)
        {
            sum = DotProductAvx2(rowPtr, in inputRef, fullBytes, out col);
        }
        else
        {
            sum = DotProductScalar(rowPtr, in inputRef, fullBytes, out col);
        }

        // Tail weights (< 4 remaining)
        if (tailWeights > 0)
        {
            byte packed = rowPtr[fullBytes];
            for (int k = 0; k < tailWeights; k++, col++)
            {
                int e = (packed >> (k * 2)) & 3;
                sum += Decode2Bit(e) * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col);
            }
        }

        return sum;
    }

    /// <summary>
    /// AVX2 fast path: processes 16 weights (4 packed bytes) per iteration.
    /// Uses Vector256 multiply-accumulate with prefetch and 16-weight zero-skip.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int DotProductAvx2(
        byte* rowPtr,
        in int inputRef,
        int fullBytes,
        out int col)
    {
        Vector256<int> acc = Vector256<int>.Zero;
        col = 0;
        int b = 0;

        // Process 16 weights (4 packed bytes) per iteration
        for (; b + 3 < fullBytes; b += 4, col += 16)
        {
            // Prefetch 2 cache lines ahead — Sse.IsSupported is a JIT constant (no branch)
            if (Sse.IsSupported)
                Sse.Prefetch0(rowPtr + b + 128);

            // Quick zero check: 4 bytes as uint32
            uint packed4 = *(uint*)(rowPtr + b);
            if (packed4 == 0) continue; // Skip 16 zero weights

            // Decode bytes 0-1 → 8 weights → Vector256<int>
            Vector256<int> w0 = Decode2PackedBytes(rowPtr[b], rowPtr[b + 1]);
            Vector256<int> x0 = Vector256.LoadUnsafe(in Unsafe.AsRef(in inputRef), (nuint)col);
            acc = Vector256.Add(acc, Vector256.Multiply(w0, x0));

            // Decode bytes 2-3 → 8 weights → Vector256<int>
            Vector256<int> w1 = Decode2PackedBytes(rowPtr[b + 2], rowPtr[b + 3]);
            Vector256<int> x1 = Vector256.LoadUnsafe(in Unsafe.AsRef(in inputRef), (nuint)(col + 8));
            acc = Vector256.Add(acc, Vector256.Multiply(w1, x1));
        }

        int sum = Vector256.Sum(acc);

        // Scalar remainder (0-3 packed bytes)
        for (; b < fullBytes; b++, col += 4)
        {
            byte packed = rowPtr[b];
            if (packed == 0) continue;

            sum += Decode2Bit(packed & 3) * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col);
            sum += Decode2Bit((packed >> 2) & 3) * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 1);
            sum += Decode2Bit((packed >> 4) & 3) * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 2);
            sum += Decode2Bit(packed >> 6) * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 3);
        }

        return sum;
    }

    /// <summary>
    /// Scalar fallback: processes 4 weights (1 packed byte) per iteration with prefetch.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int DotProductScalar(
        byte* rowPtr,
        in int inputRef,
        int fullBytes,
        out int col)
    {
        int sum = 0;
        col = 0;

        for (int b = 0; b < fullBytes; b++, col += 4)
        {
            // Prefetch 1 cache line ahead — JIT constant guard, no runtime branch
            if (Sse.IsSupported)
                Sse.Prefetch0(rowPtr + b + 64);

            byte packed = rowPtr[b];
            if (packed == 0) continue;

            sum += Decode2Bit(packed & 3) * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col);
            sum += Decode2Bit((packed >> 2) & 3) * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 1);
            sum += Decode2Bit((packed >> 4) & 3) * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 2);
            sum += Decode2Bit(packed >> 6) * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 3);
        }

        return sum;
    }

    /// <summary>
    /// Decode 2 packed bytes (8 ternary weights) into Vector256&lt;int&gt;.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector256<int> Decode2PackedBytes(byte p0, byte p1)
    {
        return Vector256.Create(
            Decode2Bit(p0 & 3),
            Decode2Bit((p0 >> 2) & 3),
            Decode2Bit((p0 >> 4) & 3),
            Decode2Bit(p0 >> 6),
            Decode2Bit(p1 & 3),
            Decode2Bit((p1 >> 2) & 3),
            Decode2Bit((p1 >> 4) & 3),
            Decode2Bit(p1 >> 6));
    }

    /// <summary>
    /// Branchless decode: 0b00→0, 0b01→+1, 0b11→-1.
    /// Formula: (e &amp; 1) * (1 - (e &amp; 2)). No branches, no LUT.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int Decode2Bit(int e)
    {
        return (e & 1) * (1 - (e & 2));
    }

    /// <summary>
    /// Matrix-vector multiply: output[r] = dot(row[r], input) for all rows.
    /// </summary>
    public void MatVecMultiply(ReadOnlySpan<int> input, Span<int> output)
    {
        if (input.Length < _cols)
            throw new ArgumentException($"Input length {input.Length} < cols {_cols}");
        if (output.Length < _rows)
            throw new ArgumentException($"Output length {output.Length} < rows {_rows}");

        for (int r = 0; r < _rows; r++)
            output[r] = DotProductRow(r, input);
    }

    /// <summary>
    /// Count non-zero weights in the logical region (excludes alignment padding).
    /// </summary>
    public long CountNonZeros()
    {
        long nnz = 0;
        for (int r = 0; r < _rows; r++)
        {
            byte* rowPtr = _data + (long)r * _rowStrideBytes;
            int fullBytes = _cols >> 2;
            int tailWeights = _cols & 3;

            for (int b = 0; b < fullBytes; b++)
            {
                byte p = rowPtr[b];
                if (p == 0) continue;
                if ((p & 3) != 0) nnz++;
                if (((p >> 2) & 3) != 0) nnz++;
                if (((p >> 4) & 3) != 0) nnz++;
                if (((p >> 6) & 3) != 0) nnz++;
            }

            if (tailWeights > 0)
            {
                byte p = rowPtr[fullBytes];
                for (int k = 0; k < tailWeights; k++)
                    if (((p >> (k * 2)) & 3) != 0) nnz++;
            }
        }
        return nnz;
    }

    /// <summary>
    /// Count zero bytes in the logical region (excludes alignment padding).
    /// </summary>
    public long CountZeroBytes()
    {
        long count = 0;
        for (int r = 0; r < _rows; r++)
        {
            byte* rowPtr = _data + (long)r * _rowStrideBytes;
            for (int b = 0; b < _packedRowBytes; b++)
                if (rowPtr[b] == 0) count++;
        }
        return count;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            if (_data != null)
            {
                NativeMemory.Free(_data);
                _data = null;
            }
            _disposed = true;
            GC.SuppressFinalize(this);
        }
    }

    ~NativeTernaryMatrix()
    {
        if (!_disposed && _data != null)
        {
            NativeMemory.Free(_data);
            _data = null;
            _disposed = true;
        }
    }

    private static void ThrowRowOutOfRange(int row) =>
        throw new ArgumentOutOfRangeException(nameof(row), $"Row index {row} out of range");
}

/// <summary>
/// Sparsity and packing statistics for a single NativeTernaryMatrix.
/// </summary>
public readonly record struct MatrixStats(
    int LogicalWeights,
    int PackedBytes,
    int ZeroByteCount,
    float ZeroByteRatio
);
