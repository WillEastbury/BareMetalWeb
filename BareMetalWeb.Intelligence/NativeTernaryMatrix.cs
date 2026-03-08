using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// 2-bit packed ternary weight matrix stored in native (unmanaged) memory.
/// Combines three memory optimizations:
///   1. 2-bit packing — 4 weights per byte (4× vs sbyte[])
///   2. Native memory — weights live outside the GC heap (zero GC pressure)
///   3. Zero-byte skipping — packed 0x00 = 4 zero weights, skipped in dot product
///
/// Encoding: -1 → 0b11, 0 → 0b00, +1 → 0b01 (2 bits per weight)
/// Branchless decode: weight = (e &amp; 1) * (1 - (e &amp; 2))
/// </summary>
public sealed unsafe class NativeTernaryMatrix : IDisposable
{
    private byte* _data;
    private readonly int _rows;
    private readonly int _cols;
    private readonly int _packedRowStride; // bytes per packed row = ceil(cols / 4)
    private readonly long _totalBytes;
    private bool _disposed;

    public int Rows => _rows;
    public int Cols => _cols;
    public long BytesAllocated => _totalBytes;
    public bool IsDisposed => _disposed;

    private NativeTernaryMatrix(int rows, int cols)
    {
        _rows = rows;
        _cols = cols;
        _packedRowStride = (cols + 3) >> 2;
        _totalBytes = (long)rows * _packedRowStride;
        _data = (byte*)NativeMemory.AllocZeroed((nuint)_totalBytes);
    }

    /// <summary>
    /// Pack an sbyte[] ternary weight matrix into 2-bit native memory.
    /// Weights must be in {-1, 0, +1}. Layout is row-major.
    /// </summary>
    public static NativeTernaryMatrix Pack(ReadOnlySpan<sbyte> weights, int rows, int cols)
    {
        if (weights.Length < rows * cols)
            throw new ArgumentException($"Weight buffer {weights.Length} < required {rows * cols}");

        var matrix = new NativeTernaryMatrix(rows, cols);

        for (int r = 0; r < rows; r++)
        {
            int srcRow = r * cols;
            int dstRow = r * matrix._packedRowStride;

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

            // Tail (0-3 remaining weights)
            if (c < cols)
            {
                byte packed = 0;
                for (int k = 0; c + k < cols; k++)
                    packed |= (byte)((weights[srcRow + c + k] & 3) << (k * 2));
                matrix._data[dstRow + byteIdx] = packed;
            }
        }

        return matrix;
    }

    /// <summary>
    /// Dot product of matrix row with an input vector.
    /// Skips zero-packed bytes (4 consecutive zeros) for sparsity acceleration.
    /// Uses branchless decode: weight = (e &amp; 1) * (1 - (e &amp; 2)).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int DotProductRow(int row, ReadOnlySpan<int> input)
    {
        if ((uint)row >= (uint)_rows)
            ThrowRowOutOfRange(row);

        byte* rowPtr = _data + (long)row * _packedRowStride;
        int sum = 0;
        int col = 0;
        int fullBytes = _cols >> 2;
        int tailWeights = _cols & 3;

        ref readonly int inputRef = ref MemoryMarshal.GetReference(input);

        for (int b = 0; b < fullBytes; b++, col += 4)
        {
            byte packed = rowPtr[b];
            if (packed == 0) continue; // Zero-skip: 4 zero weights

            // Branchless decode: (e & 1) * (1 - (e & 2))
            int e0 = packed & 3;
            int e1 = (packed >> 2) & 3;
            int e2 = (packed >> 4) & 3;
            int e3 = (packed >> 6) & 3;

            sum += (e0 & 1) * (1 - (e0 & 2)) * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col);
            sum += (e1 & 1) * (1 - (e1 & 2)) * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 1);
            sum += (e2 & 1) * (1 - (e2 & 2)) * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 2);
            sum += (e3 & 1) * (1 - (e3 & 2)) * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 3);
        }

        // Tail weights
        if (tailWeights > 0)
        {
            byte packed = rowPtr[fullBytes];
            for (int k = 0; k < tailWeights; k++, col++)
            {
                int e = (packed >> (k * 2)) & 3;
                sum += (e & 1) * (1 - (e & 2)) * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col);
            }
        }

        return sum;
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
    /// Count non-zero weights for sparsity reporting.
    /// </summary>
    public long CountNonZeros()
    {
        long nnz = 0;
        for (int r = 0; r < _rows; r++)
        {
            byte* rowPtr = _data + (long)r * _packedRowStride;
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
    /// Count packed zero bytes (each = 4 skipped weights during dot product).
    /// </summary>
    public long CountZeroBytes()
    {
        long count = 0;
        for (long i = 0; i < _totalBytes; i++)
            if (_data[i] == 0) count++;
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
