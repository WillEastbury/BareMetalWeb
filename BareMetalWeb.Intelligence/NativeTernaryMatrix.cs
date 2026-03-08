using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using System.Threading.Tasks;

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
    private const int ParallelRowThreshold = 128;

    // 256-entry LUT: packed byte → 4 decoded ternary weights {-1, 0, +1}
    private static readonly int[] s_decodeLut = BuildDecodeLut();

    private byte* _data;
    private readonly int _rows;
    private readonly int _cols;
    private readonly int _packedRowBytes;   // logical packed width = ceil(cols / 4)
    private readonly int _rowStrideBytes;   // aligned width = AlignUp(packedRowBytes, 32)
    private readonly long _totalBytes;
    private MatrixStats _stats;
    private ushort[][]? _skipIndex; // per-row non-zero byte offsets for sparse skip
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

    private static int[] BuildDecodeLut()
    {
        var lut = new int[1024]; // 256 packed bytes × 4 weights each
        for (int b = 0; b < 256; b++)
        {
            int i = b << 2;
            lut[i]     = Decode2Bit(b & 3);
            lut[i + 1] = Decode2Bit((b >> 2) & 3);
            lut[i + 2] = Decode2Bit((b >> 4) & 3);
            lut[i + 3] = Decode2Bit(b >> 6);
        }
        return lut;
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

        if (matrix._stats.ZeroByteRatio > 0.4f
            && !Vector512.IsHardwareAccelerated
            && !Vector256.IsHardwareAccelerated
            && !AdvSimd.IsSupported)
            matrix.BuildSkipIndex();

        return matrix;
    }

    /// <summary>
    /// Dot product of matrix row with an input vector.
    /// Dispatches to AVX-512 (32 weights/iter), AVX2 (16 weights/iter),
    /// NEON (8 weights/iter), sparse skip, or scalar (4 weights/iter).
    /// All paths use LUT decode, prefetching, and zero-skip acceleration.
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

        // Dispatch: AVX-512 > AVX2 > NEON > Sparse skip > Scalar
        if (Vector512.IsHardwareAccelerated && fullBytes >= 8)
        {
            sum = DotProductAvx512(rowPtr, in inputRef, fullBytes, out col);
        }
        else if (Vector256.IsHardwareAccelerated && fullBytes >= 4)
        {
            sum = DotProductAvx2(rowPtr, in inputRef, fullBytes, out col);
        }
        else if (AdvSimd.IsSupported && fullBytes >= 2)
        {
            sum = DotProductNeon(rowPtr, in inputRef, fullBytes, out col);
        }
        else if (_skipIndex is not null)
        {
            return DotProductSparse(rowPtr, in inputRef, row, fullBytes, tailWeights);
        }
        else
        {
            sum = DotProductScalar(rowPtr, in inputRef, fullBytes, out col);
        }

        // Tail weights (< 4 remaining) — LUT decode
        if (tailWeights > 0)
        {
            int lutBase = rowPtr[fullBytes] << 2;
            for (int k = 0; k < tailWeights; k++, col++)
                sum += s_decodeLut[lutBase + k] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col);
        }

        return sum;
    }

    /// <summary>
    /// AVX-512 fast path: processes 32 weights (8 packed bytes) per iteration.
    /// Uses Vector512 multiply-accumulate with LUT decode and 64-weight zero-skip.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int DotProductAvx512(
        byte* rowPtr,
        in int inputRef,
        int fullBytes,
        out int col)
    {
        Vector512<int> acc = Vector512<int>.Zero;
        col = 0;
        int b = 0;

        ref int lutRef = ref MemoryMarshal.GetArrayDataReference(s_decodeLut);

        for (; b + 7 < fullBytes; b += 8, col += 32)
        {
            if (Sse.IsSupported)
                Sse.Prefetch0(rowPtr + b + 256);

            ulong packed8 = *(ulong*)(rowPtr + b);
            if (packed8 == 0) continue; // Skip 32 zero weights

            Vector512<int> w0 = Vector512.Create(
                Vector256.Create(
                    Vector128.LoadUnsafe(ref Unsafe.Add(ref lutRef, rowPtr[b] << 2)),
                    Vector128.LoadUnsafe(ref Unsafe.Add(ref lutRef, rowPtr[b + 1] << 2))),
                Vector256.Create(
                    Vector128.LoadUnsafe(ref Unsafe.Add(ref lutRef, rowPtr[b + 2] << 2)),
                    Vector128.LoadUnsafe(ref Unsafe.Add(ref lutRef, rowPtr[b + 3] << 2))));
            Vector512<int> x0 = Vector512.LoadUnsafe(in Unsafe.AsRef(in inputRef), (nuint)col);
            acc = Vector512.Add(acc, Vector512.Multiply(w0, x0));

            Vector512<int> w1 = Vector512.Create(
                Vector256.Create(
                    Vector128.LoadUnsafe(ref Unsafe.Add(ref lutRef, rowPtr[b + 4] << 2)),
                    Vector128.LoadUnsafe(ref Unsafe.Add(ref lutRef, rowPtr[b + 5] << 2))),
                Vector256.Create(
                    Vector128.LoadUnsafe(ref Unsafe.Add(ref lutRef, rowPtr[b + 6] << 2)),
                    Vector128.LoadUnsafe(ref Unsafe.Add(ref lutRef, rowPtr[b + 7] << 2))));
            Vector512<int> x1 = Vector512.LoadUnsafe(in Unsafe.AsRef(in inputRef), (nuint)(col + 16));
            acc = Vector512.Add(acc, Vector512.Multiply(w1, x1));
        }

        int sum = Vector512.Sum(acc);

        // Scalar remainder (0-7 packed bytes)
        for (; b < fullBytes; b++, col += 4)
        {
            byte packed = rowPtr[b];
            if (packed == 0) continue;
            int lutBase = packed << 2;
            sum += s_decodeLut[lutBase] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col);
            sum += s_decodeLut[lutBase + 1] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 1);
            sum += s_decodeLut[lutBase + 2] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 2);
            sum += s_decodeLut[lutBase + 3] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 3);
        }

        return sum;
    }

    /// <summary>
    /// AVX2 fast path: processes 16 weights (4 packed bytes) per iteration.
    /// Uses Vector256 multiply-accumulate with LUT decode and 16-weight zero-skip.
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

        ref int lutRef = ref MemoryMarshal.GetArrayDataReference(s_decodeLut);

        for (; b + 3 < fullBytes; b += 4, col += 16)
        {
            if (Sse.IsSupported)
                Sse.Prefetch0(rowPtr + b + 128);

            uint packed4 = *(uint*)(rowPtr + b);
            if (packed4 == 0) continue;

            // LUT decode: 2 bytes → 8 weights → Vector256<int>
            Vector256<int> w0 = Vector256.Create(
                Vector128.LoadUnsafe(ref Unsafe.Add(ref lutRef, rowPtr[b] << 2)),
                Vector128.LoadUnsafe(ref Unsafe.Add(ref lutRef, rowPtr[b + 1] << 2)));
            Vector256<int> x0 = Vector256.LoadUnsafe(in Unsafe.AsRef(in inputRef), (nuint)col);
            acc = Vector256.Add(acc, Vector256.Multiply(w0, x0));

            Vector256<int> w1 = Vector256.Create(
                Vector128.LoadUnsafe(ref Unsafe.Add(ref lutRef, rowPtr[b + 2] << 2)),
                Vector128.LoadUnsafe(ref Unsafe.Add(ref lutRef, rowPtr[b + 3] << 2)));
            Vector256<int> x1 = Vector256.LoadUnsafe(in Unsafe.AsRef(in inputRef), (nuint)(col + 8));
            acc = Vector256.Add(acc, Vector256.Multiply(w1, x1));
        }

        int sum = Vector256.Sum(acc);

        // Scalar remainder (0-3 packed bytes)
        for (; b < fullBytes; b++, col += 4)
        {
            byte packed = rowPtr[b];
            if (packed == 0) continue;
            int lutBase = packed << 2;
            sum += s_decodeLut[lutBase] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col);
            sum += s_decodeLut[lutBase + 1] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 1);
            sum += s_decodeLut[lutBase + 2] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 2);
            sum += s_decodeLut[lutBase + 3] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 3);
        }

        return sum;
    }

    /// <summary>
    /// ARM NEON path: processes 8 weights (2 packed bytes) per iteration.
    /// Uses Vector128 multiply-accumulate with LUT decode and 8-weight zero-skip.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int DotProductNeon(
        byte* rowPtr,
        in int inputRef,
        int fullBytes,
        out int col)
    {
        Vector128<int> acc = Vector128<int>.Zero;
        col = 0;
        int b = 0;

        ref int lutRef = ref MemoryMarshal.GetArrayDataReference(s_decodeLut);

        for (; b + 1 < fullBytes; b += 2, col += 8)
        {
            ushort packed2 = *(ushort*)(rowPtr + b);
            if (packed2 == 0) continue;

            Vector128<int> w0 = Vector128.LoadUnsafe(ref Unsafe.Add(ref lutRef, rowPtr[b] << 2));
            Vector128<int> x0 = Vector128.LoadUnsafe(in Unsafe.AsRef(in inputRef), (nuint)col);
            acc = Vector128.Add(acc, Vector128.Multiply(w0, x0));

            Vector128<int> w1 = Vector128.LoadUnsafe(ref Unsafe.Add(ref lutRef, rowPtr[b + 1] << 2));
            Vector128<int> x1 = Vector128.LoadUnsafe(in Unsafe.AsRef(in inputRef), (nuint)(col + 4));
            acc = Vector128.Add(acc, Vector128.Multiply(w1, x1));
        }

        int sum = acc.GetElement(0) + acc.GetElement(1) + acc.GetElement(2) + acc.GetElement(3);

        // Scalar remainder (0-1 packed bytes)
        for (; b < fullBytes; b++, col += 4)
        {
            byte packed = rowPtr[b];
            if (packed == 0) continue;
            int lutBase = packed << 2;
            sum += s_decodeLut[lutBase] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col);
            sum += s_decodeLut[lutBase + 1] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 1);
            sum += s_decodeLut[lutBase + 2] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 2);
            sum += s_decodeLut[lutBase + 3] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 3);
        }

        return sum;
    }

    /// <summary>
    /// Scalar fallback with LUT decode: processes 4 weights per iteration.
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
            if (Sse.IsSupported)
                Sse.Prefetch0(rowPtr + b + 64);

            byte packed = rowPtr[b];
            if (packed == 0) continue;

            int lutBase = packed << 2;
            sum += s_decodeLut[lutBase] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col);
            sum += s_decodeLut[lutBase + 1] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 1);
            sum += s_decodeLut[lutBase + 2] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 2);
            sum += s_decodeLut[lutBase + 3] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 3);
        }

        return sum;
    }

    /// <summary>
    /// Sparse skip-index path: iterates only over non-zero bytes using pre-built offset list.
    /// Best for high-sparsity rows without SIMD support.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private int DotProductSparse(
        byte* rowPtr,
        in int inputRef,
        int row,
        int fullBytes,
        int tailWeights)
    {
        var offsets = _skipIndex![row];
        int sum = 0;

        for (int i = 0; i < offsets.Length; i++)
        {
            int b = offsets[i];
            int col = b << 2;
            int lutBase = rowPtr[b] << 2;
            sum += s_decodeLut[lutBase] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col);
            sum += s_decodeLut[lutBase + 1] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 1);
            sum += s_decodeLut[lutBase + 2] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 2);
            sum += s_decodeLut[lutBase + 3] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + 3);
        }

        if (tailWeights > 0)
        {
            byte p = rowPtr[fullBytes];
            if (p != 0)
            {
                int col = fullBytes << 2;
                int lutBase = p << 2;
                for (int k = 0; k < tailWeights; k++)
                    sum += s_decodeLut[lutBase + k] * Unsafe.Add(ref Unsafe.AsRef(in inputRef), col + k);
            }
        }

        return sum;
    }

    /// <summary>
    /// Branchless decode: 0b00→0, 0b01→+1, 0b11→-1.
    /// Used by LUT builder. Hot-path code uses the LUT directly.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int Decode2Bit(int e)
    {
        return (e & 1) * (1 - (e & 2));
    }

    /// <summary>
    /// Build per-row sparse skip index listing non-zero byte offsets.
    /// Enables O(nnz) iteration instead of O(n) linear scan.
    /// </summary>
    private void BuildSkipIndex()
    {
        _skipIndex = new ushort[_rows][];
        var temp = new ushort[_packedRowBytes];
        for (int r = 0; r < _rows; r++)
        {
            byte* rowPtr = _data + (long)r * _rowStrideBytes;
            int count = 0;
            for (int b = 0; b < _packedRowBytes; b++)
            {
                if (rowPtr[b] != 0) temp[count++] = (ushort)b;
            }
            _skipIndex[r] = temp[..count].ToArray();
        }
    }

    /// <summary>
    /// Matrix-vector multiply: output[r] = dot(row[r], input) for all rows.
    /// Uses parallel execution for large matrices (&gt;128 rows).
    /// </summary>
    public void MatVecMultiply(ReadOnlySpan<int> input, Span<int> output)
    {
        if (input.Length < _cols)
            throw new ArgumentException($"Input length {input.Length} < cols {_cols}");
        if (output.Length < _rows)
            throw new ArgumentException($"Output length {output.Length} < rows {_rows}");

        if (_rows >= ParallelRowThreshold && Environment.ProcessorCount > 1)
        {
            // Parallel path — pin spans so pointers survive cross-thread access
            fixed (int* pInput = input)
            fixed (int* pOutput = output)
            {
                int inputLen = input.Length;
                int rows = _rows;
                int* pi = pInput;
                int* po = pOutput;

                Parallel.For(0, rows, r =>
                {
                    var inputSpan = new ReadOnlySpan<int>(pi, inputLen);
                    po[r] = DotProductRow(r, inputSpan);
                });
            }
        }
        else
        {
            for (int r = 0; r < _rows; r++)
                output[r] = DotProductRow(r, input);
        }
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

    // ── Snapshot serialisation helpers ───────────────────────────────────

    /// <summary>
    /// Copy the raw packed data (including alignment padding) to a destination span.
    /// Returns the total number of bytes written.
    /// </summary>
    public long CopyPackedDataTo(Span<byte> destination)
    {
        if (destination.Length < _totalBytes)
            throw new ArgumentException(
                $"Destination {destination.Length} < required {_totalBytes}");
        new ReadOnlySpan<byte>(_data, (int)_totalBytes).CopyTo(destination);
        return _totalBytes;
    }

    /// <summary>Total bytes of raw packed data (including alignment padding per row).</summary>
    public long TotalPackedDataBytes => _totalBytes;

    /// <summary>
    /// Reconstruct a NativeTernaryMatrix from previously packed binary data.
    /// The data must include row alignment padding (rowStrideBytes per row).
    /// This avoids re-encoding from sbyte[] weights — instant load.
    /// </summary>
    public static NativeTernaryMatrix FromPackedData(
        ReadOnlySpan<byte> packedData, int rows, int cols)
    {
        var matrix = new NativeTernaryMatrix(rows, cols);

        long expected = (long)rows * matrix._rowStrideBytes;
        if (packedData.Length < expected)
            throw new ArgumentException(
                $"Packed data {packedData.Length} < expected {expected}");

        packedData[..(int)expected].CopyTo(
            new Span<byte>(matrix._data, (int)expected));

        // Recompute stats from the data we just loaded
        int totalLogicalBytes = rows * matrix._packedRowBytes;
        int zeroByteCount = 0;
        for (int r = 0; r < rows; r++)
        {
            byte* rowPtr = matrix._data + (long)r * matrix._rowStrideBytes;
            for (int b = 0; b < matrix._packedRowBytes; b++)
                if (rowPtr[b] == 0) zeroByteCount++;
        }

        matrix._stats = new MatrixStats(
            LogicalWeights: rows * cols,
            PackedBytes: totalLogicalBytes,
            ZeroByteCount: zeroByteCount,
            ZeroByteRatio: totalLogicalBytes > 0
                ? (float)zeroByteCount / totalLogicalBytes : 0f);

        if (matrix._stats.ZeroByteRatio > 0.4f
            && !Vector512.IsHardwareAccelerated
            && !Vector256.IsHardwareAccelerated
            && !AdvSimd.IsSupported)
            matrix.BuildSkipIndex();

        return matrix;
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
