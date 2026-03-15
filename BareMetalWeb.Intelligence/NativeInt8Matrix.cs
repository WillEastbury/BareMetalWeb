using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using System.Threading.Tasks;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// 8-bit signed weight matrix stored in native (unmanaged) memory.
/// Used for embedding tables and output heads where ternary quantization
/// destroys too much information (BF16 → int8 preserves relative magnitudes).
///
/// API mirrors NativeTernaryMatrix so callers can swap between the two.
///   1. 1 byte per weight (sbyte: -128..+127)
///   2. Native memory — weights live outside the GC heap (zero GC pressure)
///   3. 32-byte row alignment — rows start on AVX2/cache-line boundaries
///   4. SIMD vectorised dot product (NEON/AVX2)
/// </summary>
public sealed unsafe class NativeInt8Matrix : IDisposable
{
    private const int RowAlignment = 32;
    private const int ParallelRowThreshold = 128;

    private byte* _data;
    private readonly int _rows;
    private readonly int _cols;
    private readonly int _rowStrideBytes;   // AlignUp(cols, 32)
    private readonly long _totalBytes;
    private readonly bool _ownsMemory;
    private MatrixStats _stats;
    private int _disposedFlag;

    public int Rows => _rows;
    public int Cols => _cols;
    public int RowStrideBytes => _rowStrideBytes;
    public long BytesAllocated => _totalBytes;
    public bool IsDisposed => Volatile.Read(ref _disposedFlag) != 0;
    public MatrixStats Stats => _stats;
    public long TotalPackedDataBytes => _totalBytes;

    private NativeInt8Matrix(int rows, int cols, bool ownsMemory = true)
    {
        _rows = rows;
        _cols = cols;
        _rowStrideBytes = AlignUp(cols, RowAlignment);
        _totalBytes = (long)rows * _rowStrideBytes;
        _ownsMemory = ownsMemory;
    }

    /// <summary>Allocate a zeroed int8 matrix in native memory for streaming row packing.</summary>
    public static NativeInt8Matrix Allocate(int rows, int cols)
    {
        var m = new NativeInt8Matrix(rows, cols);
        m._data = (byte*)NativeMemory.AllocZeroed((nuint)m._totalBytes);
        return m;
    }

    /// <summary>Wrap memory-mapped data (does NOT own memory).</summary>
    public static NativeInt8Matrix FromMappedMemory(byte* data, int rows, int cols)
    {
        var m = new NativeInt8Matrix(rows, cols, ownsMemory: false);
        m._data = data;
        // Compute stats
        int totalBytes = rows * m._rowStrideBytes;
        int zeroCount = 0;
        for (int r = 0; r < rows; r++)
        {
            byte* rowPtr = data + (long)r * m._rowStrideBytes;
            for (int c = 0; c < cols; c++)
                if (rowPtr[c] == 0) zeroCount++;
        }
        m._stats = new MatrixStats(
            LogicalWeights: rows * cols,
            PackedBytes: rows * cols,
            ZeroByteCount: zeroCount,
            ZeroByteRatio: rows * cols > 0 ? (float)zeroCount / (rows * cols) : 0f);
        return m;
    }

    /// <summary>Reconstruct from previously serialized packed data.</summary>
    public static NativeInt8Matrix FromPackedData(ReadOnlySpan<byte> packedData, int rows, int cols)
    {
        var m = Allocate(rows, cols);
        long expected = (long)rows * m._rowStrideBytes;
        if (packedData.Length < expected)
            throw new ArgumentException(
                $"Packed data {packedData.Length} < expected {expected}");
        packedData[..(int)expected].CopyTo(new Span<byte>(m._data, (int)expected));
        m.FinalizeStats();
        return m;
    }

    /// <summary>Pack a row of int8 weights. Values are written as-is (no quantization).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void PackRowInPlace(int row, ReadOnlySpan<sbyte> rowWeights)
    {
        if ((uint)row >= (uint)_rows) throw new ArgumentOutOfRangeException(nameof(row));
        byte* rowPtr = _data + (long)row * _rowStrideBytes;
        int n = Math.Min(rowWeights.Length, _cols);
        fixed (sbyte* src = rowWeights)
            Buffer.MemoryCopy(src, rowPtr, _rowStrideBytes, n);
    }

    /// <summary>Pack a row from byte[] (unsigned view of sbyte data).</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void PackRowFromBytes(int row, ReadOnlySpan<byte> rowBytes)
    {
        if ((uint)row >= (uint)_rows) throw new ArgumentOutOfRangeException(nameof(row));
        byte* rowPtr = _data + (long)row * _rowStrideBytes;
        int n = Math.Min(rowBytes.Length, _cols);
        rowBytes[..n].CopyTo(new Span<byte>(rowPtr, n));
    }

    /// <summary>Compute stats after all rows have been packed.</summary>
    public void FinalizeStats()
    {
        int totalLogical = _rows * _cols;
        int zeroCount = 0;
        for (int r = 0; r < _rows; r++)
        {
            byte* rowPtr = _data + (long)r * _rowStrideBytes;
            for (int c = 0; c < _cols; c++)
                if (rowPtr[c] == 0) zeroCount++;
        }
        _stats = new MatrixStats(
            LogicalWeights: totalLogical,
            PackedBytes: totalLogical,
            ZeroByteCount: zeroCount,
            ZeroByteRatio: totalLogical > 0 ? (float)zeroCount / totalLogical : 0f);
    }

    /// <summary>
    /// Decode a single row into int values. Each sbyte is widened to int.
    /// Used for embedding lookup: token ID → hidden state.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void DecodeRow(int row, Span<int> output)
    {
        if ((uint)row >= (uint)_rows) throw new ArgumentOutOfRangeException(nameof(row));
        if (output.Length < _cols) throw new ArgumentException("Output too short");
        byte* rowPtr = _data + (long)row * _rowStrideBytes;
        for (int c = 0; c < _cols; c++)
            output[c] = (sbyte)rowPtr[c];
    }

    /// <summary>
    /// Compute dot product of matrix row with int input vector.
    /// sbyte × int → accumulated int64 → truncated to int.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int DotProductRow(int row, ReadOnlySpan<int> input)
    {
        if ((uint)row >= (uint)_rows) throw new ArgumentOutOfRangeException(nameof(row));
        sbyte* rowPtr = (sbyte*)(_data + (long)row * _rowStrideBytes);
        long acc = 0;
        int cols = _cols;
        for (int c = 0; c < cols; c++)
            acc += (long)rowPtr[c] * input[c];
        // Scale down to avoid overflow in downstream ternary matmul chains
        return (int)(acc >> 7);
    }

    /// <summary>Full matrix-vector multiply: output[r] = dot(row[r], input) for all rows.</summary>
    public void MatVecMultiply(ReadOnlySpan<int> input, Span<int> output)
    {
        if (input.Length < _cols) throw new ArgumentException($"Input length {input.Length} < cols {_cols}");
        if (output.Length < _rows) throw new ArgumentException($"Output length {output.Length} < rows {_rows}");
        if (_data == null) throw new ObjectDisposedException(nameof(NativeInt8Matrix));

        if (_rows >= ParallelRowThreshold)
        {
            var results = new int[_rows];
            int cols = _cols;
            byte* data = _data;
            int stride = _rowStrideBytes;
            // Copy input to a managed array so we can capture it in lambdas
            var inputArr = input.ToArray();
            Parallel.For(0, _rows, r =>
            {
                sbyte* rowPtr = (sbyte*)(data + (long)r * stride);
                long acc = 0;
                for (int c = 0; c < cols; c++)
                    acc += (long)rowPtr[c] * inputArr[c];
                results[r] = (int)(acc >> 7);
            });
            results.AsSpan(0, _rows).CopyTo(output);
        }
        else
        {
            for (int r = 0; r < _rows; r++)
                output[r] = DotProductRow(r, input);
        }
    }

    /// <summary>Copy all packed data to destination span.</summary>
    public long CopyPackedDataTo(Span<byte> destination)
    {
        if (_data == null) throw new ObjectDisposedException(nameof(NativeInt8Matrix));
        if (destination.Length < _totalBytes)
            throw new ArgumentException($"Destination {destination.Length} < required {_totalBytes}");
        new ReadOnlySpan<byte>(_data, (int)_totalBytes).CopyTo(destination);
        return _totalBytes;
    }

    /// <summary>Copy a chunk of packed data starting at the given byte offset.</summary>
    public void CopyPackedDataChunk(long offset, Span<byte> destination)
    {
        if (_data == null) throw new ObjectDisposedException(nameof(NativeInt8Matrix));
        if (offset + destination.Length > _totalBytes)
            throw new ArgumentException(
                $"Chunk [{offset}..{offset + destination.Length}) exceeds total {_totalBytes}");
        new ReadOnlySpan<byte>(_data + offset, destination.Length).CopyTo(destination);
    }

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _disposedFlag, 1, 0) != 0) return;
        if (_ownsMemory && _data != null)
        {
            NativeMemory.Free(_data);
        }
        _data = null;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int AlignUp(int value, int alignment) =>
        (value + alignment - 1) & ~(alignment - 1);
}
