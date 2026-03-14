using System.Numerics;
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
    private readonly bool _ownsMemory;      // false for mmap-backed matrices
    private MatrixStats _stats;
    private ushort[][]? _skipIndex; // per-row non-zero byte offsets for sparse skip
    private int _disposedFlag; // 0 = alive, 1 = disposed — must use Interlocked

#if NET9_0_OR_GREATER
#pragma warning disable SYSLIB5003 // Sve is experimental
    // SVE in-register decode pattern vectors (lazy-initialized)
    private static Vector<int> s_sveByteIdxVec;
    private static Vector<uint> s_sveShiftVec;
    private static volatile bool s_svePatternsReady;
#pragma warning restore SYSLIB5003
#endif

    public int Rows => _rows;
    public int Cols => _cols;
    /// <summary>Logical packed bytes per row (ceil(cols / 4)).</summary>
    public int PackedRowBytes => _packedRowBytes;
    /// <summary>Aligned stride per row (multiple of 32 bytes).</summary>
    public int RowStrideBytes => _rowStrideBytes;
    public long BytesAllocated => _totalBytes;
    public bool IsDisposed => Volatile.Read(ref Unsafe.AsRef(in _disposedFlag)) != 0;
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

#if NET9_0_OR_GREATER
#pragma warning disable SYSLIB5003
    /// <summary>
    /// Initialize SVE2 in-register decode pattern vectors.
    /// byteIdx: [0,0,0,0, 1,1,1,1, ...] — which packed byte each int32 lane reads.
    /// shifts:  [0,2,4,6, 0,2,4,6, ...] — bit shift to isolate each lane's 2-bit field.
    /// </summary>
    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void InitSveDecodePatterns()
    {
        int count = Vector<int>.Count;
        var byteIdx = new int[count];
        var shifts = new uint[count];
        for (int i = 0; i < count; i++)
        {
            byteIdx[i] = i >> 2;
            shifts[i] = (uint)((i & 3) << 1);
        }
        s_sveByteIdxVec = new Vector<int>(byteIdx);
        s_sveShiftVec = new Vector<uint>(shifts);
        s_svePatternsReady = true;
    }
#pragma warning restore SYSLIB5003
#endif

    private NativeTernaryMatrix(int rows, int cols)
    {
        _rows = rows;
        _cols = cols;
        _packedRowBytes = (cols + 3) >> 2;
        _rowStrideBytes = AlignUp(_packedRowBytes, RowAlignment);
        _totalBytes = (long)rows * _rowStrideBytes;
        _ownsMemory = true;
        _data = (byte*)NativeMemory.AllocZeroed((nuint)_totalBytes);
    }

    // Non-allocating constructor for memory-mapped matrices
    private NativeTernaryMatrix(int rows, int cols, byte* externalData)
    {
        _rows = rows;
        _cols = cols;
        _packedRowBytes = (cols + 3) >> 2;
        _rowStrideBytes = AlignUp(_packedRowBytes, RowAlignment);
        _totalBytes = (long)rows * _rowStrideBytes;
        _ownsMemory = false;
        _data = externalData;
    }

    /// <summary>
    /// Create a matrix referencing external (mmap) memory. The matrix does NOT
    /// own the memory — the caller must ensure it stays valid for the matrix's lifetime.
    /// Stats are deferred (zero-byte ratio shows 0 until data is touched).
    /// </summary>
    public static NativeTernaryMatrix FromMappedMemory(byte* data, int rows, int cols)
    {
        var matrix = new NativeTernaryMatrix(rows, cols, data);
        matrix._stats = new MatrixStats(rows * cols, rows * matrix._packedRowBytes, 0, 0f);
        return matrix;
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
#if NET9_0_OR_GREATER
#pragma warning disable SYSLIB5003
            && !Sve.IsSupported
#pragma warning restore SYSLIB5003
#endif
            && !Vector512.IsHardwareAccelerated
            && !Vector256.IsHardwareAccelerated
            && !AdvSimd.IsSupported)
            matrix.BuildSkipIndex();

        return matrix;
    }

    // 256-entry LUT: remaps a HuggingFace U8 packed byte to native encoding.
    // HF encoding per 2-bit field: 0b00→-1, 0b01→0, 0b10→+1
    // Native encoding per 2-bit field: 0b11→-1, 0b00→0, 0b01→+1
    // Remap per field: HF 0→Native 3, HF 1→Native 0, HF 2→Native 1
    private static readonly byte[] s_hfToNativeLut = BuildHfToNativeLut();

    private static byte[] BuildHfToNativeLut()
    {
        // Per 2-bit field remapping: HF value → native encoding
        ReadOnlySpan<byte> fieldMap = [3, 0, 1, 0]; // HF 0→3(-1), 1→0(0), 2→1(+1), 3→0(unused)

        var lut = new byte[256];
        for (int b = 0; b < 256; b++)
        {
            int f0 = fieldMap[b & 3];
            int f1 = fieldMap[(b >> 2) & 3];
            int f2 = fieldMap[(b >> 4) & 3];
            int f3 = fieldMap[(b >> 6) & 3];
            lut[b] = (byte)(f0 | (f1 << 2) | (f2 << 4) | (f3 << 6));
        }
        return lut;
    }

    /// <summary>
    /// Create a NativeTernaryMatrix directly from HuggingFace U8 packed ternary bytes.
    /// Each input byte holds 4 ternary weights in HF encoding (0→-1, 1→0, 2→+1).
    /// Remaps to native encoding byte-by-byte using a 256-entry LUT — no sbyte[] intermediate.
    /// </summary>
    public static NativeTernaryMatrix FromHfU8Packed(ReadOnlySpan<byte> hfPacked, int rows, int cols)
    {
        int expectedPackedBytes = (cols + 3) >> 2;
        int expectedTotal = rows * expectedPackedBytes;
        if (hfPacked.Length < expectedTotal)
            throw new ArgumentException(
                $"HF packed buffer {hfPacked.Length} < required {expectedTotal} ({rows}×{expectedPackedBytes})");

        var matrix = new NativeTernaryMatrix(rows, cols);
        var lut = s_hfToNativeLut;

        int zeroByteCount = 0;
        for (int r = 0; r < rows; r++)
        {
            int srcRow = r * expectedPackedBytes;
            long dstRow = (long)r * matrix._rowStrideBytes;

            for (int b = 0; b < expectedPackedBytes; b++)
            {
                byte remapped = lut[hfPacked[srcRow + b]];
                matrix._data[dstRow + b] = remapped;
                if (remapped == 0) zeroByteCount++;
            }
        }

        int totalLogicalBytes = rows * matrix._packedRowBytes;
        matrix._stats = new MatrixStats(
            LogicalWeights: rows * cols,
            PackedBytes: totalLogicalBytes,
            ZeroByteCount: zeroByteCount,
            ZeroByteRatio: totalLogicalBytes > 0
                ? (float)zeroByteCount / totalLogicalBytes
                : 0f);

        if (matrix._stats.ZeroByteRatio > 0.4f
#if NET9_0_OR_GREATER
#pragma warning disable SYSLIB5003
            && !Sve.IsSupported
#pragma warning restore SYSLIB5003
#endif
            && !Vector512.IsHardwareAccelerated
            && !Vector256.IsHardwareAccelerated
            && !AdvSimd.IsSupported)
            matrix.BuildSkipIndex();

        return matrix;
    }

    /// <summary>
    /// Create a NativeTernaryMatrix from HF U8 packed bytes with column truncation.
    /// Reads only the first <paramref name="keepCols"/> columns per row from a matrix
    /// stored as <paramref name="srcCols"/> columns. Used for FFN projection (dim×ffnDim → dim×dim)
    /// without unpacking to sbyte[].
    /// </summary>
    public static NativeTernaryMatrix FromHfU8PackedTruncated(
        ReadOnlySpan<byte> hfPacked, int rows, int srcCols, int keepCols)
    {
        int srcPackedPerRow = (srcCols + 3) >> 2;
        int keepPackedPerRow = (keepCols + 3) >> 2;
        if (hfPacked.Length < rows * srcPackedPerRow)
            throw new ArgumentException(
                $"HF packed buffer {hfPacked.Length} < required {rows * srcPackedPerRow}");

        var matrix = new NativeTernaryMatrix(rows, keepCols);
        var lut = s_hfToNativeLut;

        int zeroByteCount = 0;
        for (int r = 0; r < rows; r++)
        {
            int srcRow = r * srcPackedPerRow;
            long dstRow = (long)r * matrix._rowStrideBytes;

            for (int b = 0; b < keepPackedPerRow; b++)
            {
                byte remapped = lut[hfPacked[srcRow + b]];
                matrix._data[dstRow + b] = remapped;
                if (remapped == 0) zeroByteCount++;
            }
        }

        int totalLogicalBytes = rows * matrix._packedRowBytes;
        matrix._stats = new MatrixStats(
            LogicalWeights: rows * keepCols,
            PackedBytes: totalLogicalBytes,
            ZeroByteCount: zeroByteCount,
            ZeroByteRatio: totalLogicalBytes > 0
                ? (float)zeroByteCount / totalLogicalBytes
                : 0f);

        if (matrix._stats.ZeroByteRatio > 0.4f
#if NET9_0_OR_GREATER
#pragma warning disable SYSLIB5003
            && !Sve.IsSupported
#pragma warning restore SYSLIB5003
#endif
            && !Vector512.IsHardwareAccelerated
            && !Vector256.IsHardwareAccelerated
            && !AdvSimd.IsSupported)
            matrix.BuildSkipIndex();

        return matrix;
    }

    /// <summary>
    /// Dot product of matrix row with an input vector.
    /// Dispatches to SVE2, SVE, AVX-512, AVX2, NEON, sparse skip, or scalar.
    /// All paths use zero-skip acceleration. SVE2 uses in-register decode;
    /// others use LUT decode with prefetching.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int DotProductRow(int row, ReadOnlySpan<int> input)
    {
        if ((uint)row >= (uint)_rows)
            ThrowRowOutOfRange(row);
        if (input.Length < _cols)
            ThrowInputTooShort(input.Length, _cols);

        byte* ptr = _data;
        if (ptr == null)
            ThrowObjectDisposed();

        byte* rowPtr = ptr + (long)row * _rowStrideBytes;
        int fullBytes = _cols >> 2;
        int tailWeights = _cols & 3;

        ref readonly int inputRef = ref MemoryMarshal.GetReference(input);

        int sum;
        int col;

        // Dispatch: SVE2 > SVE > AVX-512 > AVX2 > NEON > Sparse skip > Scalar
#if NET9_0_OR_GREATER
#pragma warning disable SYSLIB5003
        if (Sve2.IsSupported && fullBytes >= (Vector<int>.Count >> 2))
        {
            sum = DotProductSve2(rowPtr, in inputRef, fullBytes, out col);
        }
        else if (Sve.IsSupported && fullBytes >= (Vector<int>.Count >> 2))
        {
            sum = DotProductSve(rowPtr, in inputRef, fullBytes, out col);
        }
        else
#pragma warning restore SYSLIB5003
#endif
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

#if NET9_0_OR_GREATER
#pragma warning disable SYSLIB5003
    /// <summary>
    /// ARM SVE path: scalable vector width with LUT decode.
    /// Processes Vector&lt;int&gt;.Count weights per iteration (128–2048 bits).
    /// Uses Sve.MultiplyAdd (fused MLA) and Sve.AddAcross (SADDV) for reduction.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int DotProductSve(
        byte* rowPtr,
        in int inputRef,
        int fullBytes,
        out int col)
    {
        int vecCount = Vector<int>.Count;
        int bytesPerVec = vecCount >> 2;

        Vector<int> acc = Vector<int>.Zero;
        col = 0;
        int b = 0;

        ref int lutRef = ref MemoryMarshal.GetArrayDataReference(s_decodeLut);
        int* wBuf = stackalloc int[vecCount];

        for (; b + bytesPerVec <= fullBytes; b += bytesPerVec, col += vecCount)
        {
            // Zero-skip: check packed bytes (JIT constant-folds bytesPerVec branches)
            if (bytesPerVec == 1)
            {
                if (rowPtr[b] == 0) continue;
            }
            else if (bytesPerVec == 2)
            {
                if (*(ushort*)(rowPtr + b) == 0) continue;
            }
            else if (bytesPerVec == 4)
            {
                if (*(uint*)(rowPtr + b) == 0) continue;
            }
            else if (bytesPerVec == 8)
            {
                if (*(ulong*)(rowPtr + b) == 0) continue;
            }

            // LUT decode packed bytes into stack buffer
            for (int k = 0; k < bytesPerVec; k++)
            {
                int lutBase = rowPtr[b + k] << 2;
                wBuf[k * 4]     = Unsafe.Add(ref lutRef, lutBase);
                wBuf[k * 4 + 1] = Unsafe.Add(ref lutRef, lutBase + 1);
                wBuf[k * 4 + 2] = Unsafe.Add(ref lutRef, lutBase + 2);
                wBuf[k * 4 + 3] = Unsafe.Add(ref lutRef, lutBase + 3);
            }

            var weights = new Vector<int>(new ReadOnlySpan<int>(wBuf, vecCount));
            var inputs = new Vector<int>(
                MemoryMarshal.CreateReadOnlySpan(
                    ref Unsafe.Add(ref Unsafe.AsRef(in inputRef), col), vecCount));

            // Fused multiply-accumulate (MLA instruction)
            acc = Sve.MultiplyAdd(acc, weights, inputs);
        }

        // SVE horizontal reduction (SADDV — single instruction)
        int sum = (int)Sve.AddAcross(acc).GetElement(0);

        // Scalar remainder
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
    /// ARM SVE2 path: in-register ternary decode (no LUT memory access).
    /// Uses GatherVectorByteZeroExtend to replicate packed bytes across lanes,
    /// then per-lane shift/mask for branchless 2-bit decode.
    /// Eliminates LUT cache dependency — purely compute-bound.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int DotProductSve2(
        byte* rowPtr,
        in int inputRef,
        int fullBytes,
        out int col)
    {
        if (!s_svePatternsReady) InitSveDecodePatterns();

        int vecCount = Vector<int>.Count;
        int bytesPerVec = vecCount >> 2;

        Vector<int> acc = Vector<int>.Zero;
        col = 0;
        int b = 0;

        var trueMask = Sve.CreateTrueMaskInt32(SveMaskPattern.All);
        var byteIdx = s_sveByteIdxVec;
        var shifts = s_sveShiftVec;
        var mask3 = new Vector<uint>(3);

        for (; b + bytesPerVec <= fullBytes; b += bytesPerVec, col += vecCount)
        {
            // Zero-skip
            if (bytesPerVec == 1)
            {
                if (rowPtr[b] == 0) continue;
            }
            else if (bytesPerVec == 2)
            {
                if (*(ushort*)(rowPtr + b) == 0) continue;
            }
            else if (bytesPerVec == 4)
            {
                if (*(uint*)(rowPtr + b) == 0) continue;
            }
            else if (bytesPerVec == 8)
            {
                if (*(ulong*)(rowPtr + b) == 0) continue;
            }

            // In-register decode:
            // 1. Gather bytes with lane replication: lane[i] = rowPtr[b + i/4]
            var rawBytes = Sve.GatherVectorByteZeroExtend(trueMask, rowPtr + b, byteIdx);

            // 2. Per-lane shift to align 2-bit field: shifts = [0,2,4,6,0,2,4,6,...]
            var shifted = Sve.ShiftRightLogical(
                Unsafe.BitCast<Vector<int>, Vector<uint>>(rawBytes), shifts);

            // 3. Isolate 2-bit entry and decode: weight = (e & 1) * (1 - (e & 2))
            var entry = shifted & mask3;
            var magnitude = Unsafe.BitCast<Vector<uint>, Vector<int>>(entry & Vector<uint>.One);
            var signBit = Unsafe.BitCast<Vector<uint>, Vector<int>>(entry & new Vector<uint>(2));
            var weights = magnitude * (Vector<int>.One - signBit);

            var inputs = new Vector<int>(
                MemoryMarshal.CreateReadOnlySpan(
                    ref Unsafe.Add(ref Unsafe.AsRef(in inputRef), col), vecCount));

            // Fused multiply-accumulate
            acc = Sve.MultiplyAdd(acc, weights, inputs);
        }

        int sum = (int)Sve.AddAcross(acc).GetElement(0);

        // Scalar remainder
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
#pragma warning restore SYSLIB5003
#endif

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
        if (_data == null)
            ThrowObjectDisposed();
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
        if (_data == null) ThrowObjectDisposed();
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
        if (_data == null) ThrowObjectDisposed();
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
        if (Interlocked.Exchange(ref _disposedFlag, 1) != 0)
            return;

        byte* ptr = _data;
        _data = null;

        if (_ownsMemory && ptr != null)
            NativeMemory.Free(ptr);

        GC.SuppressFinalize(this);
    }

    ~NativeTernaryMatrix()
    {
        if (Interlocked.Exchange(ref _disposedFlag, 1) != 0)
            return;

        byte* ptr = _data;
        _data = null;

        if (_ownsMemory && ptr != null)
            NativeMemory.Free(ptr);
    }

    // ── Snapshot serialisation helpers ───────────────────────────────────

    /// <summary>
    /// Copy the raw packed data (including alignment padding) to a destination span.
    /// Returns the total number of bytes written.
    /// </summary>
    public long CopyPackedDataTo(Span<byte> destination)
    {
        if (_data == null) ThrowObjectDisposed();
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
#if NET9_0_OR_GREATER
#pragma warning disable SYSLIB5003
            && !Sve.IsSupported
#pragma warning restore SYSLIB5003
#endif
            && !Vector512.IsHardwareAccelerated
            && !Vector256.IsHardwareAccelerated
            && !AdvSimd.IsSupported)
            matrix.BuildSkipIndex();

        return matrix;
    }

    /// <summary>
    /// Decode a single packed row into ternary integer values {-1, 0, +1}.
    /// Used for embedding table lookup: the token ID is the row index, and
    /// the decoded values become the initial hidden state.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void DecodeRow(int row, Span<int> output)
    {
        if ((uint)row >= (uint)_rows)
            ThrowRowOutOfRange(row);
        if (output.Length < _cols)
            ThrowInputTooShort(output.Length, _cols);

        byte* ptr = _data;
        if (ptr == null)
            ThrowObjectDisposed();

        byte* rowPtr = ptr + (long)row * _rowStrideBytes;
        int fullBytes = _cols >> 2;
        int tailWeights = _cols & 3;
        int col = 0;

        ref int lutRef = ref MemoryMarshal.GetArrayDataReference(s_decodeLut);

        for (int b = 0; b < fullBytes; b++, col += 4)
        {
            int lutBase = rowPtr[b] << 2;
            output[col]     = Unsafe.Add(ref lutRef, lutBase);
            output[col + 1] = Unsafe.Add(ref lutRef, lutBase + 1);
            output[col + 2] = Unsafe.Add(ref lutRef, lutBase + 2);
            output[col + 3] = Unsafe.Add(ref lutRef, lutBase + 3);
        }

        if (tailWeights > 0)
        {
            int lutBase = rowPtr[fullBytes] << 2;
            for (int k = 0; k < tailWeights; k++)
                output[col + k] = Unsafe.Add(ref lutRef, lutBase + k);
        }
    }

    private static void ThrowRowOutOfRange(int row) =>
        throw new ArgumentOutOfRangeException(nameof(row), $"Row index {row} out of range");

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowInputTooShort(int actual, int required) =>
        throw new ArgumentException($"Input length {actual} < required cols {required}");

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void ThrowObjectDisposed() =>
        throw new ObjectDisposedException(nameof(NativeTernaryMatrix));
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
