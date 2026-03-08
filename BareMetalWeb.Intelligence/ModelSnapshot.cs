using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Text;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Binary snapshot format for pruned + packed BitNet models.
/// Stores the final inference state so models can be loaded in milliseconds
/// without recomputing pruning or compression.
///
/// Layout:
///   [Header]           — magic, version, model metadata
///   [MatrixDescriptors] — rows, cols, stride, offset, length per matrix
///   [TokenTable]        — length-prefixed UTF-8 strings
///   [PackedData]        — raw packed bytes for all matrices back-to-back
///
/// All integers are little-endian. Offsets are relative to file start.
/// </summary>
public static class ModelSnapshot
{
    private static ReadOnlySpan<byte> Magic => "BMWM"u8;
    private const int FormatVersion = 1;

    // Header: magic(4) + version(4) + hiddenDim(4) + numLayers(4) +
    //         numHeads(4) + vocabSize(4) + activeVocab(4) + maxSeqLen(4) +
    //         matrixCount(4) + tokenCount(4) + tokenTableOffset(8) +
    //         packedDataOffset(8) = 56 bytes
    private const int HeaderSize = 56;

    // Per-matrix descriptor: rows(4) + cols(4) + rowStride(4) + dataOffset(8) + dataLength(8) = 28 bytes
    private const int DescriptorSize = 28;

    // Matrix ordering: attn[0], ffn[0], attn[1], ffn[1], ..., embeddings, outputHead
    // So matrixCount = numLayers * 2 + 2

    /// <summary>
    /// Save the current engine state to a binary snapshot file.
    /// </summary>
    public static void Save(
        string path,
        BitNetModelConfig config,
        int activeVocab,
        NativeTernaryMatrix[] compressedAttn,
        NativeTernaryMatrix[] compressedFfn,
        NativeTernaryMatrix compressedEmbeddings,
        NativeTernaryMatrix compressedOutputHead,
        IReadOnlyList<string>? tokenTable = null)
    {
        int layerCount = compressedAttn.Length;
        int matrixCount = layerCount * 2 + 2;

        // Gather all matrices in order
        var matrices = new NativeTernaryMatrix[matrixCount];
        for (int i = 0; i < layerCount; i++)
        {
            matrices[i * 2] = compressedAttn[i];
            matrices[i * 2 + 1] = compressedFfn[i];
        }
        matrices[matrixCount - 2] = compressedEmbeddings;
        matrices[matrixCount - 1] = compressedOutputHead;

        // Encode token table
        byte[] tokenTableBytes = EncodeTokenTable(tokenTable);
        int tokenCount = tokenTable?.Count ?? 0;

        // Calculate offsets
        long descriptorsOffset = HeaderSize;
        long tokenTableOffset = descriptorsOffset + (long)matrixCount * DescriptorSize;
        long packedDataOffset = tokenTableOffset + tokenTableBytes.Length;

        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write,
            FileShare.None, 65536, FileOptions.SequentialScan);
        using var bw = new BinaryWriter(fs, Encoding.UTF8, leaveOpen: false);

        // ── Header ──────────────────────────────────────────────────
        bw.Write(Magic);
        bw.Write(FormatVersion);
        bw.Write(config.HiddenDim);
        bw.Write(layerCount);
        bw.Write(config.NumHeads);
        bw.Write(config.VocabSize);
        bw.Write(activeVocab);
        bw.Write(config.MaxSeqLen);
        bw.Write(matrixCount);
        bw.Write(tokenCount);
        bw.Write(tokenTableOffset);
        bw.Write(packedDataOffset);

        // ── Matrix descriptors ──────────────────────────────────────
        long dataOffset = packedDataOffset;
        for (int i = 0; i < matrixCount; i++)
        {
            var m = matrices[i];
            long dataLen = m.TotalPackedDataBytes;
            bw.Write(m.Rows);
            bw.Write(m.Cols);
            bw.Write(m.RowStrideBytes);
            bw.Write(dataOffset);
            bw.Write(dataLen);
            dataOffset += dataLen;
        }

        // ── Token table ─────────────────────────────────────────────
        bw.Write(tokenTableBytes);

        // ── Packed matrix data ──────────────────────────────────────
        var buf = new byte[65536];
        for (int i = 0; i < matrixCount; i++)
        {
            var m = matrices[i];
            long remaining = m.TotalPackedDataBytes;
            // Write entire matrix packed data
            if (remaining <= buf.Length)
            {
                m.CopyPackedDataTo(buf.AsSpan(0, (int)remaining));
                bw.Write(buf, 0, (int)remaining);
            }
            else
            {
                // For very large matrices, write in chunks
                var fullBuf = new byte[remaining];
                m.CopyPackedDataTo(fullBuf);
                bw.Write(fullBuf);
            }
        }

        bw.Flush();
    }

    /// <summary>
    /// Load a binary snapshot from disk. Reconstructs NativeTernaryMatrix
    /// instances directly from packed data — no intermediate tensors needed.
    /// </summary>
    public static SnapshotData Load(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.Read, 65536, FileOptions.SequentialScan);
        using var br = new BinaryReader(fs, Encoding.UTF8, leaveOpen: false);

        // ── Header ──────────────────────────────────────────────────
        Span<byte> magic = stackalloc byte[4];
        if (br.Read(magic) != 4 || !magic.SequenceEqual(Magic))
            throw new InvalidDataException("Not a BMWM snapshot file");

        int version = br.ReadInt32();
        if (version != FormatVersion)
            throw new InvalidDataException(
                $"Unsupported snapshot version {version} (expected {FormatVersion})");

        int hiddenDim = br.ReadInt32();
        int layerCount = br.ReadInt32();
        int numHeads = br.ReadInt32();
        int vocabSize = br.ReadInt32();
        int activeVocab = br.ReadInt32();
        int maxSeqLen = br.ReadInt32();
        int matrixCount = br.ReadInt32();
        int tokenCount = br.ReadInt32();
        long tokenTableOffset = br.ReadInt64();
        long packedDataOffset = br.ReadInt64();

        if (matrixCount != layerCount * 2 + 2)
            throw new InvalidDataException(
                $"Matrix count {matrixCount} != expected {layerCount * 2 + 2}");

        // ── Matrix descriptors ──────────────────────────────────────
        var descriptors = new (int Rows, int Cols, int Stride, long Offset, long Length)[matrixCount];
        for (int i = 0; i < matrixCount; i++)
        {
            descriptors[i] = (
                br.ReadInt32(),  // rows
                br.ReadInt32(),  // cols
                br.ReadInt32(),  // rowStride
                br.ReadInt64(),  // dataOffset
                br.ReadInt64()); // dataLength
        }

        // ── Token table ─────────────────────────────────────────────
        fs.Seek(tokenTableOffset, SeekOrigin.Begin);
        string[] tokens = DecodeTokenTable(br, tokenCount);

        // ── Load matrices ───────────────────────────────────────────
        var matrices = new NativeTernaryMatrix[matrixCount];
        for (int i = 0; i < matrixCount; i++)
        {
            var (rows, cols, _, offset, length) = descriptors[i];
            fs.Seek(offset, SeekOrigin.Begin);

            var packedData = new byte[length];
            int totalRead = 0;
            while (totalRead < length)
            {
                int read = br.Read(packedData, totalRead, (int)(length - totalRead));
                if (read == 0) throw new EndOfStreamException();
                totalRead += read;
            }

            matrices[i] = NativeTernaryMatrix.FromPackedData(packedData, rows, cols);
        }

        // Unpack into named arrays
        var attn = new NativeTernaryMatrix[layerCount];
        var ffn = new NativeTernaryMatrix[layerCount];
        for (int i = 0; i < layerCount; i++)
        {
            attn[i] = matrices[i * 2];
            ffn[i] = matrices[i * 2 + 1];
        }

        var config = new BitNetModelConfig(hiddenDim, layerCount, numHeads, vocabSize, maxSeqLen);

        return new SnapshotData(
            Config: config,
            ActiveVocab: activeVocab,
            Attn: attn,
            Ffn: ffn,
            Embeddings: matrices[matrixCount - 2],
            OutputHead: matrices[matrixCount - 1],
            Tokens: tokens);
    }

    /// <summary>
    /// Load a snapshot using memory-mapped I/O. Matrix data is mapped
    /// directly from disk — avoids copying large packed arrays into
    /// managed memory. Best for large models on systems with limited RAM.
    /// </summary>
    public static unsafe SnapshotData LoadMapped(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.Read);
        long fileSize = fs.Length;

        using var mmf = MemoryMappedFile.CreateFromFile(
            fs, null, 0, MemoryMappedFileAccess.Read, HandleInheritability.None, true);
        using var accessor = mmf.CreateViewAccessor(0, fileSize, MemoryMappedFileAccess.Read);

        byte* basePtr = null;
        accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref basePtr);

        try
        {
            if (fileSize < HeaderSize)
                throw new InvalidDataException(
                    $"File too small for BMWM header ({fileSize} < {HeaderSize})");

            // ── Header ──────────────────────────────────────────────
            var headerSpan = new ReadOnlySpan<byte>(basePtr, HeaderSize);
            if (!headerSpan[..4].SequenceEqual(Magic))
                throw new InvalidDataException("Not a BMWM snapshot file");

            int version = MemoryMarshal.Read<int>(headerSpan[4..]);
            if (version != FormatVersion)
                throw new InvalidDataException(
                    $"Unsupported version {version}");

            int hiddenDim = MemoryMarshal.Read<int>(headerSpan[8..]);
            int layerCount = MemoryMarshal.Read<int>(headerSpan[12..]);
            int numHeads = MemoryMarshal.Read<int>(headerSpan[16..]);
            int vocabSize = MemoryMarshal.Read<int>(headerSpan[20..]);
            int activeVocab = MemoryMarshal.Read<int>(headerSpan[24..]);
            int maxSeqLen = MemoryMarshal.Read<int>(headerSpan[28..]);
            int matrixCount = MemoryMarshal.Read<int>(headerSpan[32..]);
            int tokenCount = MemoryMarshal.Read<int>(headerSpan[36..]);
            long tokenTableOffset = MemoryMarshal.Read<long>(headerSpan[40..]);

            if (matrixCount != layerCount * 2 + 2)
                throw new InvalidDataException("Matrix count mismatch");

            // ── Descriptors ─────────────────────────────────────────
            var descSpan = new ReadOnlySpan<byte>(
                basePtr + HeaderSize, matrixCount * DescriptorSize);

            var descriptors = new (int Rows, int Cols, int Stride, long Offset, long Length)[matrixCount];
            for (int i = 0; i < matrixCount; i++)
            {
                int off = i * DescriptorSize;
                descriptors[i] = (
                    MemoryMarshal.Read<int>(descSpan[off..]),
                    MemoryMarshal.Read<int>(descSpan[(off + 4)..]),
                    MemoryMarshal.Read<int>(descSpan[(off + 8)..]),
                    MemoryMarshal.Read<long>(descSpan[(off + 12)..]),
                    MemoryMarshal.Read<long>(descSpan[(off + 20)..])
                );
            }

            // ── Token table ─────────────────────────────────────────
            string[] tokens;
            using (var tokenStream = new UnmanagedMemoryStream(
                basePtr + tokenTableOffset,
                descriptors[0].Offset - tokenTableOffset))
            using (var tbr = new BinaryReader(tokenStream, Encoding.UTF8))
            {
                tokens = DecodeTokenTable(tbr, tokenCount);
            }

            // ── Matrices from mapped memory ─────────────────────────
            var matrices = new NativeTernaryMatrix[matrixCount];
            for (int i = 0; i < matrixCount; i++)
            {
                var (rows, cols, _, offset, length) = descriptors[i];
                var dataSpan = new ReadOnlySpan<byte>(
                    basePtr + offset, (int)length);
                matrices[i] = NativeTernaryMatrix.FromPackedData(dataSpan, rows, cols);
            }

            var attn = new NativeTernaryMatrix[layerCount];
            var ffn = new NativeTernaryMatrix[layerCount];
            for (int i = 0; i < layerCount; i++)
            {
                attn[i] = matrices[i * 2];
                ffn[i] = matrices[i * 2 + 1];
            }

            var config = new BitNetModelConfig(
                hiddenDim, layerCount, numHeads, vocabSize, maxSeqLen);

            return new SnapshotData(config, activeVocab, attn, ffn,
                matrices[matrixCount - 2], matrices[matrixCount - 1], tokens);
        }
        finally
        {
            accessor.SafeMemoryMappedViewHandle.ReleasePointer();
        }
    }

    /// <summary>
    /// Load a snapshot using persistent memory-mapping. Matrices reference the
    /// mapped file directly — zero copy, OS demand-pages data on first access.
    /// Layers never touched during inference (e.g. skipped by early exit) never
    /// consume physical memory.
    /// Returns a <see cref="LazySnapshot"/> that owns the mmap lifetime.
    /// </summary>
    public static unsafe LazySnapshot LoadLazy(string path)
    {
        var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        MemoryMappedFile? mmf = null;
        MemoryMappedViewAccessor? accessor = null;
        byte* basePtr = null;

        try
        {
            if (fs.Length < HeaderSize)
                throw new InvalidDataException(
                    $"File too small for BMWM header ({fs.Length} < {HeaderSize})");

            mmf = MemoryMappedFile.CreateFromFile(
                fs, null, 0, MemoryMappedFileAccess.Read, HandleInheritability.None, true);
            accessor = mmf.CreateViewAccessor(0, fs.Length, MemoryMappedFileAccess.Read);

            accessor.SafeMemoryMappedViewHandle.AcquirePointer(ref basePtr);

            // ── Header ──────────────────────────────────────────────────
            var headerSpan = new ReadOnlySpan<byte>(basePtr, HeaderSize);
            if (!headerSpan[..4].SequenceEqual(Magic))
                throw new InvalidDataException("Not a BMWM snapshot file");

            int version = MemoryMarshal.Read<int>(headerSpan[4..]);
            if (version != FormatVersion)
                throw new InvalidDataException($"Unsupported version {version}");

            int hiddenDim = MemoryMarshal.Read<int>(headerSpan[8..]);
            int layerCount = MemoryMarshal.Read<int>(headerSpan[12..]);
            int numHeads = MemoryMarshal.Read<int>(headerSpan[16..]);
            int vocabSize = MemoryMarshal.Read<int>(headerSpan[20..]);
            int activeVocab = MemoryMarshal.Read<int>(headerSpan[24..]);
            int maxSeqLen = MemoryMarshal.Read<int>(headerSpan[28..]);
            int matrixCount = MemoryMarshal.Read<int>(headerSpan[32..]);
            int tokenCount = MemoryMarshal.Read<int>(headerSpan[36..]);
            long tokenTableOffset = MemoryMarshal.Read<long>(headerSpan[40..]);

            if (matrixCount != layerCount * 2 + 2)
                throw new InvalidDataException("Matrix count mismatch");

            long minSize = HeaderSize + (long)matrixCount * DescriptorSize;
            if (fs.Length < minSize)
                throw new InvalidDataException(
                    $"File too small for descriptors ({fs.Length} < {minSize})");

            // ── Descriptors ─────────────────────────────────────────────
            var descSpan = new ReadOnlySpan<byte>(
                basePtr + HeaderSize, matrixCount * DescriptorSize);

            var descriptors = new (int Rows, int Cols, int Stride, long Offset, long Length)[matrixCount];
            for (int i = 0; i < matrixCount; i++)
            {
                int off = i * DescriptorSize;
                descriptors[i] = (
                    MemoryMarshal.Read<int>(descSpan[off..]),
                    MemoryMarshal.Read<int>(descSpan[(off + 4)..]),
                    MemoryMarshal.Read<int>(descSpan[(off + 8)..]),
                    MemoryMarshal.Read<long>(descSpan[(off + 12)..]),
                    MemoryMarshal.Read<long>(descSpan[(off + 20)..])
                );
            }

            // ── Token table ─────────────────────────────────────────────
            string[] tokens;
            using (var tokenStream = new UnmanagedMemoryStream(
                basePtr + tokenTableOffset,
                descriptors[0].Offset - tokenTableOffset))
            using (var tbr = new BinaryReader(tokenStream, Encoding.UTF8))
            {
                tokens = DecodeTokenTable(tbr, tokenCount);
            }

            // ── Zero-copy matrices from mapped memory ───────────────────
            var attn = new NativeTernaryMatrix[layerCount];
            var ffn = new NativeTernaryMatrix[layerCount];
            for (int i = 0; i < layerCount; i++)
            {
                var (rows, cols, _, offset, _) = descriptors[i * 2];
                attn[i] = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);

                (rows, cols, _, offset, _) = descriptors[i * 2 + 1];
                ffn[i] = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);
            }

            var (eRows, eCols, _, eOff, _) = descriptors[matrixCount - 2];
            var embeddings = NativeTernaryMatrix.FromMappedMemory(basePtr + eOff, eRows, eCols);

            var (oRows, oCols, _, oOff, _) = descriptors[matrixCount - 1];
            var outputHead = NativeTernaryMatrix.FromMappedMemory(basePtr + oOff, oRows, oCols);

            var config = new BitNetModelConfig(hiddenDim, layerCount, numHeads, vocabSize, maxSeqLen);
            var data = new SnapshotData(config, activeVocab, attn, ffn, embeddings, outputHead, tokens);

            return new LazySnapshot(fs, mmf, accessor, basePtr, data);
        }
        catch
        {
            // Clean up in reverse order to prevent handle leaks
            if (basePtr != null)
                accessor?.SafeMemoryMappedViewHandle.ReleasePointer();
            accessor?.Dispose();
            mmf?.Dispose();
            fs.Dispose();
            throw;
        }
    }

    // ── Token table encoding ────────────────────────────────────────────

    private static byte[] EncodeTokenTable(IReadOnlyList<string>? tokens)
    {
        if (tokens is null || tokens.Count == 0)
            return [];

        using var ms = new MemoryStream();
        using var bw = new BinaryWriter(ms, Encoding.UTF8);
        for (int i = 0; i < tokens.Count; i++)
            bw.Write(tokens[i] ?? string.Empty); // length-prefixed UTF-8
        bw.Flush();
        return ms.ToArray();
    }

    private static string[] DecodeTokenTable(BinaryReader br, int count)
    {
        if (count == 0) return [];
        var tokens = new string[count];
        for (int i = 0; i < count; i++)
            tokens[i] = br.ReadString();
        return tokens;
    }
}

/// <summary>
/// Data loaded from a binary model snapshot.
/// </summary>
public sealed record SnapshotData(
    BitNetModelConfig Config,
    int ActiveVocab,
    NativeTernaryMatrix[] Attn,
    NativeTernaryMatrix[] Ffn,
    NativeTernaryMatrix Embeddings,
    NativeTernaryMatrix OutputHead,
    string[] Tokens) : IDisposable
{
    public void Dispose()
    {
        foreach (var m in Attn) m?.Dispose();
        foreach (var m in Ffn) m?.Dispose();
        Embeddings?.Dispose();
        OutputHead?.Dispose();
    }
}

/// <summary>
/// Holds a memory-mapped snapshot file open so matrices can reference
/// mapped pages directly. Dispose releases the mapping (and invalidates
/// all matrices created from it).
/// </summary>
public sealed unsafe class LazySnapshot : IDisposable
{
    private readonly FileStream _fs;
    private readonly MemoryMappedFile _mmf;
    private readonly MemoryMappedViewAccessor _accessor;
    private byte* _basePtr;
    private int _disposedFlag;

    /// <summary>Snapshot data with zero-copy matrices pointing at mapped memory.</summary>
    public SnapshotData Data { get; }

    internal LazySnapshot(
        FileStream fs,
        MemoryMappedFile mmf,
        MemoryMappedViewAccessor accessor,
        byte* basePtr,
        SnapshotData data)
    {
        _fs = fs;
        _mmf = mmf;
        _accessor = accessor;
        _basePtr = basePtr;
        Data = data;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposedFlag, 1) != 0)
            return;

        // Matrices have _ownsMemory=false — dispose just nulls pointers
        Data.Dispose();

        byte* ptr = _basePtr;
        _basePtr = null;

        if (ptr != null)
            _accessor.SafeMemoryMappedViewHandle.ReleasePointer();

        _accessor.Dispose();
        _mmf.Dispose();
        _fs.Dispose();
    }
}
