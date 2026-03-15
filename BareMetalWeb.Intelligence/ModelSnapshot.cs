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
    private const int FormatVersion = 5;

    // Header: magic(4) + version(4) + hiddenDim(4) + numLayers(4) +
    //         numHeads(4) + vocabSize(4) + activeVocab(4) + maxSeqLen(4) +
    //         matrixCount(4) + tokenCount(4) + tokenTableOffset(8) +
    //         packedDataOffset(8) + ffnDim(4) + reserved(4) = 64 bytes
    private const int HeaderSize = 64;

    // Per-matrix descriptor: rows(4) + cols(4) + rowStride(4) + dataOffset(8) + dataLength(8) = 28 bytes
    private const int DescriptorSize = 28;

    // Matrix ordering per layer: Wq, Wk, Wv, Wo, FfnGate, FfnUp, FfnDown
    // Total: numLayers * 7 + 2 (embeddings + outputHead)

    /// <summary>
    /// Save the current engine state to a binary snapshot file.
    /// </summary>
    public static void Save(
        string path,
        BitNetModelConfig config,
        int activeVocab,
        NativeTernaryMatrix[] wq,
        NativeTernaryMatrix[] wk,
        NativeTernaryMatrix[] wv,
        NativeTernaryMatrix[] wo,
        NativeTernaryMatrix[] ffnGate,
        NativeTernaryMatrix[] ffnUp,
        NativeTernaryMatrix[] ffnDown,
        NativeInt8Matrix compressedEmbeddings,
        NativeInt8Matrix compressedOutputHead,
        IReadOnlyList<string>? tokenTable = null,
        IReadOnlyList<string>? bpeMerges = null,
        float[][]? weightScales = null,
        float[][]? inputNorm = null,
        float[][]? attnSubNorm = null,
        float[][]? postAttnNorm = null,
        float[][]? ffnSubNorm = null,
        float[]? finalNorm = null)
    {
        int layerCount = wq.Length;
        int ternaryCount = layerCount * 7;
        int matrixCount = ternaryCount + 2;

        // Encode token table and BPE merges
        byte[] tokenTableBytes = EncodeTokenTable(tokenTable);
        byte[] mergeTableBytes = EncodeTokenTable(bpeMerges);
        int tokenCount = tokenTable?.Count ?? 0;
        int mergeCount = bpeMerges?.Count ?? 0;

        // Calculate offsets
        long descriptorsOffset = HeaderSize;
        long tokenTableOffset = descriptorsOffset + (long)matrixCount * DescriptorSize;
        long packedDataOffset = tokenTableOffset + tokenTableBytes.Length + mergeTableBytes.Length;

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
        bw.Write(config.FfnDim);
        bw.Write(mergeCount);

        // ── Matrix descriptors (ternary layers, then int8 embeddings) ──
        long dataOffset = packedDataOffset;

        // Ternary layer matrices
        var ternaryMatrices = new NativeTernaryMatrix[ternaryCount];
        for (int i = 0; i < layerCount; i++)
        {
            ternaryMatrices[i * 7]     = wq[i];
            ternaryMatrices[i * 7 + 1] = wk[i];
            ternaryMatrices[i * 7 + 2] = wv[i];
            ternaryMatrices[i * 7 + 3] = wo[i];
            ternaryMatrices[i * 7 + 4] = ffnGate[i];
            ternaryMatrices[i * 7 + 5] = ffnUp[i];
            ternaryMatrices[i * 7 + 6] = ffnDown[i];
        }
        for (int i = 0; i < ternaryCount; i++)
        {
            var m = ternaryMatrices[i];
            long dataLen = m.TotalPackedDataBytes;
            bw.Write(m.Rows);
            bw.Write(m.Cols);
            bw.Write(m.RowStrideBytes);
            bw.Write(dataOffset);
            bw.Write(dataLen);
            dataOffset += dataLen;
        }

        // Int8 embedding + output head descriptors
        var int8Matrices = new[] { compressedEmbeddings, compressedOutputHead };
        for (int i = 0; i < 2; i++)
        {
            var m = int8Matrices[i];
            long dataLen = m.TotalPackedDataBytes;
            bw.Write(m.Rows);
            bw.Write(m.Cols);
            bw.Write(m.RowStrideBytes);
            bw.Write(dataOffset);
            bw.Write(dataLen);
            dataOffset += dataLen;
        }

        // ── Token table + BPE merges ────────────────────────────────
        bw.Write(tokenTableBytes);
        bw.Write(mergeTableBytes);

        // ── Packed matrix data ──────────────────────────────────────
        var buf = new byte[65536];

        // Write ternary matrices (dispose after each to free native memory)
        for (int i = 0; i < ternaryCount; i++)
        {
            var m = ternaryMatrices[i];
            long remaining = m.TotalPackedDataBytes;
            long offset = 0;
            while (remaining > 0)
            {
                int chunk = (int)Math.Min(remaining, buf.Length);
                m.CopyPackedDataChunk(offset, buf.AsSpan(0, chunk));
                bw.Write(buf, 0, chunk);
                offset += chunk;
                remaining -= chunk;
            }
            m.Dispose();
        }

        // Write int8 matrices (caller disposes)
        for (int i = 0; i < 2; i++)
        {
            var m = int8Matrices[i];
            long remaining = m.TotalPackedDataBytes;
            long offset = 0;
            while (remaining > 0)
            {
                int chunk = (int)Math.Min(remaining, buf.Length);
                m.CopyPackedDataChunk(offset, buf.AsSpan(0, chunk));
                bw.Write(buf, 0, chunk);
                offset += chunk;
                remaining -= chunk;
            }
        }

        bw.Flush();

        // ── v5 Norms/Scales appendix ────────────────────────────────
        // Written after packed data. Presence detected by "SNRM" marker.
        bool hasNorms = weightScales != null || inputNorm != null || finalNorm != null;
        if (hasNorms)
        {
            bw.Write("SNRM"u8);
            int layerCount2 = wq.Length;
            bw.Write(layerCount2);
            bw.Write(config.HiddenDim);
            bw.Write(config.EffectiveFfnDim);

            // Weight scales: [numLayers][7] as float32
            for (int L = 0; L < layerCount2; L++)
            {
                if (weightScales != null && L < weightScales.Length)
                    for (int m = 0; m < 7; m++)
                        bw.Write(m < weightScales[L].Length ? weightScales[L][m] : 1f);
                else
                    for (int m = 0; m < 7; m++)
                        bw.Write(1f);
            }

            // Final norm: float32[hiddenDim]
            WriteFloatArray(bw, finalNorm, config.HiddenDim);

            // Per-layer norms: inputNorm, attnSubNorm, postAttnNorm (each [hiddenDim])
            //                  ffnSubNorm ([ffnDim])
            for (int L = 0; L < layerCount2; L++)
            {
                WriteFloatArray(bw, inputNorm?[L], config.HiddenDim);
                WriteFloatArray(bw, attnSubNorm?[L], config.HiddenDim);
                WriteFloatArray(bw, postAttnNorm?[L], config.HiddenDim);
                WriteFloatArray(bw, ffnSubNorm?[L], config.EffectiveFfnDim);
            }

            bw.Flush();
        }
    }

    private static void WriteFloatArray(BinaryWriter bw, float[]? arr, int expectedLen)
    {
        for (int i = 0; i < expectedLen; i++)
            bw.Write(arr != null && i < arr.Length ? arr[i] : 1f);
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
        if (version < 1 || version > FormatVersion)
            throw new InvalidDataException(
                $"Unsupported snapshot version {version} (expected 1–{FormatVersion})");

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

        int ffnDim = 0;
        int mergeCount = 0;
        if (version >= 3)
        {
            ffnDim = br.ReadInt32();
            mergeCount = br.ReadInt32(); // BPE merge count (was reserved)
        }

        // v1: 2 matrices per layer (combined attn + ffn) + 2 (embeddings + outputHead)
        // v2: 5 matrices per layer (Wq, Wk, Wv, Wo, Ffn) + 2
        // v3: 7 matrices per layer (Wq, Wk, Wv, Wo, FfnGate, FfnUp, FfnDown) + 2
        bool isV1 = matrixCount == layerCount * 2 + 2;
        bool isV2 = matrixCount == layerCount * 5 + 2;
        bool isV3 = matrixCount == layerCount * 7 + 2;
        if (!isV1 && !isV2 && !isV3)
            throw new InvalidDataException(
                $"Matrix count {matrixCount} doesn't match layer count {layerCount}");

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

        // ── Token table + BPE merges ────────────────────────────────
        fs.Seek(tokenTableOffset, SeekOrigin.Begin);
        string[] tokens = DecodeTokenTable(br, tokenCount);
        string[] merges = DecodeTokenTable(br, mergeCount);

        // ── Load matrices ───────────────────────────────────────────
        int ternaryCount = matrixCount - 2;
        var ternaryMatrices = new NativeTernaryMatrix[ternaryCount];
        for (int i = 0; i < ternaryCount; i++)
        {
            var (rows, cols, _, offset, length) = descriptors[i];
            fs.Seek(offset, SeekOrigin.Begin);
            var packedData = ReadExactBytes(br, length);
            ternaryMatrices[i] = NativeTernaryMatrix.FromPackedData(packedData, rows, cols);
        }

        // Last 2 matrices: int8 (v4+) or ternary (v3 and below)
        NativeInt8Matrix embMatrix, ohMatrix;
        if (version >= 4)
        {
            var (r0, c0, _, o0, l0) = descriptors[ternaryCount];
            fs.Seek(o0, SeekOrigin.Begin);
            embMatrix = NativeInt8Matrix.FromPackedData(ReadExactBytes(br, l0), r0, c0);

            var (r1, c1, _, o1, l1) = descriptors[ternaryCount + 1];
            fs.Seek(o1, SeekOrigin.Begin);
            ohMatrix = NativeInt8Matrix.FromPackedData(ReadExactBytes(br, l1), r1, c1);
        }
        else
        {
            // Legacy v1-v3: embeddings stored as ternary — load and wrap
            var (r0, c0, _, o0, l0) = descriptors[ternaryCount];
            fs.Seek(o0, SeekOrigin.Begin);
            embMatrix = UpcastTernaryToInt8(ReadExactBytes(br, l0), r0, c0);

            var (r1, c1, _, o1, l1) = descriptors[ternaryCount + 1];
            fs.Seek(o1, SeekOrigin.Begin);
            ohMatrix = UpcastTernaryToInt8(ReadExactBytes(br, l1), r1, c1);
        }

        // Unpack into named arrays
        var wq  = new NativeTernaryMatrix[layerCount];
        var wk  = new NativeTernaryMatrix[layerCount];
        var wv  = new NativeTernaryMatrix[layerCount];
        var wo  = new NativeTernaryMatrix[layerCount];
        var ffnGate = new NativeTernaryMatrix[layerCount];
        var ffnUp   = new NativeTernaryMatrix[layerCount];
        var ffnDown = new NativeTernaryMatrix[layerCount];

        if (isV1)
        {
            for (int i = 0; i < layerCount; i++)
            {
                var attn = ternaryMatrices[i * 2];
                wq[i] = attn; wk[i] = attn; wv[i] = attn; wo[i] = attn;
                ffnGate[i] = ternaryMatrices[i * 2 + 1];
                ffnUp[i]   = ternaryMatrices[i * 2 + 1];
                ffnDown[i] = ternaryMatrices[i * 2 + 1];
            }
        }
        else if (isV2)
        {
            for (int i = 0; i < layerCount; i++)
            {
                wq[i] = ternaryMatrices[i * 5];
                wk[i] = ternaryMatrices[i * 5 + 1];
                wv[i] = ternaryMatrices[i * 5 + 2];
                wo[i] = ternaryMatrices[i * 5 + 3];
                ffnGate[i] = ternaryMatrices[i * 5 + 4];
                ffnUp[i]   = ternaryMatrices[i * 5 + 4];
                ffnDown[i] = ternaryMatrices[i * 5 + 4];
            }
        }
        else
        {
            for (int i = 0; i < layerCount; i++)
            {
                wq[i]      = ternaryMatrices[i * 7];
                wk[i]      = ternaryMatrices[i * 7 + 1];
                wv[i]      = ternaryMatrices[i * 7 + 2];
                wo[i]      = ternaryMatrices[i * 7 + 3];
                ffnGate[i] = ternaryMatrices[i * 7 + 4];
                ffnUp[i]   = ternaryMatrices[i * 7 + 5];
                ffnDown[i] = ternaryMatrices[i * 7 + 6];
            }
        }

        var config = new BitNetModelConfig(hiddenDim, layerCount, numHeads, vocabSize, maxSeqLen, ffnDim);

        // ── v5 Norms/Scales appendix ────────────────────────────────
        var normsData = TryReadNormsAppendix(br, version);

        return new SnapshotData(
            Config: config,
            ActiveVocab: activeVocab,
            Wq: wq, Wk: wk, Wv: wv, Wo: wo,
            FfnGate: ffnGate, FfnUp: ffnUp, FfnDown: ffnDown,
            Embeddings: embMatrix,
            OutputHead: ohMatrix,
            Tokens: tokens,
            Merges: merges,
            WeightScales: normsData.WeightScales,
            InputNorm: normsData.InputNorm,
            AttnSubNorm: normsData.AttnSubNorm,
            PostAttnNorm: normsData.PostAttnNorm,
            FfnSubNorm: normsData.FfnSubNorm,
            FinalNorm: normsData.FinalNorm);
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
            if (version < 1 || version > FormatVersion)
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

            int mappedFfnDim = 0;
            int mappedMergeCount = 0;
            if (version >= 3)
            {
                mappedFfnDim = MemoryMarshal.Read<int>(headerSpan[56..]);
                mappedMergeCount = MemoryMarshal.Read<int>(headerSpan[60..]);
            }

            if (matrixCount != layerCount * 7 + 2 && matrixCount != layerCount * 5 + 2 && matrixCount != layerCount * 2 + 2)
                throw new InvalidDataException("Matrix count mismatch");

            bool isMappedV1 = matrixCount == layerCount * 2 + 2;
            bool isMappedV2 = matrixCount == layerCount * 5 + 2;
            // isMappedV3: matrixCount == layerCount * 7 + 2
            long descEnd = HeaderSize + (long)matrixCount * DescriptorSize;
            if (descEnd < HeaderSize || descEnd > fileSize)
                throw new InvalidDataException(
                    $"Descriptor region out of bounds (need {descEnd}, file is {fileSize})");

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

            // ── Token table + BPE merges ────────────────────────────
            // Bounds: validate tokenTableOffset and token table region
            if (tokenTableOffset < 0 || tokenTableOffset > fileSize)
                throw new InvalidDataException(
                    $"Token table offset out of bounds ({tokenTableOffset}, file is {fileSize})");
            long tokenTableEnd = descriptors[0].Offset;
            if (tokenTableEnd < tokenTableOffset || tokenTableEnd > fileSize)
                throw new InvalidDataException(
                    $"Token table region out of bounds (offset={tokenTableOffset}, end={tokenTableEnd}, file={fileSize})");

            string[] tokens;
            string[] mappedMerges;
            using (var tokenStream = new UnmanagedMemoryStream(
                basePtr + tokenTableOffset,
                tokenTableEnd - tokenTableOffset))
            using (var tbr = new BinaryReader(tokenStream, Encoding.UTF8))
            {
                tokens = DecodeTokenTable(tbr, tokenCount);
                mappedMerges = DecodeTokenTable(tbr, mappedMergeCount);
            }

            // ── Matrices from mapped memory ─────────────────────────
            int ternaryCount = matrixCount - 2;
            var matrices = new NativeTernaryMatrix[ternaryCount];
            for (int i = 0; i < ternaryCount; i++)
            {
                var (rows, cols, _, offset, length) = descriptors[i];
                if (offset < 0 || length < 0 || length > int.MaxValue ||
                    offset + length < offset || offset + length > fileSize)
                    throw new InvalidDataException(
                        $"Matrix descriptor {i} out of bounds (offset={offset}, length={length}, file={fileSize})");
                var dataSpan = new ReadOnlySpan<byte>(
                    basePtr + offset, (int)length);
                matrices[i] = NativeTernaryMatrix.FromPackedData(dataSpan, rows, cols);
            }

            NativeInt8Matrix embMatrix, ohMatrix;
            for (int i = ternaryCount; i < matrixCount; i++)
            {
                var (_, _, _, offset, length) = descriptors[i];
                if (offset < 0 || length < 0 || length > int.MaxValue ||
                    offset + length < offset || offset + length > fileSize)
                    throw new InvalidDataException(
                        $"Matrix descriptor {i} out of bounds (offset={offset}, length={length}, file={fileSize})");
            }

            {
                var (rows, cols, _, offset, length) = descriptors[ternaryCount];
                var dataSpan = new ReadOnlySpan<byte>(basePtr + offset, (int)length);
                embMatrix = version >= 4
                    ? MaterializeMappedInt8(basePtr + offset, rows, cols)
                    : UpcastTernaryToInt8(dataSpan, rows, cols);
            }

            {
                var (rows, cols, _, offset, length) = descriptors[ternaryCount + 1];
                var dataSpan = new ReadOnlySpan<byte>(basePtr + offset, (int)length);
                ohMatrix = version >= 4
                    ? MaterializeMappedInt8(basePtr + offset, rows, cols)
                    : UpcastTernaryToInt8(dataSpan, rows, cols);
            }

            var wqA  = new NativeTernaryMatrix[layerCount];
            var wkA  = new NativeTernaryMatrix[layerCount];
            var wvA  = new NativeTernaryMatrix[layerCount];
            var woA  = new NativeTernaryMatrix[layerCount];
            var ffnGateA = new NativeTernaryMatrix[layerCount];
            var ffnUpA   = new NativeTernaryMatrix[layerCount];
            var ffnDownA = new NativeTernaryMatrix[layerCount];

            if (isMappedV1)
            {
                for (int i = 0; i < layerCount; i++)
                {
                    var attn = matrices[i * 2];
                    wqA[i] = attn; wkA[i] = attn; wvA[i] = attn; woA[i] = attn;
                    ffnGateA[i] = matrices[i * 2 + 1];
                    ffnUpA[i]   = matrices[i * 2 + 1];
                    ffnDownA[i] = matrices[i * 2 + 1];
                }
            }
            else if (isMappedV2)
            {
                for (int i = 0; i < layerCount; i++)
                {
                    wqA[i]  = matrices[i * 5];
                    wkA[i]  = matrices[i * 5 + 1];
                    wvA[i]  = matrices[i * 5 + 2];
                    woA[i]  = matrices[i * 5 + 3];
                    ffnGateA[i] = matrices[i * 5 + 4];
                    ffnUpA[i]   = matrices[i * 5 + 4];
                    ffnDownA[i] = matrices[i * 5 + 4];
                }
            }
            else
            {
                for (int i = 0; i < layerCount; i++)
                {
                    wqA[i]      = matrices[i * 7];
                    wkA[i]      = matrices[i * 7 + 1];
                    wvA[i]      = matrices[i * 7 + 2];
                    woA[i]      = matrices[i * 7 + 3];
                    ffnGateA[i] = matrices[i * 7 + 4];
                    ffnUpA[i]   = matrices[i * 7 + 5];
                    ffnDownA[i] = matrices[i * 7 + 6];
                }
            }

            var config = new BitNetModelConfig(
                hiddenDim, layerCount, numHeads, vocabSize, maxSeqLen, mappedFfnDim);

            // Read norms appendix from mapped memory
            var normsData = TryReadNormsAppendixMapped(basePtr, fileSize, descriptors, matrixCount, version);

            return new SnapshotData(config, activeVocab, wqA, wkA, wvA, woA,
                ffnGateA, ffnUpA, ffnDownA,
                embMatrix, ohMatrix, tokens, mappedMerges,
                normsData.WeightScales, normsData.InputNorm, normsData.AttnSubNorm,
                normsData.PostAttnNorm, normsData.FfnSubNorm, normsData.FinalNorm);
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
            if (version < 1 || version > FormatVersion)
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

            int lazyFfnDim = 0;
            int lazyMergeCount = 0;
            if (version >= 3)
            {
                lazyFfnDim = MemoryMarshal.Read<int>(headerSpan[56..]);
                lazyMergeCount = MemoryMarshal.Read<int>(headerSpan[60..]);
            }

            if (matrixCount != layerCount * 7 + 2 && matrixCount != layerCount * 5 + 2 && matrixCount != layerCount * 2 + 2)
                throw new InvalidDataException("Matrix count mismatch");

            bool isLazyV1 = matrixCount == layerCount * 2 + 2;
            bool isLazyV2 = matrixCount == layerCount * 5 + 2;

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

            // ── Token table + BPE merges ────────────────────────────────
            // Bounds: validate tokenTableOffset and token table region
            if (tokenTableOffset < 0 || tokenTableOffset > fs.Length)
                throw new InvalidDataException(
                    $"Token table offset out of bounds ({tokenTableOffset}, file is {fs.Length})");
            long lazyTokenEnd = descriptors[0].Offset;
            if (lazyTokenEnd < tokenTableOffset || lazyTokenEnd > fs.Length)
                throw new InvalidDataException(
                    $"Token table region out of bounds (offset={tokenTableOffset}, end={lazyTokenEnd}, file={fs.Length})");

            string[] tokens;
            string[] lazyMerges;
            using (var tokenStream = new UnmanagedMemoryStream(
                basePtr + tokenTableOffset,
                lazyTokenEnd - tokenTableOffset))
            using (var tbr = new BinaryReader(tokenStream, Encoding.UTF8))
            {
                tokens = DecodeTokenTable(tbr, tokenCount);
                lazyMerges = DecodeTokenTable(tbr, lazyMergeCount);
            }

            // ── Zero-copy matrices from mapped memory ───────────────────
            // Bounds: validate all descriptor offsets/lengths against file size
            for (int i = 0; i < matrixCount; i++)
            {
                var (_, _, _, doff, dlen) = descriptors[i];
                if (doff < 0 || dlen < 0 || doff + dlen < doff || doff + dlen > fs.Length)
                    throw new InvalidDataException(
                        $"Matrix descriptor {i} out of bounds (offset={doff}, length={dlen}, file={fs.Length})");
            }

            var wqL  = new NativeTernaryMatrix[layerCount];
            var wkL  = new NativeTernaryMatrix[layerCount];
            var wvL  = new NativeTernaryMatrix[layerCount];
            var woL  = new NativeTernaryMatrix[layerCount];
            var ffnGateL = new NativeTernaryMatrix[layerCount];
            var ffnUpL   = new NativeTernaryMatrix[layerCount];
            var ffnDownL = new NativeTernaryMatrix[layerCount];

            if (isLazyV1)
            {
                for (int i = 0; i < layerCount; i++)
                {
                    var (rows, cols, _, offset, _) = descriptors[i * 2];
                    var attn = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);
                    wqL[i] = attn; wkL[i] = attn; wvL[i] = attn; woL[i] = attn;
                    (rows, cols, _, offset, _) = descriptors[i * 2 + 1];
                    var ffnM = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);
                    ffnGateL[i] = ffnM; ffnUpL[i] = ffnM; ffnDownL[i] = ffnM;
                }
            }
            else if (isLazyV2)
            {
                for (int i = 0; i < layerCount; i++)
                {
                    var (rows, cols, _, offset, _) = descriptors[i * 5];
                    wqL[i] = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);
                    (rows, cols, _, offset, _) = descriptors[i * 5 + 1];
                    wkL[i] = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);
                    (rows, cols, _, offset, _) = descriptors[i * 5 + 2];
                    wvL[i] = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);
                    (rows, cols, _, offset, _) = descriptors[i * 5 + 3];
                    woL[i] = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);
                    (rows, cols, _, offset, _) = descriptors[i * 5 + 4];
                    var ffnM = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);
                    ffnGateL[i] = ffnM; ffnUpL[i] = ffnM; ffnDownL[i] = ffnM;
                }
            }
            else
            {
                for (int i = 0; i < layerCount; i++)
                {
                    var (rows, cols, _, offset, _) = descriptors[i * 7];
                    wqL[i] = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);
                    (rows, cols, _, offset, _) = descriptors[i * 7 + 1];
                    wkL[i] = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);
                    (rows, cols, _, offset, _) = descriptors[i * 7 + 2];
                    wvL[i] = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);
                    (rows, cols, _, offset, _) = descriptors[i * 7 + 3];
                    woL[i] = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);
                    (rows, cols, _, offset, _) = descriptors[i * 7 + 4];
                    ffnGateL[i] = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);
                    (rows, cols, _, offset, _) = descriptors[i * 7 + 5];
                    ffnUpL[i] = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);
                    (rows, cols, _, offset, _) = descriptors[i * 7 + 6];
                    ffnDownL[i] = NativeTernaryMatrix.FromMappedMemory(basePtr + offset, rows, cols);
                }
            }

            NativeInt8Matrix embeddings;
            {
                var (rows, cols, _, offset, length) = descriptors[matrixCount - 2];
                var dataSpan = new ReadOnlySpan<byte>(basePtr + offset, (int)length);
                embeddings = version >= 4
                    ? NativeInt8Matrix.FromMappedMemory(basePtr + offset, rows, cols)
                    : UpcastTernaryToInt8(dataSpan, rows, cols);
            }

            NativeInt8Matrix outputHead;
            {
                var (rows, cols, _, offset, length) = descriptors[matrixCount - 1];
                var dataSpan = new ReadOnlySpan<byte>(basePtr + offset, (int)length);
                outputHead = version >= 4
                    ? NativeInt8Matrix.FromMappedMemory(basePtr + offset, rows, cols)
                    : UpcastTernaryToInt8(dataSpan, rows, cols);
            }

            var config = new BitNetModelConfig(hiddenDim, layerCount, numHeads, vocabSize, maxSeqLen, lazyFfnDim);

            // Read norms appendix from mapped memory
            var normsData = TryReadNormsAppendixMapped(basePtr, fs.Length, descriptors, matrixCount, version);

            var data = new SnapshotData(config, activeVocab, wqL, wkL, wvL, woL,
                ffnGateL, ffnUpL, ffnDownL, embeddings, outputHead, tokens, lazyMerges,
                normsData.WeightScales, normsData.InputNorm, normsData.AttnSubNorm,
                normsData.PostAttnNorm, normsData.FfnSubNorm, normsData.FinalNorm);

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

    // ── Norms/Scales appendix (v5+) ──────────────────────────────────────

    private record struct NormsAppendix(
        float[][]? WeightScales,
        float[][]? InputNorm,
        float[][]? AttnSubNorm,
        float[][]? PostAttnNorm,
        float[][]? FfnSubNorm,
        float[]? FinalNorm);

    private static readonly ReadOnlyMemory<byte> NormsMagic = "SNRM"u8.ToArray();

    /// <summary>Read norms appendix from a BinaryReader (after packed data).</summary>
    private static NormsAppendix TryReadNormsAppendix(BinaryReader br, int version)
    {
        if (version < 5) return default;
        try
        {
            Span<byte> marker = stackalloc byte[4];
            if (br.Read(marker) != 4 || !marker.SequenceEqual(NormsMagic.Span))
                return default;

            int numLayers = br.ReadInt32();
            int hiddenDim = br.ReadInt32();
            int ffnDim    = br.ReadInt32();

            var weightScales = new float[numLayers][];
            for (int L = 0; L < numLayers; L++)
            {
                weightScales[L] = new float[7];
                for (int m = 0; m < 7; m++)
                    weightScales[L][m] = br.ReadSingle();
            }

            var finalNorm = ReadFloatArray(br, hiddenDim);

            var inputNorm    = new float[numLayers][];
            var attnSubNorm  = new float[numLayers][];
            var postAttnNorm = new float[numLayers][];
            var ffnSubNorm   = new float[numLayers][];
            for (int L = 0; L < numLayers; L++)
            {
                inputNorm[L]    = ReadFloatArray(br, hiddenDim);
                attnSubNorm[L]  = ReadFloatArray(br, hiddenDim);
                postAttnNorm[L] = ReadFloatArray(br, hiddenDim);
                ffnSubNorm[L]   = ReadFloatArray(br, ffnDim);
            }

            return new NormsAppendix(weightScales, inputNorm, attnSubNorm, postAttnNorm, ffnSubNorm, finalNorm);
        }
        catch (EndOfStreamException) { return default; }
    }

    /// <summary>Read norms appendix from memory-mapped data.</summary>
    private static unsafe NormsAppendix TryReadNormsAppendixMapped(
        byte* basePtr, long fileSize,
        (int Rows, int Cols, int Stride, long Offset, long Length)[] descriptors,
        int matrixCount, int version)
    {
        if (version < 5 || matrixCount == 0) return default;

        // Norms section starts after the last matrix's packed data
        var lastDesc = descriptors[matrixCount - 1];
        long normsStart = lastDesc.Offset + lastDesc.Length;
        if (normsStart + 16 > fileSize) return default;

        var markerSpan = new ReadOnlySpan<byte>(basePtr + normsStart, 4);
        if (!markerSpan.SequenceEqual(NormsMagic.Span))
            return default;

        // Read via UnmanagedMemoryStream + BinaryReader for simplicity
        long remaining = fileSize - normsStart;
        using var stream = new UnmanagedMemoryStream(basePtr + normsStart, remaining);
        using var br = new BinaryReader(stream, Encoding.UTF8);
        br.ReadInt32(); // skip marker
        return TryReadNormsFromReader(br);
    }

    private static NormsAppendix TryReadNormsFromReader(BinaryReader br)
    {
        int numLayers = br.ReadInt32();
        int hiddenDim = br.ReadInt32();
        int ffnDim    = br.ReadInt32();

        var weightScales = new float[numLayers][];
        for (int L = 0; L < numLayers; L++)
        {
            weightScales[L] = new float[7];
            for (int m = 0; m < 7; m++)
                weightScales[L][m] = br.ReadSingle();
        }

        var finalNorm = ReadFloatArray(br, hiddenDim);

        var inputNorm    = new float[numLayers][];
        var attnSubNorm  = new float[numLayers][];
        var postAttnNorm = new float[numLayers][];
        var ffnSubNorm   = new float[numLayers][];
        for (int L = 0; L < numLayers; L++)
        {
            inputNorm[L]    = ReadFloatArray(br, hiddenDim);
            attnSubNorm[L]  = ReadFloatArray(br, hiddenDim);
            postAttnNorm[L] = ReadFloatArray(br, hiddenDim);
            ffnSubNorm[L]   = ReadFloatArray(br, ffnDim);
        }

        return new NormsAppendix(weightScales, inputNorm, attnSubNorm, postAttnNorm, ffnSubNorm, finalNorm);
    }

    private static float[] ReadFloatArray(BinaryReader br, int count)
    {
        var arr = new float[count];
        for (int i = 0; i < count; i++)
            arr[i] = br.ReadSingle();
        return arr;
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

    private static byte[] ReadExactBytes(BinaryReader br, long length)
    {
        var buf = new byte[length];
        int totalRead = 0;
        while (totalRead < length)
        {
            int read = br.Read(buf, totalRead, (int)(length - totalRead));
            if (read == 0) throw new EndOfStreamException();
            totalRead += read;
        }
        return buf;
    }

    private static unsafe NativeInt8Matrix MaterializeMappedInt8(byte* data, int rows, int cols)
    {
        using var mapped = NativeInt8Matrix.FromMappedMemory(data, rows, cols);
        var packedData = new byte[mapped.TotalPackedDataBytes];
        mapped.CopyPackedDataTo(packedData);
        return NativeInt8Matrix.FromPackedData(packedData, rows, cols);
    }

    /// <summary>
    /// Upcast a ternary-packed matrix to int8 for backward compatibility.
    /// Creates a NativeTernaryMatrix, decodes each row, and repacks as int8.
    /// </summary>
    private static NativeInt8Matrix UpcastTernaryToInt8(ReadOnlySpan<byte> packedData, int rows, int cols)
    {
        var ternary = NativeTernaryMatrix.FromPackedData(packedData, rows, cols);
        var int8 = NativeInt8Matrix.Allocate(rows, cols);
        var intRow = new int[cols];
        var sbyteRow = new sbyte[cols];
        for (int r = 0; r < rows; r++)
        {
            ternary.DecodeRow(r, intRow);
            for (int c = 0; c < cols; c++)
                sbyteRow[c] = (sbyte)intRow[c];
            int8.PackRowInPlace(r, sbyteRow);
        }
        ternary.Dispose();
        int8.FinalizeStats();
        return int8;
    }
}

/// <summary>
/// Data loaded from a binary model snapshot.
/// </summary>
public sealed record SnapshotData(
    BitNetModelConfig Config,
    int ActiveVocab,
    NativeTernaryMatrix[] Wq,
    NativeTernaryMatrix[] Wk,
    NativeTernaryMatrix[] Wv,
    NativeTernaryMatrix[] Wo,
    NativeTernaryMatrix[] FfnGate,
    NativeTernaryMatrix[] FfnUp,
    NativeTernaryMatrix[] FfnDown,
    NativeInt8Matrix Embeddings,
    NativeInt8Matrix OutputHead,
    string[] Tokens,
    string[] Merges,
    float[][]? WeightScales = null,
    float[][]? InputNorm = null,
    float[][]? AttnSubNorm = null,
    float[][]? PostAttnNorm = null,
    float[][]? FfnSubNorm = null,
    float[]? FinalNorm = null) : IDisposable
{
    public void Dispose()
    {
        foreach (var m in Wq)  m?.Dispose();
        foreach (var m in Wk)  m?.Dispose();
        foreach (var m in Wv)  m?.Dispose();
        foreach (var m in Wo)  m?.Dispose();
        foreach (var m in FfnGate) m?.Dispose();
        foreach (var m in FfnUp)   m?.Dispose();
        foreach (var m in FfnDown) m?.Dispose();
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
