using System.Text;
using System.Text.Json;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Converts a HuggingFace model directory (SafeTensors format) to a .bmwm snapshot.
/// Designed for microsoft/BitNet-b1.58-2B-4T and compatible models.
///
/// Memory strategy: tensors are streamed row-by-row into <see cref="NativeTernaryMatrix"/>
/// instances via the internal streaming API — the full sbyte[] is never materialised
/// even for 655 MB embedding tables.
///
/// Supported HF tensor name prefixes (LLaMA / BitNet layout):
///   model.embed_tokens.weight             → embeddings
///   lm_head.weight                        → output head
///   model.layers.{i}.self_attn.q_proj.weight → Wq[i]
///   model.layers.{i}.self_attn.k_proj.weight → Wk[i]
///   model.layers.{i}.self_attn.v_proj.weight → Wv[i]
///   model.layers.{i}.self_attn.o_proj.weight → Wo[i]
///   model.layers.{i}.mlp.gate_proj.weight    → Ffn[i]  (first of SwiGLU pair)
/// </summary>
public static class HuggingFaceImporter
{
    // ── OOM mitigation caps ───────────────────────────────────────────────

    /// <summary>
    /// Maximum sequence length written into the .bmwm snapshot.
    /// Capped to avoid the KV-cache allocation (layers × maxSeq × dim × 4 bytes)
    /// ballooning on constrained hosts.
    /// Formula: 32L × 512 × 2560d × 4 bytes = 167 MB (BitNet-b1.58-2B-4T).
    /// Without the cap the default 2048-token window would require 671 MB for KV cache alone.
    /// </summary>
    public const int MaxSeqLenCap = 512;

    // Default architecture constants for microsoft/BitNet-b1.58-2B-4T
    // Used when config.json is absent.
    private const int DefaultHiddenDim  = 2560;
    private const int DefaultNumLayers  = 32;
    private const int DefaultNumHeads   = 32;
    private const int DefaultVocabSize  = 131072;
    private const int DefaultMaxSeqLen  = 2048;

    // ── Import entry point ────────────────────────────────────────────────

    /// <summary>
    /// Import a HuggingFace model directory to a .bmwm snapshot file.
    /// </summary>
    /// <param name="hfDir">
    ///   Directory containing model.safetensors (or shards) + config.json.
    /// </param>
    /// <param name="outputPath">Destination .bmwm file path.</param>
    /// <param name="progress">
    ///   Optional progress callback — receives status lines during import.
    /// </param>
    /// <exception cref="DirectoryNotFoundException">
    ///   Thrown if <paramref name="hfDir"/> does not exist.
    /// </exception>
    /// <exception cref="InvalidDataException">
    ///   Thrown if required tensors are missing or the model config is invalid.
    /// </exception>
    public static void Import(
        string hfDir,
        string outputPath,
        Action<string>? progress = null)
    {
        if (!Directory.Exists(hfDir))
            throw new DirectoryNotFoundException($"HF model directory not found: {hfDir}");

        progress?.Invoke($"  Scanning {hfDir} ...");

        // ── 1. Read config.json ────────────────────────────────────────────
        var config = ReadModelConfig(hfDir);
        progress?.Invoke($"  Config: {config.HiddenDim}d, {config.NumLayers}L, {config.NumHeads}H, vocab={config.VocabSize}");

        // ── 2. Scan all .safetensors shards ───────────────────────────────
        var tensorMap = SafeTensorsReader.ReadAllHeaders(hfDir);
        progress?.Invoke($"  Found {tensorMap.Count} tensors across {CountShards(hfDir)} shard(s)");

        // ── 3. Validate required tensors exist ─────────────────────────────
        ValidateRequiredTensors(tensorMap, config.NumLayers);

        // ── 4. Derive actual dimensions from tensor shapes ─────────────────
        //   Use Wq[0] to confirm hidden dim (may differ from config.json if pruned)
        var wq0Key   = LayerWqKey(0);
        var wq0Info  = tensorMap[wq0Key].Info;
        int dim      = wq0Info.Cols; // [out_dim, in_dim] → in_dim = hidden dim
        int numLayers = config.NumLayers;
        int numHeads  = config.NumHeads;
        int vocab     = config.VocabSize;
        // Cap MaxSeqLen to avoid OOM on KV cache allocation at inference time
        int maxSeqLen = Math.Min(config.MaxSeqLen, MaxSeqLenCap);

        progress?.Invoke($"  Effective dim={dim}, maxSeqLen capped to {maxSeqLen}");

        // ── 5. Derive FFN intermediate dimension from gate_proj shape ──────
        var gate0Key = LayerGateKey(0);
        var gate0Info = tensorMap.ContainsKey(gate0Key) ? tensorMap[gate0Key].Info : (SafeTensorsReader.TensorInfo?)null;
        // For U8 packed ternary: logical rows = packed rows × 4
        int ffnDim = gate0Info is not null
            ? gate0Info.Value.Rows * (gate0Info.Value.Dtype == "U8" ? 4 : 1)
            : dim;

        // Derive KV head dimension for GQA (Grouped Query Attention)
        var wk0Key = LayerWkKey(0);
        var wk0Info = tensorMap.ContainsKey(wk0Key) ? tensorMap[wk0Key].Info : (SafeTensorsReader.TensorInfo?)null;
        int kvDim = wk0Info is not null
            ? wk0Info.Value.Rows * (wk0Info.Value.Dtype == "U8" ? 4 : 1)
            : dim;

        // Derive Q dimension (should match dim, but verify)
        int qDim = wq0Info.Rows * (wq0Info.Dtype == "U8" ? 4 : 1);

        var bmwConfig = new BitNetModelConfig(dim, numLayers, numHeads, vocab, maxSeqLen, ffnDim);
        progress?.Invoke($"  FFN intermediate dim={ffnDim}, gated SwiGLU={bmwConfig.HasGatedFfn}");
        progress?.Invoke($"  Q dim={qDim}, KV dim={kvDim} (GQA={kvDim != qDim})");

        // ── 6. Import per-layer matrices ───────────────────────────────────
        var wq      = new NativeTernaryMatrix[numLayers];
        var wk      = new NativeTernaryMatrix[numLayers];
        var wv      = new NativeTernaryMatrix[numLayers];
        var wo      = new NativeTernaryMatrix[numLayers];
        var ffnGate = new NativeTernaryMatrix[numLayers];
        var ffnUp   = new NativeTernaryMatrix[numLayers];
        var ffnDown = new NativeTernaryMatrix[numLayers];

        for (int i = 0; i < numLayers; i++)
        {
            progress?.Invoke($"  Layer {i + 1}/{numLayers}: importing attention + ffn ...");

            wq[i]      = StreamTensor(tensorMap, LayerWqKey(i),   qDim, dim, progress);
            // GQA: expand KV heads to match Q heads by repeating each KV head group
            wk[i]      = kvDim < qDim
                ? StreamTensorWithGqaExpand(tensorMap, LayerWkKey(i), kvDim, qDim, dim, progress)
                : StreamTensor(tensorMap, LayerWkKey(i), kvDim, dim, progress);
            wv[i]      = kvDim < qDim
                ? StreamTensorWithGqaExpand(tensorMap, LayerWvKey(i), kvDim, qDim, dim, progress)
                : StreamTensor(tensorMap, LayerWvKey(i), kvDim, dim, progress);
            wo[i]      = StreamTensor(tensorMap, LayerWoKey(i),   dim, qDim, progress);
            ffnGate[i] = StreamTensor(tensorMap, LayerGateKey(i), ffnDim, dim, progress);
            ffnUp[i]   = StreamTensor(tensorMap, LayerUpKey(i),   ffnDim, dim, progress);
            ffnDown[i] = StreamTensor(tensorMap, LayerDownKey(i), dim, ffnDim, progress);

            // Blocking GC after each layer to reclaim row-buffers before next layer allocates.
            // Non-blocking collection risks memory pressure spikes on constrained hosts.
            GC.Collect(0, GCCollectionMode.Optimized, blocking: true);
        }

        // ── 7. Import embeddings + output head as int8 (NOT ternary) ──────
        //   Embeddings are BF16 in the model — ternary quantization destroys them.
        //   Scale BF16 → int8 to preserve relative magnitudes.
        progress?.Invoke("  Importing embeddings as int8 (BF16 → scaled int8) ...");
        var embeddings = StreamTensorInt8(tensorMap, EmbedKey, vocab, dim, progress);
        GC.Collect(1, GCCollectionMode.Optimized, blocking: true);

        progress?.Invoke("  Importing output head as int8 ...");
        var outputHead = StreamTensorInt8(tensorMap, LmHeadKey(tensorMap), vocab, dim, progress);
        GC.Collect(1, GCCollectionMode.Optimized, blocking: true);

        // ── 8. Load tokenizer vocab and BPE merges ─────────────────────────
        progress?.Invoke("  Loading tokenizer vocab + BPE merges ...");
        var (tokenTable, bpeMerges) = LoadTokenizerVocabAndMerges(hfDir, vocab);
        progress?.Invoke($"  Vocab loaded: {tokenTable?.Count ?? 0} tokens, {bpeMerges?.Count ?? 0} merges");

        // ── 9. Extract weight scales and layer norm weights ───────────────
        progress?.Invoke("  Extracting weight scales and layer norms ...");
        var (weightScales, inputNorm, attnSubNorm, postAttnNorm, ffnSubNorm, finalNorm) =
            ExtractNormsAndScales(tensorMap, numLayers, dim, ffnDim, progress);

        // ── 10. Write .bmwm snapshot ──────────────────────────────────────
        progress?.Invoke($"  Writing snapshot to {outputPath} ...");
        ModelSnapshot.Save(outputPath, bmwConfig, vocab,
            wq, wk, wv, wo, ffnGate, ffnUp, ffnDown,
            embeddings, outputHead,
            tokenTable, bpeMerges,
            weightScales, inputNorm, attnSubNorm, postAttnNorm, ffnSubNorm, finalNorm);

        // Dispose remaining native matrices not already freed by Save
        embeddings.Dispose();
        outputHead.Dispose();

        // ── 10. Dispose native matrices ────────────────────────────────────
        for (int i = 0; i < numLayers; i++)
        {
            wq[i].Dispose(); wk[i].Dispose(); wv[i].Dispose();
            wo[i].Dispose();
            ffnGate[i].Dispose(); ffnUp[i].Dispose(); ffnDown[i].Dispose();
        }
        embeddings.Dispose();
        outputHead.Dispose();

        var fi = new FileInfo(outputPath);
        progress?.Invoke($"  ✓ Snapshot written: {fi.Length / (1024 * 1024)} MB → {fi.FullName}");
    }

    // ── Tensor name helpers ───────────────────────────────────────────────

    private const string EmbedKey = "model.embed_tokens.weight";

    private static string LmHeadKey(Dictionary<string, (SafeTensorsReader.TensorInfo, string)> map)
        => map.ContainsKey("lm_head.weight") ? "lm_head.weight" : EmbedKey; // tied weights fallback

    private static string LayerWqKey(int i)  => $"model.layers.{i}.self_attn.q_proj.weight";
    private static string LayerWkKey(int i)  => $"model.layers.{i}.self_attn.k_proj.weight";
    private static string LayerWvKey(int i)  => $"model.layers.{i}.self_attn.v_proj.weight";
    private static string LayerWoKey(int i)  => $"model.layers.{i}.self_attn.o_proj.weight";

    private static string LayerGateKey(int i) => $"model.layers.{i}.mlp.gate_proj.weight";
    private static string LayerUpKey(int i)   => $"model.layers.{i}.mlp.up_proj.weight";
    private static string LayerDownKey(int i) => $"model.layers.{i}.mlp.down_proj.weight";

    private static string[] RequiredLayerSuffixes =
    [
        "self_attn.q_proj.weight",
        "self_attn.k_proj.weight",
        "self_attn.v_proj.weight",
        "self_attn.o_proj.weight",
        "mlp.gate_proj.weight",
        "mlp.up_proj.weight",
        "mlp.down_proj.weight",
    ];

    // ── Validation ────────────────────────────────────────────────────────

    private static void ValidateRequiredTensors(
        Dictionary<string, (SafeTensorsReader.TensorInfo, string)> map,
        int numLayers)
    {
        if (!map.ContainsKey(EmbedKey))
            throw new InvalidDataException($"Required tensor '{EmbedKey}' not found in model.");

        for (int i = 0; i < numLayers; i++)
        {
            foreach (var suffix in RequiredLayerSuffixes)
            {
                string key = $"model.layers.{i}.{suffix}";
                if (!map.ContainsKey(key))
                    throw new InvalidDataException($"Required tensor '{key}' not found in model.");
            }
        }
    }

    // ── Streaming import ──────────────────────────────────────────────────

    /// <summary>
    /// Stream a single tensor from SafeTensors into a <see cref="NativeTernaryMatrix"/>,
    /// truncating or padding to <paramref name="targetRows"/> × <paramref name="targetCols"/>.
    /// Memory peak: one row buffer only.
    /// </summary>
    private static NativeTernaryMatrix StreamTensor(
        Dictionary<string, (SafeTensorsReader.TensorInfo Info, string FilePath)> map,
        string key,
        int targetRows,
        int targetCols,
        Action<string>? progress)
    {
        var (info, filePath) = map[key];

        // U8 packed ternary: 4 ternary values per byte, packed along rows
        if (info.Dtype == "U8")
            return StreamPackedTernaryTensor(info, filePath, targetRows, targetCols);

        int srcRows = info.Rows;
        int srcCols = info.Cols;
        int rows = Math.Min(srcRows, targetRows);
        int cols = Math.Min(srcCols, targetCols);

        var matrix = NativeTernaryMatrix.Allocate(targetRows, targetCols);

        var ternRow = new sbyte[srcCols];
        var rawRow  = new byte[srcCols * info.ElementBytes];

        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, Math.Max(65536, rawRow.Length), FileOptions.SequentialScan);
        fs.Seek(info.DataStart, SeekOrigin.Begin);

        for (int r = 0; r < srcRows; r++)
        {
            ReadExact(fs, rawRow);

            if (r >= rows) continue;

            SafeTensorsReader.QuantiseRow(rawRow, ternRow, info.Dtype, srcCols);
            matrix.PackRowInPlace(r, ternRow.AsSpan(0, cols));
        }

        matrix.FinalizeStats();
        return matrix;
    }

    /// <summary>
    /// Stream a U8-packed ternary tensor. Each byte stores 4 ternary values (2 bits each)
    /// packed along the row dimension: packed_shape[0] = logical_rows/4, packed_shape[1] = logical_cols.
    /// Encoding per byte (little-endian bit pairs): 0→0, 1→+1, 2→-1.
    /// </summary>
    private static NativeTernaryMatrix StreamPackedTernaryTensor(
        SafeTensorsReader.TensorInfo info, string filePath,
        int targetRows, int targetCols)
    {
        int packedRows = info.Rows;
        int cols = info.Cols;
        int logicalRows = packedRows * 4;

        int rows = Math.Min(logicalRows, targetRows);
        int outCols = Math.Min(cols, targetCols);

        var matrix = NativeTernaryMatrix.Allocate(targetRows, targetCols);

        var packedRow = new byte[cols];
        // 4 unpacked rows, one for each 2-bit slot
        var ternRows = new sbyte[4][];
        for (int s = 0; s < 4; s++) ternRows[s] = new sbyte[cols];

        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, Math.Max(65536, cols), FileOptions.SequentialScan);
        fs.Seek(info.DataStart, SeekOrigin.Begin);

        for (int pr = 0; pr < packedRows; pr++)
        {
            ReadExact(fs, packedRow);

            int baseRow = pr * 4;
            if (baseRow >= rows) continue;

            // Unpack: each byte → 4 ternary values
            for (int c = 0; c < cols; c++)
            {
                byte packed = packedRow[c];
                // 2-bit slots: bits [1:0], [3:2], [5:4], [7:6]
                // Encoding: 0→0, 1→+1, 2→-1
                for (int s = 0; s < 4; s++)
                {
                    int val = (packed >> (s * 2)) & 0x03;
                    ternRows[s][c] = val switch { 1 => 1, 2 => -1, _ => 0 };
                }
            }

            // Pack each unpacked row into the native matrix
            for (int s = 0; s < 4; s++)
            {
                int logRow = baseRow + s;
                if (logRow >= rows) break;
                matrix.PackRowInPlace(logRow, ternRows[s].AsSpan(0, outCols));
            }
        }

        matrix.FinalizeStats();
        return matrix;
    }

    /// <summary>
    /// Stream a KV projection tensor and expand for GQA (Grouped Query Attention).
    /// Repeats each KV head's rows to match the Q head count.
    /// E.g., 5 KV heads × 128 headDim = 640 rows → repeated 4× → 2560 rows = 20 Q heads × 128.
    /// </summary>
    private static NativeTernaryMatrix StreamTensorWithGqaExpand(
        Dictionary<string, (SafeTensorsReader.TensorInfo Info, string FilePath)> map,
        string key,
        int kvDim, int qDim, int dim,
        Action<string>? progress)
    {
        // First stream the KV tensor at its natural size
        var kvMatrix = StreamTensor(map, key, kvDim, dim, progress);

        // If no expansion needed, return as-is
        if (kvDim >= qDim) return kvMatrix;

        int repeatFactor = qDim / kvDim;
        var expanded = NativeTernaryMatrix.Allocate(qDim, dim);

        // Decode each row from KV as int[], convert to sbyte[], repeat into expanded
        var intRow = new int[dim];
        var sbyteRow = new sbyte[dim];
        for (int r = 0; r < kvDim; r++)
        {
            kvMatrix.DecodeRow(r, intRow);
            for (int c = 0; c < dim; c++)
                sbyteRow[c] = (sbyte)intRow[c];

            for (int rep = 0; rep < repeatFactor; rep++)
                expanded.PackRowInPlace(r * repeatFactor + rep, sbyteRow);
        }

        kvMatrix.Dispose();
        expanded.FinalizeStats();
        return expanded;
    }

    /// <summary>
    /// Stream a BF16/F16/F32 tensor and quantize to int8 (scaled to ±127).
    /// Used for embeddings and output heads where ternary quantization is too lossy.
    /// Two-pass: first pass finds max abs value per row for scaling, second pass quantizes.
    /// For large tensors we use a global scale computed from the first 256 rows.
    /// </summary>
    private static NativeInt8Matrix StreamTensorInt8(
        Dictionary<string, (SafeTensorsReader.TensorInfo Info, string FilePath)> map,
        string key,
        int targetRows, int targetCols,
        Action<string>? progress)
    {
        var (info, filePath) = map[key];
        int srcRows = info.Rows;
        int srcCols = info.Cols;
        int rows = Math.Min(srcRows, targetRows);
        int cols = Math.Min(srcCols, targetCols);
        int elemBytes = info.ElementBytes;

        var matrix = NativeInt8Matrix.Allocate(targetRows, targetCols);
        var rawRow = new byte[srcCols * elemBytes];
        var floatRow = new float[srcCols];
        var int8Row = new sbyte[cols];

        // First pass (sample): compute global scale from first N rows
        float globalMaxAbs = 0f;
        int sampleRows = Math.Min(rows, 256);
        using (var fs1 = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, Math.Max(65536, rawRow.Length), FileOptions.SequentialScan))
        {
            fs1.Seek(info.DataStart, SeekOrigin.Begin);
            for (int r = 0; r < sampleRows; r++)
            {
                ReadExact(fs1, rawRow);
                ConvertToFloat(rawRow, floatRow, info.Dtype, srcCols);
                for (int c = 0; c < cols; c++)
                {
                    float abs = MathF.Abs(floatRow[c]);
                    if (abs > globalMaxAbs) globalMaxAbs = abs;
                }
            }
        }

        float scale = globalMaxAbs > 0f ? 127f / globalMaxAbs : 1f;

        // Second pass: quantize all rows
        using var fs2 = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, Math.Max(65536, rawRow.Length), FileOptions.SequentialScan);
        fs2.Seek(info.DataStart, SeekOrigin.Begin);

        for (int r = 0; r < srcRows; r++)
        {
            ReadExact(fs2, rawRow);
            if (r >= rows) continue;

            ConvertToFloat(rawRow, floatRow, info.Dtype, srcCols);
            for (int c = 0; c < cols; c++)
            {
                float scaled = floatRow[c] * scale;
                int clamped = (int)MathF.Round(scaled);
                int8Row[c] = (sbyte)Math.Clamp(clamped, -127, 127);
            }
            matrix.PackRowInPlace(r, int8Row);
        }

        matrix.FinalizeStats();
        return matrix;
    }

    /// <summary>Convert a raw byte row to float values based on dtype.</summary>
    private static void ConvertToFloat(byte[] raw, float[] output, string dtype, int cols)
    {
        switch (dtype)
        {
            case "BF16":
                for (int i = 0; i < cols; i++)
                {
                    ushort bits = (ushort)(raw[i * 2] | (raw[i * 2 + 1] << 8));
                    // BF16 → float32: shift left 16 bits
                    uint f32Bits = (uint)bits << 16;
                    output[i] = BitConverter.Int32BitsToSingle((int)f32Bits);
                }
                break;
            case "F16":
                for (int i = 0; i < cols; i++)
                {
                    ushort bits = (ushort)(raw[i * 2] | (raw[i * 2 + 1] << 8));
                    output[i] = (float)BitConverter.UInt16BitsToHalf(bits);
                }
                break;
            case "F32":
                for (int i = 0; i < cols; i++)
                    output[i] = BitConverter.ToSingle(raw, i * 4);
                break;
            default:
                // For I8/U8 packed data, just cast directly
                for (int i = 0; i < cols; i++)
                    output[i] = (sbyte)raw[i];
                break;
        }
    }

    // ── Weight scales and layer norms extraction ─────────────────────────

    /// <summary>
    /// Extract per-layer weight scales (BF16 scalars) and learned RMS norm weights
    /// (BF16 vectors) from the safetensors model. These are critical for correct
    /// BitNet inference — without them, magnitudes between projections are wrong
    /// and per-dimension learned scaling is lost.
    /// </summary>
    private static (float[][], float[][], float[][], float[][], float[][], float[])
        ExtractNormsAndScales(
            Dictionary<string, (SafeTensorsReader.TensorInfo Info, string FilePath)> tensorMap,
            int numLayers, int hiddenDim, int ffnDim,
            Action<string>? progress)
    {
        var weightScales = new float[numLayers][];
        var inputNorm    = new float[numLayers][];
        var attnSubNorm  = new float[numLayers][];
        var postAttnNorm = new float[numLayers][];
        var ffnSubNorm   = new float[numLayers][];

        string[] scaleKeys =
        [
            "self_attn.q_proj.weight_scale",
            "self_attn.k_proj.weight_scale",
            "self_attn.v_proj.weight_scale",
            "self_attn.o_proj.weight_scale",
            "mlp.gate_proj.weight_scale",
            "mlp.up_proj.weight_scale",
            "mlp.down_proj.weight_scale",
        ];

        for (int L = 0; L < numLayers; L++)
        {
            // Weight scales: 7 BF16 scalars per layer
            weightScales[L] = new float[7];
            for (int m = 0; m < 7; m++)
            {
                string key = $"model.layers.{L}.{scaleKeys[m]}";
                weightScales[L][m] = tensorMap.ContainsKey(key)
                    ? ReadBf16Scalar(tensorMap[key])
                    : 1f;
            }

            // Layer norms: BF16 vectors
            inputNorm[L]    = ReadBf16Vector(tensorMap, $"model.layers.{L}.input_layernorm.weight", hiddenDim);
            attnSubNorm[L]  = ReadBf16Vector(tensorMap, $"model.layers.{L}.self_attn.attn_sub_norm.weight", hiddenDim);
            postAttnNorm[L] = ReadBf16Vector(tensorMap, $"model.layers.{L}.post_attention_layernorm.weight", hiddenDim);
            ffnSubNorm[L]   = ReadBf16Vector(tensorMap, $"model.layers.{L}.mlp.ffn_sub_norm.weight", ffnDim);

            if (L == 0 || L == numLayers - 1)
                progress?.Invoke($"    Layer {L}: scales=[{string.Join(", ", weightScales[L].Select(s => s.ToString("F3")))}]");
        }

        // Final norm (before output head)
        var finalNorm = ReadBf16Vector(tensorMap, "model.norm.weight", hiddenDim);
        progress?.Invoke($"    Final norm: mean={finalNorm.Average():F4}, range=[{finalNorm.Min():F4}, {finalNorm.Max():F4}]");

        return (weightScales, inputNorm, attnSubNorm, postAttnNorm, ffnSubNorm, finalNorm);
    }

    /// <summary>Read a single BF16 scalar from a safetensors tensor.</summary>
    private static float ReadBf16Scalar(
        (SafeTensorsReader.TensorInfo Info, string FilePath) entry)
    {
        using var fs = new FileStream(entry.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        fs.Seek(entry.Info.DataStart, SeekOrigin.Begin);
        Span<byte> buf = stackalloc byte[2];
        fs.ReadExactly(buf);
        ushort bits = (ushort)(buf[0] | (buf[1] << 8));
        uint f32Bits = (uint)bits << 16;
        return BitConverter.Int32BitsToSingle((int)f32Bits);
    }

    /// <summary>Read a BF16 vector from safetensors and convert to float32.</summary>
    private static float[] ReadBf16Vector(
        Dictionary<string, (SafeTensorsReader.TensorInfo Info, string FilePath)> tensorMap,
        string key, int expectedLen)
    {
        if (!tensorMap.ContainsKey(key))
        {
            // Identity fallback — norm weight of 1.0
            var identity = new float[expectedLen];
            Array.Fill(identity, 1f);
            return identity;
        }

        var (info, filePath) = tensorMap[key];
        int count = Math.Min(info.Rows * info.Cols, expectedLen);
        var result = new float[expectedLen];

        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        fs.Seek(info.DataStart, SeekOrigin.Begin);

        int elemBytes = info.ElementBytes;
        var rawBuf = new byte[count * elemBytes];
        ReadExact(fs, rawBuf);

        // For 1D vectors, shape is [N] → Rows=N, Cols=1 in our parser.
        // Use ConvertToFloat for dtype-agnostic conversion.
        var floatBuf = new float[count];
        ConvertToFloat(rawBuf, floatBuf, info.Dtype, count);
        Array.Copy(floatBuf, result, count);

        // Fill remaining with 1.0 (identity) if shorter than expected
        for (int i = count; i < expectedLen; i++)
            result[i] = 1f;

        return result;
    }

    // ── Config / tokenizer loading ────────────────────────────────────────

    private static HfModelConfig ReadModelConfig(string hfDir)
    {
        string configPath = Path.Combine(hfDir, "config.json");
        if (!File.Exists(configPath))
        {
            // Use architecture defaults for microsoft/BitNet-b1.58-2B-4T
            return new HfModelConfig(DefaultHiddenDim, DefaultNumLayers, DefaultNumHeads,
                                     DefaultVocabSize, DefaultMaxSeqLen);
        }

        // Manual JSON parse (AOT-safe, no reflection)
        var text = File.ReadAllText(configPath).AsSpan();
        int hiddenDim  = ExtractInt(text, "hidden_size",             DefaultHiddenDim);
        int numLayers  = ExtractInt(text, "num_hidden_layers",       DefaultNumLayers);
        int numHeads   = ExtractInt(text, "num_attention_heads",     DefaultNumHeads);
        int vocabSize  = ExtractInt(text, "vocab_size",              DefaultVocabSize);
        int maxSeqLen  = ExtractInt(text, "max_position_embeddings", DefaultMaxSeqLen);

        return new HfModelConfig(hiddenDim, numLayers, numHeads, vocabSize, maxSeqLen);
    }

    /// <summary>
    /// Load the tokenizer vocabulary and BPE merges from tokenizer.json.
    /// </summary>
    private static (IReadOnlyList<string>? Vocab, IReadOnlyList<string>? Merges)
        LoadTokenizerVocabAndMerges(string hfDir, int vocabSize)
    {
        string tokPath = Path.Combine(hfDir, "tokenizer.json");
        if (!File.Exists(tokPath)) return (null, null);

        try
        {
            var text = File.ReadAllText(tokPath).AsSpan();
            var vocab = ParseVocabFromTokenizerJson(text, vocabSize);
            var merges = ParseMergesFromTokenizerJson(text);
            return (vocab, merges);
        }
        catch
        {
            return (null, null);
        }
    }

    /// <summary>
    /// Load the tokenizer vocabulary from tokenizer.json (HuggingFace format).
    /// Returns null if no tokenizer file is found.
    /// </summary>
    private static IReadOnlyList<string>? LoadTokenizerVocab(string hfDir, int vocabSize)
    {
        // Prefer tokenizer.json (HF fast tokenizer)
        string tokPath = Path.Combine(hfDir, "tokenizer.json");
        if (!File.Exists(tokPath)) return null;

        try
        {
            var text = File.ReadAllText(tokPath).AsSpan();
            return ParseVocabFromTokenizerJson(text, vocabSize);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Parse the "vocab" section from a HuggingFace tokenizer.json.
    /// Handles: {"model":{"vocab":{"token":id,...}}} and
    ///          {"model":{"vocab":[["token",id],...]}} (sentencepiece style).
    /// Returns a string[] of size vocabSize with tokens at their correct indices.
    /// </summary>
    private static string[]? ParseVocabFromTokenizerJson(ReadOnlySpan<char> json, int vocabSize)
    {
        // Find the "vocab" key
        int idx = IndexOf(json, "\"vocab\"");
        if (idx < 0) return null;
        idx += 7; // skip "vocab"

        // Skip whitespace and ':'
        while (idx < json.Length && json[idx] is ' ' or '\t' or '\n' or '\r' or ':') idx++;
        if (idx >= json.Length) return null;

        var result = new string[vocabSize];
        for (int i = 0; i < result.Length; i++) result[i] = i.ToString();

        if (json[idx] == '{')
        {
            // Object form: {"token": id, ...}
            idx++; // consume '{'
            while (idx < json.Length && json[idx] != '}')
            {
                while (idx < json.Length && json[idx] is ' ' or '\t' or '\n' or '\r' or ',') idx++;
                if (idx >= json.Length || json[idx] == '}') break;
                if (json[idx] != '"') { SkipJsonValue(json, ref idx); continue; }

                string token = ReadJsonString(json, ref idx);
                while (idx < json.Length && json[idx] is ' ' or '\t' or ':') idx++;
                if (!TryReadInt(json, ref idx, out int id)) continue;
                if ((uint)id < (uint)vocabSize) result[id] = token;
            }
        }
        // Array form not needed for BitNet-b1.58-2B-4T (uses object form)

        return result;
    }

    /// <summary>
    /// Parse the "merges" array from a HuggingFace tokenizer.json.
    /// Returns a list of merge strings like "Ġ t" (space-separated pair).
    /// </summary>
    private static IReadOnlyList<string>? ParseMergesFromTokenizerJson(ReadOnlySpan<char> json)
    {
        int idx = IndexOf(json, "\"merges\"");
        if (idx < 0) return null;
        idx += 8; // skip "merges"

        while (idx < json.Length && json[idx] is ' ' or '\t' or '\n' or '\r' or ':') idx++;
        if (idx >= json.Length || json[idx] != '[') return null;
        idx++; // consume '['

        var merges = new List<string>(300_000);
        while (idx < json.Length && json[idx] != ']')
        {
            while (idx < json.Length && json[idx] is ' ' or '\t' or '\n' or '\r' or ',') idx++;
            if (idx >= json.Length || json[idx] == ']') break;
            if (json[idx] != '"') { SkipJsonValue(json, ref idx); continue; }

            merges.Add(ReadJsonString(json, ref idx));
        }

        return merges;
    }

    // ── Config.json field helpers ─────────────────────────────────────────

    private static int ExtractInt(ReadOnlySpan<char> json, string key, int defaultVal)
    {
        int idx = IndexOf(json, $"\"{key}\"");
        if (idx < 0) return defaultVal;
        idx += key.Length + 2; // skip "key"
        while (idx < json.Length && json[idx] is ' ' or '\t' or ':') idx++;
        if (idx >= json.Length) return defaultVal;
        return TryReadInt(json, ref idx, out int v) ? v : defaultVal;
    }

    private static int IndexOf(ReadOnlySpan<char> s, string sub)
    {
        for (int i = 0; i <= s.Length - sub.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < sub.Length; j++)
                if (s[i + j] != sub[j]) { match = false; break; }
            if (match) return i;
        }
        return -1;
    }

    private static string ReadJsonString(ReadOnlySpan<char> s, ref int pos)
    {
        if (pos >= s.Length || s[pos] != '"') return string.Empty;
        pos++;
        int start = pos;
        while (pos < s.Length)
        {
            if (s[pos] == '\\') { pos += 2; continue; }
            if (s[pos] == '"') break;
            pos++;
        }
        string r = s[start..pos].ToString();
        if (pos < s.Length) pos++;
        return r;
    }

    private static bool TryReadInt(ReadOnlySpan<char> s, ref int pos, out int value)
    {
        while (pos < s.Length && s[pos] is ' ' or '\t') pos++;
        bool neg = pos < s.Length && s[pos] == '-';
        if (neg) pos++;
        if (pos >= s.Length || s[pos] < '0' || s[pos] > '9') { value = 0; return false; }
        long v = 0;
        while (pos < s.Length && s[pos] is >= '0' and <= '9') { v = v * 10 + (s[pos] - '0'); pos++; }
        value = (int)(neg ? -v : v);
        return true;
    }

    private static void SkipJsonValue(ReadOnlySpan<char> s, ref int pos)
    {
        if (pos >= s.Length) return;
        char c = s[pos];
        if (c == '"') { ReadJsonString(s, ref pos); return; }
        if (c == '{' || c == '[')
        {
            char close = c == '{' ? '}' : ']';
            pos++;
            int depth = 1;
            while (pos < s.Length && depth > 0)
            {
                if (s[pos] == '"') { ReadJsonString(s, ref pos); continue; }
                if (s[pos] == c) depth++;
                if (s[pos] == close) depth--;
                pos++;
            }
            return;
        }
        while (pos < s.Length && s[pos] is not (',' or '}' or ']' or ' ' or '\t' or '\r' or '\n'))
            pos++;
    }

    // ── I/O helpers ───────────────────────────────────────────────────────

    private static int CountShards(string hfDir)
        => Directory.GetFiles(hfDir, "*.safetensors", SearchOption.TopDirectoryOnly).Length;

    private static void ReadExact(FileStream fs, Span<byte> buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int read = fs.Read(buffer[total..]);
            if (read == 0)
                throw new EndOfStreamException(
                    $"Unexpected end of stream after {total}/{buffer.Length} bytes.");
            total += read;
        }
    }

    // ── Internal model config ─────────────────────────────────────────────

    private readonly struct HfModelConfig(
        int HiddenDim, int NumLayers, int NumHeads, int VocabSize, int MaxSeqLen)
    {
        public readonly int HiddenDim  = HiddenDim;
        public readonly int NumLayers  = NumLayers;
        public readonly int NumHeads   = NumHeads;
        public readonly int VocabSize  = VocabSize;
        public readonly int MaxSeqLen  = MaxSeqLen;
    }
}
