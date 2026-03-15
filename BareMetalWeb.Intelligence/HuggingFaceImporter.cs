using System.Text;
using System.Text.Json;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Imports a HuggingFace BitNet model (SafeTensors + tokenizer.json) and
/// converts it to the .bmwm snapshot format used by BitNetEngine.
///
/// Handles the architecture mapping between HF's LLaMA-like BitNet structure
/// (SwiGLU FFN with gate/up/down projections, per-layer norms, RoPE) and
/// our simplified ternary engine format.
///
/// The import pipeline:
///   1. Parse config.json for model dimensions
///   2. Parse tokenizer.json for vocabulary
///   3. Read weight tensors from SafeTensors files
///   4. Map weights to TernaryLayer format
///   5. Apply domain pruning (vocab, layers, heads, groups)
///   6. Pack to 2-bit NativeTernaryMatrix and save as .bmwm
/// </summary>
public static class HuggingFaceImporter
{
    /// <summary>
    /// Import a HuggingFace model directory into a .bmwm snapshot.
    /// The directory should contain: config.json, tokenizer.json, and *.safetensors files.
    /// </summary>
    public static ImportResult Import(string modelDir, ImportOptions options)
    {
        var log = new ImportLog();

        // 1. Read config.json
        var configPath = Path.Combine(modelDir, "config.json");
        if (!File.Exists(configPath))
            throw new FileNotFoundException("config.json not found in model directory", configPath);

        var hfConfig = ParseConfig(configPath);
        log.Add($"Model: hidden={hfConfig.HiddenSize}, layers={hfConfig.NumLayers}, " +
                $"heads={hfConfig.NumHeads}, kv_heads={hfConfig.NumKvHeads}, " +
                $"vocab={hfConfig.VocabSize}, intermediate={hfConfig.IntermediateSize}");

        // 2. Read tokenizer
        string[] tokenTable;
        var tokenizerPath = Path.Combine(modelDir, "tokenizer.json");
        if (File.Exists(tokenizerPath))
        {
            tokenTable = ParseTokenizer(tokenizerPath, hfConfig.VocabSize);
            log.Add($"Tokenizer: {tokenTable.Length} tokens loaded from tokenizer.json");
        }
        else
        {
            log.Add("Warning: tokenizer.json not found, using synthetic vocabulary");
            tokenTable = BuildFallbackVocab(hfConfig.VocabSize);
        }

        // 3. Find SafeTensors files
        var stFiles = Directory.GetFiles(modelDir, "*.safetensors")
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (stFiles.Length == 0)
            throw new FileNotFoundException("No .safetensors files found in model directory");
        log.Add($"SafeTensors files: {stFiles.Length}");

        // 4. Build multi-file tensor index
        var tensorIndex = BuildTensorIndex(stFiles);
        log.Add($"Tensors indexed: {tensorIndex.Count}");

        // 5. Extract weights — streaming, one layer at a time to minimize memory.
        // U8 packed tensors are remapped directly to NativeTernaryMatrix encoding
        // via a 256-byte LUT — no sbyte[] intermediate, no 4× memory expansion.
        int dim = hfConfig.HiddenSize;
        int ffnDim = hfConfig.IntermediateSize;
        int numLayers = hfConfig.NumLayers;
        int numHeads = hfConfig.NumHeads;
        int numKvHeads = hfConfig.NumKvHeads;
        int headDim = dim / numHeads;
        int kvDim = numKvHeads * headDim;

        log.Add($"Head dim: {headDim}, Q dim: {dim}, KV dim: {kvDim}");

        // Determine how many layers to keep after pruning
        int keepLayers = numLayers;
        if (options.LayerPruneRatio > 0f)
        {
            keepLayers = Math.Max(1, (int)(numLayers * (1f - options.LayerPruneRatio)));
            log.Add($"Layer pruning: keeping {keepLayers}/{numLayers} layers");
        }

        bool needsGqa = numKvHeads != numHeads;

        // Pre-allocate NativeTernaryMatrix arrays — these hold native memory, not managed arrays.
        var nWq  = new NativeTernaryMatrix[keepLayers];
        var nWk  = new NativeTernaryMatrix[keepLayers];
        var nWv  = new NativeTernaryMatrix[keepLayers];
        var nWo  = new NativeTernaryMatrix[keepLayers];
        var nFfn = new NativeTernaryMatrix[keepLayers];

        for (int i = 0; i < keepLayers; i++)
        {
            log.Add($"  Loading layer {i}/{keepLayers}...");

            // Q and O projections: dim×dim U8 → NativeTernaryMatrix directly (zero sbyte[] alloc)
            var qPacked = ReadRawPackedBytes(tensorIndex, $"model.layers.{i}.self_attn.q_proj.weight");
            nWq[i] = NativeTernaryMatrix.FromHfU8Packed(qPacked, dim, dim);
            // qPacked is now eligible for GC

            var oPacked = ReadRawPackedBytes(tensorIndex, $"model.layers.{i}.self_attn.o_proj.weight");
            nWo[i] = NativeTernaryMatrix.FromHfU8Packed(oPacked, dim, dim);

            // K/V: may need GQA expansion (kvDim < dim)
            if (needsGqa)
            {
                // GQA: unpack K/V to sbyte[] (small: kvDim×dim), expand, then pack to native
                var wkSmall = ReadPackedTernary(tensorIndex, $"model.layers.{i}.self_attn.k_proj.weight");
                var wk = ExpandGQA(wkSmall, kvDim, dim, numKvHeads, numHeads, headDim);
                nWk[i] = NativeTernaryMatrix.Pack(wk, dim, dim);

                var wvSmall = ReadPackedTernary(tensorIndex, $"model.layers.{i}.self_attn.v_proj.weight");
                var wv = ExpandGQA(wvSmall, kvDim, dim, numKvHeads, numHeads, headDim);
                nWv[i] = NativeTernaryMatrix.Pack(wv, dim, dim);
            }
            else
            {
                // No GQA — direct packed remap
                var kPacked = ReadRawPackedBytes(tensorIndex, $"model.layers.{i}.self_attn.k_proj.weight");
                nWk[i] = NativeTernaryMatrix.FromHfU8Packed(kPacked, dim, dim);

                var vPacked = ReadRawPackedBytes(tensorIndex, $"model.layers.{i}.self_attn.v_proj.weight");
                nWv[i] = NativeTernaryMatrix.FromHfU8Packed(vPacked, dim, dim);
            }

            // FFN: down_proj is [dim × ffnDim], truncate to [dim × dim] directly on packed bytes
            var downPacked = ReadRawPackedBytes(tensorIndex, $"model.layers.{i}.mlp.down_proj.weight");
            nFfn[i] = NativeTernaryMatrix.FromHfU8PackedTruncated(downPacked, dim, ffnDim, dim);

            log.Add($"    Layer {i}: packed to native ({nWq[i].BytesAllocated / 1024}KB per matrix)");
        }

        // 6. Vocabulary pruning setup — build remap table BEFORE loading embeddings
        // to avoid allocating the full 128K×dim float[] (1.3GB for 2B model).
        int activeVocab = hfConfig.VocabSize;
        VocabularyPruner? vocabPruner = null;
        string[] finalTokenTable = tokenTable;

        if (options.PruneVocabulary)
        {
            vocabPruner = VocabularyPruner.FromDataScaffold();
            vocabPruner.BuildRemapTable(tokenTable);
            activeVocab = vocabPruner.PrunedVocabSize;

            var prunedTokens = new string[activeVocab];
            for (int i = 0; i < hfConfig.VocabSize && i < tokenTable.Length; i++)
            {
                int mapped = vocabPruner.MapTokenId(i);
                if (mapped >= 0 && mapped < activeVocab)
                    prunedTokens[mapped] = tokenTable[i];
            }
            for (int i = 0; i < activeVocab; i++)
                prunedTokens[i] ??= $"<{i}>";
            finalTokenTable = prunedTokens;
            log.Add($"Vocab pruned: {hfConfig.VocabSize} → {activeVocab} tokens");
        }

        // 7. Read embeddings — stream row-by-row, only keeping pruned rows
        log.Add("Loading embeddings (BF16 → ternary, streaming)...");
        var embeddings = ReadEmbeddingsStreaming(tensorIndex, "model.embed_tokens.weight",
            hfConfig.VocabSize, dim, vocabPruner);
        log.Add($"Embeddings: {embeddings.Length:N0} weights ({activeVocab} × {dim})");

        // Tied embeddings — output head shares embed_tokens weight
        sbyte[] outputHead;
        if (tensorIndex.ContainsKey("lm_head.weight"))
        {
            outputHead = ReadEmbeddingsStreaming(tensorIndex, "lm_head.weight",
                hfConfig.VocabSize, dim, vocabPruner);
        }
        else
        {
            outputHead = new sbyte[embeddings.Length];
            embeddings.AsSpan().CopyTo(outputHead);
            log.Add("Output head: tied to embeddings (no lm_head.weight)");
        }
        log.Add($"Output head: {outputHead.Length:N0} weights");

        // 8. Pack embeddings to native
        var nEmbeddings = NativeTernaryMatrix.Pack(embeddings, activeVocab, dim);
        var nOutputHead = NativeTernaryMatrix.Pack(outputHead, activeVocab, dim);
        embeddings = null!;
        outputHead = null!;

        // 9. Save snapshot directly — skip engine allocation (no inference buffers needed)
        var config = new BitNetModelConfig(
            HiddenDim: dim,
            NumLayers: keepLayers,
            NumHeads: numHeads,
            VocabSize: hfConfig.VocabSize,
            MaxSeqLen: Math.Min(hfConfig.MaxSeqLen, options.MaxSeqLen));

        ModelSnapshot.Save(options.OutputPath, config, activeVocab,
            nWq, nWk, nWv, nWo, nFfn, nEmbeddings, nOutputHead, finalTokenTable);

        // Dispose all native matrices — data is now on disk
        foreach (var m in nWq)  m.Dispose();
        foreach (var m in nWk)  m.Dispose();
        foreach (var m in nWv)  m.Dispose();
        foreach (var m in nWo)  m.Dispose();
        foreach (var m in nFfn) m.Dispose();
        nEmbeddings.Dispose();
        nOutputHead.Dispose();

        var fileInfo = new FileInfo(options.OutputPath);
        log.Add($"Saved: {fileInfo.Length / (1024 * 1024)} MB → {options.OutputPath}");

        return new ImportResult(config, activeVocab, finalTokenTable.Length, fileInfo.Length, log);
    }

    /// <summary>
    /// Read raw packed bytes from a U8 tensor without unpacking.
    /// Returns the original packed byte[] for direct use with NativeTernaryMatrix.FromHfU8Packed().
    /// </summary>
    private static byte[] ReadRawPackedBytes(
        Dictionary<string, (string File, TensorInfo Info)> index, string name)
    {
        if (!index.TryGetValue(name, out var entry))
            throw new KeyNotFoundException($"Tensor '{name}' not found in any SafeTensors file");

        if (entry.Info.DType != "U8")
            throw new NotSupportedException(
                $"ReadRawPackedBytes requires U8 tensor, got '{entry.Info.DType}' for '{name}'");

        using var reader = SafeTensorsReader.Open(entry.File);
        return reader.ReadTensorBytes(name);
    }

    /// <summary>
    /// Read a U8 packed ternary weight tensor and unpack to sbyte[].
    /// HF BitNet stores weights as 2-bit packed U8: 4 ternary values per byte.
    /// Encoding: 2-bit 0→-1, 1→0, 2→+1.
    /// </summary>
    private static sbyte[] ReadPackedTernary(
        Dictionary<string, (string File, TensorInfo Info)> index, string name)
    {
        if (!index.TryGetValue(name, out var entry))
            throw new KeyNotFoundException($"Tensor '{name}' not found in any SafeTensors file");

        using var reader = SafeTensorsReader.Open(entry.File);
        var packed = reader.ReadTensorBytes(name);

        if (entry.Info.DType == "U8")
        {
            // Unpack 2-bit → sbyte ternary: each byte holds 4 values
            var result = new sbyte[packed.Length * 4];
            for (int i = 0; i < packed.Length; i++)
            {
                byte b = packed[i];
                int baseIdx = i * 4;
                result[baseIdx]     = (sbyte)((b & 0x03) - 1);       // bits 0-1
                result[baseIdx + 1] = (sbyte)(((b >> 2) & 0x03) - 1); // bits 2-3
                result[baseIdx + 2] = (sbyte)(((b >> 4) & 0x03) - 1); // bits 4-5
                result[baseIdx + 3] = (sbyte)(((b >> 6) & 0x03) - 1); // bits 6-7
            }
            return result;
        }

        if (entry.Info.DType == "I8")
        {
            var result = new sbyte[packed.Length];
            Buffer.BlockCopy(packed, 0, result, 0, packed.Length);
            return result;
        }

        throw new NotSupportedException(
            $"Tensor '{name}' has dtype '{entry.Info.DType}', expected U8 or I8");
    }

    /// <summary>
    /// Read BF16 embeddings and quantize to ternary sbyte[].
    /// Uses absmean thresholding per row (per token).
    /// </summary>
    private static sbyte[] ReadEmbeddings(
        Dictionary<string, (string File, TensorInfo Info)> index,
        string name, int vocabSize, int dim)
    {
        return ReadEmbeddingsStreaming(index, name, vocabSize, dim, pruner: null);
    }

    /// <summary>
    /// Read BF16 embeddings row-by-row, quantize to ternary, optionally pruning vocab.
    /// Only allocates one float[dim] row buffer — avoids the full vocabSize×dim float[] allocation.
    /// When pruner is non-null, only rows that map to a pruned ID are loaded.
    /// </summary>
    private static sbyte[] ReadEmbeddingsStreaming(
        Dictionary<string, (string File, TensorInfo Info)> index,
        string name, int vocabSize, int dim,
        VocabularyPruner? pruner)
    {
        if (!index.TryGetValue(name, out var entry))
            throw new KeyNotFoundException($"Tensor '{name}' not found");

        // For U8/I8 (already ternary), fall back to bulk read + prune
        if (entry.Info.DType == "U8" || entry.Info.DType == "I8")
        {
            var ternary = ReadPackedTernary(index, name);
            if (pruner != null)
                return pruner.PruneEmbeddings(ternary, dim);
            return ternary;
        }

        if (entry.Info.DType != "BF16" && entry.Info.DType != "F32")
            throw new NotSupportedException($"Embedding dtype '{entry.Info.DType}' not supported");

        int outputVocab = pruner?.PrunedVocabSize ?? vocabSize;
        var result = new sbyte[outputVocab * dim];
        var rowBuf = new float[dim];

        using var reader = SafeTensorsReader.Open(entry.File);

        for (int row = 0; row < vocabSize; row++)
        {
            int destRow;
            if (pruner != null)
            {
                destRow = pruner.MapTokenId(row);
                if (destRow < 0) continue; // pruned — skip this row entirely
            }
            else
            {
                destRow = row;
            }

            // Read single row from disk
            if (entry.Info.DType == "BF16")
                reader.ReadBFloat16Row(name, row, dim, rowBuf);
            else
                ReadFloat32Row(reader, name, row, dim, rowBuf);

            // Absmean quantization
            double sum = 0;
            for (int j = 0; j < dim; j++)
                sum += Math.Abs(rowBuf[j]);
            float threshold = (float)(sum / dim);

            int offset = destRow * dim;
            for (int j = 0; j < dim; j++)
            {
                float v = rowBuf[j];
                if (v > threshold) result[offset + j] = 1;
                else if (v < -threshold) result[offset + j] = -1;
                // else 0 (default)
            }
        }
        return result;
    }

    /// <summary>Read a single F32 row from a tensor.</summary>
    private static void ReadFloat32Row(SafeTensorsReader reader, string name, int row, int cols, Span<float> dest)
    {
        // F32 row reading not yet in SafeTensorsReader — fall back to BF16 path structure
        // This is less common; BF16 is the standard for BitNet embeddings
        throw new NotSupportedException("Streaming F32 row read not yet implemented — use BF16 model");
    }

    /// <summary>
    /// Expand GQA (grouped query attention) KV weights to full head count.
    /// KV heads are repeated to match the number of query heads.
    /// Input: [kvDim × inputDim], Output: [fullDim × inputDim]
    /// </summary>
    private static sbyte[] ExpandGQA(sbyte[] kvWeights, int kvDim, int fullDim,
        int numKvHeads, int numHeads, int headDim)
    {
        if (numKvHeads == numHeads)
            return kvWeights; // No GQA, already full size

        int inputDim = kvWeights.Length / kvDim;
        int repeatFactor = numHeads / numKvHeads;
        var expanded = new sbyte[fullDim * inputDim];

        for (int kvHead = 0; kvHead < numKvHeads; kvHead++)
        {
            int srcBase = kvHead * headDim * inputDim;
            for (int rep = 0; rep < repeatFactor; rep++)
            {
                int dstHead = kvHead * repeatFactor + rep;
                int dstBase = dstHead * headDim * inputDim;
                Array.Copy(kvWeights, srcBase, expanded, dstBase, headDim * inputDim);
            }
        }

        return expanded;
    }

    /// <summary>
    /// Project a wide FFN matrix [hidden × intermediate] down to [dim × dim]
    /// by truncating columns. Preserves the most important features.
    /// </summary>
    private static sbyte[] ProjectFfn(sbyte[] downProj, int dim, int ffnDim)
    {
        // down_proj shape: [hidden × intermediate]
        // We need [dim × dim], so take the first `dim` columns from each row.
        var result = new sbyte[dim * dim];
        int srcCols = ffnDim;
        int dstCols = dim;

        for (int r = 0; r < dim; r++)
        {
            int srcOffset = r * srcCols;
            int dstOffset = r * dstCols;
            int copyLen = Math.Min(dstCols, srcCols);
            Array.Copy(downProj, srcOffset, result, dstOffset, copyLen);
        }

        return result;
    }

    /// <summary>
    /// Build a tensor index across multiple SafeTensors files.
    /// Returns tensor_name → (file_path, tensor_info).
    /// </summary>
    private static Dictionary<string, (string File, TensorInfo Info)> BuildTensorIndex(
        string[] files)
    {
        var index = new Dictionary<string, (string, TensorInfo)>(StringComparer.Ordinal);

        foreach (var file in files)
        {
            using var reader = SafeTensorsReader.Open(file);
            foreach (var (name, info) in reader.Tensors)
            {
                index[name] = (file, info);
            }
        }

        return index;
    }

    // ── Config parsing ──────────────────────────────────────────────────────

    private static HfModelConfig ParseConfig(string path)
    {
        var json = File.ReadAllText(path);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        int numHeads = root.TryGetProperty("num_attention_heads", out var nh) ? nh.GetInt32() : 20;

        return new HfModelConfig(
            HiddenSize: root.TryGetProperty("hidden_size", out var h) ? h.GetInt32() : 2560,
            IntermediateSize: root.TryGetProperty("intermediate_size", out var im) ? im.GetInt32() : 6912,
            NumLayers: root.TryGetProperty("num_hidden_layers", out var l) ? l.GetInt32() : 30,
            NumHeads: numHeads,
            NumKvHeads: root.TryGetProperty("num_key_value_heads", out var nkv) ? nkv.GetInt32() : numHeads,
            VocabSize: root.TryGetProperty("vocab_size", out var v) ? v.GetInt32() : 128256,
            MaxSeqLen: root.TryGetProperty("max_position_embeddings", out var ms) ? ms.GetInt32() : 4096,
            TiedEmbeddings: root.TryGetProperty("tie_word_embeddings", out var tie) && tie.GetBoolean());
    }

    // ── Tokenizer parsing ───────────────────────────────────────────────────

    /// <summary>
    /// Parse a HuggingFace tokenizer.json to extract the vocabulary.
    /// Supports BPE (LLaMA 3) and Unigram tokenizer types.
    /// </summary>
    private static string[] ParseTokenizer(string path, int vocabSize)
    {
        var tokens = new string[vocabSize];

        // Fill with placeholders
        for (int i = 0; i < vocabSize; i++)
            tokens[i] = $"<{i}>";

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read);
        using var doc = JsonDocument.Parse(fs);
        var root = doc.RootElement;

        // Extract from model.vocab (BPE tokenizers like LLaMA 3)
        if (root.TryGetProperty("model", out var model))
        {
            if (model.TryGetProperty("vocab", out var vocab) &&
                vocab.ValueKind == JsonValueKind.Object)
            {
                foreach (var entry in vocab.EnumerateObject())
                {
                    int id = entry.Value.GetInt32();
                    if ((uint)id < (uint)vocabSize)
                        tokens[id] = UnescapeTokenString(entry.Name);
                }
            }
        }

        // Merge added_tokens (special tokens, control tokens)
        if (root.TryGetProperty("added_tokens", out var addedTokens) &&
            addedTokens.ValueKind == JsonValueKind.Array)
        {
            foreach (var tok in addedTokens.EnumerateArray())
            {
                if (tok.TryGetProperty("id", out var idProp) &&
                    tok.TryGetProperty("content", out var contentProp))
                {
                    int id = idProp.GetInt32();
                    if ((uint)id < (uint)vocabSize)
                        tokens[id] = contentProp.GetString() ?? $"<{id}>";
                }
            }
        }

        return tokens;
    }

    /// <summary>
    /// Unescape HF tokenizer string representations.
    /// HF uses 'Ġ' (U+0120) for leading space, 'Ċ' for newline, etc.
    /// </summary>
    private static string UnescapeTokenString(string token)
    {
        // LLaMA 3 / GPT tokenizers use Unicode replacements
        return token
            .Replace('\u0120', ' ')  // Ġ → space
            .Replace('\u010a', '\n') // Ċ → newline
            .Replace('\u0109', '\t') // ĉ → tab
            .Replace('\u000d', '\r'); // CR
    }

    private static string[] BuildFallbackVocab(int vocabSize)
    {
        var tokens = new string[vocabSize];
        tokens[0] = "<PAD>";
        tokens[1] = "<BOS>";
        tokens[2] = "<EOS>";
        tokens[3] = "<UNK>";

        const int asciiBase = 4;
        for (int i = 0; i < 95 && asciiBase + i < vocabSize; i++)
            tokens[asciiBase + i] = ((char)(' ' + i)).ToString();

        for (int i = 0; i < vocabSize; i++)
            tokens[i] ??= $"<{i}>";

        return tokens;
    }
}

// ── Data types ──────────────────────────────────────────────────────────────

/// <summary>HuggingFace model config.json values.</summary>
public readonly record struct HfModelConfig(
    int HiddenSize,
    int IntermediateSize,
    int NumLayers,
    int NumHeads,
    int NumKvHeads,
    int VocabSize,
    int MaxSeqLen,
    bool TiedEmbeddings);

/// <summary>Options for the HF → .bmwm import pipeline.</summary>
public sealed record ImportOptions
{
    /// <summary>Output path for the .bmwm file.</summary>
    public string OutputPath { get; init; } = "model.bmwm";

    /// <summary>Ratio of layers to drop from the end (0.0–0.5).</summary>
    public float LayerPruneRatio { get; init; }

    /// <summary>Prune vocabulary to domain-relevant tokens.</summary>
    public bool PruneVocabulary { get; init; }

    /// <summary>Ratio of attention heads to prune per layer.</summary>
    public float HeadPruneRatio { get; init; }

    /// <summary>L1 threshold for group-of-4 attention weight pruning.</summary>
    public int GroupPruneAttnThreshold { get; init; }

    /// <summary>L1 threshold for group-of-4 FFN weight pruning.</summary>
    public int GroupPruneFfnThreshold { get; init; }

    /// <summary>Maximum sequence length (may be lower than the model's native max).</summary>
    public int MaxSeqLen { get; init; } = 2048;

    /// <summary>Default: vocab prune + mild layer/head prune for admin domain.</summary>
    public static readonly ImportOptions DomainTrimmed = new()
    {
        PruneVocabulary = true,
        LayerPruneRatio = 0.25f,
        HeadPruneRatio = 0.10f,
        GroupPruneAttnThreshold = 1,
        GroupPruneFfnThreshold = 1,
    };

    /// <summary>Minimal pruning — keep as much of the model as possible.</summary>
    public static readonly ImportOptions Minimal = new()
    {
        PruneVocabulary = false,
    };
}

/// <summary>Result of an import operation.</summary>
public sealed record ImportResult(
    BitNetModelConfig Config,
    int ActiveVocab,
    int TokenTableSize,
    long FileSizeBytes,
    ImportLog Log);

/// <summary>Structured log from the import process.</summary>
public sealed class ImportLog
{
    private readonly List<string> _entries = new();
    public IReadOnlyList<string> Entries => _entries;

    public void Add(string message)
    {
        _entries.Add(message);
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write("    ");
        Console.ResetColor();
        Console.WriteLine(message);
    }
}
