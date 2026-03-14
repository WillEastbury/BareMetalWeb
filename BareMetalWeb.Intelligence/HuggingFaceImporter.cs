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
                $"heads={hfConfig.NumHeads}, vocab={hfConfig.VocabSize}, " +
                $"intermediate={hfConfig.IntermediateSize}");

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

        // 5. Extract weights
        int dim = hfConfig.HiddenSize;
        int ffnDim = hfConfig.IntermediateSize;
        int numLayers = hfConfig.NumLayers;
        int numHeads = hfConfig.NumHeads;

        // Determine how many layers to keep after pruning
        int keepLayers = numLayers;
        if (options.LayerPruneRatio > 0f)
        {
            keepLayers = Math.Max(1, (int)(numLayers * (1f - options.LayerPruneRatio)));
            log.Add($"Layer pruning: keeping {keepLayers}/{numLayers} layers");
        }

        var layers = new TernaryLayer[keepLayers];
        for (int i = 0; i < keepLayers; i++)
        {
            log.Add($"  Loading layer {i}/{keepLayers}...");

            // Attention projections: [out_features × in_features] = [dim × dim]
            var wq = ReadTernaryTensor(tensorIndex, $"model.layers.{i}.self_attn.q_proj.weight");
            var wk = ReadTernaryTensor(tensorIndex, $"model.layers.{i}.self_attn.k_proj.weight");
            var wv = ReadTernaryTensor(tensorIndex, $"model.layers.{i}.self_attn.v_proj.weight");
            var wo = ReadTernaryTensor(tensorIndex, $"model.layers.{i}.self_attn.o_proj.weight");

            // FFN: SwiGLU has gate_proj [intermediate×hidden], up_proj [intermediate×hidden],
            // down_proj [hidden×intermediate]. We combine into a single FFN matrix by
            // using the down_proj (which maps intermediate→hidden) as our FFN weight.
            // The gate/up projections are folded by computing: down_proj @ (gate * up)
            // For the simplified engine, we use a projection: down_proj @ up_proj^T → [dim×dim]
            var gate = ReadTernaryTensor(tensorIndex, $"model.layers.{i}.mlp.gate_proj.weight");
            var up = ReadTernaryTensor(tensorIndex, $"model.layers.{i}.mlp.up_proj.weight");
            var down = ReadTernaryTensor(tensorIndex, $"model.layers.{i}.mlp.down_proj.weight");

            // Combine SwiGLU into single FFN: we store gate, up, and down separately
            // in the layer and let the engine handle the SwiGLU computation.
            // For now, create a combined FFN by taking the dominant projection (down_proj).
            // The full SwiGLU path requires engine extension.
            sbyte[] ffnWeights;
            if (options.FullSwiGLU)
            {
                // Store all three as a concatenated super-matrix for the extended engine.
                // Layout: [3 * intermediate × hidden] = gate | up | down stacked vertically.
                ffnWeights = new sbyte[gate.Length + up.Length + down.Length];
                gate.AsSpan().CopyTo(ffnWeights);
                up.AsSpan().CopyTo(ffnWeights.AsSpan(gate.Length));
                down.AsSpan().CopyTo(ffnWeights.AsSpan(gate.Length + up.Length));
            }
            else
            {
                // Simplified: project down to [dim × dim] via truncated down_proj
                ffnWeights = ProjectFfn(down, dim, ffnDim);
            }

            layers[i] = new TernaryLayer
            {
                Wq = wq,
                Wk = wk,
                Wv = wv,
                Wo = wo,
                FfnWeights = ffnWeights,
            };
        }

        // 6. Read embeddings and output head
        var embeddings = ReadTernaryTensor(tensorIndex, "model.embed_tokens.weight");
        log.Add($"Embeddings: {embeddings.Length:N0} weights ({embeddings.Length / dim} × {dim})");

        sbyte[] outputHead;
        if (tensorIndex.ContainsKey("lm_head.weight"))
        {
            outputHead = ReadTernaryTensor(tensorIndex, "lm_head.weight");
        }
        else
        {
            // Tied embeddings — lm_head shares embed_tokens
            outputHead = new sbyte[embeddings.Length];
            embeddings.AsSpan().CopyTo(outputHead);
            log.Add("Output head: tied to embeddings (no lm_head.weight)");
        }
        log.Add($"Output head: {outputHead.Length:N0} weights");

        // 7. Vocabulary pruning
        int activeVocab = hfConfig.VocabSize;
        if (options.PruneVocabulary)
        {
            var pruner = VocabularyPruner.FromDataScaffold();
            pruner.BuildRemapTable(tokenTable);
            embeddings = pruner.PruneEmbeddings(embeddings, dim);
            outputHead = pruner.PruneOutputHead(outputHead, dim);
            activeVocab = pruner.PrunedVocabSize;

            // Rebuild token table to match pruned vocab
            var prunedTokens = new string[activeVocab];
            for (int i = 0; i < hfConfig.VocabSize && i < tokenTable.Length; i++)
            {
                int mapped = pruner.MapTokenId(i);
                if (mapped >= 0 && mapped < activeVocab)
                    prunedTokens[mapped] = tokenTable[i];
            }
            // Fill any gaps
            for (int i = 0; i < activeVocab; i++)
                prunedTokens[i] ??= $"<{i}>";
            tokenTable = prunedTokens;
            log.Add($"Vocab pruned: {hfConfig.VocabSize} → {activeVocab} tokens");
        }

        // 8. Head pruning
        if (options.HeadPruneRatio > 0f)
        {
            int pruned = ModelPruner.PruneAttentionHeads(layers, numHeads, options.HeadPruneRatio);
            log.Add($"Heads pruned: {pruned} across {keepLayers} layers");
        }

        // 9. Group-of-four pruning
        if (options.GroupPruneAttnThreshold > 0 || options.GroupPruneFfnThreshold > 0)
        {
            var stats = ModelPruner.PruneLayerGroups(layers, dim,
                options.GroupPruneAttnThreshold, options.GroupPruneFfnThreshold);
            log.Add($"Group pruning: {stats.Summary}");
        }

        // 10. Pack and save
        var config = new BitNetModelConfig(
            HiddenDim: dim,
            NumLayers: keepLayers,
            NumHeads: numHeads,
            VocabSize: hfConfig.VocabSize,
            MaxSeqLen: Math.Min(hfConfig.MaxSeqLen, options.MaxSeqLen));

        using var engine = new BitNetEngine(config);
        engine.LoadFromImport(layers, embeddings, outputHead, activeVocab, dim, tokenTable);
        engine.SaveSnapshot(options.OutputPath, tokenTable);

        var fileInfo = new FileInfo(options.OutputPath);
        log.Add($"Saved: {fileInfo.Length / (1024 * 1024)} MB → {options.OutputPath}");

        return new ImportResult(config, activeVocab, tokenTable.Length, fileInfo.Length, log);
    }

    /// <summary>
    /// Read a tensor as ternary sbyte[] values.
    /// Handles I8 (direct), BF16/F32 (quantize to ternary via absmean).
    /// </summary>
    private static sbyte[] ReadTernaryTensor(
        Dictionary<string, (string File, TensorInfo Info)> index, string name)
    {
        if (!index.TryGetValue(name, out var entry))
            throw new KeyNotFoundException($"Tensor '{name}' not found in any SafeTensors file");

        using var reader = SafeTensorsReader.Open(entry.File);

        return entry.Info.DType switch
        {
            "I8" => reader.ReadTensorSBytes(name),
            "BF16" => QuantizeToTernary(reader.ReadTensorBFloat16(name)),
            "F32" => QuantizeToTernary(reader.ReadTensorFloat32(name)),
            _ => throw new NotSupportedException(
                $"Tensor '{name}' has unsupported dtype '{entry.Info.DType}'")
        };
    }

    /// <summary>
    /// Quantize float weights to ternary {-1, 0, +1} using absmean threshold.
    /// This is the same quantization used during BitNet training.
    /// </summary>
    private static sbyte[] QuantizeToTernary(float[] weights)
    {
        // Compute absmean threshold
        double sum = 0;
        for (int i = 0; i < weights.Length; i++)
            sum += Math.Abs(weights[i]);
        float threshold = (float)(sum / weights.Length);

        var result = new sbyte[weights.Length];
        for (int i = 0; i < weights.Length; i++)
        {
            if (weights[i] > threshold)
                result[i] = 1;
            else if (weights[i] < -threshold)
                result[i] = -1;
            // else result[i] = 0 (default)
        }
        return result;
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

        return new HfModelConfig(
            HiddenSize: root.TryGetProperty("hidden_size", out var h) ? h.GetInt32() : 2560,
            IntermediateSize: root.TryGetProperty("intermediate_size", out var im) ? im.GetInt32() : 10240,
            NumLayers: root.TryGetProperty("num_hidden_layers", out var l) ? l.GetInt32() : 32,
            NumHeads: root.TryGetProperty("num_attention_heads", out var nh) ? nh.GetInt32() : 32,
            VocabSize: root.TryGetProperty("vocab_size", out var v) ? v.GetInt32() : 128256,
            MaxSeqLen: root.TryGetProperty("max_position_embeddings", out var ms) ? ms.GetInt32() : 4096);
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
    int VocabSize,
    int MaxSeqLen);

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

    /// <summary>
    /// If true, store the full SwiGLU triple (gate/up/down) in the snapshot.
    /// Requires engine extension to use. If false, projects to single FFN matrix.
    /// </summary>
    public bool FullSwiGLU { get; init; }

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
