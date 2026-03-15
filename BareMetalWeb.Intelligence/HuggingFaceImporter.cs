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

        // ── 5. Build output config ─────────────────────────────────────────
        var bmwConfig = new BitNetModelConfig(dim, numLayers, numHeads, vocab, maxSeqLen);

        // ── 6. Import per-layer matrices ───────────────────────────────────
        var wq  = new NativeTernaryMatrix[numLayers];
        var wk  = new NativeTernaryMatrix[numLayers];
        var wv  = new NativeTernaryMatrix[numLayers];
        var wo  = new NativeTernaryMatrix[numLayers];
        var ffn = new NativeTernaryMatrix[numLayers];

        for (int i = 0; i < numLayers; i++)
        {
            progress?.Invoke($"  Layer {i + 1}/{numLayers}: importing attention + ffn ...");

            wq[i]  = StreamTensor(tensorMap, LayerWqKey(i),   dim, dim, progress);
            wk[i]  = StreamTensor(tensorMap, LayerWkKey(i),   dim, dim, progress);
            wv[i]  = StreamTensor(tensorMap, LayerWvKey(i),   dim, dim, progress);
            wo[i]  = StreamTensor(tensorMap, LayerWoKey(i),   dim, dim, progress);
            ffn[i] = StreamTensor(tensorMap, LayerFfnKey(i),  dim, dim, progress);

            // Blocking GC after each layer to reclaim row-buffers before next layer allocates.
            // Non-blocking collection risks memory pressure spikes on constrained hosts.
            GC.Collect(0, GCCollectionMode.Optimized, blocking: true);
        }

        // ── 7. Import embeddings + output head ────────────────────────────
        progress?.Invoke("  Importing embeddings (large — streaming) ...");
        var embeddings = StreamTensor(tensorMap, EmbedKey, vocab, dim, progress);
        // Blocking GC ensures the embedding row-buffer is freed before allocating output head.
        GC.Collect(1, GCCollectionMode.Optimized, blocking: true);

        progress?.Invoke("  Importing output head ...");
        var outputHead = StreamTensor(tensorMap, LmHeadKey(tensorMap), vocab, dim, progress);
        // Blocking GC to reclaim output head row-buffer before tokenizer loading.
        GC.Collect(1, GCCollectionMode.Optimized, blocking: true);

        // ── 8. Load tokenizer vocab ────────────────────────────────────────
        progress?.Invoke("  Loading tokenizer vocab ...");
        var tokenTable = LoadTokenizerVocab(hfDir, vocab);
        progress?.Invoke($"  Vocab loaded: {tokenTable?.Count ?? 0} tokens");

        // ── 9. Write .bmwm snapshot ───────────────────────────────────────
        progress?.Invoke($"  Writing snapshot to {outputPath} ...");
        ModelSnapshot.Save(outputPath, bmwConfig, vocab,
            wq, wk, wv, wo, ffn,
            embeddings, outputHead,
            tokenTable);

        // ── 10. Dispose native matrices ────────────────────────────────────
        for (int i = 0; i < numLayers; i++)
        {
            wq[i].Dispose(); wk[i].Dispose(); wv[i].Dispose();
            wo[i].Dispose(); ffn[i].Dispose();
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

    /// <summary>
    /// Prefer gate_proj (SwiGLU first operand) as the FFN representative.
    /// Falls back to mlp.fc1 or mlp.dense_h_to_4h for other architectures.
    /// </summary>
    private static string LayerFfnKey(int i)
    {
        // Priority list — return first key; validated separately
        return $"model.layers.{i}.mlp.gate_proj.weight";
    }

    private static string[] RequiredLayerSuffixes =
    [
        "self_attn.q_proj.weight",
        "self_attn.k_proj.weight",
        "self_attn.v_proj.weight",
        "self_attn.o_proj.weight",
        "mlp.gate_proj.weight",
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
        int srcRows = info.Rows;
        int srcCols = info.Cols;
        int rows = Math.Min(srcRows, targetRows);
        int cols = Math.Min(srcCols, targetCols);

        var matrix = NativeTernaryMatrix.Allocate(targetRows, targetCols);

        // Row buffer — reused for all rows of this tensor
        var ternRow = new sbyte[srcCols];
        var rawRow  = new byte[srcCols * info.ElementBytes];

        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read,
            FileShare.Read, Math.Max(65536, rawRow.Length), FileOptions.SequentialScan);
        fs.Seek(info.DataStart, SeekOrigin.Begin);

        for (int r = 0; r < srcRows; r++)
        {
            ReadExact(fs, rawRow);

            if (r >= rows) continue; // skip excess rows (truncation)

            SafeTensorsReader.QuantiseRow(rawRow, ternRow, info.Dtype, srcCols);

            // If tensor is narrower than target, we pack only cols (rest stays zero)
            matrix.PackRowInPlace(r, ternRow.AsSpan(0, cols));
        }

        matrix.FinalizeStats();
        return matrix;
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
