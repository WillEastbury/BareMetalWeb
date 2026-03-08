using System.Runtime.CompilerServices;
using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Pure C# BitNet b1.58 ternary inference engine.
/// Demonstrates the architecture for ternary {-1,0,+1} model inference
/// using integer-only SIMD arithmetic. No floating point on the hot path.
///
/// Spike: provides the inference loop structure and layer operations.
/// A real deployment would load a trained GGUF-like ternary model file.
/// </summary>
public sealed class BitNetEngine : IBitNetEngine
{
    private readonly BitNetModelConfig _config;
    private TernaryLayer[]? _layers;
    private sbyte[]? _embeddings;       // [vocabSize × hiddenDim] or pruned
    private sbyte[]? _outputHead;       // [vocabSize × hiddenDim] or pruned
    private VocabularyPruner? _pruner;
    private PruneStats? _pruneStats;
    private ModelSizeStats? _modelStats;

    public bool IsLoaded => _layers is not null;

    /// <summary>Vocabulary pruning stats, available after load with pruning enabled.</summary>
    public PruneStats? VocabPruneStats => _pruneStats;

    /// <summary>Model size stats, available after load.</summary>
    public ModelSizeStats? ModelStats => _modelStats;

    public BitNetEngine(BitNetModelConfig? config = null)
    {
        _config = config ?? BitNetModelConfig.Default;
    }

    /// <summary>
    /// Load a test model with optional DataScaffold-informed vocabulary pruning
    /// and layer/head pruning.
    /// </summary>
    public void LoadTestModel(ModelLoadOptions? options = null)
    {
        options ??= ModelLoadOptions.Default;
        int dim = _config.HiddenDim;
        int vocab = _config.VocabSize;

        // 1. Create layers
        _layers = new TernaryLayer[_config.NumLayers];
        for (int i = 0; i < _config.NumLayers; i++)
            _layers[i] = TernaryLayer.CreateRandom(dim, _config.NumHeads);

        // 2. Create embedding and output head weights
        var rng = Random.Shared;
        _embeddings = new sbyte[vocab * dim];
        _outputHead = new sbyte[vocab * dim];
        for (int i = 0; i < _embeddings.Length; i++)
        {
            _embeddings[i] = (sbyte)(rng.Next(3) - 1);
            _outputHead[i] = (sbyte)(rng.Next(3) - 1);
        }

        // 3. Vocabulary pruning — informed by DataScaffold metadata
        int activeVocab = vocab;
        if (options.PruneVocabulary)
        {
            _pruner = options.CustomPruner ?? VocabularyPruner.FromDataScaffold();

            // Build a synthetic token list for the spike (real impl: read from model file)
            var tokenList = BuildSyntheticVocabulary(vocab);
            _pruner.BuildRemapTable(tokenList, specialTokenCount: options.SpecialTokenCount);

            _embeddings = _pruner.PruneEmbeddings(_embeddings, dim);
            _outputHead = _pruner.PruneOutputHead(_outputHead, dim);
            activeVocab = _pruner.PrunedVocabSize;

            _pruneStats = _pruner.GetStats(dim);
        }

        // 4. Layer pruning — drop last N layers for constrained domain
        if (options.LayerPruneRatio > 0f && _layers.Length > 1)
        {
            int keepLayers = Math.Max(1, (int)(_layers.Length * (1f - options.LayerPruneRatio)));
            _layers = ModelPruner.PruneLayers(_layers, keepLayers);
        }

        // 5. Attention head pruning — zero out low-importance heads
        if (options.HeadPruneRatio > 0f)
        {
            ModelPruner.PruneAttentionHeads(_layers, _config.NumHeads, options.HeadPruneRatio);
        }

        // 6. Calculate final model stats
        _modelStats = ModelPruner.CalculateSize(_layers, activeVocab, dim);
    }

    public ValueTask<string> GenerateAsync(
        ReadOnlyMemory<char> prompt,
        int maxTokens = 256,
        CancellationToken ct = default)
    {
        if (_layers is null)
            return ValueTask.FromResult("[Engine not loaded — no model file available]");

        // Spike: demonstrates the inference pipeline structure
        // Real impl would tokenise → embed → layer stack → logits → detokenise
        var result = RunInference(prompt.Span, maxTokens, ct);
        return ValueTask.FromResult(result);
    }

    private string RunInference(ReadOnlySpan<char> prompt, int maxTokens, CancellationToken ct)
    {
        int dim = _config.HiddenDim;

        // Allocate working buffers (would use ArrayPool in production for reuse)
        int[] hidden = new int[dim];
        int[] scratch = new int[dim];
        int[] output = new int[dim];

        // Simple hash-based "embedding" for spike (real impl: lookup table)
        InitHiddenState(prompt, hidden);

        // Forward pass through all layers
        for (int layerIdx = 0; layerIdx < _layers!.Length; layerIdx++)
        {
            ct.ThrowIfCancellationRequested();
            ref TernaryLayer layer = ref _layers[layerIdx];

            // Pre-norm
            TernaryTensor.RmsNormalize(hidden, scratch);

            // Ternary attention (simplified: single-head self-proj for spike)
            TernaryTensor.MatVecMultiply(
                layer.AttentionWeights, scratch, output,
                dim, dim);

            // Residual connection
            TernaryTensor.Add(hidden, output, hidden);

            // FFN: pre-norm → ternary matmul → residual
            TernaryTensor.RmsNormalize(hidden, scratch);
            TernaryTensor.MatVecMultiply(
                layer.FfnWeights, scratch, output,
                dim, dim);
            TernaryTensor.Add(hidden, output, hidden);
        }

        // Final norm
        TernaryTensor.RmsNormalize(hidden, output);

        // Top-k selection on output logits
        Span<int> topK = stackalloc int[3];
        TernaryTensor.TopK(output, topK, 3);

        return $"[BitNet spike] Inference complete. Top logit indices: {topK[0]}, {topK[1]}, {topK[2]}. " +
               $"Hidden dim: {dim}, layers: {_layers!.Length}. " +
               $"Vocab: {(_pruner is not null ? $"{_pruner.PrunedVocabSize} (pruned from {_pruner.OriginalVocabSize})" : $"{_config.VocabSize}")}. " +
               $"Prompt length: {prompt.Length} chars.";
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void InitHiddenState(ReadOnlySpan<char> prompt, Span<int> hidden)
    {
        hidden.Clear();
        // Distribute prompt character hashes across hidden dimensions
        for (int i = 0; i < prompt.Length; i++)
        {
            int idx = (i * 31 + prompt[i]) % hidden.Length;
            if (idx < 0) idx += hidden.Length;
            hidden[idx] += prompt[i] - 64; // Centre around zero
        }
    }

    private static IReadOnlyList<string> BuildSyntheticVocabulary(int vocabSize)
    {
        // Spike: creates a synthetic token list.
        // Real impl would read the tokeniser vocabulary from the model file.
        var tokens = new string[vocabSize];
        tokens[0] = "<PAD>";
        tokens[1] = "<BOS>";
        tokens[2] = "<EOS>";
        tokens[3] = "<UNK>";
        for (int i = 4; i < vocabSize; i++)
            tokens[i] = $"tok_{i}";

        // Inject real domain tokens at known positions so pruning is demonstrable
        string[] domainTokens = [
            "query", "entity", "list", "describe", "search", "status",
            "help", "index", "system", "field", "schema", "data",
            "count", "user", "session", "type", "name", "id",
            "create", "delete", "update", "show", "find", "get"
        ];
        for (int i = 0; i < domainTokens.Length && i + 4 < vocabSize; i++)
            tokens[i + 4] = domainTokens[i];

        return tokens;
    }
}

/// <summary>
/// Configuration for a BitNet ternary model.
/// </summary>
public readonly record struct BitNetModelConfig(
    int HiddenDim,
    int NumLayers,
    int NumHeads,
    int VocabSize,
    int MaxSeqLen)
{
    public static readonly BitNetModelConfig Default = new(
        HiddenDim: 128,
        NumLayers: 4,
        NumHeads: 4,
        VocabSize: 256,
        MaxSeqLen: 512);
}

/// <summary>
/// Options controlling model loading, pruning, and optimisation.
/// </summary>
public sealed record ModelLoadOptions
{
    /// <summary>Prune vocabulary against DataScaffold metadata on load.</summary>
    public bool PruneVocabulary { get; init; } = true;

    /// <summary>Ratio of layers to remove from the end (0.0 = none, 0.3 = drop 30%).</summary>
    public float LayerPruneRatio { get; init; }

    /// <summary>Ratio of attention heads to zero out per layer (0.0 = none, 0.25 = prune 25%).</summary>
    public float HeadPruneRatio { get; init; }

    /// <summary>Number of special tokens to always retain (PAD, BOS, EOS, UNK).</summary>
    public int SpecialTokenCount { get; init; } = 4;

    /// <summary>Optional custom pruner. If null, FromDataScaffold() is used.</summary>
    public VocabularyPruner? CustomPruner { get; init; }

    public static readonly ModelLoadOptions Default = new();

    /// <summary>Aggressive pruning: vocab + 25% layers + 25% heads.</summary>
    public static readonly ModelLoadOptions Aggressive = new()
    {
        PruneVocabulary = true,
        LayerPruneRatio = 0.25f,
        HeadPruneRatio = 0.25f,
    };

    /// <summary>No pruning — load the full model.</summary>
    public static readonly ModelLoadOptions NoPruning = new()
    {
        PruneVocabulary = false,
        LayerPruneRatio = 0f,
        HeadPruneRatio = 0f,
    };
}

/// <summary>
/// A single transformer layer with ternary weights.
/// </summary>
public struct TernaryLayer
{
    public sbyte[] AttentionWeights;
    public sbyte[] FfnWeights;

    public static TernaryLayer CreateRandom(int dim, int numHeads)
    {
        var rng = Random.Shared;
        var attn = new sbyte[dim * dim];
        var ffn = new sbyte[dim * dim];

        // Fill with ternary values: -1, 0, +1
        for (int i = 0; i < attn.Length; i++)
            attn[i] = (sbyte)(rng.Next(3) - 1);
        for (int i = 0; i < ffn.Length; i++)
            ffn[i] = (sbyte)(rng.Next(3) - 1);

        return new TernaryLayer { AttentionWeights = attn, FfnWeights = ffn };
    }
}
