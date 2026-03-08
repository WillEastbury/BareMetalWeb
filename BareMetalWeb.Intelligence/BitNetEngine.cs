using System.Runtime.CompilerServices;
using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Pure C# BitNet b1.58 ternary inference engine.
/// Demonstrates the architecture for ternary {-1,0,+1} model inference
/// using integer-only SIMD arithmetic. No floating point on the hot path.
///
/// After load + pruning, weights are compressed to 2-bit packed native memory
/// (NativeTernaryMatrix) — 4× smaller than sbyte[] and entirely off the GC heap.
/// </summary>
public sealed class BitNetEngine : IBitNetEngine, IDisposable
{
    private readonly BitNetModelConfig _config;
    private VocabularyPruner? _pruner;
    private PruneStats? _pruneStats;
    private ModelSizeStats? _modelStats;
    private GroupPruneStats? _groupPruneStats;
    private SemanticPruningStats? _semanticPruneStats;

    // Compressed storage — 2-bit packed in native (unmanaged) memory
    private NativeTernaryMatrix[]? _compressedAttn;
    private NativeTernaryMatrix[]? _compressedFfn;
    private NativeTernaryMatrix? _compressedEmbeddings;
    private NativeTernaryMatrix? _compressedOutputHead;
    private LazySnapshot? _lazySnapshot; // holds mmap open when lazy-loaded
    private int _layerCount;
    private bool _isLoaded;

    public bool IsLoaded => _isLoaded;

    /// <summary>Vocabulary pruning stats, available after load with pruning enabled.</summary>
    public PruneStats? VocabPruneStats => _pruneStats;

    /// <summary>Model size stats, available after load.</summary>
    public ModelSizeStats? ModelStats => _modelStats;

    /// <summary>Group-of-four structured pruning stats, available after load.</summary>
    public GroupPruneStats? GroupPruneInfo => _groupPruneStats;

    /// <summary>Coarse-to-fine semantic pruning stats, available after load.</summary>
    public SemanticPruningStats? SemanticPruneInfo => _semanticPruneStats;

    /// <summary>Total native (unmanaged) bytes allocated for compressed weights.</summary>
    public long NativeBytesAllocated { get; private set; }

    /// <summary>Per-layer sparsity statistics (attention + FFN), available after load.</summary>
    public IReadOnlyList<(MatrixStats Attn, MatrixStats Ffn)>? LayerStats { get; private set; }

    public BitNetEngine(BitNetModelConfig? config = null)
    {
        _config = config ?? BitNetModelConfig.Default;
    }

    /// <summary>
    /// Load a test model with optional DataScaffold-informed vocabulary pruning
    /// and layer/head pruning. After pruning, compresses all weights to 2-bit
    /// packed native memory and frees managed arrays.
    /// </summary>
    public void LoadTestModel(ModelLoadOptions? options = null)
    {
        options ??= ModelLoadOptions.Default;
        int dim = _config.HiddenDim;
        int vocab = _config.VocabSize;

        // 1. Create layers (temporary managed arrays)
        var layers = new TernaryLayer[_config.NumLayers];
        for (int i = 0; i < _config.NumLayers; i++)
            layers[i] = TernaryLayer.CreateRandom(dim, _config.NumHeads);

        // 2. Create embedding and output head weights
        var rng = Random.Shared;
        var embeddings = new sbyte[vocab * dim];
        var outputHead = new sbyte[vocab * dim];
        for (int i = 0; i < embeddings.Length; i++)
        {
            embeddings[i] = (sbyte)(rng.Next(3) - 1);
            outputHead[i] = (sbyte)(rng.Next(3) - 1);
        }

        // 3. Vocabulary pruning — informed by DataScaffold metadata
        int activeVocab = vocab;
        if (options.PruneVocabulary)
        {
            _pruner = options.CustomPruner ?? VocabularyPruner.FromDataScaffold();
            var tokenList = BuildSyntheticVocabulary(vocab);
            _pruner.BuildRemapTable(tokenList, specialTokenCount: options.SpecialTokenCount);

            embeddings = _pruner.PruneEmbeddings(embeddings, dim);
            outputHead = _pruner.PruneOutputHead(outputHead, dim);
            activeVocab = _pruner.PrunedVocabSize;

            _pruneStats = _pruner.GetStats(dim);
        }

        // 4. Layer pruning — drop last N layers for constrained domain
        if (options.LayerPruneRatio > 0f && layers.Length > 1)
        {
            int keepLayers = Math.Max(1, (int)(layers.Length * (1f - options.LayerPruneRatio)));
            layers = ModelPruner.PruneLayers(layers, keepLayers);
        }

        // 5. Attention head pruning — zero out low-importance heads
        if (options.HeadPruneRatio > 0f)
        {
            ModelPruner.PruneAttentionHeads(layers, _config.NumHeads, options.HeadPruneRatio);
        }

        // 6. Group-of-four structured pruning — aligns with packed byte boundaries
        if (options.GroupPruneAttnThreshold > 0 || options.GroupPruneFfnThreshold > 0)
        {
            _groupPruneStats = ModelPruner.PruneLayerGroups(
                layers, dim,
                options.GroupPruneAttnThreshold,
                options.GroupPruneFfnThreshold);
        }

        // 7. Coarse-to-fine semantic pruning — after magnitude, before packing
        if (options.SemanticPruning)
        {
            _semanticPruneStats = SemanticPruner.Prune(
                layers, dim, _config.NumHeads,
                corpus: null,
                headPruneRatio: options.SemanticHeadPruneRatio,
                neuronPruneRatio: options.SemanticNeuronPruneRatio,
                blockPruneRatio: options.SemanticBlockPruneRatio,
                driftThreshold: options.SemanticDriftThreshold);
        }

        // 8. Calculate logical model stats (after all pruning)
        _modelStats = ModelPruner.CalculateSize(layers, activeVocab, dim);

        // 9. Compress to 2-bit packed native memory
        CompressToNative(layers, embeddings, outputHead, activeVocab, dim);

        _isLoaded = true;
    }

    /// <summary>
    /// Pack all weight matrices from sbyte[] into 2-bit NativeTernaryMatrix.
    /// After packing, managed arrays become eligible for GC.
    /// </summary>
    private void CompressToNative(
        TernaryLayer[] layers,
        sbyte[] embeddings,
        sbyte[] outputHead,
        int activeVocab,
        int dim)
    {
        // Dispose any previous compressed data
        DisposeNative();

        _layerCount = layers.Length;
        _compressedAttn = new NativeTernaryMatrix[layers.Length];
        _compressedFfn = new NativeTernaryMatrix[layers.Length];

        for (int i = 0; i < layers.Length; i++)
        {
            _compressedAttn[i] = NativeTernaryMatrix.Pack(layers[i].AttentionWeights, dim, dim);
            _compressedFfn[i] = NativeTernaryMatrix.Pack(layers[i].FfnWeights, dim, dim);
        }

        _compressedEmbeddings = NativeTernaryMatrix.Pack(embeddings, activeVocab, dim);
        _compressedOutputHead = NativeTernaryMatrix.Pack(outputHead, activeVocab, dim);

        // Calculate total native allocation and per-layer stats
        NativeBytesAllocated = 0;
        var layerStatsList = new (MatrixStats Attn, MatrixStats Ffn)[layers.Length];
        for (int i = 0; i < layers.Length; i++)
        {
            NativeBytesAllocated += _compressedAttn[i].BytesAllocated;
            NativeBytesAllocated += _compressedFfn[i].BytesAllocated;
            layerStatsList[i] = (_compressedAttn[i].Stats, _compressedFfn[i].Stats);
        }
        NativeBytesAllocated += _compressedEmbeddings.BytesAllocated;
        NativeBytesAllocated += _compressedOutputHead.BytesAllocated;
        LayerStats = layerStatsList;
    }

    /// <summary>
    /// Save the current pruned + packed model state to a binary snapshot.
    /// The snapshot can be loaded later with <see cref="LoadSnapshot"/> to
    /// skip all pruning and compression steps.
    /// </summary>
    public void SaveSnapshot(string path, IReadOnlyList<string>? tokenTable = null)
    {
        if (!_isLoaded || _compressedAttn is null || _compressedFfn is null
            || _compressedEmbeddings is null || _compressedOutputHead is null)
            throw new InvalidOperationException("No model loaded to snapshot");

        int activeVocab = _pruner?.PrunedVocabSize ?? _config.VocabSize;

        ModelSnapshot.Save(path, _config, activeVocab,
            _compressedAttn, _compressedFfn,
            _compressedEmbeddings, _compressedOutputHead,
            tokenTable);
    }

    /// <summary>
    /// Load a model from a binary snapshot file. Reconstructs
    /// NativeTernaryMatrix instances directly from packed data —
    /// no pruning or compression needed, loads in milliseconds.
    /// </summary>
    /// <param name="path">Path to the .bmwm snapshot file.</param>
    /// <param name="memoryMapped">If true, use memory-mapped I/O (avoids large managed copies).</param>
    public void LoadSnapshot(string path, bool memoryMapped = false)
    {
        var snapshot = memoryMapped
            ? ModelSnapshot.LoadMapped(path)
            : ModelSnapshot.Load(path);

        // Transfer ownership from snapshot to engine
        DisposeNative();

        _layerCount = snapshot.Attn.Length;
        _compressedAttn = snapshot.Attn;
        _compressedFfn = snapshot.Ffn;
        _compressedEmbeddings = snapshot.Embeddings;
        _compressedOutputHead = snapshot.OutputHead;

        NativeBytesAllocated = 0;
        var layerStatsList = new (MatrixStats Attn, MatrixStats Ffn)[_layerCount];
        for (int i = 0; i < _layerCount; i++)
        {
            NativeBytesAllocated += _compressedAttn[i].BytesAllocated;
            NativeBytesAllocated += _compressedFfn[i].BytesAllocated;
            layerStatsList[i] = (_compressedAttn[i].Stats, _compressedFfn[i].Stats);
        }
        NativeBytesAllocated += _compressedEmbeddings.BytesAllocated;
        NativeBytesAllocated += _compressedOutputHead.BytesAllocated;
        LayerStats = layerStatsList;

        // Compute model stats from loaded data
        long totalWeights = 0;
        long zeroWeights = 0;
        for (int i = 0; i < _layerCount; i++)
        {
            totalWeights += _compressedAttn[i].Stats.LogicalWeights;
            totalWeights += _compressedFfn[i].Stats.LogicalWeights;
            zeroWeights += _compressedAttn[i].Stats.ZeroByteCount * 4L;
            zeroWeights += _compressedFfn[i].Stats.ZeroByteCount * 4L;
        }
        long embWeights = (long)_compressedEmbeddings.Stats.LogicalWeights
                        + _compressedOutputHead.Stats.LogicalWeights;

        _modelStats = new ModelSizeStats(
            TotalWeights: totalWeights + embWeights,
            LayerWeights: totalWeights,
            EmbeddingWeights: embWeights,
            ZeroWeights: zeroWeights,
            StoredBytes: totalWeights + embWeights,
            PackedBytes: NativeBytesAllocated,
            Sparsity: totalWeights > 0 ? (float)zeroWeights / totalWeights : 0f,
            LayerCount: _layerCount);

        _isLoaded = true;
    }

    /// <summary>
    /// Load a model from a snapshot using persistent memory-mapping.
    /// Matrices reference the mapped file directly — zero copy, instant load.
    /// The OS demand-pages data on first access; layers skipped by early exit
    /// never consume physical memory.
    /// </summary>
    public void LoadSnapshotLazy(string path)
    {
        DisposeNative();

        _lazySnapshot = ModelSnapshot.LoadLazy(path);
        var snap = _lazySnapshot.Data;

        _layerCount = snap.Attn.Length;
        _compressedAttn = snap.Attn;
        _compressedFfn = snap.Ffn;
        _compressedEmbeddings = snap.Embeddings;
        _compressedOutputHead = snap.OutputHead;

        NativeBytesAllocated = 0; // no native alloc — data lives in mmap
        var layerStatsList = new (MatrixStats Attn, MatrixStats Ffn)[_layerCount];
        for (int i = 0; i < _layerCount; i++)
        {
            layerStatsList[i] = (_compressedAttn[i].Stats, _compressedFfn[i].Stats);
        }
        LayerStats = layerStatsList;

        long totalWeights = 0;
        for (int i = 0; i < _layerCount; i++)
        {
            totalWeights += _compressedAttn[i].Stats.LogicalWeights;
            totalWeights += _compressedFfn[i].Stats.LogicalWeights;
        }
        long embWeights = (long)_compressedEmbeddings.Stats.LogicalWeights
                        + _compressedOutputHead.Stats.LogicalWeights;

        _modelStats = new ModelSizeStats(
            TotalWeights: totalWeights + embWeights,
            LayerWeights: totalWeights,
            EmbeddingWeights: embWeights,
            ZeroWeights: 0, // stats deferred for mmap
            StoredBytes: totalWeights + embWeights,
            PackedBytes: 0,
            Sparsity: 0f, // unknown until first access
            LayerCount: _layerCount);

        _isLoaded = true;
    }

    public ValueTask<string> GenerateAsync(
        ReadOnlyMemory<char> prompt,
        int maxTokens = 256,
        CancellationToken ct = default)
    {
        if (!_isLoaded)
            return ValueTask.FromResult("[Engine not loaded — no model file available]");

        var result = RunInference(prompt.Span, maxTokens, ct);
        return ValueTask.FromResult(result);
    }

    private const float EarlyExitThreshold = 0.9995f;
    private const int EarlyExitMinLayers = 2;

    private string RunInference(ReadOnlySpan<char> prompt, int maxTokens, CancellationToken ct)
    {
        int dim = _config.HiddenDim;

        int[] hidden = new int[dim];
        int[] scratch = new int[dim];
        int[] output = new int[dim];
        int[] prevHidden = new int[dim];

        InitHiddenState(prompt, hidden);

        int layersExecuted = _layerCount;

        // Forward pass through compressed layers (2-bit packed, native memory)
        for (int layerIdx = 0; layerIdx < _layerCount; layerIdx++)
        {
            ct.ThrowIfCancellationRequested();

            // Save state for early exit stability check
            if (layerIdx >= EarlyExitMinLayers)
                Array.Copy(hidden, prevHidden, dim);

            // Pre-norm → attention → residual
            TernaryTensor.RmsNormalize(hidden, scratch);
            _compressedAttn![layerIdx].MatVecMultiply(scratch, output);
            TernaryTensor.Add(hidden, output, hidden);

            // Pre-norm → FFN → residual
            TernaryTensor.RmsNormalize(hidden, scratch);
            _compressedFfn![layerIdx].MatVecMultiply(scratch, output);
            TernaryTensor.Add(hidden, output, hidden);

            // Early exit: if hidden state barely changed, skip remaining layers
            if (layerIdx >= EarlyExitMinLayers && layerIdx < _layerCount - 1)
            {
                float similarity = CosineSimilarityInt(prevHidden, hidden);
                if (similarity > EarlyExitThreshold)
                {
                    layersExecuted = layerIdx + 1;
                    break;
                }
            }
        }

        // Final normalization
        TernaryTensor.RmsNormalize(hidden, scratch);

        // Project through output head to get vocabulary logits
        int vocabSize = _compressedOutputHead!.Rows;
        int[] logits = new int[vocabSize];
        _compressedOutputHead.MatVecMultiply(scratch, logits);

        // Top-k on actual vocabulary logits
        Span<int> topK = stackalloc int[3];
        TernaryTensor.TopK(logits, topK, 3);

        return $"[BitNet spike] Inference complete. Top logit indices: {topK[0]}, {topK[1]}, {topK[2]}. " +
               $"Hidden dim: {dim}, layers: {layersExecuted}/{_layerCount}. " +
               $"Vocab: {(_pruner is not null ? $"{_pruner.PrunedVocabSize} (pruned from {_pruner.OriginalVocabSize})" : $"{_config.VocabSize}")}. " +
               $"Prompt length: {prompt.Length} chars.";
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float CosineSimilarityInt(int[] a, int[] b)
    {
        long dot = 0, normA = 0, normB = 0;
        for (int i = 0; i < a.Length; i++)
        {
            dot += (long)a[i] * b[i];
            normA += (long)a[i] * a[i];
            normB += (long)b[i] * b[i];
        }
        double denom = Math.Sqrt((double)normA) * Math.Sqrt((double)normB);
        return denom > 1e-10 ? (float)(dot / denom) : 0f;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void InitHiddenState(ReadOnlySpan<char> prompt, Span<int> hidden)
    {
        hidden.Clear();
        for (int i = 0; i < prompt.Length; i++)
        {
            int idx = (i * 31 + prompt[i]) % hidden.Length;
            if (idx < 0) idx += hidden.Length;
            hidden[idx] += prompt[i] - 64;
        }
    }

    private static IReadOnlyList<string> BuildSyntheticVocabulary(int vocabSize)
    {
        var tokens = new string[vocabSize];
        tokens[0] = "<PAD>";
        tokens[1] = "<BOS>";
        tokens[2] = "<EOS>";
        tokens[3] = "<UNK>";
        for (int i = 4; i < vocabSize; i++)
            tokens[i] = $"tok_{i}";

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

    private void DisposeNative()
    {
        if (_lazySnapshot is not null)
        {
            // LazySnapshot owns the mmap — disposing it releases everything
            _lazySnapshot.Dispose();
            _lazySnapshot = null;
            _compressedAttn = null;
            _compressedFfn = null;
            _compressedEmbeddings = null;
            _compressedOutputHead = null;
        }
        else
        {
            if (_compressedAttn is not null)
            {
                foreach (var m in _compressedAttn) m?.Dispose();
                _compressedAttn = null;
            }
            if (_compressedFfn is not null)
            {
                foreach (var m in _compressedFfn) m?.Dispose();
                _compressedFfn = null;
            }
            _compressedEmbeddings?.Dispose();
            _compressedOutputHead?.Dispose();
            _compressedEmbeddings = null;
            _compressedOutputHead = null;
        }
        NativeBytesAllocated = 0;
        LayerStats = null;
    }

    public void Dispose()
    {
        DisposeNative();
        _isLoaded = false;
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

    /// <summary>
    /// Group-of-four L1 threshold for attention weights.
    /// Groups with L1 sum ≤ threshold are zeroed (0 = disabled, 1 = conservative, 2 = moderate).
    /// </summary>
    public int GroupPruneAttnThreshold { get; init; }

    /// <summary>
    /// Group-of-four L1 threshold for FFN weights.
    /// FFN layers tolerate more aggressive pruning (0 = disabled, 2 = moderate, 3 = aggressive).
    /// </summary>
    public int GroupPruneFfnThreshold { get; init; }

    /// <summary>Enable coarse-to-fine semantic pruning after magnitude pruning.</summary>
    public bool SemanticPruning { get; init; }

    /// <summary>Ratio of attention heads to evaluate for semantic pruning (0.0–1.0).</summary>
    public float SemanticHeadPruneRatio { get; init; } = 0.20f;

    /// <summary>Ratio of neurons to evaluate for semantic pruning (0.0–1.0).</summary>
    public float SemanticNeuronPruneRatio { get; init; } = 0.15f;

    /// <summary>Ratio of blocks to evaluate for semantic pruning (0.0–1.0).</summary>
    public float SemanticBlockPruneRatio { get; init; } = 0.10f;

    /// <summary>Minimum cosine similarity for hidden-state drift screening (0.90–0.99).</summary>
    public float SemanticDriftThreshold { get; init; } = 0.95f;

    /// <summary>Number of special tokens to always retain (PAD, BOS, EOS, UNK).</summary>
    public int SpecialTokenCount { get; init; } = 4;

    /// <summary>Optional custom pruner. If null, FromDataScaffold() is used.</summary>
    public VocabularyPruner? CustomPruner { get; init; }

    public static readonly ModelLoadOptions Default = new();

    /// <summary>Aggressive pruning: vocab + 25% layers + 25% heads + group-of-4.</summary>
    public static readonly ModelLoadOptions Aggressive = new()
    {
        PruneVocabulary = true,
        LayerPruneRatio = 0.25f,
        HeadPruneRatio = 0.25f,
        GroupPruneAttnThreshold = 1,
        GroupPruneFfnThreshold = 2,
    };

    /// <summary>No pruning — load the full model.</summary>
    public static readonly ModelLoadOptions NoPruning = new()
    {
        PruneVocabulary = false,
        LayerPruneRatio = 0f,
        HeadPruneRatio = 0f,
        GroupPruneAttnThreshold = 0,
        GroupPruneFfnThreshold = 0,
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
