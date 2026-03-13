using System.Runtime.CompilerServices;
using System.Threading;
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
/// 
public sealed class BitNetEngine : IBitNetEngine, IDisposable
{
    private readonly BitNetModelConfig _config;
    private VocabularyPruner? _pruner;
    private PruneStats? _pruneStats;
    private ModelSizeStats? _modelStats;
    private GroupPruneStats? _groupPruneStats;
    private SemanticPruningStats? _semanticPruneStats;

    // Compressed storage — 2-bit packed in native (unmanaged) memory.
    // Each layer has four attention projections (Q, K, V, O) plus FFN.
    private NativeTernaryMatrix[]? _compressedWq;
    private NativeTernaryMatrix[]? _compressedWk;
    private NativeTernaryMatrix[]? _compressedWv;
    private NativeTernaryMatrix[]? _compressedWo;
    private NativeTernaryMatrix[]? _compressedFfn;
    private NativeTernaryMatrix? _compressedEmbeddings;
    private NativeTernaryMatrix? _compressedOutputHead;
    private LazySnapshot? _lazySnapshot; // holds mmap open when lazy-loaded
    private int _layerCount;
    private bool _isLoaded;

    // Pre-allocated inference buffers — zero GC pressure on the hot path.
    // All allocated once in CompressToNative / LoadSnapshot and reused each call.
    private int[]? _bufHidden;    // current hidden state [dim]
    private int[]? _bufNorm;      // RMS-normalised hidden  [dim]
    private int[]? _bufQ;         // query projection        [dim]
    private int[]? _bufK;         // key projection          [dim]
    private int[]? _bufV;         // value projection        [dim]
    private int[]? _bufPreWo;     // pre-Wo attention output [dim]
    private int[]? _bufScores;    // per-head dot-product scores [maxSeqLen]
    private int[]? _bufLogits;    // output head logits [vocabSize]

    // Per-layer KV cache — stores K and V for every past token position.
    // _kvCacheK[layer] = int[maxSeqLen × dim],  _kvCacheV[layer] = int[maxSeqLen × dim]
    private int[][]? _kvCacheK;
    private int[][]? _kvCacheV;

    // Vocabulary strings for token decoding, set at load time.
    private string[]? _tokenTable;

    // Serialises inference so pre-allocated buffers are not clobbered by concurrent calls.
    private readonly SemaphoreSlim _inferLock = new SemaphoreSlim(1, 1);

    // Lifetime token / throughput counters — updated atomically on each inference
    private long _totalTokensIn;
    private long _totalTokensOut;
    private long _totalRequests;
    private long _totalInferenceMs;

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

    /// <summary>
    /// Return aggregated memory, token throughput, and accuracy metrics for
    /// the pipeline. Returns <see langword="null"/> if no model is loaded yet.
    /// </summary>
    public BitNetPipelineMetrics? GetMetrics()
    {
        if (!_isLoaded || _modelStats is null)
            return null;

        var ms = _modelStats.Value;
        var sp = _semanticPruneStats;

        int origVocab = _pruner?.OriginalVocabSize ?? _config.VocabSize;
        int prunedVocab = _pruner?.PrunedVocabSize ?? _config.VocabSize;

        return new BitNetPipelineMetrics(
            OriginalWeightBytes: ms.StoredBytes,
            TrimmedWeightBytes: ms.PackedBytes,
            CompressionSavings: ms.CompressionSavings,
            TotalWeights: ms.TotalWeights,
            ZeroWeights: ms.ZeroWeights,
            Sparsity: ms.Sparsity,
            LayerCount: ms.LayerCount,
            EmbeddingWeights: ms.EmbeddingWeights,
            TotalTokensIn: Interlocked.Read(ref _totalTokensIn),
            TotalTokensOut: Interlocked.Read(ref _totalTokensOut),
            TotalRequests: Interlocked.Read(ref _totalRequests),
            TotalInferenceMs: Interlocked.Read(ref _totalInferenceMs),
            PrePruneAccuracy: sp.HasValue ? sp.Value.PrePruneAccuracy : null,
            PostPruneAccuracy: sp.HasValue ? sp.Value.PostPruneAccuracy : null,
            SemanticTestCaseCount: sp.HasValue ? sp.Value.TestCaseCount : null,
            OriginalVocabSize: origVocab,
            PrunedVocabSize: prunedVocab
        );
    }

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

        // 9. Build/cache the synthetic vocabulary token table for decoding.
        // Use the full synthetic vocabulary directly (pruner reordering is complex; 
        // correct decoding happens through the remaining active vocab indices).
        var vocabTokenList = BuildSyntheticVocabulary(activeVocab);
        _tokenTable = vocabTokenList is string[] strArr ? strArr : vocabTokenList.ToArray();

        // 10. Compress to 2-bit packed native memory
        CompressToNative(layers, embeddings, outputHead, activeVocab, dim);

        _isLoaded = true;
    }

    /// <summary>
    /// Pack all weight matrices from sbyte[] into 2-bit NativeTernaryMatrix.
    /// After packing, managed arrays become eligible for GC.
    /// Also pre-allocates all inference buffers and the KV cache.
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
        _compressedWq = new NativeTernaryMatrix[layers.Length];
        _compressedWk = new NativeTernaryMatrix[layers.Length];
        _compressedWv = new NativeTernaryMatrix[layers.Length];
        _compressedWo = new NativeTernaryMatrix[layers.Length];
        _compressedFfn = new NativeTernaryMatrix[layers.Length];

        for (int i = 0; i < layers.Length; i++)
        {
            _compressedWq[i]  = NativeTernaryMatrix.Pack(layers[i].Wq,  dim, dim);
            _compressedWk[i]  = NativeTernaryMatrix.Pack(layers[i].Wk,  dim, dim);
            _compressedWv[i]  = NativeTernaryMatrix.Pack(layers[i].Wv,  dim, dim);
            _compressedWo[i]  = NativeTernaryMatrix.Pack(layers[i].Wo,  dim, dim);
            _compressedFfn[i] = NativeTernaryMatrix.Pack(layers[i].FfnWeights, dim, dim);
        }

        _compressedEmbeddings = NativeTernaryMatrix.Pack(embeddings, activeVocab, dim);
        _compressedOutputHead = NativeTernaryMatrix.Pack(outputHead, activeVocab, dim);

        // Pre-allocate all inference buffers using the shared helper.
        AllocateInferenceBuffers(dim, activeVocab);

        // Calculate total native allocation and per-layer stats
        NativeBytesAllocated = 0;
        var layerStatsList = new (MatrixStats Attn, MatrixStats Ffn)[layers.Length];
        for (int i = 0; i < layers.Length; i++)
        {
            NativeBytesAllocated += _compressedWq[i].BytesAllocated
                                  + _compressedWk[i].BytesAllocated
                                  + _compressedWv[i].BytesAllocated
                                  + _compressedWo[i].BytesAllocated;
            NativeBytesAllocated += _compressedFfn[i].BytesAllocated;
            layerStatsList[i] = (_compressedWq[i].Stats, _compressedFfn[i].Stats);
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
        if (!_isLoaded || _compressedWq is null || _compressedFfn is null
            || _compressedEmbeddings is null || _compressedOutputHead is null)
            throw new InvalidOperationException("No model loaded to snapshot");

        int activeVocab = _pruner?.PrunedVocabSize ?? _config.VocabSize;

        ModelSnapshot.Save(path, _config, activeVocab,
            _compressedWq, _compressedWk!, _compressedWv!, _compressedWo!,
            _compressedFfn,
            _compressedEmbeddings, _compressedOutputHead,
            tokenTable ?? _tokenTable);
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

        DisposeNative();

        _layerCount = snapshot.Wq.Length;
        _compressedWq = snapshot.Wq;
        _compressedWk = snapshot.Wk;
        _compressedWv = snapshot.Wv;
        _compressedWo = snapshot.Wo;
        _compressedFfn = snapshot.Ffn;
        _compressedEmbeddings = snapshot.Embeddings;
        _compressedOutputHead = snapshot.OutputHead;
        _tokenTable = snapshot.Tokens;

        int dim = _config.HiddenDim;
        int activeVocab = snapshot.ActiveVocab;
        AllocateInferenceBuffers(dim, activeVocab);

        NativeBytesAllocated = 0;
        var layerStatsList = new (MatrixStats Attn, MatrixStats Ffn)[_layerCount];
        for (int i = 0; i < _layerCount; i++)
        {
            NativeBytesAllocated += _compressedWq[i].BytesAllocated + _compressedWk[i].BytesAllocated
                                  + _compressedWv[i].BytesAllocated + _compressedWo[i].BytesAllocated;
            NativeBytesAllocated += _compressedFfn[i].BytesAllocated;
            layerStatsList[i] = (_compressedWq[i].Stats, _compressedFfn[i].Stats);
        }
        NativeBytesAllocated += _compressedEmbeddings.BytesAllocated;
        NativeBytesAllocated += _compressedOutputHead.BytesAllocated;
        LayerStats = layerStatsList;

        long totalWeights = 0, zeroWeights = 0;
        for (int i = 0; i < _layerCount; i++)
        {
            totalWeights += _compressedWq[i].Stats.LogicalWeights + _compressedWk[i].Stats.LogicalWeights
                          + _compressedWv[i].Stats.LogicalWeights + _compressedWo[i].Stats.LogicalWeights;
            totalWeights += _compressedFfn[i].Stats.LogicalWeights;
            zeroWeights  += (_compressedWq[i].Stats.ZeroByteCount + _compressedWk[i].Stats.ZeroByteCount
                           + _compressedWv[i].Stats.ZeroByteCount + _compressedWo[i].Stats.ZeroByteCount) * 4L;
            zeroWeights  += _compressedFfn[i].Stats.ZeroByteCount * 4L;
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
    /// </summary>
    public void LoadSnapshotLazy(string path)
    {
        DisposeNative();

        _lazySnapshot = ModelSnapshot.LoadLazy(path);
        var snap = _lazySnapshot.Data;

        _layerCount = snap.Wq.Length;
        _compressedWq = snap.Wq;
        _compressedWk = snap.Wk;
        _compressedWv = snap.Wv;
        _compressedWo = snap.Wo;
        _compressedFfn = snap.Ffn;
        _compressedEmbeddings = snap.Embeddings;
        _compressedOutputHead = snap.OutputHead;
        _tokenTable = snap.Tokens;

        int dim = _config.HiddenDim;
        AllocateInferenceBuffers(dim, snap.ActiveVocab);

        NativeBytesAllocated = 0; // data lives in mmap
        var layerStatsList = new (MatrixStats Attn, MatrixStats Ffn)[_layerCount];
        for (int i = 0; i < _layerCount; i++)
            layerStatsList[i] = (_compressedWq[i].Stats, _compressedFfn[i].Stats);
        LayerStats = layerStatsList;

        long totalWeights = 0;
        for (int i = 0; i < _layerCount; i++)
        {
            totalWeights += _compressedWq[i].Stats.LogicalWeights + _compressedWk[i].Stats.LogicalWeights
                          + _compressedWv[i].Stats.LogicalWeights + _compressedWo[i].Stats.LogicalWeights;
            totalWeights += _compressedFfn[i].Stats.LogicalWeights;
        }
        long embWeights = (long)_compressedEmbeddings.Stats.LogicalWeights
                        + _compressedOutputHead.Stats.LogicalWeights;

        _modelStats = new ModelSizeStats(
            TotalWeights: totalWeights + embWeights,
            LayerWeights: totalWeights,
            EmbeddingWeights: embWeights,
            ZeroWeights: 0,
            StoredBytes: totalWeights + embWeights,
            PackedBytes: 0,
            Sparsity: 0f,
            LayerCount: _layerCount);

        _isLoaded = true;
    }

    /// <summary>
    /// Allocates all inference buffers and KV cache arrays.
    /// Called once from CompressToNative and from LoadSnapshot.
    /// </summary>
    private void AllocateInferenceBuffers(int dim, int vocabSize)
    {
        _bufHidden = new int[dim];
        _bufNorm   = new int[dim];
        _bufQ      = new int[dim];
        _bufK      = new int[dim];
        _bufV      = new int[dim];
        _bufPreWo  = new int[dim];
        _bufScores = new int[_config.MaxSeqLen];
        _bufLogits = new int[vocabSize];

        int cacheSize = _config.MaxSeqLen * dim;
        _kvCacheK = new int[_layerCount][];
        _kvCacheV = new int[_layerCount][];
        for (int i = 0; i < _layerCount; i++)
        {
            _kvCacheK[i] = new int[cacheSize];
            _kvCacheV[i] = new int[cacheSize];
        }
    }

    public async ValueTask<string> GenerateAsync(
        ReadOnlyMemory<char> prompt,
        int maxTokens = 256,
        CancellationToken ct = default)
    {
        if (!_isLoaded)
            return "[Engine not loaded — no model file available]";

        await _inferLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            long startMs = System.Diagnostics.Stopwatch.GetTimestamp();
            var result = RunInference(prompt.Span, maxTokens, ct);
            long elapsedMs = (System.Diagnostics.Stopwatch.GetTimestamp() - startMs)
                             * 1000L / System.Diagnostics.Stopwatch.Frequency;

            Interlocked.Add(ref _totalTokensIn, prompt.Length);
            Interlocked.Add(ref _totalTokensOut, result.Length);
            Interlocked.Increment(ref _totalRequests);
            Interlocked.Add(ref _totalInferenceMs, elapsedMs);

            return result;
        }
        finally
        {
            _inferLock.Release();
        }
    }

    private const int EosTokenId = 2;
    // Maximum tokens to generate per call (prevents runaway generation on random models)
    private const int MaxGenerateTokens = 16;

    /// <summary>
    /// Full autoregressive token-generation loop.
    /// 1. Encodes each prompt character as a token ID and runs a forward pass
    ///    to build the KV cache.
    /// 2. Greedily samples the next token from the output logits.
    /// 3. Repeats until EOS or <paramref name="maxTokens"/> generated.
    /// All intermediate buffers are pre-allocated — zero per-call GC pressure.
    /// </summary>
    private string RunInference(ReadOnlySpan<char> prompt, int maxTokens, CancellationToken ct)
    {
        int dim = _config.HiddenDim;
        int vocabSize = _compressedOutputHead!.Rows;

        // Work with pre-allocated slices
        var bufHidden  = _bufHidden!.AsSpan(0, dim);
        var bufNorm    = _bufNorm!.AsSpan(0, dim);
        var bufLogits  = _bufLogits!.AsSpan(0, vocabSize);

        // Clear KV cache for this inference pass
        for (int L = 0; L < _layerCount; L++)
        {
            Array.Clear(_kvCacheK![L], 0, _config.MaxSeqLen * dim);
            Array.Clear(_kvCacheV![L], 0, _config.MaxSeqLen * dim);
        }

        int seqLen = 0;

        // ── Prefill: process each prompt character ──────────────────────────
        for (int p = 0; p < prompt.Length && seqLen < _config.MaxSeqLen; p++, seqLen++)
        {
            ct.ThrowIfCancellationRequested();
            EmbedToken(prompt[p] % vocabSize, bufHidden);
            ForwardAllLayers(seqLen, bufHidden, bufNorm);
        }

        // ── Decode: generate tokens ─────────────────────────────────────────
        int generateLimit = Math.Min(maxTokens, MaxGenerateTokens);
        var output = new System.Text.StringBuilder(generateLimit * 8);

        for (int gen = 0; gen < generateLimit && seqLen < _config.MaxSeqLen; gen++)
        {
            ct.ThrowIfCancellationRequested();

            // Compute logits from current hidden state
            TernaryTensor.RmsNormalize(bufHidden, bufNorm);
            _compressedOutputHead.MatVecMultiply(bufNorm, bufLogits);

            // Greedy argmax — no float allocation
            int nextToken = ArgMax(bufLogits);
            if (nextToken == EosTokenId) break;

            // Decode token to text and append
            string tok = DecodeToken(nextToken);
            if (output.Length > 0) output.Append(' ');
            output.Append(tok);

            // Feed next token as input for the next step
            EmbedToken(nextToken, bufHidden);
            ForwardAllLayers(seqLen, bufHidden, bufNorm);
            seqLen++;
        }

        return output.Length > 0 ? output.ToString() : DecodeToken(ArgMax(bufLogits));
    }

    /// <summary>
    /// Runs all transformer layers in order. Modifies <paramref name="hidden"/> in-place.
    /// Uses only pre-allocated buffers — no managed heap allocations.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void ForwardAllLayers(int seqPos, Span<int> hidden, Span<int> norm)
    {
        var attnOut = _bufPreWo!.AsSpan();
        for (int L = 0; L < _layerCount; L++)
        {
            // Pre-norm → multi-head attention → residual
            TernaryTensor.RmsNormalize(hidden, norm);
            MultiHeadAttention(L, seqPos, norm, attnOut);
            TernaryTensor.Add(hidden, attnOut, hidden);

            // Pre-norm → FFN → residual
            TernaryTensor.RmsNormalize(hidden, norm);
            _compressedFfn![L].MatVecMultiply(norm, attnOut);
            TernaryTensor.Add(hidden, attnOut, hidden);
        }
    }

    /// <summary>
    /// Real multi-head self-attention.
    ///   Q  = Wq × input
    ///   K  = Wk × input  (cached in KV store)
    ///   V  = Wv × input  (cached in KV store)
    ///   score[h,p] = Q[h] · K_cache[h,p] / sqrt(head_dim)
    ///   attn[h]    = Σ softmax(scores)[p] * V_cache[h,p]
    ///   output     = Wo × concat(attn heads)
    /// Integer arithmetic throughout — no floating-point on the hot path.
    /// </summary>
    private void MultiHeadAttention(int layer, int seqPos, ReadOnlySpan<int> input, Span<int> output)
    {
        int dim     = _config.HiddenDim;
        int nHeads  = _config.NumHeads;
        int headDim = dim / nHeads;

        var bufQ = _bufQ!.AsSpan(0, dim);
        var bufK = _bufK!.AsSpan(0, dim);
        var bufV = _bufV!.AsSpan(0, dim);

        // Q, K, V projections using pre-allocated buffers
        _compressedWq![layer].MatVecMultiply(input, bufQ);
        _compressedWk![layer].MatVecMultiply(input, bufK);
        _compressedWv![layer].MatVecMultiply(input, bufV);

        // Cache K and V for current position
        int cacheBase = seqPos * dim;
        bufK.CopyTo(_kvCacheK![layer].AsSpan(cacheBase, dim));
        bufV.CopyTo(_kvCacheV![layer].AsSpan(cacheBase, dim));

        output.Clear();

        // scaleShift = floor(log2(headDim)/2)  — used to right-shift raw dot-product
        // scores, approximating division by sqrt(headDim) with integer arithmetic.
        //   headDim=4  → log2=2 → scaleShift=1  (divide by ~2  ≈ sqrt(4)=2)
        //   headDim=16 → log2=4 → scaleShift=2  (divide by ~4  ≈ sqrt(16)=4)
        //   headDim=32 → log2=5 → scaleShift=2  (divide by ~4  ≈ sqrt(32)≈5.7)
        int scaleShift = headDim > 1 ? (int)Math.Log2(headDim) >> 1 : 0;

        int posCount = seqPos + 1;
        var scores = _bufScores!.AsSpan(0, posCount);

        for (int h = 0; h < nHeads; h++)
        {
            int hOff = h * headDim;

            // Compute raw dot-product attention scores for head h over all past positions
            int maxScore = int.MinValue;
            for (int p = 0; p < posCount; p++)
            {
                int kBase = p * dim + hOff;
                var kCache = _kvCacheK[layer].AsSpan(kBase, headDim);
                var qSlice = bufQ.Slice(hOff, headDim);
                // SIMD-accelerated dot product (NEON / AVX2 / scalar)
                int score = TernaryTensor.DotProduct(qSlice, kCache);
                // Scale to prevent overflow: divide by √headDim using bit-shift
                score >>= scaleShift;
                scores[p] = score;
                if (score > maxScore) maxScore = score;
            }

            // Softmax approximation: shift so max = 128, clamp to [1, 128]
            long totalWeight = 0;
            for (int p = 0; p < posCount; p++)
            {
                int w = Math.Clamp(128 + (scores[p] - maxScore), 1, 128);
                scores[p] = w;
                totalWeight += w;
            }
            if (totalWeight == 0) totalWeight = 1;

            // Weighted sum of V values for this head (SIMD-accelerated two-phase):
            // Phase 1: accumulate weight * V using SIMD multiply+add (no division)
            var outSlice = output.Slice(hOff, headDim);
            for (int p = 0; p < posCount; p++)
            {
                long w = scores[p];
                int vBase = p * dim + hOff;
                var vSlice = _kvCacheV![layer].AsSpan(vBase, headDim);
                TernaryTensor.WeightedAccumulate(outSlice, w, vSlice, totalWeight);
            }
            // Phase 2: normalize by totalWeight (scalar division)
            TernaryTensor.DivideInPlace(outSlice, (int)totalWeight);
        }

        // Output projection: Wo × attention_output
        // Borrow _bufNorm to hold the pre-projection values without extra allocation
        output.CopyTo(_bufNorm!.AsSpan(0, dim));
        _compressedWo![layer].MatVecMultiply(_bufNorm.AsSpan(0, dim), output);
    }

    /// <summary>Embeds a token ID into the hidden state using the embedding table row.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void EmbedToken(int tokenId, Span<int> hidden)
    {
        int rows = _compressedEmbeddings!.Rows;
        int id = tokenId < 0 ? 0 : tokenId >= rows ? tokenId % rows : tokenId;
        _compressedEmbeddings.DecodeRow(id, hidden);
    }

    /// <summary>Greedy argmax over integer logits — no allocations.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int ArgMax(ReadOnlySpan<int> logits)
    {
        int best = 0;
        int bestVal = logits[0];
        for (int i = 1; i < logits.Length; i++)
        {
            if (logits[i] > bestVal)
            {
                bestVal = logits[i];
                best = i;
            }
        }
        return best;
    }

    /// <summary>
    /// Maps a token ID to its display string using the loaded token table,
    /// or falls back to a domain-generic name.
    /// </summary>
    private string DecodeToken(int tokenId)
    {
        if (_tokenTable is not null && (uint)tokenId < (uint)_tokenTable.Length)
            return _tokenTable[tokenId] ?? $"tok{tokenId}";
        return tokenId switch
        {
            0 => "<pad>",
            1 => "<bos>",
            EosTokenId => "<eos>",
            3 => "<unk>",
            _ => $"tok{tokenId}"
        };
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
            _lazySnapshot.Dispose();
            _lazySnapshot = null;
            _compressedWq = null;
            _compressedWk = null;
            _compressedWv = null;
            _compressedWo = null;
            _compressedFfn = null;
            _compressedEmbeddings = null;
            _compressedOutputHead = null;
        }
        else
        {
            if (_compressedWq is not null) { foreach (var m in _compressedWq) m?.Dispose(); _compressedWq = null; }
            if (_compressedWk is not null) { foreach (var m in _compressedWk) m?.Dispose(); _compressedWk = null; }
            if (_compressedWv is not null) { foreach (var m in _compressedWv) m?.Dispose(); _compressedWv = null; }
            if (_compressedWo is not null) { foreach (var m in _compressedWo) m?.Dispose(); _compressedWo = null; }
            if (_compressedFfn is not null) { foreach (var m in _compressedFfn) m?.Dispose(); _compressedFfn = null; }
            _compressedEmbeddings?.Dispose(); _compressedEmbeddings = null;
            _compressedOutputHead?.Dispose(); _compressedOutputHead = null;
        }

        // Clear buffer references (GC will reclaim them)
        _bufHidden = _bufNorm = _bufQ = _bufK = _bufV = _bufPreWo = _bufScores = _bufLogits = null;
        _kvCacheK = null;
        _kvCacheV = null;
        _tokenTable = null;
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
/// AttentionWeights is a read-only alias for Wq so that SemanticPruner and
/// ModelPruner code continues to compile without modification.
/// </summary>
public struct TernaryLayer
{
    /// <summary>Query projection  [dim × dim]</summary>
    public sbyte[] Wq;
    /// <summary>Key projection    [dim × dim]</summary>
    public sbyte[] Wk;
    /// <summary>Value projection  [dim × dim]</summary>
    public sbyte[] Wv;
    /// <summary>Output projection [dim × dim]</summary>
    public sbyte[] Wo;
    /// <summary>Feed-forward      [dim × dim]</summary>
    public sbyte[] FfnWeights;

    /// <summary>
    /// Backward-compatibility alias: returns the Wq array.
    /// Pruning code that zeros elements through this reference modifies Wq.
    /// </summary>
    public readonly sbyte[] AttentionWeights => Wq;

    public static TernaryLayer CreateRandom(int dim, int numHeads)
    {
        return new TernaryLayer
        {
            Wq         = CreateTernary(dim * dim),
            Wk         = CreateTernary(dim * dim),
            Wv         = CreateTernary(dim * dim),
            Wo         = CreateTernary(dim * dim),
            FfnWeights = CreateTernary(dim * dim),
        };
    }

    private static sbyte[] CreateTernary(int count)
    {
        var rng = Random.Shared;
        var arr = new sbyte[count];
        for (int i = 0; i < arr.Length; i++)
            arr[i] = (sbyte)(rng.Next(3) - 1);
        return arr;
    }
}
