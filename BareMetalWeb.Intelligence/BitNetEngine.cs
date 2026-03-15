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
    private BitNetModelConfig _config;
    private VocabularyPruner? _pruner = null;
    private PruneStats? _pruneStats = null;
    private ModelSizeStats? _modelStats;
    private GroupPruneStats? _groupPruneStats = null;
    private SemanticPruningStats? _semanticPruneStats = null;

    // Compressed storage — 2-bit packed in native (unmanaged) memory.
    // Each layer has four attention projections (Q, K, V, O) plus gated FFN (gate, up, down).
    private NativeTernaryMatrix[]? _compressedWq;
    private NativeTernaryMatrix[]? _compressedWk;
    private NativeTernaryMatrix[]? _compressedWv;
    private NativeTernaryMatrix[]? _compressedWo;
    private NativeTernaryMatrix[]? _compressedFfnGate;  // [ffnDim × dim]
    private NativeTernaryMatrix[]? _compressedFfnUp;    // [ffnDim × dim]
    private NativeTernaryMatrix[]? _compressedFfnDown;  // [dim × ffnDim]
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
    private int[]? _bufFfnGate;   // gated FFN gate output   [ffnDim]
    private int[]? _bufFfnUp;     // gated FFN up output     [ffnDim]
    private int[]? _bufFfnDown;   // gated FFN down input    [ffnDim]

    // Per-layer KV cache — stores K and V for every past token position.
    // _kvCacheK[layer] = int[maxSeqLen × dim],  _kvCacheV[layer] = int[maxSeqLen × dim]
    private int[][]? _kvCacheK;
    private int[][]? _kvCacheV;

    // Vocabulary strings for token decoding, set at load time.
    private string[]? _tokenTable;
    // Tokenizer wraps the token table with encode/decode logic.
    private Tokenizer? _tokenizer;

    // Serialises inference so pre-allocated buffers are not clobbered by concurrent calls.
    private readonly SemaphoreSlim _inferLock = new SemaphoreSlim(1, 1);

    // Lifetime token / throughput counters — updated atomically on each inference
    private long _totalTokensIn;
    private long _totalTokensOut;
    private long _totalRequests;
    private long _totalInferenceMs;
    // KV-cache hit/miss counters (miss = new encode position, hit = decode re-use)
    private long _kvCacheHits;
    private long _kvCacheMisses;
    // Layer timing accumulator (microseconds)
    private long _totalLayerTimeMicros;
    private long _totalLayerTimeSamples;

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

        long tokOut  = Interlocked.Read(ref _totalTokensOut);
        long totalMs = Interlocked.Read(ref _totalInferenceMs);
        float tokPerSec = totalMs > 0 ? tokOut * 1000f / totalMs : 0f;

        long samples = Interlocked.Read(ref _totalLayerTimeSamples);
        long avgLayerMicros = samples > 0
            ? Interlocked.Read(ref _totalLayerTimeMicros) / samples
            : 0;

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
            TotalTokensOut: tokOut,
            TotalRequests: Interlocked.Read(ref _totalRequests),
            TotalInferenceMs: totalMs,
            PrePruneAccuracy: sp.HasValue ? sp.Value.PrePruneAccuracy : null,
            PostPruneAccuracy: sp.HasValue ? sp.Value.PostPruneAccuracy : null,
            SemanticTestCaseCount: sp.HasValue ? sp.Value.TestCaseCount : null,
            OriginalVocabSize: origVocab,
            PrunedVocabSize: prunedVocab,
            TokensPerSec: tokPerSec,
            KvCacheHits: Interlocked.Read(ref _kvCacheHits),
            KvCacheMisses: Interlocked.Read(ref _kvCacheMisses),
            AvgLayerTimeMicros: avgLayerMicros
        );
    }

    public BitNetEngine(BitNetModelConfig? config = null)
    {
        _config = config ?? BitNetModelConfig.Default;
    }

    /// <summary>
    /// Load weights directly from an import pipeline (HuggingFace importer).
    /// Skips all pruning — the importer has already applied it.
    /// </summary>
    public void LoadFromImport(
        TernaryLayer[] layers,
        sbyte[] embeddings,
        sbyte[] outputHead,
        int activeVocab,
        int dim,
        string[] tokenTable)
    {
        _modelStats = ModelPruner.CalculateSize(layers, activeVocab, dim);

        CompressToNative(layers, embeddings, outputHead, activeVocab, dim);

        _tokenTable = tokenTable;
        _tokenizer = new Tokenizer(_tokenTable);

        _isLoaded = true;
    }

    /// <summary>
    /// Load pre-packed NativeTernaryMatrix arrays directly — no sbyte[] intermediates.
    /// Used by the streaming HuggingFace importer to avoid OOM on large models.
    /// </summary>
    public void LoadFromNativeImport(
        NativeTernaryMatrix[] wq, NativeTernaryMatrix[] wk,
        NativeTernaryMatrix[] wv, NativeTernaryMatrix[] wo,
        NativeTernaryMatrix[] ffnGate, NativeTernaryMatrix[] ffnUp, NativeTernaryMatrix[] ffnDown,
        NativeTernaryMatrix embeddings, NativeTernaryMatrix outputHead,
        int activeVocab, int dim, string[] tokenTable)
    {
        DisposeNative();

        _layerCount = wq.Length;
        _compressedWq = wq;
        _compressedWk = wk;
        _compressedWv = wv;
        _compressedWo = wo;
        _compressedFfnGate = ffnGate;
        _compressedFfnUp = ffnUp;
        _compressedFfnDown = ffnDown;
        _compressedEmbeddings = embeddings;
        _compressedOutputHead = outputHead;

        AllocateInferenceBuffers(dim, activeVocab);

        NativeBytesAllocated = 0;
        long layerWeights = 0;
        long zeroWeightEstimate = 0;
        var layerStatsList = new (MatrixStats Attn, MatrixStats Ffn)[_layerCount];
        for (int i = 0; i < _layerCount; i++)
        {
            NativeBytesAllocated += _compressedWq[i].BytesAllocated
                                  + _compressedWk[i].BytesAllocated
                                  + _compressedWv[i].BytesAllocated
                                  + _compressedWo[i].BytesAllocated;
            NativeBytesAllocated += _compressedFfnGate![i].BytesAllocated
                                  + _compressedFfnUp![i].BytesAllocated
                                  + _compressedFfnDown![i].BytesAllocated;
            layerStatsList[i] = (_compressedWq[i].Stats, _compressedFfnDown[i].Stats);

            layerWeights += _compressedWq[i].Stats.LogicalWeights
                          + _compressedWk[i].Stats.LogicalWeights
                          + _compressedWv[i].Stats.LogicalWeights
                          + _compressedWo[i].Stats.LogicalWeights
                          + _compressedFfnGate[i].Stats.LogicalWeights
                          + _compressedFfnUp[i].Stats.LogicalWeights
                          + _compressedFfnDown[i].Stats.LogicalWeights;

            // Estimate zero weights from zero-byte ratio (each zero byte = 4 zero weights)
            zeroWeightEstimate += (long)(_compressedWq[i].Stats.ZeroByteCount
                                + _compressedWk[i].Stats.ZeroByteCount
                                + _compressedWv[i].Stats.ZeroByteCount
                                + _compressedWo[i].Stats.ZeroByteCount
                                + _compressedFfnGate[i].Stats.ZeroByteCount
                                + _compressedFfnUp[i].Stats.ZeroByteCount
                                + _compressedFfnDown[i].Stats.ZeroByteCount) * 4;
        }
        NativeBytesAllocated += _compressedEmbeddings.BytesAllocated;
        NativeBytesAllocated += _compressedOutputHead.BytesAllocated;
        LayerStats = layerStatsList;

        long embeddingWeights = (long)activeVocab * dim * 2;
        long totalWeights = layerWeights + embeddingWeights;
        float sparsity = layerWeights > 0 ? (float)zeroWeightEstimate / layerWeights : 0f;
        _modelStats = new ModelSizeStats(
            TotalWeights: totalWeights,
            LayerWeights: layerWeights,
            EmbeddingWeights: embeddingWeights,
            ZeroWeights: zeroWeightEstimate,
            StoredBytes: totalWeights,
            PackedBytes: (totalWeights * 2 + 7) / 8,
            Sparsity: sparsity,
            LayerCount: _layerCount);

        _tokenTable = tokenTable;
        _tokenizer = new Tokenizer(_tokenTable);
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
        // Dispose any previous compressed data.
        // NOTE: DisposeNative also nulls _tokenTable/_tokenizer.
        // Callers must re-assign _tokenTable/_tokenizer AFTER this call.
        DisposeNative();

        _layerCount = layers.Length;
        _compressedWq = new NativeTernaryMatrix[layers.Length];
        _compressedWk = new NativeTernaryMatrix[layers.Length];
        _compressedWv = new NativeTernaryMatrix[layers.Length];
        _compressedWo = new NativeTernaryMatrix[layers.Length];
        _compressedFfnGate = new NativeTernaryMatrix[layers.Length];
        _compressedFfnUp   = new NativeTernaryMatrix[layers.Length];
        _compressedFfnDown = new NativeTernaryMatrix[layers.Length];

        for (int i = 0; i < layers.Length; i++)
        {
            _compressedWq[i]  = NativeTernaryMatrix.Pack(layers[i].Wq,  dim, dim);
            _compressedWk[i]  = NativeTernaryMatrix.Pack(layers[i].Wk,  dim, dim);
            _compressedWv[i]  = NativeTernaryMatrix.Pack(layers[i].Wv,  dim, dim);
            _compressedWo[i]  = NativeTernaryMatrix.Pack(layers[i].Wo,  dim, dim);
            // Legacy path: single FfnWeights → replicate as gate=identity, up=weights, down=identity
            _compressedFfnGate[i] = NativeTernaryMatrix.Pack(layers[i].FfnWeights, dim, dim);
            _compressedFfnUp[i]   = NativeTernaryMatrix.Pack(layers[i].FfnWeights, dim, dim);
            _compressedFfnDown[i] = NativeTernaryMatrix.Pack(layers[i].FfnWeights, dim, dim);
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
            NativeBytesAllocated += _compressedFfnGate![i].BytesAllocated
                                  + _compressedFfnUp![i].BytesAllocated
                                  + _compressedFfnDown![i].BytesAllocated;
            layerStatsList[i] = (_compressedWq[i].Stats, _compressedFfnDown[i].Stats);
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
        if (!_isLoaded || _compressedWq is null || _compressedFfnDown is null
            || _compressedEmbeddings is null || _compressedOutputHead is null)
            throw new InvalidOperationException("No model loaded to snapshot");

        int activeVocab = _pruner?.PrunedVocabSize ?? _config.VocabSize;

        ModelSnapshot.Save(path, _config, activeVocab,
            _compressedWq, _compressedWk!, _compressedWv!, _compressedWo!,
            _compressedFfnGate!, _compressedFfnUp!, _compressedFfnDown!,
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
    public void LoadSnapshot(string path, bool memoryMapped = false, int? maxSeqLenOverride = null)
    {
        var snapshot = memoryMapped
            ? ModelSnapshot.LoadMapped(path)
            : ModelSnapshot.Load(path);

        DisposeNative();

        // Override engine config with the snapshot's config — the snapshot
        // knows its own dimensions, layer count, vocab size, etc.
        var snapshotConfig = snapshot.Config;
        if (maxSeqLenOverride.HasValue)
        {
            snapshotConfig = snapshotConfig with
            {
                MaxSeqLen = Math.Min(snapshotConfig.MaxSeqLen, maxSeqLenOverride.Value)
            };
        }
        _config = snapshotConfig;

        _layerCount = snapshot.Wq.Length;
        _compressedWq = snapshot.Wq;
        _compressedWk = snapshot.Wk;
        _compressedWv = snapshot.Wv;
        _compressedWo = snapshot.Wo;
        _compressedFfnGate = snapshot.FfnGate;
        _compressedFfnUp = snapshot.FfnUp;
        _compressedFfnDown = snapshot.FfnDown;
        _compressedEmbeddings = snapshot.Embeddings;
        _compressedOutputHead = snapshot.OutputHead;

        // If the snapshot has a token table, use it.
        // Otherwise build a synthetic vocabulary from the active vocab size.
        if (snapshot.Tokens is { Length: > 0 })
        {
            _tokenTable = snapshot.Tokens;
        }
        else
        {
            var syntheticVocab = BuildSyntheticVocabulary(snapshot.ActiveVocab);
            _tokenTable = syntheticVocab is string[] arr ? arr : syntheticVocab.ToArray();
        }
        _tokenizer = new Tokenizer(_tokenTable);

        int dim = _config.HiddenDim;
        int activeVocab = snapshot.ActiveVocab;
        AllocateInferenceBuffers(dim, activeVocab);

        NativeBytesAllocated = 0;
        var layerStatsList = new (MatrixStats Attn, MatrixStats Ffn)[_layerCount];
        for (int i = 0; i < _layerCount; i++)
        {
            NativeBytesAllocated += _compressedWq[i].BytesAllocated + _compressedWk[i].BytesAllocated
                                  + _compressedWv[i].BytesAllocated + _compressedWo[i].BytesAllocated;
            NativeBytesAllocated += _compressedFfnGate![i].BytesAllocated
                                  + _compressedFfnUp![i].BytesAllocated
                                  + _compressedFfnDown![i].BytesAllocated;
            layerStatsList[i] = (_compressedWq[i].Stats, _compressedFfnDown[i].Stats);
        }
        NativeBytesAllocated += _compressedEmbeddings.BytesAllocated;
        NativeBytesAllocated += _compressedOutputHead.BytesAllocated;
        LayerStats = layerStatsList;

        long totalWeights = 0, zeroWeights = 0;
        for (int i = 0; i < _layerCount; i++)
        {
            totalWeights += _compressedWq[i].Stats.LogicalWeights + _compressedWk[i].Stats.LogicalWeights
                          + _compressedWv[i].Stats.LogicalWeights + _compressedWo[i].Stats.LogicalWeights;
            totalWeights += _compressedFfnGate![i].Stats.LogicalWeights
                          + _compressedFfnUp![i].Stats.LogicalWeights
                          + _compressedFfnDown![i].Stats.LogicalWeights;
            zeroWeights  += (_compressedWq[i].Stats.ZeroByteCount + _compressedWk[i].Stats.ZeroByteCount
                           + _compressedWv[i].Stats.ZeroByteCount + _compressedWo[i].Stats.ZeroByteCount) * 4L;
            zeroWeights  += (_compressedFfnGate[i].Stats.ZeroByteCount
                           + _compressedFfnUp[i].Stats.ZeroByteCount
                           + _compressedFfnDown[i].Stats.ZeroByteCount) * 4L;
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
    public void LoadSnapshotLazy(string path, int? maxSeqLenOverride = null)
    {
        DisposeNative();

        _lazySnapshot = ModelSnapshot.LoadLazy(path);
        var snap = _lazySnapshot.Data;

        if (maxSeqLenOverride is int seqOverride && seqOverride > 0)
            _config = snap.Config with { MaxSeqLen = seqOverride };
        else
            _config = snap.Config;

        _layerCount = snap.Wq.Length;
        _compressedWq = snap.Wq;
        _compressedWk = snap.Wk;
        _compressedWv = snap.Wv;
        _compressedWo = snap.Wo;
        _compressedFfnGate = snap.FfnGate;
        _compressedFfnUp = snap.FfnUp;
        _compressedFfnDown = snap.FfnDown;
        _compressedEmbeddings = snap.Embeddings;
        _compressedOutputHead = snap.OutputHead;

        if (snap.Tokens is { Length: > 0 })
        {
            _tokenTable = snap.Tokens;
        }
        else
        {
            var syntheticVocab = BuildSyntheticVocabulary(snap.ActiveVocab);
            _tokenTable = syntheticVocab is string[] arr ? arr : syntheticVocab.ToArray();
        }
        _tokenizer = new Tokenizer(_tokenTable);

        int dim = _config.HiddenDim;
        AllocateInferenceBuffers(dim, snap.ActiveVocab);

        NativeBytesAllocated = 0; // data lives in mmap
        var layerStatsList = new (MatrixStats Attn, MatrixStats Ffn)[_layerCount];
        for (int i = 0; i < _layerCount; i++)
            layerStatsList[i] = (_compressedWq[i].Stats, _compressedFfnDown![i].Stats);
        LayerStats = layerStatsList;

        long totalWeights = 0;
        for (int i = 0; i < _layerCount; i++)
        {
            totalWeights += _compressedWq[i].Stats.LogicalWeights + _compressedWk[i].Stats.LogicalWeights
                          + _compressedWv[i].Stats.LogicalWeights + _compressedWo[i].Stats.LogicalWeights;
            totalWeights += _compressedFfnGate![i].Stats.LogicalWeights
                          + _compressedFfnUp![i].Stats.LogicalWeights
                          + _compressedFfnDown![i].Stats.LogicalWeights;
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
        int ffnDim = _config.EffectiveFfnDim;
        _bufHidden = new int[dim];
        _bufNorm   = new int[dim];
        _bufQ      = new int[dim];
        _bufK      = new int[dim];
        _bufV      = new int[dim];
        _bufPreWo  = new int[dim];
        _bufScores = new int[_config.MaxSeqLen];
        _bufLogits = new int[vocabSize];
        _bufFfnGate = new int[ffnDim];
        _bufFfnUp   = new int[ffnDim];
        _bufFfnDown = new int[ffnDim];

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
    // Top-K sampling parameter (K=8 balances diversity and coherence)
    private const int DefaultTopK = 8;
    // Temperature in Q8 fixed-point: 256 = T=1.0 (stochastic), 0 = greedy
    // Default is greedy (deterministic) — callers may set higher values for diversity.
    private const int DefaultTempQ8 = 0;

    /// <summary>
    /// Full autoregressive token-generation loop.
    /// 1. Encodes the prompt with the Tokenizer (Encode → int[]).
    /// 2. Runs a forward pass for each prompt token to build the KV cache.
    /// 3. Samples the next token using Top-K sampling (or greedy if temp=0).
    /// 4. Repeats until EOS or <paramref name="maxTokens"/> generated.
    /// All intermediate buffers are pre-allocated — zero per-call GC pressure.
    /// </summary>
    private string RunInference(ReadOnlySpan<char> prompt, int maxTokens, CancellationToken ct)
    {
        int dim      = _config.HiddenDim;
        int vocabSize = _compressedOutputHead!.Rows;

        // Work with pre-allocated slices
        var bufHidden = _bufHidden!.AsSpan(0, dim);
        var bufNorm   = _bufNorm!.AsSpan(0, dim);
        var bufLogits = _bufLogits!.AsSpan(0, vocabSize);

        // Clear KV cache for this inference pass
        for (int L = 0; L < _layerCount; L++)
        {
            Array.Clear(_kvCacheK![L], 0, _config.MaxSeqLen * dim);
            Array.Clear(_kvCacheV![L], 0, _config.MaxSeqLen * dim);
        }

        // ── Tokenize prompt ────────────────────────────────────────────────────
        // Use the tokenizer when available; fall back to char-mod encoding.
        int[] promptTokens;
        if (_tokenizer is not null)
        {
            promptTokens = _tokenizer.Encode(prompt);
        }
        else
        {
            promptTokens = new int[prompt.Length + 2];
            promptTokens[0] = Tokenizer.BosId;
            for (int i = 0; i < prompt.Length; i++)
                promptTokens[i + 1] = prompt[i] % vocabSize;
            promptTokens[prompt.Length + 1] = Tokenizer.EosId;
        }

        int seqLen = 0;

        // ── Prefill: process each prompt token ────────────────────────────────
        for (int p = 0; p < promptTokens.Length && seqLen < _config.MaxSeqLen; p++, seqLen++)
        {
            ct.ThrowIfCancellationRequested();
            int tid = Math.Clamp(promptTokens[p], 0, vocabSize - 1);
            EmbedToken(tid, bufHidden);
            ForwardAllLayers(seqLen, bufHidden, bufNorm, isMiss: true);
        }

        // ── Decode: generate tokens ────────────────────────────────────────────
        int generateLimit = Math.Min(maxTokens, MaxGenerateTokens);
        var output = new System.Text.StringBuilder(generateLimit * 8);

        // Re-use the logits buffer as sampling scratch (same size, no extra alloc)
        var samplingBuf = _bufLogits!.AsSpan(0, vocabSize);

        for (int gen = 0; gen < generateLimit && seqLen < _config.MaxSeqLen; gen++)
        {
            ct.ThrowIfCancellationRequested();

            // Compute logits from current hidden state
            TernaryTensor.RmsNormalize(bufHidden, bufNorm);
            _compressedOutputHead.MatVecMultiply(bufNorm, bufLogits);

            // Suppress special tokens (PAD, BOS, UNK) from sampling —
            // the model should only generate content tokens or EOS.
            bufLogits[0] = int.MinValue; // PAD
            bufLogits[1] = int.MinValue; // BOS
            bufLogits[3] = int.MinValue; // UNK

            // Top-K sampling — stochastic, integer arithmetic
            int nextToken = Sampling.SampleTopK(
                bufLogits,
                topK:   DefaultTopK,
                tempQ8: DefaultTempQ8,
                rng:    Random.Shared,
                scratch: samplingBuf);

            if (nextToken == EosTokenId) break;

            // Decode token to text and append — no separator injection;
            // the space character is its own token (ID 4) in the vocabulary.
            string tok = DecodeToken(nextToken);
            output.Append(tok);

            // Feed next token as input for the next step
            EmbedToken(nextToken, bufHidden);
            ForwardAllLayers(seqLen, bufHidden, bufNorm, isMiss: false);
            seqLen++;
        }

        return output.Length > 0 ? output.ToString() : DecodeToken(Sampling.ArgMax(bufLogits));
    }

    /// <summary>
    /// Runs all transformer layers in order. Modifies <paramref name="hidden"/> in-place.
    /// Uses only pre-allocated buffers — no managed heap allocations.
    /// <paramref name="isMiss"/> controls KV-cache accounting (true = encode/miss, false = decode/hit).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void ForwardAllLayers(int seqPos, Span<int> hidden, Span<int> norm, bool isMiss = true)
    {
        // Layer timing instrumentation
        long t0 = System.Diagnostics.Stopwatch.GetTimestamp();

        var attnOut = _bufPreWo!.AsSpan();
        for (int L = 0; L < _layerCount; L++)
        {
            // Pre-norm → multi-head attention → residual
            TernaryTensor.RmsNormalize(hidden, norm);
            MultiHeadAttention(L, seqPos, norm, attnOut);
            TernaryTensor.Add(hidden, attnOut, hidden);

            // Pre-norm → gated FFN (ReLU²) → residual
            //   gate = gate_proj(x)
            //   up   = up_proj(x)
            //   ffn  = relu2(gate) ⊙ up   (relu2(x) = max(0,x)²)
            //   out  = down_proj(ffn)
            TernaryTensor.RmsNormalize(hidden, norm);
            if (_config.HasGatedFfn)
            {
                var gate = _bufFfnGate!.AsSpan();
                var up   = _bufFfnUp!.AsSpan();
                var down = _bufFfnDown!.AsSpan();
                _compressedFfnGate![L].MatVecMultiply(norm, gate);
                _compressedFfnUp![L].MatVecMultiply(norm, up);
                // ReLU² gating with overflow-safe long intermediate
                int ffnDim = gate.Length;
                for (int j = 0; j < ffnDim; j++)
                {
                    long g = gate[j];
                    if (g <= 0) { down[j] = 0; continue; }
                    // relu2(g) * up = g² * up — use long to avoid int32 overflow,
                    // then right-shift to keep values in int32 range.
                    // The shift amount is tuned to preserve precision while avoiding overflow
                    // in the subsequent down_proj ternary matmul (which sums ffnDim terms).
                    long product = g * g * up[j];
                    down[j] = (int)(product >> 16);
                }
                _compressedFfnDown![L].MatVecMultiply(down, attnOut);
            }
            else
            {
                // Legacy single-matrix FFN (no gating)
                _compressedFfnDown![L].MatVecMultiply(norm, attnOut);
            }
            TernaryTensor.Add(hidden, attnOut, hidden);
        }

        // Instrumentation: record layer time and KV-cache accounting
        long elapsedTicks = System.Diagnostics.Stopwatch.GetTimestamp() - t0;
        long elapsedMicros = elapsedTicks * 1_000_000L / System.Diagnostics.Stopwatch.Frequency;
        Interlocked.Add(ref _totalLayerTimeMicros, elapsedMicros);
        Interlocked.Increment(ref _totalLayerTimeSamples);

        if (isMiss)
            Interlocked.Increment(ref _kvCacheMisses);
        else
            Interlocked.Increment(ref _kvCacheHits);
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
            // Use IntrinsicsMatVec.DotProduct for AVX2/NEON acceleration
            int maxScore = int.MinValue;
            for (int p = 0; p < posCount; p++)
            {
                int kBase = p * dim + hOff;
                var kCache = _kvCacheK[layer].AsSpan(kBase, headDim);
                var qSlice = bufQ.Slice(hOff, headDim);
                int score = IntrinsicsMatVec.DotProduct(qSlice, kCache);
                // Scale to prevent overflow: divide by √headDim using bit-shift
                score >>= scaleShift;
                scores[p] = score;
                if (score > maxScore) maxScore = score;
            }

            // Integer softmax approximation via exponential shift.
            // Maps scores to approximate softmax weights using the identity:
            //   exp(x - max) ≈ 2^((x - max) / scale)
            // We use scale=8 (right-shift by 3) to convert the score delta
            // into a bit-shift exponent.
            //   shift = |delta| >> 3  →  weight = 256 >> shift
            //   When shift > 8: 256 >> shift = 0, clamped to 1 (minimum).
            // This replaces the previous linear clamp which was over-simplistic.
            long totalWeight = 0;
            for (int p = 0; p < posCount; p++)
            {
                int delta = scores[p] - maxScore; // ≤ 0
                int shift = (-delta) >> 3;         // non-negative right-shift amount
                // 2^(delta/8) in range [1, 256]: when shift > 8, result < 1 → clamp to 1
                int w = shift > 8 ? 1 : (256 >> shift);
                scores[p]   = w;
                totalWeight += w;
            }
            if (totalWeight == 0) totalWeight = 1;

            // Weighted sum of V values for this head using IntrinsicsMatVec
            for (int p = 0; p < posCount; p++)
            {
                long w = scores[p];
                int vBase = p * dim + hOff;
                var vSlice  = _kvCacheV![layer].AsSpan(vBase, headDim);
                var outSlice = output.Slice(hOff, headDim);
                IntrinsicsMatVec.WeightedAccumulate(w, vSlice, outSlice, totalWeight);
            }
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
        {
            var s = _tokenTable[tokenId];
            if (s is not null && s.Length > 0)
                return s;
        }
        return tokenId switch
        {
            Tokenizer.PadId => "",
            Tokenizer.BosId => "",
            Tokenizer.EosId => "",
            _ => "?",
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

    /// <summary>
    /// Builds a character-unigram vocabulary for a 256-token model.
    /// IDs 0–3: special tokens. IDs 4–98: printable ASCII (space 0x20 … tilde 0x7E).
    /// IDs 99+: multi-character domain tokens used by greedy longest-match encoding.
    /// Space is token ID 4 — the model generates it explicitly, so decoded tokens
    /// are concatenated without injected separators.
    /// </summary>
    private static IReadOnlyList<string> BuildSyntheticVocabulary(int vocabSize)
    {
        var tokens = new string[vocabSize];
        tokens[0] = "<PAD>";
        tokens[1] = "<BOS>";
        tokens[2] = "<EOS>";
        tokens[3] = "<UNK>";

        // Printable ASCII: 95 characters (space 0x20 through tilde 0x7E)
        // ID 4 = ' ', ID 5 = '!', ..., ID 98 = '~'
        const int asciiBase = 4;
        const char firstPrintable = ' ';  // 0x20
        const char lastPrintable  = '~';  // 0x7E
        int asciiCount = lastPrintable - firstPrintable + 1; // 95

        for (int i = 0; i < asciiCount && asciiBase + i < vocabSize; i++)
            tokens[asciiBase + i] = ((char)(firstPrintable + i)).ToString();

        // Multi-character domain tokens at IDs 99+.
        // These let the greedy encoder compress common words into single tokens,
        // producing shorter sequences and better inference quality.
        int domainBase = asciiBase + asciiCount; // 99
        string[] domainTokens = [
            // Whitespace / formatting
            "  ", "\n", "\t",
            // Common English
            "the", "is", "are", "was", "not", "and", "for", "with", "that", "this",
            "from", "have", "has", "can", "will", "but", "all", "your", "you", "it",
            "of", "to", "in", "on", "at", "by", "an", "or", "if", "no", "yes",
            "do", "did", "be", "my", "me", "we", "so", "up", "out", "how", "what",
            "when", "where", "which", "who", "why",
            // Domain commands & entities
            "create", "delete", "update", "show", "find", "get", "list", "search",
            "query", "entity", "field", "schema", "data", "index", "view",
            "help", "status", "system", "count", "describe",
            "user", "session", "name", "type", "id", "value",
            "todo", "task", "note", "item", "record", "page",
            // Common suffixes / fragments
            "ing", "tion", "ed", "er", "ly", "ment", "ness", "able",
            // Punctuation bigrams
            ": ", ", ", ". ", "? ", "! ",
        ];
        for (int i = 0; i < domainTokens.Length && domainBase + i < vocabSize; i++)
            tokens[domainBase + i] = domainTokens[i];

        // Fill any remaining slots with single-char fallback
        for (int i = 0; i < vocabSize; i++)
        {
            if (tokens[i] is null)
                tokens[i] = $"<{i}>";
        }

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
            _compressedFfnGate = null;
            _compressedFfnUp = null;
            _compressedFfnDown = null;            _compressedEmbeddings = null;
            _compressedOutputHead = null;
        }
        else
        {
            if (_compressedWq is not null) { foreach (var m in _compressedWq) m?.Dispose(); _compressedWq = null; }
            if (_compressedWk is not null) { foreach (var m in _compressedWk) m?.Dispose(); _compressedWk = null; }
            if (_compressedWv is not null) { foreach (var m in _compressedWv) m?.Dispose(); _compressedWv = null; }
            if (_compressedWo is not null) { foreach (var m in _compressedWo) m?.Dispose(); _compressedWo = null; }
            if (_compressedFfnGate is not null) { foreach (var m in _compressedFfnGate) m?.Dispose(); _compressedFfnGate = null; }
            if (_compressedFfnUp is not null) { foreach (var m in _compressedFfnUp) m?.Dispose(); _compressedFfnUp = null; }
            if (_compressedFfnDown is not null) { foreach (var m in _compressedFfnDown) m?.Dispose(); _compressedFfnDown = null; }
            _compressedEmbeddings?.Dispose(); _compressedEmbeddings = null;
            _compressedOutputHead?.Dispose(); _compressedOutputHead = null;
        }

        // Clear buffer references (GC will reclaim them)
        _bufHidden = _bufNorm = _bufQ = _bufK = _bufV = _bufPreWo = _bufScores = _bufLogits = null;
        _bufFfnGate = _bufFfnUp = _bufFfnDown = null;
        _kvCacheK = null;
        _kvCacheV = null;
        _tokenTable = null;
        _tokenizer  = null;
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
    int MaxSeqLen,
    int FfnDim = 0)
{
    /// <summary>Effective FFN intermediate dimension. Falls back to HiddenDim when not set.</summary>
    public int EffectiveFfnDim => FfnDim > 0 ? FfnDim : HiddenDim;

    /// <summary>Whether this config uses a gated FFN (SwiGLU/ReLU²) with 3 separate matrices.</summary>
    public bool HasGatedFfn => FfnDim > 0;

    public static readonly BitNetModelConfig Default = new(
        HiddenDim: 128,
        NumLayers: 4,
        NumHeads: 4,
        VocabSize: 256,
        MaxSeqLen: 512);
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
}
