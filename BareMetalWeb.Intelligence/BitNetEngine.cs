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
    private NativeTernaryMatrix[]? _compressedWk;   // [kvDim × dim] (may differ from Q dim for GQA)
    private NativeTernaryMatrix[]? _compressedWv;   // [kvDim × dim]
    private NativeTernaryMatrix[]? _compressedWo;
    private NativeTernaryMatrix[]? _compressedFfnGate;  // [ffnDim × dim]
    private NativeTernaryMatrix[]? _compressedFfnUp;    // [ffnDim × dim]
    private NativeTernaryMatrix[]? _compressedFfnDown;  // [dim × ffnDim]
    private NativeInt8Matrix? _compressedEmbeddings;
    private NativeInt8Matrix? _compressedOutputHead;    // may alias _compressedEmbeddings (tied)
    private LazySnapshot? _lazySnapshot; // holds mmap open when lazy-loaded
    private int _layerCount;
    private int _kvDim;                 // KV projection dimension (may be < dim for GQA)
    private bool _isLoaded;

    // Learned model parameters — norms and per-matrix weight scales.
    private float[][]? _weightScales;     // [layers][7]: Wq,Wk,Wv,Wo,gate,up,down
    private float[][]? _inputNorm;        // [layers][dim]: learned input_layernorm γ
    private float[][]? _attnSubNorm;      // [layers][dim]: attn_sub_norm γ
    private float[][]? _postAttnNorm;     // [layers][dim]: post_attention_layernorm γ
    private float[][]? _ffnSubNorm;       // [layers][ffnDim]: ffn_sub_norm γ
    private float[]? _finalNorm;          // [dim]: final model.norm γ

    // Pre-allocated inference buffers — float hidden state, int for matmul I/O.
    // Float buffers hold the hidden state and intermediate results.
    // Int buffers are for quantized activations (matmul input/output).
    private float[]? _fHidden;     // current hidden state [dim]
    private float[]? _fNorm;       // normalized activation [max(dim, ffnDim)]
    private float[]? _fQ;          // query projection [dim]
    private float[]? _fK;          // key projection [kvDim]
    private float[]? _fV;          // value projection [kvDim]
    private float[]? _fAttnOut;    // attention output [dim]
    private float[]? _fFfnGate;    // FFN gate output [ffnDim]
    private float[]? _fFfnUp;      // FFN up output [ffnDim]
    private float[]? _fFfnDown;    // FFN down/mid buffer [ffnDim]
    private float[]? _fScores;     // attention scores [maxSeqLen]
    private int[]? _iQuantized;    // quantized activation for matmul input [max(dim, ffnDim)]
    private int[]? _iMatmulOut;    // matmul output [max(dim, ffnDim, vocabSize)]
    private int[]? _bufLogits;     // output head logits [vocabSize] (int for sampling)

    // Per-layer float KV cache — stores K and V for every past token position.
    private float[][]? _fKvCacheK;   // [layer][maxSeqLen × kvDim]
    private float[][]? _fKvCacheV;   // [layer][maxSeqLen × kvDim]

    // Precomputed RoPE sin/cos tables [maxSeqLen × headDim/2]
    private float[]? _ropeCos;
    private float[]? _ropeSin;

    // Vocabulary strings for token decoding, set at load time.
    private string[]? _tokenTable;
    // BPE merge rules (from HuggingFace tokenizer.json), null for legacy models.
    private string[]? _merges;
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
        _tokenizer = new Tokenizer(_tokenTable, _merges);

        _isLoaded = true;
    }

    /// <summary>
    /// Load pre-packed native matrices directly — ternary layer weights plus int8 embeddings/output head.
    /// Used by the streaming HuggingFace importer to avoid OOM on large models.
    /// </summary>
    public void LoadFromNativeImport(
        NativeTernaryMatrix[] wq, NativeTernaryMatrix[] wk,
        NativeTernaryMatrix[] wv, NativeTernaryMatrix[] wo,
        NativeTernaryMatrix[] ffnGate, NativeTernaryMatrix[] ffnUp, NativeTernaryMatrix[] ffnDown,
        NativeInt8Matrix embeddings, NativeInt8Matrix outputHead,
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
        _tokenizer = new Tokenizer(_tokenTable, _merges);
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
        _kvDim = dim; // Legacy path: no GQA, kvDim == dim
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

        _compressedEmbeddings = PackInt8Matrix(embeddings, activeVocab, dim);
        _compressedOutputHead = PackInt8Matrix(outputHead, activeVocab, dim);

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

    private static NativeInt8Matrix PackInt8Matrix(sbyte[] source, int rows, int cols)
    {
        var matrix = NativeInt8Matrix.Allocate(rows, cols);
        for (int r = 0; r < rows; r++)
            matrix.PackRowInPlace(r, source.AsSpan(r * cols, cols));
        matrix.FinalizeStats();
        return matrix;
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
        // Detect tied embeddings: same matrix instance for embed and output head
        bool tied = ReferenceEquals(_compressedEmbeddings, _compressedOutputHead);

        ModelSnapshot.Save(path, _config, activeVocab,
            _compressedWq, _compressedWk!, _compressedWv!, _compressedWo!,
            _compressedFfnGate!, _compressedFfnUp!, _compressedFfnDown!,
            _compressedEmbeddings, tied ? null : _compressedOutputHead,
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
        _kvDim = _compressedWk[0].Rows; // may be < dim for GQA

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
        _merges = snapshot.Merges is { Length: > 0 } ? snapshot.Merges : null;
        _tokenizer = new Tokenizer(_tokenTable, _merges);

        // Load learned norms and weight scales (v5+)
        LoadNormsAndScales(snapshot);

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
        _kvDim = _compressedWk[0].Rows;

        if (snap.Tokens is { Length: > 0 })
        {
            _tokenTable = snap.Tokens;
        }
        else
        {
            var syntheticVocab = BuildSyntheticVocabulary(snap.ActiveVocab);
            _tokenTable = syntheticVocab is string[] arr ? arr : syntheticVocab.ToArray();
        }
        _merges = snap.Merges is { Length: > 0 } ? snap.Merges : null;
        _tokenizer = new Tokenizer(_tokenTable, _merges);

        LoadNormsAndScales(snap);

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
        int kvDim = _kvDim > 0 ? _kvDim : dim;
        int maxBuf = Math.Max(dim, ffnDim);

        // Float buffers for hidden state and intermediates
        _fHidden   = new float[dim];
        _fNorm     = new float[maxBuf];
        _fQ        = new float[dim];
        _fK        = new float[kvDim];
        _fV        = new float[kvDim];
        _fAttnOut  = new float[dim];
        _fFfnGate  = new float[ffnDim];
        _fFfnUp    = new float[ffnDim];
        _fFfnDown  = new float[ffnDim];
        _fScores   = new float[_config.MaxSeqLen];

        // Int buffers for ternary matmul I/O
        _iQuantized = new int[maxBuf];
        _iMatmulOut = new int[Math.Max(maxBuf, vocabSize)];
        _bufLogits  = new int[vocabSize];

        // Float KV caches — use kvDim (may be < dim for GQA)
        int cacheSize = _config.MaxSeqLen * kvDim;
        _fKvCacheK = new float[_layerCount][];
        _fKvCacheV = new float[_layerCount][];
        for (int i = 0; i < _layerCount; i++)
        {
            _fKvCacheK[i] = new float[cacheSize];
            _fKvCacheV[i] = new float[cacheSize];
        }

        // Precompute RoPE sin/cos tables
        PrecomputeRoPE();
    }

    /// <summary>
    /// Precompute RoPE (Rotary Position Embeddings) sin/cos tables.
    /// Table layout: [position * headDim/2 + pair_index] for interleaved pairs.
    /// </summary>
    private void PrecomputeRoPE()
    {
        int headDim = _config.HeadDim;
        int halfDim = headDim / 2;
        int maxSeq  = _config.MaxSeqLen;
        float theta = _config.RopeTheta;

        _ropeCos = new float[maxSeq * halfDim];
        _ropeSin = new float[maxSeq * halfDim];

        for (int pos = 0; pos < maxSeq; pos++)
        {
            int baseIdx = pos * halfDim;
            for (int j = 0; j < halfDim; j++)
            {
                double freq = 1.0 / Math.Pow(theta, (2.0 * j) / headDim);
                double angle = pos * freq;
                _ropeCos[baseIdx + j] = (float)Math.Cos(angle);
                _ropeSin[baseIdx + j] = (float)Math.Sin(angle);
            }
        }
    }

    /// <summary>Store learned norms and weight scales from snapshot data.</summary>
    private void LoadNormsAndScales(SnapshotData snapshot)
    {
        _weightScales = snapshot.WeightScales;
        _inputNorm    = snapshot.InputNorm;
        _attnSubNorm  = snapshot.AttnSubNorm;
        _postAttnNorm = snapshot.PostAttnNorm;
        _ffnSubNorm   = snapshot.FfnSubNorm;
        _finalNorm    = snapshot.FinalNorm;
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
    /// Full autoregressive token-generation loop with float hidden state.
    /// Ternary matmuls stay integer; norms, scales, attention, and RoPE use float.
    /// </summary>
    private string RunInference(ReadOnlySpan<char> prompt, int maxTokens, CancellationToken ct)
    {
        int dim       = _config.HiddenDim;
        int vocabSize = _compressedOutputHead!.Rows;

        var fHidden   = _fHidden!;
        var bufLogits = _bufLogits!.AsSpan(0, vocabSize);

        // Clear KV caches
        for (int L = 0; L < _layerCount; L++)
        {
            Array.Clear(_fKvCacheK![L]);
            Array.Clear(_fKvCacheV![L]);
        }

        // ── Tokenize prompt ────────────────────────────────────────────────
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

        // ── Prefill: process each prompt token ────────────────────────────
        for (int p = 0; p < promptTokens.Length && seqLen < _config.MaxSeqLen; p++, seqLen++)
        {
            ct.ThrowIfCancellationRequested();
            int tid = Math.Clamp(promptTokens[p], 0, vocabSize - 1);
            EmbedTokenFloat(tid, fHidden);
            ForwardAllLayersFloat(seqLen);
        }

        // ── Decode: generate tokens ────────────────────────────────────────
        int generateLimit = Math.Min(maxTokens, MaxGenerateTokens);
        var output = new System.Text.StringBuilder(generateLimit * 8);
        var samplingBuf = _bufLogits!.AsSpan(0, vocabSize);

        for (int gen = 0; gen < generateLimit && seqLen < _config.MaxSeqLen; gen++)
        {
            ct.ThrowIfCancellationRequested();

            // Final norm → quantize → output head matmul → logits
            RmsNormWithGamma(fHidden.AsSpan(0, dim), _fNorm!.AsSpan(0, dim), _finalNorm);
            QuantizeAndMatmul(_fNorm!.AsSpan(0, dim), _compressedOutputHead, bufLogits);

            // Suppress special tokens
            bufLogits[0] = int.MinValue; // PAD
            bufLogits[1] = int.MinValue; // BOS
            bufLogits[3] = int.MinValue; // UNK

            int nextToken = Sampling.SampleTopK(
                bufLogits, topK: DefaultTopK, tempQ8: DefaultTempQ8,
                rng: Random.Shared, scratch: samplingBuf);

            if (nextToken == EosTokenId) break;

            string tok = DecodeToken(nextToken);
            output.Append(tok);

            EmbedTokenFloat(nextToken, fHidden);
            ForwardAllLayersFloat(seqLen);
            seqLen++;
        }

        return output.Length > 0 ? output.ToString() : DecodeToken(Sampling.ArgMax(bufLogits));
    }

    /// <summary>
    /// Runs all transformer layers with float hidden state.
    /// Ternary matmuls remain integer; norms, scales, attention use float.
    /// </summary>
    private void ForwardAllLayersFloat(int seqPos)
    {
        long t0 = System.Diagnostics.Stopwatch.GetTimestamp();

        int dim    = _config.HiddenDim;
        int kvDim  = _kvDim;
        int ffnDim = _config.EffectiveFfnDim;
        var fH     = _fHidden!;
        var fNorm  = _fNorm!;
        var fQ     = _fQ!;
        var fK     = _fK!;
        var fV     = _fV!;
        var fAttn  = _fAttnOut!;

        for (int L = 0; L < _layerCount; L++)
        {
            float[]? scales = _weightScales?[L];

            // ── Attention ─────────────────────────────────────────────
            // input_layernorm → quantize → Q/K/V projections → dequantize → scale
            RmsNormWithGamma(fH.AsSpan(0, dim), fNorm.AsSpan(0, dim), _inputNorm?[L]);
            float absmax = QuantizeActivation(fNorm.AsSpan(0, dim), _iQuantized!.AsSpan(0, dim));

            TernaryMatmulDequant(_compressedWq![L], _iQuantized!, dim, fQ, absmax, scales?[0] ?? 1f);
            TernaryMatmulDequant(_compressedWk![L], _iQuantized!, dim, fK, absmax, scales?[1] ?? 1f);
            TernaryMatmulDequant(_compressedWv![L], _iQuantized!, dim, fV, absmax, scales?[2] ?? 1f);

            // RoPE on Q (nHeads) and K (nKvHeads)
            ApplyRoPE(fQ, seqPos, _config.NumHeads);
            ApplyRoPE(fK, seqPos, _kvDim / _config.HeadDim);

            // Cache K, V as float (kvDim per position)
            int cacheBase = seqPos * kvDim;
            fK.AsSpan(0, kvDim).CopyTo(_fKvCacheK![L].AsSpan(cacheBase, kvDim));
            fV.AsSpan(0, kvDim).CopyTo(_fKvCacheV![L].AsSpan(cacheBase, kvDim));

            // Float multi-head attention with GQA → fAttn
            MultiHeadAttentionFloat(L, seqPos, fQ, fAttn);

            // attn_sub_norm → quantize → Wo → dequantize → scale
            RmsNormWithGamma(fAttn.AsSpan(0, dim), fNorm.AsSpan(0, dim), _attnSubNorm?[L]);
            absmax = QuantizeActivation(fNorm.AsSpan(0, dim), _iQuantized!.AsSpan(0, dim));
            TernaryMatmulDequant(_compressedWo![L], _iQuantized!, dim, fAttn, absmax, scales?[3] ?? 1f);

            // Residual add
            for (int i = 0; i < dim; i++) fH[i] += fAttn[i];

            // ── FFN ───────────────────────────────────────────────────
            if (_config.HasGatedFfn)
            {
                var fGate = _fFfnGate!;
                var fUp   = _fFfnUp!;
                var fDown = _fFfnDown!;

                // post_attention_layernorm → quantize → gate/up projections
                RmsNormWithGamma(fH.AsSpan(0, dim), fNorm.AsSpan(0, dim), _postAttnNorm?[L]);
                absmax = QuantizeActivation(fNorm.AsSpan(0, dim), _iQuantized!.AsSpan(0, dim));

                TernaryMatmulDequant(_compressedFfnGate![L], _iQuantized!, dim, fGate, absmax, scales?[4] ?? 1f);
                TernaryMatmulDequant(_compressedFfnUp![L], _iQuantized!, dim, fUp, absmax, scales?[5] ?? 1f);

                // ReLU² gating: relu2(gate) * up
                for (int j = 0; j < ffnDim; j++)
                {
                    float g = fGate[j];
                    fDown[j] = g > 0 ? g * g * fUp[j] : 0;
                }

                // ffn_sub_norm → quantize → down_proj → dequantize → scale
                RmsNormWithGamma(fDown.AsSpan(0, ffnDim), fNorm.AsSpan(0, ffnDim), _ffnSubNorm?[L]);
                absmax = QuantizeActivation(fNorm.AsSpan(0, ffnDim), _iQuantized!.AsSpan(0, ffnDim));
                TernaryMatmulDequant(_compressedFfnDown![L], _iQuantized!, ffnDim, fAttn, absmax, scales?[6] ?? 1f);
            }
            else
            {
                RmsNormWithGamma(fH.AsSpan(0, dim), fNorm.AsSpan(0, dim), _postAttnNorm?[L]);
                absmax = QuantizeActivation(fNorm.AsSpan(0, dim), _iQuantized!.AsSpan(0, dim));
                TernaryMatmulDequant(_compressedFfnDown![L], _iQuantized!, dim, fAttn, absmax, scales?[6] ?? 1f);
            }

            // Residual add
            for (int i = 0; i < dim; i++) fH[i] += fAttn[i];
        }

        long elapsedTicks = System.Diagnostics.Stopwatch.GetTimestamp() - t0;
        long elapsedMicros = elapsedTicks * 1_000_000L / System.Diagnostics.Stopwatch.Frequency;
        Interlocked.Add(ref _totalLayerTimeMicros, elapsedMicros);
        Interlocked.Increment(ref _totalLayerTimeSamples);
    }

    /// <summary>
    /// Float multi-head self-attention with GQA and RoPE.
    /// Q is provided directly; K and V are read from the float KV cache.
    /// GQA: each Q head h uses KV head (h * nKvHeads / nHeads).
    /// </summary>
    private void MultiHeadAttentionFloat(int layer, int seqPos, float[] fQ, float[] output)
    {
        int dim     = _config.HiddenDim;
        int nHeads  = _config.NumHeads;
        int headDim = _config.HeadDim;
        int kvDim   = _kvDim;
        int nKvHeads = kvDim / headDim;
        float scale = 1f / MathF.Sqrt(headDim);

        int posCount = seqPos + 1;
        var scores   = _fScores!;

        Array.Clear(output, 0, dim);

        for (int h = 0; h < nHeads; h++)
        {
            int qOff  = h * headDim;
            // GQA: map Q head to KV head
            int kvH   = h * nKvHeads / nHeads;
            int kvOff = kvH * headDim;

            // Compute QK^T / sqrt(d_k) for all cached positions
            float maxScore = float.NegativeInfinity;
            for (int p = 0; p < posCount; p++)
            {
                int kBase = p * kvDim + kvOff;
                float dot = 0;
                for (int d = 0; d < headDim; d++)
                    dot += fQ[qOff + d] * _fKvCacheK![layer][kBase + d];
                dot *= scale;
                scores[p] = dot;
                if (dot > maxScore) maxScore = dot;
            }

            // Softmax: exp(score - max) / sum(exp(score - max))
            float sumExp = 0;
            for (int p = 0; p < posCount; p++)
            {
                float e = MathF.Exp(scores[p] - maxScore);
                scores[p] = e;
                sumExp += e;
            }
            if (sumExp > 0)
            {
                float invSum = 1f / sumExp;
                for (int p = 0; p < posCount; p++)
                    scores[p] *= invSum;
            }

            // Weighted sum of V values
            for (int p = 0; p < posCount; p++)
            {
                float w = scores[p];
                if (w < 1e-8f) continue;
                int vBase = p * kvDim + kvOff;
                for (int d = 0; d < headDim; d++)
                    output[qOff + d] += w * _fKvCacheV![layer][vBase + d];
            }
        }
    }

    // ── Float inference primitives ──────────────────────────────────────

    /// <summary>
    /// RMS normalize with learned gamma weights.
    /// output[i] = input[i] / rms(input) * gamma[i]
    /// If gamma is null, uses identity (gamma=1).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void RmsNormWithGamma(ReadOnlySpan<float> input, Span<float> output, float[]? gamma)
    {
        float sumSq = 0;
        for (int i = 0; i < input.Length; i++)
            sumSq += input[i] * input[i];
        float rms = MathF.Sqrt(sumSq / input.Length + 1e-5f);
        float invRms = 1f / rms;

        if (gamma != null)
        {
            for (int i = 0; i < input.Length; i++)
                output[i] = input[i] * invRms * gamma[i];
        }
        else
        {
            for (int i = 0; i < input.Length; i++)
                output[i] = input[i] * invRms;
        }
    }

    /// <summary>
    /// Quantize float activations to int8 range (±127) for ternary matmul input.
    /// Returns the absmax scale factor for dequantization.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static float QuantizeActivation(ReadOnlySpan<float> input, Span<int> output)
    {
        float absmax = 0;
        for (int i = 0; i < input.Length; i++)
        {
            float a = MathF.Abs(input[i]);
            if (a > absmax) absmax = a;
        }
        if (absmax < 1e-10f) absmax = 1e-10f;
        float scale = 127f / absmax;
        for (int i = 0; i < input.Length; i++)
            output[i] = (int)MathF.Round(input[i] * scale);
        return absmax;
    }

    /// <summary>
    /// Run ternary matmul on quantized int input, then dequantize output to float.
    /// float_output[i] = int_output[i] * weight_scale * absmax / 127
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void TernaryMatmulDequant(
        NativeTernaryMatrix W, int[] quantizedInput, int inputLen,
        float[] floatOutput, float absmax, float weightScale)
    {
        var iOut = _iMatmulOut!;
        W.MatVecMultiply(quantizedInput.AsSpan(0, inputLen), iOut.AsSpan(0, W.Rows));
        float dequantScale = weightScale * absmax / 127f;
        int outLen = W.Rows;
        for (int i = 0; i < outLen; i++)
            floatOutput[i] = iOut[i] * dequantScale;
    }

    /// <summary>
    /// Quantize float input → int8, run int8 matmul (NativeInt8Matrix), write int output.
    /// Used for output head projection where we need int logits for sampling.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void QuantizeAndMatmul(ReadOnlySpan<float> floatInput, NativeInt8Matrix W, Span<int> intOutput)
    {
        var iQ = _iQuantized!;
        QuantizeActivation(floatInput, iQ.AsSpan(0, floatInput.Length));
        W.MatVecMultiply(iQ.AsSpan(0, floatInput.Length), intOutput);
    }

    /// <summary>
    /// Apply RoPE (Rotary Position Embeddings) to a vector in-place.
    /// Rotates pairs of dimensions using precomputed sin/cos tables.
    /// nHeads specifies how many heads are in the vector (nKvHeads for K, nHeads for Q).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void ApplyRoPE(float[] vec, int pos, int nHeads)
    {
        if (_ropeCos == null || _ropeSin == null) return;

        int headDim = _config.HeadDim;
        int halfDim = headDim / 2;
        int ropeBase = pos * halfDim;

        for (int h = 0; h < nHeads; h++)
        {
            int hOff = h * headDim;
            for (int j = 0; j < halfDim; j++)
            {
                float cos = _ropeCos[ropeBase + j];
                float sin = _ropeSin[ropeBase + j];
                float x0 = vec[hOff + j];
                float x1 = vec[hOff + halfDim + j];
                vec[hOff + j]           = x0 * cos - x1 * sin;
                vec[hOff + halfDim + j] = x0 * sin + x1 * cos;
            }
        }
    }

    /// <summary>Embeds a token ID into the float hidden state.</summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void EmbedTokenFloat(int tokenId, float[] fHidden)
    {
        int rows = _compressedEmbeddings!.Rows;
        int id = tokenId < 0 ? 0 : tokenId >= rows ? tokenId % rows : tokenId;
        int cols = _compressedEmbeddings.Cols;
        // DecodeRow writes int8 values → convert to float
        var iTemp = _iQuantized!;
        _compressedEmbeddings.DecodeRow(id, iTemp.AsSpan(0, cols));
        for (int i = 0; i < cols; i++)
            fHidden[i] = iTemp[i];
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
    /// Maps a token ID to its display string using the loaded token table.
    /// For BPE tokenizers, converts byte-level Unicode chars to UTF-8 text.
    /// </summary>
    private string DecodeToken(int tokenId)
    {
        if (_tokenizer is not null)
            return _tokenizer.DecodeToText(tokenId);

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
            // Don't double-dispose when output head is tied to embeddings
            bool tied = ReferenceEquals(_compressedEmbeddings, _compressedOutputHead);
            _compressedEmbeddings?.Dispose(); _compressedEmbeddings = null;
            if (!tied) _compressedOutputHead?.Dispose();
            _compressedOutputHead = null;
        }

        // Clear buffer references (GC will reclaim them)
        _fHidden = _fNorm = _fQ = _fK = _fV = _fAttnOut = null;
        _fFfnGate = _fFfnUp = _fFfnDown = null;
        _fScores = null;
        _iQuantized = _iMatmulOut = _bufLogits = null;
        _fKvCacheK = null;
        _fKvCacheV = null;
        _ropeCos = _ropeSin = null;
        _weightScales = _inputNorm = _attnSubNorm = _postAttnNorm = _ffnSubNorm = null;
        _finalNorm = null;
        _tokenTable = null;
        _merges = null;
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
    int FfnDim = 0,
    int NumKvHeads = 0,
    float RopeTheta = 500_000f)
{
    /// <summary>Effective FFN intermediate dimension. Falls back to HiddenDim when not set.</summary>
    public int EffectiveFfnDim => FfnDim > 0 ? FfnDim : HiddenDim;

    /// <summary>Whether this config uses a gated FFN (SwiGLU/ReLU²) with 3 separate matrices.</summary>
    public bool HasGatedFfn => FfnDim > 0;

    /// <summary>Effective KV head count. Falls back to NumHeads (MHA) when not set.</summary>
    public int EffectiveNumKvHeads => NumKvHeads > 0 ? NumKvHeads : NumHeads;

    /// <summary>Head dimension = HiddenDim / NumHeads.</summary>
    public int HeadDim => HiddenDim / NumHeads;

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
