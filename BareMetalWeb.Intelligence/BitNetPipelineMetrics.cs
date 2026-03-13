namespace BareMetalWeb.Intelligence;

/// <summary>
/// Aggregated runtime and model metrics for the BitNet b1.58 inference pipeline.
/// Includes weight memory (original sbyte[] vs 2-bit packed), token throughput
/// counters, and accuracy/load stats from each pruning stage.
/// </summary>
public readonly record struct BitNetPipelineMetrics(
    // ── Weight memory ────────────────────────────────────────────────────────
    /// <summary>
    /// Original in-memory size of all weight matrices stored as sbyte[]
    /// (1 byte per ternary weight) before 2-bit packing.
    /// </summary>
    long OriginalWeightBytes,

    /// <summary>
    /// Trimmed (2-bit packed, native/unmanaged) in-memory size after compression.
    /// Approximately 4× smaller than <see cref="OriginalWeightBytes"/>.
    /// </summary>
    long TrimmedWeightBytes,

    /// <summary>
    /// Compression ratio: fraction of memory saved vs. the original sbyte[].
    /// </summary>
    float CompressionSavings,

    // ── Model shape ──────────────────────────────────────────────────────────
    long TotalWeights,
    long ZeroWeights,
    float Sparsity,
    int LayerCount,
    long EmbeddingWeights,

    // ── Token counters (lifetime totals, thread-safe) ─────────────────────
    /// <summary>Total input characters submitted across all <c>GenerateAsync</c> calls.</summary>
    long TotalTokensIn,

    /// <summary>Total output characters produced across all <c>GenerateAsync</c> calls.</summary>
    long TotalTokensOut,

    /// <summary>Total number of completed <c>GenerateAsync</c> requests.</summary>
    long TotalRequests,

    /// <summary>Cumulative inference wall-clock time in milliseconds.</summary>
    long TotalInferenceMs,

    // ── Load / accuracy stats ────────────────────────────────────────────────
    /// <summary>Pre-pruning accuracy estimate from semantic pruning (0–1), or null if semantic pruning was not run.</summary>
    float? PrePruneAccuracy,

    /// <summary>Post-pruning accuracy estimate from semantic pruning (0–1), or null if semantic pruning was not run.</summary>
    float? PostPruneAccuracy,

    /// <summary>Number of semantic test cases used for accuracy estimation, or null if not available.</summary>
    int? SemanticTestCaseCount,

    /// <summary>Vocabulary reduction: original vocab size before pruning.</summary>
    int OriginalVocabSize,

    /// <summary>Vocabulary reduction: pruned vocab size after pruning (equals original if pruning was not applied).</summary>
    int PrunedVocabSize
)
{
    /// <summary>
    /// Human-readable single-line summary of the key pipeline metrics.
    /// </summary>
    public string Summary =>
        $"Memory: {OriginalWeightBytes / 1024:N0} KB original → {TrimmedWeightBytes / 1024:N0} KB packed ({CompressionSavings:P0} saving), " +
        $"Tokens: {TotalTokensIn:N0} in / {TotalTokensOut:N0} out over {TotalRequests:N0} requests ({TotalInferenceMs:N0} ms total), " +
        $"Weights: {TotalWeights:N0} ({Sparsity:P1} sparse), " +
        $"Vocab: {PrunedVocabSize}/{OriginalVocabSize}" +
        (PrePruneAccuracy.HasValue
            ? $", Accuracy: {PrePruneAccuracy:P0}→{PostPruneAccuracy:P0}"
            : "");
}
