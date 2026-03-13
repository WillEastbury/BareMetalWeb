namespace BareMetalWeb.Intelligence.Interfaces;

/// <summary>
/// Ternary inference engine for BitNet b1.58 models.
/// Weights are restricted to {-1, 0, +1}, enabling pure integer SIMD inference.
/// </summary>
public interface IBitNetEngine
{
    /// <summary>
    /// Whether a model is currently loaded and ready for inference.
    /// </summary>
    bool IsLoaded { get; }

    /// <summary>
    /// Generate a response from the ternary model.
    /// </summary>
    ValueTask<string> GenerateAsync(
        ReadOnlyMemory<char> prompt,
        int maxTokens = 256,
        CancellationToken ct = default);

    /// <summary>
    /// Return aggregated memory, token throughput, and accuracy metrics
    /// for the pipeline. Returns <see langword="null"/> if no model is loaded.
    /// </summary>
    BitNetPipelineMetrics? GetMetrics();
}
