namespace BareMetalWeb.Intelligence;

/// <summary>
/// Prunes entire transformer layers and attention heads from a ternary model.
/// Combined with vocabulary pruning, this can reduce a 200MB model to ~100MB.
/// </summary>
public static class ModelPruner
{
    /// <summary>
    /// Remove layers from the end of a model. For constrained domains,
    /// the final 20–30% of layers often contribute little to tool-calling accuracy.
    /// Returns a new array containing only the retained layers.
    /// </summary>
    public static TernaryLayer[] PruneLayers(
        TernaryLayer[] layers,
        int layersToKeep)
    {
        if (layersToKeep <= 0)
            throw new ArgumentOutOfRangeException(nameof(layersToKeep), "Must keep at least 1 layer");
        if (layersToKeep >= layers.Length)
            return layers; // Nothing to prune

        var pruned = new TernaryLayer[layersToKeep];
        Array.Copy(layers, pruned, layersToKeep);
        return pruned;
    }

    /// <summary>
    /// Prune attention heads by zeroing out low-importance head weight blocks.
    /// Importance is measured by the L1 norm of each head's weight slice.
    /// Heads below the threshold percentile are zeroed (effectively removed).
    /// </summary>
    public static int PruneAttentionHeads(
        TernaryLayer[] layers,
        int numHeads,
        float pruneRatio = 0.25f)
    {
        if (numHeads <= 1) return 0;
        int totalPruned = 0;
        int headsToRemove = Math.Max(1, (int)(numHeads * pruneRatio));

        for (int layerIdx = 0; layerIdx < layers.Length; layerIdx++)
        {
            ref var layer = ref layers[layerIdx];
            int dim = (int)Math.Sqrt(layer.AttentionWeights.Length);
            if (dim * dim != layer.AttentionWeights.Length) continue;

            int headDim = dim / numHeads;
            if (headDim == 0) continue;

            // Compute L1 norm for each head
            var headNorms = new (int Index, long Norm)[numHeads];
            for (int h = 0; h < numHeads; h++)
            {
                long norm = 0;
                int headStart = h * headDim;
                for (int r = 0; r < dim; r++)
                {
                    int rowOffset = r * dim;
                    for (int c = headStart; c < headStart + headDim; c++)
                    {
                        norm += Math.Abs(layer.AttentionWeights[rowOffset + c]);
                    }
                }
                headNorms[h] = (h, norm);
            }

            // Sort by norm ascending — lowest importance first
            Array.Sort(headNorms, (a, b) => a.Norm.CompareTo(b.Norm));

            // Zero out the least important heads
            for (int p = 0; p < headsToRemove; p++)
            {
                int headIdx = headNorms[p].Index;
                int headStart = headIdx * headDim;
                for (int r = 0; r < dim; r++)
                {
                    int rowOffset = r * dim;
                    for (int c = headStart; c < headStart + headDim; c++)
                    {
                        layer.AttentionWeights[rowOffset + c] = 0;
                    }
                }
                totalPruned++;
            }
        }

        return totalPruned;
    }

    /// <summary>
    /// Get the total ternary weight count across all layers.
    /// Useful for calculating memory before/after pruning.
    /// </summary>
    public static ModelSizeStats CalculateSize(
        TernaryLayer[] layers,
        int vocabSize,
        int hiddenDim)
    {
        long layerWeights = 0;
        long zeroWeights = 0;

        for (int i = 0; i < layers.Length; i++)
        {
            layerWeights += layers[i].AttentionWeights.Length;
            layerWeights += layers[i].FfnWeights.Length;

            for (int j = 0; j < layers[i].AttentionWeights.Length; j++)
                if (layers[i].AttentionWeights[j] == 0) zeroWeights++;
            for (int j = 0; j < layers[i].FfnWeights.Length; j++)
                if (layers[i].FfnWeights[j] == 0) zeroWeights++;
        }

        long embeddingWeights = (long)vocabSize * hiddenDim * 2; // embed + output
        long totalWeights = layerWeights + embeddingWeights;

        // Ternary: 1.58 bits per weight, but stored as sbyte (1 byte) in this spike
        // With proper packing: 2 bits per weight
        long storedBytes = totalWeights;
        long packedBytes = (totalWeights * 2 + 7) / 8; // 2-bit packed

        float sparsity = layerWeights > 0
            ? (float)zeroWeights / layerWeights
            : 0f;

        return new ModelSizeStats(
            TotalWeights: totalWeights,
            LayerWeights: layerWeights,
            EmbeddingWeights: embeddingWeights,
            ZeroWeights: zeroWeights,
            StoredBytes: storedBytes,
            PackedBytes: packedBytes,
            Sparsity: sparsity,
            LayerCount: layers.Length);
    }
}

/// <summary>
/// Size statistics for a ternary model.
/// </summary>
public readonly record struct ModelSizeStats(
    long TotalWeights,
    long LayerWeights,
    long EmbeddingWeights,
    long ZeroWeights,
    long StoredBytes,
    long PackedBytes,
    float Sparsity,
    int LayerCount
)
{
    public string Summary =>
        $"Weights: {TotalWeights:N0} total ({LayerWeights:N0} layers + {EmbeddingWeights:N0} embeddings), " +
        $"Zeros: {ZeroWeights:N0} ({Sparsity:P1} sparsity), " +
        $"Size: {StoredBytes / 1024:N0} KB stored / {PackedBytes / 1024:N0} KB packed (2-bit), " +
        $"Layers: {LayerCount}";

    /// <summary>
    /// Savings ratio from sbyte[] to 2-bit packed native: 1.0 - (packed / stored).
    /// </summary>
    public float CompressionSavings =>
        StoredBytes > 0 ? 1f - (float)PackedBytes / StoredBytes : 0f;
}
