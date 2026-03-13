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
    /// Group-of-four structured pruning. Operates on aligned 4-weight groups
    /// that map 1:1 to packed bytes in NativeTernaryMatrix. If the L1 norm of
    /// a group is below <paramref name="threshold"/>, all 4 weights are zeroed,
    /// producing a 0x00 packed byte that the dot-product skips entirely.
    /// </summary>
    /// <param name="weights">Ternary weight array to prune in-place.</param>
    /// <param name="cols">Number of columns (for row-major stride).</param>
    /// <param name="threshold">L1 threshold (1–4). Groups with sum ≤ threshold are zeroed.</param>
    /// <returns>Number of 4-weight groups zeroed.</returns>
    public static int PruneGroupsOfFour(sbyte[] weights, int cols, int threshold)
    {
        if (threshold <= 0) return 0;
        int rows = weights.Length / cols;
        int groupsPerRow = cols >> 2; // full groups of 4 per row
        int groupsZeroed = 0;

        for (int r = 0; r < rows; r++)
        {
            int rowOffset = r * cols;
            for (int g = 0; g < groupsPerRow; g++)
            {
                int idx = rowOffset + g * 4;
                int l1 = Math.Abs(weights[idx])
                        + Math.Abs(weights[idx + 1])
                        + Math.Abs(weights[idx + 2])
                        + Math.Abs(weights[idx + 3]);

                if (l1 <= threshold)
                {
                    weights[idx] = 0;
                    weights[idx + 1] = 0;
                    weights[idx + 2] = 0;
                    weights[idx + 3] = 0;
                    groupsZeroed++;
                }
            }
        }

        return groupsZeroed;
    }

    /// <summary>
    /// Apply group-of-four pruning to all layers with layer-specific thresholds.
    /// FFN layers tolerate more aggressive pruning than attention layers.
    /// </summary>
    /// <returns>Statistics about groups zeroed per matrix type.</returns>
    public static GroupPruneStats PruneLayerGroups(
        TernaryLayer[] layers,
        int cols,
        int attnThreshold = 1,
        int ffnThreshold = 2)
    {
        int totalAttnGroups = 0;
        int totalFfnGroups = 0;

        for (int i = 0; i < layers.Length; i++)
        {
            totalAttnGroups += PruneGroupsOfFour(layers[i].Wq, cols, attnThreshold);
            totalAttnGroups += PruneGroupsOfFour(layers[i].Wk, cols, attnThreshold);
            totalAttnGroups += PruneGroupsOfFour(layers[i].Wv, cols, attnThreshold);
            totalAttnGroups += PruneGroupsOfFour(layers[i].Wo, cols, attnThreshold);
            totalFfnGroups  += PruneGroupsOfFour(layers[i].FfnWeights, cols, ffnThreshold);
        }

        int groupsPerMatrix = (layers[0].Wq.Length / cols) * (cols >> 2);
        int totalMatrices = layers.Length;

        return new GroupPruneStats(
            AttnGroupsZeroed: totalAttnGroups,
            FfnGroupsZeroed: totalFfnGroups,
            TotalAttnGroups: groupsPerMatrix * 4 * totalMatrices,  // 4 attention projections
            TotalFfnGroups: groupsPerMatrix * totalMatrices,
            AttnThreshold: attnThreshold,
            FfnThreshold: ffnThreshold);
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
            layerWeights += layers[i].Wq.Length + layers[i].Wk.Length
                          + layers[i].Wv.Length + layers[i].Wo.Length;
            layerWeights += layers[i].FfnWeights.Length;

            for (int j = 0; j < layers[i].Wq.Length; j++)
                if (layers[i].Wq[j] == 0) zeroWeights++;
            for (int j = 0; j < layers[i].Wk.Length; j++)
                if (layers[i].Wk[j] == 0) zeroWeights++;
            for (int j = 0; j < layers[i].Wv.Length; j++)
                if (layers[i].Wv[j] == 0) zeroWeights++;
            for (int j = 0; j < layers[i].Wo.Length; j++)
                if (layers[i].Wo[j] == 0) zeroWeights++;
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

/// <summary>
/// Statistics from group-of-four structured pruning.
/// </summary>
public readonly record struct GroupPruneStats(
    int AttnGroupsZeroed,
    int FfnGroupsZeroed,
    int TotalAttnGroups,
    int TotalFfnGroups,
    int AttnThreshold,
    int FfnThreshold
)
{
    public float AttnGroupSparsity => TotalAttnGroups > 0
        ? (float)AttnGroupsZeroed / TotalAttnGroups : 0f;

    public float FfnGroupSparsity => TotalFfnGroups > 0
        ? (float)FfnGroupsZeroed / TotalFfnGroups : 0f;

    public int TotalGroupsZeroed => AttnGroupsZeroed + FfnGroupsZeroed;

    public int TotalWeightsZeroed => TotalGroupsZeroed * 4;

    public string Summary =>
        $"Group pruning: Attn {AttnGroupsZeroed:N0}/{TotalAttnGroups:N0} ({AttnGroupSparsity:P0} @ L1≤{AttnThreshold}), " +
        $"FFN {FfnGroupsZeroed:N0}/{TotalFfnGroups:N0} ({FfnGroupSparsity:P0} @ L1≤{FfnThreshold})";
}
