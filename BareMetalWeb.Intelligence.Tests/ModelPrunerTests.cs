using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Intelligence.Tests;

public class ModelPrunerTests
{
    private static TernaryLayer[] CreateTestLayers(int count, int dim, int seed = 42)
    {
        var layers = new TernaryLayer[count];
        for (int i = 0; i < count; i++)
            layers[i] = CreateDeterministicLayer(dim, 4, seed + i);
        return layers;
    }

    private static TernaryLayer CreateDeterministicLayer(int dim, int numHeads, int seed)
    {
        _ = numHeads;
        var rng = new Random(seed);
        return new TernaryLayer
        {
            Wq = CreateWeights(dim * dim, rng),
            Wk = CreateWeights(dim * dim, rng),
            Wv = CreateWeights(dim * dim, rng),
            Wo = CreateWeights(dim * dim, rng),
            FfnWeights = CreateWeights(dim * dim, rng)
        };
    }

    private static sbyte[] CreateWeights(int count, Random rng)
    {
        var weights = new sbyte[count];
        for (int i = 0; i < weights.Length; i++)
            weights[i] = (sbyte)(rng.Next(3) - 1);
        return weights;
    }

    [Fact]
    public void PruneLayers_KeepsFewer_ReturnsSubset()
    {
        var layers = CreateTestLayers(8, 32);

        var pruned = ModelPruner.PruneLayers(layers, 6);

        Assert.Equal(6, pruned.Length);
        // First 6 layers should be identical to original
        for (int i = 0; i < 6; i++)
            Assert.Same(layers[i].Wq, pruned[i].Wq);
    }

    [Fact]
    public void PruneLayers_KeepAll_ReturnsSameArray()
    {
        var layers = CreateTestLayers(4, 32);

        var result = ModelPruner.PruneLayers(layers, 10); // keep more than exist

        Assert.Same(layers, result);
    }

    [Fact]
    public void PruneLayers_KeepZero_Throws()
    {
        var layers = CreateTestLayers(4, 32);

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ModelPruner.PruneLayers(layers, 0));
    }

    [Fact]
    public void PruneAttentionHeads_ZerosLowImportanceHeads()
    {
        // Create layers with known weights
        int dim = 8;
        int numHeads = 4;
        var layers = new TernaryLayer[1];
        layers[0] = new TernaryLayer
        {
            Wq = new sbyte[dim * dim], Wk = new sbyte[dim * dim], Wv = new sbyte[dim * dim], Wo = new sbyte[dim * dim],
            FfnWeights = new sbyte[dim * dim]
        };

        // Fill attention weights: head 0 has all 1s (high norm), others have 0s
        for (int r = 0; r < dim; r++)
        {
            for (int c = 0; c < 2; c++) // head 0 columns (headDim=2)
                layers[0].Wq[r * dim + c] = 1;
        }

        int pruned = ModelPruner.PruneAttentionHeads(layers, numHeads, pruneRatio: 0.50f);

        // Should have pruned 2 of 4 heads (50%)
        Assert.Equal(2, pruned);

        // Head 0 should still have non-zero values (highest norm)
        bool head0HasValues = false;
        for (int r = 0; r < dim; r++)
        {
            if (layers[0].Wq[r * dim] != 0)
            {
                head0HasValues = true;
                break;
            }
        }
        Assert.True(head0HasValues, "Highest-norm head should be retained");
    }

    [Fact]
    public void PruneAttentionHeads_SingleHead_ReturnsZero()
    {
        var layers = CreateTestLayers(2, 16);

        int pruned = ModelPruner.PruneAttentionHeads(layers, numHeads: 1);

        Assert.Equal(0, pruned);
    }

    [Fact]
    public void CalculateSize_ReportsCorrectTotals()
    {
        int dim = 32;
        var layers = CreateTestLayers(4, dim);

        var stats = ModelPruner.CalculateSize(layers, vocabSize: 100, hiddenDim: dim);

        // Each layer: 4 attention projections (Wq,Wk,Wv,Wo) + FFN = 5 × dim² weights
        // 4 layers × 5 × 32 × 32 = 20480 layer weights
        Assert.Equal(20480, stats.LayerWeights);
        // Embedding: 100 * 32 * 2 (embed + output) = 6400
        Assert.Equal(6400, stats.EmbeddingWeights);
        Assert.Equal(20480 + 6400, stats.TotalWeights);
        Assert.Equal(4, stats.LayerCount);
        Assert.True(stats.PackedBytes < stats.StoredBytes); // 2-bit < 8-bit
    }

    [Fact]
    public void CalculateSize_Sparsity_ReflectsZeros()
    {
        int dim = 4;
        var layers = new TernaryLayer[1];
        layers[0] = new TernaryLayer
        {
            Wq = new sbyte[dim * dim], Wk = new sbyte[dim * dim], Wv = new sbyte[dim * dim], Wo = new sbyte[dim * dim], // all zeros
            FfnWeights = new sbyte[] { 1, -1, 0, 0, 1, -1, 0, 0, 1, -1, 0, 0, 1, -1, 0, 0 }
        };

        var stats = ModelPruner.CalculateSize(layers, vocabSize: 0, hiddenDim: dim);

        // All 4 attention matrices are zero (4 × 16 = 64 zeros) + 8 FFN zeros = 72
        // Total layer weights: 4 × 16 (attn) + 16 (FFN) = 80
        Assert.Equal(72, stats.ZeroWeights);
        Assert.Equal(0.9f, stats.Sparsity, 0.01f);
    }

    [Fact]
    public void CalculateSize_Summary_ContainsKeyInfo()
    {
        var layers = CreateTestLayers(2, 16);
        var stats = ModelPruner.CalculateSize(layers, vocabSize: 50, hiddenDim: 16);

        Assert.Contains("Weights:", stats.Summary);
        Assert.Contains("Layers: 2", stats.Summary);
        Assert.Contains("packed", stats.Summary);
    }

    // ── Group-of-four pruning tests ──────────────────────────────

    [Fact]
    public void PruneGroupsOfFour_ZerosLowL1Groups()
    {
        // 1 row of 8 weights: two groups of 4
        // Group 0: {1, 0, 0, 0} → L1 = 1 → zeroed at threshold 1
        // Group 1: {1, -1, 1, 0} → L1 = 3 → kept at threshold 1
        sbyte[] weights = [1, 0, 0, 0, 1, -1, 1, 0];

        int zeroed = ModelPruner.PruneGroupsOfFour(weights, cols: 8, threshold: 1);

        Assert.Equal(1, zeroed);
        Assert.Equal(0, weights[0]); // group 0 zeroed
        Assert.Equal(0, weights[1]);
        Assert.Equal(0, weights[2]);
        Assert.Equal(0, weights[3]);
        Assert.Equal(1, weights[4]); // group 1 kept
        Assert.Equal(-1, weights[5]);
    }

    [Fact]
    public void PruneGroupsOfFour_ThresholdZero_NoPruning()
    {
        sbyte[] weights = [1, 0, 0, 0, 0, 0, 0, 0];

        int zeroed = ModelPruner.PruneGroupsOfFour(weights, cols: 8, threshold: 0);

        Assert.Equal(0, zeroed);
        Assert.Equal(1, weights[0]); // unchanged
    }

    [Fact]
    public void PruneGroupsOfFour_HighThreshold_ZerosEverything()
    {
        sbyte[] weights = [1, -1, 1, -1, 1, 0, 0, 0];

        int zeroed = ModelPruner.PruneGroupsOfFour(weights, cols: 8, threshold: 4);

        Assert.Equal(2, zeroed);
        Assert.True(weights.All(w => w == 0));
    }

    [Fact]
    public void PruneGroupsOfFour_MultiRow_PrunesPerRow()
    {
        // 2 rows × 4 cols
        // Row 0: {1, 0, 0, 0} L1=1 → zeroed at threshold 1
        // Row 1: {1, 1, 0, 0} L1=2 → kept at threshold 1
        sbyte[] weights = [1, 0, 0, 0, 1, 1, 0, 0];

        int zeroed = ModelPruner.PruneGroupsOfFour(weights, cols: 4, threshold: 1);

        Assert.Equal(1, zeroed);
        Assert.Equal(0, weights[0]); // row 0 zeroed
        Assert.Equal(1, weights[4]); // row 1 kept
    }

    [Fact]
    public void PruneGroupsOfFour_AlreadyZero_NotDoubleCounted()
    {
        sbyte[] weights = [0, 0, 0, 0, 1, -1, 1, -1];

        int zeroed = ModelPruner.PruneGroupsOfFour(weights, cols: 8, threshold: 1);

        // Group 0 is already zero → L1=0 ≤ 1, so counted as zeroed
        Assert.Equal(1, zeroed);
    }

    [Fact]
    public void PruneLayerGroups_DifferentThresholds_ForAttnAndFfn()
    {
        int dim = 8;
        var layers = new TernaryLayer[2];
        for (int i = 0; i < 2; i++)
        {
            layers[i] = new TernaryLayer
            {
                Wq = new sbyte[dim * dim], Wk = new sbyte[dim * dim], Wv = new sbyte[dim * dim], Wo = new sbyte[dim * dim],
                FfnWeights = new sbyte[dim * dim]
            };
            // Fill with low-magnitude groups: every group has L1 = 1
            for (int g = 0; g < dim * dim; g += 4)
            {
                layers[i].Wq[g] = 1;
                layers[i].FfnWeights[g] = 1;
            }
        }

        // Attn threshold 0 (skip), FFN threshold 1 (prune L1≤1 groups)
        var stats = ModelPruner.PruneLayerGroups(layers, dim,
            attnThreshold: 0, ffnThreshold: 1);

        Assert.Equal(0, stats.AttnGroupsZeroed);
        Assert.True(stats.FfnGroupsZeroed > 0);
        Assert.Equal(0f, stats.AttnGroupSparsity);
        Assert.True(stats.FfnGroupSparsity > 0f);
    }

    [Fact]
    public void PruneLayerGroups_Stats_HasCorrectTotals()
    {
        int dim = 8;
        var layers = new TernaryLayer[1];
        layers[0] = CreateDeterministicLayer(dim, 4, seed: 99);

        var stats = ModelPruner.PruneLayerGroups(layers, dim,
            attnThreshold: 1, ffnThreshold: 2);

        // Total groups = rows × groups_per_row = 8 × (8/4) = 16 per matrix
        // There are 4 attention projection matrices and 1 FFN matrix
        Assert.Equal(64, stats.TotalAttnGroups);  // 4 × 16
        Assert.Equal(16, stats.TotalFfnGroups);
        Assert.True(stats.TotalWeightsZeroed == stats.TotalGroupsZeroed * 4);
    }

    [Fact]
    public void GroupPruneStats_Summary_ContainsThresholds()
    {
        var stats = new GroupPruneStats(10, 20, 100, 100, 1, 2);

        Assert.Contains("L1≤1", stats.Summary);
        Assert.Contains("L1≤2", stats.Summary);
        Assert.Contains("Attn", stats.Summary);
        Assert.Contains("FFN", stats.Summary);
    }
}
