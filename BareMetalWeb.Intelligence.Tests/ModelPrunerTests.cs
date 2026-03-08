using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Intelligence.Tests;

public class ModelPrunerTests
{
    private static TernaryLayer[] CreateTestLayers(int count, int dim)
    {
        var layers = new TernaryLayer[count];
        for (int i = 0; i < count; i++)
            layers[i] = TernaryLayer.CreateRandom(dim, 4);
        return layers;
    }

    [Fact]
    public void PruneLayers_KeepsFewer_ReturnsSubset()
    {
        var layers = CreateTestLayers(8, 32);

        var pruned = ModelPruner.PruneLayers(layers, 6);

        Assert.Equal(6, pruned.Length);
        // First 6 layers should be identical to original
        for (int i = 0; i < 6; i++)
            Assert.Same(layers[i].AttentionWeights, pruned[i].AttentionWeights);
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
            AttentionWeights = new sbyte[dim * dim],
            FfnWeights = new sbyte[dim * dim]
        };

        // Fill attention weights: head 0 has all 1s (high norm), others have 0s
        for (int r = 0; r < dim; r++)
        {
            for (int c = 0; c < 2; c++) // head 0 columns (headDim=2)
                layers[0].AttentionWeights[r * dim + c] = 1;
        }

        int pruned = ModelPruner.PruneAttentionHeads(layers, numHeads, pruneRatio: 0.50f);

        // Should have pruned 2 of 4 heads (50%)
        Assert.Equal(2, pruned);

        // Head 0 should still have non-zero values (highest norm)
        bool head0HasValues = false;
        for (int r = 0; r < dim; r++)
        {
            if (layers[0].AttentionWeights[r * dim] != 0)
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

        // Each layer: dim*dim attention + dim*dim ffn = 32*32*2 = 2048 weights
        // 4 layers = 8192 layer weights
        Assert.Equal(8192, stats.LayerWeights);
        // Embedding: 100 * 32 * 2 (embed + output) = 6400
        Assert.Equal(6400, stats.EmbeddingWeights);
        Assert.Equal(8192 + 6400, stats.TotalWeights);
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
            AttentionWeights = new sbyte[dim * dim], // all zeros
            FfnWeights = new sbyte[] { 1, -1, 0, 0, 1, -1, 0, 0, 1, -1, 0, 0, 1, -1, 0, 0 }
        };

        var stats = ModelPruner.CalculateSize(layers, vocabSize: 0, hiddenDim: dim);

        // 16 zeros in attention + 8 zeros in FFN = 24 zeros out of 32 total
        Assert.Equal(24, stats.ZeroWeights);
        Assert.Equal(0.75f, stats.Sparsity, 0.01f);
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
}
