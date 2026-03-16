using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Intelligence.Tests;

public class SemanticPrunerTests
{
    private static TernaryLayer[] CreateSmallModel(int dim, int layers, int seed = 42)
    {
        var result = new TernaryLayer[layers];
        for (int i = 0; i < layers; i++)
            result[i] = CreateDeterministicLayer(dim, 4, seed + i);
        return result;
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

    // ── IntentAst tests ─────────────────────────────────────────────────

    [Fact]
    public void IntentAst_SemanticallyEquals_SameIntent_ReturnsTrue()
    {
        var a = new IntentAst("query-entity", "customers");
        var b = new IntentAst("query-entity", "customers", "active");
        Assert.True(a.SemanticallyEquals(b));
    }

    [Fact]
    public void IntentAst_SemanticallyEquals_DifferentIntent_ReturnsFalse()
    {
        var a = new IntentAst("query-entity");
        var b = new IntentAst("list-entities");
        Assert.False(a.SemanticallyEquals(b));
    }

    [Fact]
    public void IntentAst_SemanticallyEquals_NullEntity_IgnoresEntity()
    {
        var a = new IntentAst("query-entity");
        var b = new IntentAst("query-entity", "orders");
        Assert.True(a.SemanticallyEquals(b));
    }

    [Fact]
    public void IntentAst_SemanticallyEquals_CaseInsensitive()
    {
        var a = new IntentAst("Query-Entity", "Customers");
        var b = new IntentAst("query-entity", "customers");
        Assert.True(a.SemanticallyEquals(b));
    }

    // ── Corpus tests ────────────────────────────────────────────────────

    [Fact]
    public void GetDomainCorpus_ReturnsNonEmpty()
    {
        var corpus = SemanticPruner.GetDomainCorpus();
        Assert.True(corpus.Length >= 10);
        Assert.All(corpus, tc =>
        {
            Assert.NotNull(tc.Prompt);
            Assert.NotNull(tc.Expected);
            Assert.NotEmpty(tc.Expected.Intent);
        });
    }

    // ── ForwardPass tests ───────────────────────────────────────────────

    [Fact]
    public void ForwardPass_IsDeterministic()
    {
        int dim = 32;
        var layers = CreateSmallModel(dim, 2);

        var out1 = SemanticPruner.ForwardPass(layers, dim, "test prompt");
        var out2 = SemanticPruner.ForwardPass(layers, dim, "test prompt");

        Assert.Equal(out1, out2);
    }

    [Fact]
    public void ForwardPass_DifferentPrompts_DifferentOutputs()
    {
        int dim = 32;
        var layers = CreateSmallModel(dim, 2);

        var out1 = SemanticPruner.ForwardPass(layers, dim, "list entities");
        var out2 = SemanticPruner.ForwardPass(layers, dim, "system status");

        Assert.NotEqual(out1, out2);
    }

    // ── CosineSimilarity tests ──────────────────────────────────────────

    [Fact]
    public void CosineSimilarityInt_IdenticalVectors_ReturnsOne()
    {
        int[] a = [1, 2, 3, 4, 5];
        float sim = SemanticPruner.CosineSimilarityInt(a, a);
        Assert.InRange(sim, 0.999f, 1.001f);
    }

    [Fact]
    public void CosineSimilarityInt_Orthogonal_ReturnsZero()
    {
        int[] a = [1, 0, 0, 0];
        int[] b = [0, 1, 0, 0];
        float sim = SemanticPruner.CosineSimilarityInt(a, b);
        Assert.InRange(sim, -0.001f, 0.001f);
    }

    [Fact]
    public void CosineSimilarityInt_Opposite_ReturnsNegOne()
    {
        int[] a = [1, 2, 3];
        int[] b = [-1, -2, -3];
        float sim = SemanticPruner.CosineSimilarityInt(a, b);
        Assert.InRange(sim, -1.001f, -0.999f);
    }

    // ── Activation stats tests ──────────────────────────────────────────

    [Fact]
    public void CollectActivationStats_ReturnsScoresForAllHeads()
    {
        int dim = 16;
        int numHeads = 4;
        var layers = CreateSmallModel(dim, 2);
        var corpus = new[]
        {
            new SemanticTestCase("test one", new IntentAst("query-entity")),
            new SemanticTestCase("test two", new IntentAst("list-entities")),
        };

        var profile = SemanticPruner.CollectActivationStats(
            layers, dim, numHeads, corpus);

        Assert.Equal(2 * numHeads, profile.HeadScores.Length);
        Assert.All(profile.HeadScores, hs => Assert.True(hs.Score >= 0));
    }

    [Fact]
    public void CollectActivationStats_BlockScores_NonNegative()
    {
        int dim = 16;
        var layers = CreateSmallModel(dim, 2);
        var corpus = new[]
        {
            new SemanticTestCase("test", new IntentAst("help")),
        };

        var profile = SemanticPruner.CollectActivationStats(
            layers, dim, 4, corpus, blockSize: 16);

        Assert.True(profile.BlockScores.Length > 0);
        Assert.All(profile.BlockScores, bs => Assert.True(bs.Score >= 0));
    }

    // ── Drift check tests ───────────────────────────────────────────────

    [Fact]
    public void CheckDriftAcceptable_UnmodifiedModel_ReturnsTrue()
    {
        int dim = 16;
        var layers = CreateSmallModel(dim, 2);
        var corpus = new[]
        {
            new SemanticTestCase("query data", new IntentAst("query-entity")),
        };
        var baselines = SemanticPruner.ComputeAllOutputs(layers, dim, corpus);

        bool ok = SemanticPruner.CheckDriftAcceptable(
            layers, dim, corpus, baselines, threshold: 0.99f);

        Assert.True(ok);
    }

    // ── MeasureIntentStability tests ────────────────────────────────────

    [Fact]
    public void MeasureIntentStability_UnchangedModel_Returns1()
    {
        int dim = 16;
        var layers = CreateSmallModel(dim, 2);
        var corpus = new[]
        {
            new SemanticTestCase("test", new IntentAst("help")),
            new SemanticTestCase("data", new IntentAst("query-entity")),
        };
        var baselines = SemanticPruner.ComputeAllOutputs(layers, dim, corpus);

        float accuracy = SemanticPruner.MeasureIntentStability(
            layers, dim, corpus, baselines);

        Assert.Equal(1.0f, accuracy);
    }

    // ── Full pipeline tests ─────────────────────────────────────────────

    [Fact]
    public void Prune_SmallModel_ReturnsValidStats()
    {
        int dim = 32;
        int numHeads = 4;
        var layers = CreateSmallModel(dim, 2);

        var stats = SemanticPruner.Prune(
            layers, dim, numHeads,
            headPruneRatio: 0.25f,
            neuronPruneRatio: 0.10f,
            blockPruneRatio: 0.05f,
            driftThreshold: 0.90f);

        Assert.True(stats.TestCaseCount > 0);
        Assert.True(stats.PrePruneAccuracy >= 0f);
        Assert.True(stats.PostPruneAccuracy >= 0f);
        Assert.True(stats.HeadsPruned >= 0);
        Assert.True(stats.NeuronsPruned >= 0);
        Assert.True(stats.BlocksPruned >= 0);
        Assert.True(stats.FineGroupsPruned >= 0);
    }

    [Fact]
    public void Prune_IncreasesSparsity()
    {
        int dim = 32;
        var layers = CreateSmallModel(dim, 2);

        // Count zeros before
        long zerosBefore = CountZeros(layers);

        SemanticPruner.Prune(layers, dim, numHeads: 4,
            driftThreshold: 0.80f);

        long zerosAfter = CountZeros(layers);
        Assert.True(zerosAfter >= zerosBefore,
            $"Sparsity should not decrease. Before: {zerosBefore}, After: {zerosAfter}");
    }

    [Fact]
    public void Prune_WithCustomCorpus_Works()
    {
        int dim = 16;
        var layers = CreateSmallModel(dim, 2);
        var corpus = new[]
        {
            new SemanticTestCase("show items", new IntentAst("list-entities")),
            new SemanticTestCase("find data", new IntentAst("query-entity")),
        };

        var stats = SemanticPruner.Prune(layers, dim, numHeads: 4,
            corpus: corpus, driftThreshold: 0.85f);

        Assert.Equal(2, stats.TestCaseCount);
    }

    [Fact]
    public void Prune_Stats_Summary_ContainsKeyInfo()
    {
        var stats = new SemanticPruningStats(
            HeadsPruned: 2,
            NeuronsPruned: 10,
            BlocksPruned: 5,
            FineGroupsPruned: 100,
            PrePruneAccuracy: 1.0f,
            PostPruneAccuracy: 0.95f,
            TestCaseCount: 18);

        Assert.Contains("heads=2", stats.Summary);
        Assert.Contains("neurons=10", stats.Summary);
        Assert.Contains("blocks=5", stats.Summary);
        Assert.Contains("fine-groups=100", stats.Summary);
    }

    [Fact]
    public void Prune_IntegratesWithModelStats()
    {
        int dim = 32;
        var layers = CreateSmallModel(dim, 2);

        var stats = SemanticPruner.Prune(
            layers, dim, numHeads: 4,
            headPruneRatio: 0.25f,
            neuronPruneRatio: 0.10f,
            blockPruneRatio: 0.05f,
            driftThreshold: 0.80f);
        var sizeStats = ModelPruner.CalculateSize(layers, vocabSize: 64, hiddenDim: dim);

        Assert.True(stats.TestCaseCount > 0);
        Assert.True(sizeStats.Sparsity > 0);
    }

    private static long CountZeros(TernaryLayer[] layers)
    {
        long count = 0;
        foreach (var layer in layers)
        {
            foreach (var w in layer.AttentionWeights)
                if (w == 0) count++;
            foreach (var w in layer.FfnWeights)
                if (w == 0) count++;
        }
        return count;
    }
}
