using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Intelligence.Tests;

public class VocabularyPrunerTests
{
    [Fact]
    public void BuildRemapTable_PrunesNonDomainTokens()
    {
        // Arrange: 8-token vocab, domain only uses 3
        var fullVocab = new[] { "<PAD>", "<BOS>", "<EOS>", "<UNK>", "hello", "world", "query", "xyzzy" };
        var pruner = new VocabularyPruner(["query"]);

        // Act: 4 special + 1 domain = 5 kept
        pruner.BuildRemapTable(fullVocab, specialTokenCount: 4);

        // Assert
        Assert.Equal(8, pruner.OriginalVocabSize);
        Assert.Equal(5, pruner.PrunedVocabSize);
        Assert.True(pruner.CompressionRatio < 1.0f);
    }

    [Fact]
    public void BuildRemapTable_KeepsSpecialTokens()
    {
        var fullVocab = new[] { "<PAD>", "<BOS>", "<EOS>", "<UNK>", "pruned1", "pruned2" };
        var pruner = new VocabularyPruner([]);

        pruner.BuildRemapTable(fullVocab, specialTokenCount: 4);

        // All 4 specials kept even with empty domain set
        Assert.Equal(4, pruner.PrunedVocabSize);
        Assert.Equal(0, pruner.MapTokenId(0)); // PAD → 0
        Assert.Equal(1, pruner.MapTokenId(1)); // BOS → 1
        Assert.Equal(-1, pruner.MapTokenId(4)); // pruned
    }

    [Fact]
    public void MapTokenId_ReturnsMappedId()
    {
        var fullVocab = new[] { "<PAD>", "keep", "prune", "also_keep" };
        var pruner = new VocabularyPruner(["keep", "also_keep"]);
        pruner.BuildRemapTable(fullVocab, specialTokenCount: 1);

        Assert.Equal(0, pruner.MapTokenId(0));   // <PAD> → 0
        Assert.Equal(1, pruner.MapTokenId(1));   // keep → 1
        Assert.Equal(-1, pruner.MapTokenId(2));  // prune → removed
        Assert.Equal(2, pruner.MapTokenId(3));   // also_keep → 2
    }

    [Fact]
    public void UnmapTokenId_ReturnsOriginalId()
    {
        var fullVocab = new[] { "<PAD>", "keep", "prune", "also_keep" };
        var pruner = new VocabularyPruner(["keep", "also_keep"]);
        pruner.BuildRemapTable(fullVocab, specialTokenCount: 1);

        Assert.Equal(0, pruner.UnmapTokenId(0)); // pruned 0 → original 0
        Assert.Equal(1, pruner.UnmapTokenId(1)); // pruned 1 → original 1
        Assert.Equal(3, pruner.UnmapTokenId(2)); // pruned 2 → original 3
    }

    [Fact]
    public void PruneEmbeddings_RetainsCorrectRows()
    {
        // 4-token vocab, hidden dim 3, keep token 0 (special) and token 2
        var fullVocab = new[] { "<PAD>", "prune1", "keep", "prune2" };
        var pruner = new VocabularyPruner(["keep"]);
        pruner.BuildRemapTable(fullVocab, specialTokenCount: 1);

        // Embeddings: each row is [hiddenDim] sbytes
        var embeddings = new sbyte[]
        {
            1, 1, 1,    // token 0: <PAD>
            -1, -1, -1, // token 1: prune1
            0, 1, -1,   // token 2: keep
            1, 0, 0,    // token 3: prune2
        };

        var pruned = pruner.PruneEmbeddings(embeddings, hiddenDim: 3);

        // Should have 2 rows: <PAD> and "keep"
        Assert.Equal(6, pruned.Length); // 2 × 3
        Assert.Equal(new sbyte[] { 1, 1, 1 }, pruned[..3]);    // <PAD>
        Assert.Equal(new sbyte[] { 0, 1, -1 }, pruned[3..6]);  // keep
    }

    [Fact]
    public void PruneEmbeddings_BeforeBuildTable_Throws()
    {
        var pruner = new VocabularyPruner(["test"]);

        Assert.Throws<InvalidOperationException>(() =>
            pruner.PruneEmbeddings(new sbyte[10], 5));
    }

    [Fact]
    public void GetStats_ReportsCorrectSavings()
    {
        var fullVocab = Enumerable.Range(0, 32000)
            .Select(i => i < 4 ? $"<SPECIAL{i}>" : $"token_{i}")
            .ToList();
        var pruner = new VocabularyPruner(["token_100", "token_200", "token_300"]);
        pruner.BuildRemapTable(fullVocab, specialTokenCount: 4);

        var stats = pruner.GetStats(hiddenDim: 2048);

        Assert.Equal(32000, stats.OriginalVocabSize);
        Assert.Equal(7, stats.PrunedVocabSize); // 4 special + 3 domain
        Assert.True(stats.BytesSaved > 0);
        Assert.True(stats.CompressionRatio < 0.01f); // 7/32000 < 1%
    }

    [Fact]
    public void MapTokenId_OutOfRange_ReturnsNegativeOne()
    {
        var pruner = new VocabularyPruner(["test"]);
        pruner.BuildRemapTable(["<PAD>", "test"], specialTokenCount: 1);

        Assert.Equal(-1, pruner.MapTokenId(999));
        Assert.Equal(-1, pruner.MapTokenId(-1));
    }

    [Fact]
    public void SplitIdentifier_SplitsPascalCase()
    {
        var result = VocabularyPruner.SplitIdentifier("BlogPost");
        Assert.Equal(new[] { "Blog", "Post" }, result);
    }

    [Fact]
    public void SplitIdentifier_SplitsCamelCase()
    {
        var result = VocabularyPruner.SplitIdentifier("userId");
        Assert.Equal(new[] { "user", "Id" }, result);
    }

    [Fact]
    public void SplitIdentifier_HandlesAllCaps()
    {
        var result = VocabularyPruner.SplitIdentifier("ID");
        Assert.Single(result);
        Assert.Equal("ID", result[0]);
    }

    [Fact]
    public void SplitIdentifier_HandlesSingleWord()
    {
        var result = VocabularyPruner.SplitIdentifier("name");
        Assert.Single(result);
        Assert.Equal("name", result[0]);
    }

    [Fact]
    public void FromDataScaffold_CreatesWithBaseVocabulary()
    {
        // DataScaffold may not be initialised, but pruner should still
        // contain base vocabulary (JSON tokens, function words, tool actions)
        var pruner = VocabularyPruner.FromDataScaffold();

        // Build against a synthetic 1000-token vocabulary
        var vocab = Enumerable.Range(0, 1000)
            .Select(i => i < 4 ? $"<S{i}>" : $"tok_{i}")
            .ToList();
        // Manually add some domain tokens into the vocab
        vocab[10] = "query";
        vocab[20] = "entity";
        vocab[30] = "list";
        vocab[40] = "help";

        pruner.BuildRemapTable(vocab, specialTokenCount: 4);

        // Should keep specials + matched domain tokens
        Assert.True(pruner.PrunedVocabSize >= 4);
        Assert.True(pruner.PrunedVocabSize < 1000);
    }
}
