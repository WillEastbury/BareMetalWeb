using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Intelligence.Tests;

public class TokenizerTests
{
    private static Tokenizer CreateDefault()
    {
        // Minimal vocab: PAD, BOS, EOS, UNK, "hello", "world", "query"
        var vocab = new string[7];
        vocab[Tokenizer.PadId] = "<PAD>";
        vocab[Tokenizer.BosId] = "<BOS>";
        vocab[Tokenizer.EosId] = "<EOS>";
        vocab[Tokenizer.UnkId] = "<UNK>";
        vocab[4] = "hello";
        vocab[5] = "world";
        vocab[6] = "query";
        return new Tokenizer(vocab);
    }

    [Fact]
    public void VocabSize_ReturnsCorrectCount()
    {
        var tok = CreateDefault();
        Assert.Equal(7, tok.VocabSize);
    }

    [Fact]
    public void Encode_PrependsBosAndAppendEos()
    {
        var tok = CreateDefault();
        var ids = tok.Encode("hello");
        Assert.Equal(Tokenizer.BosId, ids[0]);
        Assert.Equal(Tokenizer.EosId, ids[^1]);
    }

    [Fact]
    public void Encode_KnownToken_ReturnsCorrectId()
    {
        var tok = CreateDefault();
        var ids = tok.Encode("hello");
        // BOS + hello + EOS
        Assert.Equal(3, ids.Length);
        Assert.Equal(4, ids[1]); // "hello" = id 4
    }

    [Fact]
    public void Encode_UnknownChar_ReturnsUnk()
    {
        var tok = CreateDefault();
        var ids = tok.Encode("z");
        // BOS + UNK + EOS
        Assert.Equal(3, ids.Length);
        Assert.Equal(Tokenizer.UnkId, ids[1]);
    }

    [Fact]
    public void Encode_LongestMatch_MatchesMultiCharToken()
    {
        var tok = CreateDefault();
        var ids = tok.Encode("hello world");
        // BOS + "hello"(4) + " "(UNK) + "world"(5) + EOS
        Assert.Equal(5, ids.Length);
        Assert.Equal(4, ids[1]); // "hello"
        Assert.Equal(Tokenizer.UnkId, ids[2]); // space = UNK
        Assert.Equal(5, ids[3]); // "world"
    }

    [Fact]
    public void Decode_SpecialTokens_ReturnsCorrectStrings()
    {
        var tok = CreateDefault();
        Assert.Equal("<PAD>", tok.Decode(Tokenizer.PadId));
        Assert.Equal("<BOS>", tok.Decode(Tokenizer.BosId));
        Assert.Equal("<EOS>", tok.Decode(Tokenizer.EosId));
        Assert.Equal("<UNK>", tok.Decode(Tokenizer.UnkId));
    }

    [Fact]
    public void Decode_KnownToken_ReturnsVocabEntry()
    {
        var tok = CreateDefault();
        Assert.Equal("hello", tok.Decode(4));
        Assert.Equal("world", tok.Decode(5));
    }

    [Fact]
    public void Decode_OutOfRange_ReturnsFallback()
    {
        var tok = CreateDefault();
        var result = tok.Decode(999);
        Assert.Contains("999", result);
    }

    [Fact]
    public void DecodeSequence_SkipsBosEosPad()
    {
        var tok = CreateDefault();
        int[] ids = [Tokenizer.BosId, 4, 5, Tokenizer.EosId];
        var result = tok.DecodeSequence(ids);
        Assert.Equal("hello world", result);
    }

    [Fact]
    public void DecodeSequence_EmptyAfterSkipping_ReturnsEmpty()
    {
        var tok = CreateDefault();
        int[] ids = [Tokenizer.BosId, Tokenizer.EosId, Tokenizer.PadId];
        Assert.Equal(string.Empty, tok.DecodeSequence(ids));
    }
}

public class SamplingTests
{
    [Fact]
    public void ArgMax_ReturnsIndexOfMax()
    {
        ReadOnlySpan<int> logits = [3, 7, 1, 4];
        Assert.Equal(1, Sampling.ArgMax(logits));
    }

    [Fact]
    public void ArgMax_TieBreak_ReturnsFirst()
    {
        ReadOnlySpan<int> logits = [5, 5, 3];
        Assert.Equal(0, Sampling.ArgMax(logits));
    }

    [Fact]
    public void SampleTopK_TemperatureZero_IsGreedy()
    {
        ReadOnlySpan<int> logits = [1, 100, 2, 3];
        int result = Sampling.SampleTopK(logits, topK: 4, tempQ8: 0);
        Assert.Equal(1, result); // greedy selects index 1
    }

    [Fact]
    public void SampleTopK_TopK1_IsGreedy()
    {
        ReadOnlySpan<int> logits = [1, 100, 2, 3];
        int result = Sampling.SampleTopK(logits, topK: 1, tempQ8: 256);
        Assert.Equal(1, result); // K=1 always selects the max
    }

    [Fact]
    public void SampleTopK_ValidResult_IsInRange()
    {
        int[] logits = [10, 20, 30, 40, 50];
        // Run many times — result should always be a valid index
        for (int i = 0; i < 100; i++)
        {
            int result = Sampling.SampleTopK(logits, topK: 3, tempQ8: 256);
            Assert.InRange(result, 0, logits.Length - 1);
        }
    }

    [Fact]
    public void SampleTopK_WithScratch_ProducesValidResult()
    {
        int[] logits = [5, 3, 8, 1, 6];
        int[] scratch = new int[logits.Length];
        int result = Sampling.SampleTopK(logits, topK: 3, tempQ8: 256, scratch: scratch.AsSpan());
        Assert.InRange(result, 0, logits.Length - 1);
    }

    [Fact]
    public void SampleTopK_AllZeroLogits_ReturnsFallback()
    {
        int[] logits = new int[8]; // all zeros
        // Should fall back to argmax (returns 0)
        int result = Sampling.SampleTopK(logits, topK: 4, tempQ8: 256);
        Assert.InRange(result, 0, logits.Length - 1);
    }
}

public class IntrinsicsMatVecTests
{
    [Fact]
    public void DotProduct_BasicCase_IsCorrect()
    {
        ReadOnlySpan<int> a = [1, 2, 3, 4];
        ReadOnlySpan<int> b = [4, 3, 2, 1];
        // 1*4 + 2*3 + 3*2 + 4*1 = 4 + 6 + 6 + 4 = 20
        Assert.Equal(20, IntrinsicsMatVec.DotProduct(a, b));
    }

    [Fact]
    public void DotProduct_TernaryWeights_IsCorrect()
    {
        ReadOnlySpan<int> a = [1, -1, 0, 1, -1, 0, 1, -1];  // ternary query
        ReadOnlySpan<int> b = [1, 1, -1, -1, 0, 0, 1, 1];    // ternary key
        // 1*1 + (-1)*1 + 0*(-1) + 1*(-1) + (-1)*0 + 0*0 + 1*1 + (-1)*1
        // = 1 - 1 + 0 - 1 + 0 + 0 + 1 - 1 = -1
        Assert.Equal(-1, IntrinsicsMatVec.DotProduct(a, b));
    }

    [Fact]
    public void DotProduct_LargeVectors_MatchesScalar()
    {
        int n = 128;
        var a = new int[n];
        var b = new int[n];
        var rng = new Random(42);
        long expected = 0;
        for (int i = 0; i < n; i++)
        {
            a[i] = rng.Next(3) - 1;
            b[i] = rng.Next(3) - 1;
            expected += (long)a[i] * b[i];
        }
        Assert.Equal((int)expected, IntrinsicsMatVec.DotProduct(a, b));
    }

    [Fact]
    public void DotProduct_AllZeros_ReturnsZero()
    {
        ReadOnlySpan<int> a = [0, 0, 0, 0, 0, 0, 0, 0];
        ReadOnlySpan<int> b = [1, 2, 3, 4, 5, 6, 7, 8];
        Assert.Equal(0, IntrinsicsMatVec.DotProduct(a, b));
    }

    [Fact]
    public void WeightedAccumulate_BasicCase_IsCorrect()
    {
        ReadOnlySpan<int> values = [2, 4, 6, 8];
        int[] output = new int[4];
        // weight=1, totalWeight=2 → adds half of each value
        IntrinsicsMatVec.WeightedAccumulate(1L, values, output.AsSpan(), 2L);
        Assert.Equal(1, output[0]); // 1*2/2 = 1
        Assert.Equal(2, output[1]); // 1*4/2 = 2
        Assert.Equal(3, output[2]); // 1*6/2 = 3
        Assert.Equal(4, output[3]); // 1*8/2 = 4
    }

    [Fact]
    public void WeightedAccumulate_ZeroWeight_LeavesOutputUnchanged()
    {
        ReadOnlySpan<int> values = [10, 20, 30];
        int[] output = [1, 2, 3];
        IntrinsicsMatVec.WeightedAccumulate(0L, values, output.AsSpan(), 10L);
        Assert.Equal(1, output[0]);
        Assert.Equal(2, output[1]);
        Assert.Equal(3, output[2]);
    }
}
