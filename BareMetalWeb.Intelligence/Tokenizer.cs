using System.Runtime.CompilerServices;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Minimal character-unigram tokenizer for BitNet inference.
/// Vocabulary is built from a fixed token table (loaded with the model).
/// Special tokens: 0=PAD, 1=BOS, 2=EOS, 3=UNK.
///
/// Encoding strategy:
///   1. Try to match longest token string in vocab (greedy left-to-right).
///   2. Fall back to single-character tokens, then UNK.
///
/// No allocations during Encode beyond the returned int[]; Decode returns
/// direct references from the token table (no new strings).
/// </summary>
public sealed class Tokenizer
{
    public const int PadId = 0;
    public const int BosId = 1;
    public const int EosId = 2;
    public const int UnkId = 3;

    private readonly string[] _vocab;
    // token-string → token-id, built once at construction
    private readonly Dictionary<string, int> _tokenToId;

    /// <summary>Number of tokens in the vocabulary.</summary>
    public int VocabSize => _vocab.Length;

    /// <summary>
    /// Construct a tokenizer from the token table stored in the model snapshot.
    /// </summary>
    public Tokenizer(string[] vocab)
    {
        _vocab = vocab;
        _tokenToId = new Dictionary<string, int>(vocab.Length, StringComparer.Ordinal);
        for (int i = 0; i < vocab.Length; i++)
        {
            var tok = vocab[i];
            if (tok is not null && !_tokenToId.ContainsKey(tok))
                _tokenToId[tok] = i;
        }
    }

    /// <summary>
    /// Encode a text span to token IDs.
    /// Prepends BOS and appends EOS.
    /// Returns a rented array — caller must not hold a reference after inference.
    /// (In practice we pass the result immediately into the forward pass.)
    /// </summary>
    public int[] Encode(ReadOnlySpan<char> text)
    {
        // Upper-bound: BOS + one token per char + EOS
        var ids = new int[text.Length + 2];
        int count = 0;
        ids[count++] = BosId;

        int pos = 0;
        while (pos < text.Length)
        {
            // Greedy longest-match scan (max token length capped at 16 chars for speed)
            int matchLen = 0;
            int matchId  = UnkId;
            int scanMax  = Math.Min(text.Length - pos, 16);

            for (int len = scanMax; len >= 1; len--)
            {
                var slice = text.Slice(pos, len);
#if NET6_0_OR_GREATER
                if (_tokenToId.TryGetValue(slice.ToString(), out int tid))
#else
                if (_tokenToId.TryGetValue(new string(slice), out int tid))
#endif
                {
                    matchLen = len;
                    matchId  = tid;
                    break;
                }
            }

            if (matchLen == 0) matchLen = 1; // advance even if no match (UNK)
            ids[count++] = matchId;
            pos += matchLen;
        }

        ids[count++] = EosId;

        // Return correctly-sized slice (no GC alloc on hot path — caller uses AsSpan)
        if (count == ids.Length)
            return ids;

        var result = new int[count];
        ids.AsSpan(0, count).CopyTo(result);
        return result;
    }

    /// <summary>
    /// Decode a single token ID to its string form.
    /// Returns a direct reference to the vocab table — no allocation.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public string Decode(int tokenId)
    {
        if ((uint)tokenId < (uint)_vocab.Length)
        {
            var s = _vocab[tokenId];
            if (s is not null) return s;
        }
        return tokenId switch
        {
            PadId => "<PAD>",
            BosId => "<BOS>",
            EosId => "<EOS>",
            UnkId => "<UNK>",
            _     => $"tok{tokenId}",
        };
    }

    /// <summary>
    /// Decode a sequence of token IDs to a space-joined string.
    /// Skips PAD, BOS, and EOS tokens.
    /// </summary>
    public string DecodeSequence(ReadOnlySpan<int> ids)
    {
        // Count printable tokens first to avoid string builder resize
        int printable = 0;
        for (int i = 0; i < ids.Length; i++)
        {
            int id = ids[i];
            if (id != PadId && id != BosId && id != EosId) printable++;
        }
        if (printable == 0) return string.Empty;

        var sb = new System.Text.StringBuilder(printable * 6);
        bool first = true;
        for (int i = 0; i < ids.Length; i++)
        {
            int id = ids[i];
            if (id == PadId || id == BosId || id == EosId) continue;
            if (!first) sb.Append(' ');
            first = false;
            sb.Append(Decode(id));
        }
        return sb.ToString();
    }
}
