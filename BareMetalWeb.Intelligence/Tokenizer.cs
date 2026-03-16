using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Byte-level BPE tokenizer for BitNet inference.
/// When constructed with BPE merges (from HuggingFace tokenizer.json),
/// uses proper BPE encoding. Falls back to greedy longest-match when
/// no merges are provided (legacy path).
///
/// Special tokens: 0=PAD, 1=BOS, 2=EOS, 3=UNK (synthetic vocab)
/// or model-specific IDs loaded from the HF token table.
/// </summary>
public sealed class Tokenizer
{
    public const int PadId = 0;
    public const int BosId = 1;
    public const int EosId = 2;
    public const int UnkId = 3;

    private readonly string[] _vocab;
    private readonly Dictionary<string, int> _tokenToId;

    // BPE merge tables — null when using legacy greedy tokenization
    private readonly Dictionary<(string, string), int>? _mergeRanks;
    private readonly bool _isBpe;

    // GPT-2 byte ↔ unicode mapping (used by byte-level BPE)
    private static readonly char[] s_byteToUnicode = BuildByteToUnicode();
    private static readonly Dictionary<char, byte> s_unicodeToByte = BuildUnicodeToByte();

    // Pre-tokenizer regex (GPT-4 / Llama 3 style)
    private static readonly Regex s_preTokenize = new(
        @"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+",
        RegexOptions.Compiled);

    /// <summary>Number of tokens in the vocabulary.</summary>
    public int VocabSize => _vocab.Length;

    /// <summary>Whether this tokenizer uses BPE encoding.</summary>
    public bool IsBpe => _isBpe;

    /// <summary>
    /// Construct a tokenizer from the token table stored in the model snapshot.
    /// When merges is provided, uses byte-level BPE encoding.
    /// </summary>
    public Tokenizer(string[] vocab, IReadOnlyList<string>? merges = null)
    {
        _vocab = vocab;
        _tokenToId = new Dictionary<string, int>(vocab.Length, StringComparer.Ordinal);
        for (int i = 0; i < vocab.Length; i++)
        {
            var tok = vocab[i];
            if (tok is not null && !_tokenToId.ContainsKey(tok))
                _tokenToId[tok] = i;
        }

        if (merges is { Count: > 0 })
        {
            _mergeRanks = new Dictionary<(string, string), int>(merges.Count);
            for (int i = 0; i < merges.Count; i++)
            {
                var line = merges[i];
                int sp = line.IndexOf(' ');
                if (sp > 0)
                {
                    var left = line[..sp];
                    var right = line[(sp + 1)..];
                    _mergeRanks.TryAdd((left, right), i);
                }
            }
            _isBpe = true;
        }
    }

    /// <summary>
    /// Encode a text span to token IDs.
    /// Prepends BOS and appends EOS.
    /// </summary>
    public int[] Encode(ReadOnlySpan<char> text)
    {
        if (_isBpe)
            return EncodeBpe(text);
        return EncodeGreedy(text);
    }

    /// <summary>
    /// BPE encoding: pre-tokenize → byte-level → iterative merging → vocab lookup.
    /// </summary>
    private int[] EncodeBpe(ReadOnlySpan<char> text)
    {
        var textStr = text.ToString();
        var matches = s_preTokenize.Matches(textStr);

        // Estimate output size: BOS + ~1 token per 4 chars + EOS
        var ids = new List<int>(textStr.Length / 3 + 2);
        ids.Add(BosId);

        foreach (Match m in matches)
        {
            var piece = m.Value;
            // Convert to byte-level Unicode chars
            var byteChars = TextToByteChars(piece);
            // Apply BPE merges
            var bpeTokens = ApplyBpeMerges(byteChars);
            // Look up each merged token in vocab
            foreach (var tok in bpeTokens)
            {
                if (_tokenToId.TryGetValue(tok, out int id))
                    ids.Add(id);
                else
                    ids.Add(UnkId);
            }
        }

        ids.Add(EosId);
        return ids.ToArray();
    }

    /// <summary>
    /// Convert a pre-tokenized text piece to byte-level BPE characters.
    /// Each UTF-8 byte is mapped to its GPT-2 Unicode representative.
    /// </summary>
    private static string TextToByteChars(string text)
    {
        var utf8 = Encoding.UTF8.GetBytes(text);
        var sb = new StringBuilder(utf8.Length);
        for (int i = 0; i < utf8.Length; i++)
            sb.Append(s_byteToUnicode[utf8[i]]);
        return sb.ToString();
    }

    /// <summary>
    /// Apply BPE merges iteratively until no more merges can be made.
    /// Uses the standard BPE algorithm: find the highest-priority merge pair,
    /// apply it, repeat.
    /// </summary>
    private List<string> ApplyBpeMerges(string byteChars)
    {
        if (byteChars.Length <= 1)
            return [byteChars];

        // Start with individual characters as initial tokens
        var parts = new List<string>(byteChars.Length);
        for (int i = 0; i < byteChars.Length; i++)
            parts.Add(byteChars[i].ToString());

        while (parts.Count > 1)
        {
            // Find the pair with the lowest rank (highest priority)
            int bestRank = int.MaxValue;
            int bestIdx = -1;

            for (int i = 0; i < parts.Count - 1; i++)
            {
                if (_mergeRanks!.TryGetValue((parts[i], parts[i + 1]), out int rank))
                {
                    if (rank < bestRank)
                    {
                        bestRank = rank;
                        bestIdx = i;
                    }
                }
            }

            if (bestIdx < 0) break; // no more merges possible

            // Merge the best pair
            var merged = parts[bestIdx] + parts[bestIdx + 1];
            parts[bestIdx] = merged;
            parts.RemoveAt(bestIdx + 1);
        }

        return parts;
    }

    /// <summary>
    /// Legacy greedy longest-match encoding (no BPE merges).
    /// </summary>
    private int[] EncodeGreedy(ReadOnlySpan<char> text)
    {
        var ids = new int[text.Length + 2];
        int count = 0;
        ids[count++] = BosId;

        int pos = 0;
        while (pos < text.Length)
        {
            int matchLen = 0;
            int matchId = UnkId;
            int scanMax = Math.Min(text.Length - pos, 16);

            for (int len = scanMax; len >= 1; len--)
            {
                var slice = text.Slice(pos, len);
                if (_tokenToId.TryGetValue(slice.ToString(), out int tid))
                {
                    matchLen = len;
                    matchId = tid;
                    break;
                }
            }

            if (matchLen == 0) matchLen = 1;
            ids[count++] = matchId;
            pos += matchLen;
        }

        ids[count++] = EosId;

        if (count == ids.Length) return ids;
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
    /// Decode a single token ID to its raw text form.
    /// For BPE tokenizers, converts byte-level Unicode chars back to UTF-8 text.
    /// </summary>
    public string DecodeToText(int tokenId)
    {
        var raw = Decode(tokenId);
        if (!_isBpe) return raw;
        return ByteCharsToText(raw);
    }

    /// <summary>
    /// Decode a sequence of token IDs to text.
    /// For BPE tokenizers, concatenates tokens directly (no space joining)
    /// and converts byte-level Unicode chars back to UTF-8 text.
    /// For legacy tokenizers, space-joins non-special tokens.
    /// </summary>
    public string DecodeSequence(ReadOnlySpan<int> ids)
    {
        if (_isBpe) return DecodeSequenceBpe(ids);
        return DecodeSequenceGreedy(ids);
    }

    /// <summary>
    /// BPE decode: concatenate raw token strings, then convert byte-level chars to UTF-8.
    /// No space insertion — BPE tokens encode their own whitespace (Ġ = space).
    /// </summary>
    private string DecodeSequenceBpe(ReadOnlySpan<int> ids)
    {
        var sb = new StringBuilder(ids.Length * 4);
        for (int i = 0; i < ids.Length; i++)
        {
            int id = ids[i];
            if (id == PadId || id == BosId || id == EosId) continue;
            sb.Append(Decode(id));
        }
        return ByteCharsToText(sb.ToString());
    }

    /// <summary>
    /// Legacy decode: space-join non-special tokens.
    /// </summary>
    private string DecodeSequenceGreedy(ReadOnlySpan<int> ids)
    {
        int printable = 0;
        for (int i = 0; i < ids.Length; i++)
        {
            int id = ids[i];
            if (id != PadId && id != BosId && id != EosId) printable++;
        }
        if (printable == 0) return string.Empty;

        var sb = new StringBuilder(printable * 6);
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

    /// <summary>
    /// Convert byte-level BPE Unicode characters back to UTF-8 text.
    /// Each BPE char maps to one byte via the GPT-2 unicode→byte table.
    /// </summary>
    private static string ByteCharsToText(string bpeChars)
    {
        var bytes = new byte[bpeChars.Length];
        int len = 0;
        for (int i = 0; i < bpeChars.Length; i++)
        {
            char c = bpeChars[i];
            if (s_unicodeToByte.TryGetValue(c, out byte b))
                bytes[len++] = b;
            else
                bytes[len++] = (byte)'?';
        }
        return Encoding.UTF8.GetString(bytes, 0, len);
    }

    // ── GPT-2 byte ↔ unicode mapping ─────────────────────────────────────

    private static char[] BuildByteToUnicode()
    {
        // Printable ASCII + Latin-1 supplement ranges keep their identity.
        // Non-printable bytes get mapped to U+0100+ range.
        var table = new char[256];
        // Identity ranges: 33–126 ('!'–'~'), 161–172 ('¡'–'¬'), 174–255 ('®'–'ÿ')
        int offset = 0;
        for (int b = 0; b < 256; b++)
        {
            if ((b >= 33 && b <= 126) || (b >= 161 && b <= 172) || (b >= 174 && b <= 255))
            {
                table[b] = (char)b;
            }
            else
            {
                table[b] = (char)(256 + offset);
                offset++;
            }
        }
        return table;
    }

    private static Dictionary<char, byte> BuildUnicodeToByte()
    {
        var table = new Dictionary<char, byte>(256);
        var b2u = BuildByteToUnicode();
        for (int b = 0; b < 256; b++)
            table[b2u[b]] = (byte)b;
        return table;
    }
}
