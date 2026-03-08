using System.Runtime.CompilerServices;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Prunes a ternary model's vocabulary to only domain-relevant tokens.
/// Removes rows from the embedding matrix and columns from the output head,
/// producing a compact model that's faster (smaller softmax) and smaller on disk.
/// </summary>
public sealed class VocabularyPruner
{
    private readonly HashSet<string> _domainTokens;
    private int[]? _remapTable;     // original token ID → pruned ID (-1 = pruned)
    private int[]? _reverseTable;   // pruned ID → original token ID

    public int OriginalVocabSize { get; private set; }
    public int PrunedVocabSize { get; private set; }

    /// <summary>
    /// Compression ratio achieved by pruning (0.0–1.0, lower is better).
    /// </summary>
    public float CompressionRatio =>
        OriginalVocabSize > 0 ? (float)PrunedVocabSize / OriginalVocabSize : 1f;

    public VocabularyPruner(IEnumerable<string> domainTokens)
    {
        _domainTokens = new HashSet<string>(domainTokens, StringComparer.Ordinal);
    }

    /// <summary>
    /// Build the domain vocabulary from BareMetalWeb DataScaffold metadata.
    /// Includes entity names, field names, JSON structural tokens, and
    /// a minimal set of English function words for natural queries.
    /// </summary>
    public static VocabularyPruner FromDataScaffold()
    {
        var tokens = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // JSON structural tokens (always needed for tool calling)
        foreach (var t in JsonStructuralTokens)
            tokens.Add(t);

        // Common English function words for admin queries
        foreach (var t in FunctionWords)
            tokens.Add(t);

        // Tool action vocabulary
        foreach (var t in ToolActionTokens)
            tokens.Add(t);

        // DataScaffold entity and field names
        try
        {
            var entities = BareMetalWeb.Core.DataScaffold.Entities;
            if (entities is not null)
            {
                foreach (var entity in entities)
                {
                    // Add entity name tokens (split camelCase/PascalCase)
                    foreach (var word in SplitIdentifier(entity.Name))
                        tokens.Add(word.ToLowerInvariant());
                    tokens.Add(entity.Name.ToLowerInvariant());
                    tokens.Add(entity.Slug.ToLowerInvariant());

                    if (entity.Fields is not null)
                    {
                        foreach (var field in entity.Fields)
                        {
                            foreach (var word in SplitIdentifier(field.Name))
                                tokens.Add(word.ToLowerInvariant());
                            tokens.Add(field.Name.ToLowerInvariant());
                            tokens.Add(field.FieldType.ToString().ToLowerInvariant());
                        }
                    }
                }
            }
        }
        catch
        {
            // DataScaffold may not be initialised yet — that's fine,
            // we still have the base vocabulary
        }

        return new VocabularyPruner(tokens);
    }

    /// <summary>
    /// Build the remap table from a full vocabulary list.
    /// Tokens in the domain set are kept; all others are pruned.
    /// Special tokens (IDs 0–3 typically: PAD, BOS, EOS, UNK) are always kept.
    /// </summary>
    public void BuildRemapTable(IReadOnlyList<string> fullVocabulary, int specialTokenCount = 4)
    {
        OriginalVocabSize = fullVocabulary.Count;
        _remapTable = new int[fullVocabulary.Count];
        var reverseList = new List<int>(Math.Min(fullVocabulary.Count, _domainTokens.Count + specialTokenCount));

        int prunedId = 0;

        for (int i = 0; i < fullVocabulary.Count; i++)
        {
            // Always keep special tokens
            if (i < specialTokenCount || _domainTokens.Contains(fullVocabulary[i]))
            {
                _remapTable[i] = prunedId;
                reverseList.Add(i);
                prunedId++;
            }
            else
            {
                _remapTable[i] = -1; // pruned
            }
        }

        _reverseTable = reverseList.ToArray();
        PrunedVocabSize = prunedId;
    }

    /// <summary>
    /// Prune embedding matrix rows. Input: [vocabSize × hiddenDim] ternary weights.
    /// Output: [prunedVocabSize × hiddenDim] with only domain token rows retained.
    /// </summary>
    public sbyte[] PruneEmbeddings(ReadOnlySpan<sbyte> embeddings, int hiddenDim)
    {
        if (_reverseTable is null)
            throw new InvalidOperationException("Call BuildRemapTable first");

        var pruned = new sbyte[PrunedVocabSize * hiddenDim];

        for (int p = 0; p < _reverseTable.Length; p++)
        {
            int origRow = _reverseTable[p];
            ReadOnlySpan<sbyte> src = embeddings.Slice(origRow * hiddenDim, hiddenDim);
            Span<sbyte> dst = pruned.AsSpan(p * hiddenDim, hiddenDim);
            src.CopyTo(dst);
        }

        return pruned;
    }

    /// <summary>
    /// Prune output projection (lm_head) columns.
    /// Input: [vocabSize × hiddenDim] (transposed layout, one row per output token).
    /// Output: [prunedVocabSize × hiddenDim].
    /// Same operation as PruneEmbeddings since both are vocab-indexed row arrays.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public sbyte[] PruneOutputHead(ReadOnlySpan<sbyte> outputHead, int hiddenDim)
        => PruneEmbeddings(outputHead, hiddenDim);

    /// <summary>
    /// Map an original token ID to its pruned ID. Returns -1 if pruned.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int MapTokenId(int originalId)
    {
        if (_remapTable is null || (uint)originalId >= (uint)_remapTable.Length)
            return -1;
        return _remapTable[originalId];
    }

    /// <summary>
    /// Map a pruned token ID back to the original ID.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int UnmapTokenId(int prunedId)
    {
        if (_reverseTable is null || (uint)prunedId >= (uint)_reverseTable.Length)
            return -1;
        return _reverseTable[prunedId];
    }

    /// <summary>
    /// Get summary statistics about the pruning operation.
    /// </summary>
    public PruneStats GetStats(int hiddenDim)
    {
        long originalEmbeddingBytes = (long)OriginalVocabSize * hiddenDim; // 1 byte per sbyte weight
        long prunedEmbeddingBytes = (long)PrunedVocabSize * hiddenDim;
        long savedBytes = (originalEmbeddingBytes - prunedEmbeddingBytes) * 2; // embed + output head

        return new PruneStats(
            OriginalVocabSize,
            PrunedVocabSize,
            OriginalVocabSize - PrunedVocabSize,
            savedBytes,
            CompressionRatio);
    }

    // ── Vocabulary sets ────────────────────────────────────────────────────

    private static readonly string[] JsonStructuralTokens =
    [
        "{", "}", "[", "]", ":", ",", "\"",
        "true", "false", "null",
        "name", "type", "value", "id", "slug",
        "query", "entity", "field", "result",
        "error", "success", "message", "count",
        "parameters", "tool", "action", "response"
    ];

    private static readonly string[] FunctionWords =
    [
        "the", "a", "an", "is", "are", "was", "were",
        "in", "on", "at", "to", "for", "of", "from",
        "and", "or", "not", "with", "by", "as",
        "all", "any", "each", "every", "some",
        "how", "many", "much", "what", "which", "who",
        "show", "list", "get", "find", "search", "describe",
        "create", "update", "delete", "remove",
        "status", "health", "system", "index", "help",
        "this", "that", "these", "those",
        "yes", "no", "ok", "please", "thank"
    ];

    private static readonly string[] ToolActionTokens =
    [
        "list", "entities", "describe", "query", "records",
        "status", "diagnostics", "memory", "uptime",
        "index", "rebuild", "reindex", "search",
        "help", "commands", "capabilities",
        "chlorine", "temperature", "ph", "orp", // domain-specific examples
        "user", "session", "audit", "log",
        "data", "schema", "fields", "properties",
        "count", "total", "average", "sum", "min", "max"
    ];

    /// <summary>
    /// Split a PascalCase/camelCase identifier into words.
    /// e.g., "BlogPost" → ["Blog", "Post"], "userId" → ["user", "Id"]
    /// </summary>
    internal static List<string> SplitIdentifier(string identifier)
    {
        var words = new List<string>(4);
        int start = 0;

        for (int i = 1; i < identifier.Length; i++)
        {
            if (char.IsUpper(identifier[i]) && !char.IsUpper(identifier[i - 1]))
            {
                words.Add(identifier[start..i]);
                start = i;
            }
            else if (char.IsUpper(identifier[i]) && i + 1 < identifier.Length &&
                     !char.IsUpper(identifier[i + 1]))
            {
                words.Add(identifier[start..i]);
                start = i;
            }
        }

        if (start < identifier.Length)
            words.Add(identifier[start..]);

        return words;
    }
}

/// <summary>
/// Statistics from a vocabulary pruning operation.
/// </summary>
public readonly record struct PruneStats(
    int OriginalVocabSize,
    int PrunedVocabSize,
    int TokensRemoved,
    long BytesSaved,
    float CompressionRatio
);
