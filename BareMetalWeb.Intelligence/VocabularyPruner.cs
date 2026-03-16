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
    /// Reconstruct a pruner from a persisted remap table (loaded from snapshot).
    /// The remap table maps original token ID → pruned ID (-1 = pruned).
    /// </summary>
    public static VocabularyPruner FromRemapTable(int[] remapTable)
    {
        var pruner = new VocabularyPruner(Array.Empty<string>());
        pruner._remapTable = remapTable;
        pruner.OriginalVocabSize = remapTable.Length;

        int maxPrunedId = -1;
        var reverseList = new List<int>();
        for (int i = 0; i < remapTable.Length; i++)
        {
            if (remapTable[i] >= 0)
            {
                reverseList.Add(i);
                if (remapTable[i] > maxPrunedId)
                    maxPrunedId = remapTable[i];
            }
        }
        pruner._reverseTable = reverseList.ToArray();
        pruner.PrunedVocabSize = maxPrunedId + 1;
        return pruner;
    }

    /// <summary>
    /// Build the domain vocabulary from BareMetalWeb DataScaffold metadata.
    /// Includes entity names, field names, field types, action/command names,
    /// lookup relationships, related document references, query operators,
    /// permissions, and a minimal set of English function words.
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

        // Conversational phrases (greetings, goodbyes, pleasantries)
        foreach (var t in ConversationalTokens)
            tokens.Add(t);

        // Query operators — users may type "contains", "equals", "greater than" etc.
        foreach (var t in QueryOperatorTokens)
            tokens.Add(t);

        // DataScaffold entity metadata — full semantic graph
        try
        {
            var entities = BareMetalWeb.Core.DataScaffold.Entities;
            if (entities is not null)
            {
                foreach (var entity in entities)
                {
                    // Entity name + slug (split camelCase)
                    foreach (var word in SplitIdentifier(entity.Name))
                        tokens.Add(word.ToLowerInvariant());
                    tokens.Add(entity.Name.ToLowerInvariant());
                    tokens.Add(entity.Slug.ToLowerInvariant());

                    // Singular form (strip trailing 's') for natural language queries
                    if (entity.Slug.EndsWith('s') && entity.Slug.Length > 2)
                        tokens.Add(entity.Slug[..^1].ToLowerInvariant());

                    // Permissions tokens (e.g. "admin", "read", "write")
                    if (!string.IsNullOrEmpty(entity.Permissions))
                    {
                        foreach (var perm in entity.Permissions.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        {
                            tokens.Add(perm.ToLowerInvariant());
                            foreach (var word in SplitIdentifier(perm))
                                tokens.Add(word.ToLowerInvariant());
                        }
                    }

                    // Nav group
                    if (!string.IsNullOrEmpty(entity.NavGroup))
                        tokens.Add(entity.NavGroup.ToLowerInvariant());

                    // Fields — names, types, and relationship metadata
                    if (entity.Fields is not null)
                    {
                        foreach (var field in entity.Fields)
                        {
                            foreach (var word in SplitIdentifier(field.Name))
                                tokens.Add(word.ToLowerInvariant());
                            tokens.Add(field.Name.ToLowerInvariant());
                            tokens.Add(field.FieldType.ToString().ToLowerInvariant());

                            // Field group (e.g. "Contact Details", "Billing")
                            if (!string.IsNullOrEmpty(field.FieldGroup))
                            {
                                tokens.Add(field.FieldGroup.ToLowerInvariant());
                                foreach (var word in field.FieldGroup.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                                    tokens.Add(word.ToLowerInvariant());
                            }

                            // Label (display text may differ from name)
                            if (!string.IsNullOrEmpty(field.Label))
                            {
                                foreach (var word in field.Label.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                                    tokens.Add(word.ToLowerInvariant());
                            }

                            // Lookup target — FK relationship
                            if (field.Lookup is not null)
                            {
                                tokens.Add("lookup");
                                tokens.Add("related");
                                if (!string.IsNullOrEmpty(field.Lookup.TargetSlug))
                                {
                                    tokens.Add(field.Lookup.TargetSlug.ToLowerInvariant());
                                    foreach (var word in SplitIdentifier(field.Lookup.TargetSlug))
                                        tokens.Add(word.ToLowerInvariant());
                                }
                                if (!string.IsNullOrEmpty(field.Lookup.DisplayField))
                                    tokens.Add(field.Lookup.DisplayField.ToLowerInvariant());
                            }

                            // Related document reference
                            if (field.RelatedDocument is not null)
                            {
                                tokens.Add("related");
                                tokens.Add("document");
                                if (!string.IsNullOrEmpty(field.RelatedDocument.DisplayField))
                                    tokens.Add(field.RelatedDocument.DisplayField.ToLowerInvariant());
                            }

                            // Child entity slug
                            if (!string.IsNullOrEmpty(field.ChildEntitySlug))
                            {
                                tokens.Add(field.ChildEntitySlug.ToLowerInvariant());
                                tokens.Add("child");
                                tokens.Add("parent");
                            }
                        }
                    }

                    // Commands (remote methods)
                    if (entity.Commands is not null)
                    {
                        foreach (var cmd in entity.Commands)
                        {
                            tokens.Add(cmd.Name.ToLowerInvariant());
                            foreach (var word in SplitIdentifier(cmd.Name))
                                tokens.Add(word.ToLowerInvariant());
                            if (!string.IsNullOrEmpty(cmd.Label))
                            {
                                foreach (var word in cmd.Label.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                                    tokens.Add(word.ToLowerInvariant());
                            }
                        }
                    }
                }
            }

            // Runtime-defined entity actions (may not overlap with DataScaffold commands)
            var registry = BareMetalWeb.Runtime.RuntimeEntityRegistry.Current;
            if (registry is not null)
            {
                foreach (var model in registry.All)
                {
                    tokens.Add(model.Name.ToLowerInvariant());
                    tokens.Add(model.Slug.ToLowerInvariant());

                    foreach (var action in model.Actions)
                    {
                        tokens.Add(action.Name.ToLowerInvariant());
                        foreach (var word in SplitIdentifier(action.Name))
                            tokens.Add(word.ToLowerInvariant());
                        if (!string.IsNullOrEmpty(action.Label))
                        {
                            foreach (var word in action.Label.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                                tokens.Add(word.ToLowerInvariant());
                        }
                    }

                    foreach (var field in model.Fields)
                    {
                        tokens.Add(field.Name.ToLowerInvariant());
                        foreach (var word in SplitIdentifier(field.Name))
                            tokens.Add(word.ToLowerInvariant());
                    }
                }
            }
        }
        catch
        {
            // DataScaffold/RuntimeEntityRegistry may not be initialised yet — that's fine,
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
        "how", "many", "much", "what", "which", "who", "whose", "whom",
        "show", "list", "get", "find", "search", "describe",
        "create", "update", "delete", "remove",
        "give", "give me", "fetch", "grab", "pull", "bring",
        "status", "health", "system", "index", "help",
        "this", "that", "these", "those",
        "yes", "no", "ok", "okay", "please", "thank", "thanks",
        "can", "could", "would", "will", "should",
        "i", "me", "my", "we", "you", "your", "it", "its",
        "want", "need", "like", "have", "has", "had", "do", "does", "did",
        "new", "old", "current", "existing", "available",
        "called", "named", "titled", "labelled", "labeled",
        "where", "when", "why", "there"
    ];

    // Greetings, goodbyes, and conversational phrases
    private static readonly string[] ConversationalTokens =
    [
        // Greetings
        "hello", "hi", "hey", "hiya", "howdy", "morning",
        "good morning", "good afternoon", "good evening",
        "greetings", "welcome", "sup", "yo",
        // Goodbyes
        "bye", "goodbye", "cheerio", "cheers", "later",
        "see you", "see ya", "take care", "ta", "ciao", "cya",
        "goodnight", "night",
        // Pleasantries
        "thanks", "thank you", "cheers", "ta", "nice one",
        "great", "cool", "awesome", "perfect", "brilliant",
        "sorry", "apologies", "excuse me", "pardon"
    ];

    private static readonly string[] ToolActionTokens =
    [
        // List / read / fetch synonyms
        "list", "table", "grid", "query", "entities", "records",
        "show", "display", "view", "open", "detail", "lookup",
        "read", "look at", "call up", "pull up", "bring up",
        "see", "check", "inspect", "browse", "explore",
        "give", "give me", "fetch", "grab", "pull", "bring",
        "retrieve", "return", "select", "pick",
        // Create synonyms
        "create", "add", "new", "insert", "make", "plus", "+",
        "register", "submit", "post", "build",
        // Update synonyms
        "update", "edit", "change", "modify", "alter", "patch",
        "amend", "revise", "adjust", "set", "assign", "rename",
        // Delete synonyms
        "delete", "remove", "kill", "bin", "sack off", "nuke",
        "drop", "destroy", "purge", "trash", "wipe", "erase",
        // Action / invoke synonyms
        "execute", "run", "invoke", "action", "command",
        "call", "tool", "do", "perform", "trigger", "fire", "launch",
        // Reports / settings / config
        "report", "reports", "reporting", "dashboard", "analytics",
        "settings", "setting", "configure", "configuration", "config",
        "preferences", "options", "option",
        "metadata", "gallery", "import", "export",
        "download", "upload", "sync", "refresh", "reload",
        // Describe / info
        "describe", "info", "information", "about", "details",
        "help", "commands", "capabilities",
        // System / diagnostics
        "status", "diagnostics", "memory", "uptime",
        "index", "rebuild", "reindex", "search",
        "user", "session", "audit", "log",
        "data", "schema", "fields", "properties",
        // Aggregates
        "count", "total", "average", "sum", "min", "max",
        // Save
        "save", "commit", "apply", "confirm", "approve",
        // Query clauses / filter words
        "filter", "sort", "order", "by", "where", "limit", "group",
        "first", "last", "latest", "recent", "newest", "oldest",
        "top", "bottom", "next", "previous", "page",
        "called", "named", "titled", "matching", "containing"
    ];

    private static readonly string[] QueryOperatorTokens =
    [
        "equals", "equal", "is", "notequals", "not",
        "contains", "contain", "like", "match", "matching",
        "startswith", "starts", "endswith", "ends",
        "greaterthan", "greater", "more", "above", "over",
        "lessthan", "less", "fewer", "below", "under",
        "between", "range",
        "in", "notin",
        "before", "after", "since", "until",
        "empty", "null", "blank", "missing",
        "true", "false", "yes", "no",
        "active", "inactive", "enabled", "disabled",
        "complete", "completed", "incomplete", "pending", "done"
    ];

    /// <summary>
    /// Tokenize all domain terms through the BPE tokenizer and collect the set
    /// of token IDs needed to represent them. Also includes fundamental tokens
    /// (special tokens, short fragments) so basic text generation works.
    /// Tokenizes both bare and space-prefixed forms to capture all BPE variants.
    /// </summary>
    public HashSet<int> CollectDomainTokenIds(Tokenizer tokenizer, IReadOnlyList<string> vocabTable)
    {
        var ids = new HashSet<int>();

        // Always keep special tokens (PAD, BOS, EOS, UNK)
        for (int i = 0; i < 4 && i < vocabTable.Count; i++)
            ids.Add(i);

        // Keep short tokens (≤2 chars) — single bytes, digraphs, whitespace, punctuation.
        // These are fundamental building blocks for any text.
        for (int i = 0; i < vocabTable.Count; i++)
        {
            var tok = vocabTable[i];
            if (tok is not null && tok.Length <= 2)
                ids.Add(i);
        }

        // Tokenize each domain term in BOTH bare and space-prefixed forms.
        // BPE produces different tokens for "hello" vs " hello" (Ġhello).
        // Also encode multi-word phrases to capture cross-word merge tokens.
        foreach (var term in _domainTokens)
        {
            if (string.IsNullOrWhiteSpace(term)) continue;
            try
            {
                // Bare form: captures tokens when word is at start of text
                var tokenIds = tokenizer.Encode(term.AsSpan());
                foreach (var id in tokenIds)
                    if ((uint)id < (uint)vocabTable.Count) ids.Add(id);

                // Space-prefixed form: captures Ġ-prefixed BPE tokens (most common case)
                var prefixed = " " + term;
                tokenIds = tokenizer.Encode(prefixed.AsSpan());
                foreach (var id in tokenIds)
                    if ((uint)id < (uint)vocabTable.Count) ids.Add(id);
            }
            catch { /* Skip terms that fail to tokenize */ }
        }

        return ids;
    }

    /// <summary>
    /// Build the remap table from an explicit set of token IDs to keep.
    /// Use with <see cref="CollectDomainTokenIds"/> for BPE-aware pruning.
    /// </summary>
    public void BuildRemapTableFromIds(int vocabSize, HashSet<int> keepIds)
    {
        OriginalVocabSize = vocabSize;
        _remapTable = new int[vocabSize];
        var reverseList = new List<int>(keepIds.Count);

        int prunedId = 0;
        for (int i = 0; i < vocabSize; i++)
        {
            if (keepIds.Contains(i))
            {
                _remapTable[i] = prunedId;
                reverseList.Add(i);
                prunedId++;
            }
            else
            {
                _remapTable[i] = -1;
            }
        }

        _reverseTable = reverseList.ToArray();
        PrunedVocabSize = prunedId;
    }

    /// <summary>
    /// Prune an int8 native matrix by keeping only rows in the remap table.
    /// Used for embedding and output head matrices. Preserves DequantScale.
    /// </summary>
    public NativeInt8Matrix PruneInt8Matrix(NativeInt8Matrix source)
    {
        if (_reverseTable is null)
            throw new InvalidOperationException("Call BuildRemapTableFromIds first");

        var pruned = NativeInt8Matrix.Allocate(PrunedVocabSize, source.Cols);
        pruned.DequantScale = source.DequantScale;

        var rowBuf = new byte[source.RowStrideBytes];

        for (int p = 0; p < _reverseTable.Length; p++)
        {
            int origRow = _reverseTable[p];
            source.CopyPackedDataChunk((long)origRow * source.RowStrideBytes, rowBuf);
            pruned.PackRowFromBytes(p, rowBuf);
        }
        pruned.FinalizeStats();
        return pruned;
    }

    /// <summary>
    /// Build a pruned token table containing only kept tokens.
    /// </summary>
    public string[] PruneTokenTable(IReadOnlyList<string> fullTokenTable)
    {
        if (_reverseTable is null)
            throw new InvalidOperationException("Call BuildRemapTableFromIds first");

        var pruned = new string[PrunedVocabSize];
        for (int p = 0; p < _reverseTable.Length; p++)
            pruned[p] = fullTokenTable[_reverseTable[p]];
        return pruned;
    }

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
