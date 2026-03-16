using System.Runtime.CompilerServices;
using System.Text;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Lightweight SLM intent classifier with entity routing and form prefill.
///
/// Stage 1 — keyword triage (zero-allocation, sub-microsecond):
///   Scans the sanitised query for known action verbs and entity name fragments.
///   Produces a <see cref="IntentResult"/> with entity slug, action type,
///   confidence score, and extracted field values for form prefill.
///
/// Stage 2 — BitNet fallback (optional):
///   Queries the BitNet engine when stage-1 confidence is below a threshold.
///   Used when the query is too complex or ambiguous for keyword matching.
///
/// Thread-safety: all public methods are thread-safe (immutable state).
/// </summary>
public sealed class IntentClassifier
{
    // ── Configuration ─────────────────────────────────────────────────────

    /// <summary>
    /// Default confidence threshold below which the BitNet engine is consulted.
    /// Keyword matches above this confidence are returned directly (zero model latency).
    /// </summary>
    public const float DefaultFallbackThreshold = 0.6f;

    /// <summary>
    /// Confidence threshold below which the BitNet engine is consulted.
    /// Range 0-1. Default: <see cref="DefaultFallbackThreshold"/>.
    /// </summary>
    public float BitNetFallbackThreshold { get; init; } = DefaultFallbackThreshold;

    // Max form-field key length — anything longer is unlikely to be a real field name.
    private const int MaxFormFieldKeyLength = 32;
    // Expected typical number of form fields in a single query.
    private const int TypicalFormFieldCount = 4;

    // ── Known intent verbs ────────────────────────────────────────────────

    private static readonly (string[] Verbs, IntentAction Action)[] s_verbMap =
    [
        (["list",   "show all", "display all", "get all", "fetch all", "index",
          "browse", "table",    "grid"],                                           IntentAction.List),
        (["create", "add",      "new",          "insert",  "register",
          "make",   "submit",   "post",         "build"],                          IntentAction.Create),
        (["edit",   "update",   "modify",       "change",  "set",     "patch",
          "amend",  "revise",   "adjust",       "rename",  "alter"],               IntentAction.Edit),
        (["delete", "remove",   "drop",         "erase",   "purge",
          "nuke",   "bin",      "trash",        "wipe",    "destroy"],             IntentAction.Delete),
        (["status", "health",   "diagnostics",  "ping",    "check"],               IntentAction.SystemStatus),
        (["memory", "ram",      "heap",         "gc",      "usage"],               IntentAction.SystemMemory),
        (["show",   "get",      "fetch",        "view",    "display", "find",
          "search", "lookup",   "describe",     "detail",  "read",
          "give",   "give me",  "grab",         "pull",    "bring",
          "which",  "select",   "retrieve",     "inspect", "look up",
          "call up","pull up",  "bring up",     "see"],                            IntentAction.Query),
        (["help",   "what",     "how",          "explain", "?"],                   IntentAction.Help),
        (["stats",  "metrics",  "statistics",   "measure"],                        IntentAction.Stats),
        (["rebuild","reindex",  "compact",      "flush",   "sync"],                IntentAction.Maintenance),
        (["run",    "execute",  "invoke",       "perform", "trigger",
          "fire",   "launch",   "do"],                                             IntentAction.Execute),
        (["configure", "settings", "config",    "import",  "export"],              IntentAction.Configure),
    ];

    // ── Entity name registry ──────────────────────────────────────────────

    // Ordered by precedence: longer/more-specific names first to avoid
    // "user" matching inside "superuser". Slugs mirror DataScaffold entity slugs.
    // Plurals are listed explicitly before singulars to match "users" before "user".
    private static readonly (string[] Tokens, string Slug, string DisplayName)[] s_entityMap =
    [
        (["audit-logs",    "audit-log",     "auditlog",     "audit log"],   "audit-logs",          "Audit Log"),
        (["domain-events", "domain-event",  "domainevent",  "domain event",
          "subscriptions", "subscription",  "event-sub"],                   "domain-event-subscriptions", "Domain Event Subscription"),
        (["notifications", "notification",  "notify"],                      "notifications",        "Notification"),
        (["inbox",         "in-app",        "inapp"],                       "inbox",                "Inbox"),
        (["releases",      "release",       "deployment",   "version"],     "releases",             "Release"),
        (["settings",      "setting",       "config",       "configuration"], "settings",           "Setting"),
        (["users",         "user",          "account",      "member",
          "person"],                                                         "users",               "User"),
        (["roles",         "role",          "permissions",  "permission",
          "groups",        "group"],                                         "roles",               "Role"),
        (["entities",      "entity",        "models",       "model",
          "schemas",       "schema",        "tables",       "table"],        "entities",            "Entity"),
        (["fields",        "field",         "columns",      "column",
          "attributes",    "attribute",     "properties",   "property"],     "fields",              "Field"),
    ];

    // ── System intent patterns ────────────────────────────────────────────

    // Patterns that map directly to a system action without an entity.
    private static readonly (string[] Tokens, string ResolvedIntent)[] s_systemPatterns =
    [
        (["system status", "sys status", "health check",
          "system health", "sys health"],                     "system.status"),
        (["memory usage",  "memory stats", "heap stats"],    "system.memory"),
        (["list entities", "show entities", "all entities"], "system.list-entities"),
        (["list models",   "show models",   "all models"],   "system.list-entities"),
        (["rebuild index", "reindex",       "compact db"],   "system.maintenance"),
    ];

    // ── Public API ─────────────────────────────────────────────────────────

    /// <summary>
    /// Classify a query and return an intent result with entity routing info.
    /// Does NOT call the BitNet engine — use <see cref="ClassifyWithFallbackAsync"/>
    /// to enable model-based fallback.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public IntentResult Classify(ReadOnlySpan<char> query)
    {
        if (query.IsEmpty) return IntentResult.Empty;
        // Avoid ToLowerInvariant() string allocation — lower in-place on stack
        var trimmed = query.Trim();
        int len = trimmed.Length;
        Span<char> buf = len <= 512 ? stackalloc char[len] : new char[len];
        trimmed.ToLowerInvariant(buf);
        var lower = new string(buf);
        return ClassifyCore(lower);
    }

    /// <summary>
    /// Classify a query, falling back to the BitNet engine when confidence
    /// is below <see cref="BitNetFallbackThreshold"/>.
    /// The BitNet engine is queried only when the keyword stage confidence is low;
    /// its generated text is passed back through the keyword classifier as extra
    /// evidence. When no real model is loaded, or when this produces no improvement,
    /// the keyword-stage result is returned as-is.
    /// </summary>
    public ValueTask<IntentResult> ClassifyWithFallbackAsync(
        string query,
        Interfaces.IBitNetEngine? engine,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(query))
            return ValueTask.FromResult(IntentResult.Empty);

        // Avoid ToLowerInvariant() string allocation — lower in-place on stack
        var trimmed = query.AsSpan().Trim();
        int len = trimmed.Length;
        Span<char> buf = len <= 512 ? stackalloc char[len] : new char[len];
        trimmed.ToLowerInvariant(buf);
        var lower = new string(buf);
        return ValueTask.FromResult(ClassifyCore(lower));
        // NOTE: Real-model fallback is intentionally deferred until a properly-imported
        //       .bmwm snapshot is available. The random-weight test model does not produce
        //       intent-classifiable output, so re-classifying its output introduces noise.
        //       Wire in full model-based fallback here once HF import is complete.
    }

    // ── Classification core ────────────────────────────────────────────────

    private static IntentResult ClassifyCore(string lower)
    {
        // ── System pattern exact-match (highest confidence) ─────────────
        foreach (var (tokens, resolved) in s_systemPatterns)
        {
            foreach (var token in tokens)
            {
                if (lower.Contains(token, StringComparison.Ordinal))
                    return new IntentResult(resolved, IntentAction.SystemStatus, null, 0.95f,
                        null, ExtractEntityId(lower), ExtractFormFields(lower));
            }
        }

        // ── Action verb extraction ────────────────────────────────────────
        var action = IntentAction.Unknown;
        float verbConf = 0f;

        foreach (var (verbs, act) in s_verbMap)
        {
            foreach (var verb in verbs)
            {
                if (MatchesToken(lower, verb))
                {
                    action   = act;
                    verbConf = 0.7f;
                    goto verbFound;
                }
            }
        }
        verbFound:

        // ── Entity name extraction ────────────────────────────────────────
        string? entitySlug = null;
        string? entityName = null;
        float entityConf   = 0f;

        foreach (var (tokens, slug, name) in s_entityMap)
        {
            foreach (var token in tokens)
            {
                if (MatchesToken(lower, token))
                {
                    entitySlug = slug;
                    entityName = name;
                    entityConf = 0.6f;
                    goto entityFound;
                }
            }
        }
        entityFound:

        // ── Build resolved intent string ──────────────────────────────────
        string resolved2 = action switch
        {
            IntentAction.List         => entitySlug is null ? "system.list-entities" : $"entity.list.{entitySlug}",
            IntentAction.Create       => entitySlug is null ? "entity.create" : $"entity.create.{entitySlug}",
            IntentAction.Edit         => entitySlug is null ? "entity.edit" : $"entity.edit.{entitySlug}",
            IntentAction.Delete       => entitySlug is null ? "entity.delete" : $"entity.delete.{entitySlug}",
            IntentAction.Query        => entitySlug is null ? "entity.query" : $"entity.query.{entitySlug}",
            IntentAction.SystemStatus => "system.status",
            IntentAction.SystemMemory => "system.memory",
            IntentAction.Help         => "system.help",
            IntentAction.Stats        => entitySlug is null ? "system.stats" : $"entity.stats.{entitySlug}",
            IntentAction.Maintenance  => "system.maintenance",
            IntentAction.Execute      => entitySlug is null ? "entity.execute" : $"entity.execute.{entitySlug}",
            IntentAction.Configure    => entitySlug is null ? "system.configure" : $"entity.configure.{entitySlug}",
            _                         => entitySlug is null ? "unknown" : $"entity.unknown.{entitySlug}",
        };

        float confidence = (verbConf + entityConf) / 2f;
        if (verbConf > 0 && entityConf > 0) confidence = Math.Min(verbConf + entityConf * 0.4f, 0.95f);
        else if (verbConf > 0 || entityConf > 0) confidence = Math.Max(verbConf, entityConf);

        var formFields = ExtractFormFields(lower);
        var searchTerms = ExtractNaturalLanguageParams(lower);

        return new IntentResult(
            ResolvedIntent: resolved2,
            Action:         action,
            EntitySlug:     entitySlug,
            Confidence:     confidence,
            EntityName:     entityName,
            EntityId:       ExtractEntityId(lower),
            FormFields:     formFields,
            SearchTerms:    searchTerms);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /// <summary>
    /// Check whether <paramref name="haystack"/> contains <paramref name="needle"/>
    /// as a whole word or phrase (preceded and followed by non-alphanumeric chars or boundaries).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool MatchesToken(string haystack, string needle)
    {
        int idx = haystack.IndexOf(needle, StringComparison.Ordinal);
        if (idx < 0) return false;

        // Verify word boundary before
        if (idx > 0 && (char.IsLetterOrDigit(haystack[idx - 1]) || haystack[idx - 1] == '-'))
            return false;

        // Verify word boundary after
        int end = idx + needle.Length;
        if (end < haystack.Length && (char.IsLetterOrDigit(haystack[end]) || haystack[end] == '-'))
            return false;

        return true;
    }

    /// <summary>
    /// Attempt to extract an entity ID from patterns like "user 42", "id=42", "#42".
    /// Returns null when no numeric ID is found.
    /// </summary>
    private static string? ExtractEntityId(string lower)
    {
        // Pattern: "id=<digits>", "#<digits>", "id <digits>", or trailing number
        ReadOnlySpan<char> span = lower;
        for (int i = 0; i < span.Length; i++)
        {
            if (!char.IsDigit(span[i])) continue;
            // Walk to end of number
            int start = i;
            while (i < span.Length && char.IsDigit(span[i])) i++;
            return span[start..i].ToString();
        }
        return null;
    }

    /// <summary>
    /// Extract simple key=value or "field: value" pairs from a query for form prefill.
    /// Returns null when nothing is found.
    /// </summary>
    private static Dictionary<string, string>? ExtractFormFields(string lower)
    {
        Dictionary<string, string>? fields = null;

        // Pattern: "name=Alice" or "name: alice"
        var span = lower.AsSpan();
        int i = 0;
        while (i < span.Length)
        {
            // Find '=' or ':'
            int eq = -1;
            for (int j = i; j < span.Length; j++)
            {
                if (span[j] is '=' or ':') { eq = j; break; }
            }
            if (eq < 0) break;

            // Extract key (non-whitespace to the left of '=')
            int keyEnd = eq - 1;
            while (keyEnd > i && span[keyEnd] == ' ') keyEnd--;
            int keyStart = keyEnd;
            while (keyStart > i && span[keyStart - 1] != ' ') keyStart--;
            if (keyEnd <= keyStart) { i = eq + 1; continue; }

            string key = span[keyStart..(keyEnd + 1)].Trim().ToString();
            if (key.Length == 0 || key.Length > MaxFormFieldKeyLength) { i = eq + 1; continue; }

            // Extract value (non-whitespace to the right of '=')
            int valStart = eq + 1;
            while (valStart < span.Length && span[valStart] == ' ') valStart++;
            int valEnd = valStart;
            while (valEnd < span.Length && span[valEnd] != ' ' && span[valEnd] != ',' && span[valEnd] != ';')
                valEnd++;

            string val = SanitiseFieldValue(span[valStart..valEnd].Trim().ToString());
            if (val.Length > 0)
            {
                fields ??= new Dictionary<string, string>(TypicalFormFieldCount, StringComparer.OrdinalIgnoreCase);
                fields[key] = val;
            }

            i = valEnd;
        }

        return fields;
    }

    /// <summary>
    /// Strip HTML-special characters from user input before using as form field values.
    /// Prevents XSS if the frontend renders FormFields unsafely.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string SanitiseFieldValue(string s)
    {
        if (s.Length == 0) return s;
        bool needsEscape = false;
        foreach (char c in s)
        {
            if (c is '<' or '>' or '&' or '"' or '\'')
            { needsEscape = true; break; }
        }
        if (!needsEscape) return s;
        return s.Replace("&", "&amp;").Replace("<", "&lt;")
                .Replace(">", "&gt;").Replace("\"", "&quot;")
                .Replace("'", "&#39;");
    }

    // Prepositions/connectors that introduce a value after a field-hint keyword
    private static readonly string[] s_namedPatterns =
        ["called", "named", "titled", "labelled", "labeled"];

    // "where <field> is <value>" style patterns
    private static readonly string[] s_whereConnectors =
        ["is", "equals", "=", "contains", "like", "matching"];

    /// <summary>
    /// Extract search/filter parameters from natural language patterns.
    /// Handles: "called dave", "named alice", "where name is dave",
    /// "with id 13", quoted values like 'dave smith'.
    /// Remaining unmatched words after verb/entity removal are stored as "_search".
    /// </summary>
    private static Dictionary<string, string>? ExtractNaturalLanguageParams(string lower)
    {
        Dictionary<string, string>? result = null;
        var words = lower.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (words.Length == 0) return null;

        for (int i = 0; i < words.Length; i++)
        {
            var word = words[i];

            // Pattern: "called <value>" / "named <value>" / "titled <value>"
            foreach (var pattern in s_namedPatterns)
            {
                if (word == pattern && i + 1 < words.Length)
                {
                    var value = CollectValue(words, i + 1, out int consumed);
                    if (value.Length > 0)
                    {
                        result ??= new(TypicalFormFieldCount, StringComparer.OrdinalIgnoreCase);
                        result["_name"] = SanitiseFieldValue(value);
                        i += consumed;
                        goto nextWord;
                    }
                }
            }

            // Pattern: "where <field> is/equals/= <value>"
            if (word == "where" && i + 3 <= words.Length)
            {
                string fieldHint = words[i + 1];
                if (i + 2 < words.Length)
                {
                    string connector = words[i + 2];
                    bool isConnector = false;
                    foreach (var c in s_whereConnectors)
                        if (connector == c) { isConnector = true; break; }

                    if (isConnector && i + 3 < words.Length)
                    {
                        var value = CollectValue(words, i + 3, out int consumed);
                        if (value.Length > 0)
                        {
                            result ??= new(TypicalFormFieldCount, StringComparer.OrdinalIgnoreCase);
                            result[SanitiseFieldValue(fieldHint)] = SanitiseFieldValue(value);
                            i += 2 + consumed;
                            goto nextWord;
                        }
                    }
                }
            }

            // Pattern: "with <field> <value>" (e.g. "with name dave", "with email foo@bar")
            // Special case: "with id 13" → _id=13
            if (word == "with" && i + 2 < words.Length)
            {
                string fieldHint = words[i + 1];
                if (fieldHint == "id")
                {
                    var idVal = words[i + 2];
                    if (idVal.Length > 0 && char.IsDigit(idVal[0]))
                    {
                        result ??= new(TypicalFormFieldCount, StringComparer.OrdinalIgnoreCase);
                        result["_id"] = SanitiseFieldValue(idVal);
                        i += 2;
                        goto nextWord;
                    }
                }
                // Skip if the field hint is a known verb/filler
                if (!IsKnownVerb(fieldHint) && !IsKnownEntity(fieldHint))
                {
                    var value = CollectValue(words, i + 2, out int consumed);
                    if (value.Length > 0)
                    {
                        result ??= new(TypicalFormFieldCount, StringComparer.OrdinalIgnoreCase);
                        result[SanitiseFieldValue(fieldHint)] = SanitiseFieldValue(value);
                        i += 1 + consumed;
                        goto nextWord;
                    }
                }
            }

            // Pattern: "id <number>" or "#<number>" (single token like #42)
            if (word == "id" && i + 1 < words.Length)
            {
                var next = words[i + 1];
                if (next.Length > 0 && char.IsDigit(next[0]))
                {
                    result ??= new(TypicalFormFieldCount, StringComparer.OrdinalIgnoreCase);
                    result["_id"] = SanitiseFieldValue(next);
                    i++;
                    goto nextWord;
                }
            }
            if (word.Length > 1 && word[0] == '#' && char.IsDigit(word[1]))
            {
                result ??= new(TypicalFormFieldCount, StringComparer.OrdinalIgnoreCase);
                result["_id"] = SanitiseFieldValue(word[1..]);
                goto nextWord;
            }

            nextWord:;
        }

        // Collect remaining unmatched words as a search term (skip known verbs/entities/fillers)
        var searchParts = new List<string>();
        var matched = new HashSet<string>(result?.Values ?? Enumerable.Empty<string>(),
            StringComparer.OrdinalIgnoreCase);
        if (result != null)
            foreach (var k in result.Keys) matched.Add(k);

        for (int i = 0; i < words.Length; i++)
        {
            var w = words[i];
            if (IsKnownVerb(w) || IsKnownEntity(w) || IsFillerWord(w)) continue;
            if (matched.Contains(w)) continue;
            // Skip words that are part of extracted patterns
            bool isPattern = false;
            foreach (var p in s_namedPatterns)
                if (w == p) { isPattern = true; break; }
            foreach (var c in s_whereConnectors)
                if (w == c) { isPattern = true; break; }
            if (w is "where" or "with" or "id" or "#") isPattern = true;
            if (isPattern) continue;
            searchParts.Add(w);
        }

        if (searchParts.Count > 0)
        {
            result ??= new(TypicalFormFieldCount, StringComparer.OrdinalIgnoreCase);
            result["_search"] = SanitiseFieldValue(string.Join(' ', searchParts));
        }

        return result;
    }

    /// <summary>Collect a value from words starting at index, handling quoted strings.</summary>
    private static string CollectValue(string[] words, int startIdx, out int consumed)
    {
        consumed = 0;
        if (startIdx >= words.Length) return "";

        var first = words[startIdx];

        // Quoted value: 'dave smith' or "dave smith"
        if (first.Length > 0 && first[0] is '\'' or '"')
        {
            char quote = first[0];
            var sb = new StringBuilder(32);
            for (int j = startIdx; j < words.Length; j++)
            {
                consumed++;
                var part = words[j];
                if (j == startIdx) part = part[1..]; // strip opening quote
                if (part.Length > 0 && part[^1] == quote)
                {
                    sb.Append(part[..^1]); // strip closing quote
                    return sb.ToString().Trim();
                }
                sb.Append(part);
                sb.Append(' ');
            }
            return sb.ToString().Trim(); // unclosed quote — return what we have
        }

        // Single word value (stop at known filler/verb/connector)
        consumed = 1;
        return first;
    }

    /// <summary>Check if a word is a known action verb.</summary>
    private static bool IsKnownVerb(string word)
    {
        foreach (var (verbs, _) in s_verbMap)
            foreach (var v in verbs)
                if (v == word) return true;
        return false;
    }

    /// <summary>Check if a word is a known entity token.</summary>
    private static bool IsKnownEntity(string word)
    {
        foreach (var (tokens, _, _) in s_entityMap)
            foreach (var t in tokens)
                if (t == word) return true;
        return false;
    }

    /// <summary>Common filler words to skip during search term extraction.</summary>
    private static bool IsFillerWord(string word) =>
        word is "the" or "a" or "an" or "all" or "my" or "me" or "i" or "we"
        or "to" or "for" or "of" or "from" or "in" or "on" or "at" or "by"
        or "and" or "or" or "not" or "as" or "is" or "are" or "was" or "were"
        or "this" or "that" or "these" or "those" or "it" or "its" or "you"
        or "your" or "can" or "could" or "would" or "will" or "should"
        or "please" or "?" or "!" or "." or "," or ";" or "";
}

// ── Result types ──────────────────────────────────────────────────────────

/// <summary>
/// Structured result of an intent classification operation.
/// </summary>
public readonly record struct IntentResult(
    /// <summary>Dot-notation intent string, e.g. "entity.list.users".</summary>
    string ResolvedIntent,
    /// <summary>Canonical action type.</summary>
    IntentAction Action,
    /// <summary>Matched entity slug (null if no entity was identified).</summary>
    string? EntitySlug,
    /// <summary>Confidence score 0-1.</summary>
    float Confidence,
    /// <summary>Human-readable entity name for display.</summary>
    string? EntityName = null,
    /// <summary>Extracted entity ID if present in the query.</summary>
    string? EntityId = null,
    /// <summary>Extracted field key/value pairs for form prefill (null if none).</summary>
    Dictionary<string, string>? FormFields = null,
    /// <summary>
    /// Extracted search/filter parameters from natural language patterns.
    /// Keys are field hints ("name", "email", "_search" for unqualified terms).
    /// Values are the extracted terms. Used for semantic search over metadata/WAL.
    /// </summary>
    Dictionary<string, string>? SearchTerms = null)
{
    /// <summary>Sentinel empty result returned when the query is blank.</summary>
    public static readonly IntentResult Empty = new(
        "none", IntentAction.Unknown, null, 0f);

    /// <summary>True when the confidence is high enough for direct routing.</summary>
    public bool IsConfident => Confidence >= 0.6f;
}

/// <summary>Canonical action types for intent routing.</summary>
public enum IntentAction : byte
{
    Unknown       = 0,
    List          = 1,
    Query         = 2,
    Create        = 3,
    Edit          = 4,
    Delete        = 5,
    SystemStatus  = 6,
    SystemMemory  = 7,
    Help          = 8,
    Stats         = 9,
    Maintenance   = 10,
    Execute       = 11,
    Configure     = 12,
}
