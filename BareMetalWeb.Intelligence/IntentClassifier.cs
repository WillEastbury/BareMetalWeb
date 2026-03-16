namespace BareMetalWeb.Intelligence;

/// <summary>
/// Lightweight keyword/pattern-based intent classifier that maps natural language
/// prompts to structured intents without requiring ML inference.  Runs before the
/// BitNet engine so that actionable commands (create, show, list, etc.) get routed
/// to the tool registry instantly, while freeform/ambiguous queries fall through
/// to the language model.
/// </summary>
public static class IntentClassifier
{
    /// <summary>
    /// Attempt to classify a sanitised user prompt into a structured intent.
    /// Returns null when the prompt is ambiguous or not recognised — the caller
    /// should fall through to BitNet generation in that case.
    /// </summary>
    public static IntentClassification? Classify(string prompt)
    {
        if (string.IsNullOrWhiteSpace(prompt))
            return null;

        // Avoid ToLowerInvariant() allocation — lower in-place on a stack buffer
        var trimmed = prompt.AsSpan().Trim();
        int len = trimmed.Length;
        Span<char> lowerBuf = len <= 512 ? stackalloc char[len] : new char[len];
        trimmed.ToLowerInvariant(lowerBuf);
        var lower = new string(lowerBuf);

        // ── Greetings / farewells ───────────────────────────────────────
        if (IsGreeting(lower))
            return new IntentClassification("greeting", 0.95f);
        if (IsFarewell(lower))
            return new IntentClassification("farewell", 0.95f);

        // ── Help ────────────────────────────────────────────────────────
        if (lower is "help" or "?" or "what can you do" or "commands" ||
            lower.StartsWith("help ", StringComparison.Ordinal) ||
            lower.Contains("what can you do"))
            return new IntentClassification("help", 0.9f);

        // ── System / index status ───────────────────────────────────────
        if (lower.Contains("system status") || lower.Contains("diagnostics") ||
            lower.Contains("memory usage") || lower.Contains("health check"))
            return new IntentClassification("system-status", 0.9f);

        if (lower.Contains("index status") || lower.Contains("index health") ||
            lower.Contains("search index") || lower.Contains("rebuild index"))
            return new IntentClassification("index-status", 0.9f);

        // ── List entities ───────────────────────────────────────────────
        if (lower is "list entities" or "show entities" or "list all entities" or
            "show all entities" or "all entities" or "what entities" ||
            lower.Contains("list all entities") || lower.Contains("show all data models"))
            return new IntentClassification("list-entities", 0.9f);

        // ── Create intent — extract entity + prefill fields ─────────────
        if (TryClassifyCreate(lower, prompt, out var createResult))
            return createResult;

        // ── Describe entity ─────────────────────────────────────────────
        if (TryClassifyDescribe(lower, out var descResult))
            return descResult;

        // ── Query / find / show entity ──────────────────────────────────
        if (TryClassifyQuery(lower, prompt, out var queryResult))
            return queryResult;

        // ── Count entity ────────────────────────────────────────────────
        if (TryClassifyCount(lower, out var countResult))
            return countResult;

        // ── Plan workflow ───────────────────────────────────────────────
        if (lower.StartsWith("plan ", StringComparison.Ordinal) ||
            lower.Contains("workflow") || lower.Contains("automate"))
            return new IntentClassification("plan-workflow", 0.6f)
            {
                Parameters = new Dictionary<string, string> { ["intent"] = prompt }
            };

        // Not recognised — fall through to BitNet
        return null;
    }

    // ── Create intent parser ────────────────────────────────────────────────

    private static bool TryClassifyCreate(string lower, string original,
        out IntentClassification? result)
    {
        result = null;

        // Match patterns like:
        //   "create a todo"
        //   "create a todo for reminding me about beer"
        //   "new todo"
        //   "add a customer"
        //   "make a new order"
        ReadOnlySpan<char> span = lower.AsSpan();
        string? entityHint = null;
        string? remainder = null;

        if (TryExtractAfterVerb(span, "create ", out var afterCreate))
        {
            (entityHint, remainder) = ParseEntityAndRemainder(afterCreate, original);
        }
        else if (span is "create")
        {
            // Bare verb with no entity
        }
        else if (TryExtractAfterVerb(span, "add ", out var afterAdd))
        {
            (entityHint, remainder) = ParseEntityAndRemainder(afterAdd, original);
        }
        else if (TryExtractAfterVerb(span, "make ", out var afterMake))
        {
            (entityHint, remainder) = ParseEntityAndRemainder(afterMake, original);
        }
        else if (span.StartsWith("new "))
        {
            var rest = span[4..].Trim();
            (entityHint, remainder) = ParseEntityAndRemainder(rest, original);
        }
        else
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(entityHint))
        {
            // "create" with no entity — generic create-entity intent
            result = new IntentClassification("create-entity", 0.7f);
            return true;
        }

        // Check for specific "create-todo" shortcut
        if (entityHint.Contains("todo", StringComparison.OrdinalIgnoreCase))
        {
            result = new IntentClassification("create-todo", 0.9f)
            {
                Entity = "todo",
                NavigateUrl = "/to-do/new",
            };

            if (!string.IsNullOrWhiteSpace(remainder))
            {
                result.PrefillFields = new Dictionary<string, string>
                {
                    ["Title"] = SanitiseForField(remainder.Trim())
                };
            }
            return true;
        }

        // Generic entity create
        result = new IntentClassification("create-entity", 0.85f)
        {
            Entity = entityHint,
            Parameters = new Dictionary<string, string> { ["entity"] = entityHint }
        };

        if (!string.IsNullOrWhiteSpace(remainder))
        {
            result.PrefillFields = new Dictionary<string, string>
            {
                ["Title"] = SanitiseForField(remainder.Trim()),
                ["Name"] = SanitiseForField(remainder.Trim())
            };
        }

        return true;
    }

    /// <summary>
    /// Given text after a verb (e.g. "a todo for reminding me about beer"),
    /// extracts the entity name and any remaining descriptive text.
    /// Strips articles (a, an, the) and "new".
    /// </summary>
    private static (string? entity, string? remainder) ParseEntityAndRemainder(
        ReadOnlySpan<char> text, string original)
    {
        // Strip leading articles: "a ", "an ", "the ", "new "
        var work = text.Trim();
        while (true)
        {
            if (work.StartsWith("a ") && work.Length > 2)
                work = work[2..].TrimStart();
            else if (work.StartsWith("an ") && work.Length > 3)
                work = work[3..].TrimStart();
            else if (work.StartsWith("the ") && work.Length > 4)
                work = work[4..].TrimStart();
            else if (work.StartsWith("new ") && work.Length > 4)
                work = work[4..].TrimStart();
            else
                break;
        }

        if (work.IsEmpty)
            return (null, null);

        // First word is the entity hint
        int spaceIdx = work.IndexOf(' ');
        if (spaceIdx < 0)
            return (work.ToString(), null);

        var entity = work[..spaceIdx].ToString();
        var rest = work[(spaceIdx + 1)..].Trim();

        // Strip connector words: "for", "about", "with", "called", "named", "to"
        while (true)
        {
            if (rest.StartsWith("for ") && rest.Length > 4)
                rest = rest[4..].TrimStart();
            else if (rest.StartsWith("about ") && rest.Length > 6)
                rest = rest[6..].TrimStart();
            else if (rest.StartsWith("with ") && rest.Length > 5)
                rest = rest[5..].TrimStart();
            else if (rest.StartsWith("called ") && rest.Length > 7)
                rest = rest[7..].TrimStart();
            else if (rest.StartsWith("named ") && rest.Length > 6)
                rest = rest[6..].TrimStart();
            else if (rest.StartsWith("to ") && rest.Length > 3)
                rest = rest[3..].TrimStart();
            else
                break;
        }

        return (entity, rest.IsEmpty ? null : rest.ToString());
    }

    // ── Describe intent parser ──────────────────────────────────────────────

    private static bool TryClassifyDescribe(string lower, out IntentClassification? result)
    {
        result = null;

        if (lower.StartsWith("describe ", StringComparison.Ordinal))
        {
            var entity = lower[9..].Replace("fields", "").Replace("schema", "").Trim();
            if (!string.IsNullOrEmpty(entity))
            {
                result = new IntentClassification("describe-entity", 0.85f)
                {
                    Entity = entity,
                    Parameters = new Dictionary<string, string> { ["entity"] = entity }
                };
                return true;
            }
        }

        return false;
    }

    // ── Query / find / show intent parser ────────────────────────────────────

    private static bool TryClassifyQuery(string lower, string original,
        out IntentClassification? result)
    {
        result = null;

        ReadOnlySpan<char> span = lower.AsSpan();
        ReadOnlySpan<char> origSpan = original.AsSpan().Trim();
        string? entityHint = null;
        string? filterHint = null;

        if (TryExtractAfterVerb(span, "show ", out var afterShow))
        {
            var rest = StripArticles(afterShow);
            (entityHint, filterHint) = SplitEntityFilter(rest);
        }
        else if (TryExtractAfterVerb(span, "find ", out var afterFind))
        {
            var rest = StripArticles(afterFind);
            (entityHint, filterHint) = SplitEntityFilter(rest);
        }
        else if (TryExtractAfterVerb(span, "query ", out var afterQuery))
        {
            var rest = StripArticles(afterQuery);
            (entityHint, filterHint) = SplitEntityFilter(rest);
        }
        else if (TryExtractAfterVerb(span, "search ", out var afterSearch))
        {
            var rest = StripArticles(afterSearch);
            (entityHint, filterHint) = SplitEntityFilter(rest);
        }
        else if (TryExtractAfterVerb(span, "get ", out var afterGet))
        {
            var rest = StripArticles(afterGet);
            (entityHint, filterHint) = SplitEntityFilter(rest);
        }
        else
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(entityHint))
            return false;

        var intent = filterHint is not null ? "query-entity" : "show-entity";
        result = new IntentClassification(intent, 0.8f)
        {
            Entity = entityHint,
            Parameters = new Dictionary<string, string> { ["entity"] = entityHint }
        };

        // Extract filter from original prompt to preserve casing
        if (filterHint is not null)
        {
            int filterIdx = origSpan.IndexOf(filterHint.AsSpan(), StringComparison.OrdinalIgnoreCase);
            result.Parameters["query"] = filterIdx >= 0
                ? origSpan.Slice(filterIdx, filterHint.Length).ToString()
                : filterHint;
        }

        return true;
    }

    // ── Count intent parser ─────────────────────────────────────────────────

    private static bool TryClassifyCount(string lower, out IntentClassification? result)
    {
        result = null;

        if (lower.StartsWith("count ", StringComparison.Ordinal) ||
            lower.StartsWith("how many ", StringComparison.Ordinal))
        {
            var rest = lower.StartsWith("how many ") ? lower[9..] : lower[6..];
            rest = rest.Trim();
            if (!string.IsNullOrEmpty(rest))
            {
                result = new IntentClassification("count-entity", 0.8f)
                {
                    Entity = rest,
                    Parameters = new Dictionary<string, string> { ["entity"] = rest }
                };
                return true;
            }
        }

        return false;
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static bool TryExtractAfterVerb(ReadOnlySpan<char> text,
        ReadOnlySpan<char> verb, out ReadOnlySpan<char> rest)
    {
        if (text.StartsWith(verb, StringComparison.Ordinal))
        {
            rest = text[verb.Length..];
            return true;
        }
        rest = default;
        return false;
    }

    private static ReadOnlySpan<char> StripArticles(ReadOnlySpan<char> text)
    {
        var work = text.Trim();
        if (work.StartsWith("all ")) work = work[4..].TrimStart();
        if (work.StartsWith("the ")) work = work[4..].TrimStart();
        if (work.StartsWith("a ")) work = work[2..].TrimStart();
        if (work.StartsWith("an ")) work = work[3..].TrimStart();
        return work;
    }

    private static (string? entity, string? filter) SplitEntityFilter(ReadOnlySpan<char> text)
    {
        if (text.IsEmpty) return (null, null);

        int spaceIdx = text.IndexOf(' ');
        if (spaceIdx < 0) return (text.ToString(), null);

        var entity = text[..spaceIdx].ToString();
        var filter = text[(spaceIdx + 1)..].Trim().ToString();

        // If the rest looks like "where ...", "with ...", strip the keyword
        if (filter.StartsWith("where ", StringComparison.OrdinalIgnoreCase))
            filter = filter[6..];
        else if (filter.StartsWith("with ", StringComparison.OrdinalIgnoreCase))
            filter = filter[5..];

        return (entity, string.IsNullOrEmpty(filter) ? null : filter);
    }

    private static bool IsGreeting(string lower) =>
        lower is "hi" or "hello" or "hey" or "good morning" or "good afternoon" or
            "good evening" or "howdy" or "yo" or "hiya" or "greetings" ||
        lower.StartsWith("hi ", StringComparison.Ordinal) ||
        lower.StartsWith("hi,", StringComparison.Ordinal) ||
        lower.StartsWith("hello ", StringComparison.Ordinal) ||
        lower.StartsWith("hello,", StringComparison.Ordinal) ||
        lower.StartsWith("hey ", StringComparison.Ordinal) ||
        lower.StartsWith("hey,", StringComparison.Ordinal);

    private static bool IsFarewell(string lower) =>
        lower is "bye" or "goodbye" or "good bye" or "see you" or "later" or
            "farewell" or "cya" or "peace" or "thanks bye" ||
        lower.StartsWith("bye ", StringComparison.Ordinal) ||
        lower.StartsWith("goodbye ", StringComparison.Ordinal);

    private static string CapitaliseFirst(string s) =>
        string.IsNullOrEmpty(s) ? s : char.ToUpperInvariant(s[0]) + s[1..];

    /// <summary>
    /// Strip HTML-special characters from user input before using as form field values.
    /// Prevents XSS if the frontend renders PrefillFields unsafely.
    /// </summary>
    private static string SanitiseForField(string s)
    {
        if (string.IsNullOrEmpty(s)) return s;
        // Fast path: scan for any dangerous char
        bool needsEscape = false;
        foreach (char c in s)
        {
            if (c is '<' or '>' or '&' or '"' or '\'')
            { needsEscape = true; break; }
        }
        if (!needsEscape) return CapitaliseFirst(s);
        return CapitaliseFirst(s
            .Replace("&", "&amp;")
            .Replace("<", "&lt;")
            .Replace(">", "&gt;")
            .Replace("\"", "&quot;")
            .Replace("'", "&#39;"));
    }
}

/// <summary>
/// Result of intent classification with optional entity, navigation URL,
/// and pre-filled field values for the target form.
/// </summary>
public sealed class IntentClassification
{
    public IntentClassification(string intent, float confidence)
    {
        Intent = intent;
        Confidence = confidence;
    }

    /// <summary>Intent name matching a registered tool (e.g. "create-todo").</summary>
    public string Intent { get; }

    /// <summary>Classification confidence [0–1].</summary>
    public float Confidence { get; }

    /// <summary>Resolved entity slug/hint (e.g. "todo", "customers").</summary>
    public string? Entity { get; init; }

    /// <summary>URL to navigate the user to (e.g. "/to-do/new").</summary>
    public string? NavigateUrl { get; init; }

    /// <summary>Field values to pre-fill on the target form.</summary>
    public Dictionary<string, string>? PrefillFields { get; set; }

    /// <summary>Tool parameters to pass to the tool executor.</summary>
    public Dictionary<string, string> Parameters { get; init; } = new();
}
