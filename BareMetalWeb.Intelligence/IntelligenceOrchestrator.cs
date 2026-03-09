using System.Text;
using System.Text.RegularExpressions;
using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Orchestrates intent classification and tool execution for admin chat.
/// Two-tier architecture: fast keyword match → optional BitNet fallback.
/// Maintains single-slot entity context across turns for follow-up queries.
/// </summary>
public sealed class IntelligenceOrchestrator
{
    private readonly IIntentClassifier _classifier;
    private readonly IToolExecutor _executor;
    private readonly IBitNetEngine? _engine;

    // Single-slot conversational context — remembers the last entity mentioned
    private string? _lastEntity;

    public IntelligenceOrchestrator(
        IIntentClassifier classifier,
        IToolExecutor executor,
        IBitNetEngine? engine = null)
    {
        _classifier = classifier;
        _executor = executor;
        _engine = engine;
    }

    /// <summary>
    /// Process a user query through the two-tier pipeline.
    /// </summary>
    public async ValueTask<ChatResponse> ProcessAsync(
        string query,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(query))
            return new ChatResponse("Please enter a query.", "none", 0f);

        // Sanitise input (prevent injection)
        string sanitised = SanitiseInput(query);

        // Tier 1: Intent classification
        var intent = _classifier.Classify(sanitised.AsSpan());

        if (intent.IsHighConfidence)
        {
            // Direct tool execution — fast path
            var parameters = ExtractParameters(sanitised, intent.IntentName);
            ApplyContext(parameters, intent.IntentName);
            var result = await _executor.ExecuteAsync(intent.IntentName, parameters, ct)
                .ConfigureAwait(false);

            return new ChatResponse(
                result.Success ? result.Output : $"Error: {result.ErrorMessage}",
                intent.IntentName,
                intent.Confidence);
        }

        if (intent.IsMatch)
        {
            // Medium confidence — try tool execution but note uncertainty
            var parameters = ExtractParameters(sanitised, intent.IntentName);
            ApplyContext(parameters, intent.IntentName);
            var result = await _executor.ExecuteAsync(intent.IntentName, parameters, ct)
                .ConfigureAwait(false);

            string prefix = $"(Confidence: {intent.Confidence:P0} — I think you meant '{intent.IntentName}')\n\n";
            return new ChatResponse(
                result.Success ? prefix + result.Output : $"Error: {result.ErrorMessage}",
                intent.IntentName,
                intent.Confidence);
        }

        // Tier 2: Fall through to BitNet engine if available
        if (_engine is not null && _engine.IsLoaded)
        {
            var generated = await _engine.GenerateAsync(sanitised.AsMemory(), 256, ct)
                .ConfigureAwait(false);
            return new ChatResponse(generated, "bitnet-generate", 0f);
        }

        // No match, no engine
        return new ChatResponse(
            $"I didn't understand that query (best match: '{intent.IntentName}' at {intent.Confidence:P0}).\n" +
            "Try 'help' to see available commands.",
            "unknown",
            intent.Confidence);
    }

    /// <summary>
    /// Apply conversational context — carry forward the last entity when none
    /// is mentioned in a follow-up query, and remember the current entity.
    /// </summary>
    private void ApplyContext(Dictionary<string, string> parameters, string intentName)
    {
        if (intentName is "describe-entity" or "query-entity" or "show-entity" or "count-entity")
        {
            if (parameters.TryGetValue("entity", out var entity) && !string.IsNullOrEmpty(entity))
            {
                _lastEntity = entity;
            }
            else if (_lastEntity != null)
            {
                parameters["entity"] = _lastEntity;
            }
        }
    }

    // ── Skip-word list shared across extraction methods ──

    private static readonly HashSet<string> SkipWords = new(StringComparer.OrdinalIgnoreCase)
    {
        "describe", "show", "display", "view", "open", "list",
        "query", "find", "search", "get", "fetch", "count",
        "how", "many", "fields", "of", "for", "the", "a",
        "an", "in", "from", "all", "me", "record", "detail",
        "records", "items", "results", "data", "please"
    };

    // ── Filter operator keywords mapped to QueryOperator names ──

    private static readonly Dictionary<string, string> FilterOperators = new(StringComparer.OrdinalIgnoreCase)
    {
        ["equals"]   = "Equals",   ["="]        = "Equals",   ["is"]       = "Equals",
        ["contains"] = "Contains", ["like"]     = "Contains", ["has"]      = "Contains",
        ["starts"]   = "StartsWith", ["startswith"] = "StartsWith",
        ["ends"]     = "EndsWith",   ["endswith"]   = "EndsWith",
        [">"]        = "GreaterThan",  ["greater"]    = "GreaterThan", ["above"]  = "GreaterThan", ["after"] = "GreaterThan",
        ["<"]        = "LessThan",     ["less"]       = "LessThan",    ["below"]  = "LessThan",    ["before"] = "LessThan",
        [">="]       = "GreaterThanOrEqual",
        ["<="]       = "LessThanOrEqual",
        ["not"]      = "NotEquals",    ["!="]         = "NotEquals",
    };

    /// <summary>
    /// Extract parameters from natural language, handling:
    /// - Multi-word entity names (tries 2-word then 1-word against known slugs)
    /// - "where field operator value" filter clauses
    /// - "how many" → count-entity intent upgrade
    /// - Remaining text as free-text query
    /// </summary>
    private static Dictionary<string, string> ExtractParameters(string query, string intentName)
    {
        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (intentName is not ("describe-entity" or "query-entity" or "show-entity" or "count-entity"))
            return parameters;

        var words = query.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // Phase 1: Find the entity name (try multi-word slug match first)
        int entityEndIdx = -1;
        string? resolvedEntity = null;

        // Collect candidate words (skip verb/filler words)
        var candidateIndices = new List<int>();
        for (int i = 0; i < words.Length; i++)
        {
            if (!SkipWords.Contains(words[i]))
                candidateIndices.Add(i);
        }

        if (candidateIndices.Count >= 2)
        {
            // Try 2-word slug: "work orders" → "work-orders"
            int i0 = candidateIndices[0], i1 = candidateIndices[1];
            if (i1 == i0 + 1) // adjacent words
            {
                var twoWord = words[i0] + "-" + words[i1];
                if (TryResolveEntitySlug(twoWord))
                {
                    resolvedEntity = twoWord;
                    entityEndIdx = i1;
                }
                // Also try without hyphen as a single joined slug
                if (resolvedEntity == null)
                {
                    var joined = words[i0] + words[i1];
                    if (TryResolveEntitySlug(joined))
                    {
                        resolvedEntity = joined;
                        entityEndIdx = i1;
                    }
                }
            }
        }

        if (resolvedEntity == null && candidateIndices.Count >= 1)
        {
            // Single word entity
            resolvedEntity = words[candidateIndices[0]];
            entityEndIdx = candidateIndices[0];
        }

        if (resolvedEntity != null)
            parameters["entity"] = resolvedEntity;

        // Phase 2: Parse remaining words for filters or free-text query
        if (entityEndIdx >= 0 && entityEndIdx + 1 < words.Length)
        {
            var remainder = words.AsSpan()[(entityEndIdx + 1)..];
            ParseRemainder(remainder, parameters);
        }

        return parameters;
    }

    /// <summary>
    /// Parse the remainder of the query after the entity name.
    /// Detects "where field op value" filter patterns and free-text search.
    /// </summary>
    private static void ParseRemainder(ReadOnlySpan<string> words, Dictionary<string, string> parameters)
    {
        // Look for "where" keyword to start structured filter parsing
        int whereIdx = -1;
        for (int i = 0; i < words.Length; i++)
        {
            if (string.Equals(words[i], "where", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(words[i], "with", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(words[i], "whose", StringComparison.OrdinalIgnoreCase))
            {
                whereIdx = i;
                break;
            }
        }

        if (whereIdx >= 0 && whereIdx + 2 < words.Length)
        {
            // "where <field> <op> <value...>" or "where <field> <value>" (implicit equals)
            var filterWords = words[(whereIdx + 1)..];
            string field = filterWords[0];

            if (filterWords.Length >= 3 && FilterOperators.TryGetValue(filterWords[1], out var opName))
            {
                // Explicit operator: "where status equals active"
                var valueParts = new List<string>();
                for (int i = 2; i < filterWords.Length; i++)
                    valueParts.Add(filterWords[i]);

                parameters["filterField"] = field;
                parameters["filterOp"] = opName;
                parameters["filterValue"] = string.Join(' ', valueParts);
            }
            else if (filterWords.Length >= 2)
            {
                // Implicit equals: "where status active"
                var valueParts = new List<string>();
                for (int i = 1; i < filterWords.Length; i++)
                    valueParts.Add(filterWords[i]);

                parameters["filterField"] = field;
                parameters["filterOp"] = "Contains";
                parameters["filterValue"] = string.Join(' ', valueParts);
            }

            // Pre-where text becomes the query
            if (whereIdx > 0)
            {
                var preWhere = new List<string>();
                for (int i = 0; i < whereIdx; i++)
                    preWhere.Add(words[i]);
                if (preWhere.Count > 0)
                    parameters["query"] = string.Join(' ', preWhere);
            }
        }
        else
        {
            // No "where" clause — everything is free-text query
            var parts = new List<string>();
            for (int i = 0; i < words.Length; i++)
                parts.Add(words[i]);
            if (parts.Count > 0)
                parameters["query"] = string.Join(' ', parts);
        }
    }

    /// <summary>
    /// Quick check if a slug or its singular/plural variant resolves to an entity.
    /// </summary>
    private static bool TryResolveEntitySlug(string candidate)
    {
        if (BareMetalWeb.Core.DataScaffold.TryGetEntity(candidate, out _))
            return true;
        // Try plural
        if (BareMetalWeb.Core.DataScaffold.TryGetEntity(candidate + "s", out _))
            return true;
        // Try singular
        if (candidate.EndsWith('s') && candidate.Length > 2 &&
            BareMetalWeb.Core.DataScaffold.TryGetEntity(candidate[..^1], out _))
            return true;
        return false;
    }

    private static string SanitiseInput(string input)
    {
        // Strip control characters and limit length
        if (input.Length > 1024)
            input = input[..1024];

        // Remove any control characters except standard whitespace
        var sb = new StringBuilder(input.Length);
        foreach (char c in input)
        {
            if (char.IsControl(c) && c != ' ' && c != '\t' && c != '\n')
                continue;
            sb.Append(c);
        }

        return sb.ToString().Trim();
    }
}

/// <summary>
/// Response from the intelligence orchestrator.
/// </summary>
public readonly record struct ChatResponse(
    string Message,
    string ResolvedIntent,
    float Confidence
);
