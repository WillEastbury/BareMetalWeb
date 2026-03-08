using System.Text;
using System.Text.RegularExpressions;
using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Orchestrates intent classification and tool execution for admin chat.
/// Two-tier architecture: fast keyword match → optional BitNet fallback.
/// </summary>
public sealed class IntelligenceOrchestrator
{
    private readonly IIntentClassifier _classifier;
    private readonly IToolExecutor _executor;
    private readonly IBitNetEngine? _engine;

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
    /// Extract simple parameters from the query based on intent.
    /// </summary>
    private static Dictionary<string, string> ExtractParameters(string query, string intentName)
    {
        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Extract entity name for entity-related intents
        if (intentName is "describe-entity" or "query-entity")
        {
            var words = query.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            // Look for the entity name after keyword verbs
            string[] skipWords = ["describe", "show", "list", "query", "find", "search",
                                  "get", "fetch", "count", "how", "many", "fields",
                                  "of", "for", "the", "a", "an", "in", "from", "all", "me"];

            foreach (var word in words)
            {
                if (!Array.Exists(skipWords, s =>
                    string.Equals(s, word, StringComparison.OrdinalIgnoreCase)))
                {
                    parameters["entity"] = word;
                    break;
                }
            }
        }

        return parameters;
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
