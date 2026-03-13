using System.Text;
using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Defines an intent with its matching keywords.
/// </summary>
public sealed record IntentDefinition(
    string Name,
    string Description,
    IReadOnlyList<string> Keywords
);


/// <summary>
/// Orchestrates query processing for admin chat via the BitNet b1.58 ternary SLM
/// (weights quantised to {-1, 0, +1}).
///
/// When an <see cref="IIntentClassifier"/> and <see cref="IToolExecutor"/> are
/// supplied the orchestrator uses a two-stage pipeline: keyword intent classification
/// followed by tool dispatch. The BitNet engine is used as a fallback when no
/// high-confidence intent is found, preserving the fast single-stage path for
/// open-ended queries.
/// </summary>
public sealed class IntelligenceOrchestrator
{
    private readonly IBitNetEngine _engine;
    private readonly IIntentClassifier? _classifier;
    private readonly IToolExecutor? _tools;

    public IntelligenceOrchestrator(
        IBitNetEngine engine,
       // IIntentClassifier? classifier = null,
        IToolExecutor? tools = null)
    {
        _engine = engine;
       // _classifier = classifier;
        _tools = tools;
    }

    /// <summary>
    /// Return aggregated pipeline metrics from the underlying engine.
    /// Returns <see langword="null"/> if the engine has no model loaded.
    /// </summary>
    public BitNetPipelineMetrics? GetMetrics() => _engine.GetMetrics();

    /// <summary>
    /// Process a user query. When a classifier and tool executor are available,
    /// high-confidence intents are dispatched to the matching tool first.
    /// Unmatched or low-confidence queries fall through to the BitNet engine.
    /// </summary>
    public async ValueTask<ChatResponse> ProcessAsync(
        string query,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(query))
            return new ChatResponse("Please enter a query.", "none", 0f);

        // Sanitise input (prevent injection)
        string sanitised = SanitiseInput(query);

        // Fast path: intent classification → tool dispatch
        if (_classifier is not null && _tools is not null)
        {
            var intent = _classifier.Classify(sanitised.AsSpan());
            if (intent.Confidence > 0.25f)
            {
                var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["query"] = sanitised
                };

                var toolResult = await _tools.ExecuteAsync(intent.IntentName, parameters, ct)
                    .ConfigureAwait(false);

                if (toolResult.Success)
                    return new ChatResponse(toolResult.Output, intent.IntentName, intent.Confidence);
            }
        }

        // Fallback: BitNet engine single-stage inference
        var generated = await _engine.GenerateAsync(sanitised.AsMemory(), 256, ct)
            .ConfigureAwait(false);
        return new ChatResponse(generated, "bitnet-generate", 0f);
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
