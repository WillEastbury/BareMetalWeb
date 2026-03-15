using System.Text;
using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Orchestrates query processing for admin chat via the BitNet b1.58 ternary SLM
/// (weights quantised to {-1, 0, +1}).
///
/// Pipeline: classify intent → tool dispatch (if confident) → BitNet fallback.
/// When classification confidence exceeds the threshold the orchestrator dispatches
/// directly to a registered tool, returning structured navigation and prefill data.
/// Ambiguous or freeform queries fall through to the BitNet engine.
/// </summary>
public sealed class IntelligenceOrchestrator
{
    private readonly IBitNetEngine _engine;
    private readonly IToolExecutor? _tools;

    /// <summary>Minimum confidence to dispatch to a tool instead of BitNet.</summary>
    private const float ClassifyThreshold = 0.6f;

    public IntelligenceOrchestrator(
        IBitNetEngine engine,
        IToolExecutor? tools = null)
    {
        _engine = engine;
        _tools  = tools;
    }

    /// <summary>
    /// Return aggregated pipeline metrics from the underlying engine.
    /// Returns <see langword="null"/> if the engine has no model loaded.
    /// </summary>
    public BitNetPipelineMetrics? GetMetrics() => _engine.GetMetrics();

    /// <summary>
    /// Process a user query: classify → tool dispatch → BitNet fallback.
    /// </summary>
    public async ValueTask<ChatResponse> ProcessAsync(
        string query,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(query))
            return new ChatResponse("Please enter a query.", "none", 0f);

        // Sanitise input (prevent injection)
        string sanitised = SanitiseInput(query);

        // Stage 1: Keyword-based intent classification
        var classification = IntentClassifier.Classify(sanitised);

        if (classification is not null && classification.Confidence >= ClassifyThreshold)
        {
            // Stage 2: Tool dispatch if we have a tool executor
            string message;
            if (_tools is not null)
            {
                var toolResult = await _tools.ExecuteAsync(
                    classification.Intent, classification.Parameters, ct)
                    .ConfigureAwait(false);
                message = toolResult.Success ? toolResult.Output : toolResult.ErrorMessage ?? "Tool execution failed.";
            }
            else
            {
                // No tool executor — build a navigable response from the classification
                message = BuildClassifiedResponse(classification);
            }

            return new ChatResponse(
                message,
                classification.Intent,
                classification.Confidence,
                classification.NavigateUrl,
                classification.PrefillFields);
        }

        // Stage 3: BitNet engine fallback for freeform/ambiguous queries
        var generated = await _engine.GenerateAsync(sanitised.AsMemory(), 256, ct)
            .ConfigureAwait(false);

        // Guard against degenerate output (untrained/random model weights produce
        // repetitive token sequences like "tok_72 tok_72 tok_72...")
        if (IsDegenerate(generated))
        {
            return new ChatResponse(
                "I'm not sure how to help with that. Try 'help' to see what I can do, " +
                "or use a command like 'create a todo', 'show customers', or 'system status'.",
                "bitnet-fallback", 0f);
        }

        return new ChatResponse(generated, "bitnet-generate", 0f);
    }

    /// <summary>
    /// Detects degenerate BitNet output: repetitive characters, very low
    /// character diversity, or mostly non-printable content.
    /// </summary>
    private static bool IsDegenerate(string output)
    {
        if (string.IsNullOrWhiteSpace(output)) return true;
        if (output.Length < 2) return true;

        // Check character diversity: count distinct chars.
        // Good text uses many distinct characters; degenerate output repeats a few.
        Span<bool> seen = stackalloc bool[128];
        int distinct = 0;
        int printable = 0;

        for (int i = 0; i < output.Length; i++)
        {
            char c = output[i];
            if (c >= 32 && c <= 126) printable++;
            if (c < 128 && !seen[c])
            {
                seen[c] = true;
                distinct++;
            }
        }

        // If <20% of output is printable ASCII, it's garbage
        if (output.Length > 4 && printable < output.Length * 0.2)
            return true;

        // If distinct char count is very low relative to length, it's repetitive
        // (e.g., "aaaaaaa" = 1 distinct in 7 chars)
        if (output.Length > 8 && distinct < 3)
            return true;

        // Check for excessive character-level repetition (e.g., same char >60% of output)
        Span<int> freq = stackalloc int[128];
        for (int i = 0; i < output.Length; i++)
        {
            char c = output[i];
            if (c < 128) freq[c]++;
        }
        int maxFreq = 0;
        for (int i = 0; i < 128; i++)
            if (freq[i] > maxFreq) maxFreq = freq[i];

        if (output.Length > 8 && maxFreq > output.Length * 0.6)
            return true;

        return false;
    }

    private static string BuildClassifiedResponse(IntentClassification c)
    {
        if (c.NavigateUrl is not null)
        {
            var sb = new StringBuilder(128);
            sb.Append($"Navigate to {c.NavigateUrl}");
            if (c.PrefillFields is { Count: > 0 })
            {
                sb.Append(" with ");
                bool first = true;
                foreach (var kvp in c.PrefillFields)
                {
                    if (!first) sb.Append(", ");
                    sb.Append($"{kvp.Key}=\"{kvp.Value}\"");
                    first = false;
                }
            }
            return sb.ToString();
        }

        return c.Intent switch
        {
            "greeting" => "Hello! I can help you query data, manage entities, and perform system operations. Type 'help' to see what I can do.",
            "farewell" => "Goodbye! Feel free to return anytime.",
            "help" => "Available commands: create, show, find, query, describe, count, list entities, system status, index status.",
            "list-entities" => "Use 'list entities' to see all registered data entities.",
            "system-status" => "Use 'system status' to view system diagnostics.",
            "index-status" => "Use 'index status' to view search index health.",
            _ => $"Intent: {c.Intent}" + (c.Entity is not null ? $", Entity: {c.Entity}" : "")
        };
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
    float Confidence,
    string? NavigateUrl = null,
    Dictionary<string, string>? PrefillFields = null
);
