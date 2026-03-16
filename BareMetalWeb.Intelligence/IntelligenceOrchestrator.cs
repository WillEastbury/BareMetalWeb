using System.Text;
using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Orchestrates query processing for admin chat via the BitNet b1.58 ternary SLM
/// (weights quantised to {-1, 0, +1}).
///
/// Two-stage pipeline:
///   Stage 1 — <see cref="IntentClassifier"/> (keyword triage, sub-microsecond).
///             High-confidence results are returned directly without consulting
///             the BitNet engine (zero model latency for common admin queries).
///   Stage 2 — BitNet engine inference for ambiguous / complex queries, or when
///             no model-based classifier is wired in.
///
/// When an <see cref="IToolExecutor"/> is supplied the orchestrator can dispatch
/// directly to a named tool; otherwise all queries fall through to the BitNet engine.
/// </summary>
public sealed class IntelligenceOrchestrator
{
    private readonly IBitNetEngine _engine;
    private readonly IToolExecutor? _tools;
    private readonly IntentClassifier _classifier;

    public IntelligenceOrchestrator(
        IBitNetEngine engine,
        IToolExecutor? tools = null,
        IntentClassifier? classifier = null)
    {
        _engine     = engine;
        _tools      = tools;
        _classifier = classifier ?? new IntentClassifier();
    }

    /// <summary>
    /// Return aggregated pipeline metrics from the underlying engine.
    /// Returns <see langword="null"/> if the engine has no model loaded.
    /// </summary>
    public BitNetPipelineMetrics? GetMetrics() => _engine.GetMetrics();

    /// <summary>
    /// Process a user query through the intent classifier and BitNet engine.
    /// Stage 1: keyword-based intent routing (returns immediately when confident).
    /// Stage 2: BitNet engine inference for low-confidence or complex queries.
    /// </summary>
    public async ValueTask<ChatResponse> ProcessAsync(
        string query,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(query))
            return new ChatResponse("Please enter a query.", "none", 0f);

        // Sanitise input (prevent injection)
        string sanitised = SanitiseInput(query);

        // ── Stage 1: Intent classifier triage ─────────────────────────────
        var intent = await _classifier.ClassifyWithFallbackAsync(sanitised, _engine, ct)
            .ConfigureAwait(false);

        if (intent.IsConfident)
        {
            // Build a concise routing response for high-confidence intents
            string message = BuildIntentMessage(intent);
            return new ChatResponse(message, intent.ResolvedIntent, intent.Confidence);
        }

        // ── Stage 2: BitNet engine inference ──────────────────────────────
        var generated = await _engine.GenerateAsync(sanitised.AsMemory(), 256, ct)
            .ConfigureAwait(false);
        return new ChatResponse(generated, "bitnet-generate", 0f);
    }

    // ── Message builder ────────────────────────────────────────────────────

    private static string BuildIntentMessage(IntentResult intent)
    {
        var sb = new StringBuilder(128);

        switch (intent.Action)
        {
            case IntentAction.List:
                sb.Append("Listing ");
                sb.Append(intent.EntityName ?? "records");
                if (intent.EntitySlug is not null)
                    sb.Append($" → /api/{intent.EntitySlug}");
                break;

            case IntentAction.Create:
                sb.Append("Creating ");
                sb.Append(intent.EntityName ?? "record");
                if (intent.EntitySlug is not null)
                    sb.Append($" → POST /api/{intent.EntitySlug}");
                if (intent.FormFields is { Count: > 0 } fields)
                {
                    sb.Append(" with ");
                    foreach (var kv in fields) sb.Append($"{kv.Key}={kv.Value} ");
                }
                if (intent.SearchTerms is { Count: > 0 } createSearchTerms)
                {
                    sb.Append(" [");
                    bool first = true;
                    foreach (var kv in createSearchTerms)
                    {
                        if (!first) sb.Append(", ");
                        sb.Append(kv.Key.StartsWith('_') ? kv.Key[1..] : kv.Key);
                        sb.Append('=');
                        sb.Append(kv.Value);
                        first = false;
                    }
                    sb.Append(']');
                }
                break;

            case IntentAction.Edit:
                sb.Append("Editing ");
                sb.Append(intent.EntityName ?? "record");
                if (intent.EntityId is not null) sb.Append($" #{intent.EntityId}");
                if (intent.EntitySlug is not null)
                    sb.Append($" → PUT /api/{intent.EntitySlug}/{intent.EntityId ?? "?"}");
                break;

            case IntentAction.Delete:
                sb.Append("Deleting ");
                sb.Append(intent.EntityName ?? "record");
                if (intent.EntityId is not null) sb.Append($" #{intent.EntityId}");
                break;

            case IntentAction.Query:
                sb.Append("Querying ");
                sb.Append(intent.EntityName ?? "records");
                if (intent.EntitySlug is not null)
                    sb.Append($" → GET /api/{intent.EntitySlug}");
                if (intent.EntityId is not null) sb.Append($"/{intent.EntityId}");
                if (intent.SearchTerms is { Count: > 0 } searchTerms)
                {
                    sb.Append(" [");
                    bool first = true;
                    foreach (var kv in searchTerms)
                    {
                        if (!first) sb.Append(", ");
                        sb.Append(kv.Key.StartsWith('_') ? kv.Key[1..] : kv.Key);
                        sb.Append('=');
                        sb.Append(kv.Value);
                        first = false;
                    }
                    sb.Append(']');
                }
                break;

            case IntentAction.SystemStatus:
                sb.Append("Checking system status.");
                break;

            case IntentAction.SystemMemory:
                sb.Append("Checking memory diagnostics.");
                break;

            case IntentAction.Help:
                sb.Append("Available actions: list, create, edit, delete, query, status, memory, help.");
                break;

            case IntentAction.Stats:
                sb.Append("Fetching statistics");
                if (intent.EntityName is not null) sb.Append($" for {intent.EntityName}");
                sb.Append('.');
                break;

            case IntentAction.Maintenance:
                sb.Append("Running maintenance task.");
                break;

            default:
                sb.Append(intent.EntityName is not null
                    ? $"Routing to {intent.EntityName} ({intent.ResolvedIntent})."
                    : $"Intent: {intent.ResolvedIntent}.");
                break;
        }

        return sb.ToString();
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
