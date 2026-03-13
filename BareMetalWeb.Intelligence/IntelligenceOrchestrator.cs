using System.Text;
using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Orchestrates query processing for admin chat via the BitNet b1.58 ternary SLM
/// (weights quantised to {-1, 0, +1}).
///
/// When an <see cref="IToolExecutor"/> is supplied the orchestrator can dispatch
/// directly to a named tool; otherwise all queries fall through to the BitNet engine.
/// </summary>
public sealed class IntelligenceOrchestrator
{
    private readonly IBitNetEngine _engine;
    private readonly IToolExecutor? _tools;

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
    /// Process a user query through the BitNet engine.
    /// </summary>
    public async ValueTask<ChatResponse> ProcessAsync(
        string query,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(query))
            return new ChatResponse("Please enter a query.", "none", 0f);

        // Sanitise input (prevent injection)
        string sanitised = SanitiseInput(query);

        // BitNet engine single-stage inference
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
