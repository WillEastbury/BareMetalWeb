using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Host;

/// <summary>
/// Backend handler for the Agent Panel chat interface.
/// Routes all messages through the IntelligenceOrchestrator via the single-stage
/// BitNet SLM pipeline.
/// </summary>
public static class AgentApiHandlers
{
    private static IBufferedLogger? _logger;
    private static IntelligenceOrchestrator? _orchestrator;

    /// <summary>
    /// Optionally supply a logger before the first chat request.
    /// </summary>
    public static void Initialize(IBufferedLogger? logger = null) => _logger = logger;

    private static IntelligenceOrchestrator GetOrchestrator()
    {
        return GetOrCreateOrchestrator();
    }

    /// <summary>
    /// Get or create the shared IntelligenceOrchestrator instance.
    /// Used by chat API routes and the agent panel.
    /// </summary>
    public static IntelligenceOrchestrator GetOrCreateOrchestrator()
    {
        if (_orchestrator is not null)
            return _orchestrator;

        var engine = new BitNetEngine();
        engine.LoadTestModel(ModelLoadOptions.Aggressive);

        var classifier = new KeywordIntentClassifier(AdminToolCatalogue.GetIntentDefinitions());
        var tools = AdminToolCatalogue.CreateRegistry();

        _orchestrator = new IntelligenceOrchestrator(engine, classifier, tools);
        return _orchestrator;
    }

    /// <summary>POST /api/agent/chat</summary>
    public static async ValueTask ChatHandler(BmwContext context)
    {
        using var doc = await JsonDocument.ParseAsync(context.HttpRequest.Body);
        var root = doc.RootElement;
        var message = root.GetProperty("message").GetString()?.Trim() ?? "";

        string reply;
        try
        {
            var orchestrator = GetOrchestrator();
            var response = await orchestrator.ProcessAsync(message, context.RequestAborted)
                .ConfigureAwait(false);
            reply = response.Message;
        }
        catch (Exception ex)
        {
            _logger?.LogError("AgentChat|ProcessAsync", ex);
            reply = "Sorry, an error occurred processing your request.";
        }

        await JsonWriterHelper.WriteResponseAsync(context.Response, new Dictionary<string, object?> { ["reply"] = reply });
    }

    /// <summary>GET /api/agent/metrics — returns BitNet pipeline memory and throughput metrics.</summary>
    public static async ValueTask MetricsHandler(BmwContext context)
    {
        var orchestrator = GetOrCreateOrchestrator();
        var m = orchestrator.GetMetrics();

        if (m is null)
        {
            context.Response.StatusCode = 503;
            await JsonWriterHelper.WriteResponseAsync(context.Response,
                new Dictionary<string, object?> { ["error"] = "Model not loaded" });
            return;
        }

        var payload = new Dictionary<string, object?>
        {
            // ── Weight memory ────────────────────────────────────────────────
            ["original_weight_bytes"]  = m.Value.OriginalWeightBytes,
            ["trimmed_weight_bytes"]   = m.Value.TrimmedWeightBytes,
            ["compression_savings"]    = m.Value.CompressionSavings,
            // ── Model shape ─────────────────────────────────────────────────
            ["total_weights"]          = m.Value.TotalWeights,
            ["zero_weights"]           = m.Value.ZeroWeights,
            ["sparsity"]               = m.Value.Sparsity,
            ["layer_count"]            = m.Value.LayerCount,
            ["embedding_weights"]      = m.Value.EmbeddingWeights,
            // ── Token throughput ─────────────────────────────────────────────
            ["total_tokens_in"]        = m.Value.TotalTokensIn,
            ["total_tokens_out"]       = m.Value.TotalTokensOut,
            ["total_requests"]         = m.Value.TotalRequests,
            ["total_inference_ms"]     = m.Value.TotalInferenceMs,
            // ── Vocabulary ──────────────────────────────────────────────────
            ["original_vocab_size"]    = m.Value.OriginalVocabSize,
            ["pruned_vocab_size"]      = m.Value.PrunedVocabSize,
            // ── Accuracy / pruning ───────────────────────────────────────────
            ["pre_prune_accuracy"]     = m.Value.PrePruneAccuracy,
            ["post_prune_accuracy"]    = m.Value.PostPruneAccuracy,
            ["semantic_test_cases"]    = m.Value.SemanticTestCaseCount,
            // ── Summary ─────────────────────────────────────────────────────
            ["summary"]                = m.Value.Summary,
        };

        await JsonWriterHelper.WriteResponseAsync(context.Response, payload,
            ct: context.RequestAborted);
    }
}
