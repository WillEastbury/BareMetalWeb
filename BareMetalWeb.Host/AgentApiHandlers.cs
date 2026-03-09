using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Host;

/// <summary>
/// Backend handler for the Agent Panel chat interface.
/// Routes all messages through the two-tier IntelligenceOrchestrator pipeline:
///   Tier 1 — TF-IDF keyword intent classifier (fast path, no model required).
///   Tier 2 — BitNet ternary engine fallback for unrecognised natural-language queries.
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
        if (_orchestrator is not null)
            return _orchestrator;

        var intents = AdminToolCatalogue.GetIntentDefinitions();
        var classifier = new KeywordIntentClassifier(intents);
        var executor = AdminToolCatalogue.CreateRegistry();

        // BitNet engine is not loaded here — the host can call
        // IntelligenceExtensions.CreateIntelligenceRoutes(enableBitNet: true)
        // to warm it up separately.  The orchestrator degrades gracefully when null.
        _orchestrator = new IntelligenceOrchestrator(classifier, executor, engine: null);
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
}
