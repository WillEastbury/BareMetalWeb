using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Core.Interfaces;
using BareMetalWeb.Intelligence;

namespace BareMetalWeb.Host;

/// <summary>
/// Backend handler for the Agent Panel chat interface.
/// Routes all messages through the IntelligenceOrchestrator via the single-stage
/// BitNet SLM pipeline.
///
/// Model lifecycle:
///   • On first access, looks for a domain-trimmed snapshot (model-trimmed.bmwm).
///   • If missing or stale (metadata hash mismatch), loads the full model,
///     trims vocabulary using DataScaffold metadata, and saves the trimmed snapshot.
///   • On metadata change, call <see cref="InvalidateTrimmedModel"/> to force rebuild.
/// </summary>
public static class AgentApiHandlers
{
    private static IBufferedLogger? _logger;
    private static volatile IntelligenceOrchestrator? _orchestrator;
    private static readonly object _orchestratorLock = new();

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
    /// Automatically builds a domain-trimmed model snapshot if one does not
    /// exist or the metadata hash is stale.
    /// </summary>
    public static IntelligenceOrchestrator GetOrCreateOrchestrator()
    {
        // Fast path — volatile read, no lock
        var existing = _orchestrator;
        if (existing is not null)
            return existing;

        // Slow path — double-checked lock to avoid duplicate BitNet engines
        lock (_orchestratorLock)
        {
            if (_orchestrator is not null)
                return _orchestrator;

            var engine = new BitNetEngine();

            // 1. Try to load an existing trimmed model (if metadata hash matches)
            if (!TryLoadTrimmedModel(engine))
            {
                // 2. Try to build a trimmed model from the full snapshot
                if (!TryBuildTrimmedModel(engine))
                {
                    // 3. Fall back to loading any available snapshot as-is
                    IntelligenceExtensions.TryLoadSnapshot(engine);
                }
            }

            var tools = AdminToolCatalogue.CreateRegistry();

            _orchestrator = new IntelligenceOrchestrator(engine, tools);
            return _orchestrator;
        }
    }

    /// <summary>
    /// Invalidate the trimmed model snapshot. Deletes the cached file and
    /// forces the next <see cref="GetOrCreateOrchestrator"/> call to rebuild.
    /// Call this when entity metadata changes (new entities, fields, etc.).
    /// </summary>
    public static void InvalidateTrimmedModel()
    {
        lock (_orchestratorLock)
        {
            _orchestrator = null;

            // Delete trimmed model files from all search paths
            foreach (var fullPath in IntelligenceExtensions.GetSnapshotSearchPaths())
            {
                var trimmedPath = GetTrimmedPath(fullPath);
                try { if (File.Exists(trimmedPath)) File.Delete(trimmedPath); } catch { }
                try { if (File.Exists(trimmedPath + ".hash")) File.Delete(trimmedPath + ".hash"); } catch { }
            }
        }
    }

    // ── Model loading helpers ───────────────────────────────────────────────

    /// <summary>
    /// Try to load an existing domain-trimmed snapshot. Validates the metadata
    /// hash before loading — returns false if the snapshot is missing or stale.
    /// </summary>
    private static bool TryLoadTrimmedModel(BitNetEngine engine)
    {
        var fullPath = FindFullModelPath();
        if (fullPath is null) return false;

        var trimmedPath = GetTrimmedPath(fullPath);
        if (!File.Exists(trimmedPath)) return false;

        // Check metadata hash
        var hashPath = trimmedPath + ".hash";
        if (File.Exists(hashPath))
        {
            var savedHash = File.ReadAllText(hashPath).Trim();
            var currentHash = ComputeMetadataHash();
            if (savedHash != currentHash)
            {
                // Metadata changed — discard stale trimmed model
                try { File.Delete(trimmedPath); } catch { }
                try { File.Delete(hashPath); } catch { }
                return false;
            }
        }

        try
        {
            engine.LoadSnapshotLazy(trimmedPath);
            _logger?.LogInfo($"[Agent] Loaded trimmed model from {trimmedPath} ({engine.TokenTable?.Count ?? 0} tokens)");
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogError("Agent|LoadTrimmed", ex);
            return false;
        }
    }

    /// <summary>
    /// Build a trimmed model from the full snapshot + DataScaffold metadata.
    /// Loads the full model into a temporary engine, trims vocabulary, saves
    /// the trimmed snapshot, then loads it into the real engine.
    /// </summary>
    private static bool TryBuildTrimmedModel(BitNetEngine engine)
    {
        var fullPath = FindFullModelPath();
        if (fullPath is null) return false;

        var trimmedPath = GetTrimmedPath(fullPath);
        _logger?.LogInfo($"[Agent] Building trimmed model from {fullPath}...");

        try
        {
            // Use a temporary engine so we can dispose the full model after saving
            using (var tempEngine = new BitNetEngine())
            {
                tempEngine.LoadSnapshotLazy(fullPath);

                if (tempEngine.LoadedTokenizer is null || tempEngine.TokenTable is null)
                {
                    _logger?.LogInfo("[Agent] Full model has no tokenizer — skipping trim");
                    return false;
                }

                // Build domain vocabulary from DataScaffold metadata
                var pruner = VocabularyPruner.FromDataScaffold();
                var keepIds = pruner.CollectDomainTokenIds(tempEngine.LoadedTokenizer, tempEngine.TokenTable);
                pruner.BuildRemapTableFromIds(tempEngine.LoadedTokenizer.VocabSize, keepIds);

                // Trim and save with Brotli compression
                tempEngine.TrimVocabulary(pruner);
                tempEngine.SaveSnapshot(trimmedPath, compress: true);

                var stats = pruner.GetStats(2560);
                _logger?.LogInfo(
                    $"[Agent] Trimmed model: {stats.OriginalVocabSize:N0} → {stats.PrunedVocabSize:N0} tokens " +
                    $"({stats.CompressionRatio:P1}), saved {stats.BytesSaved / 1024 / 1024:N0} MB");
            }

            // Save metadata hash
            File.WriteAllText(trimmedPath + ".hash", ComputeMetadataHash());

            // Load the trimmed snapshot into the real engine
            engine.LoadSnapshotLazy(trimmedPath);
            return true;
        }
        catch (Exception ex)
        {
            _logger?.LogError("Agent|BuildTrimmed", ex);
            // Clean up partial file
            try { if (File.Exists(trimmedPath)) File.Delete(trimmedPath); } catch { }
            return false;
        }
    }

    /// <summary>Find the first available full model snapshot.</summary>
    private static string? FindFullModelPath()
    {
        foreach (var path in IntelligenceExtensions.GetSnapshotSearchPaths())
        {
            if (File.Exists(path)) return path;
        }
        return null;
    }

    /// <summary>Derive the trimmed model path from the full model path.</summary>
    private static string GetTrimmedPath(string fullPath)
    {
        var dir = Path.GetDirectoryName(fullPath) ?? ".";
        return Path.Combine(dir, "model-trimmed.bmwm");
    }

    /// <summary>
    /// Compute a hash of the current entity metadata. Used to detect when the
    /// trimmed model is stale and needs rebuilding.
    /// </summary>
    private static string ComputeMetadataHash()
    {
        uint hash = 2166136261; // FNV-1a offset basis

        try
        {
            var entities = DataScaffold.Entities;
            if (entities is not null)
            {
                foreach (var e in entities)
                {
                    foreach (char c in e.Name) { hash ^= c; hash *= 16777619; }
                    foreach (char c in e.Slug) { hash ^= c; hash *= 16777619; }
                    if (e.Fields is not null)
                    {
                        foreach (var f in e.Fields)
                        {
                            foreach (char c in f.Name) { hash ^= c; hash *= 16777619; }
                        }
                    }
                }
            }
        }
        catch { }

        return hash.ToString("X8");
    }

    // ── Route handlers ──────────────────────────────────────────────────────

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
            // ── Performance ─────────────────────────────────────────────────
            ["tokens_per_sec"]         = m.Value.TokensPerSec,
            ["kv_cache_hits"]          = m.Value.KvCacheHits,
            ["kv_cache_misses"]        = m.Value.KvCacheMisses,
            ["kv_cache_hit_ratio"]     = m.Value.KvCacheHitRatio,
            ["avg_layer_time_micros"]  = m.Value.AvgLayerTimeMicros,
            // ── Summary ─────────────────────────────────────────────────────
            ["summary"]                = m.Value.Summary,
        };

        await JsonWriterHelper.WriteResponseAsync(context.Response, payload,
            ct: context.RequestAborted);
    }

    /// <summary>GET /ai/generate?prompt=... — simple prompt-based text generation endpoint.</summary>
    public static async ValueTask GenerateHandler(BmwContext context)
    {
        var prompt = context.HttpRequest.Query["prompt"].ToString()?.Trim() ?? "";
        if (string.IsNullOrEmpty(prompt))
        {
            context.Response.StatusCode = 400;
            await JsonWriterHelper.WriteResponseAsync(context.Response,
                new Dictionary<string, object?> { ["error"] = "prompt query parameter is required" });
            return;
        }

        string reply;
        try
        {
            var orchestrator = GetOrCreateOrchestrator();
            var response = await orchestrator.ProcessAsync(prompt, context.RequestAborted)
                .ConfigureAwait(false);
            reply = response.Message;
        }
        catch (Exception ex)
        {
            _logger?.LogError("AgentGenerate|ProcessAsync", ex);
            reply = "Sorry, an error occurred processing your request.";
        }

        await JsonWriterHelper.WriteResponseAsync(context.Response,
            new Dictionary<string, object?> { ["generated"] = reply, ["prompt"] = prompt },
            ct: context.RequestAborted);
    }
}
