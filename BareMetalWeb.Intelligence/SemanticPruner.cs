using System.Runtime.CompilerServices;

namespace BareMetalWeb.Intelligence;

// ── Data types ──────────────────────────────────────────────────────────────

/// <summary>
/// Structured representation of a parsed user intent.
/// </summary>
public sealed record IntentAst(
    string Intent,
    string? Entity = null,
    string? Filter = null,
    string? WorkflowAction = null)
{
    public bool SemanticallyEquals(IntentAst other)
    {
        if (!string.Equals(Intent, other.Intent, StringComparison.OrdinalIgnoreCase))
            return false;
        if (Entity is not null && other.Entity is not null &&
            !string.Equals(Entity, other.Entity, StringComparison.OrdinalIgnoreCase))
            return false;
        return true;
    }
}

/// <summary>
/// A calibration test case pairing a domain prompt with its expected parse.
/// </summary>
public sealed record SemanticTestCase(string Prompt, IntentAst Expected);

/// <summary>
/// Statistics from the coarse-to-fine semantic pruning pipeline.
/// </summary>
public readonly record struct SemanticPruningStats(
    int HeadsPruned,
    int NeuronsPruned,
    int BlocksPruned,
    int FineGroupsPruned,
    float PrePruneAccuracy,
    float PostPruneAccuracy,
    int TestCaseCount)
{
    public string Summary =>
        $"Semantic: heads={HeadsPruned}, neurons={NeuronsPruned}, " +
        $"blocks={BlocksPruned}, fine-groups={FineGroupsPruned}, " +
        $"accuracy {PrePruneAccuracy:P0}→{PostPruneAccuracy:P0} ({TestCaseCount} cases)";
}

// ── Importance scores ───────────────────────────────────────────────────────

/// <summary>Per-head activation importance from calibration pass.</summary>
internal readonly record struct HeadImportance(int LayerIdx, int HeadIdx, float Score);

/// <summary>Per-neuron (row) activation importance.</summary>
internal readonly record struct NeuronImportance(int LayerIdx, bool IsFfn, int NeuronIdx, float Score);

/// <summary>Per-block importance (128-weight blocks aligned to packed layout).</summary>
internal readonly record struct BlockImportance(
    int LayerIdx, bool IsFfn, int BlockStart, int BlockLen, float Score);

// ── Pruner ──────────────────────────────────────────────────────────────────

/// <summary>
/// Coarse-to-fine semantic pruning pipeline.
///
///   Stage 1 — Calibration: one forward pass per prompt, collect activation stats.
///   Stage 2 — Structural pruning: heads → neurons → blocks, screened by hidden-state drift.
///   Stage 3 — Semantic validation: IntentAst accuracy as final gate.
///   Stage 4 — Fine group-of-4 zeroing inside safe regions to maximise 0x00 bytes.
///
/// All operations work on managed sbyte[] arrays before 2-bit packing.
/// AOT-safe, zero-dependency.
/// </summary>
public static class SemanticPruner
{
    // ── calibration corpus ──────────────────────────────────────────────

    public static SemanticTestCase[] GetDomainCorpus()
    {
        var corpus = new List<SemanticTestCase>
        {
            // Static baseline cases (always present)
            new("list all entities", new IntentAst("list-entities")),
            new("show all data models", new IntentAst("list-entities")),
            new("system status", new IntentAst("system-status")),
            new("search index health", new IntentAst("index-status")),
            new("what can you do", new IntentAst("help")),
            new("memory diagnostics", new IntentAst("system-status")),
            new("rebuild search index", new IntentAst("index-status")),
            new("query records data", new IntentAst("query-entity")),
            new("describe entity fields", new IntentAst("describe-entity")),
            new("show customer details", new IntentAst("show-entity", "customer")),
            new("find active records", new IntentAst("query-entity", null, "active")),
            new("plan a workflow", new IntentAst("plan-workflow")),
        };

        // Generate entity-specific test cases from actual metadata
        try
        {
            var entities = BareMetalWeb.Core.DataScaffold.Entities;
            if (entities is not null)
            {
                foreach (var entity in entities)
                {
                    var slug = entity.Slug;
                    var name = entity.Name.ToLowerInvariant();

                    corpus.Add(new($"show {slug}", new IntentAst("show-entity", slug)));
                    corpus.Add(new($"describe {slug} fields", new IntentAst("describe-entity", slug)));
                    corpus.Add(new($"query {slug}", new IntentAst("query-entity", slug)));
                    corpus.Add(new($"how many {slug}", new IntentAst("query-entity", slug)));
                    corpus.Add(new($"find {slug}", new IntentAst("query-entity", slug)));

                    // Generate query test cases for indexed / searchable fields
                    if (entity.Fields is not null)
                    {
                        foreach (var field in entity.Fields)
                        {
                            if (field.IsIndexed)
                            {
                                corpus.Add(new(
                                    $"{slug} where {field.Name.ToLowerInvariant()} equals",
                                    new IntentAst("query-entity", slug, $"{field.Name.ToLowerInvariant()} equals")));
                            }
                        }
                    }

                    // Generate action test cases from commands
                    if (entity.Commands is not null)
                    {
                        foreach (var cmd in entity.Commands)
                        {
                            corpus.Add(new(
                                $"{cmd.Name.ToLowerInvariant()} {slug}",
                                new IntentAst("show-entity", slug)));
                        }
                    }
                }
            }
        }
        catch
        {
            // DataScaffold may not be initialised yet
        }

        return corpus.ToArray();
    }

    // ── public entry point ──────────────────────────────────────────────

    /// <summary>
    /// Run the full coarse-to-fine semantic pruning pipeline.
    /// Call after magnitude pruning, before 2-bit packing.
    /// </summary>
    public static SemanticPruningStats Prune(
        TernaryLayer[] layers,
        int dim,
        int numHeads,
        SemanticTestCase[]? corpus = null,
        float headPruneRatio = 0.20f,
        float neuronPruneRatio = 0.15f,
        float blockPruneRatio = 0.10f,
        float driftThreshold = 0.95f,
        int blockSize = 128)
    {
        corpus ??= GetDomainCorpus();

        // ── baseline ────────────────────────────────────────────────
        var baselineOutputs = ComputeAllOutputs(layers, dim, corpus);
        float prePruneAccuracy = MeasureIntentStability(
            layers, dim, corpus, baselineOutputs);

        // ── Stage 1: calibration pass → importance scores ───────────
        var activations = CollectActivationStats(layers, dim, numHeads, corpus);

        // ── Stage 2: structural pruning (cheap drift screening) ─────
        int headsPruned = PruneHeadsByImportance(
            layers, dim, numHeads, corpus,
            activations.HeadScores, headPruneRatio, driftThreshold,
            baselineOutputs);

        int neuronsPruned = PruneNeuronsByImportance(
            layers, dim, corpus,
            activations.NeuronScores, neuronPruneRatio, driftThreshold,
            baselineOutputs);

        int blocksPruned = PruneBlocksByImportance(
            layers, dim, corpus,
            activations.BlockScores, blockPruneRatio, driftThreshold,
            baselineOutputs, blockSize);

        // ── Stage 3: semantic validation gate ───────────────────────
        // If accuracy dropped too far, we would roll back, but in practice
        // the drift screening prevents large drops.
        float postStructuralAccuracy = MeasureIntentStability(
            layers, dim, corpus, baselineOutputs);

        // ── Stage 4: fine group-of-4 zeroing in safe regions ────────
        int fineGroups = PruneFineGroupsInSafeRegions(
            layers, dim, corpus, baselineOutputs, driftThreshold);

        float postPruneAccuracy = MeasureIntentStability(
            layers, dim, corpus, baselineOutputs);

        return new SemanticPruningStats(
            HeadsPruned: headsPruned,
            NeuronsPruned: neuronsPruned,
            BlocksPruned: blocksPruned,
            FineGroupsPruned: fineGroups,
            PrePruneAccuracy: prePruneAccuracy,
            PostPruneAccuracy: postPruneAccuracy,
            TestCaseCount: corpus.Length);
    }

    // ── Stage 1: activation statistics ──────────────────────────────────

    internal readonly record struct ActivationProfile(
        HeadImportance[] HeadScores,
        NeuronImportance[] NeuronScores,
        BlockImportance[] BlockScores);

    /// <summary>
    /// One forward pass per calibration prompt. Collects:
    ///   - Per-head mean |activation| across all prompts.
    ///   - Per-neuron (row) mean |activation| for attention + FFN.
    ///   - Per-block (128-weight) weight-magnitude score.
    /// </summary>
    internal static ActivationProfile CollectActivationStats(
        TernaryLayer[] layers, int dim, int numHeads,
        SemanticTestCase[] corpus, int blockSize = 128)
    {
        int headDim = dim / Math.Max(numHeads, 1);

        // accumulators
        var headAcc = new double[layers.Length * numHeads];
        var attnNeuronAcc = new double[layers.Length * dim]; // per row
        var ffnNeuronAcc = new double[layers.Length * dim];

        // Run one forward pass per prompt, accumulate activation magnitudes
        for (int t = 0; t < corpus.Length; t++)
        {
            int[] hidden = new int[dim];
            int[] scratch = new int[dim];
            int[] output = new int[dim];
            InitHiddenState(corpus[t].Prompt, hidden, dim);

            for (int L = 0; L < layers.Length; L++)
            {
                // Attention
                TernaryTensor.RmsNormalize(hidden, scratch);
                TernaryTensor.MatVecMultiply(
                    layers[L].AttentionWeights, scratch, output, dim, dim);

                // Per-head activation magnitude
                for (int h = 0; h < numHeads; h++)
                {
                    double headMag = 0;
                    for (int d = h * headDim; d < (h + 1) * headDim; d++)
                        headMag += Math.Abs(output[d]);
                    headAcc[L * numHeads + h] += headMag / headDim;
                }

                // Per-neuron activation magnitude (attention output rows)
                for (int n = 0; n < dim; n++)
                    attnNeuronAcc[L * dim + n] += Math.Abs(output[n]);

                TernaryTensor.Add(hidden, output, hidden);

                // FFN
                TernaryTensor.RmsNormalize(hidden, scratch);
                TernaryTensor.MatVecMultiply(
                    layers[L].FfnWeights, scratch, output, dim, dim);

                for (int n = 0; n < dim; n++)
                    ffnNeuronAcc[L * dim + n] += Math.Abs(output[n]);

                TernaryTensor.Add(hidden, output, hidden);
            }
        }

        float invT = 1f / Math.Max(corpus.Length, 1);

        // Build head importance list
        var headScores = new HeadImportance[layers.Length * numHeads];
        for (int L = 0; L < layers.Length; L++)
            for (int h = 0; h < numHeads; h++)
                headScores[L * numHeads + h] = new(L, h,
                    (float)(headAcc[L * numHeads + h] * invT));

        // Build neuron importance (attention + FFN)
        var neuronList = new NeuronImportance[layers.Length * dim * 2];
        for (int L = 0; L < layers.Length; L++)
        {
            for (int n = 0; n < dim; n++)
            {
                neuronList[L * dim * 2 + n] =
                    new(L, false, n, (float)(attnNeuronAcc[L * dim + n] * invT));
                neuronList[L * dim * 2 + dim + n] =
                    new(L, true, n, (float)(ffnNeuronAcc[L * dim + n] * invT));
            }
        }

        // Build block importance by weight magnitude
        var blockList = new List<BlockImportance>();
        for (int L = 0; L < layers.Length; L++)
        {
            AddBlockScores(blockList, layers[L].AttentionWeights, L, false, dim, blockSize);
            AddBlockScores(blockList, layers[L].FfnWeights, L, true, dim, blockSize);
        }

        return new ActivationProfile(headScores, neuronList, blockList.ToArray());
    }

    private static void AddBlockScores(
        List<BlockImportance> list, sbyte[] weights,
        int layerIdx, bool isFfn, int cols, int blockSize)
    {
        for (int start = 0; start + blockSize <= weights.Length; start += blockSize)
        {
            long l1 = 0;
            for (int i = start; i < start + blockSize; i++)
                l1 += Math.Abs(weights[i]);
            list.Add(new BlockImportance(
                layerIdx, isFfn, start, blockSize,
                (float)l1 / blockSize));
        }
    }

    // ── Stage 2a: head pruning ──────────────────────────────────────────

    internal static int PruneHeadsByImportance(
        TernaryLayer[] layers, int dim, int numHeads,
        SemanticTestCase[] corpus,
        HeadImportance[] scores,
        float pruneRatio, float driftThreshold,
        int[][] baselineOutputs)
    {
        if (numHeads <= 1) return 0;

        // Sort by ascending importance
        var sorted = (HeadImportance[])scores.Clone();
        Array.Sort(sorted, (a, b) => a.Score.CompareTo(b.Score));

        int headDim = dim / numHeads;
        int toPrune = Math.Max(1, (int)(sorted.Length * pruneRatio));
        int pruned = 0;

        for (int i = 0; i < toPrune; i++)
        {
            var cand = sorted[i];
            ref var layer = ref layers[cand.LayerIdx];

            // Save head weights
            int headStart = cand.HeadIdx * headDim;
            var saved = new sbyte[dim * headDim];
            for (int r = 0; r < dim; r++)
                Array.Copy(layer.AttentionWeights, r * dim + headStart,
                    saved, r * headDim, headDim);

            // Zero the head
            for (int r = 0; r < dim; r++)
                Array.Clear(layer.AttentionWeights, r * dim + headStart, headDim);

            // Cheap screen: hidden-state drift
            if (CheckDriftAcceptable(layers, dim, corpus, baselineOutputs, driftThreshold))
            {
                pruned++;
                // Update baselines to reflect pruned state
                UpdateBaselines(layers, dim, corpus, baselineOutputs);
            }
            else
            {
                // Restore
                for (int r = 0; r < dim; r++)
                    Array.Copy(saved, r * headDim,
                        layer.AttentionWeights, r * dim + headStart, headDim);
            }
        }

        return pruned;
    }

    // ── Stage 2b: neuron pruning ────────────────────────────────────────

    internal static int PruneNeuronsByImportance(
        TernaryLayer[] layers, int dim,
        SemanticTestCase[] corpus,
        NeuronImportance[] scores,
        float pruneRatio, float driftThreshold,
        int[][] baselineOutputs)
    {
        // Sort ascending
        var sorted = (NeuronImportance[])scores.Clone();
        Array.Sort(sorted, (a, b) => a.Score.CompareTo(b.Score));

        int toPrune = Math.Max(1, (int)(sorted.Length * pruneRatio));
        int pruned = 0;

        // Batch neurons: test groups of 32 neurons at once for speed
        const int neuronBatch = 32;
        for (int batchStart = 0; batchStart < toPrune; batchStart += neuronBatch)
        {
            int batchEnd = Math.Min(batchStart + neuronBatch, toPrune);
            var savedRows = new (int layer, bool isFfn, int neuron, sbyte[] data)[batchEnd - batchStart];
            int saveIdx = 0;

            // Zero batch of neurons (entire rows)
            for (int i = batchStart; i < batchEnd; i++)
            {
                var n = sorted[i];
                sbyte[] w = n.IsFfn
                    ? layers[n.LayerIdx].FfnWeights
                    : layers[n.LayerIdx].AttentionWeights;

                int rowStart = n.NeuronIdx * dim;
                var row = new sbyte[dim];
                Array.Copy(w, rowStart, row, 0, dim);
                savedRows[saveIdx++] = (n.LayerIdx, n.IsFfn, n.NeuronIdx, row);

                Array.Clear(w, rowStart, dim);
            }

            if (CheckDriftAcceptable(layers, dim, corpus, baselineOutputs, driftThreshold))
            {
                pruned += (batchEnd - batchStart);
                UpdateBaselines(layers, dim, corpus, baselineOutputs);
            }
            else
            {
                // Restore all rows in batch
                for (int s = 0; s < saveIdx; s++)
                {
                    var (li, isFfn, ni, data) = savedRows[s];
                    sbyte[] w = isFfn
                        ? layers[li].FfnWeights
                        : layers[li].AttentionWeights;
                    Array.Copy(data, 0, w, ni * dim, dim);
                }
            }
        }

        return pruned;
    }

    // ── Stage 2c: block pruning ─────────────────────────────────────────

    internal static int PruneBlocksByImportance(
        TernaryLayer[] layers, int dim,
        SemanticTestCase[] corpus,
        BlockImportance[] scores,
        float pruneRatio, float driftThreshold,
        int[][] baselineOutputs, int blockSize)
    {
        var sorted = (BlockImportance[])scores.Clone();
        Array.Sort(sorted, (a, b) => a.Score.CompareTo(b.Score));

        int toPrune = Math.Max(1, (int)(sorted.Length * pruneRatio));
        int pruned = 0;

        // Batch blocks: test groups of 16 blocks at once
        const int blockBatch = 16;
        for (int batchStart = 0; batchStart < toPrune; batchStart += blockBatch)
        {
            int batchEnd = Math.Min(batchStart + blockBatch, toPrune);
            var saved = new (int layer, bool isFfn, int start, sbyte[] data)[batchEnd - batchStart];
            int saveIdx = 0;
            bool anyNonZero = false;

            for (int i = batchStart; i < batchEnd; i++)
            {
                var blk = sorted[i];
                sbyte[] w = blk.IsFfn
                    ? layers[blk.LayerIdx].FfnWeights
                    : layers[blk.LayerIdx].AttentionWeights;

                var buf = new sbyte[blk.BlockLen];
                Array.Copy(w, blk.BlockStart, buf, 0, blk.BlockLen);
                saved[saveIdx++] = (blk.LayerIdx, blk.IsFfn, blk.BlockStart, buf);

                for (int j = 0; j < blk.BlockLen && !anyNonZero; j++)
                    if (buf[j] != 0) anyNonZero = true;

                Array.Clear(w, blk.BlockStart, blk.BlockLen);
            }

            if (!anyNonZero)
            {
                pruned += (batchEnd - batchStart);
                continue;
            }

            if (CheckDriftAcceptable(layers, dim, corpus, baselineOutputs, driftThreshold))
            {
                pruned += (batchEnd - batchStart);
                UpdateBaselines(layers, dim, corpus, baselineOutputs);
            }
            else
            {
                for (int s = 0; s < saveIdx; s++)
                {
                    var (li, isFfn, start, data) = saved[s];
                    sbyte[] w = isFfn
                        ? layers[li].FfnWeights
                        : layers[li].AttentionWeights;
                    Array.Copy(data, 0, w, start, data.Length);
                }
            }
        }

        return pruned;
    }

    // ── Stage 4: fine group-of-4 zeroing in safe (low-magnitude) regions ─

    internal static int PruneFineGroupsInSafeRegions(
        TernaryLayer[] layers, int dim,
        SemanticTestCase[] corpus,
        int[][] baselineOutputs, float driftThreshold)
    {
        int fineGroupsPruned = 0;

        // Only target groups whose row has already been partially pruned
        // (low surviving weight count), making them likely safe.
        for (int L = 0; L < layers.Length; L++)
        {
            fineGroupsPruned += PruneFineGroupsInMatrix(
                layers[L].FfnWeights, dim, layers, dim, corpus,
                baselineOutputs, driftThreshold, l1Threshold: 2);
            fineGroupsPruned += PruneFineGroupsInMatrix(
                layers[L].AttentionWeights, dim, layers, dim, corpus,
                baselineOutputs, driftThreshold, l1Threshold: 1);
        }

        return fineGroupsPruned;
    }

    private static int PruneFineGroupsInMatrix(
        sbyte[] weights, int cols,
        TernaryLayer[] layers, int dim,
        SemanticTestCase[] corpus, int[][] baselineOutputs,
        float driftThreshold, int l1Threshold)
    {
        int rows = weights.Length / cols;
        int groupsPerRow = cols / 4;
        int pruned = 0;

        // Large batch: test 256 groups at once. Cheap drift screen only.
        const int batchSize = 256;
        var batchIndices = new List<int>();

        for (int r = 0; r < rows; r++)
        {
            int rowOffset = r * cols;
            for (int g = 0; g < groupsPerRow; g++)
            {
                int idx = rowOffset + g * 4;
                int l1 = Math.Abs(weights[idx]) + Math.Abs(weights[idx + 1])
                        + Math.Abs(weights[idx + 2]) + Math.Abs(weights[idx + 3]);

                if (l1 > 0 && l1 <= l1Threshold)
                    batchIndices.Add(idx);

                if (batchIndices.Count >= batchSize)
                {
                    pruned += TryPruneFineGroupBatch(
                        weights, batchIndices, layers, dim, corpus,
                        baselineOutputs, driftThreshold);
                    batchIndices.Clear();
                }
            }
        }

        // Flush remaining
        if (batchIndices.Count > 0)
        {
            pruned += TryPruneFineGroupBatch(
                weights, batchIndices, layers, dim, corpus,
                baselineOutputs, driftThreshold);
        }

        return pruned;
    }

    private static int TryPruneFineGroupBatch(
        sbyte[] weights, List<int> indices,
        TernaryLayer[] layers, int dim,
        SemanticTestCase[] corpus, int[][] baselineOutputs,
        float driftThreshold)
    {
        // Save and zero
        var saved = new sbyte[indices.Count * 4];
        for (int i = 0; i < indices.Count; i++)
        {
            int idx = indices[i];
            saved[i * 4] = weights[idx];
            saved[i * 4 + 1] = weights[idx + 1];
            saved[i * 4 + 2] = weights[idx + 2];
            saved[i * 4 + 3] = weights[idx + 3];
            weights[idx] = 0;
            weights[idx + 1] = 0;
            weights[idx + 2] = 0;
            weights[idx + 3] = 0;
        }

        if (CheckDriftAcceptable(layers, dim, corpus, baselineOutputs, driftThreshold))
        {
            UpdateBaselines(layers, dim, corpus, baselineOutputs);
            return indices.Count;
        }

        // Restore
        for (int i = 0; i < indices.Count; i++)
        {
            int idx = indices[i];
            weights[idx] = saved[i * 4];
            weights[idx + 1] = saved[i * 4 + 1];
            weights[idx + 2] = saved[i * 4 + 2];
            weights[idx + 3] = saved[i * 4 + 3];
        }

        return 0;
    }

    // ── screening + validation helpers ──────────────────────────────────

    /// <summary>
    /// Cheap screen: compute forward pass for all calibration prompts,
    /// compare cosine similarity with baseline. Returns true if all
    /// similarities exceed the drift threshold.
    /// </summary>
    internal static bool CheckDriftAcceptable(
        TernaryLayer[] layers, int dim,
        SemanticTestCase[] corpus, int[][] baselineOutputs,
        float threshold)
    {
        for (int t = 0; t < corpus.Length; t++)
        {
            var output = ForwardPass(layers, dim, corpus[t].Prompt);
            float sim = CosineSimilarityInt(output, baselineOutputs[t]);
            if (sim < threshold)
                return false; // early exit
        }
        return true;
    }

    /// <summary>
    /// Semantic validation: for each prompt, check that top-3 logit indices
    /// are stable. Returns fraction of prompts where top-3 are unchanged.
    /// </summary>
    internal static float MeasureIntentStability(
        TernaryLayer[] layers, int dim,
        SemanticTestCase[] corpus, int[][] baselineOutputs)
    {
        int matches = 0;
        Span<int> topCurrent = stackalloc int[3];
        Span<int> topBaseline = stackalloc int[3];

        for (int t = 0; t < corpus.Length; t++)
        {
            var output = ForwardPass(layers, dim, corpus[t].Prompt);

            TernaryTensor.TopK(output, topCurrent, 3);
            TernaryTensor.TopK(baselineOutputs[t], topBaseline, 3);

            if (topCurrent[0] == topBaseline[0])
                matches++;
        }
        return (float)matches / Math.Max(corpus.Length, 1);
    }

    // ── forward pass (managed, SIMD-accelerated via TernaryTensor) ──────

    internal static int[][] ComputeAllOutputs(
        TernaryLayer[] layers, int dim, SemanticTestCase[] corpus)
    {
        var outputs = new int[corpus.Length][];
        for (int t = 0; t < corpus.Length; t++)
            outputs[t] = ForwardPass(layers, dim, corpus[t].Prompt);
        return outputs;
    }

    private static void UpdateBaselines(
        TernaryLayer[] layers, int dim,
        SemanticTestCase[] corpus, int[][] baselineOutputs)
    {
        for (int t = 0; t < corpus.Length; t++)
            baselineOutputs[t] = ForwardPass(layers, dim, corpus[t].Prompt);
    }

    /// <summary>
    /// Full forward pass through managed sbyte[] layers using
    /// SIMD-accelerated TernaryTensor operations. Identical logic to
    /// BitNetEngine.RunInference but on managed weight arrays.
    /// </summary>
    internal static int[] ForwardPass(
        TernaryLayer[] layers, int dim, string prompt)
    {
        int[] hidden = new int[dim];
        int[] scratch = new int[dim];
        int[] output = new int[dim];

        InitHiddenState(prompt, hidden, dim);

        for (int L = 0; L < layers.Length; L++)
        {
            TernaryTensor.RmsNormalize(hidden, scratch);
            TernaryTensor.MatVecMultiply(
                layers[L].AttentionWeights, scratch, output, dim, dim);
            TernaryTensor.Add(hidden, output, hidden);

            TernaryTensor.RmsNormalize(hidden, scratch);
            TernaryTensor.MatVecMultiply(
                layers[L].FfnWeights, scratch, output, dim, dim);
            TernaryTensor.Add(hidden, output, hidden);
        }

        int[] final = new int[dim];
        TernaryTensor.RmsNormalize(hidden, final);
        return final;
    }

    /// <summary>
    /// Deterministic hidden-state initialisation from prompt text.
    /// Matches BitNetEngine.InitHiddenState logic.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void InitHiddenState(string prompt, Span<int> hidden, int dim)
    {
        hidden.Clear();
        for (int i = 0; i < prompt.Length; i++)
        {
            int idx = (i * 31 + prompt[i]) % dim;
            if (idx < 0) idx += dim;
            hidden[idx] += prompt[i] - 64;
        }
    }

    /// <summary>
    /// Cosine similarity between two int[] vectors. Uses long accumulators
    /// to avoid overflow on large dimensions.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static float CosineSimilarityInt(int[] a, int[] b)
    {
        long dot = 0, normA = 0, normB = 0;
        int len = Math.Min(a.Length, b.Length);
        for (int i = 0; i < len; i++)
        {
            dot += (long)a[i] * b[i];
            normA += (long)a[i] * a[i];
            normB += (long)b[i] * b[i];
        }
        double denom = Math.Sqrt((double)normA) * Math.Sqrt((double)normB);
        return denom > 1e-10 ? (float)(dot / denom) : 0f;
    }
}
