using System.Diagnostics;
using BareMetalWeb.Intelligence;
using BareMetalWeb.Intelligence.Interfaces;

const string Banner = """

    ╔══════════════════════════════════════════════════════════╗
    ║  BareMetalWeb Intelligence CLI                          ║
    ║  Intent Classifier + BitNet b1.58 Ternary Engine        ║
    ║  2-bit packed · native memory · zero-skip sparse        ║
    ╚══════════════════════════════════════════════════════════╝

    """;

Console.ForegroundColor = ConsoleColor.Cyan;
Console.Write(Banner);
Console.ResetColor();

// --- Load engine from snapshot (no random-weight fallback) ---
Console.Write("  Loading engine... ");
var sw = Stopwatch.StartNew();

// Config is a placeholder used to size pre-allocated inference buffers before
// a snapshot is loaded.  Once LoadSnapshot() runs, the engine rebuilds its
// internal buffers from the snapshot's actual dimensions.
// MaxSeqLen=512 matches HuggingFaceImporter.MaxSeqLenCap — keeping both in sync
// avoids KV-cache resizing on the first snapshot load.
var config = new BitNetModelConfig(
    HiddenDim: 2048,
    NumLayers: 24,
    NumHeads: 16,
    VocabSize: 32000,
    MaxSeqLen: HuggingFaceImporter.MaxSeqLenCap);

var executor = AdminToolCatalogue.CreateRegistry();
using var engine = new BitNetEngine(config);

bool modelLoaded = IntelligenceExtensions.TryLoadSnapshot(engine, maxSeqLenOverride: 128);

GC.Collect(2, GCCollectionMode.Aggressive, true, true);

var orchestrator = new IntelligenceOrchestrator(engine);
sw.Stop();

if (modelLoaded)
{
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"ready ({sw.ElapsedMilliseconds}ms)");
}
else
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("started (no model — intent classifier active, BitNet unavailable)");
    Console.ResetColor();
    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.WriteLine();
    Console.WriteLine("  No .bmwm snapshot found. To import a model:");
    Console.WriteLine("  1. Download microsoft/BitNet-b1.58-2B-4T from HuggingFace");
    Console.WriteLine("  2. Run:  import <path-to-hf-model-dir>");
    Console.WriteLine("  3. Then: load model.bmwm");
    Console.WriteLine();
    Console.WriteLine("  Search paths:");
    foreach (var p in IntelligenceExtensions.GetSnapshotSearchPaths())
        Console.WriteLine($"    {p}");
}
Console.ResetColor();
Console.WriteLine();

// --- Print stats (only if model loaded) ---
if (modelLoaded) PrintStats(engine, config);

// --- REPL ---
Console.WriteLine("  Type a query, or use a command below:");
Console.WriteLine();
PrintHelp();

while (true)
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.Write("  bmw> ");
    Console.ResetColor();

    var input = Console.ReadLine();
    if (input is null) break; // EOF
    input = input.Trim();
    if (input.Length == 0) continue;

    switch (input.ToLowerInvariant())
    {
        case "exit" or "quit" or "q":
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("  Bye.");
            Console.ResetColor();
            return;

        case "help" or "?":
            PrintHelp();
            continue;

        case "stats" or "mem":
            PrintStats(engine, config);
            continue;

        case "gc":
            GC.Collect(2, GCCollectionMode.Aggressive, true, true);
            PrintMemory();
            continue;

        case "tools":
            PrintTools(executor);
            continue;

        case "layers":
            PrintLayerStats(engine);
            continue;

        case "semantic":
            RunSemanticComparison(config);
            continue;

        case "bench":
            RunBenchmark(orchestrator);
            continue;

        case "compare":
            RunPruneComparison(config);
            continue;

        case "trim":
            TrimAndSave(engine);
            continue;

        default:
            if (input.StartsWith("import ", StringComparison.OrdinalIgnoreCase))
            {
                var newOrch = await ImportHuggingFaceModel(engine, input[7..].Trim(), config);
                if (newOrch is not null) orchestrator = newOrch;
                modelLoaded = engine.IsLoaded;
                continue;
            }
            if (input.StartsWith("save ", StringComparison.OrdinalIgnoreCase))
            {
                SaveSnapshot(engine, input[5..].Trim());
                continue;
            }
            if (input.StartsWith("load ", StringComparison.OrdinalIgnoreCase)
                && !input.StartsWith("loadlazy ", StringComparison.OrdinalIgnoreCase))
            {
                LoadSnapshot(engine, input[5..].Trim(), config, ref orchestrator);
                continue;
            }
            if (input.StartsWith("loadlazy ", StringComparison.OrdinalIgnoreCase))
            {
                LoadSnapshotLazy(engine, input[9..].Trim(), config, ref orchestrator);
                continue;
            }
            await RunQuery(orchestrator, input);
            continue;
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

static void PrintHelp()
{
    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.WriteLine("  ┌─────────────────────────────────────────────────┐");
    Console.WriteLine("  │  Commands:                                      │");
    Console.WriteLine("  │    help, ?          — Show this help            │");
    Console.WriteLine("  │    stats, mem       — Show model & memory stats │");
    Console.WriteLine("  │    gc               — Force GC and show memory  │");
    Console.WriteLine("  │    tools            — List available admin tools │");
    Console.WriteLine("  │    layers           — Per-layer sparsity stats  │");
    Console.WriteLine("  │    semantic         — Semantic pruning compare  │");
    Console.WriteLine("  │    bench            — Run inference benchmark   │");
    Console.WriteLine("  │    compare          — Compare pruning levels    │");
    Console.WriteLine("  │    import <hf-dir>  — Import HF model → .bmwm  │");
    Console.WriteLine("  │      [output.bmwm]    (optional output path)    │");
    Console.WriteLine("  │    save <path>      — Save snapshot (.bmwm)     │");
    Console.WriteLine("  │    load <path>      — Load snapshot (.bmwm)     │");
    Console.WriteLine("  │    loadlazy <path>  — Lazy mmap load (zero-copy)│");
    Console.WriteLine("  │    exit, quit       — Exit                      │");
    Console.WriteLine("  │                                                 │");
    Console.WriteLine("  │  Or type a natural language query:              │");
    Console.WriteLine("  │    > list entities                              │");
    Console.WriteLine("  │    > system status                              │");
    Console.WriteLine("  │    > describe user                              │");
    Console.WriteLine("  └─────────────────────────────────────────────────┘");
    Console.ResetColor();
    Console.WriteLine();
}

static void PrintStats(BitNetEngine engine, BitNetModelConfig config)
{
    var proc = Process.GetCurrentProcess();
    Console.ForegroundColor = ConsoleColor.DarkCyan;
    Console.WriteLine("  ── Memory & Model Stats ──────────────────────────");
    Console.ResetColor();
    Console.WriteLine($"    Working set:       {proc.WorkingSet64 / (1024 * 1024),6} MB");
    Console.WriteLine($"    GC heap:           {GC.GetTotalMemory(false) / (1024 * 1024),6} MB");
    Console.WriteLine($"    Native alloc:      {engine.NativeBytesAllocated / (1024 * 1024),6} MB");
    Console.WriteLine($"    GC Gen0/1/2:       {GC.CollectionCount(0)}/{GC.CollectionCount(1)}/{GC.CollectionCount(2)}");
    Console.WriteLine();

    if (engine.VocabPruneStats is { } vs)
    {
        Console.WriteLine($"    Vocab original:    {vs.OriginalVocabSize,6} tokens");
        Console.WriteLine($"    Vocab pruned:      {vs.PrunedVocabSize,6} tokens");
        Console.WriteLine($"    Vocab compression: {vs.CompressionRatio,9:P2}");
        Console.WriteLine($"    Embedding savings: {vs.BytesSaved / (1024 * 1024),6} MB");
    }

    if (engine.ModelStats is { } ms)
    {
        Console.WriteLine($"    Layers:            {ms.LayerCount,6}");
        Console.WriteLine($"    Total weights:     {ms.TotalWeights,12:N0}");
        Console.WriteLine($"    Sparsity:          {ms.Sparsity,9:P1}");
        Console.WriteLine($"    Was (sbyte):       {ms.StoredBytes / (1024 * 1024),6} MB");
        Console.WriteLine($"    Now (2-bit native):{engine.NativeBytesAllocated / (1024 * 1024),6} MB");
        Console.WriteLine($"    Compression:       {ms.CompressionSavings,9:P0} smaller");
    }

    if (engine.GroupPruneInfo is { } gp)
    {
        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.WriteLine("  ── Group-of-4 Pruning ────────────────────────────");
        Console.ResetColor();
        Console.WriteLine($"    Attn groups zeroed:  {gp.AttnGroupsZeroed,12:N0} / {gp.TotalAttnGroups:N0} ({gp.AttnGroupSparsity:P0} @ L1<={gp.AttnThreshold})");
        Console.WriteLine($"    FFN groups zeroed:   {gp.FfnGroupsZeroed,12:N0} / {gp.TotalFfnGroups:N0} ({gp.FfnGroupSparsity:P0} @ L1<={gp.FfnThreshold})");
        Console.WriteLine($"    Total weights zeroed:{gp.TotalWeightsZeroed,12:N0}");
    }

    if (engine.SemanticPruneInfo is { } sp)
    {
        Console.ForegroundColor = ConsoleColor.DarkCyan;
        Console.WriteLine("  ── Semantic Pruning (coarse→fine) ────────────────");
        Console.ResetColor();
        Console.WriteLine($"    Heads pruned:       {sp.HeadsPruned,6}");
        Console.WriteLine($"    Neurons pruned:     {sp.NeuronsPruned,6}");
        Console.WriteLine($"    Blocks pruned:      {sp.BlocksPruned,6}");
        Console.WriteLine($"    Fine groups pruned: {sp.FineGroupsPruned,6}");
        Console.WriteLine($"    Accuracy:           {sp.PrePruneAccuracy,5:P0} → {sp.PostPruneAccuracy:P0} ({sp.TestCaseCount} cases)");
    }

    Console.WriteLine();
}

static void PrintMemory()
{
    var proc = Process.GetCurrentProcess();
    Console.WriteLine($"    Working set: {proc.WorkingSet64 / (1024 * 1024)} MB, GC heap: {GC.GetTotalMemory(false) / (1024 * 1024)} MB");
    Console.WriteLine();
}

static void PrintTools(IToolExecutor executor)
{
    var tools = executor.GetTools();
    Console.ForegroundColor = ConsoleColor.DarkCyan;
    Console.WriteLine("  ── Registered Tools ──────────────────────────────");
    Console.ResetColor();
    foreach (var t in tools)
    {
        Console.Write("    • ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write(t.Name.PadRight(20));
        Console.ResetColor();
        Console.WriteLine(t.Description);
    }
    Console.WriteLine();
}

static async Task RunQuery(IntelligenceOrchestrator orch, string input)
{
    var sw = Stopwatch.StartNew();
    var response = await orch.ProcessAsync(input);
    sw.Stop();

    Console.ForegroundColor = ConsoleColor.DarkGray;
    Console.WriteLine($"  [{response.ResolvedIntent} @ {response.Confidence:P0}, {sw.ElapsedMilliseconds}ms]");
    Console.ResetColor();

    // Print response with indent
    foreach (var line in response.Message.Split('\n'))
    {
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write("  │ ");
        Console.ResetColor();
        Console.WriteLine(line.TrimEnd('\r'));
    }
    Console.WriteLine();
}

static void PrintLayerStats(BitNetEngine engine)
{
    if (engine.LayerStats is not { } stats || stats.Count == 0)
    {
        Console.WriteLine("    No layer stats available.");
        Console.WriteLine();
        return;
    }

    Console.ForegroundColor = ConsoleColor.DarkCyan;
    Console.WriteLine("  ── Per-Layer Sparsity ────────────────────────────");
    Console.ResetColor();

    Console.WriteLine("    {0,-12} {1,14} {2,14} {3,12} {4,12}",
        "Layer", "Attn Weights", "Attn 0-bytes", "FFN Weights", "FFN 0-bytes");
    Console.WriteLine("    {0,-12} {1,14} {2,14} {3,12} {4,12}",
        "─────", "────────────", "────────────", "───────────", "───────────");

    for (int i = 0; i < stats.Count; i++)
    {
        var (attn, ffn) = stats[i];
        Console.Write($"    Layer {i,-5}");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($" {attn.LogicalWeights,12:N0}  ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($" {attn.ZeroByteRatio,11:P0}  ");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($" {ffn.LogicalWeights,10:N0}  ");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($" {ffn.ZeroByteRatio,10:P0}");
        Console.ResetColor();
        Console.WriteLine();
    }

    Console.WriteLine();
}

static void RunBenchmark(IntelligenceOrchestrator orch)
{
    Console.Write("  Running 50 inferences... ");

    // Warmup
    for (int i = 0; i < 5; i++)
        orch.ProcessAsync("warmup query").AsTask().GetAwaiter().GetResult();

    string[] queries = [
        "list entities",
        "system status",
        "help what can you do",
        "describe user fields",
        "query records data",
        "index statistics rebuild",
        "show all data models",
        "what is xyzzy plugh random",
        "search index health",
        "system memory diagnostics"
    ];

    var sw = Stopwatch.StartNew();
    int runs = 50;
    for (int i = 0; i < runs; i++)
        orch.ProcessAsync(queries[i % queries.Length]).AsTask().GetAwaiter().GetResult();
    sw.Stop();

    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"{runs} queries in {sw.ElapsedMilliseconds}ms ({(double)sw.ElapsedMilliseconds / runs:F1}ms avg)");
    Console.ResetColor();
    Console.WriteLine();
}

static void RunPruneComparison(BitNetModelConfig config)
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("  Pruning comparison not yet available for v3 models.");
    Console.ResetColor();
}

static void RunSemanticComparison(BitNetModelConfig config)
{
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("  Semantic pruning comparison not yet available for v3 models.");
    Console.ResetColor();
}

static void SaveSnapshot(BitNetEngine engine, string path)
{
    if (string.IsNullOrWhiteSpace(path))
    {
        path = "model.bmwm";
        Console.WriteLine($"    Using default path: {path}");
    }

    try
    {
        var sw = Stopwatch.StartNew();
        engine.SaveSnapshot(path);
        sw.Stop();

        var fi = new FileInfo(path);
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"  ✓ Saved ");
        Console.ResetColor();
        Console.WriteLine($"{fi.Length / (1024 * 1024)} MB to {fi.FullName} ({sw.ElapsedMilliseconds}ms)");
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  ✗ Save failed: {ex.Message}");
        Console.ResetColor();
    }
    Console.WriteLine();
}

static void LoadSnapshot(
    BitNetEngine engine, string path,
    BitNetModelConfig config,
    ref IntelligenceOrchestrator orchestrator)
{
    if (string.IsNullOrWhiteSpace(path))
    {
        path = "model.bmwm";
        Console.WriteLine($"    Using default path: {path}");
    }

    if (!File.Exists(path))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  ✗ File not found: {path}");
        Console.ResetColor();
        Console.WriteLine();
        return;
    }

    try
    {
        var sw = Stopwatch.StartNew();
        engine.LoadSnapshot(path, maxSeqLenOverride: 128);
        GC.Collect(2, GCCollectionMode.Aggressive, true, true);
        sw.Stop();

        orchestrator = new IntelligenceOrchestrator(engine);

        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"  ✓ Loaded ");
        Console.ResetColor();
        Console.WriteLine($"from {path} ({sw.ElapsedMilliseconds}ms)");
        PrintStats(engine, config);
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  ✗ Load failed: {ex.Message}");
        Console.ResetColor();
    }
    Console.WriteLine();
}

static void LoadSnapshotLazy(
    BitNetEngine engine, string path,
    BitNetModelConfig config,
    ref IntelligenceOrchestrator orchestrator)
{
    if (string.IsNullOrWhiteSpace(path))
    {
        path = "model.bmwm";
        Console.WriteLine($"    Using default path: {path}");
    }

    if (!File.Exists(path))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  ✗ File not found: {path}");
        Console.ResetColor();
        Console.WriteLine();
        return;
    }

    try
    {
        var sw = Stopwatch.StartNew();
        engine.LoadSnapshotLazy(path, maxSeqLenOverride: 128);
        sw.Stop();

        orchestrator = new IntelligenceOrchestrator(engine);

        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"  ✓ Lazy-loaded ");
        Console.ResetColor();
        Console.WriteLine($"from {path} ({sw.ElapsedMilliseconds}ms, zero-copy mmap)");
        PrintStats(engine, config);
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  ✗ Lazy load failed: {ex.Message}");
        Console.ResetColor();
    }
    Console.WriteLine();
}

static async Task<IntelligenceOrchestrator?> ImportHuggingFaceModel(
    BitNetEngine engine, string args,
    BitNetModelConfig config)
{
    // Parse: import <hf-dir> [output-path]
    var parts = args.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    string? hfDir = parts.Length > 0 ? parts[0] : null;
    string? outputPath = parts.Length > 1 ? parts[1] : null;

    if (string.IsNullOrWhiteSpace(hfDir))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("  Usage: import <path-to-hf-model-dir> [output.bmwm]");
        Console.ResetColor();
        Console.WriteLine();
        return null;
    }

    if (!Directory.Exists(hfDir))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  ✗ Directory not found: {hfDir}");
        Console.ResetColor();
        Console.WriteLine();
        return null;
    }

    outputPath ??= Path.Combine(Directory.GetCurrentDirectory(), "model.bmwm");

    Console.ForegroundColor = ConsoleColor.DarkCyan;
    Console.WriteLine("  ── HuggingFace Import ────────────────────────────────");
    Console.ResetColor();
    Console.WriteLine($"    Source : {hfDir}");
    Console.WriteLine($"    Output : {outputPath}");
    Console.WriteLine();

    try
    {
        var sw = Stopwatch.StartNew();

        // Stream import with progress callbacks — runs on the thread pool to keep UI responsive
        await Task.Run(() => HuggingFaceImporter.Import(hfDir, outputPath, msg =>
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine(msg);
            Console.ResetColor();
        }));

        GC.Collect(2, GCCollectionMode.Aggressive, true, true);
        sw.Stop();

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"  ✓ Import complete ({sw.ElapsedMilliseconds / 1000.0:F1}s)");
        Console.ResetColor();
        Console.WriteLine();

        // Auto-load the freshly imported snapshot using lazy mmap to avoid OOM
        Console.Write("  Loading imported snapshot (lazy mmap)... ");
        engine.LoadSnapshotLazy(outputPath, maxSeqLenOverride: config.MaxSeqLen);
        var orchestrator = new IntelligenceOrchestrator(engine);
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("done");
        Console.ResetColor();
        PrintStats(engine, config);
        return orchestrator;
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  ✗ Import failed: {ex.Message}");
        Console.WriteLine($"    {ex.StackTrace}");
        Console.ResetColor();
    }
    Console.WriteLine();
    return null;
}

static void TrimAndSave(BitNetEngine engine)
{
    if (!engine.IsLoaded)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("  ✗ No model loaded");
        Console.ResetColor();
        return;
    }

    if (engine.LoadedTokenizer is null || engine.TokenTable is null)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine("  ✗ Model has no tokenizer/token table");
        Console.ResetColor();
        return;
    }

    Console.ForegroundColor = ConsoleColor.DarkCyan;
    Console.WriteLine("  ── Vocabulary Trim ───────────────────────────────────");
    Console.ResetColor();

    var sw = Stopwatch.StartNew();

    // Build domain vocabulary from static lists (no DataScaffold in CLI)
    var pruner = VocabularyPruner.FromDataScaffold();
    var keepIds = pruner.CollectDomainTokenIds(engine.LoadedTokenizer, engine.TokenTable);
    Console.WriteLine($"    Domain token IDs to keep : {keepIds.Count:N0}");

    pruner.BuildRemapTableFromIds(engine.LoadedTokenizer.VocabSize, keepIds);
    Console.WriteLine($"    Original vocab           : {pruner.OriginalVocabSize:N0}");
    Console.WriteLine($"    Pruned vocab             : {pruner.PrunedVocabSize:N0}");
    Console.WriteLine($"    Compression              : {pruner.CompressionRatio:P1}");

    // Trim
    engine.TrimVocabulary(pruner);
    Console.WriteLine($"    Trim time                : {sw.ElapsedMilliseconds:N0} ms");

    // Save with Brotli compression
    var trimmedPath = Path.Combine(Directory.GetCurrentDirectory(), "model-trimmed.bmwm");
    engine.SaveSnapshot(trimmedPath, compress: true);
    var fi = new FileInfo(trimmedPath);
    Console.WriteLine($"    Saved                    : {trimmedPath}");
    Console.WriteLine($"    Size (compressed)        : {fi.Length / 1024 / 1024:N0} MB");

    var stats = pruner.GetStats(2560);
    Console.WriteLine($"    Embedding bytes saved    : {stats.BytesSaved / 1024 / 1024:N0} MB");
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"    ✓ Done in {sw.ElapsedMilliseconds:N0} ms");
    Console.ResetColor();
    Console.WriteLine();

    // Test: reload and generate
    Console.Write("    Reloading trimmed model... ");
    engine.LoadSnapshotLazy(trimmedPath);
    Console.WriteLine($"OK ({engine.TokenTable?.Count:N0} tokens)");

    // Diagnostic: check token encoding + remapping
    if (engine.LoadedTokenizer is not null)
    {
        var testPrompt = "list entities";
        var origIds = engine.LoadedTokenizer.Encode(testPrompt.AsSpan());
        Console.Write($"    '{testPrompt}' token IDs: [");
        Console.Write(string.Join(", ", origIds));
        Console.WriteLine("]");
    }

    Console.Write("    Generating 'list entities' → ");
    var result = engine.GenerateAsync("list entities".AsMemory()).GetAwaiter().GetResult();
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine(result);
    Console.ResetColor();

    Console.Write("    Generating 'show all users' → ");
    var result2 = engine.GenerateAsync("show all users".AsMemory()).GetAwaiter().GetResult();
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine(result2);
    Console.ResetColor();
    Console.WriteLine();
}
