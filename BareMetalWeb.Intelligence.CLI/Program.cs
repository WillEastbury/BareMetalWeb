using System.Diagnostics;
using BareMetalWeb.Intelligence;
using BareMetalWeb.Intelligence.Interfaces;

const string Banner = """

    ╔══════════════════════════════════════════════════════════╗
    ║  BareMetalWeb Intelligence CLI                          ║
    ║  Hybrid Embeddings + BitNet b1.58 Ternary Engine        ║
    ║  2-bit packed · native memory · zero-skip sparse        ║
    ╚══════════════════════════════════════════════════════════╝

    """;

Console.ForegroundColor = ConsoleColor.Cyan;
Console.Write(Banner);
Console.ResetColor();

// --- Load engine ---
Console.Write("  Loading engine... ");
var sw = Stopwatch.StartNew();

var config = new BitNetModelConfig(
    HiddenDim: 2048,
    NumLayers: 24,
    NumHeads: 16,
    VocabSize: 32000,
    MaxSeqLen: 2048);

var executor = AdminToolCatalogue.CreateRegistry();
using var engine = new BitNetEngine(config);

// Try loading a trained snapshot first; fall back to test model
var snapshotPath = FindCliModelSnapshot();
if (snapshotPath is not null)
{
    engine.LoadSnapshot(snapshotPath);
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine($"loaded snapshot ({sw.ElapsedMilliseconds}ms): {snapshotPath}");
}
else
{
    engine.LoadTestModel(ModelLoadOptions.Aggressive);
    Console.ForegroundColor = ConsoleColor.DarkYellow;
    Console.WriteLine($"no snapshot found — using random test model ({sw.ElapsedMilliseconds}ms)");
}

// Force GC to reclaim the temporary sbyte[] arrays used during construction
GC.Collect(2, GCCollectionMode.Aggressive, true, true);

var orchestrator = new IntelligenceOrchestrator(engine);
sw.Stop();

Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine($"ready ({sw.ElapsedMilliseconds}ms)");
Console.ResetColor();
Console.WriteLine();

// --- Print stats ---
PrintStats(engine, config);

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

        default:
            if (input.StartsWith("import ", StringComparison.OrdinalIgnoreCase))
            {
                RunImport(input[7..].Trim());
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
    Console.WriteLine("  │    help, ?      — Show this help                │");
    Console.WriteLine("  │    stats, mem   — Show model & memory stats     │");
    Console.WriteLine("  │    gc           — Force GC and show memory      │");
    Console.WriteLine("  │    tools        — List available admin tools     │");
    Console.WriteLine("  │    layers       — Per-layer sparsity stats      │");
    Console.WriteLine("  │    semantic     — Run semantic pruning comparison│");
    Console.WriteLine("  │    bench        — Run inference benchmark       │");
    Console.WriteLine("  │    compare      — Compare pruning levels RAM    │");
    Console.WriteLine("  │    save <path>  — Save model snapshot (.bmwm)   │");
    Console.WriteLine("  │    load <path>  — Load model snapshot (.bmwm)   │");
    Console.WriteLine("  │    loadlazy <p> — Lazy mmap load (zero-copy)    │");
    Console.WriteLine("  │    import <dir> — Import HF model to .bmwm      │");
    Console.WriteLine("  │    exit, quit   — Exit                          │");
    Console.WriteLine("  │                                                 │");
    Console.WriteLine("  │  Or just type a natural language query:         │");
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
    Console.ForegroundColor = ConsoleColor.DarkCyan;
    Console.WriteLine("  ── Pruning Level Comparison ──────────────────────");
    Console.ResetColor();

    var levels = new (string Name, ModelLoadOptions Opts)[]
    {
        ("No pruning",  ModelLoadOptions.NoPruning),
        ("Vocab only",  ModelLoadOptions.Default),
        ("Aggressive",  ModelLoadOptions.Aggressive),
        ("Maximum",     new ModelLoadOptions
        {
            PruneVocabulary = true,
            LayerPruneRatio = 0.50f,
            HeadPruneRatio = 0.50f,
            GroupPruneAttnThreshold = 2,
            GroupPruneFfnThreshold = 3,
        }),
    };

    Console.WriteLine("    {0,-16} {1,10} {2,8} {3,8} {4,7} {5,9} {6,8}", "Level", "WorkSet", "GCHeap", "Native", "Layers", "Sparsity", "Vocab");
    Console.WriteLine("    {0,-16} {1,10} {2,8} {3,8} {4,7} {5,9} {6,8}", "─────", "──────", "──────", "──────", "──────", "────────", "─────");

    foreach (var (name, opts) in levels)
    {
        GC.Collect(2, GCCollectionMode.Aggressive, true, true);
        var proc = Process.GetCurrentProcess();
        proc.Refresh();
        long wsBefore = proc.WorkingSet64;

        using var e = new BitNetEngine(config);
        e.LoadTestModel(opts);
        GC.Collect(2, GCCollectionMode.Aggressive, true, true);

        proc.Refresh();
        long wsAfter = proc.WorkingSet64;
        long wsDelta = wsAfter - wsBefore;

        int vocab = e.VocabPruneStats?.PrunedVocabSize ?? config.VocabSize;
        int layers = e.ModelStats?.LayerCount ?? config.NumLayers;
        float sparsity = e.ModelStats?.Sparsity ?? 0f;
        long nativeBytes = e.NativeBytesAllocated;
        long gcHeap = GC.GetTotalMemory(false);

        Console.Write($"    {name,-16}");
        Console.ForegroundColor = ConsoleColor.White;
        Console.Write($" {wsAfter / (1024 * 1024),7} MB");
        Console.ResetColor();
        Console.Write($" {gcHeap / (1024 * 1024),5} MB");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($" {nativeBytes / (1024 * 1024),5} MB");
        Console.ResetColor();
        Console.WriteLine($" {layers,7} {sparsity,9:P1} {vocab,8}");
    }

    Console.WriteLine();
}

static void RunSemanticComparison(BitNetModelConfig config)
{
    // Use a smaller model for the interactive comparison to keep it fast
    var smallConfig = new BitNetModelConfig(
        HiddenDim: 256,
        NumLayers: 4,
        NumHeads: 4,
        VocabSize: 1000,
        MaxSeqLen: 512);

    Console.ForegroundColor = ConsoleColor.DarkCyan;
    Console.WriteLine("  ── Semantic Pruning Comparison (256-dim model) ───");
    Console.ResetColor();

    var levels = new (string Name, ModelLoadOptions Opts)[]
    {
        ("Magnitude only",  new ModelLoadOptions
        {
            PruneVocabulary = true,
            GroupPruneAttnThreshold = 1,
            GroupPruneFfnThreshold = 2,
        }),
        ("Semantic (0.95)",  new ModelLoadOptions
        {
            PruneVocabulary = true,
            GroupPruneAttnThreshold = 1,
            GroupPruneFfnThreshold = 2,
            SemanticPruning = true,
            SemanticDriftThreshold = 0.95f,
        }),
        ("Semantic (0.90)",  new ModelLoadOptions
        {
            PruneVocabulary = true,
            GroupPruneAttnThreshold = 1,
            GroupPruneFfnThreshold = 2,
            SemanticPruning = true,
            SemanticDriftThreshold = 0.90f,
        }),
    };

    Console.WriteLine("    {0,-18} {1,10} {2,7} {3,8} {4,7} {5,7} {6,6}",
        "Level", "Sparsity", "Heads", "Neurons", "Blocks", "Fine", "Acc");
    Console.WriteLine("    {0,-18} {1,10} {2,7} {3,8} {4,7} {5,7} {6,6}",
        "─────", "────────", "─────", "───────", "──────", "────", "───");

    foreach (var (name, opts) in levels)
    {
        var sw = Stopwatch.StartNew();
        using var e = new BitNetEngine(smallConfig);
        e.LoadTestModel(opts);
        sw.Stop();

        float sparsity = e.ModelStats?.Sparsity ?? 0f;
        var sp = e.SemanticPruneInfo;

        Console.Write($"    {name,-18}");
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($" {sparsity,9:P1}");
        Console.ResetColor();

        if (sp is { } s)
        {
            Console.Write($" {s.HeadsPruned,7}");
            Console.Write($" {s.NeuronsPruned,8}");
            Console.Write($" {s.BlocksPruned,7}");
            Console.Write($" {s.FineGroupsPruned,7}");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write($" {s.PostPruneAccuracy,5:P0}");
            Console.ResetColor();
        }
        else
        {
            Console.Write($" {"—",7} {"—",8} {"—",7} {"—",7} {"—",5}");
        }

        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"  ({sw.ElapsedMilliseconds}ms)");
        Console.ResetColor();
        Console.WriteLine();
    }

    GC.Collect(2, GCCollectionMode.Aggressive, true, true);
    Console.WriteLine();
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
        engine.LoadSnapshot(path);
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
        engine.LoadSnapshotLazy(path);
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

static string? FindCliModelSnapshot()
{
    string[] candidates =
    [
        "model.bmwm",
        Path.Combine(AppContext.BaseDirectory, "model.bmwm"),
        Path.Combine(AppContext.BaseDirectory, "..", "model.bmwm"),
    ];

    foreach (var path in candidates)
    {
        if (File.Exists(path))
            return Path.GetFullPath(path);
    }

    return null;
}

static void RunImport(string modelDir)
{
    if (string.IsNullOrWhiteSpace(modelDir))
    {
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("  Usage: import <path-to-hf-model-directory>");
        Console.WriteLine();
        Console.WriteLine("  The directory should contain:");
        Console.WriteLine("    config.json       — HuggingFace model config");
        Console.WriteLine("    tokenizer.json    — Tokenizer vocabulary");
        Console.WriteLine("    *.safetensors     — Model weight files");
        Console.WriteLine();
        Console.WriteLine("  Download first with:");
        Console.WriteLine("    huggingface-cli download microsoft/bitnet-b1.58-2B-4T --local-dir ./bitnet-2b");
        Console.ResetColor();
        Console.WriteLine();
        return;
    }

    if (!Directory.Exists(modelDir))
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  ✗ Directory not found: {modelDir}");
        Console.ResetColor();
        Console.WriteLine();
        return;
    }

    Console.ForegroundColor = ConsoleColor.DarkCyan;
    Console.WriteLine("  ── HuggingFace Import ────────────────────────────");
    Console.ResetColor();

    try
    {
        var sw = Stopwatch.StartNew();
        var result = HuggingFaceImporter.Import(modelDir, ImportOptions.DomainTrimmed);
        sw.Stop();

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Green;
        Console.Write($"  ✓ Import complete ");
        Console.ResetColor();
        Console.WriteLine($"({sw.ElapsedMilliseconds}ms)");
        Console.WriteLine($"    Config: {result.Config.HiddenDim}d × {result.Config.NumLayers}L × {result.Config.NumHeads}H");
        Console.WriteLine($"    Vocab: {result.ActiveVocab} active tokens ({result.TokenTableSize} in table)");
        Console.WriteLine($"    File: {result.FileSizeBytes / (1024 * 1024)} MB → {ImportOptions.DomainTrimmed.OutputPath}");
        Console.WriteLine();
        Console.WriteLine("    Load with: load model.bmwm");
    }
    catch (Exception ex)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"  ✗ Import failed: {ex.Message}");
        if (ex.InnerException is not null)
            Console.WriteLine($"    {ex.InnerException.Message}");
        Console.ResetColor();
    }
    Console.WriteLine();
}
