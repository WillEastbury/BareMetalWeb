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

var intents = AdminToolCatalogue.GetIntentDefinitions();
var classifier = new KeywordIntentClassifier(intents);
var executor = AdminToolCatalogue.CreateRegistry();
using var engine = new BitNetEngine(config);
engine.LoadTestModel(ModelLoadOptions.Aggressive);

// Force GC to reclaim the temporary sbyte[] arrays used during construction
GC.Collect(2, GCCollectionMode.Aggressive, true, true);

var orchestrator = new IntelligenceOrchestrator(classifier, executor, engine);
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

        case "bench":
            RunBenchmark(orchestrator);
            continue;

        case "compare":
            RunPruneComparison(config);
            continue;

        default:
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
    Console.WriteLine("  │    bench        — Run inference benchmark       │");
    Console.WriteLine("  │    compare      — Compare pruning levels RAM    │");
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
        ("Maximum",     new ModelLoadOptions { PruneVocabulary = true, LayerPruneRatio = 0.50f, HeadPruneRatio = 0.50f }),
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
