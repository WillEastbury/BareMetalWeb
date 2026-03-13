using BareMetalWeb.Agent;

// ── Signal handling ──────────────────────────────────────────────────────────
var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
AppDomain.CurrentDomain.ProcessExit += (_, _) => cts.Cancel();

// ── Configuration ────────────────────────────────────────────────────────────
var config = AgentConfig.Load(args.Length > 0 ? args[0] : null);

if (!config.IsValid)
{
    Console.Error.WriteLine(
        $"[BMW Agent] ERROR: valid node identity not found at '{config.StateFile}'.");
    Console.Error.WriteLine(
        "[BMW Agent] Provision a node.json file or set BMW_STATE_FILE.");
    return 1;
}

// ── Run ───────────────────────────────────────────────────────────────────────
using var pm = new RuntimeProcessManager(config);
var service  = new AgentPollingService(config, pm);

await service.RunAsync(cts.Token);
return 0;
