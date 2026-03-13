using BareMetalWeb.Agent;

// ── Signal handling ──────────────────────────────────────────────────────────
var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
AppDomain.CurrentDomain.ProcessExit += (_, _) => cts.Cancel();

// ── Configuration ────────────────────────────────────────────────────────────
var config = AgentConfig.Load(args.Length > 0 ? args[0] : null);

// ── First-boot registration ───────────────────────────────────────────────────
// If no valid node identity is present on disk, attempt self-registration with the
// bootstrap endpoint using hardware-derived credentials (CPU serial + NIC MAC hash).
if (!config.IsValid)
{
    if (!string.IsNullOrEmpty(config.BootstrapEndpoint))
    {
        Console.WriteLine($"{DateTime.UtcNow:O} | No node identity found — starting first-boot registration.");
        var reg  = new NodeRegistrationService(config);
        var node = await reg.RegisterAsync(cts.Token);

        if (node is null)
        {
            Console.Error.WriteLine("[BMW Agent] ERROR: First-boot registration failed.");
            Console.Error.WriteLine("[BMW Agent] Set BMW_BOOTSTRAP_ENDPOINT and ensure the control plane is reachable.");
            return 1;
        }

        // Load the newly-written state file into the existing config so that all
        // env-var-derived settings (RuntimeDir, poll intervals, etc.) are preserved.
        var freshConfig = AgentConfig.Load(config.StateFile);
        config.Node = freshConfig.Node;
    }
    else
    {
        Console.Error.WriteLine(
            $"[BMW Agent] ERROR: valid node identity not found at '{config.StateFile}'.");
        Console.Error.WriteLine(
            "[BMW Agent] Either provision a node.json file, set BMW_STATE_FILE, " +
            "or set BMW_BOOTSTRAP_ENDPOINT to enable self-registration.");
        return 1;
    }
}

// ── Attest on every boot ──────────────────────────────────────────────────────
// Re-attest OS/glibc/architecture with the control plane so it can verify the
// node's platform hasn't changed since registration.
if (config.IsValid && config.Node is { } existingNode)
{
    var reg = new NodeRegistrationService(config);
    await reg.AttestAsync(existingNode, cts.Token);
}

// ── Run polling loop ──────────────────────────────────────────────────────────
using var pm = new RuntimeProcessManager(config);
var service  = new AgentPollingService(config, pm);

await service.RunAsync(cts.Token);
return 0;
