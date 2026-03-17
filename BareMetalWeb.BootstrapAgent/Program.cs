using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

const string DefaultControlPlane = "https://cluster.bmw.mesh";
const string StateFile = "/var/lib/bmw/node.json";
const string RuntimeDir = "/opt/bmw";
const string RuntimeLink = "/opt/bmw/bmw";

Directory.CreateDirectory(RuntimeDir);

var controlPlane = Environment.GetEnvironmentVariable("BMW_CONTROL_PLANE") ?? DefaultControlPlane;
var stateFile = Environment.GetEnvironmentVariable("BMW_STATE_FILE") ?? StateFile;

if (!File.Exists(stateFile))
{
    Log($"State file not found: {stateFile}");
    return 1;
}

var node = ReadNodeIdentity(File.ReadAllText(stateFile));

Log("Agent started");
Log($"Node: {node.NodeId} → {controlPlane}");

var random = new Random();
var jitter = random.Next(0, 30_000);
Log($"Jitter delay: {jitter}ms");
await Task.Delay(jitter);

Process? bmwProcess = null;

while (true)
{
    try
    {
        var runtime = await PollDesiredRuntime(node, controlPlane);

        var current = GetCurrentVersion();

        if (runtime.DesiredVersion != null && runtime.DesiredVersion != current)
        {
            Log($"Upgrade required: {current ?? "(none)"} → {runtime.DesiredVersion}");
            await DownloadRuntime(runtime, node, controlPlane);
            InstallRuntime(runtime.DesiredVersion);
            RestartBMW(ref bmwProcess, node);
        }

        if (bmwProcess == null || bmwProcess.HasExited)
        {
            if (File.Exists(RuntimeLink))
            {
                Log("BMW not running → launching");
                StartBMW(ref bmwProcess, node);
            }
            else
            {
                Log("No runtime installed yet, waiting…");
            }
        }

        var pollSeconds = runtime.PollSeconds > 0 ? runtime.PollSeconds : 60;
        await Task.Delay(TimeSpan.FromSeconds(pollSeconds));
    }
    catch (Exception ex)
    {
        Log($"ERROR: {ex.Message}");
        await Task.Delay(5000);
    }
}

static string? GetCurrentVersion()
{
    if (!File.Exists(RuntimeLink))
        return null;

    var target = new FileInfo(RuntimeLink).LinkTarget;
    if (target == null)
        return null;

    // Target format: /opt/bmw/bmw-1.6.0 or bmw-1.6.0
    var name = Path.GetFileName(target);
    var dash = name.IndexOf('-');
    return dash >= 0 ? name[(dash + 1)..] : null;
}

static async Task<RuntimeResponse> PollDesiredRuntime(NodeIdentity node, string controlPlane)
{
    using var http = new HttpClient();
    http.DefaultRequestHeaders.Add("Authorization", $"Bearer {node.Secret}");
    http.DefaultRequestHeaders.Add("X-BMW-Architecture", RuntimeInformation.ProcessArchitecture.ToString());
    http.DefaultRequestHeaders.Add("X-BMW-Current-Version", GetCurrentVersion() ?? "");

    var json = await http.GetStringAsync(
        $"{controlPlane}/api/runtime/desired/{node.NodeId}");

    return ReadRuntimeResponse(json);
}

static async Task DownloadRuntime(RuntimeResponse r, NodeIdentity node, string controlPlane)
{
    var target = $"{RuntimeDir}/bmw-{r.DesiredVersion}";

    if (File.Exists(target))
    {
        Log("Runtime already cached");
        return;
    }

    Log($"Downloading runtime {r.DesiredVersion}");

    using var http = new HttpClient();
    http.DefaultRequestHeaders.Add("Authorization", $"Bearer {node.Secret}");

    var data = await http.GetByteArrayAsync(controlPlane + r.DownloadUrl);

    var hash = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    if (hash != r.Sha256?.ToLowerInvariant())
        throw new InvalidOperationException("SHA256 mismatch — download corrupted or tampered");

    await File.WriteAllBytesAsync(target, data);

    if (!OperatingSystem.IsWindows())
    {
        File.SetUnixFileMode(target,
            UnixFileMode.UserRead |
            UnixFileMode.UserExecute);
    }

    Log("Runtime downloaded and verified");
}

static void InstallRuntime(string version)
{
    var target = $"{RuntimeDir}/bmw-{version}";

    if (File.Exists(RuntimeLink))
        File.Delete(RuntimeLink);

    File.CreateSymbolicLink(RuntimeLink, target);

    Log($"Runtime installed → {version}");
}

static void RestartBMW(ref Process? proc, NodeIdentity node)
{
    if (proc != null && !proc.HasExited)
    {
        Log("Stopping BMW");
        proc.Kill(entireProcessTree: true);
        proc.WaitForExit();
    }

    StartBMW(ref proc, node);
}

static void StartBMW(ref Process? proc, NodeIdentity node)
{
    var psi = new ProcessStartInfo(RuntimeLink)
    {
        UseShellExecute = false
    };

    psi.Environment["BMW_NODE_ID"] = node.NodeId;
    psi.Environment["BMW_SERVICE_PRINCIPAL"] = node.ServicePrincipal;
    psi.Environment["BMW_SECRET"] = node.Secret;
    psi.Environment["BMW_CLUSTER_ENDPOINT"] = node.ClusterEndpoint;
    psi.Environment["BMW_CERT_FINGERPRINT"] = node.CertFingerprint;

    proc = Process.Start(psi);

    Log($"BMW started (pid {proc?.Id})");
}

static void Log(string msg)
{
    Console.WriteLine($"{DateTime.UtcNow:O} | {msg}");
}

// ── Manual JSON helpers (no JsonSerializer, no source generators) ──────────

static NodeIdentity ReadNodeIdentity(string json)
{
    using var doc = JsonDocument.Parse(json);
    var r = doc.RootElement;
    return new NodeIdentity(
        r.TryGetProperty("nodeId", out var nid) ? nid.GetString() ?? "" : "",
        r.TryGetProperty("servicePrincipal", out var sp) ? sp.GetString() ?? "" : "",
        r.TryGetProperty("secret", out var sec) ? sec.GetString() ?? "" : "",
        r.TryGetProperty("clusterEndpoint", out var ce) ? ce.GetString() ?? "" : "",
        r.TryGetProperty("certFingerprint", out var cf) ? cf.GetString() ?? "" : ""
    );
}

static RuntimeResponse ReadRuntimeResponse(string json)
{
    using var doc = JsonDocument.Parse(json);
    var r = doc.RootElement;
    return new RuntimeResponse(
        r.TryGetProperty("desiredVersion", out var dv) ? dv.GetString() : null,
        r.TryGetProperty("sha256", out var sha) ? sha.GetString() : null,
        r.TryGetProperty("downloadUrl", out var du) ? du.GetString() : null,
        r.TryGetProperty("pollSeconds", out var ps) && ps.TryGetInt32(out var pollVal) ? pollVal : 0
    );
}

record NodeIdentity(string NodeId, string ServicePrincipal, string Secret, string ClusterEndpoint, string CertFingerprint);

record RuntimeResponse(string? DesiredVersion, string? Sha256, string? DownloadUrl, int PollSeconds);
