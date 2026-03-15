using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Extension methods to register Intelligence routes on a BareMetalWeb host.
/// Keeps the module fully optional — only active if explicitly registered.
/// </summary>
public static class IntelligenceExtensions
{
    private static IntelligenceOrchestrator? _orchestrator;

    /// <summary>
    /// Initialise the Intelligence module and return route handler delegates.
    /// The caller is responsible for registering these with the host's route table.
    /// Attempts to load the model from a .bmwm snapshot file. Accepted search
    /// paths (first match wins):
    ///   1. BMWM_MODEL_PATH environment variable
    ///   2. model.bmwm in the current working directory
    ///   3. ~/.bmwm/model.bmwm
    ///   4. The directory of the running executable
    /// When no snapshot is found the engine starts unloaded — queries return a
    /// descriptive "model not available" response until a snapshot is loaded.
    /// </summary>
    public static IntelligenceRoutes CreateIntelligenceRoutes()
    {
        var engine = new BitNetEngine();
        TryLoadSnapshot(engine);

        var tools = AdminToolCatalogue.CreateRegistry();

        _orchestrator = new IntelligenceOrchestrator(engine, tools);

        return new IntelligenceRoutes(
            ChatHandler,
            ToolsHandler,
            StatusHandler);
    }

    /// <summary>
    /// Attempt to load a .bmwm snapshot from well-known paths.
    /// Returns true when a snapshot was found and loaded successfully.
    /// </summary>
    public static bool TryLoadSnapshot(BitNetEngine engine)
    {
        foreach (var path in GetSnapshotSearchPaths())
        {
            if (!File.Exists(path)) continue;
            try
            {
                engine.LoadSnapshot(path);
                return true;
            }
            catch (Exception ex)
            {
                // Corrupt or incompatible snapshot — try the next candidate.
                // Write to stderr so the issue is visible without crashing startup.
                Console.Error.WriteLine($"  [Intelligence] Skipping '{path}': {ex.Message}");
            }
        }
        return false;
    }

    /// <summary>
    /// Enumerate candidate .bmwm snapshot paths in priority order.
    /// </summary>
    public static IEnumerable<string> GetSnapshotSearchPaths()
    {
        // 1. Explicit override via environment variable
        var envPath = Environment.GetEnvironmentVariable("BMWM_MODEL_PATH");
        if (!string.IsNullOrWhiteSpace(envPath))
            yield return envPath;

        // 2. Current working directory
        yield return Path.Combine(Directory.GetCurrentDirectory(), "model.bmwm");

        // 3. User home directory
        yield return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".bmwm", "model.bmwm");

        // 4. Executable directory
        var exeDir = Path.GetDirectoryName(Environment.ProcessPath);
        if (!string.IsNullOrWhiteSpace(exeDir))
            yield return Path.Combine(exeDir, "model.bmwm");
    }

    private static async Task ChatHandler(HttpContext context)
    {
        if (_orchestrator is null)
        {
            context.Response.StatusCode = 503;
            await context.Response.WriteAsync("Intelligence module not initialised");
            return;
        }

        string? query = null;

        if (HttpMethods.IsPost(context.Request.Method))
        {
            // Read JSON body: { "query": "..." }
            if (context.Request.ContentType?.Contains("json", StringComparison.OrdinalIgnoreCase) == true)
            {
                using var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true);
                var body = await reader.ReadToEndAsync(context.RequestAborted);

                // Simple manual JSON parse to avoid reflection-based deserialisation
                query = ExtractJsonField(body, "query");
            }
        }
        else if (HttpMethods.IsGet(context.Request.Method))
        {
            query = context.Request.Query["q"].FirstOrDefault();
        }

        if (string.IsNullOrWhiteSpace(query))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("{\"error\":\"Missing 'query' parameter\"}");
            return;
        }

        var response = await _orchestrator.ProcessAsync(query, context.RequestAborted);

        context.Response.ContentType = "application/json; charset=utf-8";
        var json = BuildResponseJson(response);
        await context.Response.WriteAsync(json, context.RequestAborted);
    }

    private static async Task ToolsHandler(HttpContext context)
    {
        if (_orchestrator is null)
        {
            context.Response.StatusCode = 503;
            return;
        }

        var registry = AdminToolCatalogue.CreateRegistry();
        var tools = registry.GetTools();

        context.Response.ContentType = "application/json; charset=utf-8";
        var sb = new StringBuilder(512);
        sb.Append("{\"tools\":[");
        for (int i = 0; i < tools.Count; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append("{\"name\":\"");
            sb.Append(EscapeJson(tools[i].Name));
            sb.Append("\",\"description\":\"");
            sb.Append(EscapeJson(tools[i].Description));
            sb.Append("\"}");
        }
        sb.Append("]}");
        await context.Response.WriteAsync(sb.ToString(), context.RequestAborted);
    }

    private static async Task StatusHandler(HttpContext context)
    {
        context.Response.ContentType = "application/json; charset=utf-8";
        bool loaded = _orchestrator is not null;
        bool modelLoaded = _orchestrator?.GetMetrics() is not null;
        var json = $"{{\"initialized\":{(loaded ? "true" : "false")}," +
                   $"\"bitnet_loaded\":{(modelLoaded ? "true" : "false")}," +
                   $"\"architecture\":\"two-stage-intent-classifier+slm\"}}";
        await context.Response.WriteAsync(json, context.RequestAborted);
    }

    private static string BuildResponseJson(ChatResponse response)
    {
        var sb = new StringBuilder(256);
        sb.Append("{\"message\":\"");
        sb.Append(EscapeJson(response.Message));
        sb.Append("\",\"intent\":\"");
        sb.Append(EscapeJson(response.ResolvedIntent));
        sb.Append("\",\"confidence\":");
        sb.Append(response.Confidence.ToString("F3"));
        sb.Append('}');
        return sb.ToString();
    }

    private static string EscapeJson(string value)
    {
        return value
            .Replace("\\", "\\\\")
            .Replace("\"", "\\\"")
            .Replace("\n", "\\n")
            .Replace("\r", "\\r")
            .Replace("\t", "\\t");
    }

    private static string? ExtractJsonField(string json, string fieldName)
    {
        // Simple field extraction without reflection-based JSON deserialisation
        var key = $"\"{fieldName}\"";
        int idx = json.IndexOf(key, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return null;

        int colonIdx = json.IndexOf(':', idx + key.Length);
        if (colonIdx < 0) return null;

        int quoteStart = json.IndexOf('"', colonIdx + 1);
        if (quoteStart < 0) return null;

        int quoteEnd = quoteStart + 1;
        while (quoteEnd < json.Length)
        {
            if (json[quoteEnd] == '\\') { quoteEnd += 2; continue; }
            if (json[quoteEnd] == '"') break;
            quoteEnd++;
        }

        if (quoteEnd >= json.Length) return null;
        return json[(quoteStart + 1)..quoteEnd];
    }
}

/// <summary>
/// Route handler delegates for Intelligence endpoints.
/// Register these with the host's route table.
/// </summary>
public readonly record struct IntelligenceRoutes(
    Func<HttpContext, Task> Chat,
    Func<HttpContext, Task> Tools,
    Func<HttpContext, Task> Status
);
