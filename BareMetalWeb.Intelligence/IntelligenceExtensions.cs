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
    /// </summary>
    public static IntelligenceRoutes CreateIntelligenceRoutes(bool enableBitNet = false)
    {
        var intents = AdminToolCatalogue.GetIntentDefinitions();
        var classifier = new KeywordIntentClassifier(intents);
        var executor = AdminToolCatalogue.CreateRegistry();

        BitNetEngine? engine = null;
        if (enableBitNet)
        {
            engine = new BitNetEngine();
            engine.LoadTestModel();
        }

        _orchestrator = new IntelligenceOrchestrator(classifier, executor, engine);

        return new IntelligenceRoutes(
            ChatHandler,
            ToolsHandler,
            StatusHandler);
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
        var json = $"{{\"initialized\":{(loaded ? "true" : "false")}," +
                   $"\"bitnet_loaded\":{(_orchestrator is not null ? "true" : "false")}," +
                   $"\"architecture\":\"hybrid-embeddings-bitnet\"}}";
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
