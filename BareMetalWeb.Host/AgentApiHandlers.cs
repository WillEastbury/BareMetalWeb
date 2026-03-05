using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Data.Interfaces;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Backend handler for the Agent Panel chat interface.
/// Parses natural language queries and maps them to data operations:
/// - "list [entity]" → query records
/// - "count [entity]" → count records
/// - "show [entity] [id]" → fetch a record
/// - "search [entity] [term]" → search records
/// - "entities" / "types" → list available entities
/// - "help" → show available commands
/// </summary>
public static class AgentApiHandlers
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
    };

    /// <summary>POST /api/agent/chat</summary>
    public static async ValueTask ChatHandler(HttpContext context)
    {
        using var doc = await JsonDocument.ParseAsync(context.Request.Body);
        var root = doc.RootElement;
        var message = root.GetProperty("message").GetString()?.Trim() ?? "";

        string reply;
        try
        {
            reply = await ProcessMessageAsync(message, context.RequestAborted);
        }
        catch (Exception ex)
        {
            reply = $"Error: {ex.Message}";
        }

        context.Response.ContentType = "application/json";
        await JsonSerializer.SerializeAsync(context.Response.Body, new { reply }, JsonOpts);
    }

    private static async ValueTask<string> ProcessMessageAsync(string message, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(message))
            return "Please enter a command or question.";

        var lower = message.ToLowerInvariant().Trim();

        // Help
        if (lower is "help" or "?" or "commands")
            return "Available commands:\n" +
                   "• entities — list all entity types\n" +
                   "• list [entity] — show recent records\n" +
                   "• count [entity] — count records\n" +
                   "• show [entity] [id] — show a specific record\n" +
                   "• search [entity] [term] — search records\n" +
                   "• schema [entity] — show fields/schema\n" +
                   "• status — system status";

        // List entities
        if (lower is "entities" or "types" or "list entities" or "show entities")
        {
            var entities = DataScaffold.Entities;
            if (entities.Count == 0) return "No entities registered.";
            var entityLines = new List<string>(entities.Count);
            foreach (var e in entities)
                entityLines.Add($"• {e.Slug} ({e.Name})");
            return "Available entities:\n" + string.Join("\n", entityLines);
        }

        // Status
        if (lower is "status" or "system status")
        {
            var provider = DataStoreProvider.PrimaryProvider;
            var entities = DataScaffold.Entities;
            return $"System status: OK\n" +
                   $"Entities: {entities.Count}\n" +
                   $"Provider: {provider?.GetType().Name ?? "none"}";
        }

        // Schema [entity]
        if (lower.StartsWith("schema "))
        {
            var slug = ExtractEntitySlug(lower, "schema ");
            if (!DataScaffold.TryGetEntity(slug, out var meta))
                return $"Entity '{slug}' not found. Type 'entities' to see available types.";
            var fields = new List<string>(meta.Fields.Count);
            foreach (var f in meta.Fields)
                fields.Add($"  {f.Name} ({f.FieldType})");
            return $"Schema for {meta.Name}:\n{string.Join("\n", fields)}";
        }

        // Count [entity]
        if (lower.StartsWith("count "))
        {
            var slug = ExtractEntitySlug(lower, "count ");
            if (!DataScaffold.TryGetEntity(slug, out var meta))
                return $"Entity '{slug}' not found.";
            var store = DataStoreProvider.Current;
            var count = await store.CountAsync<DataRecord>(null, ct);
            return $"{meta.Name}: {count} record(s)";
        }

        // List [entity]
        if (lower.StartsWith("list ") || lower.StartsWith("show all "))
        {
            var prefix = lower.StartsWith("list ") ? "list " : "show all ";
            var slug = ExtractEntitySlug(lower, prefix);
            if (!DataScaffold.TryGetEntity(slug, out var meta))
                return $"Entity '{slug}' not found.";
            var store = DataStoreProvider.Current;
            var query = new QueryDefinition { Top = 10 };
            var items = await store.QueryAsync<DataRecord>(query, ct);
            var list = new List<DataRecord>();
            foreach (var item in items)
                list.Add(item);
            if (list.Count == 0)
                return $"No {meta.Name} found.";
            var lines = new List<string>(list.Count);
            foreach (var item in list)
            {
                var name = item.Key.ToString();
                lines.Add($"• [{item.Key}] {name}");
            }
            return $"{meta.Name} (top 10):\n{string.Join("\n", lines)}";
        }

        // Show [entity] [id]
        if (lower.StartsWith("show ") || lower.StartsWith("get "))
        {
            var prefix = lower.StartsWith("show ") ? "show " : "get ";
            var rest = message.Substring(prefix.Length).Trim();
            var parts = rest.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
                return "Usage: show [entity] [id]";
            var slug = parts[0].ToLowerInvariant();
            if (!DataScaffold.TryGetEntity(slug, out var meta))
                return $"Entity '{slug}' not found.";
            if (!uint.TryParse(parts[1], out var id))
                return $"Invalid ID: {parts[1]}";
            return $"Record {slug} #{id} — use the detail view at /{slug}/{id} for full details.";
        }

        // Search [entity] [term]
        if (lower.StartsWith("search ") || lower.StartsWith("find "))
        {
            var prefix = lower.StartsWith("search ") ? "search " : "find ";
            var rest = message.Substring(prefix.Length).Trim();
            var parts = rest.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
                return "Usage: search [entity] [term]";
            var slug = parts[0].ToLowerInvariant();
            if (!DataScaffold.TryGetEntity(slug, out var meta))
                return $"Entity '{slug}' not found.";
            var term = parts[1];
            var store = DataStoreProvider.Current;
            var query = new QueryDefinition
            {
                Top = 10,
                Clauses = new List<QueryClause>
                {
                    new() { Field = "Name", Operator = QueryOperator.Contains, Value = term }
                }
            };
            var items = await store.QueryAsync<DataRecord>(query, ct);
            var list = new List<DataRecord>();
            foreach (var item in items)
                list.Add(item);
            if (list.Count == 0)
                return $"No {meta.Name} matching '{term}'.";
            var lines = new List<string>(list.Count);
            foreach (var item in list)
                lines.Add($"• [{item.Key}] {item.Key.ToString()}");
            return $"Results for '{term}' in {meta.Name}:\n{string.Join("\n", lines)}";
        }

        return "I didn't understand that. Type 'help' for available commands.";
    }

    private static string ExtractEntitySlug(string lower, string prefix)
    {
        return lower.Substring(prefix.Length).Trim().Split(' ')[0];
    }
}
