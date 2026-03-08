using BareMetalWeb.Core;
using BareMetalWeb.Intelligence.Interfaces;

namespace BareMetalWeb.Intelligence;

/// <summary>
/// Pre-configured tool catalogue for BareMetalWeb admin operations.
/// Registers standard tools for entity queries, system diagnostics,
/// and index management against DataScaffold metadata.
/// </summary>
public static class AdminToolCatalogue
{
    /// <summary>
    /// Intent definitions for the keyword classifier.
    /// Each intent maps to a tool in the registry.
    /// </summary>
    public static IReadOnlyList<IntentDefinition> GetIntentDefinitions() =>
    [
        new("list-entities",
            "List all registered data entities",
            ["list", "show", "entities", "types", "data", "models", "schema", "all"]),

        new("describe-entity",
            "Describe fields and metadata for a specific entity",
            ["describe", "fields", "schema", "metadata", "properties", "columns", "entity", "type", "model"]),

        new("query-entity",
            "Query records from a data entity",
            ["query", "find", "search", "get", "records", "rows", "data", "fetch", "count", "how", "many"]),

        new("system-status",
            "Show system status and diagnostics",
            ["status", "health", "diagnostics", "uptime", "memory", "system", "info"]),

        new("index-status",
            "Show search index health and statistics",
            ["index", "search", "reindex", "rebuild", "fragmentation", "statistics"]),

        new("help",
            "Show available commands and capabilities",
            ["help", "commands", "what", "can", "you", "do", "capabilities"]),
    ];

    /// <summary>
    /// Register all admin tools into a ToolRegistry.
    /// Uses DataScaffold for entity metadata access.
    /// </summary>
    public static ToolRegistry CreateRegistry()
    {
        var registry = new ToolRegistry();

        registry.Register(
            "list-entities",
            "List all registered data entities",
            [],
            ListEntitiesHandler);

        registry.Register(
            "describe-entity",
            "Describe fields for a specific entity",
            [new ToolParameter("entity", "Entity name or slug", true)],
            DescribeEntityHandler);

        registry.Register(
            "query-entity",
            "Query records from a data entity",
            [
                new ToolParameter("entity", "Entity name or slug", true),
                new ToolParameter("limit", "Max records to return", false),
            ],
            QueryEntityHandler);

        registry.Register(
            "system-status",
            "Show system status and diagnostics",
            [],
            SystemStatusHandler);

        registry.Register(
            "index-status",
            "Show search index health",
            [],
            IndexStatusHandler);

        registry.Register(
            "help",
            "Show available commands",
            [],
            HelpHandler);

        return registry;
    }

    private static ValueTask<ToolResult> ListEntitiesHandler(
        IReadOnlyDictionary<string, string> parameters, CancellationToken ct)
    {
        try
        {
            var entities = DataScaffold.Entities;
            if (entities is null || entities.Count == 0)
                return ValueTask.FromResult(ToolResult.Ok("No data entities registered."));

            var lines = new System.Text.StringBuilder(256);
            lines.AppendLine($"Registered entities ({entities.Count}):");
            lines.AppendLine();

            foreach (var entity in entities)
            {
                int fieldCount = entity.Fields?.Count ?? 0;
                lines.AppendLine($"  • {entity.Name} (/{entity.Slug}) — {fieldCount} fields");
            }

            return ValueTask.FromResult(ToolResult.Ok(lines.ToString()));
        }
        catch (Exception ex)
        {
            return ValueTask.FromResult(ToolResult.Fail($"Failed to list entities: {ex.GetType().Name}"));
        }
    }

    private static ValueTask<ToolResult> DescribeEntityHandler(
        IReadOnlyDictionary<string, string> parameters, CancellationToken ct)
    {
        if (!parameters.TryGetValue("entity", out var entityName) || string.IsNullOrEmpty(entityName))
            return ValueTask.FromResult(ToolResult.Fail("Please specify an entity name."));

        try
        {
            var entities = DataScaffold.Entities;
            var entity = entities?.FirstOrDefault(e =>
                string.Equals(e.Name, entityName, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(e.Slug, entityName, StringComparison.OrdinalIgnoreCase));

            if (entity is null)
                return ValueTask.FromResult(ToolResult.Fail($"Entity '{entityName}' not found."));

            var sb = new System.Text.StringBuilder(512);
            sb.AppendLine($"Entity: {entity.Name}");
            sb.AppendLine($"  Slug: /{entity.Slug}");
            sb.AppendLine($"  Permissions: {entity.Permissions}");
            sb.AppendLine($"  Show on nav: {entity.ShowOnNav}");
            sb.AppendLine($"  Fields:");

            if (entity.Fields is not null)
            {
                foreach (var field in entity.Fields)
                {
                    string req = field.Required ? " [required]" : "";
                    sb.AppendLine($"    • {field.Name} ({field.FieldType}){req}");
                }
            }

            return ValueTask.FromResult(ToolResult.Ok(sb.ToString()));
        }
        catch (Exception ex)
        {
            return ValueTask.FromResult(ToolResult.Fail($"Failed to describe entity: {ex.GetType().Name}"));
        }
    }

    private static async ValueTask<ToolResult> QueryEntityHandler(
        IReadOnlyDictionary<string, string> parameters, CancellationToken ct)
    {
        if (!parameters.TryGetValue("entity", out var entityName) || string.IsNullOrEmpty(entityName))
            return ToolResult.Fail("Please specify an entity name.");

        int limit = 10;
        if (parameters.TryGetValue("limit", out var limitStr) && int.TryParse(limitStr, out var parsed))
            limit = Math.Clamp(parsed, 1, 100);

        try
        {
            var entities = DataScaffold.Entities;
            var entity = entities?.FirstOrDefault(e =>
                string.Equals(e.Name, entityName, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(e.Slug, entityName, StringComparison.OrdinalIgnoreCase));

            if (entity is null)
                return ToolResult.Fail($"Entity '{entityName}' not found.");

            var count = await entity.Handlers.CountAsync(null, ct).ConfigureAwait(false);
            var items = await entity.Handlers.QueryAsync(null, ct).ConfigureAwait(false);
            var list = items.Take(limit).ToList();

            var sb = new System.Text.StringBuilder(256);
            sb.AppendLine($"{entity.Name}: {count} total records (showing {list.Count})");

            foreach (var item in list)
            {
                sb.AppendLine($"  [{item.Id}] {item}");
            }

            return ToolResult.Ok(sb.ToString());
        }
        catch (Exception ex)
        {
            return ToolResult.Fail($"Query failed: {ex.GetType().Name}");
        }
    }

    private static ValueTask<ToolResult> SystemStatusHandler(
        IReadOnlyDictionary<string, string> parameters, CancellationToken ct)
    {
        var process = System.Diagnostics.Process.GetCurrentProcess();
        var sb = new System.Text.StringBuilder(256);
        sb.AppendLine("System Status:");
        sb.AppendLine($"  Working set: {process.WorkingSet64 / (1024 * 1024)} MB");
        sb.AppendLine($"  GC Heap: {GC.GetTotalMemory(false) / (1024 * 1024)} MB");
        sb.AppendLine($"  GC collections: Gen0={GC.CollectionCount(0)}, Gen1={GC.CollectionCount(1)}, Gen2={GC.CollectionCount(2)}");
        sb.AppendLine($"  Uptime: {DateTime.UtcNow - process.StartTime.ToUniversalTime():hh\\:mm\\:ss}");
        sb.AppendLine($"  Threads: {process.Threads.Count}");
        sb.AppendLine($"  Entity count: {DataScaffold.Entities?.Count ?? 0}");
        return ValueTask.FromResult(ToolResult.Ok(sb.ToString()));
    }

    private static ValueTask<ToolResult> IndexStatusHandler(
        IReadOnlyDictionary<string, string> parameters, CancellationToken ct)
    {
        var sb = new System.Text.StringBuilder(128);
        sb.AppendLine("Search Index Status:");
        sb.AppendLine($"  Entity count: {DataScaffold.Entities?.Count ?? 0}");
        sb.AppendLine("  (Detailed index stats require SearchIndexManager integration)");
        return ValueTask.FromResult(ToolResult.Ok(sb.ToString()));
    }

    private static ValueTask<ToolResult> HelpHandler(
        IReadOnlyDictionary<string, string> parameters, CancellationToken ct)
    {
        var sb = new System.Text.StringBuilder(512);
        sb.AppendLine("Available commands:");
        sb.AppendLine("  • list entities     — Show all registered data entities");
        sb.AppendLine("  • describe <entity> — Show fields and metadata for an entity");
        sb.AppendLine("  • query <entity>    — Query records from an entity");
        sb.AppendLine("  • system status     — Show memory, GC, uptime diagnostics");
        sb.AppendLine("  • index status      — Show search index health");
        sb.AppendLine("  • help              — Show this help message");
        sb.AppendLine();
        sb.AppendLine("Architecture: Keyword intent classifier (fast path) + BitNet ternary engine (complex queries)");
        return ValueTask.FromResult(ToolResult.Ok(sb.ToString()));
    }
}
