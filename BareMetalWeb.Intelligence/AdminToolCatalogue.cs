using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Intelligence.Interfaces;
using BareMetalWeb.Runtime.CapabilityGraph;

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
        new("greeting",
            "Respond to a greeting or conversational opener",
            ["hi", "hello"]),

        new("farewell",
            "Respond to a farewell or closing message",
            ["bye", "goodbye"]),

        new("list-entities",
            "List all registered data entities",
            ["list", "entities", "types", "data", "models", "schema", "all"]),

        new("show-entity",
            "Show a specific entity record by ID or name",
            ["show", "display", "view", "open", "detail", "record", "item", "lookup"]),

        new("describe-entity",
            "Describe fields and metadata for a specific entity",
            ["describe", "fields", "schema", "metadata", "properties", "columns", "entity", "type", "model"]),

        new("query-entity",
            "Query records from a data entity",
            ["query", "find", "search", "get", "records", "rows", "data", "fetch", "where", "filter"]),

        new("count-entity",
            "Count records in a data entity",
            ["count", "how", "many", "total", "number"]),

        new("system-status",
            "Show system status and diagnostics",
            ["status", "health", "diagnostics", "uptime", "memory", "system", "info"]),

        new("index-status",
            "Show search index health and statistics",
            ["index", "search", "reindex", "rebuild", "fragmentation", "statistics"]),

        new("help",
            "Show available commands and capabilities",
            ["help", "commands", "what", "can", "you", "do", "capabilities"]),

        new("plan-workflow",
            "Generate a multi-step workflow plan from natural language",
            ["plan", "workflow", "automate", "steps", "pipeline", "sequence", "batch", "multi", "chain"]),
    ];

    /// <summary>
    /// Register all admin tools into a ToolRegistry.
    /// Uses DataScaffold for entity metadata access.
    /// </summary>
    public static ToolRegistry CreateRegistry()
    {
        var registry = new ToolRegistry();

        registry.Register(
            "greeting",
            "Respond to a greeting",
            [],
            GreetingHandler);

        registry.Register(
            "farewell",
            "Respond to a farewell",
            [],
            FarewellHandler);

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
            "show-entity",
            "Show a specific entity record by ID or name",
            [
                new ToolParameter("entity", "Entity name or slug", true),
                new ToolParameter("query", "Record ID or name to search for", false),
            ],
            ShowEntityHandler);

        registry.Register(
            "query-entity",
            "Query records from a data entity",
            [
                new ToolParameter("entity", "Entity name or slug", true),
                new ToolParameter("query", "Optional search text to filter results", false),
                new ToolParameter("filterField", "Field name for structured filter", false),
                new ToolParameter("filterOp", "Filter operator (Equals, Contains, etc.)", false),
                new ToolParameter("filterValue", "Filter value", false),
                new ToolParameter("limit", "Max records to return", false),
            ],
            QueryEntityHandler);

        registry.Register(
            "count-entity",
            "Count records in a data entity",
            [
                new ToolParameter("entity", "Entity name or slug", true),
                new ToolParameter("filterField", "Field name for structured filter", false),
                new ToolParameter("filterOp", "Filter operator (Equals, Contains, etc.)", false),
                new ToolParameter("filterValue", "Filter value", false),
            ],
            CountEntityHandler);

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

        registry.Register(
            "plan-workflow",
            "Generate a multi-step workflow plan from natural language intent",
            [new ToolParameter("intent", "Natural language description of the workflow", true)],
            PlanWorkflowHandler);

        return registry;
    }

    private static ValueTask<ToolResult> GreetingHandler(
        IReadOnlyDictionary<string, string> parameters, CancellationToken ct)
    {
        return ValueTask.FromResult(ToolResult.Ok(
            "Hello! I can help you query data, manage entities, and perform system operations.\n" +
            "Type 'help' to see what I can do, or just ask me a question in plain English."));
    }

    private static ValueTask<ToolResult> FarewellHandler(
        IReadOnlyDictionary<string, string> parameters, CancellationToken ct)
    {
        return ValueTask.FromResult(ToolResult.Ok("Goodbye! Feel free to return anytime."));
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
            var entity = ResolveEntity(entityName);

            if (entity is null)
                return ValueTask.FromResult(ToolResult.Fail($"Entity '{entityName}' not found. Use 'list entities' to see available types."));

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

    private static async ValueTask<ToolResult> ShowEntityHandler(
        IReadOnlyDictionary<string, string> parameters, CancellationToken ct)
    {
        if (!parameters.TryGetValue("entity", out var entityName) || string.IsNullOrEmpty(entityName))
            return ToolResult.Fail("Please specify an entity name.");

        try
        {
            var entity = ResolveEntity(entityName);
            if (entity is null)
                return ToolResult.Fail($"Entity '{entityName}' not found. Use 'list entities' to see available types.");

            parameters.TryGetValue("query", out var searchText);

            // Try numeric ID first
            if (!string.IsNullOrWhiteSpace(searchText) && uint.TryParse(searchText.Trim(), out var id))
            {
                var item = await entity.Handlers.LoadAsync(id, ct).ConfigureAwait(false);
                if (item is null)
                    return ToolResult.Fail($"No {entity.Name} record found with ID {id}.");

                return ToolResult.Ok(FormatRecord(entity, item));
            }

            // Search by text across string fields
            if (!string.IsNullOrWhiteSpace(searchText))
            {
                var matches = await SearchByText(entity, searchText.Trim(), ct).ConfigureAwait(false);
                if (matches.Count == 0)
                    return ToolResult.Fail($"No {entity.Name} records found matching '{searchText}'.");

                if (matches.Count == 1)
                    return ToolResult.Ok(FormatRecord(entity, matches[0]));

                var sb = new System.Text.StringBuilder(512);
                sb.AppendLine($"Found {matches.Count} {entity.Name} records matching '{searchText}':");
                sb.AppendLine();
                foreach (var match in matches)
                    sb.AppendLine(FormatRecordSummary(entity, match));
                return ToolResult.Ok(sb.ToString());
            }

            return ToolResult.Fail($"Please specify an ID or name to look up. Example: 'show {entity.Slug} 65' or 'show {entity.Slug} John'.");
        }
        catch (Exception ex)
        {
            return ToolResult.Fail($"Show failed: {ex.GetType().Name}");
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
            var entity = ResolveEntity(entityName);
            if (entity is null)
                return ToolResult.Fail($"Entity '{entityName}' not found. Use 'list entities' to see available types.");

            // Build a structured filter if filterField/filterOp/filterValue are provided
            QueryDefinition? query = BuildFilterQuery(parameters);

            // If a search query is provided, search by text
            parameters.TryGetValue("query", out var searchText);
            if (!string.IsNullOrWhiteSpace(searchText))
            {
                var matches = await SearchByText(entity, searchText.Trim(), ct).ConfigureAwait(false);
                if (matches.Count == 0)
                    return ToolResult.Ok($"No {entity.Name} records found matching '{searchText}'.");

                var sb = new System.Text.StringBuilder(512);
                sb.AppendLine($"Found {matches.Count} {entity.Name} record(s) matching '{searchText}':");
                sb.AppendLine();
                foreach (var match in matches.Take(limit))
                    sb.AppendLine(FormatRecordSummary(entity, match));
                return ToolResult.Ok(sb.ToString());
            }

            var count = await entity.Handlers.CountAsync(query, ct).ConfigureAwait(false);
            var items = await entity.Handlers.QueryAsync(query, ct).ConfigureAwait(false);
            var list = items.Take(limit).ToList();

            var filterDesc = query != null ? " (filtered)" : "";
            var output = new System.Text.StringBuilder(256);
            output.AppendLine($"{entity.Name}{filterDesc}: {count} total records (showing {list.Count})");
            output.AppendLine();

            foreach (var item in list)
                output.AppendLine(FormatRecordSummary(entity, item));

            return ToolResult.Ok(output.ToString());
        }
        catch (Exception ex)
        {
            return ToolResult.Fail($"Query failed: {ex.GetType().Name}");
        }
    }

    private static async ValueTask<ToolResult> CountEntityHandler(
        IReadOnlyDictionary<string, string> parameters, CancellationToken ct)
    {
        if (!parameters.TryGetValue("entity", out var entityName) || string.IsNullOrEmpty(entityName))
            return ToolResult.Fail("Please specify an entity name.");

        try
        {
            var entity = ResolveEntity(entityName);
            if (entity is null)
                return ToolResult.Fail($"Entity '{entityName}' not found. Use 'list entities' to see available types.");

            QueryDefinition? query = BuildFilterQuery(parameters);
            var count = await entity.Handlers.CountAsync(query, ct).ConfigureAwait(false);

            var filterDesc = query != null ? " matching filter" : " total";
            return ToolResult.Ok($"{entity.Name}: {count} record(s){filterDesc}.");
        }
        catch (Exception ex)
        {
            return ToolResult.Fail($"Count failed: {ex.GetType().Name}");
        }
    }

    /// <summary>
    /// Builds a QueryDefinition from structured filter parameters, if present.
    /// </summary>
    private static QueryDefinition? BuildFilterQuery(IReadOnlyDictionary<string, string> parameters)
    {
        if (!parameters.TryGetValue("filterField", out var field) || string.IsNullOrWhiteSpace(field))
            return null;
        if (!parameters.TryGetValue("filterValue", out var value) || string.IsNullOrWhiteSpace(value))
            return null;

        parameters.TryGetValue("filterOp", out var opStr);
        if (!Enum.TryParse<QueryOperator>(opStr ?? "Equals", true, out var op))
            op = QueryOperator.Equals;

        return new QueryDefinition
        {
            Clauses = [new QueryClause { Field = field, Operator = op, Value = value }]
        };
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
        sb.AppendLine("  • list entities       — Show all registered data entities");
        sb.AppendLine("  • describe <entity>   — Show fields and metadata for an entity");
        sb.AppendLine("  • show <entity> <id>  — Show a record by numeric ID");
        sb.AppendLine("  • show <entity> <name>— Search for a record by name");
        sb.AppendLine("  • query <entity>      — Query records from an entity");
        sb.AppendLine("  • plan workflow       — Generate a multi-step workflow plan from natural language");
        sb.AppendLine("  • system status       — Show memory, GC, uptime diagnostics");
        sb.AppendLine("  • index status        — Show search index health");
        sb.AppendLine("  • help                — Show this help message");
        sb.AppendLine();
        sb.AppendLine("Entity names are flexible — singular/plural forms and abbreviations are accepted.");
        sb.AppendLine("Architecture: Keyword intent classifier (fast path) + BitNet ternary engine (complex queries)");
        return ValueTask.FromResult(ToolResult.Ok(sb.ToString()));
    }

    private static ValueTask<ToolResult> PlanWorkflowHandler(
        IReadOnlyDictionary<string, string> parameters, CancellationToken ct)
    {
        var graph = BareMetalWeb.Runtime.CapabilityGraph.CapabilityGraphRegistry.Current;
        if (graph == null)
            return ValueTask.FromResult(ToolResult.Fail("Capability graph not yet built — server is still initializing."));

        if (!parameters.TryGetValue("intent", out var intent) || string.IsNullOrWhiteSpace(intent))
        {
            // If no explicit "intent" parameter, concatenate all parameter values
            // (the orchestrator may pass the raw query as parameters)
            var sb = new System.Text.StringBuilder();
            foreach (var kvp in parameters)
                if (!string.IsNullOrWhiteSpace(kvp.Value))
                    sb.Append(kvp.Value).Append(' ');
            intent = sb.ToString().Trim();

            if (string.IsNullOrWhiteSpace(intent))
                return ValueTask.FromResult(ToolResult.Fail("Please describe the workflow you want to create."));
        }

        var planner = new WorkflowPlanner(graph);
        var plan = planner.GeneratePlan(intent);
        var output = WorkflowPlanner.FormatPlan(plan);

        return ValueTask.FromResult(plan.IsValid ? ToolResult.Ok(output) : ToolResult.Ok(output));
    }

    // ── Entity resolution helpers ──────────────────────────────────────────────

    /// <summary>
    /// Resolves an entity by exact slug, exact name, singular form (strips trailing 's'),
    /// or partial/prefix match. Returns null if no match found.
    /// </summary>
    private static DataEntityMetadata? ResolveEntity(string input)
    {
        var entities = DataScaffold.Entities;
        if (entities is null || entities.Count == 0) return null;

        // Exact slug or name match
        foreach (var e in entities)
        {
            if (string.Equals(e.Slug, input, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(e.Name, input, StringComparison.OrdinalIgnoreCase))
                return e;
        }

        // Singular → plural: try appending 's'
        var plural = input + "s";
        foreach (var e in entities)
        {
            if (string.Equals(e.Slug, plural, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(e.Name, plural, StringComparison.OrdinalIgnoreCase))
                return e;
        }

        // Plural → singular: try stripping trailing 's', 'es', 'ies'→'y'
        if (input.Length > 3 && input.EndsWith("ies", StringComparison.OrdinalIgnoreCase))
        {
            var singular = input[..^3] + "y";
            foreach (var e in entities)
                if (string.Equals(e.Slug, singular, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(e.Name, singular, StringComparison.OrdinalIgnoreCase))
                    return e;
        }
        else if (input.Length > 2 && input.EndsWith("es", StringComparison.OrdinalIgnoreCase))
        {
            var singular = input[..^2];
            foreach (var e in entities)
                if (string.Equals(e.Slug, singular, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(e.Name, singular, StringComparison.OrdinalIgnoreCase))
                    return e;
        }
        else if (input.Length > 1 && input.EndsWith('s'))
        {
            var singular = input[..^1];
            foreach (var e in entities)
                if (string.Equals(e.Slug, singular, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(e.Name, singular, StringComparison.OrdinalIgnoreCase))
                    return e;
        }

        // Prefix/contains match (e.g. "cust" matches "customers")
        foreach (var e in entities)
        {
            if (e.Slug.StartsWith(input, StringComparison.OrdinalIgnoreCase) ||
                e.Name.StartsWith(input, StringComparison.OrdinalIgnoreCase))
                return e;
        }

        foreach (var e in entities)
        {
            if (e.Slug.Contains(input, StringComparison.OrdinalIgnoreCase) ||
                e.Name.Contains(input, StringComparison.OrdinalIgnoreCase))
                return e;
        }

        return null;
    }

    /// <summary>
    /// Searches records by text, matching against all string-type fields.
    /// </summary>
    private static async Task<List<BaseDataObject>> SearchByText(
        DataEntityMetadata entity, string searchText, CancellationToken ct)
    {
        var items = await entity.Handlers.QueryAsync(null, ct).ConfigureAwait(false);
        var layout = EntityLayoutCompiler.GetOrCompile(entity);
        var matches = new List<BaseDataObject>();

        // Find string-type fields to search against
        var stringFields = new List<FieldRuntime>();
        foreach (var f in layout.Fields)
        {
            if (f.ClrType == typeof(string))
                stringFields.Add(f);
        }

        foreach (var item in items)
        {
            foreach (var field in stringFields)
            {
                try
                {
                    var val = field.Getter(item)?.ToString();
                    if (val != null && val.Contains(searchText, StringComparison.OrdinalIgnoreCase))
                    {
                        matches.Add(item);
                        break;
                    }
                }
                catch { }
            }

            if (matches.Count >= 25) break;
        }

        return matches;
    }

    /// <summary>
    /// Formats a single record with all field values for detailed display.
    /// </summary>
    private static string FormatRecord(DataEntityMetadata entity, BaseDataObject item)
    {
        var layout = EntityLayoutCompiler.GetOrCompile(entity);
        var sb = new System.Text.StringBuilder(512);
        sb.AppendLine($"{entity.Name} #{item.Key}  → /{entity.Slug}/{item.Key}");
        sb.AppendLine();

        foreach (var field in layout.Fields)
        {
            try
            {
                var val = field.Getter(item);
                sb.AppendLine($"  {field.Name}: {val ?? "(empty)"}");
            }
            catch { sb.AppendLine($"  {field.Name}: (error reading)"); }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Formats a record as a one-line summary showing key identifying fields.
    /// </summary>
    private static string FormatRecordSummary(DataEntityMetadata entity, BaseDataObject item)
    {
        var layout = EntityLayoutCompiler.GetOrCompile(entity);
        var parts = new List<string>(6);

        int shown = 0;
        foreach (var field in layout.Fields)
        {
            if (shown >= 4) break;
            try
            {
                var val = field.Getter(item);
                if (val != null)
                {
                    var str = val.ToString();
                    if (!string.IsNullOrWhiteSpace(str))
                    {
                        parts.Add($"{field.Name}={str}");
                        shown++;
                    }
                }
            }
            catch { }
        }

        return $"  [{item.Key}] {string.Join(", ", parts)}  → /{entity.Slug}/{item.Key}";
    }
}
