using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using BareMetalWeb.Runtime;
using BareMetalWeb.Rendering.Models;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// Implements a minimal MCP (Model Context Protocol) server over HTTP.
/// Exposes all registered BareMetalWeb entity CRUD operations and named commands
/// as MCP tools, enabling AI assistants to query and mutate application data
/// via the standard MCP protocol (JSON-RPC 2.0 over HTTP).
///
/// Endpoint: POST /mcp
///
/// Supported MCP methods:
///   initialize    — Capability negotiation
///   initialized   — Client acknowledgment (notification, no response)
///   ping          — Keepalive
///   tools/list    — Enumerate available tools
///   tools/call    — Execute a tool (query, get, create, update, delete, command)
///   resources/list — Returns empty list (data is accessed via tools)
///   prompts/list  — Returns empty list
/// </summary>
internal static class McpRouteHandler
{
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private const string ProtocolVersion = "2024-11-05";
    private const string ServerName = "BareMetalWeb";

    // ── Entry point ───────────────────────────────────────────────────────────

    internal static async ValueTask HandleAsync(BmwContext context)
    {
        context.Response.ContentType = "application/json";

        // Require authentication — MCP tools expose full CRUD operations
        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted);
        if (user == null)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync(
                "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Authentication required\"}}",
                context.RequestAborted).ConfigureAwait(false);
            return;
        }

        // Body size limit
        if (context.HttpRequest.ContentLength.HasValue && context.HttpRequest.ContentLength.Value > 10 * 1024 * 1024)
        {
            context.Response.StatusCode = 413;
            await context.Response.WriteAsync(
                "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32600,\"message\":\"Request body too large\"}}",
                context.RequestAborted).ConfigureAwait(false);
            return;
        }

        string body;
        using (var reader = new System.IO.StreamReader(context.HttpRequest.Body))
            body = await reader.ReadToEndAsync(context.RequestAborted).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(body))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync(
                "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error: empty body\"}}",
                context.RequestAborted).ConfigureAwait(false);
            return;
        }

        JsonDocument? doc = null;
        try
        {
            doc = JsonDocument.Parse(body);
            await DispatchRequestAsync(context, doc.RootElement).ConfigureAwait(false);
        }
        catch (JsonException)
        {
            context.Response.StatusCode = 400;
            await WriteRawAsync(context, BuildErrorEnvelope(null, -32700, "Parse error"))
                .ConfigureAwait(false);
        }
        finally
        {
            doc?.Dispose();
        }
    }

    // ── Dispatch ──────────────────────────────────────────────────────────────

    private static async Task DispatchRequestAsync(BmwContext context, JsonElement root)
    {
        // JSON-RPC notifications (no "id") — acknowledge with 202, no body
        bool hasId = root.TryGetProperty("id", out var id);
        if (!hasId)
        {
            context.Response.StatusCode = 202;
            return;
        }

        var method = root.TryGetProperty("method", out var mp) ? mp.GetString() ?? string.Empty : string.Empty;
        var @params = root.TryGetProperty("params", out var pp) ? pp : default;

        try
        {
            var result = method switch
            {
                "initialize" => BuildInitializeResult(),
                "ping" => (object)new { },
                "tools/list" => BuildToolsList(),
                "tools/call" => await ExecuteToolCallAsync(@params, context.RequestAborted).ConfigureAwait(false),
                "resources/list" => new { resources = Array.Empty<object>() },
                "prompts/list" => new { prompts = Array.Empty<object>() },
                _ => null
            };

            if (result is null)
            {
                await WriteRawAsync(context, BuildErrorEnvelope(id, -32601, $"Method not found: {method}"))
                    .ConfigureAwait(false);
                return;
            }

            await WriteRawAsync(context, BuildSuccessEnvelope(id, result)).ConfigureAwait(false);
        }
        catch (Exception)
        {
            await WriteRawAsync(context, BuildErrorEnvelope(id, -32603, "Internal error"))
                .ConfigureAwait(false);
        }
    }

    // ── MCP method handlers ───────────────────────────────────────────────────

    private static object BuildInitializeResult()
    {
        // Use Assembly.GetName().Version — no reflection attribute scanning needed.
        var version = typeof(McpRouteHandler).Assembly.GetName().Version;
        var serverVersion = version != null ? $"{version.Major}.{version.Minor}.{version.Build}" : "1.0";

        return new
        {
            protocolVersion = ProtocolVersion,
            capabilities = new
            {
                tools = new { },
                resources = new { }
            },
            serverInfo = new { name = ServerName, version = serverVersion }
        };
    }

    private static object BuildToolsList()
    {
        var tools = new List<Dictionary<string, object?>>();

        foreach (var entity in DataScaffold.Entities)
        {
            var slug = ToToolSegment(entity.Slug);
            var name = entity.Name;

            // Field map for create/update input schemas
            var writableFields = new List<DataFieldMetadata>();
            foreach (var f in entity.Fields)
            {
                if (f.FieldType != FormFieldType.CustomHtml
                    && f.FieldType != FormFieldType.Button
                    && f.FieldType != FormFieldType.Link
                    && !f.ReadOnly)
                {
                    writableFields.Add(f);
                }
            }

            var fieldProps = BuildFieldProperties(writableFields);
            var requiredCreateList = new List<string>();
            foreach (var f in writableFields)
            {
                if (f.Required && f.Create)
                    requiredCreateList.Add(f.Name);
            }
            var requiredCreateFields = requiredCreateList.ToArray();

            // query_{slug}
            tools.Add(MakeTool(
                $"query_{slug}",
                $"Query {name} records with optional filters. Returns a list of matching {name} objects.",
                new Dictionary<string, object?>
                {
                    ["type"] = "object",
                    ["properties"] = new Dictionary<string, object?>
                    {
                        ["filters"] = new Dictionary<string, object?>
                        {
                            ["type"] = "array",
                            ["description"] = "Optional AND-combined filter conditions",
                            ["items"] = new Dictionary<string, object?>
                            {
                                ["type"] = "object",
                                ["properties"] = new Dictionary<string, object?>
                                {
                                    ["field"] = new Dictionary<string, object?> { ["type"] = "string", ["description"] = "Field name" },
                                    ["operator"] = new Dictionary<string, object?> { ["type"] = "string", ["enum"] = new[] { "Equals", "NotEquals", "Contains", "StartsWith", "EndsWith", "In", "NotIn", "GreaterThan", "LessThan", "GreaterThanOrEqual", "LessThanOrEqual" } },
                                    ["value"] = new Dictionary<string, object?> { ["type"] = "string", ["description"] = "Value to compare against" }
                                },
                                ["required"] = new[] { "field", "operator", "value" }
                            }
                        },
                        ["top"] = new Dictionary<string, object?> { ["type"] = "integer", ["description"] = "Maximum records to return (default 50, max 200)", ["default"] = 50 }
                    }
                }));

            // get_{slug}
            tools.Add(MakeTool(
                $"get_{slug}",
                $"Retrieve a single {name} record by its ID.",
                new Dictionary<string, object?>
                {
                    ["type"] = "object",
                    ["properties"] = new Dictionary<string, object?> { ["id"] = new Dictionary<string, object?> { ["type"] = "string", ["description"] = $"The ID of the {name} record" } },
                    ["required"] = new[] { "id" }
                }));

            // create_{slug}
            tools.Add(MakeTool(
                $"create_{slug}",
                $"Create a new {name} record.",
                new Dictionary<string, object?>
                {
                    ["type"] = "object",
                    ["properties"] = (object)fieldProps,
                    ["required"] = requiredCreateFields.Length > 0 ? (object)requiredCreateFields : Array.Empty<string>()
                }));

            // update_{slug}
            var updateProps = new Dictionary<string, object?>(fieldProps)
            {
                ["id"] = new Dictionary<string, object?> { ["type"] = "string", ["description"] = $"The ID of the {name} record to update" }
            };
            tools.Add(MakeTool(
                $"update_{slug}",
                $"Update fields on an existing {name} record.",
                new Dictionary<string, object?>
                {
                    ["type"] = "object",
                    ["properties"] = (object)updateProps,
                    ["required"] = new[] { "id" }
                }));

            // delete_{slug}
            tools.Add(MakeTool(
                $"delete_{slug}",
                $"Delete a {name} record by its ID.",
                new Dictionary<string, object?>
                {
                    ["type"] = "object",
                    ["properties"] = new Dictionary<string, object?> { ["id"] = new Dictionary<string, object?> { ["type"] = "string", ["description"] = $"The ID of the {name} record to delete" } },
                    ["required"] = new[] { "id" }
                }));

            // command_{slug}_{actionName} for each RemoteCommand
            foreach (var cmd in entity.Commands)
            {
                var cmdNameSlug = ToToolSegment(cmd.Name);
                var description = $"Execute the '{cmd.Label}' action on a {name} record.";
                if (!string.IsNullOrWhiteSpace(cmd.ConfirmMessage))
                    description += $" ({cmd.ConfirmMessage})";

                tools.Add(MakeTool(
                    $"command_{slug}_{cmdNameSlug}",
                    description,
                    new Dictionary<string, object?>
                    {
                        ["type"] = "object",
                        ["properties"] = new Dictionary<string, object?> { ["id"] = new Dictionary<string, object?> { ["type"] = "string", ["description"] = $"The ID of the {name} record" } },
                        ["required"] = new[] { "id" }
                    }));
            }
        }

        return new { tools };
    }

    private static async ValueTask<object> ExecuteToolCallAsync(JsonElement @params, CancellationToken ct)
    {
        if (@params.ValueKind != JsonValueKind.Object)
            return BuildToolErrorResult("Invalid params: expected an object.");

        var toolName = @params.TryGetProperty("name", out var np) ? np.GetString() ?? string.Empty : string.Empty;
        if (string.IsNullOrWhiteSpace(toolName))
            return BuildToolErrorResult("Tool name is required.");

        var arguments = @params.TryGetProperty("arguments", out var ap) ? ap : default;

        if (toolName.StartsWith("query_", StringComparison.Ordinal))
            return await ExecuteQueryAsync(toolName["query_".Length..], arguments, ct).ConfigureAwait(false);

        if (toolName.StartsWith("get_", StringComparison.Ordinal))
            return await ExecuteGetAsync(toolName["get_".Length..], arguments, ct).ConfigureAwait(false);

        if (toolName.StartsWith("create_", StringComparison.Ordinal))
            return await ExecuteCreateAsync(toolName["create_".Length..], arguments, ct).ConfigureAwait(false);

        if (toolName.StartsWith("update_", StringComparison.Ordinal))
            return await ExecuteUpdateAsync(toolName["update_".Length..], arguments, ct).ConfigureAwait(false);

        if (toolName.StartsWith("delete_", StringComparison.Ordinal))
            return await ExecuteDeleteAsync(toolName["delete_".Length..], arguments, ct).ConfigureAwait(false);

        if (toolName.StartsWith("command_", StringComparison.Ordinal))
            return await ExecuteCommandAsync(toolName["command_".Length..], arguments, ct).ConfigureAwait(false);

        return BuildToolErrorResult($"Unknown tool: '{toolName}'. Use tools/list to see available tools.");
    }

    // ── Tool implementations ──────────────────────────────────────────────────

    private static async ValueTask<object> ExecuteQueryAsync(
        string slugSegment, JsonElement arguments, CancellationToken ct)
    {
        var slug = FromToolSegment(slugSegment);
        if (!DataScaffold.TryGetEntity(slug, out _))
            return BuildToolErrorResult("Entity not found.");

        var query = BuildQueryDefinition(arguments);
        var svc = new QueryService();
        var results = await svc.QueryAsync(slug, query, ct).ConfigureAwait(false);
        var list = new List<Dictionary<string, object?>>();
        foreach (var item in results)
            list.Add(item);
        return BuildToolTextResult(JsonSerializer.Serialize(list, _jsonOptions));
    }

    private static async ValueTask<object> ExecuteGetAsync(
        string slugSegment, JsonElement arguments, CancellationToken ct)
    {
        var slug = FromToolSegment(slugSegment);
        if (!DataScaffold.TryGetEntity(slug, out _))
            return BuildToolErrorResult("Entity not found.");

        var id = GetStringArg(arguments, "id");
        if (string.IsNullOrWhiteSpace(id))
            return BuildToolErrorResult("Argument 'id' is required.");

        var svc = new QueryService();
        var item = await svc.GetByIdAsync(slug, id, ct).ConfigureAwait(false);
        if (item is null)
            return BuildToolErrorResult("Record not found.");

        return BuildToolTextResult(JsonSerializer.Serialize(item, _jsonOptions));
    }

    private static async ValueTask<object> ExecuteCreateAsync(
        string slugSegment, JsonElement arguments, CancellationToken ct)
    {
        var slug = FromToolSegment(slugSegment);
        var fields = ExtractStringFields(arguments);
        var svc = new CommandService();
        var result = await svc.ExecuteAsync(
            new CommandIntent { EntitySlug = slug, Operation = "create", Fields = fields }, ct)
            .ConfigureAwait(false);

        return result.Success
            ? BuildToolTextResult(JsonSerializer.Serialize(new { id = result.EntityId, data = result.Data }, _jsonOptions))
            : BuildToolErrorResult(result.Error ?? "Create failed.");
    }

    private static async ValueTask<object> ExecuteUpdateAsync(
        string slugSegment, JsonElement arguments, CancellationToken ct)
    {
        var slug = FromToolSegment(slugSegment);
        var id = GetStringArg(arguments, "id");
        if (string.IsNullOrWhiteSpace(id))
            return BuildToolErrorResult("Argument 'id' is required.");

        var fields = ExtractStringFields(arguments);
        fields.Remove("id");

        var svc = new CommandService();
        var result = await svc.ExecuteAsync(
            new CommandIntent { EntitySlug = slug, EntityId = id, Operation = "update", Fields = fields }, ct)
            .ConfigureAwait(false);

        return result.Success
            ? BuildToolTextResult(JsonSerializer.Serialize(new { id = result.EntityId, data = result.Data }, _jsonOptions))
            : BuildToolErrorResult(result.Error ?? "Update failed.");
    }

    private static async ValueTask<object> ExecuteDeleteAsync(
        string slugSegment, JsonElement arguments, CancellationToken ct)
    {
        var slug = FromToolSegment(slugSegment);
        var id = GetStringArg(arguments, "id");
        if (string.IsNullOrWhiteSpace(id))
            return BuildToolErrorResult("Argument 'id' is required.");

        var svc = new CommandService();
        var result = await svc.ExecuteAsync(
            new CommandIntent { EntitySlug = slug, EntityId = id, Operation = "delete" }, ct)
            .ConfigureAwait(false);

        return result.Success
            ? BuildToolTextResult($"Deleted '{slug}' record '{id}' successfully.")
            : BuildToolErrorResult(result.Error ?? "Delete failed.");
    }

    private static async ValueTask<object> ExecuteCommandAsync(
        string remainder, JsonElement arguments, CancellationToken ct)
    {
        // remainder = "{slug}_{actionName}" — find the right split by matching known entity slugs
        var (slug, actionName) = SplitSlugAndAction(remainder);
        if (slug is null || actionName is null)
            return BuildToolErrorResult($"Could not resolve entity/action from '{remainder}'.");

        var id = GetStringArg(arguments, "id");
        if (string.IsNullOrWhiteSpace(id))
            return BuildToolErrorResult("Argument 'id' is required.");

        var svc = new CommandService();
        var result = await svc.ExecuteAsync(
            new CommandIntent { EntitySlug = slug, EntityId = id, Operation = actionName }, ct)
            .ConfigureAwait(false);

        return result.Success
            ? BuildToolTextResult(JsonSerializer.Serialize(new { id = result.EntityId, data = result.Data }, _jsonOptions))
            : BuildToolErrorResult(result.Error ?? "Command failed.");
    }

    // ── Helper: build QueryDefinition from arguments JSON ─────────────────────

    private static QueryDefinition? BuildQueryDefinition(JsonElement arguments)
    {
        if (arguments.ValueKind != JsonValueKind.Object)
            return null;

        var clauses = new List<QueryClause>();

        if (arguments.TryGetProperty("filters", out var filtersProp)
            && filtersProp.ValueKind == JsonValueKind.Array)
        {
            foreach (var f in filtersProp.EnumerateArray())
            {
                var field = f.TryGetProperty("field", out var fp) ? fp.GetString() ?? string.Empty : string.Empty;
                var opStr = f.TryGetProperty("operator", out var opp) ? opp.GetString() ?? "Equals" : "Equals";
                var value = f.TryGetProperty("value", out var vp) ? vp.GetString() ?? string.Empty : string.Empty;

                if (string.IsNullOrWhiteSpace(field))
                    continue;

                clauses.Add(new QueryClause
                {
                    Field = field,
                    Operator = Enum.TryParse<QueryOperator>(opStr, ignoreCase: true, out var qop)
                        ? qop
                        : QueryOperator.Equals,
                    Value = value
                });
            }
        }

        int top = 50;
        if (arguments.TryGetProperty("top", out var topProp) && topProp.TryGetInt32(out var topVal))
            top = Math.Min(Math.Max(1, topVal), 200);

        if (clauses.Count == 0 && top == 50)
            return null; // no constraints — load all (respects any default limit in the store)

        return new QueryDefinition { Clauses = clauses, Top = top };
    }

    // ── Helper: extract string fields from arguments ───────────────────────────

    private static Dictionary<string, string?> ExtractStringFields(JsonElement arguments)
    {
        var result = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        if (arguments.ValueKind != JsonValueKind.Object)
            return result;

        foreach (var prop in arguments.EnumerateObject())
        {
            result[prop.Name] = prop.Value.ValueKind switch
            {
                JsonValueKind.String => prop.Value.GetString(),
                JsonValueKind.Null => null,
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => prop.Value.ToString()
            };
        }

        return result;
    }

    private static string? GetStringArg(JsonElement arguments, string key)
    {
        if (arguments.ValueKind == JsonValueKind.Object
            && arguments.TryGetProperty(key, out var prop))
        {
            return prop.ValueKind == JsonValueKind.String ? prop.GetString() : prop.ToString();
        }
        return null;
    }

    // ── Helper: slug/action splitting for command tools ────────────────────────

    /// <summary>
    /// Given a string like "orders_approve", tries all registered entity slugs
    /// (longest-prefix-first) to find the slug/action split.
    /// </summary>
    private static (string? slug, string? action) SplitSlugAndAction(string remainder)
    {
        // Scan all entities and pick the longest matching prefix to handle slugs containing underscores.
        string? bestSlug = null;
        string? bestAction = null;

        foreach (var entity in DataScaffold.Entities)
        {
            var prefix = ToToolSegment(entity.Slug) + "_";
            if (remainder.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                && remainder.Length > prefix.Length
                && (bestSlug is null || prefix.Length > ToToolSegment(bestSlug).Length + 1))
            {
                bestSlug = entity.Slug;
                bestAction = remainder[prefix.Length..];
            }
        }

        return (bestSlug, bestAction);
    }

    // ── Helper: tool name segment normalisation ────────────────────────────────

    /// <summary>Normalises a slug/name for use as part of an MCP tool name (lowercase, hyphens→underscores).</summary>
    private static string ToToolSegment(string value)
        => value.ToLowerInvariant().Replace('-', '_').Replace(' ', '_');

    /// <summary>Reverses <see cref="ToToolSegment"/> (best effort — looks up original slug in DataScaffold).</summary>
    private static string FromToolSegment(string segment)
    {
        // Try exact match first (most common)
        if (DataScaffold.TryGetEntity(segment, out _))
            return segment;

        // Try matching with original slug casing
        DataEntityMetadata? match = null;
        foreach (var e in DataScaffold.Entities)
        {
            if (string.Equals(ToToolSegment(e.Slug), segment, StringComparison.OrdinalIgnoreCase))
            {
                match = e;
                break;
            }
        }

        return match?.Slug ?? segment;
    }

    // ── Helper: build JSON Schema properties from field metadata ──────────────

    private static Dictionary<string, object?> BuildFieldProperties(IEnumerable<DataFieldMetadata> fields)
    {
        var props = new Dictionary<string, object?>();
        foreach (var f in fields)
        {
            var schema = new Dictionary<string, object?>
            {
                ["type"] = MapToJsonSchemaType(f.FieldType),
                ["description"] = f.Label
            };

            if (f.FieldType == FormFieldType.Enum && f.Property.PropertyType.IsEnum)
            {
                schema["enum"] = Enum.GetNames(f.Property.PropertyType);
            }

            props[f.Name] = schema;
        }
        return props;
    }

    private static string MapToJsonSchemaType(FormFieldType fieldType) => fieldType switch
    {
        FormFieldType.Integer => "integer",
        FormFieldType.Decimal or FormFieldType.Money => "number",
        FormFieldType.YesNo => "boolean",
        _ => "string"
    };

    // ── Helper: MCP tool result builders ─────────────────────────────────────

    private static object BuildToolTextResult(string text) => new
    {
        content = new[] { new { type = "text", text } }
    };

    private static object BuildToolErrorResult(string message) => new
    {
        content = new[] { new { type = "text", text = message } },
        isError = true
    };

    // ── Helper: build MCP tool descriptor ─────────────────────────────────────

    private static Dictionary<string, object?> MakeTool(
        string name, string description, Dictionary<string, object?> inputSchema)
        => new()
        {
            ["name"] = name,
            ["description"] = description,
            ["inputSchema"] = inputSchema
        };

    // ── Helper: JSON-RPC envelope builders ───────────────────────────────────

    private static string BuildSuccessEnvelope(JsonElement id, object result)
        => JsonSerializer.Serialize(new
        {
            jsonrpc = "2.0",
            id = id,
            result
        }, _jsonOptions);

    private static string BuildErrorEnvelope(
        JsonElement? id, int code, string message, string? data = null)
    {
        var error = data is null
            ? (object)new { code, message }
            : new { code, message, data };

        return JsonSerializer.Serialize(new
        {
            jsonrpc = "2.0",
            id = id,
            error
        }, _jsonOptions);
    }

    private static Task WriteRawAsync(BmwContext context, string json)
        => context.Response.WriteAsync(json, context.RequestAborted);
}
