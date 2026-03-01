using System.Collections.Concurrent;
using System.Text.Json;
using BareMetalWeb.Core;
using BareMetalWeb.Data;
using Microsoft.AspNetCore.Http;

namespace BareMetalWeb.Host;

/// <summary>
/// HTTP handlers for the Action & Transaction engine.
/// POST /api/_binary/{type}/_action/{actionId} — execute an action
/// GET /api/_binary/{type}/_actions — list registered actions
/// </summary>
public static class ActionApiHandlers
{
    private static readonly ConcurrentDictionary<string, ActionDef> _actions = new(StringComparer.OrdinalIgnoreCase);
    private static AggregateLockManager? _lockManager;
    private static TransactionCommitEngine? _commitEngine;

    /// <summary>Initialize the action subsystem.</summary>
    public static void Initialize()
    {
        _lockManager = new AggregateLockManager();
        _commitEngine = new TransactionCommitEngine(_lockManager);
    }

    /// <summary>Register an action definition.</summary>
    public static void RegisterAction(ActionDef action)
    {
        var key = $"{action.AggregateType}:{action.ActionId}";
        _actions[key] = action;
    }

    /// <summary>Resolve an action by composite key (type:actionId).</summary>
    public static ActionDef? ResolveAction(string compositeKey)
        => _actions.TryGetValue(compositeKey, out var action) ? action : null;

    /// <summary>
    /// POST /api/_binary/{type}/_action/{actionId}
    /// Body (JSON): { "aggregateId": 123, "parameters": { "key": "value", ... } }
    /// </summary>
    public static async ValueTask ExecuteActionHandler(HttpContext context)
    {
        if (_commitEngine == null)
        {
            await WriteError(context, 500, "Action engine not initialized.");
            return;
        }

        var typeSlug = BinaryApiHandlers.GetRouteValue(context, "type") ?? string.Empty;
        var actionId = BinaryApiHandlers.GetRouteValue(context, "actionId") ?? string.Empty;

        if (string.IsNullOrWhiteSpace(typeSlug) || string.IsNullOrWhiteSpace(actionId))
        {
            await WriteError(context, 400, "Entity type and action ID required.");
            return;
        }

        var compositeKey = $"{typeSlug}:{actionId}";
        var action = ResolveAction(compositeKey);
        if (action == null)
        {
            await WriteError(context, 404, $"Action '{actionId}' not found for entity type '{typeSlug}'.");
            return;
        }

        // Auth
        var user = await UserAuth.GetRequestUserAsync(context, context.RequestAborted);
        var userName = user?.UserName ?? "anonymous";

        // Parse request body
        uint aggregateId;
        Dictionary<string, object?>? parameters = null;

        try
        {
            using var doc = await JsonDocument.ParseAsync(context.Request.Body, cancellationToken: context.RequestAborted);
            var root = doc.RootElement;

            if (!root.TryGetProperty("aggregateId", out var idEl))
            {
                await WriteError(context, 400, "aggregateId is required.");
                return;
            }
            aggregateId = idEl.GetUInt32();

            if (root.TryGetProperty("parameters", out var paramsEl) && paramsEl.ValueKind == JsonValueKind.Object)
            {
                parameters = new Dictionary<string, object?>();
                foreach (var prop in paramsEl.EnumerateObject())
                {
                    parameters[prop.Name] = prop.Value.ValueKind switch
                    {
                        JsonValueKind.String => prop.Value.GetString(),
                        JsonValueKind.Number => prop.Value.TryGetInt64(out var l) ? l : prop.Value.GetDouble(),
                        JsonValueKind.True => true,
                        JsonValueKind.False => false,
                        JsonValueKind.Null => null,
                        _ => prop.Value.GetRawText(),
                    };
                }
            }
        }
        catch (JsonException)
        {
            await WriteError(context, 400, "Invalid JSON request body.");
            return;
        }

        try
        {
            var result = await _commitEngine.ExecuteActionAsync(
                action, aggregateId, parameters, ResolveAction, userName, context.RequestAborted);

            context.Response.StatusCode = result.Success ? 200 : 422;
            context.Response.ContentType = "application/json";
            await using var writer = new Utf8JsonWriter(context.Response.Body);
            writer.WriteStartObject();
            writer.WriteBoolean("success", result.Success);
            if (result.ErrorCode != null) writer.WriteString("errorCode", result.ErrorCode);
            if (result.ErrorMessage != null) writer.WriteString("errorMessage", result.ErrorMessage);
            if (result.Warnings is { Count: > 0 })
            {
                writer.WriteStartArray("warnings");
                foreach (var w in result.Warnings)
                {
                    writer.WriteStartObject();
                    writer.WriteString("code", w.Code);
                    writer.WriteString("message", w.Message);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();
            }
            writer.WriteEndObject();
            await writer.FlushAsync(context.RequestAborted);
        }
        catch (TimeoutException)
        {
            await WriteError(context, 409, "Lock acquisition timed out. Retry later.");
        }
        catch (Exception ex)
        {
            await WriteError(context, 500, $"Error executing action: {ex.Message}");
        }
    }

    /// <summary>
    /// GET /api/_binary/{type}/_actions
    /// Returns list of registered actions for the entity type.
    /// </summary>
    public static async ValueTask ListActionsHandler(HttpContext context)
    {
        var typeSlug = BinaryApiHandlers.GetRouteValue(context, "type") ?? string.Empty;

        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/json";
        await using var writer = new Utf8JsonWriter(context.Response.Body);
        writer.WriteStartObject();
        writer.WriteStartArray("actions");

        foreach (var (key, action) in _actions)
        {
            if (!string.Equals(action.AggregateType, typeSlug, StringComparison.OrdinalIgnoreCase))
                continue;

            writer.WriteStartObject();
            writer.WriteString("actionId", action.ActionId);
            writer.WriteString("aggregateType", action.AggregateType);
            writer.WriteNumber("version", action.Version);
            writer.WriteNumber("commandCount", action.Commands.Length);
            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
        await writer.FlushAsync(context.RequestAborted);
    }

    public static int RegisteredActionCount => _actions.Count;
    public static AggregateLockManager? LockManager => _lockManager;

    private static async ValueTask WriteError(HttpContext context, int statusCode, string message)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        await using var writer = new Utf8JsonWriter(context.Response.Body);
        writer.WriteStartObject();
        writer.WriteBoolean("success", false);
        writer.WriteString("errorMessage", message);
        writer.WriteEndObject();
        await writer.FlushAsync(context.RequestAborted);
    }
}
