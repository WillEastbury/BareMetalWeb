using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using BareMetalWeb.Data;
using BareMetalWeb.Core;
using BareMetalWeb.Host;

namespace BareMetalWeb.API;

public sealed class ApiRouteHandlers : IApiRouteHandlers
{
    private readonly Func<HttpContext, User?> _getUser;

    public ApiRouteHandlers(Func<HttpContext, User?> getUser)
    {
        _getUser = getUser ?? throw new ArgumentNullException(nameof(getUser));
    }
    public async ValueTask DataApiListHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        if (meta == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Entity not found.");
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        var query = DataScaffold.BuildQueryDefinition(ToQueryDictionary(context.Request.Query), meta);
        var results = await DataScaffold.QueryAsync(meta, query);
        var payload = results.Cast<object>().Select(item => BuildApiModel(meta, item)).ToArray();

        await WriteJsonResponseAsync(context, payload);
    }

    public async ValueTask DataApiGetHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        var id = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(id))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Entity not found.");
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, id);
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Item not found.");
            return;
        }

        await WriteJsonResponseAsync(context, BuildApiModel(meta, instance));
    }

    public async ValueTask DataApiPostHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        if (meta == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Entity not found.");
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        var payload = await ReadJsonBodyAsync(context);
        if (payload == null)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid JSON body.");
            return;
        }

        var instance = meta.Handlers.Create();

        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, payload, forCreate: true, allowMissing: false);
        if (errors.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync(string.Join(" | ", errors));
            return;
        }

        ApplyAuditInfo(instance, context, isCreate: true);
        await DataScaffold.SaveAsync(meta, instance);
        context.Response.StatusCode = StatusCodes.Status201Created;
        await WriteJsonResponseAsync(context, BuildApiModel(meta, instance));
    }

    public async ValueTask DataApiPutHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        var id = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(id))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Entity not found.");
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        var payload = await ReadJsonBodyAsync(context);
        if (payload == null)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid JSON body.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, id);
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Item not found.");
            return;
        }

        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, payload, forCreate: false, allowMissing: false);
        if (errors.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync(string.Join(" | ", errors));
            return;
        }

        ApplyAuditInfo(instance, context, isCreate: false);
        await DataScaffold.SaveAsync(meta, instance);
        await WriteJsonResponseAsync(context, BuildApiModel(meta, instance));
    }

    public async ValueTask DataApiPatchHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        var id = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(id))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Entity not found.");
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        var payload = await ReadJsonBodyAsync(context);
        if (payload == null)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync("Invalid JSON body.");
            return;
        }

        var instance = await DataScaffold.LoadAsync(meta, id);
        if (instance == null)
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync("Item not found.");
            return;
        }

        var errors = DataScaffold.ApplyValuesFromJson(meta, instance, payload, forCreate: false, allowMissing: true);
        if (errors.Count > 0)
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            await context.Response.WriteAsync(string.Join(" | ", errors));
            return;
        }

        ApplyAuditInfo(instance, context, isCreate: false);
        await DataScaffold.SaveAsync(meta, instance);
        await WriteJsonResponseAsync(context, BuildApiModel(meta, instance));
    }

    public async ValueTask DataApiDeleteHandler(HttpContext context)
    {
        var meta = ResolveEntity(context, out _, out var errorMessage);
        var id = GetRouteValue(context, "id");
        if (meta == null || string.IsNullOrWhiteSpace(id))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            await context.Response.WriteAsync(errorMessage ?? "Entity not found.");
            return;
        }

        if (!HasEntityPermission(context, meta))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("Access denied.");
            return;
        }

        await DataScaffold.DeleteAsync(meta, id);
        context.Response.StatusCode = StatusCodes.Status204NoContent;
    }

    public async ValueTask MetricsJsonHandler(HttpContext context)
    {
        var app = context.GetApp();
        if (app == null)
        {
            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            return;
        }

        var snapshot = app.Metrics.GetSnapshot();
        var payload = new Dictionary<string, object?>
        {
            ["totalRequests"] = snapshot.TotalRequests,
            ["errorRequests"] = snapshot.ErrorRequests,
            ["averageResponseTimeMs"] = snapshot.AverageResponseTime.TotalMilliseconds,
            ["recentMinimumResponseTimeMs"] = snapshot.RecentMinimumResponseTime.TotalMilliseconds,
            ["recentMaximumResponseTimeMs"] = snapshot.RecentMaximumResponseTime.TotalMilliseconds,
            ["recentAverageResponseTimeMs"] = snapshot.RecentAverageResponseTime.TotalMilliseconds,
            ["recentP95ResponseTimeMs"] = snapshot.RecentP95ResponseTime.TotalMilliseconds,
            ["recentP99ResponseTimeMs"] = snapshot.RecentP99ResponseTime.TotalMilliseconds,
            ["recent10sAverageResponseTimeMs"] = snapshot.Recent10sAverageResponseTime.TotalMilliseconds,
            ["requests2xx"] = snapshot.Requests2xx,
            ["requests4xx"] = snapshot.Requests4xx,
            ["requests5xx"] = snapshot.Requests5xx,
            ["requestsOther"] = snapshot.RequestsOther,
            ["throttledRequests"] = snapshot.ThrottledRequests
        };

        await WriteJsonResponseAsync(context, payload);
    }

    // Helper methods
    private static Dictionary<string, object?> BuildApiModel(DataEntityMetadata meta, object instance)
    {
        var data = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        var id = instance is BaseDataObject dataObject ? DataScaffold.GetIdValue(dataObject) : null;
        if (!string.IsNullOrWhiteSpace(id))
            data["id"] = id;

        foreach (var field in meta.Fields.Where(f => f.View))
        {
            data[field.Name] = field.Property.GetValue(instance);
        }

        return data;
    }

    private static DataEntityMetadata? ResolveEntity(HttpContext context, out string typeSlug, out string? errorMessage)
    {
        typeSlug = GetRouteValue(context, "type") ?? string.Empty;
        if (string.IsNullOrWhiteSpace(typeSlug))
        {
            errorMessage = "Entity type not specified.";
            return null;
        }

        if (DataScaffold.TryGetEntity(typeSlug, out var metadata))
        {
            errorMessage = null;
            return metadata;
        }

        errorMessage = $"Unknown entity '{WebUtility.HtmlEncode(typeSlug)}'.";
        return null;
    }

    private static string? GetRouteValue(HttpContext context, string key)
    {
        var pageContext = context.GetPageContext();
        if (pageContext == null)
            return null;

        for (int i = 0; i < pageContext.PageMetaDataKeys.Length; i++)
        {
            if (string.Equals(pageContext.PageMetaDataKeys[i], key, StringComparison.OrdinalIgnoreCase))
                return WebUtility.HtmlDecode(pageContext.PageMetaDataValues[i]);
        }

        return null;
    }

    private static Dictionary<string, string?> ToQueryDictionary(IQueryCollection query)
    {
        var dict = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var kvp in query)
        {
            dict[kvp.Key] = kvp.Value.ToString();
        }

        return dict;
    }

    private bool HasEntityPermission(HttpContext context, DataEntityMetadata meta)
    {
        var permissionsNeeded = meta.Permissions?.Trim();
        if (string.IsNullOrWhiteSpace(permissionsNeeded) || string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase))
            return true;

        var user = _getUser(context);
        if (user == null)
        {
            return string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase);
        }

        if (string.Equals(permissionsNeeded, "Authenticated", StringComparison.OrdinalIgnoreCase))
            return true;

        if (string.Equals(permissionsNeeded, "AnonymousOnly", StringComparison.OrdinalIgnoreCase))
            return false;

        var userPermissions = new HashSet<string>(user.Permissions ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        var required = permissionsNeeded.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return required.Length == 0 || required.All(userPermissions.Contains);
    }

    private void ApplyAuditInfo(object instance, HttpContext context, bool isCreate)
    {
        if (instance is not BaseDataObject dataObject)
            return;

        var user = _getUser(context);
        var userName = user?.UserName ?? "system";

        if (isCreate)
        {
            dataObject.CreatedBy = userName;
            dataObject.UpdatedBy = userName;
            dataObject.CreatedOnUtc = DateTime.UtcNow;
            dataObject.UpdatedOnUtc = dataObject.CreatedOnUtc;
        }
        else
        {
            dataObject.Touch(userName);
        }
    }

    private static async ValueTask<Dictionary<string, JsonElement>?> ReadJsonBodyAsync(HttpContext context)
    {
        if (context.Request.ContentLength.HasValue && context.Request.ContentLength.Value == 0)
            return null;

        try
        {
            using var doc = await JsonDocument.ParseAsync(context.Request.Body).ConfigureAwait(false);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return null;

            var payload = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in doc.RootElement.EnumerateObject())
            {
                payload[property.Name] = property.Value.Clone();
            }

            return payload;
        }
        catch
        {
            return null;
        }
    }

    private static async ValueTask WriteJsonResponseAsync(HttpContext context, object payload)
    {
        context.Response.ContentType = "application/json";
        await using var writer = new Utf8JsonWriter(context.Response.Body, new JsonWriterOptions { Indented = true });
        WriteJsonValue(writer, payload);
        await writer.FlushAsync();
    }

    private static void WriteJsonValue(Utf8JsonWriter writer, object? value)
    {
        if (value == null)
        {
            writer.WriteNullValue();
            return;
        }

        switch (value)
        {
            case JsonElement element:
                element.WriteTo(writer);
                return;
            case string s:
                writer.WriteStringValue(s);
                return;
            case bool b:
                writer.WriteBooleanValue(b);
                return;
            case int i:
                writer.WriteNumberValue(i);
                return;
            case long l:
                writer.WriteNumberValue(l);
                return;
            case double d:
                writer.WriteNumberValue(d);
                return;
            case decimal m:
                writer.WriteNumberValue(m);
                return;
            case float f:
                writer.WriteNumberValue(f);
                return;
            case DateTime dt:
                writer.WriteStringValue(dt.ToString("O"));
                return;
            case DateTimeOffset dto:
                writer.WriteStringValue(dto.ToString("O"));
                return;
            case Guid g:
                writer.WriteStringValue(g);
                return;
        }

        if (value is IDictionary<string, object?> dict)
        {
            writer.WriteStartObject();
            foreach (var kvp in dict)
            {
                writer.WritePropertyName(kvp.Key);
                WriteJsonValue(writer, kvp.Value);
            }
            writer.WriteEndObject();
            return;
        }

        if (value is System.Collections.IEnumerable enumerable && value is not string)
        {
            writer.WriteStartArray();
            foreach (var item in enumerable)
            {
                WriteJsonValue(writer, item);
            }
            writer.WriteEndArray();
            return;
        }

        writer.WriteStringValue(value.ToString());
    }
}
