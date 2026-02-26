using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using BareMetalWeb.Core;
using BareMetalWeb.Data;

namespace BareMetalWeb.Host;

/// <summary>
/// API handlers for the lookup() JavaScript function.
/// Provides endpoints for dynamic client-side data queries.
/// </summary>
public static class LookupApiHandlers
{
    /// <summary>
    /// GET /api/_lookup/{EntityType}/{Id}
    /// Fetches a single entity by ID.
    /// </summary>
    public static async ValueTask GetEntityByIdHandler(HttpContext context)
    {
        var (meta, typeSlug, errorResponse) = await ValidateAndResolveEntityAsync(context);
        if (meta == null)
        {
            await WriteJsonErrorAsync(context, errorResponse!.StatusCode, errorResponse!.Message);
            return;
        }

        var id = GetRouteValue(context, "id") ?? string.Empty;
        if (string.IsNullOrWhiteSpace(id))
        {
            await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, "Entity ID not specified.");
            return;
        }

        var traverse = context.Request.Query.TryGetValue("traverseRelationships", out var tvVal)
            && string.Equals(tvVal.FirstOrDefault(), "true", StringComparison.OrdinalIgnoreCase);

        try
        {
            var entity = await meta.Handlers.LoadAsync(id, context.RequestAborted);
            if (entity == null)
            {
                await WriteJsonErrorAsync(context, StatusCodes.Status404NotFound, $"Entity with ID '{id}' not found.");
                return;
            }

            var result = await EntityToJsonAsync(entity, meta, traverse, context.RequestAborted);
            await WriteJsonAsync(context, result);
        }
        catch (Exception)
        {
            await WriteJsonErrorAsync(context, StatusCodes.Status500InternalServerError, "Error loading entity.");
        }
    }

    /// <summary>
    /// GET /api/_lookup/{EntityType}?filter=field:value&filter=field2:value2
    /// Queries entities with optional filters.
    /// Supports multiple filters, sorting, pagination.
    /// </summary>
    public static async ValueTask QueryEntitiesHandler(HttpContext context)
    {
        var (meta, typeSlug, errorResponse) = await ValidateAndResolveEntityAsync(context);
        if (meta == null)
        {
            await WriteJsonErrorAsync(context, errorResponse!.StatusCode, errorResponse!.Message);
            return;
        }

        // Validate lookup relationship if source context is provided
        var sourceSlug = context.Request.Query["from"].ToString();
        var sourceField = context.Request.Query["via"].ToString();
        if (!string.IsNullOrWhiteSpace(sourceSlug) || !string.IsNullOrWhiteSpace(sourceField))
        {
            if (!ValidateLookupRelationship(sourceSlug, sourceField, typeSlug))
            {
                await WriteJsonErrorAsync(context, StatusCodes.Status403Forbidden, "No declared lookup relationship between the specified entities.");
                return;
            }
        }

        var traverse = context.Request.Query.TryGetValue("traverseRelationships", out var tvVal)
            && string.Equals(tvVal.FirstOrDefault(), "true", StringComparison.OrdinalIgnoreCase);

        try
        {
            var queryDef = BuildQueryFromRequest(context, meta);
            var entities = await meta.Handlers.QueryAsync(queryDef, context.RequestAborted);
            var results = new List<Dictionary<string, object?>>();
            foreach (var e in entities)
                results.Add(await EntityToJsonAsync(e, meta, traverse, context.RequestAborted));

            await WriteJsonAsync(context, new Dictionary<string, object>
            {
                ["data"] = results,
                ["count"] = results.Count
            });
        }
        catch (Exception)
        {
            await WriteJsonErrorAsync(context, StatusCodes.Status500InternalServerError, "Error querying entities.");
        }
    }

    /// <summary>
    /// POST /api/_lookup/{EntityType}/_batch
    /// Fetches multiple entities by ID in a single request.
    /// Request body: { "ids": ["id1", "id2", ...] }
    /// Response: { "results": { "id1": {...}, "id2": {...} } }
    /// </summary>
    public static async ValueTask BatchGetEntitiesHandler(HttpContext context)
    {
        var (meta, typeSlug, errorResponse) = await ValidateAndResolveEntityAsync(context);
        if (meta == null)
        {
            await WriteJsonErrorAsync(context, errorResponse!.StatusCode, errorResponse!.Message);
            return;
        }

        List<string> ids;
        try
        {
            using var doc = await JsonDocument.ParseAsync(context.Request.Body, cancellationToken: context.RequestAborted);
            if (!doc.RootElement.TryGetProperty("ids", out var idsElement) || idsElement.ValueKind != JsonValueKind.Array)
            {
                await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, "Request body must contain an 'ids' array.");
                return;
            }

            ids = idsElement.EnumerateArray()
                .Where(e => e.ValueKind == JsonValueKind.String)
                .Select(e => e.GetString()!)
                .Where(s => !string.IsNullOrWhiteSpace(s))
                .Distinct()
                .ToList();
        }
        catch (JsonException)
        {
            await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, "Invalid JSON body.");
            return;
        }

        if (ids.Count == 0)
        {
            await WriteJsonAsync(context, new Dictionary<string, object> { ["results"] = new Dictionary<string, object?>() });
            return;
        }

        var traverse = context.Request.Query.TryGetValue("traverseRelationships", out var tvVal)
            && string.Equals(tvVal.FirstOrDefault(), "true", StringComparison.OrdinalIgnoreCase);

        try
        {
            var results = new Dictionary<string, object?>(ids.Count);
            foreach (var id in ids)
            {
                var entity = await meta.Handlers.LoadAsync(id, context.RequestAborted);
                if (entity != null)
                    results[id] = await EntityToJsonAsync(entity, meta, traverse, context.RequestAborted);
            }

            await WriteJsonAsync(context, new Dictionary<string, object> { ["results"] = results });
        }
        catch (Exception)
        {
            await WriteJsonErrorAsync(context, StatusCodes.Status500InternalServerError, "Error loading entities.");
        }
    }

    /// <summary>
    /// GET /api/_lookup/{EntityType}/_field/{Id}/{FieldName}
    /// Fetches a single field value from an entity.
    /// </summary>
    public static async ValueTask GetEntityFieldHandler(HttpContext context)
    {
        var (meta, typeSlug, errorResponse) = await ValidateAndResolveEntityAsync(context);
        if (meta == null)
        {
            await WriteJsonErrorAsync(context, errorResponse!.StatusCode, errorResponse!.Message);
            return;
        }

        var id = GetRouteValue(context, "id") ?? string.Empty;
        var fieldName = GetRouteValue(context, "fieldName") ?? string.Empty;

        if (string.IsNullOrWhiteSpace(id))
        {
            await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, "Entity ID not specified.");
            return;
        }

        if (string.IsNullOrWhiteSpace(fieldName))
        {
            await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, "Field name not specified.");
            return;
        }

        try
        {
            var entity = await meta.Handlers.LoadAsync(id, context.RequestAborted);
            if (entity == null)
            {
                await WriteJsonErrorAsync(context, StatusCodes.Status404NotFound, $"Entity with ID '{id}' not found.");
                return;
            }

            var field = meta.Fields.FirstOrDefault(f => 
                string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase) && f.View);
            
            if (field == null)
            {
                await WriteJsonErrorAsync(context, StatusCodes.Status404NotFound, $"Field '{fieldName}' not found.");
                return;
            }

            var value = field.Property.GetValue(entity);
            await WriteJsonAsync(context, new Dictionary<string, object?>
            {
                ["field"] = field.Name,
                ["value"] = value
            });
        }
        catch (Exception)
        {
            await WriteJsonErrorAsync(context, StatusCodes.Status500InternalServerError, "Error loading field.");
        }
    }

    /// <summary>
    /// GET /api/_lookup/{EntityType}/_aggregate?fn=count&field=Total&filter=field:value
    /// Performs aggregate operations on entities (count, sum, avg, min, max).
    /// </summary>
    public static async ValueTask AggregateEntitiesHandler(HttpContext context)
    {
        var (meta, typeSlug, errorResponse) = await ValidateAndResolveEntityAsync(context);
        if (meta == null)
        {
            await WriteJsonErrorAsync(context, errorResponse!.StatusCode, errorResponse!.Message);
            return;
        }

        var fn = context.Request.Query["fn"].ToString().ToLowerInvariant();
        var fieldName = context.Request.Query["field"].ToString();

        if (string.IsNullOrWhiteSpace(fn))
        {
            await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, "Aggregate function not specified (use ?fn=count|sum|avg|min|max).");
            return;
        }

        try
        {
            var queryDef = BuildQueryFromRequest(context, meta);
            
            if (fn == "count")
            {
                var count = await meta.Handlers.CountAsync(queryDef, context.RequestAborted);
                await WriteJsonAsync(context, new Dictionary<string, object>
                {
                    ["function"] = "count",
                    ["result"] = count
                });
                return;
            }

            // For sum, avg, min, max we need to load entities and compute
            if (string.IsNullOrWhiteSpace(fieldName))
            {
                await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, $"Field name required for '{fn}' function (use ?field=FieldName).");
                return;
            }

            var field = meta.Fields.FirstOrDefault(f => 
                string.Equals(f.Name, fieldName, StringComparison.OrdinalIgnoreCase) && f.View);
            
            if (field == null)
            {
                await WriteJsonErrorAsync(context, StatusCodes.Status404NotFound, $"Field '{fieldName}' not found.");
                return;
            }

            var entities = await meta.Handlers.QueryAsync(queryDef, context.RequestAborted);
            var values = entities.Select(e => field.Property.GetValue(e)).Where(v => v != null).ToList();

            object? result = fn switch
            {
                "sum" => ComputeSum(values),
                "avg" => ComputeAverage(values),
                "min" => ComputeMin(values),
                "max" => ComputeMax(values),
                _ => null
            };

            if (result == null)
            {
                await WriteJsonErrorAsync(context, StatusCodes.Status400BadRequest, $"Unsupported aggregate function '{fn}'.");
                return;
            }

            await WriteJsonAsync(context, new Dictionary<string, object?>
            {
                ["function"] = fn,
                ["field"] = fieldName,
                ["result"] = result,
                ["count"] = values.Count
            });
        }
        catch (Exception)
        {
            await WriteJsonErrorAsync(context, StatusCodes.Status500InternalServerError, "Error computing aggregate.");
        }
    }

    #region Helper Methods

    private static async ValueTask<(DataEntityMetadata? Meta, string TypeSlug, ErrorResponse? Error)> ValidateAndResolveEntityAsync(HttpContext context)
    {
        var typeSlug = GetRouteValue(context, "type") ?? string.Empty;
        if (string.IsNullOrWhiteSpace(typeSlug))
        {
            return (null, typeSlug, new ErrorResponse(StatusCodes.Status400BadRequest, "Entity type not specified."));
        }

        if (!DataScaffold.TryGetEntity(typeSlug, out var metadata))
        {
            return (null, typeSlug, new ErrorResponse(StatusCodes.Status404NotFound, $"Unknown entity type '{typeSlug}'."));
        }

        // Check permissions
        if (!await HasEntityPermissionAsync(context, metadata!, context.RequestAborted))
        {
            return (null, typeSlug, new ErrorResponse(StatusCodes.Status403Forbidden, "Access denied."));
        }

        return (metadata, typeSlug, null);
    }

    private static async ValueTask<bool> HasEntityPermissionAsync(HttpContext context, DataEntityMetadata meta, CancellationToken cancellationToken)
    {
        var permissionsNeeded = meta.Permissions?.Trim();
        if (string.IsNullOrWhiteSpace(permissionsNeeded) || 
            string.Equals(permissionsNeeded, "Public", StringComparison.OrdinalIgnoreCase))
            return true;

        var user = await UserAuth.GetRequestUserAsync(context, cancellationToken);
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

    private static string? GetRouteValue(HttpContext context, string key)
    {
        var pageContext = context.GetPageContext();
        if (pageContext == null)
            return null;

        for (int i = 0; i < pageContext.PageMetaDataKeys.Length; i++)
        {
            if (string.Equals(pageContext.PageMetaDataKeys[i], key, StringComparison.OrdinalIgnoreCase))
                return pageContext.PageMetaDataValues[i];
        }
        return null;
    }

    private static QueryDefinition BuildQueryFromRequest(HttpContext context, DataEntityMetadata meta)
    {
        var queryDef = new QueryDefinition();

        var viewableFields = new HashSet<string>(
            meta.Fields.Where(f => f.View).Select(f => f.Name),
            StringComparer.OrdinalIgnoreCase);

        // Parse filters from query string: ?filter=field:value
        var filters = context.Request.Query["filter"];
        foreach (var filter in filters)
        {
            if (string.IsNullOrWhiteSpace(filter))
                continue;

            var parts = filter.Split(':', 2);
            if (parts.Length == 2)
            {
                var fieldName = parts[0].Trim();
                if (!viewableFields.Contains(fieldName))
                    continue; // reject unknown or non-viewable fields
                queryDef.Clauses.Add(new QueryClause
                {
                    Field = fieldName,
                    Operator = QueryOperator.Equals,
                    Value = parts[1].Trim()
                });
            }
        }

        // Parse sort: ?sort=fieldName&dir=asc|desc — only allow viewable fields
        var sortField = context.Request.Query["sort"].ToString();
        var sortDir = context.Request.Query["dir"].ToString();
        if (!string.IsNullOrWhiteSpace(sortField) && viewableFields.Contains(sortField))
        {
            queryDef.Sorts.Add(new SortClause
            {
                Field = sortField,
                Direction = string.Equals(sortDir, "desc", StringComparison.OrdinalIgnoreCase) 
                    ? SortDirection.Desc 
                    : SortDirection.Asc
            });
        }
        else if (!string.IsNullOrWhiteSpace(meta.DefaultSortField) && viewableFields.Contains(meta.DefaultSortField))
        {
            queryDef.Sorts.Add(new SortClause
            {
                Field = meta.DefaultSortField,
                Direction = meta.DefaultSortDirection
            });
        }

        // Parse pagination: ?skip=0&top=10
        if (int.TryParse(context.Request.Query["skip"].ToString(), out var skip) && skip > 0)
            queryDef.Skip = skip;
        
        const int LookupMaxPageSize = 10000;
        const int LookupDefaultPageSize = 200;
        queryDef.Top = int.TryParse(context.Request.Query["top"].ToString(), out var top) && top > 0
            ? Math.Min(top, LookupMaxPageSize)
            : LookupDefaultPageSize;

        // Parse search: ?search=term&searchField=FieldName — only allow viewable fields
        var searchTerm = context.Request.Query["search"].ToString();
        var searchField = context.Request.Query["searchField"].ToString();
        if (!string.IsNullOrWhiteSpace(searchTerm) && !string.IsNullOrWhiteSpace(searchField)
            && viewableFields.Contains(searchField))
        {
            queryDef.Clauses.Add(new QueryClause
            {
                Field = searchField,
                Operator = QueryOperator.Contains,
                Value = searchTerm
            });
        }

        return queryDef;
    }

    /// <summary>
    /// Validates that <paramref name="sourceSlug"/> declares a field named <paramref name="sourceFieldName"/>
    /// with a lookup that targets the entity identified by <paramref name="targetSlug"/>.
    /// Returns <c>false</c> if either entity is unknown, the field does not exist, or the field has no
    /// lookup pointing at the target entity.
    /// </summary>
    private static bool ValidateLookupRelationship(string sourceSlug, string sourceFieldName, string targetSlug)
    {
        if (string.IsNullOrWhiteSpace(sourceSlug) || string.IsNullOrWhiteSpace(sourceFieldName))
            return false;

        if (!DataScaffold.TryGetEntity(sourceSlug, out var sourceMeta))
            return false;

        var field = sourceMeta!.Fields.FirstOrDefault(f =>
            string.Equals(f.Name, sourceFieldName, StringComparison.OrdinalIgnoreCase));

        if (field?.Lookup == null)
            return false;

        var targetMeta = DataScaffold.GetEntityByType(field.Lookup.TargetType);
        return string.Equals(targetMeta?.Slug, targetSlug, StringComparison.OrdinalIgnoreCase);
    }

    private static Dictionary<string, object?> EntityToJson(BaseDataObject entity, DataEntityMetadata meta)
    {
        var result = new Dictionary<string, object?>
        {
            ["id"] = entity.Id
        };

        foreach (var field in meta.Fields.Where(f => f.View))
        {
            var value = field.Property.GetValue(entity);
            result[field.Name] = value;
        }

        return result;
    }

    /// <summary>
    /// Builds the JSON dictionary for an entity, optionally expanding lookup FK fields into nested objects.
    /// When <paramref name="traverseRelationships"/> is <c>true</c>, each viewable field decorated with
    /// <see cref="DataLookupAttribute"/> will have an additional key added alongside it — the field name
    /// with any trailing "Id" stripped — whose value is the full related entity object.
    /// For example, <c>CustomerId: "abc"</c> becomes accompanied by <c>Customer: {id: "abc", Name: "Acme", ...}</c>.
    /// Expansion is one level deep only to prevent circular traversal.
    /// </summary>
    private static async ValueTask<Dictionary<string, object?>> EntityToJsonAsync(
        BaseDataObject entity,
        DataEntityMetadata meta,
        bool traverseRelationships,
        CancellationToken cancellationToken)
    {
        var result = EntityToJson(entity, meta);

        if (!traverseRelationships)
            return result;

        foreach (var field in meta.Fields.Where(f => f.View && f.Lookup != null))
        {
            if (!result.TryGetValue(field.Name, out var rawValue) || rawValue == null)
                continue;

            if (rawValue is not string idStr || string.IsNullOrWhiteSpace(idStr))
                continue;

            var relatedMeta = DataScaffold.GetEntityByType(field.Lookup!.TargetType);
            if (relatedMeta == null)
                continue;

            var expandedKey = StripIdSuffix(field.Name);
            if (string.Equals(expandedKey, field.Name, StringComparison.Ordinal) || result.ContainsKey(expandedKey))
                continue;

            var related = await relatedMeta.Handlers.LoadAsync(idStr, cancellationToken);
            if (related != null)
                result[expandedKey] = EntityToJson(related, relatedMeta);
        }

        return result;
    }

    /// <summary>
    /// Returns <paramref name="fieldName"/> with a trailing "Id" (case-insensitive) stripped.
    /// Returns the original name unchanged when it does not end with "Id" or is 2 characters or shorter.
    /// </summary>
    private static string StripIdSuffix(string fieldName)
    {
        if (fieldName.Length > 2 && fieldName.EndsWith("Id", StringComparison.OrdinalIgnoreCase))
            return fieldName[..^2];
        return fieldName;
    }

    private static async ValueTask WriteJsonAsync(HttpContext context, object data)
    {
        context.Response.ContentType = "application/json";
        context.Response.StatusCode = StatusCodes.Status200OK;
        await JsonSerializer.SerializeAsync(context.Response.Body, data, new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false
        });
    }

    private static async ValueTask WriteJsonErrorAsync(HttpContext context, int statusCode, string message)
    {
        context.Response.ContentType = "application/json";
        context.Response.StatusCode = statusCode;
        await JsonSerializer.SerializeAsync(context.Response.Body, new Dictionary<string, object>
        {
            ["error"] = message,
            ["status"] = statusCode
        });
    }

    private static object? ComputeSum(List<object?> values)
    {
        if (values.Count == 0) return 0;
        
        var first = values[0];
        if (first is int || first is long || first is short || first is byte)
            return values.Sum(v => Convert.ToInt64(v));
        if (first is float || first is double)
            return values.Sum(v => Convert.ToDouble(v));
        if (first is decimal)
            return values.Sum(v => Convert.ToDecimal(v));
        
        return null;
    }

    private static object? ComputeAverage(List<object?> values)
    {
        if (values.Count == 0) return 0;
        
        var first = values[0];
        if (first is int || first is long || first is short || first is byte)
            return values.Average(v => Convert.ToDouble(v));
        if (first is float || first is double)
            return values.Average(v => Convert.ToDouble(v));
        if (first is decimal)
            return values.Average(v => Convert.ToDecimal(v));
        
        return null;
    }

    private static object? ComputeMin(List<object?> values)
    {
        if (values.Count == 0) return null;
        return values.Min();
    }

    private static object? ComputeMax(List<object?> values)
    {
        if (values.Count == 0) return null;
        return values.Max();
    }

    private record ErrorResponse(int StatusCode, string Message);

    #endregion
}
